//! Tiny stdio MCP server used by the integration tests

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use rmcp::{
    ErrorData, RoleServer, ServerHandler, ServiceExt,
    handler::server::{
        router::tool::{ToolRoute, ToolRouter},
        tool::ToolCallContext,
        wrapper::{Json, Parameters},
    },
    model::{
        CallToolResponse, CallToolResult, ContentBlock, ErrorCode, InitializeRequestParams,
        InitializeResult, ServerCapabilities, ServerConfig, Tool,
    },
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, schemars::JsonSchema)]
struct WhoamiParams {
    /// Account to describe; only `login` makes it usable
    account: String,
}

#[derive(Serialize, schemars::JsonSchema)]
struct Pid {
    /// This server's process id
    pid: u32,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EnvParams {
    /// Variable to read
    name: String,
    /// Answer with an error that quotes the value instead
    #[serde(default)]
    fail: bool,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct AddParams {
    /// Left operand
    a: i64,
    /// Right operand
    b: i64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EchoParams {
    /// Text to return
    text: String,
    /// How long to wait before answering
    delay_ms: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct OverlapParams {
    /// How long to stay in flight
    delay_ms: u64,
}

#[derive(Serialize, schemars::JsonSchema)]
struct Overlap {
    /// Most calls of this tool in flight at once so far
    peak: usize,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FailParams {
    /// Text of the error to answer with
    message: String,
}

/// Calls of `overlap` running now, and the most seen at once
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

#[derive(Deserialize, schemars::JsonSchema)]
struct UseTokenParams {
    /// The token to use
    token: String,
}

#[derive(Serialize, schemars::JsonSchema)]
struct EchoResult {
    echoed: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct Filter {
    /// Field to match
    field: String,
    /// Allowed values
    mode: Mode,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Exact,
    Fuzzy,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FindParams {
    /// Search text
    query: String,
    /// Optional nested filter
    filter: Option<Filter>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
struct Wide {
    /// A number that does not fit in an i64
    n: u64,
}

/// A tool with a hand-written input schema that echoes its arguments as JSON
/// text, so schema shapes `schemars` never produces can be exercised
fn echo_route(name: &'static str, schema: Value) -> ToolRoute<Fixture> {
    let schema = schema.as_object().cloned().unwrap_or_default();
    let tool = Tool::new(name, "Echo the arguments as JSON text", Arc::new(schema));

    ToolRoute::new_dyn(tool, |context: ToolCallContext<'_, Fixture>| {
        let arguments = Value::Object(context.arguments.clone().unwrap_or_default());

        Box::pin(async move {
            Ok(CallToolResponse::Complete(CallToolResult::success(vec![
                ContentBlock::text(arguments.to_string()),
            ])))
        })
    })
}

/// Declares an output schema but answers with plain prose
fn unstructured_route() -> ToolRoute<Fixture> {
    let schema = json!({"type": "object", "properties": {}});
    let output = json!({"type": "object", "properties": {"ok": {"type": "boolean"}}});
    let tool = Tool::new(
        "declared_output",
        "Promises structured output and does not deliver",
        Arc::new(schema.as_object().cloned().unwrap_or_default()),
    )
    .with_raw_output_schema(Arc::new(output.as_object().cloned().unwrap_or_default()));

    ToolRoute::new_dyn(tool, |_context: ToolCallContext<'_, Fixture>| {
        Box::pin(async {
            Ok(CallToolResponse::Complete(CallToolResult::success(vec![
                ContentBlock::text("all good, no structure"),
            ])))
        })
    })
}

/// Declares an output schema and delivers structured content that breaks it
/// three levels down
fn mismatched_route() -> ToolRoute<Fixture> {
    let schema = json!({"type": "object", "properties": {}});
    let output = json!({
        "type": "object",
        "required": ["ok", "items"],
        "properties": {
            "ok": {"type": "boolean"},
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {"name": {"type": "string"}},
                },
            },
        },
    });
    let tool = Tool::new(
        "mismatched_output",
        "Declares a schema its result does not follow",
        Arc::new(schema.as_object().cloned().unwrap_or_default()),
    )
    .with_raw_output_schema(Arc::new(output.as_object().cloned().unwrap_or_default()));

    ToolRoute::new_dyn(tool, |_context: ToolCallContext<'_, Fixture>| {
        Box::pin(async {
            Ok(CallToolResponse::Complete(CallToolResult::structured(
                json!({"ok": true, "items": [{"name": "fine"}, {"name": 7}]}),
            )))
        })
    })
}

/// Blocks until the client cancels the call, then writes `marker` so a test
/// can tell the cancellation reached the server
fn hang_route() -> ToolRoute<Fixture> {
    let schema = json!({
        "type": "object",
        "required": ["marker"],
        "properties": {"marker": {"type": "string"}},
    });
    let tool = Tool::new(
        "hang",
        "Wait until cancelled, then write the marker file",
        Arc::new(schema.as_object().cloned().unwrap_or_default()),
    );

    ToolRoute::new_dyn(tool, |context: ToolCallContext<'_, Fixture>| {
        let marker = context
            .arguments
            .as_ref()
            .and_then(|arguments| arguments.get("marker"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let cancelled = context.request_context.ct.clone();

        Box::pin(async move {
            cancelled.cancelled().await;
            if let Some(marker) = marker {
                let _ = std::fs::write(marker, "cancelled");
            }

            Ok(CallToolResponse::Complete(CallToolResult::success(vec![
                ContentBlock::text("cancelled"),
            ])))
        })
    })
}

#[derive(Clone)]
struct Fixture {
    tool_router: ToolRouter<Fixture>,
    /// Set by `login`, like a server that grants scopes per connection
    logged_in: Arc<AtomicBool>,
}

impl Fixture {
    fn new() -> Self {
        let tool_router = Self::tool_router()
            .with_route(echo_route(
                "ref_root",
                json!({
                    "$ref": "#/$defs/Args",
                    "$defs": {
                        "Args": {
                            "type": "object",
                            "required": ["query"],
                            "properties": {"query": {"type": "string"}},
                        },
                    },
                }),
            ))
            .with_route(echo_route(
                "open_args",
                json!({
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "additionalProperties": true,
                }),
            ))
            .with_route(echo_route(
                "odd_names",
                json!({
                    "type": "object",
                    "properties": {"page-size": {"type": "integer"}},
                }),
            ))
            .with_route(unstructured_route())
            .with_route(mismatched_route())
            .with_route(hang_route());

        Self {
            tool_router,
            logged_in: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[tool_router]
impl Fixture {
    #[tool(description = "Log in for this connection; whoami refuses until then")]
    fn login(&self) -> String {
        self.logged_in.store(true, Ordering::SeqCst);

        "logged in".to_owned()
    }

    #[tool(description = "Name the account, once logged in")]
    fn whoami(
        &self,
        Parameters(WhoamiParams { account }): Parameters<WhoamiParams>,
    ) -> Result<String, String> {
        if self.logged_in.load(Ordering::SeqCst) {
            Ok(format!("account {account}"))
        } else {
            Err("Missing required scope. Call the login tool first.".to_owned())
        }
    }

    #[tool(description = "This server's process id")]
    fn pid(&self) -> Json<Pid> {
        Json(Pid {
            pid: std::process::id(),
        })
    }

    #[tool(description = "Read one of this server's environment variables")]
    fn env(
        &self,
        Parameters(EnvParams { name, fail }): Parameters<EnvParams>,
    ) -> Result<String, String> {
        let value = std::env::var(&name).unwrap_or_default();
        if fail {
            Err(format!("refused; the value was {value}"))
        } else {
            Ok(value)
        }
    }

    #[tool(description = "Add two integers")]
    fn add(&self, Parameters(AddParams { a, b }): Parameters<AddParams>) -> String {
        (a + b).to_string()
    }

    #[tool(description = "Return the text after sleeping for delay_ms milliseconds")]
    async fn slow_echo(&self, Parameters(params): Parameters<EchoParams>) -> Json<EchoResult> {
        tokio::time::sleep(Duration::from_millis(params.delay_ms)).await;

        Json(EchoResult {
            echoed: params.text,
        })
    }

    #[tool(description = "Answer with an error carrying the message")]
    fn fail(
        &self,
        Parameters(FailParams { message }): Parameters<FailParams>,
    ) -> Result<String, String> {
        Err(message)
    }

    #[tool(description = "Stay in flight for delay_ms, then report the most calls seen at once")]
    async fn overlap(&self, Parameters(params): Parameters<OverlapParams>) -> Json<Overlap> {
        let running = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK.fetch_max(running, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(params.delay_ms)).await;
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);

        Json(Overlap {
            peak: PEAK.load(Ordering::SeqCst),
        })
    }

    #[tool(description = "The largest u64, which no i64 can hold")]
    fn wide(&self) -> Json<Wide> {
        Json(Wide { n: u64::MAX })
    }

    #[tool(description = "Return the number it was given")]
    fn echo_wide(&self, Parameters(wide): Parameters<Wide>) -> Json<Wide> {
        Json(wide)
    }

    #[tool(description = "A JSON array delivered as plain text")]
    fn json_text(&self) -> String {
        "[1, 2, {\"k\": \"v\"}]".to_owned()
    }

    #[tool(description = "Hand out a token as JSON text, with no declared output schema")]
    fn issue_token(&self) -> String {
        json!({"token": "tok-1"}).to_string()
    }

    #[tool(description = "Echo the token it was given")]
    fn use_token(
        &self,
        Parameters(UseTokenParams { token }): Parameters<UseTokenParams>,
    ) -> String {
        format!("used {token}")
    }

    #[tool(description = "Look things up with an optional nested filter")]
    fn find(&self, Parameters(params): Parameters<FindParams>) -> String {
        let filter = match params.filter {
            Some(Filter {
                field,
                mode: Mode::Exact,
            }) => format!("{field}=exact"),
            Some(Filter {
                field,
                mode: Mode::Fuzzy,
            }) => format!("{field}=fuzzy"),
            None => "none".to_owned(),
        };

        format!("{}:{filter}", params.query)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Fixture {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Call fixture_add before anything else.\nThen any tool.")
    }

    /// Refuses an `initialize` naming a version that has no handshake, as
    /// Google's Workspace MCP servers do
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        if !request.protocol_version.has_initialize() {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "Method not supported",
                None,
            ));
        }

        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = Fixture::new().serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
