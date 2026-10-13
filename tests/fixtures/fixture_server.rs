//! Tiny stdio MCP server used by the integration tests

use std::{sync::Arc, time::Duration};

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{
        router::tool::{ToolRoute, ToolRouter},
        tool::ToolCallContext,
        wrapper::{Json, Parameters},
    },
    model::{
        CallToolResponse, CallToolResult, ContentBlock, ServerCapabilities, ServerConfig, Tool,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

        Self { tool_router }
    }
}

#[tool_router]
impl Fixture {
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
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = Fixture::new().serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}
