//! `{{ op://... }}` references in server config, read through a fake `op`

use std::{
    error::Error,
    io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::Router;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing_subscriber::fmt::MakeWriter;

use super::{
    harness::{Harness, Setup, TestResult, execute, temp_state_dir, text_of},
    oauth::Locked,
};

pub(super) const VALUE: &str = "value-from-1password";
/// The part of a URL that works as a key, as in Zoho's MCP URLs
pub(super) const URL_KEY: &str = "zk-9f3a71c2d8b4e6";
/// A key with characters that a query string percent-encodes
pub(super) const SYMBOL_KEY: &str = "zk+9f3a71c2=d8b4e6";
/// A key with uppercase letters, which a host name would lowercase
pub(super) const MIXED_KEY: &str = "PrivateKey123abc";

/// A stand-in for the 1Password CLI that knows one item and logs each read,
/// already authorized so it reads without asking
pub(super) fn fake_op() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let (program, log) = signed_out_op()?;
    std::fs::write(log.with_file_name("authorized"), "")?;

    Ok((program, log))
}

/// Like [`fake_op`], but `whoami` fails until the first read, as if that
/// read showed 1Password's prompt and was approved
pub(super) fn signed_out_op() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let log = directory.join("reads.log");
    let program = directory.join("op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = whoami ]; then\n\
               [ -e '{authorized}' ] && exit 0\n\
               echo '[ERROR] 2026/10/15 21:12:29 account is not signed in' >&2; exit 1\n\
             fi\n\
             echo \"$3\" >> '{log}'\n\
             [ \"$1 $2\" = 'read --no-newline' ] || exit 2\n\
             touch '{authorized}'\n\
             case \"$3\" in\n\
               op://Dev/fixture/credential) printf '{VALUE}' ;;\n\
               op://Dev/mcpurl/credential) cat '{dir}/url' ;;\n\
               op://Dev/deadurl/credential) cat '{dir}/dead-url' ;;\n\
               op://Dev/urlkey/credential) printf '{URL_KEY}' ;;\n\
               op://Dev/symbolkey/credential) printf '{SYMBOL_KEY}' ;;\n\
               op://Dev/slashkey/credential) printf '%s' 'zk/9f3a71c2d8b4e6' ;;\n\
               op://Dev/mixedkey/credential) printf '%s' '{MIXED_KEY}' ;;\n\
               op://Dev/colonkey/credential) printf '%s' 'zk:9f3a71c2d8b4e6' ;;\n\
               op://Dev/backslash/credential) printf '%s' 'zk\\9f3a71c2d8b4e6' ;;\n\
               op://Dev/shortkey/credential) printf '%s' 'aB9xZ' ;;\n\
               op://Dev/encodedkey/credential) printf '%s' 'zk%2B9f3a71c2%3Dd8b4e6' ;;\n\
               op://Dev/big/credential) head -c 70000 /dev/zero | tr '\\0' a ;;\n\
               *) echo \"[ERROR] could not read secret '$3': no item matched\" >&2; exit 1 ;;\n\
             esac\n",
            log = log.display(),
            authorized = directory.join("authorized").display(),
            dir = directory.display(),
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok((program, log))
}

pub(super) fn reads(log: &PathBuf, reference: &str) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == reference)
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn references_are_read_once_and_kept_out_of_script_text() -> TestResult {
    let (op, log) = fake_op()?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\n\
         [servers.twin]\n\
         command = \"{fixture}\"\n\
         env = {{ FIXTURE_SECRET = \"{{{{ op://Dev/fixture/credential }}}}\" }}\n\n\
         [servers.locked]\n\
         command = \"{fixture}\"\n\
         env = {{ FIXTURE_SECRET = \"{{{{ op://Dev/missing/credential }}}}\" }}\n",
        op = op.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let Some(harness) = Harness::with(Setup {
        server: "env = { FIXTURE_SECRET = \"key-{{ op://Dev/fixture/credential }}\" }",
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    let script = r#"
value = await fixture_env(name="FIXTURE_SECRET")
twin = await twin_env(name="FIXTURE_SECRET")
try:
    await fixture_env(name="FIXTURE_SECRET", fail=True)
    refused = "no error"
except RuntimeError as error:
    refused = str(error)
[value, refused, twin]
"#;
    let body = harness.execute_json(script).await?;
    assert_eq!(body["result"][0], format!("key-{VALUE}"), "{body}");
    let refused = body["result"][1].as_str().unwrap_or_default();
    assert!(refused.contains("[redacted]"), "{body}");
    assert!(!refused.contains(VALUE), "{body}");
    assert_eq!(body["result"][2], VALUE, "{body}");

    // a second server and a reconnect reuse the value instead of asking
    // 1Password again
    assert!(harness.app.gateway().reconnect("fixture"));
    let mut again = Value::Null;
    for _ in 0..40 {
        // while the server reconnects the answer can be an error in prose
        let result = execute(&harness.client, script).await?;
        again = serde_json::from_str(&text_of(&result)).unwrap_or(Value::Null);
        if again["result"][0] == format!("key-{VALUE}") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(again["result"][0], format!("key-{VALUE}"), "{again}");
    assert_eq!(reads(&log, "op://Dev/fixture/credential"), 1);

    // a reference that cannot be read leaves only a coarse category public
    let health = harness
        .http
        .get(format!("{}/healthz", harness.base()))
        .send()
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&health)?;
    let locked = parsed["upstreams"]
        .as_array()
        .and_then(|upstreams| {
            upstreams
                .iter()
                .find(|upstream| upstream["name"] == "locked")
        })
        .ok_or("locked server missing from /healthz")?;
    assert_eq!(locked["state"], "unavailable", "{health}");
    assert_eq!(locked["error"], "secret_unavailable", "{health}");
    assert!(!health.contains("op://"), "{health}");
    assert_eq!(reads(&log, "op://Dev/missing/credential"), 1);

    harness.stop().await
}

/// Everything the daemon logs, kept for a search
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    fn text(&self) -> String {
        let bytes = self.0.lock().map(|bytes| bytes.clone()).unwrap_or_default();

        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl io::Write for LogCapture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Ok(mut bytes) = self.0.lock() {
            bytes.extend_from_slice(buffer);
        }

        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogCapture {
    type Writer = Self;

    fn make_writer(&self) -> Self {
        self.clone()
    }
}

/// Installs the process-wide subscriber on first use; other tests in this
/// binary log into it too, which only adds text for the search to miss
fn capture_logs() -> LogCapture {
    static CAPTURE: OnceLock<LogCapture> = OnceLock::new();

    CAPTURE
        .get_or_init(|| {
            let capture = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(codemode_mcp::secrets::redacting_logs(capture.clone()))
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);

            capture
        })
        .clone()
}

/// Serves an MCP endpoint under `/mcp/<URL_KEY>/rpc` only, so a client
/// that connects there was handed the resolved URL
pub(super) async fn serve_keyed_endpoint() -> Result<std::net::SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mcp = StreamableHttpService::new(
        || Ok(Locked),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().disable_allowed_hosts(),
    );
    let router = Router::new().nest_service(&format!("/mcp/{URL_KEY}/rpc"), mcp);
    tokio::spawn(async move { axum::serve(listener, router).await });

    Ok(address)
}

/// Answers 404 to everything and records the raw path of each request
async fn serve_recorder() -> Result<(std::net::SocketAddr, Arc<Mutex<Vec<String>>>), Box<dyn Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let router = Router::new().fallback(move |request: axum::extract::Request| {
        let recorded = Arc::clone(&recorded);
        async move {
            if let Ok(mut paths) = recorded.lock() {
                paths.push(request.uri().path().to_owned());
            }

            axum::http::StatusCode::NOT_FOUND
        }
    });
    tokio::spawn(async move { axum::serve(listener, router).await });

    Ok((address, seen))
}

/// Waits for `expected` among the paths `seen` has recorded
async fn path_seen(seen: &Arc<Mutex<Vec<String>>>, expected: &str) -> bool {
    for _ in 0..80 {
        let paths = seen.lock().map(|paths| paths.clone()).unwrap_or_default();
        if paths.iter().any(|path| path == expected) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    false
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_value_with_separators_is_one_encoded_path_segment() -> TestResult {
    let (op, _) = fake_op()?;
    let (plain, plain_seen) = serve_recorder().await?;
    let (oauth, oauth_seen) = serve_recorder().await?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\n\
         [servers.slash]\n\
         url = \"http://{plain}/mcp/{{{{ op://Dev/slashkey/credential }}}}/rpc\"\n\n\
         [servers.backslash]\n\
         url = \"http://{plain}/mcp/{{{{ op://Dev/backslash/credential }}}}/rpc\"\n\n\
         [servers.anonymous]\n\
         url = \"http://{oauth}/mcp/{{{{ op://Dev/slashkey/credential }}}}/rpc\"\n\
         oauth = true\n",
        op = op.display(),
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    // the value never splits the path, with or without a login, and the
    // servers still report nothing of it
    assert!(path_seen(&plain_seen, "/mcp/zk%2F9f3a71c2d8b4e6/rpc").await);
    assert!(path_seen(&plain_seen, "/mcp/zk%5C9f3a71c2d8b4e6/rpc").await);
    assert!(path_seen(&oauth_seen, "/mcp/zk%2F9f3a71c2d8b4e6/rpc").await);
    let report = serde_json::to_string(&harness.app.gateway().report())?;
    assert!(!report.contains("9f3a71c2d8b4e6"), "{report}");

    harness.stop().await
}

#[tokio::test]
async fn a_url_value_with_separators_is_redacted_in_every_encoding() -> TestResult {
    use codemode_mcp::secrets::{OnePassword, Redactor};

    let (op, _) = fake_op()?;
    let onepassword = OnePassword::new(op.display().to_string());
    let resolved = onepassword
        .resolve_url("https://example.invalid/mcp/{{ op://Dev/slashkey/credential }}/rpc")
        .await?;
    assert_eq!(
        resolved.url,
        "https://example.invalid/mcp/zk%2F9f3a71c2d8b4e6/rpc"
    );

    let redactor = Redactor::default();
    redactor.add(resolved.secrets);
    for text in [
        resolved.url.as_str(),
        "key zk/9f3a71c2d8b4e6",
        "key ZK%2f9F3A71C2D8B4E6",
    ] {
        let scrubbed = redactor.scrub(text);
        assert!(scrubbed.contains("[redacted]"), "{scrubbed}");
        assert!(
            !scrubbed.to_lowercase().contains("9f3a71c2d8b4e6"),
            "{scrubbed}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_url_held_in_1password_connects_and_stays_out_of_every_surface() -> TestResult {
    let logs = capture_logs();
    let (op, log) = fake_op()?;
    let address = serve_keyed_endpoint().await?;
    // a port nobody listens on, so connecting fails with the URL in the error
    let closed = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    std::fs::write(
        op.with_file_name("url"),
        format!("http://{address}/mcp/{URL_KEY}/rpc"),
    )?;
    std::fs::write(
        op.with_file_name("dead-url"),
        format!("http://{closed}/mcp/{URL_KEY}/rpc"),
    )?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\
         identity_file = \"{identity}\"\n\n\
         [servers.whole]\n\
         url = \"{{{{ op://Dev/mcpurl/credential }}}}\"\n\n\
         [servers.embedded]\n\
         url = \"http://{address}/mcp/{{{{ op://Dev/urlkey/credential }}}}/rpc\"\n\n\
         [servers.dead]\n\
         url = \"{{{{ op://Dev/deadurl/credential }}}}\"\n",
        op = op.display(),
        identity = op.with_file_name("gateway.key").display(),
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    // both forms reach the endpoint that exists at the resolved URL only
    let mut called = Value::Null;
    for _ in 0..40 {
        let result = execute(
            &harness.client,
            "[await whole_hello(), await embedded_hello()]",
        )
        .await?;
        called = serde_json::from_str(&text_of(&result)).unwrap_or(Value::Null);
        if called["result"] == json!(["hello", "hello"]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(called["result"], json!(["hello", "hello"]), "{called}");
    assert_eq!(reads(&log, "op://Dev/mcpurl/credential"), 1);
    assert_eq!(reads(&log, "op://Dev/urlkey/credential"), 1);

    // a refused connection prints the URL in the client's own error text,
    // which the report carries in full
    let mut dead = Value::Null;
    for _ in 0..40 {
        let report = serde_json::to_value(harness.app.gateway().report())?;
        dead = report
            .as_array()
            .and_then(|servers| servers.iter().find(|server| server["name"] == "dead"))
            .cloned()
            .unwrap_or(Value::Null);
        if dead["state"] == "unavailable" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(dead["state"], "unavailable", "{dead}");
    let error = dead["error"].as_str().unwrap_or_default();
    assert!(!error.is_empty(), "{dead}");
    assert!(!error.contains(URL_KEY), "{dead}");

    // the companion allow list names the references, never their values
    let (status, invite) = harness
        .admin_json("/admin/companion/invite", &Value::Null)
        .await?;
    assert_eq!(status, 200, "{invite}");
    assert_eq!(
        invite["references"],
        json!([
            "op://Dev/deadurl/credential",
            "op://Dev/mcpurl/credential",
            "op://Dev/urlkey/credential"
        ])
    );
    assert!(!invite.to_string().contains(URL_KEY), "{invite}");

    let logged = logs.text();
    assert!(logged.contains("upstream connection failed"), "{logged}");
    assert!(!logged.contains(URL_KEY), "{logged}");
    assert!(!harness.state_holds(URL_KEY));

    harness.stop().await
}

#[test]
fn redacting_logs_scrubs_a_registered_secret_from_a_written_line() -> TestResult {
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    let secret = "log-writer-secret-5d1c7e";
    codemode_mcp::secrets::Redactor::shared(&codemode_mcp::config::Config::default())
        .add([secret.to_owned()]);
    let capture = LogCapture::default();
    let logs = codemode_mcp::secrets::redacting_logs(capture.clone());

    let mut writer = logs.make_writer();
    // a writer that is given a line in pieces must not leak the secret
    let (head, tail) = secret.split_at(secret.len() / 2);
    write!(writer, "connecting to https://host/{head}")?;
    writeln!(writer, "{tail}/mcp failed")?;
    writer.flush()?;

    let written = capture.text();
    assert!(!written.contains(secret), "{written}");
    assert!(written.contains("https://host/[redacted]/mcp"), "{written}");

    Ok(())
}

#[tokio::test]
async fn a_zoho_url_redacts_its_key_but_not_its_public_path_words() -> TestResult {
    use codemode_mcp::secrets::{OnePassword, Redactor};

    let (op, _) = fake_op()?;
    let onepassword = OnePassword::new(op.display().to_string());
    let unrelated = "Could not parse the message: messages are realms apart";

    // a key embedded in the url is the only secret
    let embedded = onepassword
        .resolve_url("https://srv-1234.zohomcp.com/mcp/{{ op://Dev/urlkey/credential }}/message")
        .await?;
    let redactor = Redactor::default();
    redactor.add(embedded.secrets);
    assert_eq!(redactor.scrub(unrelated), unrelated);
    let leaked = redactor.scrub(&format!("GET /mcp/{URL_KEY}/message failed"));
    assert_eq!(leaked, "GET /mcp/[redacted]/message failed");
    // an issuer sharing public words is not a leak, one holding the key is
    assert!(!Redactor::holds_any(
        "https://id.example.com/realms/production-us-east-1",
        &embedded.keys
    ));
    assert!(Redactor::holds_any(
        &format!("https://id.example.com/{URL_KEY}/authorize"),
        &embedded.keys
    ));

    // a url that is a reference alone is a secret whole
    let url = format!("https://srv-1234.zohomcp.com/mcp/{URL_KEY}/message");
    std::fs::write(op.with_file_name("url"), &url)?;
    let whole = onepassword
        .resolve_url("{{ op://Dev/mcpurl/credential }}")
        .await?;
    let redactor = Redactor::default();
    redactor.add(whole.secrets);
    assert_eq!(redactor.scrub(unrelated), unrelated);
    let leaked = redactor.scrub(&format!("GET {url} failed; path /mcp/{URL_KEY}/message"));
    assert!(!leaked.contains(URL_KEY), "{leaked}");

    Ok(())
}

#[tokio::test]
async fn a_url_key_too_short_to_redact_is_refused() -> TestResult {
    use codemode_mcp::secrets::{OnePassword, SecretError};

    let (op, _) = fake_op()?;
    let onepassword = OnePassword::new(op.display().to_string());

    let refused = onepassword
        .resolve_url("https://example.invalid/mcp/{{ op://Dev/shortkey/credential }}")
        .await;
    assert!(matches!(refused, Err(SecretError::UrlValueTooShort)));

    Ok(())
}

#[tokio::test]
async fn a_decoded_form_of_an_encoded_url_key_is_redacted() -> TestResult {
    use codemode_mcp::secrets::{OnePassword, Redactor};

    let (op, _) = fake_op()?;
    let onepassword = OnePassword::new(op.display().to_string());

    // the value is itself percent-encoded, as some providers store keys
    let resolved = onepassword
        .resolve_url("https://example.invalid/mcp?k={{ op://Dev/encodedkey/credential }}")
        .await?;
    let redactor = Redactor::default();
    redactor.add(resolved.secrets);
    assert_eq!(
        redactor.scrub("bad key zk+9f3a71c2=d8b4e6"),
        "bad key [redacted]"
    );

    Ok(())
}

#[tokio::test]
async fn a_form_decoded_query_value_is_redacted() -> TestResult {
    use codemode_mcp::secrets::{OnePassword, Redactor};

    let (op, _) = fake_op()?;
    let onepassword = OnePassword::new(op.display().to_string());

    // a library that form-decodes the query turns `+` into a space
    let resolved = onepassword
        .resolve_url("https://example.invalid/mcp?k={{ op://Dev/symbolkey/credential }}")
        .await?;
    let redactor = Redactor::default();
    redactor.add(resolved.secrets);
    assert_eq!(
        redactor.scrub("bad key zk 9f3a71c2=d8b4e6"),
        "bad key [redacted]"
    );
    assert!(!redactor.scrub(&resolved.url).contains("9f3a71c2"));

    Ok(())
}
