//! `{{ op://... }}` references in server config, read through a fake `op`

use std::{error::Error, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

use serde_json::Value;

use super::harness::{Harness, Setup, TestResult, execute, temp_state_dir, text_of};

pub(super) const VALUE: &str = "value-from-1password";

/// A stand-in for the 1Password CLI that knows one item and logs each read
pub(super) fn fake_op() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let log = directory.join("reads.log");
    let program = directory.join("op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             echo \"$3\" >> '{log}'\n\
             [ \"$1 $2\" = 'read --no-newline' ] || exit 2\n\
             case \"$3\" in\n\
               op://Dev/fixture/credential) printf '{VALUE}' ;;\n\
               op://Dev/big/credential) head -c 70000 /dev/zero | tr '\\0' a ;;\n\
               *) echo \"[ERROR] could not read secret '$3': no item matched\" >&2; exit 1 ;;\n\
             esac\n",
            log = log.display(),
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
