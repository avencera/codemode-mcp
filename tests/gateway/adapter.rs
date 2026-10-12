//! The homebased adapter behind the gateway, driven by real scripts against
//! a fake homebased CLI that records what it was asked

use std::{error::Error, path::PathBuf, time::Duration};

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};

use super::harness::{Harness, Setup, TestResult, temp_state_dir, text_of};

const THREAD: &str = "11111111-2222-4333-8444-555555555555";
const UNKNOWN_THREAD: &str = "00000000-0000-4000-8000-000000000000";
const AFTER: &str = "01a10000-0000-7000-8000-000000000001";

struct Fake {
    log: PathBuf,
}

impl Fake {
    fn new() -> Self {
        Self {
            log: temp_state_dir().with_extension("log"),
        }
    }

    /// Server table running the adapter against the fake
    fn server_config(&self) -> String {
        format!(
            "[servers.homebased]\n\
             command = \"{adapter}\"\n\
             args = [\"adapter\", \"homebased\", \"--homebased-bin\", \"{fake}\"]\n\
             env = {{ FAKE_HOMEBASED_LOG = \"{log}\", HOMEBASED_TASK_ID = \"leaked\" }}\n",
            adapter = env!("CARGO_BIN_EXE_codemode-mcp"),
            fake = env!("CARGO_BIN_EXE_codemode-fake-homebased"),
            log = self.log.display(),
        )
    }

    fn calls(&self) -> Result<Vec<Value>, Box<dyn Error>> {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();

        Ok(text
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?)
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.log);
    }
}

fn argv(call: &Value) -> Vec<&str> {
    call["argv"]
        .as_array()
        .map(|args| args.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn homebased_tools_map_to_argv_and_specs() -> TestResult {
    let fake = Fake::new();
    let extra = fake.server_config();
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    let script = format!(
        r#"import asyncio
listed, status = await asyncio.gather(
    homebased_task_list(status=["running", "queued"], thread="{THREAD}"),
    homebased_daemon_status(),
)
submitted = await homebased_task_submit_agent(
    thread="{THREAD}", name="review", cwd="/tmp", agent="claude",
    prompt="Review the diff.\nReport findings.", model="opus", after=["{AFTER}"],
)
again = await homebased_task_submit_agent(
    thread="{THREAD}", name="review", cwd="/tmp", agent="claude",
    prompt="Review the diff.\nReport findings.", model="opus", after=["{AFTER}"],
    request_id=submitted["request_id"], dry_run=True,
)
command = await homebased_task_submit_command(
    thread="{THREAD}", name="build", cwd="/tmp", command=["cargo", "build", "--release"],
)
log = await homebased_task_log(id="{AFTER}")
[listed, status, submitted, again, command, log]"#
    );
    let body = harness.execute_json(&script).await?;
    let [listed, status, submitted, again, command, _log] =
        body["result"].as_array().ok_or("no result")?.as_slice()
    else {
        return Err(format!("unexpected result {body}").into());
    };
    assert_eq!(listed["tasks"], json!([]), "{body}");
    assert_eq!(status["socket"], "up", "{body}");
    let request_id = submitted["request_id"].as_str().ok_or("no request_id")?;
    assert!(uuid::Uuid::parse_str(request_id).is_ok(), "{submitted}");
    assert_eq!(submitted["status"], "queued", "{submitted}");
    assert_eq!(again["request_id"], request_id, "{again}");
    assert_ne!(command["request_id"], request_id, "{command}");

    let calls = fake.calls()?;
    let find = |words: &[&str]| {
        calls
            .iter()
            .filter(|call| {
                let args = argv(call);
                words.iter().all(|word| args.contains(word))
            })
            .cloned()
            .collect::<Vec<Value>>()
    };

    let list = &find(&["list"])[0];
    assert_eq!(
        argv(list),
        [
            "--json",
            "task",
            "list",
            "--status=running,queued",
            &format!("--thread={THREAD}")
        ]
    );
    // the adapter acts for many sessions, so it never passes its own
    // caller identity on
    assert!(calls.iter().all(|call| call["task_id_env"].is_null()));

    let submits = find(&["submit"]);
    assert_eq!(submits.len(), 3);
    let agent = &submits[0];
    assert_eq!(
        argv(agent),
        [
            "--json",
            "task",
            "submit",
            "--spec=-",
            &format!("--request-id={request_id}")
        ]
    );
    let spec = &agent["spec"];
    assert_eq!(spec["api_version"], 1);
    assert_eq!(spec["thread"], THREAD);
    assert_eq!(spec["after"], json!([AFTER]));
    assert_eq!(spec["workload"]["type"], "agent");
    assert_eq!(spec["workload"]["agent"], "claude");
    assert_eq!(spec["workload"]["model"], "opus");
    assert!(spec["workload"].get("prompt").is_none(), "{spec}");
    let file = &agent["files"][0];
    assert_eq!(file["text"], "Review the diff.\nReport findings.");
    assert_eq!(file["mode"], "600");
    let prompt_path = file["path"].as_str().ok_or("no prompt path")?;
    assert!(
        !std::path::Path::new(prompt_path).exists(),
        "prompt file left behind"
    );

    assert!(argv(&submits[1]).contains(&"--dry-run"));
    assert!(argv(&submits[1]).contains(&format!("--request-id={request_id}").as_str()));
    assert_eq!(
        submits[2]["spec"]["workload"],
        json!({ "type": "task", "command": ["cargo", "build", "--release"] })
    );
    let log = &find(&["log"])[0];
    assert_eq!(argv(log)[4], "--tail=200");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn homebased_errors_and_bad_arguments_reach_the_script() -> TestResult {
    let fake = Fake::new();
    let extra = fake.server_config();
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    let script = format!(
        r#"async def attempt(call) -> str:
    try:
        await call
        return "ok"
    except Exception as error:
        return str(error)

[
    await attempt(homebased_task_submit_agent(
        thread="{UNKNOWN_THREAD}", name="x", cwd="/tmp", agent="codex", prompt="p",
    )),
    await attempt(homebased_task_cancel(id="--yes")),
    await attempt(homebased_message_send(task="{AFTER}", worker="{AFTER}", message="hi")),
    await attempt(homebased_task_submit_command(thread="{THREAD}", name="x", cwd="/tmp", command=[])),
    await attempt(homebased_message_send(task="{AFTER}", message="hi")),
    await attempt(homebased_task_submit_agent(
        thread="{THREAD}", name="x", cwd="/tmp", agent="claude", prompt="p",
        extra_args=["--settings", "/tmp/hooks.json"],
    )),
]"#
    );
    let body = harness.execute_json(&script).await?;
    let results: Vec<&str> = body["result"]
        .as_array()
        .ok_or("no result")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(results.len(), 6, "{body}");
    assert!(
        results[0].contains("homebased error unknown_thread (exit 2, retryable: false)"),
        "{body}"
    );
    assert!(results[1].contains("must be a full UUID"), "{body}");
    assert!(results[2].contains("exactly one of"), "{body}");
    assert!(results[3].contains("non-empty program"), "{body}");
    assert_eq!(results[4], "ok", "{body}");
    assert!(
        results[5].contains("only accepts reasoning-effort flags"),
        "{body}"
    );

    // refused arguments never reached homebased
    let calls = fake.calls()?;
    assert_eq!(calls.len(), 2, "{calls:?}");
    let message = argv(&calls[1]);
    assert_eq!(
        &message[..4],
        ["--json", "message", "send", &format!("--task={AFTER}")]
    );
    assert_eq!(message[4], "--message=hi");
    assert!(message[5].starts_with("--message-id="));

    harness.stop().await
}

/// Read-only calls against the real homebased, when it is installed
#[tokio::test(flavor = "multi_thread")]
async fn real_homebased_answers_read_only_calls() -> TestResult {
    let installed = std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join("homebased").is_file())
    });
    if !installed {
        eprintln!("skipping: homebased is not on PATH");

        return Ok(());
    }

    let command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_codemode-mcp")).configure(|command| {
            command.args([
                "--config",
                "/nonexistent/codemode.toml",
                "adapter",
                "homebased",
            ]);
        });
    let client = ().serve(TokioChildProcess::new(command)?).await?;
    for tool in ["daemon_status", "task_list"] {
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            client.call_tool(CallToolRequestParams::new(tool)),
        )
        .await??;
        let text = text_of(&result);
        assert_eq!(result.is_error, Some(false), "{tool}: {text}");
        let value: Value = serde_json::from_str(&text)?;
        assert_eq!(value["api_version"], 1, "{tool}: {text}");
    }
    client.cancel().await?;

    Ok(())
}
