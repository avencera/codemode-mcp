//! What survives a daemon restart: results, approvals, grants, parked
//! executions, enrollment links, admin actions and ceremonies. Each test
//! stops the daemon and starts another on the same state directory

use std::{
    error::Error,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use codemode_mcp::{
    approvals::Choice,
    durable::{Durable, Sensitivity},
    executions::WaitResult,
    store::{Store, approvals::NewApproval, now_ms, parked::ParkedPayload},
    usage::{Caller, Classification, EXEC_CLIENT, ExecutionRecord},
};
use serde_json::{Value, json};
use webauthn_rs::prelude::{RequestChallengeResponse, Url};

use tokio::io::{AsyncBufReadExt, BufReader};

use super::harness::{
    Harness, ORIGIN, Setup, Stop, TestResult, approval_id, call, connect_as, execute, monty_worker,
    temp_state_dir, text_of,
};

/// `add` asks and the server is not sensitive, so a parked script waiting on
/// it is stored and can resume
const PLAIN_ASK: &str = "sensitive = false\ntools.add.policy = \"ask\"";
const ADD: &str = "int(await fixture_add(a=1, b=2))";

async fn harness_with(
    server: &str,
    extra: &str,
    limits: &str,
) -> Result<Option<Harness>, Box<dyn Error>> {
    Harness::with(Setup {
        limits,
        server,
        extra,
        notify: true,
        ..Setup::default()
    })
    .await
}

fn json_of(text: &str) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(text)?)
}

fn execution_id(pending: &Value) -> Result<String, Box<dyn Error>> {
    Ok(pending["execution_id"]
        .as_str()
        .ok_or_else(|| format!("no execution_id in {pending}"))?
        .to_owned())
}

/// Parks a script on the `add` approval and restarts the daemon
async fn park_and_restart(harness: Harness, how: Stop) -> Result<(Harness, Value), Box<dyn Error>> {
    let pending = harness.execute_body(ADD).await?;
    assert_eq!(pending["status"], "pending", "{pending}");

    Ok((harness.restart(how).await?, pending))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_result_is_returned_by_wait_after_a_restart() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let executions = harness.app.executions();
    let id = executions.start("{\"answer\": 6 * 7}".to_owned(), Caller::default())?;
    executions.wait(&id, Duration::from_secs(10)).await;

    let harness = harness.restart(Stop::Crash).await?;
    let done = json_of(&text_of(&harness.wait_done(&id).await?))?;
    assert_eq!(done["result"]["answer"], 42, "{done}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parked_execution_resumes_after_a_restart_and_is_approved() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let (harness, pending) = park_and_restart(harness, Stop::Drain).await?;
    let id = approval_id(&pending)?;
    let execution = execution_id(&pending)?;

    // still waiting, and the page and the request are back
    let waiting = json_of(&text_of(
        &call(
            &harness.client,
            "wait",
            json!({ "execution_id": execution }),
        )
        .await?,
    ))?;
    assert_eq!(waiting["status"], "pending", "{waiting}");
    assert_eq!(
        waiting["approval_url"], pending["approval_url"],
        "{waiting}"
    );
    let page = harness
        .http
        .get(format!("{}/approve/{id}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 200);

    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &id, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    let done = json_of(&text_of(&harness.wait_done(&execution).await?))?;
    assert_eq!(done["result"], 3, "{done}");
    assert!(harness.app.store().parked_executions()?.is_empty());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parked_execution_denied_after_a_restart_gets_a_permission_error() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let (harness, pending) = park_and_restart(harness, Stop::Crash).await?;
    let id = approval_id(&pending)?;

    let (status, body) = harness
        .post_json(&format!("/approve/{id}/deny"), &json!({}))
        .await?;
    assert_eq!(status, 200, "{body}");
    let denied = harness.wait_done(&execution_id(&pending)?).await?;
    let text = text_of(&denied);
    assert_eq!(denied.is_error, Some(true), "{text}");
    assert!(text.contains("PermissionError"), "{text}");
    assert!(text.contains("denied on the approval page"), "{text}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parked_execution_expires_on_the_deadline_stored_before_the_restart() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "[approvals]\ntimeout_secs = 6", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let parked_at = Instant::now();
    let pending = harness.execute_body(ADD).await?;
    assert_eq!(pending["status"], "pending", "{pending}");

    tokio::time::sleep(Duration::from_secs(4)).await;
    let harness = harness.restart(Stop::Crash).await?;

    let expired = harness.wait_done(&execution_id(&pending)?).await?;
    let waited = parked_at.elapsed();
    let text = text_of(&expired);
    assert_eq!(expired.is_error, Some(true), "{text}");
    assert!(text.contains("PermissionError"), "{text}");
    assert!(text.contains("expired"), "{text}");
    // a timer started afresh at the restart could not fire before the
    // 4 s sleep, the boot and a whole 6 s timeout had passed
    assert!(
        waited < Duration::from_millis(8500),
        "expiry took {waited:?} after the park, so the stored deadline was ignored"
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_grant_made_before_a_restart_still_applies() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let first = harness.execute_body(ADD).await?;
    harness.app.approvals().decide(
        &approval_id(&first)?,
        Choice::Client(Duration::from_secs(15 * 60)),
    )?;
    harness.wait_done(&execution_id(&first)?).await?;

    let harness = harness.restart(Stop::Crash).await?;
    let covered = harness.execute_json(ADD).await?;

    assert_eq!(covered["result"], 3, "{covered}");
    assert!(harness.notifier.tool_requests().len() == 1);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_grant_made_before_a_restart_still_applies() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    let first = harness.execute_body(ADD).await?;
    let session = first["session"].as_str().ok_or("no session")?.to_owned();
    harness.app.approvals().decide(
        &approval_id(&first)?,
        Choice::Session(Duration::from_secs(15 * 60)),
    )?;
    harness.wait_done(&execution_id(&first)?).await?;

    let harness = harness.restart(Stop::Crash).await?;
    let covered = text_of(
        &call(
            &harness.client,
            "execute",
            json!({ "code": ADD, "session": session }),
        )
        .await?,
    );
    let covered = json_of(&covered)?;
    assert_eq!(covered["result"], 3, "{covered}");

    // the grant is the session's, not the client's
    let other = harness.execute_body(ADD).await?;
    assert_eq!(other["status"], "pending", "{other}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_execution_running_at_a_restart_is_interrupted_and_lists_its_calls() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let script = "total = await fixture_add(a=1, b=2)\n\
                  await fixture_slow_echo(text=\"late\", delay_ms=60000)";
    let pending = harness.execute_body(script).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let id = execution_id(&pending)?;
    // the first call is logged by the usage writer thread
    harness.app.usage().flush().await;

    let harness = harness.restart(Stop::Crash).await?;
    let result = harness.wait_done(&id).await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains("daemon restarted"), "{text}");
    assert!(text.contains("fixture"), "{text}");
    assert!(text.contains("add"), "{text}");
    assert!(text.contains("Writes may have happened"), "{text}");

    // counted in the review's data
    let interrupted: i64 = {
        let connection = codemode_mcp::store::open(harness.app.state_dir())?;
        connection.query_row(
            "SELECT COUNT(*) FROM executions WHERE outcome = 'interrupted'",
            (),
            |row| row.get(0),
        )?
    };
    assert_eq!(interrupted, 1);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_graceful_drain_lets_a_short_script_finish() -> TestResult {
    let Some(harness) = Harness::start("drain_secs = 20", "").await? else {
        return Ok(());
    };
    let executions = harness.app.executions();
    let id = executions.start(
        "await fixture_slow_echo(text=\"done\", delay_ms=1500)".to_owned(),
        Caller::default(),
    )?;

    let harness = harness.restart(Stop::Drain).await?;
    let done = json_of(&text_of(&harness.wait_done(&id).await?))?;
    assert_eq!(done["result"]["echoed"], "done", "{done}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drain_past_its_limit_interrupts_what_is_still_running() -> TestResult {
    let Some(harness) = Harness::start("drain_secs = 1", "").await? else {
        return Ok(());
    };
    let id = harness.app.executions().start(
        "await fixture_slow_echo(text=\"late\", delay_ms=60000)".to_owned(),
        Caller::default(),
    )?;

    let harness = harness.restart(Stop::Drain).await?;
    let text = text_of(&harness.wait_done(&id).await?);
    assert!(text.contains("daemon restarted"), "{text}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_drain_answers_waits_on_parked_executions_at_once() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    let pending = harness.execute_body(ADD).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let execution = execution_id(&pending)?;

    // a client long-polling while the user approves; the stop must answer
    // it with something resumable, not hold it past the server's shutdown
    let executions = harness.app.executions().clone();
    let waiting =
        tokio::spawn(async move { executions.wait(&execution, Duration::from_secs(60)).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    harness.app.drain().await;

    let answered = tokio::time::timeout(Duration::from_secs(5), waiting).await??;
    assert!(matches!(answered, WaitResult::Pending));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_draining_daemon_refuses_new_executions() -> TestResult {
    let Some(harness) = Harness::start("drain_secs = 5", "").await? else {
        return Ok(());
    };
    let id = harness.app.executions().start(
        "await fixture_slow_echo(text=\"x\", delay_ms=1500)".to_owned(),
        Caller::default(),
    )?;
    let app = harness.app.clone();
    let draining = tokio::spawn(async move { app.drain().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let refused = harness
        .app
        .executions()
        .start("1".to_owned(), Caller::default());
    let message = refused
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(message.contains("restarting"), "{message}");

    draining.await?;
    harness
        .app
        .executions()
        .wait(&id, Duration::from_secs(5))
        .await;
    harness.stop().await
}

/// Every byte the state directory holds, database and write-ahead log alike
fn state_bytes(directory: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_file() {
            all.extend(std::fs::read(path)?);
        }
    }

    Ok(all)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

const SECRET: &str = "[servers.secret]\n\
                      command = \"{fixture}\"\n\
                      sensitive = true\n\
                      tools.add.policy = \"ask\"\n\
                      tools.add.output = \"text\"";

#[tokio::test(flavor = "multi_thread")]
async fn nothing_sensitive_reaches_the_database_file() -> TestResult {
    let secret = SECRET.replace("{fixture}", env!("CARGO_BIN_EXE_codemode-fixture"));
    let Some(harness) = harness_with(PLAIN_ASK, &secret, "").await? else {
        return Ok(());
    };
    harness.enroll_passkey().await?;
    // the numbers are built at run time so the script text, which is kept,
    // does not hold them
    let plain = "int(await fixture_add(a=int(\"777\") * 10000 + 1234, b=1))";
    let hidden = "int(await secret_add(a=int(\"888\") * 10000 + 1234, b=1))";

    // finished in this process: the plain one is stored, the sensitive one
    // is not
    let mut hidden_id = String::new();
    for script in [plain, hidden] {
        let pending = harness.execute_body(script).await?;
        harness
            .app
            .approvals()
            .decide(&approval_id(&pending)?, Choice::Once)?;
        harness.wait_done(&execution_id(&pending)?).await?;
        hidden_id = execution_id(&pending)?;
    }
    // parked at a restart: the sensitive one has no dump to resume from
    let parked = harness.execute_body(hidden).await?;
    let parked_id = execution_id(&parked)?;
    let state_dir = harness.app.state_dir().clone();
    let approval = approval_id(&parked)?;
    let harness = harness.restart(Stop::Crash).await?;

    let bytes = state_bytes(&state_dir)?;
    // the control: the same kind of data is kept when it may be
    assert!(contains(&bytes, "7771234"), "plain arguments are stored");
    assert!(contains(&bytes, "7771235"), "plain results are stored");
    assert!(
        !contains(&bytes, "8881234"),
        "sensitive arguments reached the file"
    );
    assert!(
        !contains(&bytes, "8881235"),
        "sensitive results reached the file"
    );

    let result = harness.wait_done(&parked_id).await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains("sensitive state is not kept"), "{text}");
    assert!(text.contains("Re-run"), "{text}");

    // the sensitive script that finished is not "interrupted": telling an
    // agent to re-run it would repeat a finished write
    let finished = harness.wait_done(&hidden_id).await?;
    let text = text_of(&finished);
    assert_eq!(finished.is_error, Some(false), "{text}");
    assert!(text.contains("finished (ok)"), "{text}");
    assert!(text.contains("Do not re-run"), "{text}");
    assert!(!text.contains("interrupted"), "{text}");

    let page = harness
        .http
        .get(format!("{}/approve/{approval}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 410);
    assert!(page.text().await?.contains("withdrawn"));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_enrollment_link_made_before_a_restart_still_works() -> TestResult {
    let Some(harness) = harness_with("", "", "").await? else {
        return Ok(());
    };
    let (path, _) = harness.request_enrollment("phone").await?;

    let harness = harness.restart(Stop::Crash).await?;
    harness.register_at(&path).await?;
    assert_eq!(harness.app.passkeys().store().passkey_count()?, 1);

    // the link is single use, and only its hash was stored
    let again = harness
        .http
        .get(format!("{}{path}", harness.base()))
        .send()
        .await?;
    assert_eq!(again.status().as_u16(), 404);
    let token = path.rsplit('/').next().unwrap_or_default();
    let bytes = state_bytes(harness.app.state_dir())?;
    assert!(!contains(&bytes, token), "the raw token reached the file");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_actions_waiting_on_approval_are_performed_after_a_restart() -> TestResult {
    let Some(harness) = harness_with("", "", "").await? else {
        return Ok(());
    };
    let mut phone = harness.enroll_passkey().await?;
    let first_id = harness.app.passkeys().store().list_passkeys()?[0].id;

    // a second passkey waits for the first one's approval across a restart
    let (path, enrolled) = harness.request_enrollment("tablet").await?;
    let approval = approval_id(&json!({ "approval_url": enrolled["approval_url"] }))?;
    let harness = harness.restart(Stop::Crash).await?;
    let (status, body) = harness
        .approve_with_passkey(&mut phone, &approval, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut tablet = harness.register_at(&path).await?;
    assert_eq!(harness.app.passkeys().store().passkey_count()?, 2);

    // removing the first one is approved by the second, after a restart
    let (status, body) = harness
        .admin_json("/admin/passkey/remove", &json!({ "id": first_id }))
        .await?;
    assert_eq!(status, 200, "{body}");
    let removal = approval_id(&body)?;
    let harness = harness.restart(Stop::Crash).await?;
    let (status, body) = harness
        .approve_with_passkey(&mut tablet, &removal, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let left = harness.app.passkeys().store().list_passkeys()?;
    assert_eq!(left.len(), 1);
    assert!(left.iter().all(|passkey| passkey.id != first_id));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ceremony_started_before_a_restart_finishes_after_it() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let pending = harness.execute_body(ADD).await?;
    let id = approval_id(&pending)?;

    let (status, started) = harness
        .post_json(
            &format!("/approve/{id}/options"),
            &json!({ "choice": "once" }),
        )
        .await?;
    assert_eq!(status, 200, "{started}");
    let options: RequestChallengeResponse = serde_json::from_value(started["options"].clone())?;
    let credential = passkey
        .do_authentication(Url::parse(ORIGIN)?, options)
        .map_err(|error| format!("assertion failed: {error:?}"))?;

    let harness = harness.restart(Stop::Crash).await?;
    let (status, body) = harness
        .post_json(
            &format!("/approve/{id}/confirm"),
            &json!({ "ceremony": started["ceremony"], "credential": credential }),
        )
        .await?;
    assert_eq!(status, 200, "{body}");
    let done = json_of(&text_of(
        &harness.wait_done(&execution_id(&pending)?).await?,
    ))?;
    assert_eq!(done["result"], 3, "{done}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn two_store_handles_share_one_file() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    // the CLI opens the file beside the daemon and writes an execution row
    let cli = Store::open(harness.app.state_dir())?;
    cli.begin_execution("cli-run", now_ms(), &Caller::default(), "1 + 1")?;

    let daemon = harness.app.store().stored_execution("cli-run")?;
    assert!(daemon.is_some_and(|row| row.outcome == "running"));

    // and what the daemon writes is visible to it
    let id = harness
        .app
        .executions()
        .start("2 + 2".to_owned(), Caller::default())?;
    harness
        .app
        .executions()
        .wait(&id, Duration::from_secs(10))
        .await;
    assert!(
        cli.stored_execution(&id)?
            .is_some_and(|row| row.result.is_some())
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_started_script_has_a_row_before_it_ends() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let pending = harness
        .execute_body("await fixture_slow_echo(text=\"x\", delay_ms=5000)")
        .await?;
    let id = execution_id(&pending)?;

    let row = harness.app.store().stored_execution(&id)?;
    assert!(row.is_some_and(|row| row.outcome == "running"));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_is_down_at_boot_keeps_its_cached_tools() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    assert!(
        harness
            .app
            .gateway()
            .catalog()
            .entries()
            .iter()
            .any(|entry| entry.function == "fixture_add" && entry.available)
    );

    let harness = harness
        .restart_with(Stop::Crash, |config| {
            if let Some(server) = config.servers.get_mut("fixture") {
                server.command = Some("/nonexistent/codemode-fixture".to_owned());
            }
        })
        .await?;
    // the catalog is rebuilt in the background once the first attempt fails
    let mut shown = false;
    for _ in 0..50 {
        shown = harness
            .app
            .gateway()
            .catalog()
            .entries()
            .iter()
            .any(|entry| entry.function == "fixture_add" && !entry.available);
        if shown {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(shown, "the cached tools never reached the catalog");

    let result = call(
        &harness.client,
        "execute",
        json!({ "code": "await fixture_add(a=1, b=2)" }),
    )
    .await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains("unavailable"), "{text}");

    harness.stop().await
}

/// Config for the real binary on a state directory another daemon may hold:
/// both listeners on free ports, the fixture as the only upstream
fn cli_config(state: &Path, limits: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    let Some(worker) = monty_worker()? else {
        return Ok(None);
    };
    std::fs::create_dir_all(state)?;
    // beside the state directory, not in it, so the directory only holds
    // what the daemon wrote
    let path = state.with_extension("toml");
    std::fs::write(
        &path,
        format!(
            r#"
            listen = "127.0.0.1:0"
            admin_listen = "127.0.0.1:0"
            worker_path = "{worker}"
            state_dir = "{state}"
            public_origin = "{ORIGIN}"

            [notify]
            homebased_config = "/nonexistent/homebased.toml"

            [limits]
            execute_wait_secs = 1
            {limits}

            [servers.fixture]
            command = "{fixture}"
            "#,
            worker = worker.display(),
            state = state.display(),
            fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
        ),
    )?;

    Ok(Some(path))
}

fn codemode(config: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_codemode-mcp"));
    command
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .kill_on_drop(true);

    command
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_serve_on_the_state_directory_is_refused_and_changes_nothing() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let pending = harness.execute_body(ADD).await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let execution = execution_id(&pending)?;
    let approval = approval_id(&pending)?;
    // parked: the worker is released and the dump is stored
    for _ in 0..50 {
        if !harness.app.store().parked_executions()?.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(harness.app.store().parked_executions()?.len(), 1);

    let Some(config) = cli_config(harness.app.state_dir(), "")? else {
        return Ok(());
    };
    let second = tokio::time::timeout(
        Duration::from_secs(30),
        codemode(&config).arg("serve").output(),
    )
    .await??;
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!second.status.success(), "{stderr}");
    assert!(stderr.contains("another daemon owns"), "{stderr}");

    // nothing the first daemon waits for was touched
    let row = harness.app.store().stored_execution(&execution)?;
    assert!(row.is_some_and(|row| row.outcome == "running"));
    assert_eq!(harness.app.store().parked_executions()?.len(), 1);
    let page = harness
        .http
        .get(format!("{}/approve/{approval}", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 200);

    // and it carries on: the approval completes the script
    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &approval, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    let done = json_of(&text_of(&harness.wait_done(&execution).await?))?;
    assert_eq!(done["result"], 3, "{done}");
    let row = harness.app.store().stored_execution(&execution)?;
    assert!(row.is_some_and(|row| row.outcome == "ok"));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_first_terminal_outcome_of_an_execution_wins() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let store = harness.app.store();
    store.begin_execution("raced", now_ms(), &Caller::default(), "1")?;
    assert!(store.interrupt_execution("raced", false)?);

    // a task that outlived the interruption finishes late
    let record = ExecutionRecord {
        id: "raced".to_owned(),
        started_ms: now_ms(),
        caller: Caller::default(),
        script: "1".to_owned(),
        classification: Classification::ok(),
        duration: Duration::from_millis(5),
        result_bytes: 1,
    };
    store.finish_execution(
        &record,
        &Durable::gate(Sensitivity::PLAIN, || "1".to_owned()),
    )?;

    let row = store.stored_execution("raced")?;
    assert!(
        row.is_some_and(|row| row.outcome == "interrupted" && row.result.is_none()),
        "a late finish replaced the interrupted row"
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parked_row_can_be_claimed_once() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let store = harness.app.store();
    let payload = ParkedPayload {
        state: "{}".to_owned(),
        dump: vec![1, 2, 3],
        tag: vec![4],
    };
    store.put_parked(
        "claimed",
        now_ms(),
        &Durable::gate(Sensitivity::PLAIN, || payload),
    )?;

    assert!(store.delete_parked("claimed")?);
    assert!(!store.delete_parked("claimed")?);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resumed_execution_that_lost_its_claim_makes_no_call() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    let mut passkey = harness.enroll_passkey().await?;
    let (harness, pending) = park_and_restart(harness, Stop::Crash).await?;
    let execution = execution_id(&pending)?;

    // another process restored the session first and removed the row
    assert!(harness.app.store().delete_parked(&execution)?);
    let (status, body) = harness
        .approve_with_passkey(&mut passkey, &approval_id(&pending)?, "once")
        .await?;
    assert_eq!(status, 200, "{body}");

    let result = harness.wait_done(&execution).await?;
    let text = text_of(&result);
    assert_eq!(result.is_error, Some(true), "{text}");
    harness.app.usage().flush().await;
    assert!(
        harness
            .app
            .store()
            .upstream_calls_of(&execution)?
            .is_empty(),
        "the approved call reached the upstream twice"
    );

    harness.stop().await
}

#[test]
fn an_app_dropped_without_a_halt_leaves_parked_work_for_the_next_boot() -> TestResult {
    // the first daemon lives in a runtime of its own, which is dropped the
    // way a process exit drops it: its tasks are torn down with no halt
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let started = runtime.block_on(async {
        let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
            return Ok::<_, Box<dyn Error>>(None);
        };
        let passkey = harness.enroll_passkey().await?;
        let pending = harness.execute_body(ADD).await?;
        assert_eq!(pending["status"], "pending", "{pending}");
        for _ in 0..50 {
            if !harness.app.store().parked_executions()?.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(Some((harness.forget().await?, passkey, pending)))
    })?;
    drop(runtime);
    let Some((left, mut passkey, pending)) = started else {
        return Ok(());
    };

    let second = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    second.block_on(async {
        let harness = left.boot().await?;
        let execution = execution_id(&pending)?;
        let approval = approval_id(&pending)?;

        // still pending, not abandoned, and resumed rather than failed
        let waiting = json_of(&text_of(
            &call(
                &harness.client,
                "wait",
                json!({ "execution_id": execution }),
            )
            .await?,
        ))?;
        assert_eq!(waiting["status"], "pending", "{waiting}");
        let (status, body) = harness
            .approve_with_passkey(&mut passkey, &approval, "once")
            .await?;
        assert_eq!(status, 200, "{body}");
        let done = json_of(&text_of(&harness.wait_done(&execution).await?))?;
        assert_eq!(done["result"], 3, "{done}");

        harness.stop().await
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_request_nothing_took_up_is_withdrawn_at_boot() -> TestResult {
    let Some(harness) = harness_with(PLAIN_ASK, "", "").await? else {
        return Ok(());
    };
    // a request whose execution left no parked row: it can never be answered
    let now = now_ms();
    harness.app.store().create_approval(
        &NewApproval {
            id: "orphaned",
            created_ms: now,
            expires_ms: now + 600_000,
            caller: &Caller::default(),
            execution_id: "gone",
            server: "fixture",
            tool: "add",
            grant_mode: "session",
            action: None,
            notify: false,
        },
        &Durable::gate(Sensitivity::PLAIN, String::new),
    )?;

    let harness = harness.restart(Stop::Crash).await?;

    let connection = codemode_mcp::store::open(harness.app.state_dir())?;
    let decision: Option<String> = connection.query_row(
        "SELECT decision FROM approvals WHERE id = 'orphaned'",
        (),
        |row| row.get(0),
    )?;
    assert_eq!(decision.as_deref(), Some("abandoned"));
    let page = harness
        .http
        .get(format!("{}/approve/orphaned", harness.base()))
        .send()
        .await?;
    assert_eq!(page.status().as_u16(), 410);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cli_works_on_the_state_directory_beside_a_running_daemon() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let Some(config) = cli_config(harness.app.state_dir(), "")? else {
        return Ok(());
    };
    let script = harness.app.state_dir().with_extension("py");
    std::fs::write(&script, "40 + 2")?;

    let exec = tokio::time::timeout(
        Duration::from_secs(60),
        codemode(&config).arg("exec").arg(&script).output(),
    )
    .await??;
    let stdout = String::from_utf8_lossy(&exec.stdout);
    let stderr = String::from_utf8_lossy(&exec.stderr);
    assert!(exec.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("42"), "{stdout}");

    // the daemon sees the row the other process wrote
    let connection = codemode_mcp::store::open(harness.app.state_dir())?;
    let rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM executions WHERE client_name = ?1 AND outcome = 'ok'",
        turso::params![EXEC_CLIENT],
        |row| row.get(0),
    )?;
    assert_eq!(rows, 1);

    let stats = tokio::time::timeout(
        Duration::from_secs(30),
        codemode(&config).args(["stats", "--since", "1d"]).output(),
    )
    .await??;
    let report = String::from_utf8_lossy(&stats.stdout);
    assert!(stats.status.success(), "{report}");
    assert!(report.contains("executions 1"), "{report}");

    // and the daemon keeps working on the shared file
    let id = harness
        .app
        .executions()
        .start("6 * 7".to_owned(), Caller::default())?;
    harness
        .app
        .executions()
        .wait(&id, Duration::from_secs(10))
        .await;
    assert!(harness.app.store().stored_execution(&id)?.is_some());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_off_exec_of_another_process_survives_a_daemon_boot() -> TestResult {
    let Some(harness) = Harness::start("", "").await? else {
        return Ok(());
    };
    let Some(config) = cli_config(harness.app.state_dir(), "")? else {
        return Ok(());
    };
    let script = harness.app.state_dir().with_extension("py");
    std::fs::write(
        &script,
        "await fixture_slow_echo(text=\"cli\", delay_ms=4000)",
    )?;
    let exec = codemode(&config)
        .arg("exec")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // wait for its row
    let connection = codemode_mcp::store::open(harness.app.state_dir())?;
    let mut running = 0_i64;
    for _ in 0..100 {
        running = connection.query_row(
            "SELECT COUNT(*) FROM executions WHERE client_name = ?1 AND outcome = 'running'",
            turso::params![EXEC_CLIENT],
            |row| row.get(0),
        )?;
        if running > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(running, 1, "the exec run never recorded its start");

    // a daemon boots while it runs, and must not interrupt it
    let harness = harness.restart(Stop::Crash).await?;
    let interrupted: i64 = codemode_mcp::store::open(harness.app.state_dir())?.query_row(
        "SELECT COUNT(*) FROM executions WHERE outcome = 'interrupted'",
        (),
        |row| row.get(0),
    )?;
    assert_eq!(interrupted, 0, "the daemon interrupted a live exec run");

    let output = tokio::time::timeout(Duration::from_secs(60), exec.wait_with_output()).await??;
    assert!(output.status.success(), "{:?}", output);
    let outcome: String = codemode_mcp::store::open(harness.app.state_dir())?.query_row(
        "SELECT outcome FROM executions WHERE client_name = ?1",
        turso::params![EXEC_CLIENT],
        |row| row.get(0),
    )?;
    assert_eq!(outcome, "ok");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_lets_a_running_script_finish_and_flushes_the_log() -> TestResult {
    let state = temp_state_dir();
    let Some(config) = cli_config(&state, "drain_secs = 10")? else {
        return Ok(());
    };
    let mut child = codemode(&config)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let Some(stderr) = child.stderr.take() else {
        return Err("no stderr".into());
    };
    let mut lines = BufReader::new(stderr).lines();
    let listening = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await? {
            if line.contains("listening") {
                return Ok::<_, std::io::Error>(line);
            }
        }

        Err(std::io::Error::other("the daemon never listened"))
    })
    .await??;
    // keep reading, so the daemon never blocks on a full pipe
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    let port = listening
        .split("127.0.0.1:")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .ok_or("no port in the log line")?;

    let client = connect_as(&format!("http://127.0.0.1:{port}"), "sigterm-test/1.0").await?;
    let pending = serde_json::from_str::<Value>(&text_of(
        &execute(
            &client,
            "await fixture_slow_echo(text=\"done\", delay_ms=2000)",
        )
        .await?,
    ))?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let execution = execution_id(&pending)?;

    let pid = child.id().and_then(|pid| i32::try_from(pid).ok());
    let pid = pid
        .and_then(rustix::process::Pid::from_raw)
        .ok_or("no pid")?;
    let sent = Instant::now();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;

    let status = tokio::time::timeout(Duration::from_secs(15), child.wait()).await??;
    assert!(status.success(), "{status}");
    assert!(
        sent.elapsed() < Duration::from_secs(10),
        "the daemon outlived its drain"
    );
    let _ = client.cancel().await;

    let connection = codemode_mcp::store::open(&state)?;
    let outcome: String = connection.query_row(
        "SELECT outcome FROM executions WHERE id = ?1",
        turso::params![execution.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(outcome, "ok");
    // the upstream call finished during the drain, a moment before the exit
    let calls: i64 = connection.query_row(
        "SELECT COUNT(*) FROM upstream_calls WHERE execution_id = ?1",
        turso::params![execution.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(calls, 1, "the usage log was not flushed at the exit");
    drop(connection);
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_file(&config);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_results_and_over_budget_results_lose_their_payload_but_not_their_row() -> TestResult
{
    let Some(harness) =
        Harness::start("result_ttl_secs = 2\nmax_retained_result_bytes = 400", "").await?
    else {
        return Ok(());
    };
    let executions = harness.app.executions();
    let store = harness.app.store();
    // each result is about 300 bytes; two do not fit in 400
    let mut ids = Vec::new();
    for _ in 0..2 {
        let id = executions.start("\"x\" * 300".to_owned(), Caller::default())?;
        executions.wait(&id, Duration::from_secs(10)).await;
        ids.push(id);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        store
            .stored_execution(&ids[0])?
            .is_some_and(|row| row.result.is_some()),
        "the first result was stored"
    );

    // over the byte cap: the oldest payload goes, the newest stays
    executions.purge_now();
    let first = store.stored_execution(&ids[0])?;
    let second = store.stored_execution(&ids[1])?;
    assert!(
        first.is_some_and(|row| row.result.is_none() && row.outcome == "ok"),
        "the oldest result kept its payload or lost its row"
    );
    assert!(second.is_some_and(|row| row.result.is_some()));

    // past the TTL: the last payload goes too, and the audit row stays
    tokio::time::sleep(Duration::from_millis(2200)).await;
    executions.purge_now();
    let second = store.stored_execution(&ids[1])?;
    assert!(
        second.is_some_and(|row| row.result.is_none() && row.outcome == "ok"),
        "the expired result kept its payload or lost its row"
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_boot_purges_results_that_expired_while_the_daemon_was_down() -> TestResult {
    let Some(harness) = Harness::start("result_ttl_secs = 1", "").await? else {
        return Ok(());
    };
    let id = harness
        .app
        .executions()
        .start("40 + 2".to_owned(), Caller::default())?;
    harness
        .app
        .executions()
        .wait(&id, Duration::from_secs(10))
        .await;
    assert!(
        harness
            .app
            .store()
            .stored_execution(&id)?
            .is_some_and(|row| row.result.is_some())
    );

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let harness = harness.restart(Stop::Crash).await?;

    let row = harness.app.store().stored_execution(&id)?;
    assert!(row.is_some_and(|row| row.result.is_none() && row.outcome == "ok"));

    harness.stop().await
}
