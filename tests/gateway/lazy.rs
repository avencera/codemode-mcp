//! `lazy` servers: no process until a call needs one, stopped again once idle

use std::{error::Error, time::Duration};

use serde_json::Value;

use super::harness::{Harness, Setup, Stop, TestResult};

async fn state(harness: &Harness, server: &str) -> Result<String, Box<dyn Error>> {
    let health: Value = harness
        .http
        .get(format!("{}/healthz", harness.base()))
        .send()
        .await?
        .json()
        .await?;
    let found = health["upstreams"]
        .as_array()
        .and_then(|upstreams| upstreams.iter().find(|upstream| upstream["name"] == server))
        .ok_or(format!("{server} missing from /healthz"))?;

    Ok(found["state"].as_str().unwrap_or_default().to_owned())
}

async fn wait_for_state(harness: &Harness, server: &str, wanted: &str) -> TestResult {
    let mut last = String::new();
    for _ in 0..80 {
        last = state(harness, server).await?;
        if last == wanted {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(format!("{server} never became {wanted}; last {last}").into())
}

async fn pid(harness: &Harness) -> Result<i64, Box<dyn Error>> {
    let body = harness
        .execute_json("(await fixture_pid())[\"pid\"]")
        .await?;

    Ok(body["result"].as_i64().ok_or(format!("no pid in {body}"))?)
}

/// Processes whose command line contains `pattern`
fn matching(pattern: &str) -> usize {
    std::process::Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).lines().count())
        .unwrap_or(0)
}

fn running(pid: i64) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

#[tokio::test(flavor = "multi_thread")]
async fn lazy_servers_start_on_a_call_and_stop_when_idle() -> TestResult {
    // a launcher that leaves a child behind, as `uvx` or `npx` can
    let marker = format!("sleep 9{}", std::process::id());
    let extra = format!(
        "[servers.wrapped]\n\
         command = \"/bin/sh\"\n\
         args = [\"-c\", \"{marker} & exec {fixture}\"]\n\
         lazy = true\n\
         idle_secs = 2\n",
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let Some(harness) = Harness::with(Setup {
        server: "lazy = true\nidle_secs = 1",
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    // nothing was cached yet, so the first boot connects to learn the tools,
    // then goes idle like any other quiet spell
    assert_eq!(matching(&marker), 1, "the launcher's child never started");
    wait_for_state(&harness, "fixture", "idle").await?;

    let first = pid(&harness).await?;
    assert!(running(first));
    wait_for_state(&harness, "fixture", "idle").await?;
    for _ in 0..50 {
        if !running(first) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !running(first),
        "the idle server's process is still running"
    );

    // the idle stop ends the whole group, not only the launcher
    wait_for_state(&harness, "wrapped", "idle").await?;
    for _ in 0..50 {
        if matching(&marker) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        matching(&marker),
        0,
        "the launcher's child outlived the idle stop"
    );

    // with the tool list cached, a restart starts no process until a call,
    // and calls that arrive together share one start
    let harness = harness.restart(Stop::Drain).await?;
    assert_eq!(state(&harness, "fixture").await?, "idle");
    let started = std::time::Instant::now();
    let body = harness
        .execute_json(
            "import asyncio\n\
             answers = await asyncio.gather(fixture_pid(), fixture_pid(), fixture_pid())\n\
             [answer[\"pid\"] for answer in answers]",
        )
        .await?;
    let pids: Vec<i64> = body["result"]
        .as_array()
        .ok_or(format!("no pids in {body}"))?
        .iter()
        .filter_map(Value::as_i64)
        .collect();
    assert_eq!(pids.len(), 3, "{body}");
    assert!(pids.iter().all(|pid| *pid == pids[0]), "{body}");
    assert_ne!(pids[0], first);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the woken calls stalled"
    );

    harness.stop().await
}
