//! Stand-in for the homebased CLI in the adapter tests
//!
//! Appends one JSON line per call to `$FAKE_HOMEBASED_LOG` with the argv,
//! stdin, the caller-identity environment it saw, and the contents and
//! mode of any prompt or message file, then answers like homebased does

use std::{io::Read, os::unix::fs::PermissionsExt};

use serde_json::{Value, json};

/// Thread id the fake treats as unknown, to exercise error mapping
const UNKNOWN_THREAD: &str = "00000000-0000-4000-8000-000000000000";

fn file_entry(path: &str) -> Value {
    let mode = std::fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777)
        .unwrap_or(0);

    json!({
        "path": path,
        "text": std::fs::read_to_string(path).ok(),
        "mode": format!("{mode:o}"),
    })
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin = String::new();
    if argv.iter().any(|arg| arg == "--spec=-") {
        let _ = std::io::stdin().read_to_string(&mut stdin);
    }
    let spec: Value = serde_json::from_str(&stdin).unwrap_or(Value::Null);

    let mut files = Vec::new();
    if let Some(path) = spec["workload"]["prompt_file"].as_str() {
        files.push(file_entry(path));
    }
    for arg in &argv {
        if let Some(path) = arg.strip_prefix("--message-file=") {
            files.push(file_entry(path));
        }
    }
    let record = json!({
        "argv": argv,
        "spec": spec,
        "files": files,
        "task_id_env": std::env::var("HOMEBASED_TASK_ID").ok(),
    });
    if let Ok(path) = std::env::var("FAKE_HOMEBASED_LOG") {
        use std::io::Write;
        if let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            // one write per line, so concurrent calls never interleave
            let _ = log.write_all(format!("{record}\n").as_bytes());
        }
    }

    let words: Vec<&str> = argv
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .map(String::as_str)
        .collect();
    if spec["thread"] == UNKNOWN_THREAD {
        eprintln!(
            "{}",
            json!({ "api_version": 1, "error": {
                "code": "unknown_thread",
                "message": "spec field thread names no session on this machine",
                "retryable": false,
            }})
        );
        std::process::exit(2);
    }

    let request_id = argv
        .iter()
        .find_map(|arg| arg.strip_prefix("--request-id="))
        .unwrap_or("01a10000-0000-7000-8000-0000000000aa");
    let dry_run = argv.iter().any(|arg| arg == "--dry-run");

    let answer = match words.as_slice() {
        ["daemon", "status"] => daemon_status(),
        ["task", "list"] => task_list(),
        ["task", "show", id] => task_show(id),
        ["task", "log", id] => task_log(id),
        ["task", "usage"] => task_usage(),
        ["fleet", "machines"] => fleet_machines(),
        ["task", "submit"] if dry_run => dry_run_answer(&spec),
        ["task", "submit"] | ["task", "followup", _] => submit_answer(request_id),
        ["task", "cancel", id] => json!({ "api_version": 1, "id": id, "status": "cancelled" }),
        ["message", "send"] => message_answer(&argv),
        _ => json!({ "api_version": 1, "ok": true }),
    };
    println!("{answer}");
}

// the answers below are trimmed copies of real `homebased --json` output,
// so the adapter's declared schemas are checked against what the CLI prints

const MACHINE: &str = "01a0d11a-c5ad-71c2-8250-0cb4c7b5b135";
const SUCCEEDED_TASK: &str = "01a13278-e978-7336-90e9-8873e9cce4f6";
const FAILED_TASK: &str = "01a1112c-3959-72b4-85b8-3f3de18d9348";

fn daemon_status() -> Value {
    json!({
        "api_version": 1,
        "home": "/Users/me/.local/state/homebased",
        "in_flight": 0,
        "socket": "up",
        "web": "http://0.0.0.0:7677",
    })
}

fn task_list() -> Value {
    json!({
        "api_version": 1,
        "tasks": [
            {
                "callback": "sent",
                "cancel_requested_at": null,
                "check_timeout": "pending",
                "created_at": "2026-10-12T23:35:47.320Z",
                "cwd": "/Users/me/work/cove",
                "execution_machine": MACHINE,
                "exit_reason": { "code": 0, "kind": "exit" },
                "id": SUCCEEDED_TASK,
                "name": "review address grouping (grok)",
                "origin_machine": MACHINE,
                "pid": null,
                "project_root": "/Users/me/work/cove",
                "status": "succeeded",
                "thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
                "timeout_secs": 3600,
                "updated_at": "2026-10-12T23:49:48.097Z",
                "workload": { "agent": "grok", "model": "grok-4.7", "type": "agent" },
            },
            {
                "after": [{ "outcome": "cancelled", "state": "ended", "task": SUCCEEDED_TASK }],
                "callback": "sent",
                "cancel_requested_at": null,
                "chain": { "id": SUCCEEDED_TASK, "outcome": "cancelled", "run": 5, "runs": 5, "state": "ended" },
                "check_timeout": "pending",
                "created_at": "2026-10-12T23:40:01.000Z",
                "cwd": "/Users/me/work/cove",
                "exit_reason": { "code": 1, "kind": "exit" },
                "id": FAILED_TASK,
                "name": "build",
                "pid": null,
                "status": "failed",
                "thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
                "timeout_secs": 3600,
                "updated_at": "2026-10-12T23:41:12.500Z",
                "workload": { "command": ["cargo", "build"], "type": "task" },
            },
            {
                "callback": "pending",
                "cancel_requested_at": null,
                "check_timeout": "pending",
                "created_at": "2026-10-12T23:50:00.000Z",
                "cwd": "/Users/me/work/cove",
                "exit_reason": null,
                "id": "01a13300-0000-7000-8000-000000000003",
                "name": "still going",
                "pid": null,
                "status": "running",
                "thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
                "timeout_secs": 3600,
                "updated_at": "2026-10-12T23:50:00.000Z",
                "workload": { "agent": "claude", "model": "claude-opus-5-5", "reasoning": "high", "type": "agent" },
            },
        ],
    })
}

fn task_show(id: &str) -> Value {
    json!({
        "api_version": 1,
        "availability": "available",
        "callback": "sent",
        "cancel_requested_at": null,
        "created_at": "2026-10-12T23:35:47.320Z",
        "cwd": "/Users/me/work/cove",
        "evidence": format!("/Users/me/.local/state/homebased/tasks/{id}"),
        "execution_machine": MACHINE,
        "exit_reason": { "code": 0, "kind": "exit" },
        "failed_events": [],
        "found_on": MACHINE,
        "id": id,
        "last_event": {
            "api_version": 1,
            "event": "TASK_SUCCEEDED",
            "name": "review address grouping (grok)",
            "next_action": "review_output",
            "process": { "code": 0, "kind": "exit" },
            "reports": [{ "outcome": "succeeded", "seq": 1, "summary": "Grouping is correct." }],
            "task": id,
            "thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
        },
        "name": "review address grouping (grok)",
        "output_log": format!("/Users/me/.local/state/homebased/tasks/{id}/output.log"),
        "pid": null,
        "reports": [{
            "outcome": "succeeded",
            "reported_at": "2026-10-12T23:49:39.432Z",
            "seq": 1,
            "summary": "Grouping is correct.",
        }],
        "status": "succeeded",
        "thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
        "timeout_secs": 3600,
        "updated_at": "2026-10-12T23:49:48.097Z",
        "waiting_events": [],
        "workload": { "agent": "grok", "model": "grok-4.7", "type": "agent" },
    })
}

fn task_log(id: &str) -> Value {
    json!({
        "api_version": 1,
        "availability": "available",
        "execution_machine": MACHINE,
        "found_on": MACHINE,
        "id": id,
        "log": "running tests\n12 passed\n",
        "origin_machine": MACHINE,
        "truncated": true,
    })
}

fn usage_row(key: &str) -> Value {
    json!({
        "cache_read_tokens": 60940996,
        "cache_write_tokens": 1869091,
        "cost_usd": 28.32137458999999,
        "input_tokens": 812,
        "key": key,
        "output_tokens": 665740,
        "partial_tasks": 0,
        "tasks": 6,
    })
}

fn task_usage() -> Value {
    let mut totals = usage_row("");
    if let Some(object) = totals.as_object_mut() {
        object.remove("key");
    }

    json!({
        "api_version": 1,
        "by_day": [usage_row("2026-10-12")],
        "by_model": [usage_row("claude-opus-5-5")],
        "by_thread": [usage_row("1029572c-a3ce-4f6c-8d47-11b5d2ca9902")],
        "since": "2026-10-05T00:00:00Z",
        "tasks": [],
        "totals": totals,
    })
}

fn fleet_machines() -> Value {
    json!({
        "api_version": 1,
        "local": {
            "advertised": ["http://100.64.0.10:7677"],
            "identity": { "state": "consistent" },
            "machine": MACHINE,
            "name": "main",
        },
        "machines": [{
            "addresses": [{
                "address": "http://100.64.0.11:7677",
                "source": "explicit",
                "verified_at": "2026-09-28T19:48:56.041550Z",
            }],
            "advertised": ["http://10.77.0.18:7677"],
            "boot": "01a0e97e-df66-7634-8738-220ab27417bd",
            "capabilities": { "agents": ["codex", "claude"], "arch": "x86_64", "os": "linux" },
            "compatibility": {
                "local": { "max": 3, "min": 3 },
                "remote": { "max": 2, "min": 2 },
                "state": "incompatible",
            },
            "identity": { "state": "consistent" },
            "machine": "01a0d117-07b3-76a8-ad09-60bf243f0014",
            "name": "code",
            "name_conflict": false,
            "protocol": { "max": 2, "min": 2 },
            "reachability": { "last_seen": "2026-09-28T19:48:56.041550Z", "state": "offline" },
            "version": "0.9.0",
        }],
    })
}

fn submit_answer(request_id: &str) -> Value {
    json!({
        "api_version": 1,
        "id": "01a10000-0000-7000-8000-000000000001",
        "request_id": request_id,
        "status": "queued",
        "task_id": "01a10000-0000-7000-8000-000000000001",
    })
}

fn dry_run_answer(spec: &Value) -> Value {
    json!({ "api_version": 1, "argv": ["/usr/bin/true"], "spec": spec, "stdin": "null" })
}

fn message_answer(argv: &[String]) -> Value {
    let message_id = argv
        .iter()
        .find_map(|arg| arg.strip_prefix("--message-id="))
        .unwrap_or("01a10000-0000-7000-8000-0000000000bb");

    json!({
        "api_version": 1,
        "destination_cwd": "/repo",
        "destination_machine": MACHINE,
        "destination_thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
        "message_id": message_id,
        "receipt": {
            "api_version": 1,
            "delivered_at": "2026-10-12T23:51:00.000Z",
            "destination_cwd": "/repo",
            "destination_thread": "02a4db98-0edf-47df-b8a3-1b2bdf83f1d5",
            "message_id": message_id,
            "protocol_version": 1,
        },
    })
}
