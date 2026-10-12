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

    let answer = match words.as_slice() {
        ["daemon", "status"] => json!({ "api_version": 1, "socket": "up", "in_flight": 0 }),
        ["task", "list"] => json!({ "api_version": 1, "tasks": [] }),
        ["task", "submit"] => json!({
            "api_version": 1,
            "id": "01a10000-0000-7000-8000-000000000001",
            "status": "queued",
        }),
        _ => json!({ "api_version": 1, "ok": true }),
    };
    println!("{answer}");
}
