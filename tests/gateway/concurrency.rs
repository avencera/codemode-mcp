//! `max_concurrent`: calls past a server's cap wait their turn, and a rate
//! limit error says where to lower the cap

use super::harness::{Harness, Setup, TestResult};

#[tokio::test(flavor = "multi_thread")]
async fn calls_past_the_cap_wait_and_rate_limits_name_the_setting() -> TestResult {
    let fixture = env!("CARGO_BIN_EXE_codemode-fixture");
    let extra = format!("[servers.roomy]\ncommand = \"{fixture}\"\n");
    // a server kept in an included file is changed there, not in config.toml
    let shared = std::env::temp_dir().join(format!(
        "codemode-concurrency-{}-servers.toml",
        std::process::id()
    ));
    std::fs::write(
        &shared,
        format!("[servers.shared]\ncommand = \"{fixture}\"\nmax_concurrent = 3\n"),
    )?;
    let top = format!("include = [\"{}\"]", shared.display());
    let Some(harness) = Harness::with(Setup {
        server: "max_concurrent = 2",
        extra: &extra,
        top: &top,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    // every call still runs; none is refused for waiting
    let body = harness
        .execute_json(
            "import asyncio\n\
             capped = await asyncio.gather(*[fixture_overlap(delay_ms=200) for _ in range(6)])\n\
             roomy = await asyncio.gather(*[roomy_overlap(delay_ms=200) for _ in range(12)])\n\
             [len(capped), max(r[\"peak\"] for r in capped), len(roomy), max(r[\"peak\"] for r in roomy)]",
        )
        .await?;
    assert_eq!(body["result"], serde_json::json!([6, 2, 12, 8]), "{body}");

    let body = harness
        .execute_json(
            "messages: list[str] = []\n\
             for message in [\"429 Too Many Requests\", \"no such issue\"]:\n    \
                 try:\n        await fixture_fail(message=message)\n    \
                 except RuntimeError as error:\n        messages.append(str(error))\n\
             messages",
        )
        .await?;
    let limited = body["result"][0].as_str().unwrap_or_default();
    assert!(
        limited.contains("at most 2 calls")
            && limited.contains("`max_concurrent` under `[servers.fixture]`")
            && limited.contains("config.toml"),
        "{body}"
    );
    let other = body["result"][1].as_str().unwrap_or_default();
    assert_eq!(other, "no such issue", "{body}");

    let body = harness
        .execute_json(
            "message = \"\"\n\
             try:\n    await shared_fail(message=\"Rate limit exceeded\")\n\
             except RuntimeError as error:\n    message = str(error)\n\
             message",
        )
        .await?;
    let _ = std::fs::remove_file(&shared);
    let limited = body["result"].as_str().unwrap_or_default();
    assert!(
        limited.contains("at most 3 calls") && limited.contains(&format!("`{}`", shared.display())),
        "{body}"
    );

    Ok(())
}
