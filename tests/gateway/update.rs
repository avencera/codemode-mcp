//! `update` against a release served locally, run as the real binary under a
//! temporary home so the installed service is never touched. Signatures are
//! checked on macOS only, so Linux covers the checksum and the install

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    extract::{Path as UrlPath, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use sha2::{Digest, Sha256};

use super::harness::{TestResult, temp_state_dir};

const TAG: &str = "v9.9.9";
#[cfg(target_os = "macos")]
const ASSET: &str = "codemode-mcp-v9.9.9-aarch64-apple-darwin.tar.gz";
#[cfg(target_os = "macos")]
const SUMS: &str = "codemode-mcp-v9.9.9-aarch64-apple-darwin.sha256";
#[cfg(target_os = "linux")]
const ASSET: &str = "codemode-mcp-v9.9.9-x86_64-unknown-linux-gnu.tar.gz";
#[cfg(target_os = "linux")]
const SUMS: &str = "codemode-mcp-v9.9.9-x86_64-unknown-linux-gnu.sha256";

/// What the fake GitHub serves: the archive and its checksum file
type Served = Arc<Mutex<(Vec<u8>, String)>>;

async fn download(
    UrlPath((tag, file)): UrlPath<(String, String)>,
    State(served): State<Served>,
) -> Response {
    let Ok(served) = served.lock() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match (tag.as_str(), file.as_str()) {
        (TAG, ASSET) => served.0.clone().into_response(),
        (TAG, SUMS) => served.1.clone().into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn serve(served: Served) -> Result<String, Box<dyn std::error::Error>> {
    let app = Router::new()
        .route(
            "/releases/latest",
            get(|| async { Redirect::temporary(&format!("/releases/tag/{TAG}")) }),
        )
        .route("/releases/tag/{tag}", get(|| async { "release page" }))
        .route("/releases/download/{tag}/{file}", get(download))
        .with_state(served);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move { axum::serve(listener, app).await });

    Ok(format!("http://{address}"))
}

fn run(program: &str, args: &[&str]) -> TestResult {
    let status = std::process::Command::new(program).args(args).status()?;
    assert!(status.success(), "{program} {args:?}");

    Ok(())
}

/// A release archive whose two executables are, on macOS, ad hoc signed as
/// `binary_id` and `worker_id`, and the checksum file that lists it
fn release(
    dir: &Path,
    binary_id: &str,
    worker_id: &str,
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    for (name, identifier) in [("codemode-mcp", binary_id), ("monty", worker_id)] {
        let path = dir.join(name).display().to_string();
        std::fs::copy(env!("CARGO_BIN_EXE_codemode-fixture"), &path)?;
        if cfg!(target_os = "macos") {
            run(
                "codesign",
                &["--force", "--sign", "-", "--identifier", identifier, &path],
            )?;
        }
    }
    let archive = dir.join(ASSET).display().to_string();
    let root = dir.display().to_string();
    run(
        "tar",
        &["-czf", &archive, "-C", &root, "codemode-mcp", "monty"],
    )?;

    let bytes = std::fs::read(&archive)?;
    let sum: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Ok((bytes, format!("{sum}  {ASSET}\n")))
}

async fn update(home: &Path, base_url: &str) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_codemode-mcp"))
        .arg("update")
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .env("CODEMODE_UPDATE_BASE_URL", base_url)
        // ad hoc signatures carry no team, so only the identifiers are checked
        .env("CODEMODE_UPDATE_ANCHOR", "always")
        .output()
        .await?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Ok((output.status.success(), text))
}

#[tokio::test(flavor = "multi_thread")]
async fn update_installs_only_a_checked_release() -> TestResult {
    let home = temp_state_dir();
    let binary = home.join(".local/bin/codemode-mcp");
    let worker = home.join(".local/share/codemode-mcp/monty");
    for (path, contents) in [(&binary, "old binary"), (&worker, "old worker")] {
        std::fs::create_dir_all(path.parent().ok_or("no parent")?)?;
        std::fs::write(path, contents)?;
    }
    let unchanged = || -> TestResult {
        assert_eq!(std::fs::read_to_string(&binary)?, "old binary");
        assert_eq!(std::fs::read_to_string(&worker)?, "old worker");

        Ok(())
    };

    let good = release(
        &home.join("good"),
        "com.avencera.codemode-mcp",
        "com.avencera.monty",
    )?;
    let served: Served = Arc::new(Mutex::new((good.0.clone(), "0".repeat(64) + "  " + ASSET)));
    let base_url = serve(served.clone()).await?;

    let (ok, text) = update(&home, &base_url).await?;
    assert!(!ok && text.contains("the release publishes"), "{text}");
    unchanged()?;

    // a worker signed under another identifier is refused
    if cfg!(target_os = "macos") {
        let forged = release(
            &home.join("forged"),
            "com.avencera.codemode-mcp",
            "com.example.monty",
        )?;
        *served.lock().map_err(|_| "poisoned")? = forged;
        let (ok, text) = update(&home, &base_url).await?;
        assert!(!ok && text.contains("does not satisfy"), "{text}");
        unchanged()?;
    }

    *served.lock().map_err(|_| "poisoned")? = good;
    let (ok, text) = update(&home, &base_url).await?;
    assert!(ok, "{text}");
    assert!(text.contains("service is not installed"), "{text}");
    let fixture = std::fs::read(env!("CARGO_BIN_EXE_codemode-fixture"))?;
    for (path, identifier) in [
        (&binary, "com.avencera.codemode-mcp"),
        (&worker, "com.avencera.monty"),
    ] {
        if !cfg!(target_os = "macos") {
            assert_eq!(std::fs::read(path)?, fixture);
            continue;
        }

        // same code as the fixture, with the signature the release carried
        assert_ne!(std::fs::read(path)?, fixture);
        let requirement = format!("=identifier \"{identifier}\"");
        run(
            "codesign",
            &[
                "--verify",
                "--strict",
                "-R",
                &requirement,
                &path.display().to_string(),
            ],
        )?;
    }

    Ok(())
}
