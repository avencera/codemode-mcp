//! `service` dry runs and `config init`, run as the real binary under a
//! temporary home so nothing outside it can change

use std::{path::Path, process::Command};

use super::harness::{TestResult, temp_state_dir};

fn codemode(
    home: &Path,
    args: &[&str],
) -> Result<(bool, String, String), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_codemode-mcp"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .output()?;

    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// Every file under `directory`, relative to it
fn files(directory: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(relative) = path.strip_prefix(directory) {
                found.push(relative.display().to_string());
            }
        }
    }
    found.sort();

    found
}

#[test]
fn service_dry_runs_change_nothing() -> TestResult {
    let home = temp_state_dir();
    std::fs::create_dir_all(&home)?;
    let worker = home.join("monty");
    std::fs::write(&worker, "#!/bin/sh\n")?;
    let config = home.join("codemode.toml");
    std::fs::write(&config, format!("worker_path = \"{}\"\n", worker.display()))?;
    let config = config.display().to_string();
    let before = files(&home);

    let (ok, out, err) = codemode(
        &home,
        &["--config", &config, "service", "install", "--dry-run"],
    )?;
    assert!(ok, "{err}");
    let home_text = home.display().to_string();
    assert!(
        out.contains(&format!(
            "install -m 755 {} {home_text}/.local/share/codemode-mcp/monty",
            worker.display()
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!("{home_text}/.local/bin/codemode-mcp")),
        "{out}"
    );
    assert!(out.contains("launchctl bootout gui/"), "{out}");
    assert!(
        out.contains("/dev.praveen.codemode-mcp.plist  # retried for up to 10s"),
        "{out}"
    );
    // the plist is shown, pinned to the explicit config
    assert!(
        out.contains(&format!(
            "<string>--config</string>\n    <string>{config}</string>"
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "{home_text}/.local/state/codemode-mcp/logs/codemode-mcp.out.log"
        )),
        "{out}"
    );

    for command in ["uninstall", "restart", "status"] {
        let (ok, out, err) = codemode(
            &home,
            &["--config", &config, "service", command, "--dry-run"],
        )?;
        assert!(ok, "{command}: {err}");
        assert!(out.starts_with("Dry run"), "{command}: {out}");
    }
    let (_, out, _) = codemode(
        &home,
        &["--config", &config, "service", "uninstall", "--dry-run"],
    )?;
    assert!(
        out.contains("rm -f") && out.contains("LaunchAgents/dev.praveen.codemode-mcp.plist"),
        "{out}"
    );

    assert_eq!(files(&home), before);
    let _ = std::fs::remove_dir_all(&home);

    Ok(())
}

#[test]
fn config_init_prints_writes_and_refuses_to_overwrite() -> TestResult {
    let home = temp_state_dir();
    std::fs::create_dir_all(&home)?;
    let target = home.join(".config/codemode-mcp/config.toml");

    let (ok, printed, err) = codemode(&home, &["config", "init", "--print"])?;
    assert!(ok, "{err}");
    assert!(printed.contains(&format!(
        "command = \"{}/.local/bin/codemode-mcp\"",
        home.display()
    )));
    assert!(!target.exists());

    let (ok, _, err) = codemode(&home, &["config", "init"])?;
    assert!(ok, "{err}");
    assert_eq!(std::fs::read_to_string(&target)?, printed);
    std::fs::write(&target, "# mine\n")?;
    let (ok, _, err) = codemode(&home, &["config", "init"])?;
    assert!(!ok);
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(std::fs::read_to_string(&target)?, "# mine\n");

    let _ = std::fs::remove_dir_all(&home);

    Ok(())
}
