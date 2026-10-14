//! launchd service management and the starter config
//!
//! Mirrors homebased: a per-user LaunchAgent in `gui/<uid>`, loaded with
//! `launchctl bootstrap` after a `bootout` of any previous copy. Unlike
//! homebased, the binary and the Monty worker are copied to stable paths
//! first, so a rebuild in the repository cannot change the running service.
//! Every command can print its plan instead of running it (`--dry-run`)

use std::{
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// launchd label and plist name
pub const LABEL: &str = "dev.praveen.codemode-mcp";
/// Time launchd gives the daemon beyond the drain before it sends SIGKILL:
/// parking, flushing the usage log and tearing down the workers
const EXIT_GRACE: Duration = Duration::from_secs(30);
/// How long `launchctl bootstrap` is retried while a previous instance exits
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(10);
/// Short name `service install` links to the installed binary
pub const ALIAS: &str = "cmcp";
/// Starter configuration; `{{HOME}}` is replaced with the home directory
const STARTER_CONFIG: &str = include_str!("../assets/starter-config.toml");

/// Failures managing the service
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// `$HOME` is unset
    #[error("$HOME is not set")]
    NoHome,
    /// The Monty worker to install was not found
    #[error(
        "Monty worker not found at {0}; set `worker_path` in the config or run from the repository"
    )]
    NoWorker(PathBuf),
    /// A file operation failed
    #[error("{action}: {source}")]
    Io {
        /// What was attempted
        action: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// A command exited unsuccessfully
    #[error("`{command}` failed: {detail}")]
    Command {
        /// The command line
        command: String,
        /// Its stderr or exit status
        detail: String,
    },
    /// The config file already exists
    #[error("{0} already exists; edit it or move it away first")]
    ConfigExists(PathBuf),
}

fn io(action: impl Into<String>) -> impl FnOnce(std::io::Error) -> ServiceError {
    let action = action.into();

    move |source| ServiceError::Io { action, source }
}

/// Where the service lives, all derived from one home directory
#[derive(Debug, Clone)]
pub struct ServicePaths {
    /// Home directory
    pub home: PathBuf,
    /// Installed binary, `~/.local/bin/codemode-mcp`
    pub binary: PathBuf,
    /// Short-name symlink to the binary, `~/.local/bin/cmcp`
    pub alias: PathBuf,
    /// Installed Monty worker, `~/.local/share/codemode-mcp/monty`
    pub worker: PathBuf,
    /// LaunchAgent plist
    pub plist: PathBuf,
    /// launchd stdout and stderr files
    pub logs: PathBuf,
}

impl ServicePaths {
    /// Paths under `home`; logs go to `<state_dir>/logs`
    pub fn new(home: &Path, state_dir: &Path) -> Self {
        Self {
            home: home.to_owned(),
            binary: home.join(".local/bin/codemode-mcp"),
            alias: home.join(".local/bin").join(ALIAS),
            worker: default_worker_path(home),
            plist: home.join(format!("Library/LaunchAgents/{LABEL}.plist")),
            logs: state_dir.join("logs"),
        }
    }

    /// Paths under `$HOME`
    pub fn from_env(state_dir: &Path) -> Result<Self, ServiceError> {
        let home = std::env::var_os("HOME").ok_or(ServiceError::NoHome)?;

        Ok(Self::new(Path::new(&home), state_dir))
    }
}

/// Where `service install` puts the Monty worker, and where the daemon
/// looks for it when `worker_path` is unset
pub fn default_worker_path(home: &Path) -> PathBuf {
    home.join(".local/share/codemode-mcp/monty")
}

/// One step of a plan
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create a directory (mode 0700 when new)
    CreateDir(PathBuf),
    /// Copy an executable, replacing the target atomically
    Install {
        /// Source file
        from: PathBuf,
        /// Destination
        to: PathBuf,
    },
    /// Write a file
    Write {
        /// Destination
        path: PathBuf,
        /// Contents
        contents: String,
    },
    /// Replace `to` with `from` atomically
    Rename {
        /// Source file
        from: PathBuf,
        /// Destination
        to: PathBuf,
    },
    /// Point the symlink `link` at `target`, leaving anything else already
    /// at `link` in place
    Link {
        /// What the link points to, relative to its directory
        target: PathBuf,
        /// The symlink
        link: PathBuf,
    },
    /// Remove a file if it exists
    Remove(PathBuf),
    /// Run a command
    Run {
        /// Program and arguments
        argv: Vec<String>,
        /// Whether a failure is expected and ignored (e.g. `bootout` of a
        /// service that is not loaded)
        tolerate_failure: bool,
        /// Keep retrying a failure for this long
        retry_for: Option<Duration>,
    },
}

impl Action {
    fn run(argv: &[&str]) -> Self {
        Self::Run {
            argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            tolerate_failure: false,
            retry_for: None,
        }
    }

    /// One line for `--dry-run`
    pub fn describe(&self) -> String {
        match self {
            Self::CreateDir(path) => format!("mkdir -p {}", path.display()),
            Self::Install { from, to } => {
                format!("install -m 755 {} {}", from.display(), to.display())
            }
            Self::Write { path, contents } => {
                format!("write {} ({} bytes)", path.display(), contents.len())
            }
            Self::Rename { from, to } => format!("mv {} {}", from.display(), to.display()),
            Self::Link { target, link } => {
                format!("ln -s {} {}", target.display(), link.display())
            }
            Self::Remove(path) => format!("rm -f {}", path.display()),
            Self::Run {
                argv,
                tolerate_failure,
                retry_for,
            } => {
                let mut line = argv.join(" ");
                if *tolerate_failure {
                    line.push_str("  # failure ignored");
                }
                if let Some(wait) = retry_for {
                    line.push_str(&format!("  # retried for up to {}s", wait.as_secs()));
                }

                line
            }
        }
    }

    /// Performs the step
    pub fn apply(&self) -> Result<(), ServiceError> {
        match self {
            Self::CreateDir(path) => std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(io(format!("create {}", path.display()))),
            Self::Install { from, to } => install_file(from, to),
            Self::Write { path, contents } => {
                std::fs::write(path, contents).map_err(io(format!("write {}", path.display())))
            }
            Self::Rename { from, to } => {
                std::fs::rename(from, to).map_err(io(format!("rename to {}", to.display())))
            }
            Self::Link { target, link } => link_alias(target, link),
            Self::Remove(path) => match std::fs::remove_file(path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    Err(ServiceError::Io {
                        action: format!("remove {}", path.display()),
                        source: error,
                    })
                }
                _ => Ok(()),
            },
            Self::Run {
                argv,
                tolerate_failure,
                retry_for,
            } => {
                let deadline = retry_for.map(|wait| Instant::now() + wait);
                loop {
                    match run_command(argv) {
                        Ok(_) => return Ok(()),
                        Err(_) if *tolerate_failure => return Ok(()),
                        Err(error) => match deadline {
                            // launchd may still be tearing down the old instance
                            Some(deadline) if Instant::now() < deadline => {
                                std::thread::sleep(Duration::from_millis(200));
                            }
                            _ => return Err(error),
                        },
                    }
                }
            }
        }
    }
}

/// Copies through a temporary file and renames, so a running daemon keeps
/// its old inode and a crash never leaves a half-written binary
fn install_file(from: &Path, to: &Path) -> Result<(), ServiceError> {
    let same = std::fs::canonicalize(from).ok() == std::fs::canonicalize(to).ok();
    if same {
        return Ok(());
    }

    let temporary = to.with_extension(format!("tmp-{}", std::process::id()));
    let copied = std::fs::copy(from, &temporary)
        .map_err(io(format!(
            "copy {} to {}",
            from.display(),
            temporary.display()
        )))
        .and_then(|_| {
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
                .map_err(io(format!("chmod {}", temporary.display())))
        })
        .and_then(|()| {
            std::fs::rename(&temporary, to).map_err(io(format!("rename to {}", to.display())))
        });
    if copied.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }

    copied
}

/// Runs a command and returns its stdout
pub fn run_command(argv: &[String]) -> Result<String, ServiceError> {
    let command_line = argv.join(" ");
    let Some((program, args)) = argv.split_first() else {
        return Err(ServiceError::Command {
            command: command_line,
            detail: "empty command".into(),
        });
    };
    let output =
        Command::new(program)
            .args(args)
            .output()
            .map_err(|error| ServiceError::Command {
                command: command_line.clone(),
                detail: error.to_string(),
            })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

        return Err(ServiceError::Command {
            command: command_line,
            detail: if stderr.is_empty() {
                output.status.to_string()
            } else {
                stderr
            },
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The current user's id, for the `gui/<uid>` launchd domain
pub fn current_uid() -> Result<u32, ServiceError> {
    let output = run_command(&["id".to_owned(), "-u".to_owned()])?;

    output.trim().parse().map_err(|_| ServiceError::Command {
        command: "id -u".into(),
        detail: format!("unexpected output {output:?}"),
    })
}

/// launchd's own default when a plist has no `ExitTimeOut`
const LAUNCHD_EXIT_TIMEOUT_SECS: u64 = 20;

/// Time the daemon needs beyond the drain to park, flush and exit
const EXIT_MARGIN: Duration = Duration::from_secs(10);

/// Warning for an installed plist whose `ExitTimeOut` would cut a drain short
///
/// `None` when the plist is fine; `plist` is its text
pub fn exit_timeout_warning(plist: &str, drain: Duration) -> Option<String> {
    let configured = plist
        .split_once("<key>ExitTimeOut</key>")
        .and_then(|(_, rest)| rest.split_once("<integer>"))
        .and_then(|(_, rest)| rest.split_once("</integer>"))
        .and_then(|(number, _)| number.trim().parse::<u64>().ok())
        .unwrap_or(LAUNCHD_EXIT_TIMEOUT_SECS);
    let needed = (drain + EXIT_MARGIN).as_secs();

    (configured < needed).then(|| {
        format!(
            "the installed launchd plist gives the daemon {configured}s to exit, less than the \
             {needed}s its {}s drain needs; run `codemode-mcp service install` again",
            drain.as_secs()
        )
    })
}

/// Escapes text for XML element content
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The LaunchAgent plist; `config` is passed to `serve` when given
///
/// `ExitTimeOut` is the configured `drain` plus a grace period: launchd's
/// default of 20 seconds would kill the daemon in the middle of its drain
pub fn render_plist(paths: &ServicePaths, config: Option<&Path>, drain: Duration) -> String {
    let exit_timeout = (drain + EXIT_GRACE).as_secs();
    let mut arguments = vec![paths.binary.display().to_string()];
    if let Some(config) = config {
        arguments.push("--config".to_owned());
        arguments.push(config.display().to_string());
    }
    arguments.push("serve".to_owned());
    let arguments: String = arguments
        .iter()
        .map(|argument| format!("    <string>{}</string>\n", xml_escape(argument)))
        .collect();
    // launchd starts agents with a minimal PATH; upstream commands and the
    // homebased adapter need Homebrew and ~/.local/bin
    let path = format!(
        "{}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        paths.home.display()
    );

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{arguments}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>ExitTimeOut</key>
  <integer>{exit_timeout}</integer>
  <key>WorkingDirectory</key>
  <string>{home}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{path}</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        home = xml_escape(&paths.home.display().to_string()),
        path = xml_escape(&path),
        stdout = xml_escape(
            &paths
                .logs
                .join("codemode-mcp.out.log")
                .display()
                .to_string()
        ),
        stderr = xml_escape(
            &paths
                .logs
                .join("codemode-mcp.err.log")
                .display()
                .to_string()
        ),
    )
}

/// `gui/<uid>/<label>`
/// Creates the symlink unless something is already at `link`: our own link
/// is left as is, and anything else (a user's script, another tool's link)
/// is left alone with a warning rather than failing the install halfway
fn link_alias(target: &Path, link: &Path) -> Result<(), ServiceError> {
    match std::fs::read_link(link) {
        Ok(existing) if existing == target => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return std::os::unix::fs::symlink(target, link)
                .map_err(io(format!("link {}", link.display())));
        }
        // a regular file or directory: read_link fails with InvalidInput
        Err(_) => {}
    }

    tracing::warn!(
        path = %link.display(),
        "something else is already at this path, so the short name was not linked"
    );
    Ok(())
}

fn target(uid: u32) -> String {
    format!("gui/{uid}/{LABEL}")
}

/// Steps of `service install`
pub fn install_plan(
    paths: &ServicePaths,
    uid: u32,
    binary: &Path,
    worker: &Path,
    config: Option<&Path>,
    drain: Duration,
) -> Vec<Action> {
    let parent = |path: &Path| path.parent().map(Path::to_owned).unwrap_or_default();
    let plist = paths.plist.display().to_string();
    // the new plist is linted before it replaces a working one, and before
    // the running service is booted out
    let staged = paths.plist.with_extension("plist.new");

    vec![
        Action::CreateDir(parent(&paths.binary)),
        Action::Install {
            from: binary.to_owned(),
            to: paths.binary.clone(),
        },
        // relative, so the link follows the binary whatever the home path
        Action::Link {
            target: paths
                .binary
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_default(),
            link: paths.alias.clone(),
        },
        Action::CreateDir(parent(&paths.worker)),
        Action::Install {
            from: worker.to_owned(),
            to: paths.worker.clone(),
        },
        Action::CreateDir(paths.logs.clone()),
        Action::CreateDir(parent(&paths.plist)),
        Action::Write {
            path: staged.clone(),
            contents: render_plist(paths, config, drain),
        },
        Action::run(&["plutil", "-lint", &staged.display().to_string()]),
        Action::Rename {
            from: staged,
            to: paths.plist.clone(),
        },
        Action::Run {
            argv: vec!["launchctl".into(), "bootout".into(), target(uid)],
            tolerate_failure: true,
            retry_for: None,
        },
        Action::Run {
            argv: vec![
                "launchctl".into(),
                "bootstrap".into(),
                format!("gui/{uid}"),
                plist,
            ],
            tolerate_failure: false,
            retry_for: Some(BOOTSTRAP_WAIT),
        },
    ]
}

/// Steps of `service uninstall`; state and installed files, including the
/// `cmcp` link, stay
pub fn uninstall_plan(paths: &ServicePaths, uid: u32) -> Vec<Action> {
    vec![
        Action::Run {
            argv: vec!["launchctl".into(), "bootout".into(), target(uid)],
            tolerate_failure: true,
            retry_for: None,
        },
        Action::Remove(paths.plist.clone()),
    ]
}

/// Steps of `service restart`
pub fn restart_plan(uid: u32) -> Vec<Action> {
    vec![Action::run(&["launchctl", "kickstart", "-k", &target(uid)])]
}

/// The read-only command `service status` runs
pub fn status_command(uid: u32) -> Vec<String> {
    vec!["launchctl".into(), "print".into(), target(uid)]
}

/// The pid launchd reports for the running service, if it is running
pub fn running_pid(uid: u32) -> Option<u32> {
    let output = run_command(&status_command(uid)).ok()?;

    output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("pid = ")?.parse().ok())
}

/// The starter config for `home`
pub fn starter_config(home: &Path) -> String {
    STARTER_CONFIG.replace("{{HOME}}", &home.display().to_string())
}

/// Writes the starter config to `path`, refusing to replace a file
pub fn write_starter_config(path: &Path, home: &Path) -> Result<(), ServiceError> {
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(io(format!("create {}", parent.display())))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ServiceError::ConfigExists(path.to_owned())
            } else {
                ServiceError::Io {
                    action: format!("create {}", path.display()),
                    source: error,
                }
            }
        })?;

    std::io::Write::write_all(&mut file, starter_config(home).as_bytes())
        .map_err(io(format!("write {}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, policy::Policy};

    #[test]
    fn plist_escapes_paths_and_runs_serve() {
        let paths = ServicePaths::new(Path::new("/Users/a&b"), Path::new("/Users/a&b/state"));
        let plist = render_plist(
            &paths,
            Some(Path::new("/tmp/<c>.toml")),
            Duration::from_secs(20),
        );

        assert!(plist.contains("<string>/Users/a&amp;b/.local/bin/codemode-mcp</string>"));
        assert!(plist.contains("<string>--config</string>\n    <string>/tmp/&lt;c&gt;.toml</string>\n    <string>serve</string>"));
        assert!(plist.contains("/Users/a&amp;b/.local/bin:/opt/homebrew/bin:"));
        assert!(plist.contains("<string>/Users/a&amp;b/state/logs/codemode-mcp.err.log</string>"));
        assert!(!plist.contains("a&b"));
        // drain 20s plus the grace period, so launchd waits out the drain
        assert!(plist.contains("<key>ExitTimeOut</key>\n  <integer>50</integer>"));
    }

    #[test]
    fn the_short_name_links_once_and_never_replaces_a_users_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!("codemode-alias-{}", std::process::id()));
        std::fs::create_dir_all(&directory)?;
        let binary = Path::new("codemode-mcp");
        let link = directory.join(ALIAS);
        let link_action = Action::Link {
            target: binary.to_owned(),
            link: link.clone(),
        };

        // a fresh install links, and a reinstall keeps the same link
        link_action.apply()?;
        link_action.apply()?;
        assert_eq!(std::fs::read_link(&link)?, binary);

        // a file the user put there survives the install untouched
        std::fs::remove_file(&link)?;
        std::fs::write(&link, "#!/bin/sh\necho mine\n")?;
        link_action.apply()?;
        assert_eq!(std::fs::read_to_string(&link)?, "#!/bin/sh\necho mine\n");

        // so does a link of theirs pointing elsewhere
        std::fs::remove_file(&link)?;
        std::os::unix::fs::symlink("/usr/bin/true", &link)?;
        link_action.apply()?;
        assert_eq!(std::fs::read_link(&link)?, Path::new("/usr/bin/true"));

        std::fs::remove_dir_all(&directory)?;
        Ok(())
    }

    #[test]
    fn a_plist_that_cuts_the_drain_short_is_reported() {
        let paths = ServicePaths::new(Path::new("/Users/a"), Path::new("/Users/a/state"));
        let drain = Duration::from_secs(20);

        let current = render_plist(&paths, None, drain);
        assert_eq!(exit_timeout_warning(&current, drain), None);

        // a plist from before the drain existed has no ExitTimeOut at all
        let old = current.replace("<key>ExitTimeOut</key>\n  <integer>50</integer>\n  ", "");
        let warning = exit_timeout_warning(&old, drain);
        assert!(
            warning.is_some_and(|text| text.contains("service install")),
            "{old}"
        );
        assert!(exit_timeout_warning(&current, Duration::from_secs(60)).is_some());
    }

    #[test]
    fn starter_config_parses_with_the_intended_policies() -> Result<(), Box<dyn std::error::Error>>
    {
        let text = starter_config(Path::new("/Users/someone"));
        let config = Config::parse(&text, Path::new("starter.toml"))?;

        let onepassword = &config.servers["onepassword"];
        assert_eq!(onepassword.policy_for("list_environments"), Policy::Ask);
        assert_eq!(
            onepassword.grant_for("create_environment"),
            crate::policy::GrantMode::PerCall
        );
        assert!(onepassword.warm.is_some());
        assert!(config.servers["exa"].oauth);
        assert!(config.notify.ntfy.is_none());

        let homebased = &config.servers["homebased"];
        assert_eq!(
            homebased.command.as_deref(),
            Some("/Users/someone/.local/bin/codemode-mcp")
        );
        assert!(!homebased.is_sensitive());
        for tool in ["task_submit_command", "task_cancel", "message_send"] {
            assert_eq!(homebased.policy_for(tool), Policy::Ask, "{tool}");
        }
        for tool in ["task_submit_agent", "task_list", "notify"] {
            assert_eq!(homebased.policy_for(tool), Policy::Allow, "{tool}");
        }

        Ok(())
    }
}
