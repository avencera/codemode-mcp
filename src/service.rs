//! Service management and the starter config
//!
//! Mirrors homebased. On macOS a per-user LaunchAgent in `gui/<uid>`, loaded
//! with `launchctl bootstrap` after a `bootout` of any previous copy; on
//! Linux a systemd user unit, enabled and restarted with `systemctl --user`.
//! Unlike homebased, the binary and the Monty worker are copied to stable
//! paths first, so a rebuild in the repository cannot change the running
//! service. Every command can print its plan instead of running it
//! (`--dry-run`)

use std::{
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// launchd label and plist name; the systemd unit is `codemode-mcp.service`
pub const LABEL: &str = "dev.praveen.codemode-mcp";
/// launchd label and plist name of the companion agent
pub const COMPANION_LABEL: &str = "dev.praveen.codemode-mcp.companion";
/// Time launchd gives the daemon beyond the drain before it sends SIGKILL:
/// parking, flushing the usage log and tearing down the workers
const EXIT_GRACE: Duration = Duration::from_secs(30);
/// How long `launchctl bootstrap` is retried while a previous instance exits
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(10);
/// Short name `service install` links to the installed binary
pub const ALIAS: &str = "cmcp";
/// Developer ID that signs installed binaries, the one homebased releases use.
/// macOS and the 1Password app key their grants to an ad-hoc binary by its
/// hash, so every rebuild prompted again; a stable certificate keeps them
pub const SIGNING_IDENTITY: &str = "Developer ID Application: InfraOps LLC (Q8UP8C53Y8)";
/// Apple team of [`SIGNING_IDENTITY`], which `update` requires of a release
pub const TEAM_ID: &str = "Q8UP8C53Y8";
/// Prefix of each signed binary's identifier, as in `com.avencera.codemode-mcp`
const SIGNING_PREFIX: &str = "com.avencera.";
/// Entitlements signed into the daemon; the hardened runtime denies EventKit
/// without the calendars one, which covers reminders too
const DAEMON_ENTITLEMENTS: &str = include_str!("../assets/codemode-mcp.entitlements");
/// Starter configuration; `{{HOME}}` is replaced with the home directory
const STARTER_CONFIG: &str = include_str!("../assets/starter-config.toml");
/// Starter configuration of a spoke; `{{HUB}}` is replaced with the hub
const SPOKE_CONFIG: &str = include_str!("../assets/spoke-config.toml");
/// Search path of a systemd unit when the installing shell has none
const SYSTEMD_DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    /// The signing certificate is not in any keychain
    #[error(
        "the signing identity \"{SIGNING_IDENTITY}\" is not in your keychain, and this binary is \
         not a signed release; install a release with install.sh, or import the InfraOps Developer \
         ID .p12 (the one in the homebased release secrets) into the login keychain and install again"
    )]
    NoSigningIdentity,
}

fn io(action: impl Into<String>) -> impl FnOnce(std::io::Error) -> ServiceError {
    let action = action.into();

    move |source| ServiceError::Io { action, source }
}

/// The service manager that runs the daemon
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    /// A launchd LaunchAgent, on macOS
    Launchd,
    /// A systemd user unit, on Linux
    Systemd,
}

impl Manager {
    /// The manager of this machine
    pub fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::Launchd
        } else {
            Self::Systemd
        }
    }

    /// What `service` commands call the installed file in their output
    pub fn file_kind(self) -> &'static str {
        match self {
            Self::Launchd => "plist",
            Self::Systemd => "unit",
        }
    }
}

/// Where the service lives, all derived from one home directory
#[derive(Debug, Clone)]
pub struct ServicePaths {
    /// The service manager the paths are for
    pub manager: Manager,
    /// Home directory
    pub home: PathBuf,
    /// Installed binary, `~/.local/bin/codemode-mcp`
    pub binary: PathBuf,
    /// Short-name symlink to the binary, `~/.local/bin/cmcp`
    pub alias: PathBuf,
    /// Installed Monty worker, `~/.local/share/codemode-mcp/monty`
    pub worker: PathBuf,
    /// LaunchAgent plist or systemd unit
    pub service_file: PathBuf,
    /// LaunchAgent plist of `companion serve`; the companion runs on macOS
    /// only, so a systemd host never installs it
    pub companion_service_file: PathBuf,
    /// The service's stdout and stderr files
    pub logs: PathBuf,
    /// `PATH` the service runs with
    pub search_path: String,
}

impl ServicePaths {
    /// Paths under `home` for this machine's manager; logs go to
    /// `<state_dir>/logs`
    pub fn new(home: &Path, state_dir: &Path) -> Self {
        let search_path = match Manager::host() {
            Manager::Launchd => None,
            Manager::Systemd => std::env::var("PATH").ok(),
        };

        Self::for_manager(Manager::host(), home, state_dir, search_path.as_deref())
    }

    /// Paths under `home` for `manager`
    ///
    /// launchd starts agents with a minimal `PATH`, so upstream commands get
    /// Homebrew and `~/.local/bin`. A systemd unit keeps the installing
    /// shell's `shell_path`, since Linux tools live in many more places
    /// (`~/.cargo/bin`, nvm, linuxbrew); `~/.local/bin` comes first either
    /// way
    pub fn for_manager(
        manager: Manager,
        home: &Path,
        state_dir: &Path,
        shell_path: Option<&str>,
    ) -> Self {
        let local_bin = home.join(".local/bin").display().to_string();
        let search_path = match manager {
            Manager::Launchd => format!(
                "{local_bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            ),
            Manager::Systemd => {
                let rest = shell_path
                    .filter(|path| !path.is_empty())
                    .unwrap_or(SYSTEMD_DEFAULT_PATH);
                let rest: Vec<&str> = rest
                    .split(':')
                    .filter(|entry| !entry.is_empty() && *entry != local_bin)
                    .collect();

                std::iter::once(local_bin.as_str())
                    .chain(rest)
                    .collect::<Vec<_>>()
                    .join(":")
            }
        };
        let (service_file, companion_service_file) = match manager {
            Manager::Launchd => (
                home.join(format!("Library/LaunchAgents/{LABEL}.plist")),
                home.join(format!("Library/LaunchAgents/{COMPANION_LABEL}.plist")),
            ),
            Manager::Systemd => (
                home.join(format!(".config/systemd/user/{}", Agent::Daemon.unit())),
                home.join(format!(".config/systemd/user/{}", Agent::Companion.unit())),
            ),
        };

        Self {
            manager,
            home: home.to_owned(),
            binary: home.join(".local/bin/codemode-mcp"),
            alias: home.join(".local/bin").join(ALIAS),
            worker: default_worker_path(home),
            service_file,
            companion_service_file,
            logs: state_dir.join("logs"),
            search_path,
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
    /// Copy an executable, sign the copy with [`SIGNING_IDENTITY`] and
    /// replace the target atomically
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
            Self::Install { from, to } if cfg!(target_os = "macos") => format!(
                "install -m 755 {} {}  # signed as {}, hardened runtime",
                from.display(),
                to.display(),
                signing_identifier(to)
            ),
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
    if same_file(from, to) {
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
        // signed before the rename, so the path never holds an unsigned binary
        // and a running daemon's file is never rewritten in place. A release
        // binary already carries the team's signature, and copying keeps it
        .and_then(|()| {
            if needs_signing(from, to) {
                sign(&temporary, &signing_identifier(to))
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            std::fs::rename(&temporary, to).map_err(io(format!("rename to {}", to.display())))
        });
    if copied.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }

    copied
}

/// Identifier `to` is signed under; named after the destination, since the
/// file codesign sees is a temporary copy
pub fn signing_identifier(to: &Path) -> String {
    let name = to
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    format!("{SIGNING_PREFIX}{name}")
}

fn sign(path: &Path, identifier: &str) -> Result<(), ServiceError> {
    // --force replaces the linker's ad-hoc signature. The hardened runtime
    // refuses DYLD_* variables (the LaunchAgent plist is user-writable) and
    // libraries signed by anyone but Apple or this team
    let mut argv: Vec<String> = vec![
        "codesign".into(),
        "--force".into(),
        "--options".into(),
        "runtime".into(),
        "--sign".into(),
        SIGNING_IDENTITY.into(),
        "--identifier".into(),
        identifier.into(),
    ];

    // only the daemon gets EventKit; the worker runs agent scripts
    let entitlements = path.with_extension("entitlements");
    let daemon = identifier == format!("{SIGNING_PREFIX}codemode-mcp");
    if daemon {
        std::fs::write(&entitlements, DAEMON_ENTITLEMENTS)
            .map_err(io(format!("write {}", entitlements.display())))?;
        argv.extend(["--entitlements".into(), entitlements.display().to_string()]);
    }
    argv.push(path.display().to_string());

    let signed = run_command(&argv).map(drop);
    if daemon {
        let _ = std::fs::remove_file(&entitlements);
    }

    signed
}

/// Code signing requirement anchored to [`TEAM_ID`], before an identifier
/// is added
pub fn team_anchor() -> String {
    format!("anchor apple generic and certificate leaf[subject.OU] = \"{TEAM_ID}\"")
}

/// Whether installing `from` at `to` has to sign it here: false when it is
/// already there, or already signed by [`TEAM_ID`] under the identifier `to`
/// gets, as release binaries are in CI
///
/// Only macOS signs: the signature exists for its keychain and the 1Password
/// app, neither of which a Linux spoke has
fn needs_signing(from: &Path, to: &Path) -> bool {
    if !cfg!(target_os = "macos") || same_file(from, to) {
        return false;
    }

    let requirement = format!(
        "={} and identifier \"{}\"",
        team_anchor(),
        signing_identifier(to)
    );
    let signed = Command::new("codesign")
        .args(["--verify", "--strict", "-R"])
        .arg(requirement)
        .arg(from)
        .output()
        .is_ok_and(|output| output.status.success());

    !signed
}

fn same_file(from: &Path, to: &Path) -> bool {
    std::fs::canonicalize(from).ok() == std::fs::canonicalize(to).ok()
}

/// Fails unless [`SIGNING_IDENTITY`] can sign, when some step of `plan` has
/// to sign, so an install stops before it changes anything rather than
/// halfway through. Installing a release needs no certificate
pub fn check_signing_identity(plan: &[Action]) -> Result<(), ServiceError> {
    let signs = plan.iter().any(|action| match action {
        Action::Install { from, to } => needs_signing(from, to),
        _ => false,
    });
    if !signs {
        return Ok(());
    }

    let identities = run_command(&[
        "security".into(),
        "find-identity".into(),
        "-v".into(),
        "-p".into(),
        "codesigning".into(),
    ])?;
    if identities.contains(&format!("\"{SIGNING_IDENTITY}\"")) {
        Ok(())
    } else {
        Err(ServiceError::NoSigningIdentity)
    }
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

/// The current user's id, for the `gui/<uid>` launchd domain; systemd's user
/// manager needs none
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

/// systemd's own default when a unit has no `TimeoutStopSec`
const SYSTEMD_EXIT_TIMEOUT_SECS: u64 = 90;

/// Warning for an installed plist or unit whose stop timeout would cut a
/// drain short
///
/// `None` when the file is fine; `text` is its contents
pub fn exit_timeout_warning(manager: Manager, text: &str, drain: Duration) -> Option<String> {
    let configured = match manager {
        Manager::Launchd => text
            .split_once("<key>ExitTimeOut</key>")
            .and_then(|(_, rest)| rest.split_once("<integer>"))
            .and_then(|(_, rest)| rest.split_once("</integer>"))
            .and_then(|(number, _)| number.trim().parse::<u64>().ok())
            .unwrap_or(LAUNCHD_EXIT_TIMEOUT_SECS),
        Manager::Systemd => text
            .lines()
            .find_map(|line| line.trim().strip_prefix("TimeoutStopSec="))
            .and_then(|number| number.trim().parse::<u64>().ok())
            .unwrap_or(SYSTEMD_EXIT_TIMEOUT_SECS),
    };
    let needed = (drain + EXIT_MARGIN).as_secs();

    (configured < needed).then(|| {
        format!(
            "the installed service {} gives the daemon {configured}s to exit, less than the \
             {needed}s its {}s drain needs; run `codemode-mcp service install` again",
            manager.file_kind(),
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

/// A LaunchAgent this binary installs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    /// The gateway daemon, `serve`
    Daemon,
    /// The companion on another Mac, `companion serve`
    Companion,
}

impl Agent {
    /// launchd label
    pub fn label(self) -> &'static str {
        match self {
            Self::Daemon => LABEL,
            Self::Companion => COMPANION_LABEL,
        }
    }

    /// Arguments after the binary and `--config`
    fn subcommand(self) -> &'static [&'static str] {
        match self {
            Self::Daemon => &["serve"],
            Self::Companion => &["companion", "serve"],
        }
    }

    /// Start of the launchd log file names
    fn log_stem(self) -> &'static str {
        match self {
            Self::Daemon => "codemode-mcp",
            Self::Companion => "codemode-mcp-companion",
        }
    }

    /// systemd unit name
    pub fn unit(self) -> &'static str {
        match self {
            Self::Daemon => "codemode-mcp.service",
            Self::Companion => "codemode-mcp-companion.service",
        }
    }

    fn service_file(self, paths: &ServicePaths) -> &Path {
        match self {
            Self::Daemon => &paths.service_file,
            Self::Companion => &paths.companion_service_file,
        }
    }

    fn arguments(self, paths: &ServicePaths, config: Option<&Path>) -> Vec<String> {
        let mut arguments = vec![paths.binary.display().to_string()];
        if let Some(config) = config {
            arguments.push("--config".to_owned());
            arguments.push(config.display().to_string());
        }
        arguments.extend(self.subcommand().iter().map(|word| (*word).to_owned()));

        arguments
    }

    fn log(self, paths: &ServicePaths, stream: &str) -> String {
        paths
            .logs
            .join(format!("{}.{stream}.log", self.log_stem()))
            .display()
            .to_string()
    }
}

/// The LaunchAgent plist of `agent`; `config` is passed to it when given
///
/// `ExitTimeOut` is the configured `drain` plus a grace period: launchd's
/// default of 20 seconds would kill the daemon in the middle of its drain
pub fn render_plist(
    agent: Agent,
    paths: &ServicePaths,
    config: Option<&Path>,
    drain: Duration,
) -> String {
    let exit_timeout = (drain + EXIT_GRACE).as_secs();
    let arguments: String = agent
        .arguments(paths, config)
        .iter()
        .map(|argument| format!("    <string>{}</string>\n", xml_escape(argument)))
        .collect();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
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
        label = agent.label(),
        home = xml_escape(&paths.home.display().to_string()),
        path = xml_escape(&paths.search_path),
        stdout = xml_escape(&agent.log(paths, "out")),
        stderr = xml_escape(&agent.log(paths, "err")),
    )
}

/// The systemd user unit of `agent`; `config` is passed to it when given
///
/// `TimeoutStopSec` is the configured `drain` plus a grace period, like the
/// plist's `ExitTimeOut`. `KillMode=mixed` sends SIGTERM to the daemon
/// alone, which tears down its workers and lazy servers itself, and SIGKILL
/// to whatever is left once the timeout runs out
pub fn render_unit(
    agent: Agent,
    paths: &ServicePaths,
    config: Option<&Path>,
    drain: Duration,
) -> String {
    let exit_timeout = (drain + EXIT_GRACE).as_secs();
    let exec: Vec<String> = agent
        .arguments(paths, config)
        .iter()
        .map(|argument| systemd_quote(argument))
        .collect();
    let description = match agent {
        Agent::Daemon => "codemode-mcp gateway",
        Agent::Companion => "codemode-mcp companion",
    };

    format!(
        "[Unit]
Description={description}

[Service]
ExecStart={exec}
WorkingDirectory={home}
Environment={path}
Restart=always
RestartSec=10
KillMode=mixed
TimeoutStopSec={exit_timeout}
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy=default.target
",
        exec = exec.join(" "),
        home = systemd_quote(&paths.home.display().to_string()),
        path = systemd_quote(&format!("PATH={}", paths.search_path)),
        stdout = systemd_escape(&agent.log(paths, "out")),
        stderr = systemd_escape(&agent.log(paths, "err")),
    )
}

/// Escapes systemd's specifiers (`%`) and variable references (`$`)
fn systemd_escape(text: &str) -> String {
    text.replace('%', "%%").replace('$', "$$")
}

/// One double-quoted word of a unit file, with C-style escapes
fn systemd_quote(text: &str) -> String {
    let escaped = systemd_escape(&text.replace('\\', "\\\\").replace('"', "\\\""));

    format!("\"{escaped}\"")
}

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

/// `gui/<uid>/<label>`
fn target(uid: u32, agent: Agent) -> String {
    format!("gui/{uid}/{}", agent.label())
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
    let mut plan = binary_steps(paths, binary);
    plan.extend([
        Action::CreateDir(parent(&paths.worker)),
        Action::Install {
            from: worker.to_owned(),
            to: paths.worker.clone(),
        },
    ]);
    plan.extend(agent_steps(paths, uid, Agent::Daemon, config, drain));

    plan
}

/// Steps of `companion install`: the signed binary and its own LaunchAgent,
/// without the Monty worker
///
/// The binary is installed the same way as for the daemon, so the keychain
/// item holding the identity stays tied to the signed copy
pub fn companion_install_plan(
    paths: &ServicePaths,
    uid: u32,
    binary: &Path,
    config: Option<&Path>,
) -> Vec<Action> {
    let mut plan = binary_steps(paths, binary);
    // nothing to drain: the companion holds no executions
    plan.extend(agent_steps(
        paths,
        uid,
        Agent::Companion,
        config,
        Duration::ZERO,
    ));

    plan
}

fn parent(path: &Path) -> PathBuf {
    path.parent().map(Path::to_owned).unwrap_or_default()
}

/// The signed binary at its stable path and the short-name link
fn binary_steps(paths: &ServicePaths, binary: &Path) -> Vec<Action> {
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
    ]
}

/// Writes `agent`'s plist or unit and loads it, replacing a loaded copy
fn agent_steps(
    paths: &ServicePaths,
    uid: u32,
    agent: Agent,
    config: Option<&Path>,
    drain: Duration,
) -> Vec<Action> {
    let file = agent.service_file(paths);
    // the new file is checked before it replaces a working one, and before
    // the running service is stopped
    let staged = PathBuf::from(format!("{}.new", file.display()));
    let mut steps = vec![
        Action::CreateDir(paths.logs.clone()),
        Action::CreateDir(parent(file)),
    ];

    match paths.manager {
        Manager::Launchd => steps.extend([
            Action::Write {
                path: staged.clone(),
                contents: render_plist(agent, paths, config, drain),
            },
            Action::run(&["plutil", "-lint", &staged.display().to_string()]),
            Action::Rename {
                from: staged,
                to: file.to_owned(),
            },
            Action::Run {
                argv: vec!["launchctl".into(), "bootout".into(), target(uid, agent)],
                tolerate_failure: true,
                retry_for: None,
            },
            Action::Run {
                argv: vec![
                    "launchctl".into(),
                    "bootstrap".into(),
                    format!("gui/{uid}"),
                    file.display().to_string(),
                ],
                tolerate_failure: false,
                retry_for: Some(BOOTSTRAP_WAIT),
            },
        ]),
        // `restart` starts a stopped unit too, and waits out the old
        // instance's drain before it starts the new one
        Manager::Systemd => steps.extend([
            Action::Write {
                path: staged.clone(),
                contents: render_unit(agent, paths, config, drain),
            },
            Action::Rename {
                from: staged,
                to: file.to_owned(),
            },
            systemctl(&["daemon-reload"]),
            systemctl(&["enable", agent.unit()]),
            systemctl(&["restart", agent.unit()]),
        ]),
    }

    steps
}

fn systemctl(args: &[&str]) -> Action {
    let mut argv = vec!["systemctl", "--user"];
    argv.extend(args);

    Action::run(&argv)
}

/// Steps of `service uninstall`; state and installed files, including the
/// `cmcp` link, stay
pub fn uninstall_plan(paths: &ServicePaths, uid: u32) -> Vec<Action> {
    removal_steps(paths, uid, Agent::Daemon)
}

/// Steps of `companion uninstall`; the installed binary stays
pub fn companion_uninstall_plan(paths: &ServicePaths, uid: u32) -> Vec<Action> {
    removal_steps(paths, uid, Agent::Companion)
}

fn removal_steps(paths: &ServicePaths, uid: u32, agent: Agent) -> Vec<Action> {
    let file = agent.service_file(paths).to_owned();

    match paths.manager {
        Manager::Launchd => vec![
            Action::Run {
                argv: vec!["launchctl".into(), "bootout".into(), target(uid, agent)],
                tolerate_failure: true,
                retry_for: None,
            },
            Action::Remove(file),
        ],
        Manager::Systemd => vec![
            Action::Run {
                argv: ["systemctl", "--user", "disable", "--now", agent.unit()]
                    .map(str::to_owned)
                    .to_vec(),
                tolerate_failure: true,
                retry_for: None,
            },
            Action::Remove(file),
            systemctl(&["daemon-reload"]),
        ],
    }
}

/// Steps of `service restart`, or of restarting the companion after an update
pub fn restart_plan(manager: Manager, uid: u32, agent: Agent) -> Vec<Action> {
    match manager {
        Manager::Launchd => vec![Action::run(&[
            "launchctl",
            "kickstart",
            "-k",
            &target(uid, agent),
        ])],
        Manager::Systemd => vec![systemctl(&["restart", agent.unit()])],
    }
}

/// The read-only command that asks the service manager about `agent`
pub fn status_command(manager: Manager, uid: u32, agent: Agent) -> Vec<String> {
    match manager {
        Manager::Launchd => vec!["launchctl".into(), "print".into(), target(uid, agent)],
        Manager::Systemd => [
            "systemctl",
            "--user",
            "show",
            agent.unit(),
            "--property=LoadState,ActiveState,SubState,MainPID",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
}

/// The state and pid lines of [`status_command`]'s output, or `None` when
/// the service is not loaded
///
/// launchctl fails for an agent it does not know, so its output is always
/// of a loaded one; systemctl answers for any name, with `LoadState=not-found`
pub fn status_summary(manager: Manager, output: &str) -> Option<String> {
    let lines = output.lines().map(str::trim);
    let summary: Vec<&str> = match manager {
        Manager::Launchd => lines
            .filter(|line| line.starts_with("state =") || line.starts_with("pid ="))
            .collect(),
        Manager::Systemd => {
            if output
                .lines()
                .any(|line| line.trim() == "LoadState=not-found")
            {
                return None;
            }

            lines
                .filter(|line| !line.starts_with("LoadState=") && !line.is_empty())
                .collect()
        }
    };

    Some(summary.join(", "))
}

/// The pid the service manager reports for the running service, if it is
/// running
pub fn running_pid(manager: Manager, uid: u32) -> Option<u32> {
    let output = run_command(&status_command(manager, uid, Agent::Daemon)).ok()?;
    let prefix = match manager {
        Manager::Launchd => "pid = ",
        Manager::Systemd => "MainPID=",
    };

    output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(prefix)?.parse().ok())
        // systemd reports 0 for a unit with no running process
        .filter(|pid| *pid != 0)
}

/// Whether the user's systemd manager outlives their logins, so the service
/// keeps running with nobody logged in; `None` when `loginctl` cannot say
pub fn lingers() -> Option<bool> {
    let user = std::env::var("USER").ok()?;
    let output = run_command(&[
        "loginctl".into(),
        "show-user".into(),
        user,
        "--property=Linger".into(),
    ])
    .ok()?;

    match output.trim() {
        "Linger=yes" => Some(true),
        "Linger=no" => Some(false),
        _ => None,
    }
}

/// The starter config for `home`: the hub's own, or with `hub` a spoke's
pub fn starter_config(home: &Path, hub: Option<&str>) -> String {
    let home = home.display().to_string();

    match hub {
        None => STARTER_CONFIG.replace("{{HOME}}", &home),
        Some(hub) => SPOKE_CONFIG
            .replace("{{HUB}}", &toml::Value::String(hub.to_owned()).to_string())
            .replace("{{HOME}}", &home),
    }
}

/// Writes `contents` to `path` as the starter config, refusing to replace a
/// file
pub fn write_starter_config(path: &Path, contents: &str) -> Result<(), ServiceError> {
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

    std::io::Write::write_all(&mut file, contents.as_bytes())
        .map_err(io(format!("write {}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, policy::Policy};

    fn launchd(home: &str) -> ServicePaths {
        ServicePaths::for_manager(
            Manager::Launchd,
            Path::new(home),
            &Path::new(home).join("state"),
            None,
        )
    }

    #[test]
    fn plist_escapes_paths_and_runs_serve() {
        let paths = launchd("/Users/a&b");
        let plist = render_plist(
            Agent::Daemon,
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
        let paths = launchd("/Users/a");
        let drain = Duration::from_secs(20);

        let current = render_plist(Agent::Daemon, &paths, None, drain);
        assert_eq!(
            exit_timeout_warning(Manager::Launchd, &current, drain),
            None
        );

        // a plist from before the drain existed has no ExitTimeOut at all
        let old = current.replace("<key>ExitTimeOut</key>\n  <integer>50</integer>\n  ", "");
        let warning = exit_timeout_warning(Manager::Launchd, &old, drain);
        assert!(
            warning.is_some_and(|text| text.contains("service install")),
            "{old}"
        );
        assert!(
            exit_timeout_warning(Manager::Launchd, &current, Duration::from_secs(60)).is_some()
        );
    }

    #[test]
    fn the_systemd_unit_quotes_paths_keeps_the_shell_path_and_outlasts_the_drain() {
        let paths = ServicePaths::for_manager(
            Manager::Systemd,
            Path::new("/home/a b"),
            Path::new("/home/a b/state%1"),
            Some("/home/a b/.local/bin:/home/a b/.cargo/bin::/usr/bin"),
        );
        let drain = Duration::from_secs(20);
        let unit = render_unit(
            Agent::Daemon,
            &paths,
            Some(Path::new("/etc/\"c\".toml")),
            drain,
        );

        assert_eq!(
            paths.service_file,
            Path::new("/home/a b/.config/systemd/user/codemode-mcp.service")
        );
        assert!(unit.contains(
            "ExecStart=\"/home/a b/.local/bin/codemode-mcp\" \"--config\" \"/etc/\\\"c\\\".toml\" \"serve\"\n"
        ));
        // ~/.local/bin once, first, then the installing shell's own entries
        assert!(
            unit.contains(
                "Environment=\"PATH=/home/a b/.local/bin:/home/a b/.cargo/bin:/usr/bin\"\n"
            )
        );
        assert!(
            unit.contains("StandardError=append:/home/a b/state%%1/logs/codemode-mcp.err.log\n")
        );
        assert!(unit.contains("TimeoutStopSec=50\n"));
        assert_eq!(exit_timeout_warning(Manager::Systemd, &unit, drain), None);

        // without TimeoutStopSec systemd gives 90s, short of a 100s drain
        let old = unit.replace("TimeoutStopSec=50\n", "");
        assert_eq!(exit_timeout_warning(Manager::Systemd, &old, drain), None);
        assert!(
            exit_timeout_warning(Manager::Systemd, &old, Duration::from_secs(100))
                .is_some_and(|text| text.contains("service unit"))
        );
    }

    #[test]
    fn systemd_reports_a_missing_unit_as_not_loaded() {
        assert_eq!(
            status_summary(
                Manager::Systemd,
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n"
            ),
            None
        );
        assert_eq!(
            status_summary(
                Manager::Systemd,
                "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\n"
            )
            .as_deref(),
            Some("ActiveState=active, SubState=running, MainPID=42")
        );
    }

    #[test]
    fn the_spoke_starter_names_its_hub() -> Result<(), Box<dyn std::error::Error>> {
        let text = starter_config(Path::new("/home/someone"), Some("mac \"mini\""));
        let config = Config::parse(&text, Path::new("spoke.toml"))?;

        let hub = config.hub.ok_or("no [hub] section")?;
        assert_eq!(hub.host, "mac \"mini\"");
        assert_eq!(
            config.servers.keys().collect::<Vec<_>>(),
            ["secrets"],
            "a spoke's own write_env, nothing else"
        );

        Ok(())
    }

    #[test]
    fn starter_config_parses_with_the_intended_policies() -> Result<(), Box<dyn std::error::Error>>
    {
        let text = starter_config(Path::new("/Users/someone"), None);
        let config = Config::parse(&text, Path::new("starter.toml"))?;

        let onepassword = &config.servers["onepassword"];
        assert_eq!(onepassword.policy_for("list_environments"), Policy::Ask);
        assert_eq!(
            onepassword.grant_for("create_environment"),
            crate::policy::GrantMode::PerCall
        );
        assert!(onepassword.warm.is_some());
        assert!(config.notify.ntfy.is_none());

        assert_eq!(
            config.servers["calendar"].command.as_deref(),
            Some("/Users/someone/.local/bin/codemode-mcp")
        );

        // EventKit adapters: reads free, every write asks
        for (server, reads, writes) in [
            (
                "calendar",
                &["list_calendars", "list_events", "get_event"][..],
                &["create_event", "update_event", "delete_event"][..],
            ),
            (
                "reminders",
                &["list_reminder_lists", "list_reminders", "get_reminder"][..],
                &[
                    "create_reminder",
                    "update_reminder",
                    "complete_reminder",
                    "delete_reminder",
                ][..],
            ),
        ] {
            let config = &config.servers[server];
            assert!(!config.is_sensitive(), "{server}");
            for tool in reads {
                assert_eq!(config.policy_for(tool), Policy::Allow, "{server}.{tool}");
            }
            for tool in writes {
                assert_eq!(config.policy_for(tool), Policy::Ask, "{server}.{tool}");
            }
        }

        // Xcode: arbitrary code and deletes ask, the rest of the coding loop runs
        let xcode = &config.servers["xcode"];
        assert!(!xcode.is_sensitive());
        for tool in ["RunCodeSnippet", "InvokeDebuggerCommand", "XcodeRM"] {
            assert_eq!(xcode.policy_for(tool), Policy::Ask, "{tool}");
        }
        for tool in [
            "XcodeOpenWorkspace",
            "XcodeUpdate",
            "BuildProject",
            "RunAllTests",
        ] {
            assert_eq!(xcode.policy_for(tool), Policy::Allow, "{tool}");
        }

        Ok(())
    }
}
