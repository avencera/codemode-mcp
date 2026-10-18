//! Command-line entry point: serve the gateway, inspect its catalog, or run
//! one script against the configured upstreams

use std::{
    io::{IsTerminal, Read, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use codemode_mcp::{
    adapters::apple::Entity,
    admin::{
        self, CompanionCheckOneRequest, CompanionCheckRequest, CompanionCheckResponse,
        CompanionCheckResult, CompanionListResponse, CompanionTrustRequest, CompanionTrustResponse,
        EnrollRequest, EnrollResponse, InviteOpenRequest, InviteOpenResponse, InviteResponse,
        InviteStatusRequest, OAuthLoginResponse, OAuthLogoutResponse, OAuthServerRequest,
        OAuthStatusResponse, RemoveRequest, RemoveResponse, WarmRequest, WarmResponse,
    },
    app::App,
    catalog::function_prefix,
    companion::{
        self, AnyTicket, InviteStatus, InviteTicket, Joining, PairCheck, Paired, Pairing,
        ProgramTarget, ProgramValue, Ticket,
    },
    config::{Config, ConfigError, expand_home},
    executions::WaitResult,
    op,
    secrets::NOT_TEXT,
    server::{Listeners, outcome_text},
    service::{self, Action, ServicePaths},
    store::{self, Store},
    update::{self, Release, Source},
    usage::{
        Caller, EXEC_CLIENT,
        report::{Reporter, human_duration, parse_since, render_stats},
    },
};
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use qrcode::{EcLevel, QrCode, render::unicode::Dense1x2};
use tracing_subscriber::EnvFilter;

/// How often `companion invite` asks the daemon whether the other Mac came
const INVITE_POLL: Duration = Duration::from_secs(1);

/// How long startup waits for upstreams to finish their first connection attempt
const SETTLE_LIMIT: Duration = Duration::from_secs(15);

/// How long a stop lets in-flight MCP requests answer after the drain
const ANSWER_GRACE: Duration = Duration::from_secs(5);

/// How long the CLI waits on an admin route; `companion check` waits up to
/// [`companion::ASK_TIMEOUT`] for the slowest companion, so this outlasts it
/// and the per-companion results still arrive
const ADMIN_TIMEOUT: Duration = companion::ASK_TIMEOUT.saturating_add(Duration::from_secs(30));

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Config file; defaults to ~/.config/codemode-mcp/config.toml
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server
    Serve,
    /// Connect to the upstreams and print the tool catalog
    Tools {
        /// Print the full documented Python stubs instead of one line per tool
        #[arg(long)]
        stubs: bool,
    },
    /// Run a script once against the upstreams, without the server; tools
    /// whose policy is `ask` are refused because no approval page is served
    Exec {
        /// Script file, or `-` for stdin
        script: String,
    },
    /// Print usage numbers per client
    Stats {
        /// Window such as 12h, 7d or 2w
        #[arg(long, default_value = "7d")]
        since: String,
    },
    /// Write the Markdown usage review
    Review {
        /// Window such as 12h, 7d or 2w
        #[arg(long, default_value = "7d")]
        since: String,
        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Manage the passkeys that approve sensitive tool calls
    Passkey {
        #[command(subcommand)]
        command: PasskeyCommand,
    },
    /// 1Password helpers
    Op {
        #[command(subcommand)]
        command: OpCommand,
    },
    /// Sign in to remote upstreams configured with `oauth = true`
    #[command(name = "oauth")]
    OAuth {
        #[command(subcommand)]
        command: OAuthCommand,
    },
    /// Manage the launchd service
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Replace the installed binary and Monty worker with a GitHub release,
    /// then restart the service if it is installed
    Update {
        /// Release tag such as v0.2.0; defaults to the latest release
        #[arg(long)]
        tag: Option<String>,
        /// Reinstall even when the installed binary already reports the tag
        #[arg(long)]
        force: bool,
        /// Print what would be installed without downloading it
        #[arg(long)]
        dry_run: bool,
    },
    /// Read 1Password references on another Mac, where the owner is
    Companion {
        #[command(subcommand)]
        command: CompanionCommand,
    },
    /// Manage the configuration file
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Run a built-in MCP adapter on stdio, as an upstream of the gateway
    Adapter {
        #[command(subcommand)]
        command: AdapterCommand,
    },
}

#[derive(Subcommand)]
enum OAuthCommand {
    /// Start a browser sign-in on the running daemon
    Login {
        /// Server name from the config
        server: String,
        /// Print the link without opening a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Show the login state of every OAuth server
    Status,
    /// Forget a server's tokens; it reconnects anonymously
    Logout {
        /// Server name from the config
        server: String,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Copy the binary and Monty worker to stable paths, write the
    /// LaunchAgent and load it
    Install {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// Unload and remove the LaunchAgent; state and installed files stay
    Uninstall {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// Show whether the service is loaded and healthy
    Status {
        /// Print what would be checked
        #[arg(long)]
        dry_run: bool,
    },
    /// Restart the running service; the secrets it read for its servers
    /// carry over, sealed, so nothing is asked again
    Restart {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
        /// Read every secret again after the restart, as after rotating a
        /// key in 1Password
        #[arg(long)]
        fresh: bool,
    },
}

#[derive(Subcommand)]
enum CompanionCommand {
    /// On the gateway Mac: print a one-line command (and its QR code) that
    /// sets up another Mac as a companion, then wait for it to register;
    /// needs the daemon running
    Invite {
        /// Print a ticket that pairs without reaching this Mac, for when the
        /// other Mac cannot; its block is then added here by hand
        #[arg(long)]
        manual: bool,
        /// Seconds the invite stays open, at most 600
        #[arg(long, value_name = "SECONDS")]
        valid_for: Option<u64>,
    },
    /// On the companion Mac: pair with a ticket from `companion invite`,
    /// then install and start the companion
    ///
    /// An invite ticket registers this Mac with the gateway and ends with a
    /// check approved by Touch ID here. A `--manual` ticket writes the
    /// `[companion]` section and prints the block the gateway needs
    Pair {
        /// Ticket from `companion invite`
        ticket: String,
        /// Keep this Mac's key in a file (mode 0600) instead of the login
        /// keychain
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
    /// On the companion Mac: answer the gateway's reads, in the foreground
    Serve,
    /// On the companion Mac: copy the binary, sign it and load a LaunchAgent
    /// that runs `companion serve`
    Install {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// On the companion Mac: unload and remove the LaunchAgent
    Uninstall {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
    },
    /// On the gateway Mac: ask the companions and phones, and only them, to
    /// read a reference, and report whether each could; the value is never
    /// shown
    Check {
        /// An op://vault/item/field reference
        reference: String,
        /// Ask only this companion or phone, and finish when it answers;
        /// without it every one is asked and the others are waited for
        #[arg(long)]
        companion: Option<String>,
    },
    /// On the gateway Mac: have a companion Mac create a 1Password item from
    /// the secret on stdin; it asks Touch ID there and never edits or
    /// deletes an item
    Create {
        /// Vault to create the item in; the companion must list it under
        /// `create_vaults`
        #[arg(long)]
        vault: String,
        /// Title of the new item; the companion refuses a title in use
        #[arg(long)]
        title: String,
        /// 1Password category
        #[arg(long, default_value = companion::wire::DEFAULT_CATEGORY)]
        category: String,
        /// Label of the field that holds the secret
        #[arg(long, default_value = companion::wire::DEFAULT_FIELD)]
        field: String,
        /// Companion to ask; needed when several are listed
        #[arg(long)]
        companion: Option<String>,
    },
    /// On the gateway Mac: list the companion Macs and phones in the config
    /// and whether the daemon trusts each; an untrusted one is never used
    List,
    /// On the gateway Mac: trust a companion or phone the config lists, once
    /// Touch ID on this Mac approves it, so the daemon starts using it
    ///
    /// A device paired with an invite is trusted already; this is for one
    /// added to the config by hand, or one listed while the daemon could not
    /// vouch for it
    Trust {
        /// Its name under `secrets.companions` or `secrets.phones`
        name: String,
    },
    /// Print this Mac's companion endpoint id, creating its key if needed
    Id {
        /// Read the key from this file instead of the login keychain
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Write a starter config; refuses to replace an existing file
    Init {
        /// Print it instead of writing it
        #[arg(long)]
        print: bool,
    },
}

#[derive(Subcommand)]
enum AdapterCommand {
    /// The Calendar app's events as MCP tools, through EventKit (macOS)
    Calendar,
    /// The Reminders app as MCP tools, through EventKit (macOS)
    Reminders,
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// Print a one-time link (valid 10 minutes) for adding a passkey; needs
    /// the daemon running. Once a passkey exists, an existing passkey must
    /// approve the new one before the link works
    Enroll {
        /// Name for the new passkey, e.g. the device holding it
        #[arg(long)]
        label: String,
    },
    /// List enrolled passkeys
    List,
    /// Ask an existing passkey to approve removing a passkey; needs the
    /// daemon running
    Remove {
        /// Id from `passkey list`
        id: i64,
    },
}

#[derive(Subcommand)]
enum OpCommand {
    /// Run the configured warm-up calls on the running daemon so the
    /// 1Password app's own prompts happen now, on the Mac
    Warm {
        /// Only this server
        #[arg(long)]
        server: Option<String>,
    },
    /// Print 1Password values, like `op read`, approved wherever the owner
    /// is: Touch ID here, then (or while away, at once) on a companion Mac or
    /// the phone
    ///
    /// One reference prints its value; several print a JSON object of each
    /// reference to its value, all with one approval. What is printed lands
    /// in whatever reads this command's output, such as an agent's context;
    /// prefer `--out-file`, `op inject` or `op run`
    #[command(after_long_help = OP_AFTER_HELP)]
    Read {
        /// The `op://vault/item/field` references
        #[arg(required_unless_present = "describe", conflicts_with = "describe")]
        references: Vec<String>,
        /// Describe the item instead of naming it, such as "Pushover app
        /// token"; only the phone can answer, where the owner picks the item
        /// with AutoFill
        #[arg(long)]
        describe: Option<String>,
        /// Why the value is needed; every prompt shows it
        #[arg(long)]
        reason: Option<String>,
        /// Hand the same values out again without asking for this long, such
        /// as `15m`; at most 60 minutes, and every prompt says so
        #[arg(long, value_parser = parse_keep)]
        keep: Option<u64>,
        /// Write what would be printed to this file, created with
        /// `--file-mode`; every prompt names it
        #[arg(short = 'o', long)]
        out_file: Option<PathBuf>,
        /// Replace `--out-file` if it exists
        #[arg(short, long)]
        force: bool,
        /// Mode of `--out-file`, in octal
        #[arg(long, default_value = "0600", value_parser = parse_mode)]
        file_mode: u32,
        /// Print the value without a trailing newline
        #[arg(short, long)]
        no_newline: bool,
    },
    /// Fill each `{{ op://… }}` in a template, like `op inject`, with one
    /// approval for the whole template
    ///
    /// The usual way to keep a secrets file, such as a stack's
    /// `*.secrets.env`: the values go into the file and never into this
    /// command's output
    #[command(after_long_help = OP_AFTER_HELP)]
    Inject {
        /// The template; standard input when not given
        #[arg(short, long)]
        in_file: Option<PathBuf>,
        /// Where to write the filled template, created with `--file-mode`;
        /// standard output when not given
        #[arg(short, long)]
        out_file: Option<PathBuf>,
        /// Replace `--out-file` if it exists; it may be the template itself
        #[arg(short, long)]
        force: bool,
        /// Mode of `--out-file`, in octal
        #[arg(long, default_value = "0600", value_parser = parse_mode)]
        file_mode: u32,
        /// Why the values are needed; every prompt shows it
        #[arg(long)]
        reason: Option<String>,
        /// Hand the same values out again without asking for this long, such
        /// as `15m`; at most 60 minutes, and every prompt says so
        #[arg(long, value_parser = parse_keep)]
        keep: Option<u64>,
    },
    /// Run a command with 1Password values in its environment only, like
    /// `op run`, with one approval for all of them
    ///
    /// Opt-in for high-severity secrets: no file holds the values, they live
    /// only in the command's environment, and any value of 3 or more
    /// characters the command prints, or any line of one, is replaced with
    /// [redacted]. Values come from `--env-file` lines such
    /// as `TOKEN=op://vault/item/field` or `URL=https://{{ op://… }}@host`,
    /// and from variables already set to an `op://` reference
    #[command(after_long_help = OP_AFTER_HELP)]
    Run {
        /// An env file of `KEY=value` lines; may be given more than once
        #[arg(long)]
        env_file: Vec<PathBuf>,
        /// Pass the command's output through unmasked
        #[arg(long)]
        no_masking: bool,
        /// Why the values are needed; every prompt shows it
        #[arg(long)]
        reason: Option<String>,
        /// Hand the same values out again without asking for this long, such
        /// as `15m`; at most 60 minutes, and every prompt says so
        #[arg(long, value_parser = parse_keep)]
        keep: Option<u64>,
        /// The command and its arguments, after `--`
        #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
        command: Vec<String>,
    },
}

/// Who `op read`, `op inject` and `op run` ask, shown under their `--help`
const OP_AFTER_HELP: &str = "\
Who approves: while the owner is at this Mac, its own Touch ID prompt names every value and the \
program's reason, and this Mac's `op` reads them. The phone and companion Macs are asked 5 seconds \
later, or at once while the owner is away, and the first approval sends every value. A Deny on any \
device stops the read. Every prompt names the file the values go to. Nothing is reused from \
earlier approvals unless one was given `--keep`, and the daemon keeps no value past that; a phone \
keeps a copy sealed to its Face ID.

Which command: `op inject -o FILE` writes values into a file such as a stack's *.secrets.env, which \
is the default for most secrets. For high-severity secrets that should never be in a file, keep \
only op:// references and use `op run`.";

/// Reads a keep window such as `15m`, `1h` or `90s`, in seconds; a bare
/// number is minutes
fn parse_keep(text: &str) -> Result<u64, String> {
    let (number, unit) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => text.split_at(at),
        None => (text, "m"),
    };
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        _ => return Err(format!("{text} is not a duration such as 15m")),
    };
    let secs = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(scale))
        .filter(|secs| *secs > 0)
        .ok_or_else(|| format!("{text} is not a duration such as 15m"))?;
    if secs > companion::wire::MAX_KEEP_SECS {
        return Err(format!(
            "{text} is longer than the 60 minutes a grant may last"
        ));
    }

    Ok(secs)
}

/// Reads an octal file mode such as `0600`
fn parse_mode(text: &str) -> Result<u32, String> {
    let mode = u32::from_str_radix(text.trim_start_matches("0o"), 8)
        .map_err(|_| format!("{text} is not an octal mode such as 0600"))?;
    if mode > 0o777 {
        return Err(format!("{text} is not a file mode"));
    }

    Ok(mode)
}

#[tokio::main]
async fn main() -> Result<()> {
    // the daemon and the `op` commands hold secret values in memory, which a
    // crash must not write to disk; the hard limit stays, so a command `op
    // run` starts can still turn its own dumps back on
    let core = rustix::process::getrlimit(rustix::process::Resource::Core);
    let _ = rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            ..core
        },
    );

    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rmcp=warn")),
        )
        .with_writer(codemode_mcp::secrets::redacting_logs(std::io::stderr))
        .init();

    let cli = Cli::parse();
    let explicit = cli.config.clone();
    let path = match cli.config {
        Some(path) => path,
        None => Config::default_path()?,
    };

    match cli.command {
        Command::Serve => serve_command(Config::load(&path)?).await,
        Command::Tools { stubs } => tools_command(Config::load(&path)?, stubs).await,
        Command::Exec { script } => exec_command(Config::load(&path)?, &script).await,
        Command::Stats { since } => stats_command(&Config::load(&path)?, &since),
        Command::Review { since, out } => review_command(&Config::load(&path)?, &since, out),
        Command::Passkey { command } => passkey_command(&Config::load(&path)?, command).await,
        Command::Op { command } => match command {
            OpCommand::Warm { server } => warm_command(&Config::load(&path)?, server).await,
            command => op_command(&load_or_default(&path)?, command).await,
        },
        Command::OAuth { command } => oauth_command(&Config::load(&path)?, command).await,
        Command::Service { command } => {
            service_command(&load_or_default(&path)?, explicit.as_deref(), command).await
        }
        Command::Companion { command } => {
            companion_command(&path, explicit.as_deref(), command).await
        }
        Command::Update {
            tag,
            force,
            dry_run,
        } => update_command(&load_or_default(&path)?, tag, force, dry_run).await,
        Command::Config {
            command: ConfigCommand::Init { print },
        } => config_init_command(&path, print),
        Command::Adapter {
            command: AdapterCommand::Calendar,
        } => eventkit_adapter_command(Entity::Events).await,
        Command::Adapter {
            command: AdapterCommand::Reminders,
        } => eventkit_adapter_command(Entity::Reminders).await,
    }
}

/// The config at `path`, or the defaults when there is no file yet
fn load_or_default(path: &std::path::Path) -> Result<Config> {
    match Config::load(path) {
        Ok(config) => Ok(config),
        Err(ConfigError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(Config::default())
        }
        Err(error) => Err(error.into()),
    }
}

async fn oauth_command(config: &Config, command: OAuthCommand) -> Result<()> {
    match command {
        OAuthCommand::Login { server, no_open } => {
            let response: OAuthLoginResponse =
                admin_post(config, "/admin/oauth/login", &OAuthServerRequest { server }).await?;
            println!("Open this link in a browser on this Mac to sign in:");
            println!("{}", response.authorization_url);
            if !no_open && cfg!(target_os = "macos") {
                let opened = std::process::Command::new("open")
                    .arg(&response.authorization_url)
                    .status();
                if !opened.is_ok_and(|status| status.success()) {
                    eprintln!("could not open a browser; open the link yourself");
                }
            }
        }
        OAuthCommand::Status => {
            let response: OAuthStatusResponse =
                admin_post(config, "/admin/oauth/status", &()).await?;
            if response.servers.is_empty() {
                println!("No server is configured with `oauth = true`.");
            }
            let now = store::now_ms();
            for entry in response.servers {
                let login = &entry.login;
                let detail = if login.logged_in {
                    let expiry = login.expires_at_ms.map_or_else(
                        || "no expiry".to_owned(),
                        |at| {
                            if at > now {
                                format!("token expires in {}", human_duration(at - now))
                            } else {
                                format!("token expired {} ago", human_duration(now - at))
                            }
                        },
                    );
                    let refresh = if login.refreshable {
                        "refreshes automatically"
                    } else {
                        "no refresh token"
                    };
                    let scopes = if login.scopes.is_empty() {
                        "-".to_owned()
                    } else {
                        login.scopes.join(" ")
                    };

                    format!("logged in, {expiry}, {refresh}, scopes {scopes}")
                } else {
                    "not logged in".to_owned()
                };
                println!("{}\t{}\t{detail}", login.server, entry.state);
            }
        }
        OAuthCommand::Logout { server } => {
            let response: OAuthLogoutResponse = admin_post(
                config,
                "/admin/oauth/logout",
                &OAuthServerRequest {
                    server: server.clone(),
                },
            )
            .await?;
            if response.removed {
                println!("Forgot the login for {server}; it reconnects without one.");
            } else {
                println!("{server} had no stored login.");
            }
        }
    }

    Ok(())
}

async fn service_command(
    config: &Config,
    explicit_config: Option<&std::path::Path>,
    command: ServiceCommand,
) -> Result<()> {
    let paths = ServicePaths::from_env(&config.state_dir()?)?;
    let uid = service::current_uid()?;
    let starts_daemon = matches!(
        command,
        ServiceCommand::Install { .. } | ServiceCommand::Restart { .. }
    );

    let (plan, dry_run) = match command {
        ServiceCommand::Install { dry_run } => {
            let binary = std::env::current_exe().wrap_err("cannot locate this binary")?;
            let worker = match &config.worker_path {
                Some(path) => expand_home(path),
                None => {
                    let checkout = std::env::current_dir()?.join(".tools/bin/monty");
                    if checkout.is_file() {
                        checkout
                    } else {
                        paths.worker.clone()
                    }
                }
            };
            if !worker.is_file() {
                return Err(service::ServiceError::NoWorker(worker).into());
            }
            if config.worker_path.is_some() {
                eprintln!(
                    "note: `worker_path` is set, so the service keeps using {} rather than the \
                     installed copy; remove it from the config to use {}",
                    worker.display(),
                    paths.worker.display()
                );
            }
            // an explicit config is pinned in the plist; the default path
            // is found by the daemon itself
            let pinned = match explicit_config {
                Some(path) => Some(std::path::absolute(path)?),
                None => None,
            };

            let plan = service::install_plan(
                &paths,
                uid,
                &binary,
                &worker,
                pinned.as_deref(),
                config.limits.drain(),
            );
            if !dry_run {
                service::check_signing_identity(&plan)?;
            }

            (plan, dry_run)
        }
        ServiceCommand::Uninstall { dry_run } => (service::uninstall_plan(&paths, uid), dry_run),
        ServiceCommand::Restart { dry_run, fresh } => {
            if fresh && !dry_run {
                let forgot: admin::ForgetSecretsResponse =
                    admin_post_as_owner(config, "/admin/secrets/forget", &serde_json::json!({}))
                        .await
                        .wrap_err("could not ask the daemon to forget its secrets")?;
                println!(
                    "The daemon forgot {} secrets; they are read again after the restart.",
                    forgot.forgotten
                );
            }

            (service::restart_plan(uid, service::Agent::Daemon), dry_run)
        }
        ServiceCommand::Status { dry_run } => {
            return service_status(config, &paths, uid, dry_run).await;
        }
    };

    if dry_run {
        print_plan(&plan);

        return Ok(());
    }

    let previous_pid = service::running_pid(uid);
    for action in &plan {
        println!("{}", action.describe());
        action.apply()?;
    }

    // launchctl returns before the new daemon listens, so a follow-up such
    // as `op warm` would hit a closed admin port
    if starts_daemon {
        wait_until_serving(config, uid, previous_pid).await?;
    }

    Ok(())
}

/// The secret on stdin, minus one trailing newline; empty input is refused
/// and the text of the secret appears in no message
fn read_secret_from_stdin() -> Result<String> {
    if std::io::stdin().is_terminal() {
        bail!("pipe the secret in on stdin, e.g. `pbpaste | codemode-mcp companion create ...`");
    }

    // escaping only grows a value, so anything longer than the escaped limit
    // is refused without reading the rest of an endless pipe
    let limit = codemode_mcp::secrets::MAX_ITEM_VALUE_JSON_BYTES;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .wrap_err("cannot read the secret from stdin")?;
    if bytes.len() > limit {
        bail!("the secret on stdin is over {} KiB", limit / 1024);
    }
    let text = String::from_utf8(bytes).map_err(|_| eyre!("the secret on stdin is not UTF-8"))?;
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if value.is_empty() {
        bail!(
            "nothing on stdin; pipe the secret in, e.g. `pbpaste | codemode-mcp companion create ...`"
        );
    }

    Ok(value.to_owned())
}

async fn companion_command(
    path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
    command: CompanionCommand,
) -> Result<()> {
    match command {
        CompanionCommand::Invite { manual, valid_for } => {
            let config = load_or_default(path)?;
            if manual {
                manual_invite(&config).await?;
            } else {
                invite(&config, valid_for).await?;
            }
        }
        CompanionCommand::Pair {
            ticket,
            identity_file,
        } => match AnyTicket::decode(&ticket)? {
            AnyTicket::Invite(ticket) => {
                pair_with_invite(path, explicit_config, &ticket, identity_file.as_deref()).await?;
            }
            AnyTicket::Manual(ticket) => {
                pair_by_hand(path, explicit_config, &ticket, identity_file.as_deref())?;
            }
        },
        CompanionCommand::Serve => {
            strip_companion_allow(path)?;
            companion_serve_command(Config::load(path)?).await?;
        }
        CompanionCommand::Install { dry_run } => {
            if !dry_run {
                strip_companion_allow(path)?;
            }
            install_companion(path, explicit_config, dry_run)?;
        }
        CompanionCommand::Uninstall { dry_run } => {
            let config = load_or_default(path)?;
            let paths = ServicePaths::from_env(&config.state_dir()?)?;
            let plan = service::companion_uninstall_plan(&paths, service::current_uid()?);
            run_plan(&plan, dry_run)?;
        }
        CompanionCommand::Check {
            reference,
            companion,
        } => {
            let config = load_or_default(path)?;
            match &companion {
                Some(name) => println!(
                    "Asking {name} to read the reference. Approve on that device; no other is \
                     asked."
                ),
                None => println!(
                    "Asking the companions to read the reference. Touch ID is asked on their \
                     Macs; approve there."
                ),
            }
            let response: CompanionCheckResponse = match companion {
                Some(companion) => admin_post(
                    &config,
                    "/admin/companion/check/one",
                    &CompanionCheckOneRequest {
                        reference,
                        companion,
                    },
                )
                .await
                .map_err(|error| {
                    // a daemon from before `--companion` has no such route,
                    // so it refuses instead of asking every device
                    if error.to_string().contains("404") {
                        error.wrap_err(
                            "the running daemon cannot check one device; restart it with \
                             `codemode-mcp service restart`",
                        )
                    } else {
                        error
                    }
                })?,
                None => {
                    admin_post(
                        &config,
                        "/admin/companion/check",
                        &CompanionCheckRequest { reference },
                    )
                    .await?
                }
            };

            let mut failed = false;
            for entry in response.companions {
                match entry.result {
                    CompanionCheckResult::Ok { bytes } => {
                        println!("{}: ok ({bytes} bytes)", entry.name);
                    }
                    CompanionCheckResult::Error { message } => {
                        failed = true;
                        println!("{}: FAILED ({message})", entry.name);
                    }
                }
            }
            if failed {
                std::process::exit(1);
            }
        }
        CompanionCommand::Create {
            vault,
            title,
            category,
            field,
            companion,
        } => {
            let value = read_secret_from_stdin()?;
            let config = load_or_default(path)?;
            println!(
                "Asking the companion to create \"{title}\" in {vault}. Touch ID is asked on its \
                 Mac; approve there."
            );
            let response: admin::CompanionCreateResponse = admin_post_as_owner(
                &config,
                "/admin/companion/create",
                &admin::CompanionCreateRequest {
                    companion,
                    item: companion::NewItem {
                        vault,
                        title,
                        category: Some(category),
                        field: Some(field),
                        value,
                    },
                },
            )
            .await
            .map_err(|error| {
                if may_have_reached_daemon(&error) {
                    error.wrap_err(
                        "the daemon did not answer, so the item may have been created; check the \
                         vault in 1Password before trying again",
                    )
                } else {
                    error
                }
            })?;

            match response {
                admin::CompanionCreateResponse::Created {
                    companion,
                    id,
                    reference,
                } => println!("{companion} created the item {id}\nreference: {reference}"),
                admin::CompanionCreateResponse::Refused { message } => {
                    eprintln!("Nothing was created: {message}");
                    std::process::exit(1);
                }
                admin::CompanionCreateResponse::Unconfirmed { message } => {
                    eprintln!(
                        "The item may have been created: {message}\nCheck the vault in \
                         1Password before trying again."
                    );
                    std::process::exit(1);
                }
            }
        }
        CompanionCommand::List => {
            let config = load_or_default(path)?;
            let listed: CompanionListResponse =
                admin_post(&config, "/admin/companion/list", &()).await?;
            if listed.devices.is_empty() {
                println!("No companion Mac or phone is listed under [secrets].");
            }
            for device in listed.devices {
                let state = if device.trusted {
                    "trusted".to_owned()
                } else {
                    format!(
                        "NOT TRUSTED, not used; run `codemode-mcp companion trust {}`",
                        device.name
                    )
                };
                println!(
                    "{} ({}, {}, fingerprint {}): {state}",
                    device.name, device.kind, device.id, device.fingerprint
                );
            }
        }
        CompanionCommand::Trust { name } => {
            let config = load_or_default(path)?;
            println!(
                "Approve trusting {name} with Touch ID on this Mac; check that the prompt shows \
                 the fingerprint `codemode-mcp companion list` gives for it."
            );
            let trusted: CompanionTrustResponse = admin_post_as_owner(
                &config,
                "/admin/companion/trust",
                &CompanionTrustRequest { name },
            )
            .await?;
            println!(
                "{} ({}, fingerprint {}) is trusted; the daemon uses it from now on.",
                trusted.device.name, trusted.device.kind, trusted.device.fingerprint
            );
        }
        CompanionCommand::Id { identity_file } => {
            let file = match identity_file {
                Some(file) => Some(file),
                None => load_or_default(path)?
                    .companion
                    .and_then(|companion| companion.identity_file),
            };
            println!("{}", companion::companion_id(file.as_deref())?);
        }
    }

    Ok(())
}

/// Opens an invite on the daemon, prints the command that uses it, and
/// reports the Mac that registers with it
async fn invite(config: &Config, valid_for: Option<u64>) -> Result<()> {
    println!("Approve the pairing with Touch ID on this Mac.");
    let opened: InviteOpenResponse = admin_post_as_owner(
        config,
        "/admin/companion/invite/open",
        &InviteOpenRequest {
            valid_secs: valid_for,
        },
    )
    .await?;
    let ticket = &opened.ticket;
    // the latest release rather than this build's version: a build from a
    // checkout may have no release, and the pairing protocol is versioned
    let one_liner = format!(
        "curl -LSfs https://github.com/{}/releases/latest/download/install.sh | sh -s -- --pair {ticket}",
        update::REPOSITORY
    );

    println!(
        "On the other Mac (the one that has 1Password and the owner), paste this into a terminal:"
    );
    println!("  {one_liner}");
    println!(
        "It installs codemode-mcp, registers that Mac with this one ({}) and starts it as a \
         companion. Where codemode-mcp is already installed, this does the same:",
        opened.gateway_name
    );
    println!("  codemode-mcp companion pair {ticket}");
    // piped output gets the text only; the escape codes would be noise
    if std::io::stdout().is_terminal() {
        println!(
            "\nOr scan this with a phone and paste the text it copies into a terminal on the \
             other Mac. To pair an iPhone instead, scan it in the codemode-mcp Companion app:\n"
        );
        // the invite is open already, so a QR failure must not end the wait
        match terminal_qr(&one_liner) {
            Ok(qr) => println!("{qr}"),
            Err(error) => println!("(no QR code: {error})"),
        }
    }
    println!(
        "\nWaiting for the other Mac. The invite works once, within {}.",
        human_duration(i64::try_from(opened.valid_secs.saturating_mul(1000)).unwrap_or(i64::MAX))
    );

    wait_for_registration(config, &opened.invite).await
}

/// Polls the invite until the Mac that used it is done, and reports it
async fn wait_for_registration(config: &Config, invite: &str) -> Result<()> {
    let request = InviteStatusRequest {
        invite: invite.to_owned(),
    };
    let mut announced = false;
    loop {
        let status: InviteStatus =
            admin_post_as_owner(config, "/admin/companion/invite/status", &request).await?;
        match status {
            InviteStatus::Open { .. } | InviteStatus::Registering => {}
            InviteStatus::Expired => bail!(
                "the invite expired before another Mac used it; run `codemode-mcp companion \
                 invite` again"
            ),
            InviteStatus::Failed { message } => {
                bail!("a Mac used the invite but was not added: {message}")
            }
            InviteStatus::Registered {
                name,
                id,
                already_listed,
                phone,
            } => {
                if !announced {
                    announce_registration(&name, id, already_listed, phone);
                    if phone {
                        println!(
                            "Waiting for {name} to check the pairing; approve the read on the \
                             phone."
                        );
                    } else {
                        println!(
                            "Waiting for {name} to start its companion; the check needs a Touch \
                             ID approval there."
                        );
                    }
                    announced = true;
                }
            }
            InviteStatus::Done {
                name,
                id,
                already_listed,
                check,
                in_use,
                phone,
            } => {
                if !announced {
                    announce_registration(&name, id, already_listed, phone);
                }
                if !in_use {
                    bail!(
                        "{name} is in this Mac's config, but the daemon does not read through it: \
                         its setup ended before the check reached it. Finish it with a new \
                         `codemode-mcp companion invite` and the pair command on {name}, or \
                         remove its [[secrets.companions]] entry; a restart would start using it \
                         as it is."
                    );
                }

                return match check {
                    Some(PairCheck::Read { reference, bytes }) => {
                        println!("Check passed: {name} read {reference} ({bytes} bytes).");

                        Ok(())
                    }
                    Some(PairCheck::Failed { reference, message }) => {
                        // the message carries the companion's own words
                        bail!(
                            "{name} is paired, but reading {reference} through it failed: {}",
                            peer_text(&message)
                        )
                    }
                    Some(PairCheck::Skipped) => {
                        println!(
                            "No server here uses an op:// reference, so there was nothing to check."
                        );

                        Ok(())
                    }
                    Some(PairCheck::NothingSealed) => {
                        println!(
                            "Paired, with nothing to check yet: nothing has been read since the \
                             daemon started. {name} opens a reference with Face ID once it has \
                             been read, and until then you enter its value there."
                        );

                        Ok(())
                    }
                    None => {
                        println!(
                            "{name} hung up without a check; once its companion runs, try \
                             `codemode-mcp companion check <reference>`."
                        );

                        Ok(())
                    }
                };
            }
        }
        tokio::time::sleep(INVITE_POLL).await;
    }
}

fn announce_registration(name: &str, id: iroh::EndpointId, already_listed: bool, phone: bool) {
    if already_listed {
        println!("{name} ({id}) registered; it was already in this Mac's config.");
    } else if phone {
        println!(
            "{name} ({id}) registered and was added to [secrets.phones] in this Mac's config. \
             The daemon asks it from now on."
        );
    } else {
        println!(
            "{name} ({id}) registered and was added to [secrets.companions] in this Mac's \
             config. The daemon starts reading through it once the check reaches it."
        );
    }
}

/// `text` as a QR code of half-block characters, drawn black on white with
/// 256-color escapes so it scans the same in dark and light terminal themes
fn terminal_qr(text: &str) -> Result<String> {
    // the lowest error correction keeps the code small enough for a terminal;
    // a screen has no smudges or tears for more of it to recover from
    let code = QrCode::with_error_correction_level(text, EcLevel::L)?;
    let image = code.render::<Dense1x2>().build();

    Ok(image
        .lines()
        .map(|line| format!("\x1b[38;5;16;48;5;231m{line}\x1b[0m"))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Prints a ticket that carries everything the companion's config needs,
/// for pairing without reaching this Mac
async fn manual_invite(config: &Config) -> Result<()> {
    let response: InviteResponse =
        admin_post_as_owner(config, "/admin/companion/invite", &()).await?;
    let name = response.gateway_name.clone();
    let ticket = response.ticket().encode()?;
    println!("On the other Mac (the one that has 1Password and the owner), run:");
    println!("  codemode-mcp companion pair {ticket}");
    println!("It prints a block to append to the config on this Mac ({name}).");
    println!(
        "Once it is appended, run `codemode-mcp companion trust <its name>` here; the daemon \
         uses no device the config lists until Touch ID on this Mac approves it."
    );

    Ok(())
}

/// Registers this Mac with the invite's gateway, writes its `[companion]`
/// section, starts the agent and has the gateway read one reference
/// through it
async fn pair_with_invite(
    path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
    ticket: &InviteTicket,
    identity_file: Option<&std::path::Path>,
) -> Result<()> {
    // everything below is refused before the invite is used up
    let existing = load_or_default(path)?.companion;
    if let Some(section) = &existing
        && section.gateway != ticket.gateway
    {
        bail!(
            "{} already has a [companion] section for another gateway ({}); remove it to pair \
             with this one",
            path.display(),
            section.gateway_name
        );
    }
    // an existing section is kept as it is, so the gateway must list the key
    // and port its agent uses, not ones this run would pick
    let identity_file = match (&existing, identity_file) {
        (Some(section), Some(asked)) => {
            let asked = std::path::absolute(expand_home(asked))?;
            if section.identity_file.as_deref() != Some(asked.as_path()) {
                bail!(
                    "{} already has a [companion] section with another identity; drop \
                     --identity-file, or remove the section to pair with this key",
                    path.display()
                );
            }

            Some(asked)
        }
        (Some(section), None) => section.identity_file.clone(),
        (None, asked) => asked.map(std::path::Path::to_owned),
    };
    let port = existing
        .as_ref()
        .and_then(|section| section.listen)
        .map_or(companion::DIRECT_PORT, |listen| listen.port());

    // the signing identity is the one thing the agent install can lack;
    // asked now, it fails before the gateway lists this Mac
    let (_, plan) = companion_plan(path, explicit_config)?;
    service::check_signing_identity(&plan)?;

    let id = companion::companion_id(identity_file.as_deref())?;
    let name = companion::short_hostname();
    println!("Registering {name} with the gateway...");
    let joined = companion::join(Joining {
        ticket,
        id,
        name,
        addrs: Vec::new(),
        port,
    })
    .await
    .map_err(|error| {
        eyre!(
            "{}\nIf this Mac cannot reach the gateway, run `codemode-mcp companion invite \
             --manual` there and pair with that ticket instead.",
            peer_text(&error.to_string())
        )
    })?;
    let registered = joined.registered().clone();
    // what the gateway sent is printed before the config check sees it
    let gateway = peer_text(&registered.gateway_name);
    let listed_as = peer_text(&registered.name);
    if registered.already_listed {
        println!("{gateway} already listed this Mac, as {listed_as}.");
    } else {
        println!("Registered with {gateway} as {listed_as}.");
    }

    // without discovery the gateway dials the address this Mac sent, so the
    // agent must listen on that port
    let listen =
        (!ticket.addrs.is_empty()).then(|| std::net::SocketAddr::from(([0, 0, 0, 0], port)));
    let section = Ticket {
        gateway: ticket.gateway,
        gateway_name: registered.gateway_name.clone(),
        references: registered.references.clone(),
    };
    let set_up = companion::pair(&section, path, identity_file.as_deref(), listen)
        .map_err(color_eyre::Report::from)
        .and_then(|paired| {
            match paired {
                Paired::Written(_) => {
                    println!("Added a [companion] section to {}.", path.display())
                }
                Paired::AlreadyConfigured { .. } => println!(
                    "{} already has a [companion] section for this gateway, so it was left as is.",
                    path.display()
                ),
            }

            install_companion(path, explicit_config, false)
        });
    if let Err(error) = set_up {
        joined.close().await;

        return Err(error);
    }

    println!(
        "Checking the pairing: approve the Touch ID prompt on this Mac, which names the \
         reference; 1Password asks too while it has not yet let `op` in."
    );
    let check = joined
        .check()
        .await
        .map_err(|error| eyre!("{}", peer_text(&error.to_string())))?;
    match check {
        PairCheck::Read { reference, bytes } => println!(
            "Check passed: {gateway} read {} ({bytes} bytes) through this Mac.",
            peer_text(&reference)
        ),
        PairCheck::Failed { reference, message } => bail!(
            "paired, but reading {} through this Mac failed: {}",
            peer_text(&reference),
            peer_text(&message)
        ),
        PairCheck::Skipped => println!(
            "Paired. No server on {gateway} uses an op:// reference yet, so there was nothing to \
             check."
        ),
        // only a phone is answered this way
        PairCheck::NothingSealed => println!("Paired."),
    }

    Ok(())
}

/// Writes the `[companion]` section from a manual ticket, prints the block
/// the gateway's config needs and starts the agent
///
/// Running it again with the same gateway's ticket prints the block and
/// installs again, so a failed install can be retried
fn pair_by_hand(
    path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
    ticket: &Ticket,
    identity_file: Option<&std::path::Path>,
) -> Result<()> {
    let pairing = match companion::pair(ticket, path, identity_file, None)? {
        Paired::Written(pairing) => {
            println!("Added a [companion] section to {}:", path.display());
            println!("\n{}", pairing.section);

            pairing
        }
        Paired::AlreadyConfigured { section } => {
            let existing = load_or_default(path)?.companion;
            let Some(existing) = existing.filter(|existing| existing.gateway == ticket.gateway)
            else {
                println!(
                    "{} already has a [companion] section for another gateway, so it was not \
                     changed. Replace it with this one to pair with {}:",
                    path.display(),
                    ticket.gateway_name
                );
                println!("\n{section}");

                return Ok(());
            };
            println!(
                "{} already has a [companion] section for this gateway; installing its agent \
                 again.",
                path.display()
            );

            Pairing {
                id: companion::companion_id(existing.identity_file.as_deref())?,
                name: companion::short_hostname(),
                section,
            }
        }
    };

    // before the install, so a failed install does not hide it
    println!(
        "\nOn the gateway Mac ({}), append this to the end of the config:",
        ticket.gateway_name
    );
    println!("\n{}\n", pairing.gateway_entry());
    println!(
        "then run `codemode-mcp companion trust {}` there, which asks Touch ID and starts using \
         this Mac, and `codemode-mcp companion check <reference>` to try it.\n",
        pairing.name
    );

    install_companion(path, explicit_config, false)
}

/// Drops a `[companion]` allow list left from before every read was asked
/// for by name, so the config still loads after an update
fn strip_companion_allow(path: &std::path::Path) -> Result<()> {
    if Config::strip_companion_allow(path)? {
        tracing::warn!(
            config = %path.display(),
            "removed the [companion] allow list: every read now asks Touch ID naming the reference"
        );
    }

    Ok(())
}

/// Copies and signs the binary and loads the companion's LaunchAgent, as
/// `companion install` does
fn install_companion(
    path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
    dry_run: bool,
) -> Result<()> {
    let (config, plan) = companion_plan(path, explicit_config)?;
    if !dry_run {
        if config.companion.is_none() {
            bail!(
                "{} has no [companion] section; run `codemode-mcp companion pair <ticket>` first",
                path.display()
            );
        }
        service::check_signing_identity(&plan)?;
    }

    run_plan(&plan, dry_run)
}

/// The config at `path` and the steps that install the companion's agent
fn companion_plan(
    path: &std::path::Path,
    explicit_config: Option<&std::path::Path>,
) -> Result<(Config, Vec<Action>)> {
    let config = load_or_default(path)?;
    let binary = std::env::current_exe().wrap_err("cannot locate this binary")?;
    let paths = ServicePaths::from_env(&config.state_dir()?)?;
    let pinned = match explicit_config {
        Some(path) => Some(std::path::absolute(path)?),
        None => None,
    };
    let plan = service::companion_install_plan(
        &paths,
        service::current_uid()?,
        &binary,
        pinned.as_deref(),
    );

    Ok((config, plan))
}

/// Text another Mac sent, on one line and without escape sequences, so it
/// cannot rewrite what this terminal shows
fn peer_text(text: &str) -> String {
    codemode_mcp::prompt::one_line(text, 1000)
}

/// Prints `plan` for a dry run, otherwise carries it out
fn run_plan(plan: &[Action], dry_run: bool) -> Result<()> {
    if dry_run {
        print_plan(plan);

        return Ok(());
    }
    for action in plan {
        println!("{}", action.describe());
        action.apply()?;
    }

    Ok(())
}

/// Runs the companion until a stop signal
async fn companion_serve_command(config: Config) -> Result<()> {
    let companion_config = config.companion.ok_or_else(|| {
        eyre!("the config has no [companion] section; run `codemode-mcp companion pair <ticket>`")
    })?;

    #[cfg(target_os = "macos")]
    let mac: Option<Arc<dyn codemode_mcp::mac::Mac>> =
        Some(Arc::new(codemode_mcp::mac::MacOs::new()));
    #[cfg(not(target_os = "macos"))]
    let mac: Option<Arc<dyn codemode_mcp::mac::Mac>> = None;

    let handle = companion::serve(companion_config, mac).await?;
    tracing::info!(id = %handle.id(), addrs = ?handle.bound_addrs(), "companion is serving");

    shutdown_signal().await;
    handle.shutdown().await;

    Ok(())
}

/// Waits until a daemon other than `previous_pid` answers on both listeners
async fn wait_until_serving(config: &Config, uid: u32, previous_pid: Option<u32>) -> Result<()> {
    // the old daemon may drain for the full window before launchd starts the
    // new one
    let deadline = Instant::now() + config.limits.drain() + Duration::from_secs(30);
    let health = format!("http://127.0.0.1:{}/healthz", config.listen.port());
    let client = reqwest::Client::new();

    loop {
        if let Some(pid) = service::running_pid(uid).filter(|pid| Some(*pid) != previous_pid) {
            let healthy = client
                .get(&health)
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            let admin_open = tokio::net::TcpStream::connect(config.admin_listen)
                .await
                .is_ok();
            if healthy && admin_open {
                println!("daemon is serving (pid {pid})");

                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            bail!(
                "the daemon did not start serving; check `codemode-mcp service status` and the logs"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn print_plan(plan: &[Action]) {
    println!("Dry run; nothing is changed. Would run:");
    for action in plan {
        println!("  {}", action.describe());
    }
    for action in plan {
        if let Action::Write { path, contents } = action {
            println!("\n--- {} ---\n{contents}", path.display());
        }
    }
}

async fn service_status(
    config: &Config,
    paths: &ServicePaths,
    uid: u32,
    dry_run: bool,
) -> Result<()> {
    let launchctl = service::status_command(uid, service::Agent::Daemon);
    let health = format!("http://127.0.0.1:{}/healthz", config.listen.port());
    if dry_run {
        println!("Dry run; would check:");
        println!("  test -f {}", paths.plist.display());
        println!("  {}", launchctl.join(" "));
        println!("  GET {health}");

        return Ok(());
    }

    println!(
        "plist: {} ({})",
        paths.plist.display(),
        if paths.plist.is_file() {
            "installed"
        } else {
            "missing"
        }
    );
    match service::run_command(&launchctl) {
        Ok(output) => {
            let summary: Vec<&str> = output
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with("state =") || line.starts_with("pid ="))
                .collect();
            println!("launchd: loaded ({})", summary.join(", "));
        }
        Err(_) => println!("launchd: not loaded"),
    }
    let answer = reqwest::Client::new()
        .get(&health)
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    match answer {
        Ok(response) => println!("health: {}", response.text().await?),
        Err(_) => println!("health: no answer on {health}"),
    }

    Ok(())
}

async fn update_command(
    config: &Config,
    tag: Option<String>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    update::check_platform()?;
    let source = Source::from_env();
    // a stalled download must not hang `cmd fleet update`
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()?;
    let requested = tag.is_some();
    let tag = match tag {
        Some(tag) => tag,
        None => source.latest_tag(&client).await?,
    };
    let paths = ServicePaths::from_env(&config.state_dir()?)?;
    let installed = update::installed_tag(&paths.binary);

    // a Mac with only the companion agent never had a Monty worker
    let companion_only = paths.companion_plist.is_file() && !paths.plist.is_file();

    // `cmd fleet update` runs this every time, and a restart drains the
    // running executions, so a current install is left alone; a missing
    // worker is always replaced, except where only the companion runs
    if !force && (paths.worker.is_file() || companion_only) {
        if installed.as_deref() == Some(tag.as_str()) {
            println!("{} is already {tag}", paths.binary.display());

            return Ok(());
        }
        // a local build ahead of the latest release is not downgraded
        let newer = installed
            .as_deref()
            .and_then(update::version)
            .zip(update::version(&tag))
            .is_some_and(|(installed, latest)| installed > latest);
        if newer && !requested {
            println!(
                "{} is {}, newer than the latest release {tag}; `--tag {tag}` installs it anyway",
                paths.binary.display(),
                installed.as_deref().unwrap_or_default(),
            );

            return Ok(());
        }
    }
    if dry_run {
        println!(
            "Dry run; would replace {} ({}) and {} with {tag} from {}",
            paths.binary.display(),
            installed.as_deref().unwrap_or("not installed"),
            paths.worker.display(),
            source.base_url,
        );

        return Ok(());
    }

    let release = Release::fetch(&source, &tag, &client).await?;
    release.install(&paths)?;
    println!(
        "Installed {} to {} and {}",
        release.tag,
        paths.binary.display(),
        paths.worker.display()
    );
    if let Some(worker) = &config.worker_path {
        eprintln!(
            "note: `worker_path` is set, so the service keeps using {}",
            expand_home(worker).display()
        );
    }

    // the plist is checked first, so a run under another home never asks
    // launchd about the real service
    let uid = service::current_uid()?;
    let is_loaded = |plist: &std::path::Path, agent| {
        plist.is_file() && service::run_command(&service::status_command(uid, agent)).is_ok()
    };
    let daemon_loaded = is_loaded(&paths.plist, service::Agent::Daemon);
    let companion_loaded = is_loaded(&paths.companion_plist, service::Agent::Companion);
    if !daemon_loaded && !companion_loaded {
        println!("The service is not installed; `codemode-mcp service install` starts it.");

        return Ok(());
    }

    // the companion holds no executions, so it restarts at once; the daemon
    // keeps its drain
    if companion_loaded {
        run_plan(
            &service::restart_plan(uid, service::Agent::Companion),
            false,
        )?;
    }
    if daemon_loaded {
        service_command(
            config,
            None,
            ServiceCommand::Restart {
                dry_run: false,
                fresh: false,
            },
        )
        .await?;
    }

    Ok(())
}

fn config_init_command(path: &std::path::Path, print: bool) -> Result<()> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("$HOME is not set"))?;
    if print {
        print!("{}", service::starter_config(std::path::Path::new(&home)));

        return Ok(());
    }

    service::write_starter_config(path, std::path::Path::new(&home))?;
    println!("Wrote {}", path.display());

    Ok(())
}

/// Serves the calendar or reminders adapter over EventKit
///
/// macOS asks the owner the first time; the prompt names the daemon, since
/// it started this process
#[cfg(target_os = "macos")]
async fn eventkit_adapter_command(entity: Entity) -> Result<()> {
    use codemode_mcp::adapters::apple::{
        calendar::CalendarAdapter, dates, eventkit::EventKit, reminders::RemindersAdapter,
    };

    let zone = dates::local_zone();
    let store = Arc::new(
        EventKit::start(entity, zone.clone()).wrap_err("failed to start the EventKit thread")?,
    );
    let served = match entity {
        Entity::Events => CalendarAdapter::new(store, zone).serve_stdio().await,
        Entity::Reminders => RemindersAdapter::new(store, zone).serve_stdio().await,
    };

    served.map_err(|error| eyre!(error))
}

#[cfg(not(target_os = "macos"))]
async fn eventkit_adapter_command(_entity: Entity) -> Result<()> {
    bail!("the calendar and reminders adapters use EventKit, which needs macOS")
}

async fn serve_command(config: Config) -> Result<()> {
    // before anything touches state: a second daemon on one state directory
    // would resume the first one's parked executions and interrupt its
    // running ones
    let _lock = store::DaemonLock::acquire(&config.state_dir()?)?;
    warn_on_short_exit_timeout(&config);
    if config.public_origin.is_none() {
        tracing::warn!(
            origin = %config.public_origin(),
            "public_origin is unset, so approval and enrollment links only open on this machine"
        );
    }

    // a taken port fails here, before any state is settled
    let listeners = Listeners::bind(&config)
        .await
        .wrap_err("failed to bind the listeners")?;
    let app = App::start(config).await?;
    // frozen however this function ends, so tearing tasks down cannot
    // withdraw what the next boot resumes
    let _freeze = app.freeze_on_drop();

    // before anything is answered: nothing else may start while the previous
    // process's leftovers are settled
    app.recover();
    app.gateway().wait_ready(SETTLE_LIMIT).await;
    let server = listeners
        .serve(&app)
        .wrap_err("failed to start the server")?;

    let token = server.shutdown_token();
    let in_flight = server.in_flight();
    let stopping = app.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        // the server keeps answering `wait` and the approval pages meanwhile
        stopping.drain().await;
        // the drain released every `wait`, so these answer within moments
        in_flight.settled(ANSWER_GRACE).await;
        token.cancel();
    });

    let served = server.finished().await;
    app.shutdown().await;

    Ok(served?)
}

/// Logs when the installed launchd plist would kill the daemon mid-drain
fn warn_on_short_exit_timeout(config: &Config) {
    let Ok(paths) = config
        .state_dir()
        .map_err(|_| ())
        .and_then(|state| ServicePaths::from_env(&state).map_err(|_| ()))
    else {
        return;
    };
    // no plist: the daemon was started by hand
    let Ok(plist) = std::fs::read_to_string(&paths.plist) else {
        return;
    };

    if let Some(warning) = service::exit_timeout_warning(&plist, config.limits.drain()) {
        tracing::warn!("{warning}");
    }
}

async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}

async fn tools_command(config: Config, stubs: bool) -> Result<()> {
    let app = App::start_without_approvals(config).await?;
    app.gateway().wait_ready(SETTLE_LIMIT).await;

    for report in app.gateway().report() {
        let detail = serde_json::to_string(&report.status)?;
        eprintln!("server {}: {detail} ({} tools)", report.name, report.tools);
    }

    let catalog = app.gateway().catalog();
    if stubs {
        let names: Vec<String> = catalog
            .entries()
            .iter()
            .map(|entry| entry.function.clone())
            .collect();
        print!("{}", catalog.describe(&names).0);

        return Ok(());
    }
    for entry in catalog.entries() {
        let marker = if entry.available {
            ""
        } else {
            " [unavailable]"
        };
        println!("{}{marker}: {}", entry.function, entry.summary());
    }

    Ok(())
}

async fn exec_command(config: Config, script: &str) -> Result<()> {
    let code = if script == "-" {
        let mut code = String::new();
        std::io::stdin().read_to_string(&mut code)?;

        code
    } else {
        std::fs::read_to_string(script).wrap_err_with(|| format!("failed to read {script}"))?
    };

    let started = Instant::now();
    let app = App::start_without_approvals(config).await?;
    let started_pool = started.elapsed();
    app.gateway().wait_ready(SETTLE_LIMIT).await;
    let ready = started.elapsed();
    let tools = app.gateway().catalog().entries().len();

    let run_started = Instant::now();
    let caller = Caller {
        client_name: Some(EXEC_CLIENT.to_owned()),
        client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        ..Caller::default()
    };
    let id = app.executions().start(code, caller)?;
    let outcome = loop {
        match app.executions().wait(&id, Duration::from_secs(60)).await {
            WaitResult::Finished(outcome) => break outcome,
            WaitResult::Pending => {}
            WaitResult::Unknown => return Err(eyre!("execution vanished")),
        }
    };
    eprintln!(
        "timings: pool {started_pool:?}, upstreams+catalog ready {ready:?} ({tools} tools), type-check+run {:?}",
        run_started.elapsed()
    );

    let (text, failed) = outcome_text(&outcome, app.config().limits.max_response_bytes());
    println!("{text}");
    app.usage().flush().await;
    if failed {
        std::process::exit(1);
    }

    Ok(())
}

fn stats_command(config: &Config, since: &str) -> Result<()> {
    let window = parse_since(since).map_err(|message| eyre!(message))?;
    let connection = store::open(&config.state_dir()?)?;
    let stats = Reporter::new(&connection, window).stats()?;
    print!("{}", render_stats(&stats));

    Ok(())
}

fn review_command(config: &Config, since: &str, out: Option<PathBuf>) -> Result<()> {
    let window = parse_since(since).map_err(|message| eyre!(message))?;
    let connection = store::open(&config.state_dir()?)?;
    let prefixes: Vec<String> = config
        .servers
        .keys()
        .map(|name| function_prefix(name))
        .collect();
    let review = Reporter::new(&connection, window).review(&prefixes)?;

    match out {
        Some(path) => {
            std::fs::write(&path, review)
                .wrap_err_with(|| format!("failed to write {}", path.display()))?;
            eprintln!("wrote {}", path.display());
        }
        None => print!("{review}"),
    }

    Ok(())
}

async fn passkey_command(config: &Config, command: PasskeyCommand) -> Result<()> {
    match command {
        PasskeyCommand::Enroll { label } => {
            let response: EnrollResponse =
                admin_post(config, "/admin/enroll", &EnrollRequest { label }).await?;
            if !response.notified {
                eprintln!(
                    "warning: no ntfy topic is configured, so the phone was not told about this request"
                );
            }
            if let Some(approval_url) = &response.approval_url {
                println!("A passkey is already enrolled, so this enrollment needs its approval.");
                println!(
                    "Confirmation code: {} (the approval page shows the same code)",
                    response.code.as_deref().unwrap_or("-")
                );
                println!(
                    "1. Approve the request with an existing passkey (a notification was sent):"
                );
                println!("   {approval_url}");
                println!(
                    "2. Then open this link on the new device (one use, valid 10 minutes after approval):"
                );
                println!("   {}", response.url);
            } else {
                println!(
                    "Open this link on the device that will approve (valid 10 minutes, one use):"
                );
                println!("{}", response.url);
            }
        }
        PasskeyCommand::List => {
            let passkeys = Store::open(&config.state_dir()?)?.list_passkeys()?;
            if passkeys.is_empty() {
                println!("No passkeys enrolled; run `codemode-mcp passkey enroll --label NAME`.");
            }
            let now = store::now_ms();
            for passkey in passkeys {
                let used = passkey.last_used_ms.map_or_else(
                    || "never used".to_owned(),
                    |used| format!("last used {} ago", human_duration(now - used)),
                );
                println!(
                    "{}\t{}\tadded {} ago, {used}",
                    passkey.id,
                    passkey.label,
                    human_duration(now - passkey.created_ms)
                );
            }
        }
        PasskeyCommand::Remove { id } => {
            let response: RemoveResponse =
                admin_post(config, "/admin/passkey/remove", &RemoveRequest { id }).await?;
            if !response.notified {
                eprintln!(
                    "warning: no ntfy topic is configured, so the phone was not told about this request"
                );
            }
            println!(
                "Confirmation code: {} (the approval page shows the same code)",
                response.code
            );
            println!(
                "Passkey {id} ({}) is removed once an existing passkey approves it \
                 (a notification was sent):",
                response.label
            );
            println!("{}", response.approval_url);
        }
    }

    Ok(())
}

/// `op read`, `op inject` and `op run`
async fn op_command(config: &Config, command: OpCommand) -> Result<()> {
    match command {
        // needs the full config, so it is run before this
        OpCommand::Warm { server } => warm_command(config, server).await?,
        OpCommand::Read {
            references,
            describe,
            reason,
            keep,
            out_file,
            force,
            file_mode,
            no_newline,
        } => {
            let several = references.len() > 1;
            let targets = match describe {
                Some(description) => vec![ProgramTarget::Describe(description)],
                None if references.is_empty() => bail!("give a reference or --describe"),
                None => references
                    .iter()
                    .map(|reference| ProgramTarget::Reference(reference.trim().to_owned()))
                    .collect(),
            };
            // the file written is the one the prompt names, even if a link
            // on the way changes while the owner decides
            let out_file = out_file.map(|path| resolved_path(&path));
            let destination = match &out_file {
                Some(path) => {
                    op::check_writable(path, force)?;
                    Some(path.display().to_string())
                }
                None => None,
            };
            let values = program_values(
                config,
                admin::OpReadRequest {
                    targets,
                    reason,
                    destination,
                    keep_secs: keep,
                },
            )
            .await?;
            let mut contents = if several {
                // keyed as the daemon read them, trimmed; a repeat is one key
                let mut map = std::collections::BTreeMap::new();
                for (reference, value) in references
                    .iter()
                    .map(|reference| reference.trim())
                    .zip(&values)
                {
                    let text = value.as_text().ok_or_else(|| {
                        eyre!("{reference} cannot go in a JSON object: {NOT_TEXT}")
                    })?;
                    map.insert(reference, text);
                }

                serde_json::to_string_pretty(&map)?.into_bytes()
            } else {
                values.into_iter().next().unwrap_or_default().into_bytes()
            };
            // a file such as a `.p12` is written exactly as 1Password holds
            // it, since a newline after it would change it
            let binary = std::str::from_utf8(&contents).is_err();
            if !no_newline && !binary {
                contents.push(b'\n');
            }

            match out_file {
                Some(path) => {
                    op::write_private(&path, &contents, file_mode, force)
                        .wrap_err_with(|| format!("cannot write {}", path.display()))?;
                    eprintln!("Wrote {}", path.display());
                }
                // raw bytes could set off a terminal's control sequences
                None if binary && std::io::stdout().is_terminal() => {
                    bail!(
                        "the value holds binary data such as a file; write it with --out-file <path>"
                    )
                }
                None => {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(&contents)?;
                    stdout.flush()?;
                }
            }
        }
        OpCommand::Inject {
            in_file,
            out_file,
            force,
            file_mode,
            reason,
            keep,
        } => {
            let template = match &in_file {
                Some(path) => std::fs::read_to_string(path)
                    .wrap_err_with(|| format!("cannot read {}", path.display()))?,
                None => {
                    let mut text = String::new();
                    std::io::stdin().read_to_string(&mut text)?;

                    text
                }
            };
            let references = op::template_references(&template)?;
            // the file written is the one the prompt names, even if a link
            // on the way changes while the owner decides
            let out_file = out_file.map(|path| resolved_path(&path));
            let destination = match &out_file {
                Some(path) => {
                    op::check_writable(path, force)?;
                    Some(path.display().to_string())
                }
                None => None,
            };
            let values = program_map(
                config,
                references,
                OpContext {
                    reason,
                    destination,
                    keep_secs: keep,
                },
            )
            .await?;
            let filled = op::fill_template(&template, &values)?;

            match out_file {
                Some(path) => {
                    op::write_private(&path, filled.as_bytes(), file_mode, force)
                        .wrap_err_with(|| format!("cannot write {}", path.display()))?;
                    eprintln!("Wrote {} with {} values", path.display(), values.len());
                }
                None => print!("{filled}"),
            }
        }
        OpCommand::Run {
            env_file,
            no_masking,
            reason,
            keep,
            command,
        } => {
            // quoted, so different argument lists never read the same, and
            // a grant for one never answers another
            let line = command
                .iter()
                .map(|argument| shell_word(argument))
                .collect::<Vec<_>>()
                .join(" ");
            // refused rather than cut, since a part the prompt leaves out
            // could change what the command does with the values, and a
            // grant keyed by a cut line could answer another command
            if line.chars().count() > MAX_COMMAND_CHARS
                || codemode_mcp::prompt::one_line(&line, usize::MAX) != line
            {
                bail!(
                    "a command line must fit one line of at most {MAX_COMMAND_CHARS} \
                     characters so its prompt shows it whole; put a long script in a file"
                );
            }
            let context = OpContext {
                reason,
                destination: Some(format!("the environment of {line}")),
                keep_secs: keep,
            };
            let code = op_run(config, &env_file, no_masking, context, &command).await?;
            std::process::exit(code);
        }
    }

    Ok(())
}

/// Runs `command` with the values of `env_files` and of variables set to
/// references in its environment, masking them in its output unless
/// `no_masking`; the command's exit code, or 128 plus the signal that
/// stopped it
async fn op_run(
    config: &Config,
    env_files: &[PathBuf],
    no_masking: bool,
    context: OpContext,
    command: &[String],
) -> Result<i32> {
    let mut entries = Vec::new();
    for path in env_files {
        let text = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot read {}", path.display()))?;
        entries
            .extend(op::parse_env(&text).map_err(|reason| eyre!("{}: {reason}", path.display()))?);
    }
    // as `op run` does, a variable already set to a reference is read too;
    // one that is not text cannot be a reference
    for (key, value) in std::env::vars_os() {
        if let (Some(key), Some(value)) = (key.to_str(), value.to_str())
            && value.starts_with("op://")
        {
            entries.push(op::EnvEntry {
                key: key.to_owned(),
                value: value.to_owned(),
            });
        }
    }

    let mut references = Vec::new();
    for entry in &entries {
        references.extend(entry.references()?);
    }
    let values = program_map(config, op::unique(references), context).await?;
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| eyre!("give the command to run after --"))?;
    let mut child = tokio::process::Command::new(program);
    child.args(arguments);
    for entry in &entries {
        child.env(&entry.key, entry.filled(&values)?);
    }
    let masking = !no_masking && !values.is_empty();
    if masking {
        child
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
    }
    let mut running = child
        .spawn()
        .wrap_err_with(|| format!("cannot run {program}"))?;
    let forwarding = forward_signals(running.id());

    let mut pipes = Vec::new();
    if masking {
        let masker = Arc::new(op::Masker::new(values.values()));
        if let Some(stdout) = running.stdout.take() {
            let masker = Arc::clone(&masker);
            pipes.push(tokio::spawn(async move {
                let _ = masker.pipe(stdout, tokio::io::stdout()).await;
            }));
        }
        if let Some(stderr) = running.stderr.take() {
            pipes.push(tokio::spawn(async move {
                let _ = masker.pipe(stderr, tokio::io::stderr()).await;
            }));
        }
    }
    let status = running.wait().await?;
    forwarding.abort();
    // a background process the command left behind may hold the pipes open;
    // what is already in them is passed on, then this exits with the code
    let drained = async {
        for pipe in &mut pipes {
            let _ = pipe.await;
        }
    };
    if tokio::time::timeout(PIPE_DRAIN, drained).await.is_err() {
        for pipe in &pipes {
            pipe.abort();
        }
    }

    Ok(exit_code(status))
}

/// How long `op run` passes on output after its command exits
const PIPE_DRAIN: Duration = Duration::from_secs(2);

/// The longest command line `op run` takes, leaving room for the words
/// around it within the destination's limit
const MAX_COMMAND_CHARS: usize = 200;

/// `argument` as a shell would need it typed: as is when it holds only
/// characters a shell leaves alone, otherwise in single quotes
fn shell_word(argument: &str) -> String {
    let plain = !argument.is_empty()
        && argument
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.,:/=+@%".contains(character));
    if plain {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', r"'\''"))
    }
}

/// Passes the signals that stop a terminal command on to the child `pid`,
/// so it is never left running with the values after this process ends
fn forward_signals(pid: Option<u32>) -> tokio::task::JoinHandle<()> {
    use tokio::signal::unix::{SignalKind, signal};

    tokio::spawn(async move {
        let Some(pid) = pid
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(rustix::process::Pid::from_raw)
        else {
            return;
        };
        let (Ok(mut interrupt), Ok(mut terminate), Ok(mut hangup)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            return;
        };
        loop {
            let forwarded = tokio::select! {
                Some(()) = interrupt.recv() => rustix::process::Signal::INT,
                Some(()) = terminate.recv() => rustix::process::Signal::TERM,
                Some(()) = hangup.recv() => rustix::process::Signal::HUP,
                else => return,
            };
            let _ = rustix::process::kill_process(pid, forwarded);
        }
    })
}

/// The shell's exit code for `status`: its own code, or 128 plus the signal
/// that stopped it
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// What every prompt of one `op` command shows besides the items
struct OpContext {
    reason: Option<String>,
    destination: Option<String>,
    keep_secs: Option<u64>,
}

/// `path` absolute, with its directory resolved, so prompts name the file
/// written rather than a path whose `..` or links lead elsewhere, and the
/// write goes there
fn resolved_path(path: &std::path::Path) -> PathBuf {
    let resolved = path.file_name().and_then(|name| {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };

        std::fs::canonicalize(parent)
            .ok()
            .map(|parent| parent.join(name))
    });

    resolved
        .or_else(|| std::path::absolute(path).ok())
        .unwrap_or_else(|| path.to_path_buf())
}

/// Each reference mapped to its value, read in one approval; empty, asking
/// nobody, when there are none
async fn program_map(
    config: &Config,
    references: Vec<String>,
    context: OpContext,
) -> Result<std::collections::HashMap<String, String>> {
    if references.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let targets = references
        .iter()
        .cloned()
        .map(ProgramTarget::Reference)
        .collect();
    let request = admin::OpReadRequest {
        targets,
        reason: context.reason,
        destination: context.destination,
        keep_secs: context.keep_secs,
    };
    let values = program_values(config, request).await?;

    references
        .into_iter()
        .zip(values)
        .map(
            |(reference, value)| match String::from_utf8(value.into_bytes()) {
                Ok(text) => Ok((reference, text)),
                Err(_) => Err(eyre!(
                    "{reference} cannot go in a template or an environment: {NOT_TEXT}"
                )),
            },
        )
        .collect()
}

/// Asks the daemon for the request's targets, which asks the owner, and
/// returns one value per target
async fn program_values(
    config: &Config,
    request: admin::OpReadRequest,
) -> Result<Vec<ProgramValue>> {
    let count = request.targets.len();
    let noun = if count == 1 { "value" } else { "values" };
    eprintln!(
        "Asking the owner to approve {count} 1Password {noun}: Touch ID on this Mac, or the \
         phone or a companion Mac..."
    );
    let response: admin::OpReadResponse =
        admin_post_as_owner(config, "/admin/op/read", &request).await?;

    match response {
        admin::OpReadResponse::Values { source, values } if values.len() == count => {
            eprintln!("Approved on {source}");

            Ok(values)
        }
        admin::OpReadResponse::Values { .. } => bail!("the daemon sent the wrong number of values"),
        admin::OpReadResponse::Invalid { message } => bail!("refused: {message}"),
        admin::OpReadResponse::Denied { message } => bail!("denied: {message}"),
        admin::OpReadResponse::Failed { message } => bail!("no values: {message}"),
    }
}

async fn warm_command(config: &Config, server: Option<String>) -> Result<()> {
    println!(
        "Running warm-up calls on the daemon. The 1Password app on this Mac may show \
         prompts to accept; approve them there."
    );
    let response: WarmResponse = admin_post(config, "/admin/warm", &WarmRequest { server }).await?;
    if response.results.is_empty() {
        println!("No server has [servers.<name>.warm] calls configured.");
    }

    let mut failed = false;
    for result in response.results {
        failed |= !result.ok;
        let mark = if result.ok { "ok" } else { "FAILED" };
        println!(
            "{}.{}: {mark} ({})",
            result.server, result.tool, result.detail
        );
    }
    if failed {
        std::process::exit(1);
    }

    Ok(())
}

/// Posts JSON to the daemon's loopback admin listener
async fn admin_post<T: serde::de::DeserializeOwned>(
    config: &Config,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<T> {
    admin_request(config, path, body, None).await
}

/// [`admin_post`] for the routes only the daemon's user may call
///
/// The token never crosses the socket: whatever holds the admin port first
/// proves it holds the token too, so a program that took the port while the
/// daemon was down learns nothing and cannot pass for it, and the request
/// carries a single-use proof bound to its route
async fn admin_post_as_owner<T: serde::de::DeserializeOwned>(
    config: &Config,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<T> {
    let file = config.state_dir()?.join(admin::OWNER_TOKEN_FILE);
    let token = std::fs::read_to_string(&file).wrap_err_with(|| {
        format!(
            "cannot read {}; run this as the user that runs the daemon, once it has started",
            file.display()
        )
    })?;
    let token = token.trim();

    let client_nonce = hex::encode(rand::random::<[u8; 16]>());
    let challenge: admin::ChallengeResponse = admin_post(
        config,
        "/admin/owner/challenge",
        &admin::ChallengeRequest {
            client_nonce: client_nonce.clone(),
        },
    )
    .await?;
    if !admin::daemon_proof_matches(
        token,
        &client_nonce,
        &challenge.server_nonce,
        &challenge.proof,
    ) {
        bail!(
            "the program at {} could not prove it is this user's daemon; check what holds that port",
            config.admin_listen
        );
    }
    let proof = format!(
        "{}:{}",
        challenge.server_nonce,
        admin::request_proof(token, &challenge.server_nonce, path)
    );

    admin_request(config, path, body, Some(&proof)).await
}

/// Whether a failed admin request got far enough that the daemon may have
/// acted on it: a timeout or a connection lost after connecting, as opposed
/// to a refused connection
fn may_have_reached_daemon(error: &color_eyre::Report) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| !error.is_connect() && !error.is_builder())
    })
}

async fn admin_request<T: serde::de::DeserializeOwned>(
    config: &Config,
    path: &str,
    body: &impl serde::Serialize,
    owner_proof: Option<&str>,
) -> Result<T> {
    let url = format!("http://{}{path}", config.admin_listen);
    // no_proxy: the body can hold a secret and the proof is bound to this
    // route, and the daemon is always on this machine, so an HTTP(S)_PROXY or
    // ALL_PROXY in the environment must not see either. Every admin call
    // goes through here
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .post(&url)
        .timeout(ADMIN_TIMEOUT)
        .json(body);
    if let Some(proof) = owner_proof {
        request = request.header(admin::OWNER_PROOF_HEADER, proof);
    }
    let response = request.send().await.wrap_err_with(|| {
        format!(
            "could not reach the daemon's admin listener at {}; is `codemode-mcp serve` running?",
            config.admin_listen
        )
    })?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| value["error"].as_str().map(str::to_owned))
            .unwrap_or(text);
        bail!("daemon answered {status}: {message}");
    }

    Ok(serde_json::from_str(&text)?)
}
