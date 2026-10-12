//! Command-line entry point: serve the gateway, inspect its catalog, or run
//! one script against the configured upstreams

use std::{
    io::Read,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use codemode_mcp::{
    adapters::homebased::HomebasedAdapter,
    admin::{
        EnrollRequest, EnrollResponse, OAuthLoginResponse, OAuthLogoutResponse, OAuthServerRequest,
        OAuthStatusResponse, RemoveRequest, RemoveResponse, WarmRequest, WarmResponse,
    },
    app::App,
    catalog::function_prefix,
    config::{Config, ConfigError, expand_home},
    executions::WaitResult,
    notify::{Notifier, Ntfy},
    server::{outcome_text, serve},
    service::{self, Action, ServicePaths},
    store::{self, Store},
    usage::{
        Caller,
        report::{Reporter, human_duration, parse_since, render_stats},
    },
};
use color_eyre::eyre::{Result, WrapErr, bail, eyre};
use tracing_subscriber::EnvFilter;

/// How long startup waits for upstreams to finish their first connection attempt
const SETTLE_LIMIT: Duration = Duration::from_secs(15);

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
    /// Restart the running service
    Restart {
        /// Print what would be done
        #[arg(long)]
        dry_run: bool,
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
    /// The homebased CLI as MCP tools
    Homebased {
        /// homebased executable; `$CODEMODE_HOMEBASED_BIN`, else `homebased` on PATH
        #[arg(long)]
        homebased_bin: Option<PathBuf>,
    },
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
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rmcp=warn")),
        )
        .with_writer(std::io::stderr)
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
        Command::Op {
            command: OpCommand::Warm { server },
        } => warm_command(&Config::load(&path)?, server).await,
        Command::OAuth { command } => oauth_command(&Config::load(&path)?, command).await,
        Command::Service { command } => {
            service_command(&load_or_default(&path)?, explicit.as_deref(), command).await
        }
        Command::Config {
            command: ConfigCommand::Init { print },
        } => config_init_command(&path, print),
        Command::Adapter {
            command: AdapterCommand::Homebased { homebased_bin },
        } => adapter_command(&load_or_default(&path)?, homebased_bin).await,
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

            (
                service::install_plan(&paths, uid, &binary, &worker, pinned.as_deref()),
                dry_run,
            )
        }
        ServiceCommand::Uninstall { dry_run } => (service::uninstall_plan(&paths, uid), dry_run),
        ServiceCommand::Restart { dry_run } => (service::restart_plan(uid), dry_run),
        ServiceCommand::Status { dry_run } => {
            return service_status(config, &paths, uid, dry_run).await;
        }
    };

    if dry_run {
        print_plan(&plan);

        return Ok(());
    }
    for action in &plan {
        println!("{}", action.describe());
        action.apply()?;
    }

    Ok(())
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
    let launchctl = service::status_command(uid);
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

async fn adapter_command(config: &Config, homebased_bin: Option<PathBuf>) -> Result<()> {
    let notifier: Option<Arc<dyn Notifier>> = match config.notify.resolve_ntfy() {
        Ok(Some(ntfy)) => Some(Arc::new(Ntfy::new(ntfy))),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "notify tool unavailable");

            None
        }
    };
    let program = homebased_bin.unwrap_or_else(HomebasedAdapter::program_from_env);

    HomebasedAdapter::new(program, notifier)
        .serve_stdio()
        .await
        .map_err(|error| eyre!(error))
}

async fn serve_command(config: Config) -> Result<()> {
    let app = App::start(config).await?;
    app.gateway().wait_ready(SETTLE_LIMIT).await;
    let server = serve(&app).await.wrap_err("failed to start the server")?;

    let token = server.shutdown_token();
    tokio::spawn(async move {
        shutdown_signal().await;
        token.cancel();
    });

    server.finished().await?;

    Ok(())
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
    let app = App::start(config).await?;
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
        session: None,
        client_name: Some("codemode-mcp exec".to_owned()),
        client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
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
                println!("No passkeys enrolled; run `codemode-mcp passkey enroll`.");
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
    let url = format!("http://{}{path}", config.admin_listen);
    let response = reqwest::Client::new()
        .post(&url)
        .timeout(Duration::from_secs(120))
        .json(body)
        .send()
        .await
        .wrap_err_with(|| {
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
