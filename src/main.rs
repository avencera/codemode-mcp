//! Command-line entry point: serve the gateway, inspect its catalog, or run
//! one script against the configured upstreams

use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use codemode_mcp::{
    admin::{EnrollResponse, WarmRequest, WarmResponse},
    app::App,
    catalog::function_prefix,
    config::Config,
    executions::WaitResult,
    server::{outcome_text, serve},
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
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// Print a one-time link (valid 10 minutes) for adding a passkey; needs
    /// the daemon running
    Enroll,
    /// List enrolled passkeys
    List,
    /// Remove a passkey by id
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
    let path = match cli.config {
        Some(path) => path,
        None => Config::default_path()?,
    };
    let config = Config::load(&path)?;

    match cli.command {
        Command::Serve => serve_command(config).await,
        Command::Tools { stubs } => tools_command(config, stubs).await,
        Command::Exec { script } => exec_command(config, &script).await,
        Command::Stats { since } => stats_command(&config, &since),
        Command::Review { since, out } => review_command(&config, &since, out),
        Command::Passkey { command } => passkey_command(&config, command).await,
        Command::Op {
            command: OpCommand::Warm { server },
        } => warm_command(&config, server).await,
    }
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
        PasskeyCommand::Enroll => {
            let response: EnrollResponse = admin_post(config, "/admin/enroll", &()).await?;
            println!("Open this link on the device that will approve (valid 10 minutes, one use):");
            println!("{}", response.url);
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
            let store = Store::open(&config.state_dir()?)?;
            let label = store.passkey_label(id)?;
            if !store.remove_passkey(id)? {
                bail!("no passkey with id {id}");
            }
            println!("removed passkey {id} ({})", label.unwrap_or_default());
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
