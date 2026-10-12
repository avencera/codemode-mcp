//! Command-line entry point: serve the gateway, inspect its catalog, or run
//! one script against the configured upstreams

use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use codemode_mcp::{
    app::App,
    config::Config,
    executions::WaitResult,
    server::{outcome_text, serve},
};
use color_eyre::eyre::{Result, WrapErr, eyre};
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
    /// Run a script once against the upstreams, without the server
    Exec {
        /// Script file, or `-` for stdin
        script: String,
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
    let app = App::start(config).await?;
    let started_pool = started.elapsed();
    app.gateway().wait_ready(SETTLE_LIMIT).await;
    let ready = started.elapsed();
    let tools = app.gateway().catalog().entries().len();

    let run_started = Instant::now();
    let id = app.executions().start(code)?;
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
    if failed {
        std::process::exit(1);
    }

    Ok(())
}
