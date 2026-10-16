//! Builds, installs and ships the iPhone companion: `cargo xtask <command>`,
//! usually through the `ios-*` recipes in the justfile

mod ios;

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

#[derive(Parser)]
#[command(about = "Build, install and ship the codemode-mcp iPhone companion")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build the Rust core for iOS, generate the Swift bindings and put both
    /// in the CompanionCore Swift package
    BuildIos {
        /// Optimized build, as TestFlight gets
        #[arg(long)]
        release: bool,
        /// Also build for the simulator on Apple silicon
        #[arg(long)]
        sim: bool,
    },
    /// Generate ios/Companion.xcodeproj from ios/project.yml
    Project,
    /// Build the app, install it on a connected iPhone and launch it
    RunIos {
        /// The iPhone's UDID, as `xcrun devicectl list devices` shows it
        #[arg(long, env = "IOS_DEVICE_UDID")]
        udid: String,
        /// Optimized build
        #[arg(long)]
        release: bool,
        /// Sign without the push entitlements, so the team's wildcard
        /// profile does; the app then answers only while it is open
        #[arg(long)]
        without_push: bool,
        /// An App Store Connect API key, which lets Xcode register the app
        /// and its push capability without a signed-in account
        #[arg(long, env = "ASC_API_KEY_PATH")]
        api_key_path: Option<std::path::PathBuf>,
        /// The key's id
        #[arg(long, env = "ASC_API_KEY_ID", requires = "api_key_path")]
        api_key_id: Option<String>,
        /// The issuer id
        #[arg(long, env = "ASC_API_ISSUER_ID", requires = "api_key_path")]
        api_issuer_id: Option<String>,
    },
    /// Archive a release build and upload it to App Store Connect for
    /// TestFlight
    Testflight {
        /// The App Store Connect API key (`AuthKey_<id>.p8`)
        #[arg(long, env = "ASC_API_KEY_PATH")]
        api_key_path: std::path::PathBuf,
        /// The key's id
        #[arg(long, env = "ASC_API_KEY_ID")]
        api_key_id: String,
        /// The issuer id App Store Connect shows above the keys
        #[arg(long, env = "ASC_API_ISSUER_ID")]
        api_issuer_id: String,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    let sh = xshell::Shell::new()?;
    // every path below is relative to the workspace root
    sh.change_dir(env!("CARGO_MANIFEST_DIR"));
    sh.change_dir("..");

    match cli.command {
        Command::BuildIos { release, sim } => ios::build_core(&sh, release, sim),
        Command::Project => ios::project(&sh),
        Command::RunIos {
            udid,
            release,
            without_push,
            api_key_path,
            api_key_id,
            api_issuer_id,
        } => {
            let key = match (api_key_path, api_key_id, api_issuer_id) {
                (Some(path), Some(id), Some(issuer)) => Some(ios::ApiKey { path, id, issuer }),
                _ => None,
            };
            ios::run(&sh, &udid, release, without_push, key.as_ref())
        }
        Command::Testflight {
            api_key_path,
            api_key_id,
            api_issuer_id,
        } => ios::testflight(
            &sh,
            &ios::ApiKey {
                path: api_key_path,
                id: api_key_id,
                issuer: api_issuer_id,
            },
        ),
    }
}
