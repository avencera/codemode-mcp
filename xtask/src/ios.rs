//! The iOS build, following Cove's: per-target `cargo build`, then
//! uniffi-bindgen-swift on the static library, then one xcframework in a local
//! Swift package the app links

use std::path::{Path, PathBuf};

use color_eyre::eyre::{Result, bail, eyre};
use xshell::{Shell, cmd};

const DEVICE_TARGET: &str = "aarch64-apple-ios";
const SIMULATOR_TARGET: &str = "aarch64-apple-ios-sim";
// must match `deploymentTarget` in ios/project.yml
const DEPLOYMENT_TARGET: &str = "26.0";
const LIBRARY: &str = "libcompanion_core.a";
const MODULE: &str = "companion_core_ffi";
const PACKAGE_DIR: &str = "ios/CompanionCore";
const GENERATED_DIR: &str = "ios/CompanionCore/Sources/CompanionCore/generated";
const PROJECT: &str = "ios/Companion.xcodeproj";
const SCHEME: &str = "Companion";
const BUNDLE_ID: &str = "com.avencera.codemode-mcp.companion";
const TEAM_ID: &str = "Q8UP8C53Y8";
/// Build products, outside the source tree
const BUILD_DIR: &str = "target/ios";
/// The workspace manifest, whose package version the app ships as
const MANIFEST: &str = include_str!("../../Cargo.toml");

/// An App Store Connect API key, for signing and uploading without Xcode's
/// account settings
pub struct ApiKey {
    /// The `.p8` file
    pub path: PathBuf,
    /// The key's id
    pub id: String,
    /// The issuer id
    pub issuer: String,
}

impl ApiKey {
    /// The xcodebuild arguments that sign in with this key
    fn arguments(&self) -> Vec<String> {
        vec![
            "-authenticationKeyPath".to_owned(),
            self.path.display().to_string(),
            "-authenticationKeyID".to_owned(),
            self.id.clone(),
            "-authenticationKeyIssuerID".to_owned(),
            self.issuer.clone(),
        ]
    }
}

/// Builds the core for the device (and the simulator with `sim`), and puts
/// the bindings and the xcframework into the CompanionCore package
pub fn build_core(sh: &Shell, release: bool, sim: bool) -> Result<()> {
    let mut targets = vec![DEVICE_TARGET];
    if sim {
        targets.push(SIMULATOR_TARGET);
    }
    let profile = if release { "release" } else { "debug" };
    let release_flag: &[&str] = if release { &["--release"] } else { &[] };

    let _deployment = sh.push_env("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET);
    let mut libraries = Vec::new();
    for target in &targets {
        println!("building the core for {target} ({profile})");
        cmd!(
            sh,
            "cargo build --locked --quiet -p companion-core --target {target} {release_flag...}"
        )
        .run()?;
        let library = PathBuf::from(format!("target/{target}/{profile}/{LIBRARY}"));
        if !sh.path_exists(&library) {
            bail!("{} was not built", library.display());
        }
        libraries.push(library);
    }

    let bindings = PathBuf::from(BUILD_DIR).join("bindings");
    let headers = PathBuf::from(BUILD_DIR).join("headers");
    sh.remove_path(&bindings)?;
    sh.remove_path(&headers)?;
    sh.create_dir(&headers)?;
    println!("generating the Swift bindings");
    let library = &libraries[0];
    cmd!(
        sh,
        "cargo run --locked --quiet -p uniffi_cli -- {library} {bindings}
            --swift-sources --headers --modulemap
            --module-name {MODULE} --modulemap-filename module.modulemap"
    )
    .run()?;

    // the xcframework takes the C side only; the Swift side is package source
    for entry in sh.read_dir(&bindings)? {
        let keep = entry
            .extension()
            .is_some_and(|extension| extension == "h" || extension == "modulemap");
        if keep {
            sh.copy_file(&entry, &headers)?;
        }
    }
    let xcframework = PathBuf::from(PACKAGE_DIR).join(format!("{MODULE}.xcframework"));
    sh.remove_path(&xcframework)?;
    let mut arguments = Vec::new();
    for library in &libraries {
        arguments.push("-library".to_owned());
        arguments.push(library.display().to_string());
        arguments.push("-headers".to_owned());
        arguments.push(headers.display().to_string());
    }
    cmd!(
        sh,
        "xcodebuild -quiet -create-xcframework {arguments...} -output {xcframework}"
    )
    .run()?;

    sh.remove_path(GENERATED_DIR)?;
    sh.create_dir(GENERATED_DIR)?;
    for entry in sh.read_dir(&bindings)? {
        if entry
            .extension()
            .is_some_and(|extension| extension == "swift")
        {
            sh.copy_file(&entry, GENERATED_DIR)?;
        }
    }
    println!("CompanionCore is ready in {PACKAGE_DIR}");

    Ok(())
}

/// Generates the Xcode project from ios/project.yml; the project itself is
/// not checked in, so it never drifts from the spec
pub fn project(sh: &Shell) -> Result<()> {
    if cmd!(sh, "which xcodegen")
        .quiet()
        .ignore_stdout()
        .run()
        .is_err()
    {
        bail!("xcodegen is missing; install it with `brew install xcodegen`");
    }
    // the app and the gateway are released together, so `just bump` moves
    // the app's version too; ios/project.yml reads it from the environment
    let version = app_version()?;
    let _version = sh.push_env("COMPANION_VERSION", version);
    cmd!(
        sh,
        "xcodegen generate --quiet --spec ios/project.yml --project ios"
    )
    .run()?;

    Ok(())
}

/// Builds and installs the app on the iPhone `udid`, then launches it
pub fn run(
    sh: &Shell,
    udid: &str,
    release: bool,
    without_push: bool,
    key: Option<&ApiKey>,
) -> Result<()> {
    build_core(sh, release, false)?;
    project(sh)?;

    let configuration = if release { "Release" } else { "Debug" };
    let derived = derived_data();
    let mut extra = Vec::new();
    if let Some(key) = key {
        extra.extend(key.arguments());
    }
    if without_push {
        // empty entitlements, so no capability the wildcard profile lacks
        let empty = std::env::current_dir()?
            .join(BUILD_DIR)
            .join("without-push.entitlements");
        sh.write_file(
            &empty,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict/></plist>\n",
        )?;
        extra.push(format!("CODE_SIGN_ENTITLEMENTS={}", empty.display()));
    }
    println!("building the app for {udid}");
    cmd!(
        sh,
        "xcodebuild -quiet -project {PROJECT} -scheme {SCHEME} -configuration {configuration}
            -destination platform=iOS,id={udid} -derivedDataPath {derived}
            -allowProvisioningUpdates {extra...} build"
    )
    .run()?;

    let app = derived.join(format!(
        "Build/Products/{configuration}-iphoneos/{SCHEME}.app"
    ));
    if !sh.path_exists(&app) {
        bail!("the build left no app at {}", app.display());
    }
    println!("installing on {udid}");
    cmd!(
        sh,
        "xcrun devicectl device install app --device {udid} {app}"
    )
    .run()?;
    // a locked phone refuses the launch; the install still stands
    if cmd!(
        sh,
        "xcrun devicectl device process launch --device {udid} --terminate-existing {BUNDLE_ID}"
    )
    .run()
    .is_err()
    {
        println!("installed, but not launched: unlock the phone and open Companion");
    }

    Ok(())
}

/// Archives a release build and uploads it to App Store Connect, where it
/// becomes a TestFlight build once Apple has processed it
pub fn testflight(sh: &Shell, key: &ApiKey) -> Result<()> {
    if !key.path.is_file() {
        bail!("no API key at {}", key.path.display());
    }
    build_core(sh, true, false)?;
    project(sh)?;

    let build_dir = PathBuf::from(BUILD_DIR);
    let archive = build_dir.join("Companion.xcarchive");
    let export = build_dir.join("export");
    let options = build_dir.join("ExportOptions.plist");
    sh.remove_path(&archive)?;
    sh.remove_path(&export)?;
    sh.write_file(&options, export_options())?;

    // App Store Connect wants a higher build number on every upload
    let build_number = cmd!(sh, "date -u +%Y%m%d%H%M").read()?;
    let authentication = key.arguments();
    let authentication_again = key.arguments();
    let derived = derived_data();
    println!("archiving build {build_number}");
    cmd!(
        sh,
        "xcodebuild -quiet -project {PROJECT} -scheme {SCHEME} -configuration Release
            -destination generic/platform=iOS -archivePath {archive}
            -derivedDataPath {derived}
            -allowProvisioningUpdates {authentication...}
            CURRENT_PROJECT_VERSION={build_number} archive"
    )
    .run()?;

    println!("uploading to App Store Connect");
    // the export copies with /usr/bin/rsync, which starts its other end
    // from PATH; a Homebrew rsync there rejects its `-E` and the export
    // fails with only "Copy failed"
    let path = std::env::var("PATH").unwrap_or_default();
    let _path = sh.push_env("PATH", format!("/usr/bin:{path}"));
    cmd!(
        sh,
        "xcodebuild -exportArchive -archivePath {archive} -exportPath {export}
            -exportOptionsPlist {options} -allowProvisioningUpdates
            {authentication_again...}"
    )
    .run()
    .map_err(|error| eyre!("the upload failed: {error}"))?;
    println!("uploaded build {build_number}; it shows in TestFlight once Apple has processed it");

    Ok(())
}

/// The codemode-mcp release the app is built from: the `version` of the
/// workspace's `[package]`, not of any dependency table
fn app_version() -> Result<&'static str> {
    let mut in_package = false;
    for line in MANIFEST.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package && let Some(value) = line.strip_prefix("version = ") {
            return Ok(value.trim_matches('"'));
        }
    }

    bail!("no [package] version in Cargo.toml")
}

fn derived_data() -> PathBuf {
    Path::new(BUILD_DIR).join("DerivedData")
}

/// Upload straight to App Store Connect, signed automatically by the team
fn export_options() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>destination</key>
    <string>upload</string>
    <key>method</key>
    <string>app-store-connect</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>teamID</key>
    <string>{TEAM_ID}</string>
    <key>manageAppVersionAndBuildNumber</key>
    <false/>
    <key>uploadSymbols</key>
    <true/>
</dict>
</plist>
"#
    )
}
