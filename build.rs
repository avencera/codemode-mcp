//! Embeds `assets/Info.plist` in the `codemode-mcp` binary on macOS
//!
//! macOS reads a command-line tool's privacy prompts and bundle identifier
//! from an `__info_plist` section; without one, EventKit's calendar and
//! reminders access requests are refused without a prompt

fn main() {
    let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/Info.plist");
    println!("cargo:rerun-if-changed={}", plist.display());

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!(
            "cargo:rustc-link-arg-bin=codemode-mcp=-Wl,-sectcreate,__TEXT,__info_plist,{}",
            plist.display()
        );
    }
}
