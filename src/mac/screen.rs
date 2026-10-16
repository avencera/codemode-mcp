//! The focused field through Accessibility, the browser that owns it by its
//! code signature, and typing into it with keyboard events posted to that
//! browser
//!
//! Everything here blocks: Accessibility messages the target app and waits
//! for its answer, up to [`MESSAGING_TIMEOUT`], and the browser's settings
//! are read from disk

use std::{
    ffi::c_void,
    path::{Path, PathBuf},
    ptr::NonNull,
    sync::Mutex,
    time::Duration,
};

use objc2_application_services::{AXError, AXIsProcessTrustedWithOptions, AXUIElement};
use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, CFType, CFURL};
use objc2_core_graphics::{
    CGEvent, CGEventFlags, CGEventSource, CGEventSourceStateID, CGPreflightPostEventAccess,
    CGRequestPostEventAccess,
};

use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use crate::logins::{Exposure, FieldKind, FieldRule, FillError, FocusedField, Setting};

/// How long one Accessibility request may wait on a busy app
const MESSAGING_TIMEOUT: f32 = 1.0;
/// Most parents walked from the field to the window, looking for its pages
const MAX_DEPTH: usize = 256;
/// Pause between characters, so a page handling each key event in script
/// keeps up
const KEY_GAP: Duration = Duration::from_millis(5);
/// Held while keys are typed, by the blocking thread itself: a call whose
/// caller gave up keeps typing until it ends, and the next fill waits
static TYPING: Mutex<()> = Mutex::new(());
/// What the System Settings switch is called, for the error that asks for it
const GRANT: &str = "turn on codemode-mcp in System Settings > Privacy & Security > \
     Accessibility, then fill again";

/// Where a browser keeps "Allow JavaScript from Apple Events"
enum Scripting {
    /// Safari's preferences, in the container of this bundle id
    Safari(&'static str),
    /// A Chromium browser's user data directory under Application Support,
    /// each of whose profiles has a `Preferences` file
    Chromium(&'static str),
    /// Firefox, which has no such setting
    Firefox,
}

/// A browser the `logins` server types into, known by its designated
/// requirement rather than its name, which any app can copy
struct Browser {
    /// Shown to the owner and in errors
    name: &'static str,
    /// Code signing requirement the running process must satisfy
    requirement: &'static str,
    scripting: Scripting,
}

/// Chrome's designated requirement as `codesign -d -r-` prints it, narrowed
/// from its four channels to one so each channel finds its own profiles
macro_rules! chrome {
    ($identifier:literal) => {
        concat!(
            "identifier \"",
            $identifier,
            "\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] \
             /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and \
             certificate leaf[subject.OU] = EQHXZ8M8AV"
        )
    };
}

/// A Developer ID app of the team `$team`
macro_rules! developer_id {
    ($identifier:literal, $team:literal) => {
        concat!(
            "identifier \"",
            $identifier,
            "\" and anchor apple generic and certificate leaf[subject.OU] = \"",
            $team,
            "\""
        )
    };
}

/// The browsers a login may be typed into
///
/// Read from `codesign -d -r-` on a local install: Safari and Google Chrome.
/// Team ids from the vendors' published signing identity, as listed on
/// appcatalog.cloud, without a local install to compare: Firefox
/// (Mozilla, 43AQ936H96), Microsoft Edge (UBF8T346G9), Brave (KL8N8XSYF4)
/// and Arc (The Browser Company, S6N382Y83G). Safari Technology Preview
/// follows Safari's form. An entry that is wrong only refuses its browser
const BROWSERS: [Browser; 10] = [
    Browser {
        name: "Safari",
        requirement: "identifier \"com.apple.Safari\" and anchor apple",
        scripting: Scripting::Safari("com.apple.Safari"),
    },
    Browser {
        name: "Safari Technology Preview",
        requirement: "identifier \"com.apple.SafariTechnologyPreview\" and anchor apple",
        scripting: Scripting::Safari("com.apple.SafariTechnologyPreview"),
    },
    Browser {
        name: "Chrome",
        requirement: chrome!("com.google.Chrome"),
        scripting: Scripting::Chromium("Google/Chrome"),
    },
    Browser {
        name: "Chrome Beta",
        requirement: chrome!("com.google.Chrome.beta"),
        scripting: Scripting::Chromium("Google/Chrome Beta"),
    },
    Browser {
        name: "Chrome Dev",
        requirement: chrome!("com.google.Chrome.dev"),
        scripting: Scripting::Chromium("Google/Chrome Dev"),
    },
    Browser {
        name: "Chrome Canary",
        requirement: chrome!("com.google.Chrome.canary"),
        scripting: Scripting::Chromium("Google/Chrome Canary"),
    },
    Browser {
        name: "Firefox",
        requirement: developer_id!("org.mozilla.firefox", "43AQ936H96"),
        scripting: Scripting::Firefox,
    },
    Browser {
        name: "Microsoft Edge",
        requirement: developer_id!("com.microsoft.edgemac", "UBF8T346G9"),
        scripting: Scripting::Chromium("Microsoft Edge"),
    },
    Browser {
        name: "Brave",
        requirement: developer_id!("com.brave.Browser", "KL8N8XSYF4"),
        scripting: Scripting::Chromium("BraveSoftware/Brave-Browser"),
    },
    Browser {
        name: "Arc",
        requirement: developer_id!("company.thebrowser.Browser", "S6N382Y83G"),
        scripting: Scripting::Chromium("Arc/User Data"),
    },
];

/// Checks that the daemon may read other apps and post keyboard events,
/// asking macOS to show its prompt when it may not
fn trusted() -> Result<(), FillError> {
    let key = CFString::from_static_str("AXTrustedCheckOptionPrompt");
    let options =
        CFDictionary::<CFString, CFBoolean>::from_slices(&[&*key], &[CFBoolean::new(true)]);
    // SAFETY: the dictionary holds the one key the call documents
    let accessibility = unsafe { AXIsProcessTrustedWithOptions(Some(options.as_opaque())) };
    if !accessibility {
        return Err(FillError::Unavailable(format!(
            "this Mac has not let codemode-mcp use Accessibility; {GRANT}"
        )));
    }
    // Accessibility normally covers posting events; this asks for it alone
    // on a Mac where it does not
    if !CGPreflightPostEventAccess() {
        CGRequestPostEventAccess();

        return Err(FillError::Unavailable(format!(
            "this Mac has not let codemode-mcp post keyboard events; {GRANT}"
        )));
    }

    Ok(())
}

/// `element`'s value for `name`; `None` when it has none. Any other
/// failure, such as a busy app timing out, is the error
fn copy_value(element: &AXUIElement, name: &str) -> Result<Option<CFRetained<CFType>>, AXError> {
    let name = CFString::from_str(name);
    let mut value: *const CFType = std::ptr::null();
    // SAFETY: `value` is a valid out pointer, and on success holds a +1
    // reference the caller owns
    let error = unsafe { element.copy_attribute_value(&name, NonNull::from(&mut value)) };
    match error {
        AXError::Success => {
            Ok(NonNull::new(value.cast_mut()).map(|value| unsafe { CFRetained::from_raw(value) }))
        }
        AXError::NoValue | AXError::AttributeUnsupported => Ok(None),
        error => Err(error),
    }
}

fn disabled() -> FillError {
    FillError::Unavailable(format!("Accessibility is off for codemode-mcp; {GRANT}"))
}

/// `element`'s value for `name`; `None` when it has none or cannot answer,
/// for reads where a missing value is refused anyway
fn attribute(element: &AXUIElement, name: &str) -> Result<Option<CFRetained<CFType>>, FillError> {
    match copy_value(element, name) {
        Ok(value) => Ok(value),
        Err(AXError::APIDisabled) => Err(disabled()),
        Err(_) => Ok(None),
    }
}

/// `element`'s value for `name` on the walk to the top page, where a read
/// that fails must not pass for the end of the tree: that would leave the
/// pages above it unchecked
fn page_attribute(
    element: &AXUIElement,
    name: &str,
) -> Result<Option<CFRetained<CFType>>, FillError> {
    match copy_value(element, name) {
        Ok(value) => Ok(value),
        Err(AXError::APIDisabled) => Err(disabled()),
        Err(_) => Err(FillError::Refused(
            "could not read the pages around the focused field; fill again".to_owned(),
        )),
    }
}

fn text_attribute(element: &AXUIElement, name: &str) -> Result<Option<String>, FillError> {
    Ok(text(attribute(element, name)?))
}

fn text(value: Option<CFRetained<CFType>>) -> Option<String> {
    value
        .and_then(|value| value.downcast::<CFString>().ok())
        .map(|text| text.to_string())
}

fn element(value: Option<CFRetained<CFType>>) -> Option<CFRetained<AXUIElement>> {
    value.and_then(|value| value.downcast::<AXUIElement>().ok())
}

/// The element with keyboard focus, across every app
fn focused_element() -> Result<CFRetained<AXUIElement>, FillError> {
    // SAFETY: plain constructor
    let system = unsafe { AXUIElement::new_system_wide() };
    // SAFETY: a valid element and a finite timeout
    unsafe { system.set_messaging_timeout(MESSAGING_TIMEOUT) };

    element(attribute(&system, "AXFocusedUIElement")?).ok_or_else(|| {
        FillError::Refused("no element has keyboard focus; click the field first".to_owned())
    })
}

fn kind(element: &AXUIElement) -> Result<FieldKind, FillError> {
    let role = text_attribute(element, "AXRole")?;
    let subrole = text_attribute(element, "AXSubrole")?;

    Ok(match (role.as_deref(), subrole.as_deref()) {
        (_, Some("AXSecureTextField")) => FieldKind::Secure,
        (Some("AXTextField" | "AXComboBox"), _) => FieldKind::Text,
        _ => FieldKind::Other,
    })
}

/// Addresses of every page around `element`, innermost first, so a field
/// in a frame lists the frame's document before the page holding it
///
/// A page whose address cannot be read is listed as an empty address,
/// which the rule refuses, rather than skipped
fn page_urls(field: &AXUIElement) -> Result<Vec<String>, FillError> {
    let mut pages = Vec::new();
    let mut current = element(page_attribute(field, "AXParent")?);
    for _ in 0..MAX_DEPTH {
        let Some(node) = current else {
            return Ok(pages);
        };
        if text(page_attribute(&node, "AXRole")?).as_deref() == Some("AXWebArea") {
            pages.push(web_area_url(&node)?.unwrap_or_default());
        }
        current = element(page_attribute(&node, "AXParent")?);
    }

    // deeper than any page goes; a top page left unseen could be anything
    Err(FillError::Refused(
        "the focused field is nested too deeply to find its page".to_owned(),
    ))
}

fn web_area_url(area: &AXUIElement) -> Result<Option<String>, FillError> {
    let Some(url) = attribute(area, "AXURL")? else {
        return Ok(None);
    };

    // Safari and Chrome answer a URL; take text as well, in case
    Ok(match url.downcast::<CFURL>() {
        Ok(url) => Some(url.string().to_string()),
        Err(other) => other
            .downcast::<CFString>()
            .ok()
            .map(|text| text.to_string()),
    })
}

/// The browser that owns the focused field, and what other programs could
/// do with it; read once per check, since the app behind a field does not
/// change while it keeps focus
struct Owner {
    pid: libc::pid_t,
    browser: Option<&'static Browser>,
    exposure: Exposure,
}

fn owner(field: &AXUIElement) -> Result<Owner, FillError> {
    let mut pid: libc::pid_t = 0;
    // SAFETY: `pid` is a valid out pointer
    if unsafe { field.pid(NonNull::from(&mut pid)) } != AXError::Success {
        return Err(FillError::Failed(
            "could not tell which app owns the focused field".to_owned(),
        ));
    }
    let browser = browser(pid);
    let exposure = browser
        .map(|browser| exposure(pid, browser))
        .unwrap_or_default();

    Ok(Owner {
        pid,
        browser,
        exposure,
    })
}

/// The browser whose designated requirement the running process `pid`
/// satisfies, asked of the kernel's code signing rather than the app
fn browser(pid: libc::pid_t) -> Option<&'static Browser> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE).ok()?;

    BROWSERS.iter().find(|browser| {
        browser
            .requirement
            .parse::<SecRequirement>()
            .is_ok_and(|requirement| code.check_validity(Flags::NONE, &requirement).is_ok())
    })
}

fn exposure(pid: libc::pid_t, browser: &Browser) -> Exposure {
    let started = match browser.scripting {
        Scripting::Safari(_) => None,
        Scripting::Chromium(_) | Scripting::Firefox => Some(command_line(pid)),
    };
    let remote_debugging = match &started {
        None => Setting::Off,
        Some(None) => Setting::Unknown,
        Some(Some(started)) if started.remote_debugging() => Setting::On,
        Some(Some(_)) => Setting::Off,
    };
    let apple_events_javascript = match browser.scripting {
        Scripting::Safari(bundle) => safari_javascript(bundle),
        Scripting::Chromium(directory) => {
            let flagged = started
                .flatten()
                .and_then(|started| started.switch("user-data-dir").map(PathBuf::from));
            match flagged
                .or_else(|| home().map(|home| home.join(APPLICATION_SUPPORT).join(directory)))
            {
                Some(directory) => chromium_javascript(&directory),
                None => Setting::Unknown,
            }
        }
        Scripting::Firefox => Setting::Off,
    };

    Exposure {
        remote_debugging,
        apple_events_javascript,
    }
}

/// Where Chromium browsers keep their user data, under the home folder
const APPLICATION_SUPPORT: &str = "Library/Application Support";

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// What a process was started with
#[derive(Debug, PartialEq, Eq)]
struct CommandLine {
    arguments: Vec<String>,
    /// `NAME=value` entries
    environment: Vec<String>,
}

impl CommandLine {
    /// Whether it turns on a debugging protocol: Chromium's port or pipe,
    /// which Firefox also takes for its own protocol, or Firefox's
    /// Marionette, by flag or environment, and devtools server
    fn remote_debugging(&self) -> bool {
        self.arguments.iter().any(|argument| {
            switch_name(argument).is_some_and(|(name, _)| {
                matches!(
                    name,
                    "remote-debugging-port"
                        | "remote-debugging-pipe"
                        | "marionette"
                        | "start-debugger-server"
                )
            })
        }) || self.environment.iter().any(|entry| {
            entry
                .split_once('=')
                .is_some_and(|(name, _)| name == "MOZ_MARIONETTE")
        })
    }

    /// The value of switch `name`, read as Chromium reads it: with one dash
    /// or two, and the last one given winning
    fn switch(&self, name: &str) -> Option<&str> {
        self.arguments
            .iter()
            .rev()
            .map(String::as_str)
            .filter_map(switch_name)
            .find(|(switch, _)| *switch == name)
            .map(|(_, value)| value.unwrap_or_default())
    }
}

/// A switch's name and value, for an argument that starts with one dash or
/// two, as Chromium and Firefox both take them
fn switch_name(argument: &str) -> Option<(&str, Option<&str>)> {
    let switch = argument
        .strip_prefix("--")
        .or_else(|| argument.strip_prefix('-'))?;

    Some(match switch.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (switch, None),
    })
}

/// The command line of process `pid`, from `KERN_PROCARGS2`; `None` when
/// the kernel will not say, as for another user's process
fn command_line(pid: libc::pid_t) -> Option<CommandLine> {
    let mut max: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut name = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `max` holds `size` bytes, and the name has the two parts given
    let read = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            2,
            (&raw mut max).cast::<c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 || max <= 0 {
        return None;
    }

    let mut buffer = vec![0_u8; usize::try_from(max).ok()?];
    let mut size = buffer.len();
    let mut name = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buffer` holds `size` bytes, and the name has the three parts
    // given
    let read = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    buffer.truncate(size);

    procargs(&buffer)
}

/// The arguments and environment in a `KERN_PROCARGS2` answer: the
/// argument count, the executable's path, padding, then the arguments and
/// the environment, each ending in a NUL, until an empty one
fn procargs(buffer: &[u8]) -> Option<CommandLine> {
    let (count, rest) = buffer.split_first_chunk::<4>()?;
    let count = usize::try_from(i32::from_ne_bytes(*count)).ok()?;
    let rest = &rest[rest.iter().position(|byte| *byte == 0)?..];
    let rest = &rest[rest.iter().position(|byte| *byte != 0)?..];
    let mut entries = rest
        .split(|byte| *byte == 0)
        .map(|entry| String::from_utf8_lossy(entry).into_owned());
    let arguments: Vec<String> = entries.by_ref().take(count).collect();
    if arguments.len() != count {
        return None;
    }
    let environment = entries.take_while(|entry| !entry.is_empty()).collect();

    Some(CommandLine {
        arguments,
        environment,
    })
}

/// Safari's "Allow JavaScript from Apple Events", from its container, which
/// only a process with Full Disk Access may read
fn safari_javascript(bundle: &str) -> Setting {
    let Some(home) = home() else {
        return Setting::Unknown;
    };
    let path = home
        .join("Library/Containers")
        .join(bundle)
        .join("Data/Library/Preferences")
        .join(format!("{bundle}.plist"));
    let Ok(preferences) = plist::Value::from_file(path) else {
        return Setting::Unknown;
    };
    let on = preferences
        .as_dictionary()
        .and_then(|preferences| preferences.get("AllowJavaScriptFromAppleEvents"))
        .and_then(plist::Value::as_boolean);

    if on == Some(true) {
        Setting::On
    } else {
        Setting::Off
    }
}

/// A Chromium browser's "Allow JavaScript from Apple Events": on when any
/// profile turned it on, since the field may be in any of them, and
/// unknown when a profile or the directory cannot be read
fn chromium_javascript(user_data: &Path) -> Setting {
    let Ok(entries) = std::fs::read_dir(user_data) else {
        return Setting::Unknown;
    };
    let mut profiles = 0;
    let mut unread = false;
    for entry in entries {
        let Ok(entry) = entry else {
            unread = true;
            continue;
        };
        let path = entry.path().join("Preferences");
        if !path.is_file() {
            continue;
        }
        profiles += 1;
        let preferences = std::fs::read(&path)
            .ok()
            .and_then(|text| serde_json::from_slice::<serde_json::Value>(&text).ok());
        let Some(preferences) = preferences else {
            unread = true;
            continue;
        };
        if preferences.pointer("/browser/allow_javascript_apple_events")
            == Some(&serde_json::Value::Bool(true))
        {
            return Setting::On;
        }
    }

    // no profile at all means the setting was looked for in the wrong place
    if unread || profiles == 0 {
        Setting::Unknown
    } else {
        Setting::Off
    }
}

fn describe(element: &AXUIElement, owner: &Owner) -> Result<FocusedField, FillError> {
    Ok(FocusedField {
        kind: kind(element)?,
        pages: page_urls(element)?,
        browser: owner.browser.map(|browser| browser.name.to_owned()),
        exposure: owner.exposure.clone(),
    })
}

/// The focused field, for the checks before the owner is asked and before a
/// value is read
pub fn focused_field() -> Result<FocusedField, FillError> {
    trusted()?;
    let field = focused_element()?;

    describe(&field, &owner(&field)?)
}

/// Types `text` into the focused field once `rule` passes it; see
/// [`crate::mac::Mac::fill`]
pub fn fill(text: &str, rule: &FieldRule) -> Result<String, FillError> {
    // a poisoned lock only means an earlier fill panicked; nothing it
    // guards is left half changed
    let _typing = TYPING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    trusted()?;
    let field = focused_element()?;
    let owner = owner(&field)?;
    let host = rule.check(&describe(&field, &owner)?)?;

    // a private source, so keys held on the real keyboard do not combine
    // with the characters typed here
    let source = CGEventSource::new(CGEventSourceStateID::Private)
        .ok_or_else(|| FillError::Failed("could not create a keyboard event source".to_owned()))?;

    let mut units = [0_u16; 2];
    for character in text.chars() {
        // before each character, so typing stops soon after focus moves or
        // the page under the same field navigates, or a show-password
        // button turns the field into plain text; keys already posted may
        // still land, since the app handles them after this check. A failed
        // check stops it too, and the field may then hold part of the value.
        // The same element keeps the same app, so its signature and
        // settings are not read again
        let unchanged = focused_element().ok().as_ref() == Some(&field)
            && describe(&field, &owner)
                .and_then(|now| rule.check(&now))
                .is_ok_and(|now| now == host);
        if !unchanged {
            return Err(FillError::Interrupted);
        }
        let encoded = character.encode_utf16(&mut units);
        for down in [true, false] {
            let event = CGEvent::new_keyboard_event(Some(&source), 0, down)
                .ok_or_else(|| FillError::Failed("could not create a keyboard event".to_owned()))?;
            CGEvent::set_flags(Some(&event), CGEventFlags(0));
            // SAFETY: `encoded` holds `len` UTF-16 units and outlives the call
            unsafe {
                CGEvent::keyboard_set_unicode_string(
                    Some(&event),
                    encoded.len() as _,
                    encoded.as_ptr(),
                );
            }
            CGEvent::post_to_pid(owner.pid, Some(&event));
        }
        std::thread::sleep(KEY_GAP);
    }

    Ok(host)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use core_foundation::url::CFURL;
    use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};

    use super::{BROWSERS, CommandLine, command_line, procargs};

    #[test]
    fn every_requirement_compiles_and_matches_its_installed_browser() {
        for browser in &BROWSERS {
            let requirement = SecRequirement::from_str(browser.requirement);
            assert!(requirement.is_ok(), "{}", browser.name);
        }

        // only the browsers this Mac has; an entry that is wrong for one
        // it lacks refuses that browser rather than letting another in
        for (name, path) in [
            ("Safari", "/Applications/Safari.app"),
            ("Chrome", "/Applications/Google Chrome.app"),
            ("Firefox", "/Applications/Firefox.app"),
            ("Microsoft Edge", "/Applications/Microsoft Edge.app"),
            ("Brave", "/Applications/Brave Browser.app"),
            ("Arc", "/Applications/Arc.app"),
        ] {
            let Some(url) = CFURL::from_path(path, true) else {
                continue;
            };
            let Ok(code) = SecStaticCode::from_path(&url, Flags::NONE) else {
                continue;
            };
            let matched: Vec<&str> = BROWSERS
                .iter()
                .filter(|browser| {
                    SecRequirement::from_str(browser.requirement).is_ok_and(|requirement| {
                        code.check_validity(Flags::BASIC_VALIDATE_ONLY, &requirement)
                            .is_ok()
                    })
                })
                .map(|browser| browser.name)
                .collect();
            assert_eq!(matched, [name], "{path}");
        }
    }

    fn started(arguments: &[&str], environment: &[&str]) -> CommandLine {
        CommandLine {
            arguments: arguments.iter().map(|text| (*text).to_owned()).collect(),
            environment: environment.iter().map(|text| (*text).to_owned()).collect(),
        }
    }

    #[test]
    fn the_kernel_reports_this_process_s_own_arguments() {
        let expected: Vec<String> = std::env::args().collect();
        let own = command_line(std::process::id() as libc::pid_t);
        assert_eq!(own.as_ref().map(|own| &own.arguments), Some(&expected));
        assert!(
            own.is_some_and(|own| own
                .environment
                .iter()
                .any(|entry| entry.starts_with("PATH="))),
            "no environment"
        );

        let mut answer = 2_i32.to_ne_bytes().to_vec();
        answer.extend_from_slice(
            b"/bin/x\0\0\0x\0--remote-debugging-port=9222\0MOZ_MARIONETTE=1\0\0junk\0",
        );
        assert_eq!(
            procargs(&answer),
            Some(started(
                &["x", "--remote-debugging-port=9222"],
                &["MOZ_MARIONETTE=1"]
            ))
        );
    }

    #[test]
    fn debugging_and_profile_switches_are_read_as_the_browser_reads_them() {
        for flag in [
            "--remote-debugging-port=9222",
            "--remote-debugging-port=0",
            "--remote-debugging-pipe",
            "-remote-debugging-port",
            "--marionette",
            "-marionette",
            "--start-debugger-server=6000",
        ] {
            assert!(started(&["x", flag], &[]).remote_debugging(), "{flag}");
        }
        assert!(started(&["x"], &["MOZ_MARIONETTE="]).remote_debugging());
        for other in [
            "https://example.com/--remote-debugging-port",
            "--remote-allow-origins=*",
            "marionette",
        ] {
            assert!(
                !started(&["x", other], &["HOME=/u"]).remote_debugging(),
                "{other}"
            );
        }

        // the last one wins, with either dash, as in Chromium
        let profiles = started(
            &[
                "x",
                "--user-data-dir=/a",
                "-user-data-dir=/b",
                "--user-data-dirx=/c",
            ],
            &[],
        );
        assert_eq!(profiles.switch("user-data-dir"), Some("/b"));
    }
}
