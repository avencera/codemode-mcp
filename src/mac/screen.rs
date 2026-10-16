//! The focused field through Accessibility, and typing into it with keyboard
//! events posted to the app that owns it
//!
//! Everything here blocks: Accessibility messages the target app and waits
//! for its answer, up to [`MESSAGING_TIMEOUT`]

use std::{ptr::NonNull, sync::Mutex, time::Duration};

use objc2_application_services::{AXError, AXIsProcessTrustedWithOptions, AXUIElement};
use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, CFType, CFURL};
use objc2_core_graphics::{
    CGEvent, CGEventFlags, CGEventSource, CGEventSourceStateID, CGPreflightPostEventAccess,
    CGRequestPostEventAccess,
};

use crate::logins::{FieldKind, FieldRule, FillError, FocusedField};

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

fn describe(element: &AXUIElement) -> Result<FocusedField, FillError> {
    Ok(FocusedField {
        kind: kind(element)?,
        pages: page_urls(element)?,
    })
}

/// The focused field, for the check before a value is read
pub fn focused_field() -> Result<FocusedField, FillError> {
    trusted()?;

    describe(&*focused_element()?)
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
    let host = rule.check(&describe(&field)?)?;

    let mut pid: libc::pid_t = 0;
    // SAFETY: `pid` is a valid out pointer
    if unsafe { field.pid(NonNull::from(&mut pid)) } != AXError::Success {
        return Err(FillError::Failed(
            "could not tell which app owns the focused field".to_owned(),
        ));
    }
    // a private source, so keys held on the real keyboard do not combine
    // with the characters typed here
    let source = CGEventSource::new(CGEventSourceStateID::Private)
        .ok_or_else(|| FillError::Failed("could not create a keyboard event source".to_owned()))?;

    let mut units = [0_u16; 2];
    for character in text.chars() {
        // before each character, so typing stops soon after focus moves;
        // keys already posted may still land, since the app handles them
        // after this check. A failed check stops it too, and the field may
        // then hold part of the value
        if focused_element().ok().as_ref() != Some(&field) {
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
            CGEvent::post_to_pid(pid, Some(&event));
        }
        std::thread::sleep(KEY_GAP);
    }

    Ok(host)
}
