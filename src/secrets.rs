//! `{{ op://vault/item/field }}` references in a server's `headers`, `env`
//! and `url`, read through the 1Password CLI when it first connects, and the
//! redactor that keeps secrets out of scripts' text and the logs
//!
//! The braces follow `op inject`'s template syntax, so a value can mix text
//! and references, e.g. `Bearer {{ op://Dev/Context7/credential }}`

pub mod approved;
mod find;
pub mod handoff;
pub mod key_store;
mod logs;
mod spawn;

pub use find::{FindError, LoginPart, SavedLogin};
pub use logs::{RedactingMakeWriter, redacting_logs};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, PoisonError, RwLock},
    time::Duration,
};

use tokio::{sync::Mutex, task::JoinSet};

use self::approved::{Approved, Consumer};
use crate::{
    companion::{Companions, CreatedItem, DeviceTrust, FindBatches, NewItem, ProgramValue},
    config::{Config, SecretsConfig},
    mac::{OnMac, TouchId},
    store::Store,
};

/// How long one `op read` may take; long enough for the 1Password app's
/// unlock or Touch ID prompt on the Mac
const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the phones wait while the owner is at this Mac, whose own
/// prompt usually answers first; a read answered within it never pushes
pub const PHONE_GRACE: Duration = Duration::from_secs(5);
/// Longest upstream error text handed to a script
const MAX_ERROR_TEXT: usize = 2000;
/// Replacement for secrets found in upstream text
const REDACTED: &str = "[redacted]";
/// Shorter secrets would redact ordinary words
const MIN_SECRET_LEN: usize = 6;
/// Longest line of `op`'s error output forwarded from a failed create
const MAX_OP_ERROR_CHARS: usize = 200;
/// Longest vault name, item title, field label or category accepted
const MAX_ITEM_NAME_CHARS: usize = 80;

/// Most bytes a new item's value may take once escaped for JSON, well inside
/// the companion protocol's body limit with the names around it; escaping
/// can grow a value up to six times, so the escaped form is what is measured
pub const MAX_ITEM_VALUE_JSON_BYTES: usize = 32 * 1024;
/// Longest `op://` reference accepted
const MAX_REFERENCE_CHARS: usize = 256;
/// Why a value that is not UTF-8, such as a `.p12` file attached to an item,
/// cannot go where only text fits
pub const NOT_TEXT: &str = "it holds binary data such as a file, not text; write it to its own \
                            file with `codemode-mcp op read <reference> --out-file <path>`";

/// The daemon's one 1Password reader and the companions it may ask, shared
/// by upstream connections and OAuth logins so they keep one cache and one
/// iroh endpoint
#[derive(Clone)]
pub struct Secrets {
    /// Reads references, also through the companions when any are paired
    pub onepassword: OnePassword,
    /// Always built, since `companion invite` pairs the first one
    pub companions: Arc<Companions>,
}

impl Secrets {
    /// Readers for `config`, loaded from `config_path`; `presence` tells
    /// whether the owner is at this Mac, which decides whether a read also
    /// runs the local `op`
    ///
    /// The companions are attached even when there are none yet, since one
    /// registering with an invite is used without a restart. Only those
    /// `trust` vouches for are used. Values sealed to the phones are kept in
    /// `store`; without one no phone is asked
    pub fn new(
        config: &SecretsConfig,
        config_path: Option<PathBuf>,
        presence: Option<OnMac>,
        store: Option<Store>,
        trust: DeviceTrust,
        approved: Arc<Approved>,
    ) -> Self {
        let companions = Arc::new(Companions::new(
            config,
            config_path,
            store,
            trust,
            presence.clone(),
        ));
        let onepassword = OnePassword::new(config.op.clone())
            .with_companions(Arc::clone(&companions), presence)
            .with_approved(approved);

        Self {
            onepassword,
            companions,
        }
    }
}

/// Failures turning references into values; none of them carries a value
/// that was read
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// A `{{` has no closing `}}`
    #[error("a `{{{{` has no closing `}}}}`")]
    Unclosed,
    /// The text between the braces is not an `op://` reference; it is left
    /// out of the message in case it is a pasted secret
    #[error("the text between `{{{{` and `}}}}` must be an op://vault/item/field reference")]
    NotAReference,
    /// A `url` is not an `http` or `https` URL with a host, or does not
    /// become one once its references are read; the value is left out of the
    /// message
    #[error("the `url` is not a valid http(s) URL with a literal host")]
    NotAUrl,
    /// A `url` is a reference alone, so codemode cannot tell which part of
    /// it is the key
    #[error(
        "a `url` must start with a literal http:// or https:// and a literal host, and hold references only in path segments and query names or values; e.g. url = \"https://host/mcp/{{{{ op://Vault/Item/key }}}}\""
    )]
    UrlReferenceWhole,
    /// A reference in a `url` sits outside the path and the query
    #[error(
        "references in a `url` may appear only in path segments and query names or values, not in the scheme, credentials, host, port or fragment; e.g. url = \"https://host/mcp/{{{{ op://Vault/Item/key }}}}/message\""
    )]
    UrlReferenceMisplaced,
    /// A value read for a `url` is shorter than the redactor can match
    #[error(
        "a value read for the `url` is too short to be protected; use a key of at least {MIN_FRAGMENT_KEY_LEN} bytes"
    )]
    UrlValueTooShort,
    /// A value read for an embedded `url` reference holds a character that
    /// URL parsing, escaping or a library's logging could change into a form
    /// the redactor does not know
    #[error(
        "a value read for the `url` may hold only ASCII letters, digits and - . _ ~ + / = : @ ! * , ; characters"
    )]
    UrlValueUnprotectable,
    /// A value read for a `url` reference is itself a URL: the item's URL
    /// field was read, pasted or filled in place of the key, which then
    /// lands percent-encoded in one segment and the server rejects it
    #[error(
        "the value read for `{0}` is a whole URL, not the part that goes in its place in the server's `url`; it was dropped and is read again on the next attempt. When a phone asks, paste only that field's value: AutoFill fills the item's password"
    )]
    UrlValueIsUrl(String),
    /// `op` could not be started
    #[error("failed to start `{program}`: {source}")]
    Spawn {
        /// Program that failed
        program: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// `op read` did not answer in time, e.g. a prompt nobody answered
    #[error("`op read {reference}` took longer than {timeout:?}")]
    TimedOut {
        /// Reference being read
        reference: String,
        /// Timeout that elapsed
        timeout: Duration,
    },
    /// `op read` failed, e.g. a locked app, a denied prompt or a missing item
    #[error("`op read {reference}` failed: {reason}")]
    Read {
        /// Reference being read
        reference: String,
        /// First line of `op`'s error output
        reason: String,
    },
}

impl SecretError {
    /// Why a read failed, without the reference, for joining the answers
    /// of several sources
    fn reason(&self) -> String {
        match self {
            Self::Read { reason, .. } => reason.clone(),
            Self::TimedOut { timeout, .. } => format!("took longer than {timeout:?}"),
            other => other.to_string(),
        }
    }
}

/// One piece of a configured value
#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    Text(&'a str),
    Reference(&'a str),
}

fn pieces(value: &str) -> Result<Vec<Piece<'_>>, SecretError> {
    let mut pieces = Vec::new();
    let mut rest = value;

    while let Some(start) = rest.find("{{") {
        if start > 0 {
            pieces.push(Piece::Text(&rest[..start]));
        }
        let after = &rest[start + 2..];
        let end = after.find("}}").ok_or(SecretError::Unclosed)?;
        let reference = after[..end].trim();
        if !is_reference(reference) {
            return Err(SecretError::NotAReference);
        }
        pieces.push(Piece::Reference(reference));
        rest = &after[end + 2..];
    }

    if !rest.is_empty() {
        pieces.push(Piece::Text(rest));
    }

    Ok(pieces)
}

/// `op://vault/item/field` or `op://vault/item/section/field`; names may
/// hold spaces, and `op` itself rejects anything else it cannot find
pub fn is_reference(text: &str) -> bool {
    // a companion's Touch ID prompt shows the reference, so it must read as
    // stored and stay short enough to be seen whole
    if text.chars().count() > MAX_REFERENCE_CHARS
        || crate::prompt::one_line(text, usize::MAX) != text
    {
        return false;
    }

    text.strip_prefix("op://").is_some_and(|path| {
        let segments: Vec<&str> = path.split('/').collect();

        (3..=4).contains(&segments.len())
            && segments.iter().all(|segment| !segment.trim().is_empty())
    })
}

/// `secret` as it appears in text a library or an authorization server may
/// print: as is and percent-encoded the ways a query string carries it (form
/// encoding, the unreserved set only, and every non-alphanumeric byte); JSON
/// escapes are undone by [`unescaped_with_spans`] when text is matched
fn variants(secret: &str) -> Vec<String> {
    fn encode(text: &str, kept: &[u8], lower: bool) -> String {
        let mut encoded = String::with_capacity(text.len() * 2);
        for byte in text.bytes() {
            if byte.is_ascii_alphanumeric() || kept.contains(&byte) {
                encoded.push(char::from(byte));
            } else {
                encoded.push_str(&if lower {
                    format!("%{byte:02x}")
                } else {
                    format!("%{byte:02X}")
                });
            }
        }

        encoded
    }

    // libraries differ on the case of the hex digits
    let mut variants = vec![secret.to_owned()];
    for lower in [false, true] {
        variants.extend([
            encode(secret, b"*-._", lower),
            encode(secret, b"-._~", lower),
            encode(secret, b"", lower),
        ]);
    }
    variants.retain(|variant| !variant.is_empty());
    variants.sort();
    variants.dedup();

    variants
}

/// The byte a `%XX` escape at the start of `bytes` stands for, in either case
fn escaped_byte(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [b'%', high, low, ..] => {
            let digit = |byte: &u8| char::from(*byte).to_digit(16);

            Some(u8::try_from(digit(high)? * 16 + digit(low)?).ok()?)
        }
        _ => None,
    }
}

/// The character a JSON string escape at the start of `bytes` stands for, and
/// the escape's width; `\uXXXX` pairs of surrogates stand for one character
fn json_escape(bytes: &[u8]) -> Option<(char, usize)> {
    let unit = |at: &[u8]| -> Option<u32> {
        match at {
            [b'\\', b'u', digits @ ..] if digits.len() >= 4 => {
                let digits = std::str::from_utf8(&digits[..4]).ok()?;
                if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return None;
                }

                u32::from_str_radix(digits, 16).ok()
            }
            _ => None,
        }
    };

    let simple = match bytes {
        [b'\\', b'/', ..] => Some('/'),
        [b'\\', b'\\', ..] => Some('\\'),
        [b'\\', b'"', ..] => Some('"'),
        [b'\\', b'b', ..] => Some('\u{8}'),
        [b'\\', b'f', ..] => Some('\u{c}'),
        [b'\\', b'n', ..] => Some('\n'),
        [b'\\', b'r', ..] => Some('\r'),
        [b'\\', b't', ..] => Some('\t'),
        _ => None,
    };
    if let Some(character) = simple {
        return Some((character, 2));
    }

    let first = unit(bytes)?;
    match first {
        0xD800..=0xDBFF => {
            // a high surrogate stands for a character only with its low half
            let second = unit(bytes.get(6..)?)?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return None;
            }
            let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);

            Some((char::from_u32(code)?, 12))
        }
        0xDC00..=0xDFFF => None,
        _ => Some((char::from_u32(first)?, 6)),
    }
}

/// Which escapes a decoded view undoes; a key holding a literal `%41` is only
/// found in text that escaped it for JSON by leaving the percent escapes alone
#[derive(Clone, Copy)]
struct Unescape {
    percent: bool,
    json: bool,
    plus_is_space: bool,
    html: bool,
}

/// Named HTML character references a response body may print a key's bytes as
const HTML_ENTITIES: [(&str, char); 19] = [
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("plus", '+'),
    ("sol", '/'),
    ("colon", ':'),
    ("equals", '='),
    ("commat", '@'),
    ("excl", '!'),
    ("ast", '*'),
    ("comma", ','),
    ("semi", ';'),
    ("period", '.'),
    ("lowbar", '_'),
    ("tilde", '~'),
    ("hyphen", '-'),
    ("dash", '-'),
];

/// The character an HTML reference (`&#NN;`, `&#xHH;` or a named one) at the
/// start of `bytes` stands for, and the reference's length
fn html_entity(bytes: &[u8]) -> Option<(char, usize)> {
    let rest = bytes.strip_prefix(b"&")?;
    let end = rest.iter().take(10).position(|byte| *byte == b';')?;
    let body = std::str::from_utf8(&rest[..end]).ok()?;
    let character = match body.strip_prefix('#') {
        Some(number) => {
            // `from_str_radix` would also take a leading sign
            if !number.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return None;
            }
            let code = match number.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16),
                None => number.parse(),
            };

            char::from_u32(code.ok()?)?
        }
        None => HTML_ENTITIES.iter().find(|(name, _)| *name == body)?.1,
    };

    Some((character, end + 2))
}

impl Unescape {
    /// Every combination worth matching text against, each with and without
    /// HTML references; a header or env secret may hold a literal `&amp;`
    /// that only a view leaving HTML alone still matches
    const VIEWS: [Self; 8] = [
        Self::new(true, false, false, false),
        Self::new(true, false, true, false),
        Self::new(false, true, false, false),
        Self::new(true, true, false, false),
        Self::new(true, false, false, true),
        Self::new(true, false, true, true),
        Self::new(false, true, false, true),
        Self::new(true, true, false, true),
    ];

    const fn new(percent: bool, json: bool, plus_is_space: bool, html: bool) -> Self {
        Self {
            percent,
            json,
            plus_is_space,
            html,
        }
    }
}

/// Decoded bytes with, for each, the span of the original text it came from
type Decoded = (Vec<u8>, Vec<(usize, usize)>);

/// How many times a view decodes its own output; a client's `Debug` output
/// escapes the JSON escapes of a body, and each layer may nest in another
const MAX_UNESCAPE_PASSES: usize = 4;

/// `text` with the escapes `mode` names decoded, repeatedly until the text
/// stops changing or [`MAX_UNESCAPE_PASSES`] passes have run, and for each
/// decoded byte the span of `text` it came from
///
/// Returns every layer after the first pass, so a key is found whichever
/// layer it shows in
fn unescaped_layers(text: &str, mode: Unescape) -> Vec<Decoded> {
    let mut layers: Vec<Decoded> = Vec::new();
    let mut current = unescaped_with_spans(text.as_bytes(), mode);
    for _ in 1..MAX_UNESCAPE_PASSES {
        let (next, next_spans) = unescaped_with_spans(&current.0, mode);
        if next == current.0 {
            break;
        }
        // a byte of the next layer spans what its source bytes span
        let spans = next_spans
            .into_iter()
            .map(|(start, end)| (current.1[start].0, current.1[end - 1].1))
            .collect();
        layers.push(std::mem::replace(&mut current, (next, spans)));
    }
    layers.push(current);

    layers
}

/// `bytes` with the escapes `mode` names decoded in one pass, and for each
/// decoded byte the span of `bytes` it came from; the bytes of a character an
/// escape stands for share its span
fn unescaped_with_spans(bytes: &[u8], mode: Unescape) -> Decoded {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut spans = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(byte) = escaped_byte(&bytes[index..]).filter(|_| mode.percent) {
            decoded.push(byte);
            spans.push((index, index + 3));
            index += 3;
        } else if let Some((character, width)) = json_escape(&bytes[index..])
            .filter(|_| mode.json)
            .or_else(|| html_entity(&bytes[index..]).filter(|_| mode.html))
        {
            let mut buffer = [0; 4];
            for byte in character.encode_utf8(&mut buffer).bytes() {
                decoded.push(byte);
                spans.push((index, index + width));
            }
            index += width;
        } else {
            decoded.push(if mode.plus_is_space && bytes[index] == b'+' {
                b' '
            } else {
                bytes[index]
            });
            spans.push((index, index + 1));
            index += 1;
        }
    }

    (decoded, spans)
}

/// Whether `text` can be a vault name, item title or field label in a new
/// item's `op://vault/title/field` reference
///
/// ASCII letters, digits, space, `-`, `_` and `.` only, the characters a
/// secret reference allows. No Unicode lookalike, invisible or combining
/// character can pass for another name, the duplicate check is exact, and
/// `?` (starts an attribute query), `$` (variable substitution), `/` (the
/// separator), quotes and `\` cannot make a reference that reads another
/// item. A leading `-` (read as an `op` option) and leading or trailing
/// space are refused too. Owners can rename an item in 1Password afterwards
pub fn is_item_name(text: &str) -> bool {
    !text.is_empty()
        && text.chars().count() <= MAX_ITEM_NAME_CHARS
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || " -_.".contains(character))
        && !text.starts_with(['-', ' '])
        && !text.ends_with(' ')
}

/// Why `item` cannot be created, if it cannot: the vault, title, field label
/// and category must pass their checks and the value must not be empty
pub fn check_new_item(item: &NewItem) -> Result<(), String> {
    let name_rule = |what: &str| {
        format!(
            "the {what} must be 1 to {MAX_ITEM_NAME_CHARS} ASCII letters, digits, spaces, `-`, `_` \
             or `.`, with no leading `-` and no leading or trailing space"
        )
    };

    if !is_item_name(&item.vault) {
        return Err(name_rule("vault name"));
    }
    if !is_item_name(&item.title) {
        return Err(name_rule("title"));
    }
    if !is_item_name(item.field()) {
        return Err(name_rule("field label"));
    }
    if !is_category(item.category()) {
        return Err("the category must be upper-case letters and `_`, like API_CREDENTIAL".into());
    }
    if item.value.is_empty() {
        return Err("the value is empty".into());
    }
    if serde_json::to_string(&item.value).map_or(usize::MAX, |escaped| escaped.len())
        > MAX_ITEM_VALUE_JSON_BYTES
    {
        return Err(format!(
            "the value is too long; it must stay under {} KiB",
            MAX_ITEM_VALUE_JSON_BYTES / 1024
        ));
    }

    Ok(())
}

/// Whether `text` names a 1Password category such as `API_CREDENTIAL`
pub fn is_category(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_ITEM_NAME_CHARS
        && text
            .chars()
            .all(|character| character.is_ascii_uppercase() || character == '_')
}

/// Checks a configured value's references without reading them
pub fn check(value: &str) -> Result<(), SecretError> {
    pieces(value).map(|_| ())
}

/// The references in a configured value, in order
pub fn references(value: &str) -> Result<Vec<&str>, SecretError> {
    Ok(pieces(value)?
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Reference(reference) => Some(reference),
            Piece::Text(_) => None,
        })
        .collect())
}

/// `value` with each `{{ op://… }}` replaced by what `lookup` gives for the
/// reference; `None` from `lookup` is a [`SecretError::Read`]
pub fn fill<'a>(
    value: &str,
    lookup: impl Fn(&str) -> Option<&'a str>,
) -> Result<String, SecretError> {
    let mut text = String::with_capacity(value.len());
    for piece in pieces(value)? {
        match piece {
            Piece::Text(literal) => text.push_str(literal),
            Piece::Reference(reference) => {
                let found = lookup(reference).ok_or_else(|| SecretError::Read {
                    reference: reference.to_owned(),
                    reason: "no value was read for it".to_owned(),
                })?;
                text.push_str(found);
            }
        }
    }

    Ok(text)
}

/// A server `url` with its references replaced
pub struct ResolvedUrl {
    /// The URL to connect to; never to be logged or stored
    pub url: String,
    /// What the redactor learns: the keys in the encodings text prints them in
    pub secrets: Vec<String>,
    /// The values read from 1Password, with their encodings: what nothing an
    /// authorization server returns may hold when it is stored or shown
    pub keys: Vec<String>,
    /// The keys whose fragments the redactor also replaces, since a client
    /// may print only part of a key when it cuts a response short
    pub fragile: Vec<String>,
}

/// A server `url` template with its references checked for where they sit
///
/// Each reference is replaced by a unique alphanumeric placeholder and the
/// result is parsed as a URL, so the component a reference lands in is
/// known exactly. Values are filled into the parsed URL already encoded as
/// data, so a value can never become URL structure
pub struct UrlTemplate<'a> {
    pieces: Vec<Piece<'a>>,
    /// The template parsed with `tag`-based placeholders in the references'
    /// places
    parsed: reqwest::Url,
    tag: String,
}

impl<'a> UrlTemplate<'a> {
    /// Checks `template` without reading anything: the references must
    /// close, and the template must be an `http(s)` URL with a literal host
    /// that holds references only in path segments and query names or
    /// values; a template that is one reference is refused
    pub fn parse(template: &'a str) -> Result<Self, SecretError> {
        let template = template.trim();
        let pieces = pieces(template)?;
        if matches!(pieces.as_slice(), [Piece::Reference(_)]) {
            return Err(SecretError::UrlReferenceWhole);
        }

        // lowercase, since a host is lowercased when parsed
        let lowered = template.to_ascii_lowercase();
        let mut tag = String::from("cmref");
        while lowered.contains(&tag) {
            tag.push('x');
        }
        let mut with_placeholders = String::with_capacity(template.len());
        let mut count = 0;
        for piece in &pieces {
            match piece {
                Piece::Text(literal) => with_placeholders.push_str(literal),
                Piece::Reference(_) => {
                    with_placeholders.push_str(&placeholder(&tag, count));
                    count += 1;
                }
            }
        }
        let parsed = reqwest::Url::parse(&with_placeholders).map_err(|_| SecretError::NotAUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none_or(str::is_empty)
        {
            return Err(SecretError::NotAUrl);
        }

        let outside = [
            Some(parsed.scheme()),
            Some(parsed.username()),
            parsed.password(),
            parsed.host_str(),
            parsed.fragment(),
        ];
        let inside = [Some(parsed.path()), parsed.query()];
        let found: usize = inside
            .into_iter()
            .flatten()
            .map(|text| text.matches(tag.as_str()).count())
            .sum();
        // a reference the parser dropped (`/{{ ref }}/..`) is also misplaced
        if outside
            .into_iter()
            .flatten()
            .any(|text| text.contains(&tag))
            || found != count
        {
            return Err(SecretError::UrlReferenceMisplaced);
        }

        Ok(Self {
            pieces,
            parsed,
            tag,
        })
    }

    /// The template's references, in order
    pub fn references(&self) -> impl Iterator<Item = &'a str> {
        self.pieces.iter().filter_map(|piece| match piece {
            Piece::Reference(reference) => Some(*reference),
            Piece::Text(_) => None,
        })
    }

    /// The URL with `values`, one per reference in order, filled in
    pub fn fill(&self, values: &[String]) -> Result<ResolvedUrl, SecretError> {
        if values
            .iter()
            .any(|value| value.len() < MIN_FRAGMENT_KEY_LEN)
        {
            return Err(SecretError::UrlValueTooShort);
        }
        // only characters that no URL parser, escape or logger rewrites
        // leave nothing for IDNA, `+`-as-space, percent-decoding, backslash
        // normalization or JSON escaping to turn into an unmatched form
        if values
            .iter()
            .any(|value| !value.bytes().all(is_embeddable_byte))
        {
            return Err(SecretError::UrlValueUnprotectable);
        }

        let Self { parsed, tag, .. } = self;
        let mut url = parsed.clone();
        let path = fill_placeholders(parsed.path(), tag, |index| path_encoded(&values[index]));
        url.set_path(&path);
        if let Some(query) = parsed.query() {
            let query = fill_placeholders(query, tag, |index| query_encoded(&values[index]));
            url.set_query(Some(&query));
        }
        let keys: Vec<String> = values
            .iter()
            .flat_map(|value| embedded_keys(value))
            .collect();

        Ok(ResolvedUrl {
            url: url.into(),
            secrets: keys.clone(),
            fragile: keys.clone(),
            keys,
        })
    }
}

/// Whether `value` is an `http(s)` URL, which a key never is
fn is_whole_url(value: &str) -> bool {
    let value = value.trim_start().to_ascii_lowercase();

    value.starts_with("https://") || value.starts_with("http://")
}

/// Whether an embedded url value may hold `byte`: ASCII letters, digits and
/// `- . _ ~ + / = : @ ! * , ;`, which covers hex, base64, base64url, JWT-like
/// and colon-separated keys
fn is_embeddable_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~+/=:@!*,;".contains(&byte)
}

/// The text standing in for the `index`th reference of a template; it ends
/// in `e` so that no index is the prefix of another
fn placeholder(tag: &str, index: usize) -> String {
    format!("{tag}{index}e")
}

/// `text` with each placeholder replaced by what `value` returns for its
/// index
fn fill_placeholders(text: &str, tag: &str, value: impl Fn(usize) -> String) -> String {
    let mut filled = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(tag) {
        let literal = &rest[..start];
        // a trailing incomplete escape would swallow the first characters of
        // the value, so its `%` is escaped
        let open = literal.rfind('%').filter(|at| {
            literal[at + 1..].len() <= 1 && literal[at + 1..].bytes().all(|b| b.is_ascii_hexdigit())
        });
        match open {
            Some(at) => {
                filled.push_str(&literal[..at]);
                filled.push_str("%25");
                filled.push_str(&literal[at + 1..]);
            }
            None => filled.push_str(literal),
        }
        let after = &rest[start + tag.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        // `parse` already checked that each placeholder is whole
        let index = after[..digits].parse().unwrap_or(0);
        filled.push_str(&value(index));
        rest = &after[(digits + 1).min(after.len())..];
    }
    filled.push_str(rest);

    filled
}

/// `value` as one path segment of a URL
fn path_encoded(value: &str) -> String {
    let Ok(mut scratch) = reqwest::Url::parse("http://scratch/") else {
        return String::new();
    };
    if let Ok(mut segments) = scratch.path_segments_mut() {
        segments.push(value);
    }

    scratch.path().trim_start_matches('/').to_owned()
}

/// `value` as a query name or value, form encoded
fn query_encoded(value: &str) -> String {
    let Ok(mut scratch) = reqwest::Url::parse("http://scratch/") else {
        return String::new();
    };
    scratch.query_pairs_mut().append_pair("", value);

    scratch
        .query()
        .and_then(|query| query.strip_prefix('='))
        .unwrap_or_default()
        .to_owned()
}

/// `text` with the hex digits of its `%XX` escapes in lowercase
fn lower_hex(text: &str) -> String {
    let mut lowered = text.to_owned();
    let mut start = 0;
    while let Some(offset) = lowered[start..].find('%') {
        let at = start + offset;
        if let Some(escape) = lowered.get(at + 1..at + 3) {
            let lower = escape.to_ascii_lowercase();
            lowered.replace_range(at + 1..at + 3, &lower);
        }
        start = at + 1;
    }

    lowered
}

/// An allowed-character value read for an embedded `url` reference as text may
/// print it: as read and in the encodings the URL holds it in, each escaped
/// the ways `variants` knows
fn embedded_keys(value: &str) -> Vec<String> {
    let mut keys = variants(value);
    keys.extend(
        [path_encoded(value), query_encoded(value)]
            .into_iter()
            .flat_map(|form| [lower_hex(&form), form]),
    );
    // a decoder may turn `+` into a space, and `%20` then shows the same text
    let spaced: Vec<String> = keys
        .iter()
        .filter(|key| key.contains('+'))
        .map(|key| key.replace('+', " "))
        .filter(|key| !key.trim().is_empty())
        .collect();
    keys.extend(spaced);
    keys.retain(|key| !key.is_empty());
    keys.sort();
    keys.dedup();

    keys
}

/// Values with their references replaced, and the secrets that were read
pub struct Resolved {
    /// Same keys as the configured map
    pub values: BTreeMap<String, String>,
    /// Every value read from 1Password, for the redactor
    pub secrets: Vec<String>,
}

/// Reads `op://` references through the 1Password CLI, which decides how
/// to sign in: the desktop app integration (the Mac prompts) or a service
/// account token in the daemon's environment (nothing prompts)
///
/// Clones share one cache: each reference is read once per process, and
/// reads run one at a time, so servers that connect together or reconnect
/// later never put a second prompt on the Mac for the same reference
///
/// With companions, a read also asks them; see [`OnePassword::with_companions`]
#[derive(Clone)]
pub struct OnePassword {
    program: String,
    known: Arc<Mutex<HashMap<String, String>>>,
    /// Values a program read with a keep window, by destination and
    /// reference, until it ends; never handed to the next daemon
    kept: Arc<Mutex<KeptValues>>,
    /// Which servers each config reference was approved for; any other
    /// server asks first, cached value or not
    approved: Arc<Approved>,
    companions: Option<Arc<Companions>>,
    on_mac: Option<OnMac>,
    /// Finds waiting to share one prompt with others from the same script
    finds: Arc<FindBatches>,
}

/// The keep grants, and how many times they were forgotten, so a read
/// approved before a forget cannot keep its values after it
#[derive(Default)]
struct KeptValues {
    grants: HashMap<(Option<String>, String), Kept>,
    forgotten: u64,
}

/// A value a program may get again without asking until both clocks pass
/// its end: `Instant` stops while the Mac sleeps, the wall clock can be set
struct Kept {
    value: ProgramValue,
    until: std::time::Instant,
    until_wall: std::time::SystemTime,
}

impl Kept {
    fn live(&self) -> bool {
        std::time::Instant::now() < self.until && std::time::SystemTime::now() < self.until_wall
    }
}

impl std::fmt::Debug for OnePassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OnePassword")
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

impl OnePassword {
    /// Uses `program` as the `op` executable
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            known: Arc::default(),
            kept: Arc::default(),
            approved: Arc::new(Approved::ungated()),
            companions: None,
            on_mac: None,
            finds: Arc::default(),
        }
    }

    /// Also asks `companions` for every read, and reads locally only while
    /// the owner is at this Mac (always when `on_mac` is `None`)
    ///
    /// The first answer wins and the others are dropped; the local `op`
    /// child dies with its future. Skipping the local read while the owner
    /// is away keeps a 1Password prompt from waiting on an unattended screen
    #[must_use]
    pub fn with_companions(mut self, companions: Arc<Companions>, on_mac: Option<OnMac>) -> Self {
        companions.share_cache(Arc::clone(&self.known));
        self.companions = Some(companions);
        self.on_mac = on_mac;

        self
    }

    /// Gives a cached or read value to a server only while `approved`
    /// approves it for that server as it stands, asking first otherwise
    #[must_use]
    pub fn with_approved(mut self, approved: Arc<Approved>) -> Self {
        self.approved = approved;

        self
    }

    /// Seals every value this process read for its config for the next
    /// daemon on `state_dir` (see [`handoff`]); how many
    pub async fn hand_off(
        &self,
        state_dir: &Path,
        store: &key_store::KeyStore,
    ) -> Result<usize, String> {
        let known = self.known.lock().await;

        handoff::hand_off(state_dir, store, &known)
    }

    /// Fills the cache from the last daemon's handoff, so its values are not
    /// asked for again; how many it held. Each still goes only to a server
    /// approved for it (see [`approved`])
    pub async fn take_over(
        &self,
        state_dir: &Path,
        store: &key_store::KeyStore,
    ) -> Result<usize, String> {
        let values = handoff::take_over(state_dir, store)?;
        let count = values.len();
        self.known.lock().await.extend(values);

        Ok(count)
    }

    /// Forgets every value read, and every value kept for programs, so the
    /// next read of each asks again, as after a rotated key; how many config
    /// values were held
    pub async fn forget(&self) -> usize {
        {
            let mut kept = self.kept.lock().await;
            kept.grants.clear();
            kept.forgotten += 1;
        }
        let mut known = self.known.lock().await;
        let count = known.len();
        known.clear();

        count
    }

    /// The companions and phones this reader asks, when it has any
    pub fn companions(&self) -> Option<&Arc<Companions>> {
        self.companions.as_ref()
    }

    /// The finds still gathering others before they are asked
    pub(crate) fn find_batches(&self) -> &FindBatches {
        &self.finds
    }

    /// The values kept for `references` going to `destination`, when every
    /// one of them is still within a window approved for that destination
    pub(crate) async fn kept_values(
        &self,
        destination: Option<&str>,
        references: &[String],
    ) -> Option<Vec<ProgramValue>> {
        let mut kept = self.kept.lock().await;
        kept.grants.retain(|_, entry| entry.live());
        let destination = destination.map(str::to_owned);

        references
            .iter()
            .map(|reference| {
                kept.grants
                    .get(&(destination.clone(), reference.clone()))
                    .map(|entry| entry.value.clone())
            })
            .collect()
    }

    /// How many times the grants were forgotten; pass it to [`Self::keep`]
    pub(crate) async fn forgotten(&self) -> u64 {
        self.kept.lock().await.forgotten
    }

    /// Keeps `values`, one per reference, for programs sending them to the
    /// same `destination` to get again without asking until `keep` has
    /// passed; nothing is kept when the grants were forgotten since
    /// `forgotten` was read, as the owner asked while this read waited
    pub(crate) async fn keep(
        &self,
        destination: Option<&str>,
        references: &[String],
        values: &[ProgramValue],
        keep: Duration,
        forgotten: u64,
    ) {
        let until = std::time::Instant::now() + keep;
        let until_wall = std::time::SystemTime::now() + keep;
        let mut kept = self.kept.lock().await;
        if kept.forgotten != forgotten {
            return;
        }
        for (reference, value) in references.iter().zip(values) {
            kept.grants.insert(
                (destination.map(str::to_owned), reference.clone()),
                Kept {
                    value: value.clone(),
                    until,
                    until_wall,
                },
            );
        }
    }

    /// Where the owner's presence is read and Touch ID asked, when this
    /// reader was set up with one
    pub fn on_mac(&self) -> Option<&OnMac> {
        self.on_mac.as_ref()
    }

    /// `values` with every reference replaced by what 1Password holds, for
    /// the server `consumer`; a map without references is returned as is,
    /// without running `op`
    pub async fn resolve(
        &self,
        consumer: Option<&Consumer>,
        values: &BTreeMap<String, String>,
    ) -> Result<Resolved, SecretError> {
        let mut resolved = Resolved {
            values: BTreeMap::new(),
            secrets: Vec::new(),
        };

        for (key, value) in values {
            let text = self
                .resolve_text(consumer, value, &mut resolved.secrets)
                .await?;
            resolved.values.insert(key.clone(), text);
        }

        Ok(resolved)
    }

    /// An HTTP server's `url` with its references read
    ///
    /// The template is checked before anything is read, so a reference in
    /// the wrong place never raises a prompt. Each value is filled into its
    /// path segment or query name or value as data: `/`, `\`, `?`, `#` and
    /// `%` in it are percent-encoded. A value shorter than the redactor can
    /// match is refused
    ///
    /// The keys are exactly the values read, in the encodings the URL and
    /// clients print them
    pub async fn resolve_url(
        &self,
        consumer: Option<&Consumer>,
        template: &str,
    ) -> Result<ResolvedUrl, SecretError> {
        let template = UrlTemplate::parse(template)?;
        let mut values = Vec::new();
        for reference in template.references() {
            let value = self.value(consumer, reference).await?;
            if is_whole_url(&value) {
                self.forget_value(reference).await;

                return Err(SecretError::UrlValueIsUrl(reference.to_owned()));
            }
            values.push(value);
        }

        template.fill(&values)
    }

    /// Drops what was read for `reference`, here and on the phones, so the
    /// next read asks again instead of replaying a wrong value
    async fn forget_value(&self, reference: &str) {
        self.known.lock().await.remove(reference);
        if let Some(companions) = &self.companions {
            companions.unseal_for_phones(reference);
        }
    }

    async fn resolve_text(
        &self,
        consumer: Option<&Consumer>,
        value: &str,
        secrets: &mut Vec<String>,
    ) -> Result<String, SecretError> {
        let mut text = String::with_capacity(value.len());
        for piece in pieces(value)? {
            match piece {
                Piece::Text(literal) => text.push_str(literal),
                Piece::Reference(reference) => {
                    let secret = self.value(consumer, reference).await?;
                    text.push_str(&secret);
                    secrets.push(secret);
                }
            }
        }

        Ok(text)
    }

    /// What 1Password holds for one `op://` reference, through the cache
    /// and every source a configured value would use
    pub async fn read_reference(&self, reference: &str) -> Result<String, SecretError> {
        self.value(None, reference).await
    }

    /// The value of `reference` for the server `consumer`, from the cache
    /// while the server is approved for it, otherwise read again from a
    /// source that asks the owner, which approves it from then on
    async fn value(
        &self,
        consumer: Option<&Consumer>,
        reference: &str,
    ) -> Result<String, SecretError> {
        // held across the read on purpose: a second caller waits for the
        // first prompt's answer instead of raising its own
        let mut known = self.known.lock().await;
        let ask = consumer.filter(|consumer| !self.approved.allows(consumer, reference));
        if ask.is_none()
            && let Some(value) = known.get(reference)
        {
            return Ok(value.clone());
        }
        let value = self.read(reference, ask).await?;
        known.insert(reference.to_owned(), value.clone());
        // every source asked the owner, naming the server here, unless
        // there is no Mac to ask on, where `op` answered as it would
        // anyone: that read is not taken as an approval
        if let Some(consumer) = ask
            && self.on_mac.is_some()
        {
            self.approved.approve(consumer, reference);
        }

        Ok(value)
    }

    /// Reads `reference` from every source; with `ask`, a server not yet
    /// approved for it, this Mac's `op` runs only after a Touch ID prompt
    /// naming the server, since 1Password may answer unprompted for minutes
    /// after any earlier approval, while phones and companion Macs ask always
    async fn read(&self, reference: &str, ask: Option<&Consumer>) -> Result<String, SecretError> {
        let value = self.race(reference, ask).await?;
        // whichever source won, its value replaces the phones' copies: a
        // value the owner entered on a phone is opened with Face ID next time
        if let Some(companions) = &self.companions {
            companions.seal_for_phones(reference, &value).await;
        }

        Ok(value)
    }

    /// Reads `reference` from every source at once; the first value wins
    async fn race(&self, reference: &str, ask: Option<&Consumer>) -> Result<String, SecretError> {
        let ask = ask.map(|consumer| consumer.name.clone());
        let peers = self
            .companions
            .as_ref()
            .map(|companions| companions.peers())
            .unwrap_or_default();
        // a phone opens its sealed copy, or the owner enters the value there
        let phones: Vec<String> = self
            .companions
            .as_ref()
            .map(|companions| {
                companions
                    .phones()
                    .into_iter()
                    .map(|phone| phone.name)
                    .collect()
            })
            .unwrap_or_default();
        let Some(companions) = self
            .companions
            .as_ref()
            .filter(|_| !peers.is_empty() || !phones.is_empty())
        else {
            return self.read_on_this_mac(reference, ask).await;
        };

        let local = match &self.on_mac {
            Some(on_mac) => on_mac.mac.present(on_mac.config.idle()).await,
            None => true,
        };
        let mut sources: JoinSet<(String, Result<String, String>)> = JoinSet::new();
        if local {
            let onepassword = self.clone();
            let reference = reference.to_owned();
            sources.spawn(async move {
                let value = onepassword
                    .read_on_this_mac(&reference, ask)
                    .await
                    .map_err(|error| error.reason());

                ("local".to_owned(), value)
            });
        }
        for peer in peers {
            let companions = Arc::clone(companions);
            let name = peer.name.clone();
            let reference = reference.to_owned();
            sources.spawn(async move {
                let value = companions
                    .read(&name, &reference)
                    .await
                    .map_err(|error| error.to_string());

                (name, value)
            });
        }
        let grace = if local { PHONE_GRACE } else { Duration::ZERO };
        for name in phones {
            let companions = Arc::clone(companions);
            let reference = reference.to_owned();
            sources.spawn(async move {
                tokio::time::sleep(grace).await;
                // the race gives up READ_TIMEOUT after it began, grace included
                let value = companions
                    .read_phone(&name, &reference, READ_TIMEOUT.saturating_sub(grace))
                    .await
                    .map_err(|error| error.to_string());

                (name, value)
            });
        }

        // dropping the set on any exit aborts what is still running, which
        // kills the local `op` child, hangs up on the companions and stops
        // the phones' streams
        let first_success = async {
            // named, so a failure with the owner away says why `op` never ran
            let mut failures = Vec::new();
            if !local {
                failures.push("local: skipped, the owner is away from this Mac".to_owned());
            }
            while let Some(finished) = sources.join_next().await {
                match finished {
                    Ok((_, Ok(value))) => return Ok(value),
                    Ok((source, Err(reason))) => failures.push(format!("{source}: {reason}")),
                    Err(error) => failures.push(format!("a read stopped unexpectedly: {error}")),
                }
            }

            Err(failures)
        };

        match tokio::time::timeout(READ_TIMEOUT, first_success).await {
            Ok(Ok(won)) => Ok(won),
            Ok(Err(failures)) if failures.is_empty() => Err(SecretError::Read {
                reference: reference.to_owned(),
                reason: "no source could read it".to_owned(),
            }),
            Ok(Err(failures)) => Err(SecretError::Read {
                reference: reference.to_owned(),
                reason: failures.join("; "),
            }),
            Err(_) => Err(SecretError::TimedOut {
                reference: reference.to_owned(),
                timeout: READ_TIMEOUT,
            }),
        }
    }

    /// Reads `reference` with this Mac's `op`, after a Touch ID prompt when
    /// it goes to the server `ask`, which is not approved for it yet
    async fn read_on_this_mac(
        &self,
        reference: &str,
        ask: Option<String>,
    ) -> Result<String, SecretError> {
        // without a Mac to ask on there is no prompt of codemode's own,
        // as for every config read there
        if let (Some(server), Some(on_mac)) = (ask, &self.on_mac) {
            let text = crate::prompt::one_line(
                &format!(
                    "Give {reference} to the server “{server}”, new or changed since it was last \
                     approved"
                ),
                usize::MAX,
            );
            let refused = |reason: &str| SecretError::Read {
                reference: reference.to_owned(),
                reason: format!("this Mac: {reason}"),
            };
            // a prompt nobody answers gives up with the read
            let answer = tokio::time::timeout(READ_TIMEOUT, on_mac.mac.touch_id(&text, "Deny"))
                .await
                .unwrap_or(TouchId::Away);
            match answer {
                TouchId::Approved => {}
                TouchId::Review => return Err(refused("not approved")),
                TouchId::Away => return Err(refused("the prompt was taken down")),
                TouchId::Unavailable => return Err(refused("Touch ID is unavailable")),
            }
        }

        self.read_local_text(reference).await
    }

    /// [`Self::read_local`] for a value that must be text, such as one going
    /// into a server's config
    pub async fn read_local_text(&self, reference: &str) -> Result<String, SecretError> {
        let bytes = self.read_local(reference).await?;

        String::from_utf8(bytes).map_err(|_| SecretError::Read {
            reference: reference.to_owned(),
            reason: NOT_TEXT.to_owned(),
        })
    }

    /// Runs `op read` on this Mac, with no cache and no companions; the bytes
    /// as 1Password holds them, which may be a file such as a `.p12`
    ///
    /// The companion side answers with this: every request asks anew
    pub async fn read_local(&self, reference: &str) -> Result<Vec<u8>, SecretError> {
        let args = ["read", "--no-newline", reference];
        let output = tokio::time::timeout(READ_TIMEOUT, spawn::output(&self.program, &args, None))
            .await
            .map_err(|_| SecretError::TimedOut {
                reference: reference.to_owned(),
                timeout: READ_TIMEOUT,
            })?
            .map_err(|error| SecretError::Spawn {
                program: self.program.clone(),
                source: error.into_io(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let reason = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("no error output")
                .trim()
                .to_owned();

            return Err(SecretError::Read {
                reference: reference.to_owned(),
                reason: format!("{reason} ({})", output.status),
            });
        }

        Ok(output.stdout)
    }

    /// Creates one item on this Mac, with no cache and no companions, unless
    /// the vault already holds an item with that title, archived or not
    ///
    /// The value reaches `op` on stdin as a JSON item template, never in its
    /// arguments, environment or a file. Only `id` is read from what `op`
    /// prints on success; on failure only one redacted line of its error
    /// output is kept
    pub async fn create_local(&self, item: &NewItem) -> Result<CreatedItem, CreateError> {
        let list = self
            .run(
                "item list",
                &[
                    "item",
                    "list",
                    "--vault",
                    &item.vault,
                    "--include-archive",
                    "--format",
                    "json",
                ],
                None,
                &item.value,
            )
            .await?;
        let listed: Vec<serde_json::Value> =
            serde_json::from_slice(&list).map_err(|_| CreateError::Failed {
                command: "item list",
                reason: "the answer was not a JSON list".to_owned(),
            })?;
        let taken = listed.iter().any(|existing| {
            existing["title"]
                .as_str()
                .is_some_and(|title| title.trim().eq_ignore_ascii_case(&item.title))
        });
        if taken {
            return Err(CreateError::Exists {
                vault: item.vault.clone(),
                title: item.title.clone(),
            });
        }

        let template = serde_json::json!({
            "title": item.title,
            "category": item.category(),
            "fields": [{
                "id": item.field(),
                "label": item.field(),
                "type": "CONCEALED",
                "value": item.value,
            }],
        });
        let template = serde_json::to_vec(&template).map_err(|error| CreateError::Failed {
            command: "item create",
            reason: error.to_string(),
        })?;
        let created = self
            .run(
                "item create",
                &[
                    "item",
                    "create",
                    "--vault",
                    &item.vault,
                    "--format",
                    "json",
                    "-",
                ],
                Some(&template),
                &item.value,
            )
            .await
            // once `op` has the template, running out of time or losing its
            // answer says nothing about whether it went on to write the item
            .map_err(|error| match error {
                CreateError::TimedOut { .. } | CreateError::Lost { .. } => {
                    CreateError::Unconfirmed {
                        reason: error.to_string(),
                    }
                }
                other => other,
            })?;
        let id = serde_json::from_slice::<serde_json::Value>(&created)
            .ok()
            .and_then(|answer| answer["id"].as_str().map(str::to_owned))
            .ok_or_else(|| CreateError::Unconfirmed {
                reason: "`op item create` succeeded but its answer had no item id".to_owned(),
            })?;

        Ok(CreatedItem {
            id,
            reference: format!("op://{}/{}/{}", item.vault, item.title, item.field()),
        })
    }

    /// Runs `op` and returns its stdout; failures carry one bounded line of
    /// `op`'s error output with `value` and its JSON-escaped form replaced,
    /// never its stdout
    async fn run(
        &self,
        command: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
        value: &str,
    ) -> Result<Vec<u8>, CreateError> {
        let output = tokio::time::timeout(READ_TIMEOUT, spawn::output(&self.program, args, stdin))
            .await
            .map_err(|_| CreateError::TimedOut {
                command,
                timeout: READ_TIMEOUT,
            })?
            .map_err(|error| match error {
                spawn::RunError::Start(source) => CreateError::Spawn {
                    program: self.program.clone(),
                    source,
                },
                spawn::RunError::Collect(source) => CreateError::Lost {
                    command,
                    reason: source.to_string(),
                },
            })?;

        // a signal can stop `op` after it has done its work but before it
        // has said so
        if output.status.code().is_none() {
            return Err(CreateError::Lost {
                command,
                reason: format!("`op` was stopped ({})", output.status),
            });
        }
        if !output.status.success() {
            let escaped = serde_json::to_string(value).unwrap_or_default();
            let escaped = escaped.trim_matches('"');
            // a value that spans lines is redacted before the first line is
            // taken, and escaped form first because it may contain the raw one
            let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            if !value.is_empty() {
                stderr = stderr.replace(escaped, REDACTED).replace(value, REDACTED);
            }
            let line = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("no error output");
            let reason = crate::prompt::one_line(line.trim(), MAX_OP_ERROR_CHARS);

            return Err(CreateError::Failed {
                command,
                reason: format!("{reason} ({})", output.status),
            });
        }

        Ok(output.stdout)
    }
}

/// Why `op` did not create an item; no message holds the value
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The title is already used in the vault, so nothing was written
    #[error("an item titled \"{title}\" already exists in {vault}")]
    Exists {
        /// Vault searched
        vault: String,
        /// Title that is taken
        title: String,
    },
    /// `op` did not start
    #[error("cannot run {program}: {source}")]
    Spawn {
        /// Program that failed to start
        program: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// `op` did not answer in time, e.g. a prompt nobody answered
    #[error("`op {command}` took longer than {timeout:?}")]
    TimedOut {
        /// What was being run
        command: &'static str,
        /// Timeout that elapsed
        timeout: Duration,
    },
    /// `op` started, but stopped on a signal or its answer was lost
    #[error("`op {command}` gave no answer: {reason}")]
    Lost {
        /// What was being run
        command: &'static str,
        /// What happened to the answer
        reason: String,
    },
    /// `op item create` may have written the item but did not confirm it
    #[error("{reason}")]
    Unconfirmed {
        /// What went wrong after `op` had the item
        reason: String,
    },
    /// `op` failed or answered something unexpected
    #[error("`op {command}` failed: {reason}")]
    Failed {
        /// What was being run
        command: &'static str,
        /// First line of `op`'s error output, or what was wrong with its
        /// answer
        reason: String,
    },
}

/// Replaces secrets in text that came from an upstream: configured header
/// and env values, URL query strings and userinfo, and values read from
/// 1Password (a `url` included) once a server has connected
#[derive(Default)]
pub struct Redactor(RwLock<Known>);

/// The shortest key whose fragments are also replaced
const MIN_FRAGMENT_KEY_LEN: usize = 16;

/// The length of the shortest fragment of a key that is replaced
const FRAGMENT_LEN: usize = 8;

/// What a [`Redactor`] replaces
#[derive(Default)]
struct Known {
    /// Whole secrets in lowercase, longest first
    secrets: Vec<String>,
    /// Every [`FRAGMENT_LEN`]-byte window of every long key, in lowercase
    windows: HashSet<[u8; FRAGMENT_LEN]>,
}

impl Known {
    /// The spans of `text`, already in lowercase, that hold a whole secret
    /// or a run of at least [`FRAGMENT_LEN`] bytes of a key
    fn spans(&self, text: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        for secret in &self.secrets {
            let needle = secret.as_bytes();
            for (start, window) in text.windows(needle.len()).enumerate() {
                if window == needle {
                    spans.push((start, start + needle.len()));
                }
            }
        }

        // consecutive windows that are all a key's join into the longest run
        let mut run: Option<(usize, usize)> = None;
        if !self.windows.is_empty() {
            for (start, window) in text.windows(FRAGMENT_LEN).enumerate() {
                let end = start + FRAGMENT_LEN;
                if !self.windows.contains(window) {
                    continue;
                }
                match &mut run {
                    Some((_, last)) if start <= *last => *last = end,
                    _ => {
                        spans.extend(run.take());
                        run = Some((start, end));
                    }
                }
            }
        }
        spans.extend(run);

        spans
    }
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .secrets
            .len();

        write!(formatter, "Redactor({count} secrets)")
    }
}

impl Redactor {
    /// The process's one redactor, which also scrubs the daemon's logs, since
    /// libraries print the URL they were connecting to; starts with the
    /// secrets written into `config`
    pub fn shared(config: &Config) -> Arc<Self> {
        let redactor = Arc::clone(Self::log());
        redactor.add(Self::configured(config));

        redactor
    }

    fn log() -> &'static Arc<Self> {
        static SHARED: OnceLock<Arc<Redactor>> = OnceLock::new();

        SHARED.get_or_init(Arc::default)
    }

    /// Starts with the secrets written into `config`
    pub fn new(config: &Config) -> Self {
        let redactor = Self::default();
        redactor.add(Self::configured(config));

        redactor
    }

    fn configured(config: &Config) -> Vec<String> {
        let mut secrets = Vec::new();
        for server in config.servers.values() {
            // a value with references holds no secret until it is resolved
            let literal = server
                .headers
                .values()
                .chain(server.env.values())
                .filter(|value| !value.contains("{{"));
            for value in literal {
                secrets.push(value.clone());
                if let Some(token) = value.strip_prefix("Bearer ") {
                    secrets.push(token.to_owned());
                }
            }
            // a url with references holds no secret until it is resolved
            if let Some(url) = server.url.as_deref().filter(|url| !url.contains("{{")) {
                if let Some((_, query)) = url.split_once('?') {
                    secrets.push(query.to_owned());
                }
                // `https://user:password@host/...`
                if let Some((userinfo, _)) = url
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split_once('@'))
                    .filter(|(userinfo, _)| !userinfo.contains('/'))
                {
                    secrets.push(userinfo.to_owned());
                }
            }
        }

        secrets
    }

    /// Redacts these too from now on
    pub fn add(&self, secrets: impl IntoIterator<Item = String>) {
        self.learn(secrets, false);
    }

    /// Redacts these too from now on, along with any run of
    /// [`FRAGMENT_LEN`] or more bytes of one that is at least
    /// [`MIN_FRAGMENT_KEY_LEN`] bytes long, since a client may print only the
    /// part of a key that survives cutting a response short
    ///
    /// Fragments are for the redactor only; the checks on what is stored
    /// ([`Redactor::holds_any`]) would refuse legitimate data on a fragment
    pub fn add_keys(&self, keys: impl IntoIterator<Item = String>) {
        self.learn(keys, true);
    }

    fn learn(&self, secrets: impl IntoIterator<Item = String>, fragments: bool) {
        let mut known = self.0.write().unwrap_or_else(PoisonError::into_inner);
        // kept in lowercase, since text is matched ignoring ASCII case
        let secrets = secrets
            .into_iter()
            .filter(|secret| secret.len() >= MIN_SECRET_LEN)
            .map(|secret| secret.to_ascii_lowercase());
        for secret in secrets {
            if fragments && secret.len() >= MIN_FRAGMENT_KEY_LEN {
                for window in secret.as_bytes().windows(FRAGMENT_LEN) {
                    if let Ok(window) = window.try_into() {
                        known.windows.insert(window);
                    }
                }
            }
            known.secrets.push(secret);
        }
        // longest first, so a secret that contains another is replaced whole;
        // ties sort by text so `dedup` sees every duplicate and reconnects
        // do not grow the list
        known
            .secrets
            .sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        known.secrets.dedup();
    }

    /// Whether `text` holds any of `keys`, ignoring ASCII case, as is or once
    /// its percent and JSON string escapes are decoded, however deeply nested
    ///
    /// A provider may change the case of what it echoes, e.g. by putting a
    /// key in a host name
    pub fn holds_any(text: &str, keys: &[String]) -> bool {
        let keys: Vec<String> = keys
            .iter()
            .filter(|key| key.len() >= MIN_SECRET_LEN)
            .map(|key| key.to_ascii_lowercase())
            .collect();
        let holds = |text: &[u8]| {
            let text = text.to_ascii_lowercase();

            keys.iter().any(|key| {
                text.windows(key.len())
                    .any(|window| window == key.as_bytes())
            })
        };

        holds(text.as_bytes())
            || (text.contains(['%', '+', '\\', '&'])
                && Unescape::VIEWS.into_iter().any(|mode| {
                    unescaped_layers(text, mode)
                        .iter()
                        .any(|(decoded, _)| holds(decoded))
                }))
    }

    /// `text` with every known secret replaced, ignoring ASCII case and
    /// however its percent or JSON string escapes are cased or mixed with
    /// plain characters
    pub fn scrub(&self, text: &str) -> String {
        let known = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut hits = known.spans(text.to_ascii_lowercase().as_bytes());

        // the view is built only for text that has an escape
        if text.contains(['%', '\\', '&']) {
            for mode in Unescape::VIEWS
                .into_iter()
                .filter(|mode| !mode.plus_is_space)
            {
                for (mut decoded, spans) in unescaped_layers(text, mode) {
                    // an escape can stand for an uppercase letter
                    decoded.make_ascii_lowercase();
                    hits.extend(
                        known
                            .spans(&decoded)
                            .into_iter()
                            .map(|(start, end)| (spans[start].0, spans[end - 1].1)),
                    );
                }
            }
        }
        hits.sort_unstable();

        let mut scrubbed = Vec::with_capacity(text.len());
        let mut copied = 0;
        for (start, end) in hits {
            if start < copied {
                // overlaps a span already replaced; extend it
                copied = copied.max(end);
                continue;
            }
            scrubbed.extend_from_slice(&text.as_bytes()[copied..start]);
            scrubbed.extend_from_slice(REDACTED.as_bytes());
            copied = end;
        }
        scrubbed.extend_from_slice(&text.as_bytes()[copied..]);

        String::from_utf8_lossy(&scrubbed).into_owned()
    }

    /// `text` with every known secret replaced, cut to a length fit for a
    /// script
    pub fn apply(&self, text: &str) -> String {
        let mut text = self.scrub(text);
        if text.len() > MAX_ERROR_TEXT {
            let mut end = MAX_ERROR_TEXT;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str("...[truncated]");
        }

        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_split_into_text_and_references() -> Result<(), SecretError> {
        assert_eq!(
            pieces("Bearer {{ op://Dev/Context7/credential }}")?,
            [
                Piece::Text("Bearer "),
                Piece::Reference("op://Dev/Context7/credential")
            ]
        );
        assert_eq!(
            pieces("{{op://Private/My Item/api/key}}-{{ op://a/b/c }}")?,
            [
                Piece::Reference("op://Private/My Item/api/key"),
                Piece::Text("-"),
                Piece::Reference("op://a/b/c"),
            ]
        );
        assert_eq!(pieces("plain")?, [Piece::Text("plain")]);

        Ok(())
    }

    #[test]
    fn malformed_references_are_refused() {
        assert!(matches!(check("{{ op://a/b/c"), Err(SecretError::Unclosed)));
        for value in [
            "{{ sk-live-123 }}",
            "{{ op://vault/item }}",
            "{{ op://a//c }}",
            "{{ op://a/b/c/d/e }}",
        ] {
            assert!(
                matches!(check(value), Err(SecretError::NotAReference)),
                "{value}"
            );
        }
    }

    #[test]
    fn lowercase_and_uppercase_percent_encoding_are_both_scrubbed() {
        let redactor = Redactor::default();
        redactor.add(variants("zk+9f3a71c2=d8b4e6"));

        for text in ["zk%2B9f3a71c2%3Dd8b4e6", "zk%2b9f3a71c2%3dd8b4e6"] {
            assert_eq!(redactor.scrub(text), REDACTED, "{text}");
        }
    }

    #[test]
    fn mixed_case_and_partly_encoded_secrets_are_scrubbed() {
        let redactor = Redactor::default();
        redactor.add(["zk+9f3a71c2=d8b4e6".to_owned()]);

        for text in [
            "key zk%2b9f3a71c2%3Dd8b4e6 end",
            "key zk%2B9f3a71c2=d8b4e6 end",
            "key %7ak%2B9f3a71c2%3d%64%38b4e6 end",
        ] {
            assert_eq!(redactor.scrub(text), "key [redacted] end", "{text}");
        }
    }

    #[test]
    fn json_escaped_keys_are_scrubbed_from_error_text_and_logs() {
        let redactor = Redactor::default();
        redactor.add([
            "zk/9f3a71c2d8b4e6".to_owned(),
            "a\"b\\c\td-secret".to_owned(),
        ]);

        for (text, expected) in [
            (
                r#"{"error":"bad key zk\/9f3a71c2d8b4e6"}"#,
                r#"{"error":"bad key [redacted]"}"#,
            ),
            (
                r#"{"error":"bad key zk\u002f9f3a71c2d8b4e6 x"}"#,
                r#"{"error":"bad key [redacted] x"}"#,
            ),
            (
                r#"k \u007A\u006b/9f3a71c2d8b4\u0065\u0036 k"#,
                "k [redacted] k",
            ),
            (
                r#"k zk\/9f3a71c2d8b4e6 and a\"b\\c\td-secret"#,
                "k [redacted] and [redacted]",
            ),
        ] {
            assert_eq!(redactor.scrub(text), expected, "{text}");
        }
    }

    #[test]
    fn a_key_holding_a_percent_escape_is_found_beside_json_escapes() {
        let redactor = Redactor::default();
        redactor.add(["ab%41\"cd-secret".to_owned()]);

        assert_eq!(redactor.scrub(r#"x ab%41\"cd-secret y"#), "x [redacted] y");
        assert!(Redactor::holds_any(
            r#"ab%41\"cd-secret"#,
            &["ab%41\"cd-secret".to_owned()]
        ));
    }

    #[test]
    fn json_surrogate_pairs_decode_to_one_character() {
        let redactor = Redactor::default();
        redactor.add(["key-\u{1F600}-value".to_owned()]);

        assert_eq!(
            redactor.scrub(r"x key-\uD83D\uDE00-value y"),
            "x [redacted] y"
        );
        // a lone surrogate stands for nothing
        assert_eq!(redactor.scrub(r"key-\uD83D-value"), r"key-\uD83D-value");
    }

    #[test]
    fn holds_any_sees_json_escaped_keys() {
        let keys = ["zk/9f3a71c2d8b4e6".to_owned()];

        assert!(Redactor::holds_any(r"https://h/zk\/9f3a71c2d8b4e6", &keys));
        assert!(Redactor::holds_any(r"zk\u002F9f3a71c2d8b4e6", &keys));
        assert!(!Redactor::holds_any(r"zk\q9f3a71c2d8b4e6", &keys));
    }

    fn filled(template: &str, values: &[&str]) -> Result<ResolvedUrl, SecretError> {
        let values: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();

        UrlTemplate::parse(template)?.fill(&values)
    }

    #[test]
    fn values_are_filled_into_url_components_as_data() -> Result<(), SecretError> {
        let resolved = filled(
            "https://h.example/mcp/{{ op://a/b/c }}/message/?k={{ op://a/b/c }}&{{ op://a/b/c }}=1",
            &[
                "a/b=c:d@e,f+hxxxxx",
                "a/b=c:d@e,f+hxxxxx",
                "a/b=c:d@e,f+hxxxxx",
            ],
        )?;
        let parsed = reqwest::Url::parse(&resolved.url).map_err(|_| SecretError::NotAUrl)?;

        assert_eq!(parsed.host_str(), Some("h.example"));
        assert_eq!(parsed.fragment(), None);
        assert_eq!(parsed.path(), "/mcp/a%2Fb=c:d@e,f+hxxxxx/message/");
        assert_eq!(
            parsed.query(),
            Some("k=a%2Fb%3Dc%3Ad%40e%2Cf%2Bhxxxxx&a%2Fb%3Dc%3Ad%40e%2Cf%2Bhxxxxx=1")
        );

        Ok(())
    }

    #[test]
    fn unprotectable_values_are_refused() {
        for value in [
            "has space1234567",
            "sëcret1234567890",
            "tenant\\SecretKey123456",
            "abc\"def\"ghi123456789",
            "key'quote1234567890",
            "a<b>c^{d}|e[f]1234567",
            "k`tick#hash?q%r&s$t(u)xx",
            "%41%42%43%44%45%46%47",
            "50%off-secret-value",
        ] {
            assert!(
                matches!(
                    filled("https://h.example/mcp/{{ op://a/b/c }}", &[value]),
                    Err(SecretError::UrlValueUnprotectable)
                ),
                "{value}"
            );
        }
        assert!(
            filled(
                "https://h.example/mcp/{{ op://a/b/c }}",
                &["acct:key~1234567890"]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_literal_percent_before_a_value_cannot_complete_an_escape() -> Result<(), SecretError> {
        let resolved = filled(
            "https://host/mcp/%{{ op://a/b/c }}",
            &["2Fsecret-1234567890"],
        )?;

        assert_eq!(resolved.url, "https://host/mcp/%252Fsecret-1234567890");

        Ok(())
    }

    #[test]
    fn references_outside_the_path_and_query_are_refused() {
        for template in [
            "https:///{{ op://a/b/c }}/mcp/{{ op://a/b/c }}",
            "https://{{ op://a/b/c }}.example/mcp",
            "https://user:{{ op://a/b/c }}@example/mcp",
            "https://example:{{ op://a/b/c }}/mcp",
            "https://example/mcp#{{ op://a/b/c }}",
            "{{ op://a/b/c }}://example/mcp",
            "https://example/{{ op://a/b/c }}/..",
        ] {
            assert!(UrlTemplate::parse(template).is_err(), "{template}");
        }
        assert!(UrlTemplate::parse("https://h.example?k={{ op://a/b/c }}").is_ok());
    }

    #[test]
    fn a_url_that_is_one_reference_is_refused() {
        for template in ["{{ op://a/b/c }}", "  {{ op://a/b/c }}  "] {
            assert!(
                matches!(
                    UrlTemplate::parse(template),
                    Err(SecretError::UrlReferenceWhole)
                ),
                "{template}"
            );
        }
    }

    #[test]
    fn a_key_in_a_debug_formatted_error_is_redacted_through_nested_escapes() {
        let redactor = Redactor::default();
        redactor.add(["aB7cD/Ef8gH/Jk9L".to_owned()]);

        // the body holds the key as `aB7cD\/Ef8gH\/Jk9L` once JSON and
        // `Debug` have each escaped it
        let body = r#"{"echo":"aB7cD\/Ef8gH\/Jk9L"}"#;
        let logged = format!("{body:?}");
        assert!(logged.contains(r"aB7cD\\/Ef8gH"), "{logged}");

        let scrubbed = redactor.scrub(&logged);
        assert!(!scrubbed.contains("Ef8gH"), "{scrubbed}");
        assert!(scrubbed.contains("[redacted]"), "{scrubbed}");
        assert!(Redactor::holds_any(
            &logged,
            &["aB7cD/Ef8gH/Jk9L".to_owned()]
        ));
    }

    #[test]
    fn a_secret_holding_a_literal_html_reference_is_redacted_through_json_escapes() {
        let redactor = Redactor::default();
        redactor.add(["abc&amp;def/ghi".to_owned()]);

        let scrubbed = redactor.scrub(r#"{"error":"bad token abc&amp;def\/ghi"}"#);
        assert!(!scrubbed.contains("def"), "{scrubbed}");
        assert!(scrubbed.contains("[redacted]"), "{scrubbed}");
    }

    #[test]
    fn a_key_in_an_html_error_body_is_redacted_through_character_references()
    -> Result<(), SecretError> {
        let resolved = filled(
            "https://h.example/mcp/{{ op://a/b/c }}",
            &["aB7cD+Ef8gH+Jk9L"],
        )?;
        let redactor = Redactor::default();
        redactor.add(resolved.secrets.clone());
        redactor.add_keys(resolved.fragile);

        for body in [
            "<p>bad key aB7cD&#43;Ef8gH&#43;Jk9L</p>",
            "<p>bad key aB7cD&#x2B;Ef8gH&#X2b;Jk9L</p>",
            "<p>bad key aB7cD&plus;Ef8gH&plus;Jk9L</p>",
        ] {
            let scrubbed = redactor.scrub(body);
            assert!(!scrubbed.contains("Ef8gH"), "{scrubbed}");
            assert!(scrubbed.contains("[redacted]"), "{scrubbed}");
            assert!(Redactor::holds_any(body, &resolved.keys), "{body}");
        }

        Ok(())
    }

    #[test]
    fn a_key_echoed_with_plus_as_space_is_redacted_and_refused() -> Result<(), SecretError> {
        let resolved = filled(
            "https://h.example/mcp/{{ op://a/b/c }}/message",
            &["ab+cDe/f12==xyzw"],
        )?;
        let redactor = Redactor::default();
        redactor.add(resolved.secrets.clone());
        redactor.add_keys(resolved.fragile);

        for echo in [
            "ab cDe/f12==xyzw",
            "ab%20cDe/f12==xyzw",
            "ab%20cDe%2Ff12%3D%3Dxyzw",
        ] {
            let scrubbed = redactor.scrub(echo);
            assert!(!scrubbed.contains("cDe"), "{scrubbed}");
            assert!(Redactor::holds_any(echo, &resolved.keys), "{echo}");
        }

        Ok(())
    }

    #[test]
    fn a_url_value_under_16_bytes_is_refused() {
        let refused = filled(
            "https://h.example/mcp/{{ op://a/b/c }}",
            &["9f3a71c2d8b4e6f"],
        );
        assert!(matches!(refused, Err(SecretError::UrlValueTooShort)));
        assert!(
            filled(
                "https://h.example/mcp/{{ op://a/b/c }}",
                &["9f3a71c2d8b4e6f0"]
            )
            .is_ok()
        );
    }

    #[test]
    fn matching_ignores_ascii_case() {
        let redactor = Redactor::default();
        redactor.add(["PrivateKey123".to_owned()]);

        assert_eq!(
            redactor.scrub("https://privatekey123.auth/x"),
            "https://[redacted].auth/x"
        );
        assert_eq!(redactor.scrub("a %70rivateKEY123 b"), "a [redacted] b");
        assert!(Redactor::holds_any(
            "https://privatekey123.auth",
            &["PrivateKey123".to_owned()]
        ));
    }
}
