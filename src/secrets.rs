//! `{{ op://vault/item/field }}` references in a server's `headers`, `env`
//! and `url`, read through the 1Password CLI when it first connects, and the
//! redactor that keeps secrets out of scripts' text and the logs
//!
//! The braces follow `op inject`'s template syntax, so a value can mix text
//! and references, e.g. `Bearer {{ op://Dev/Context7/credential }}`

mod logs;
mod spawn;

pub use logs::{RedactingMakeWriter, redacting_logs};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, OnceLock, PoisonError, RwLock},
    time::Duration,
};

use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    companion::Companions,
    config::{Config, SecretsConfig},
    mac::OnMac,
};

/// How long one `op read` may take; long enough for the 1Password app's
/// unlock or Touch ID prompt on the Mac
const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// How long `op whoami` may take; it answers without a prompt
const WHOAMI_TIMEOUT: Duration = Duration::from_secs(10);
/// What `op whoami` prints when the app has not authorized the CLI
const SIGNED_OUT: &str = "account is not signed in";
/// Longest upstream error text handed to a script
const MAX_ERROR_TEXT: usize = 2000;
/// Replacement for secrets found in upstream text
const REDACTED: &str = "[redacted]";
/// Shorter secrets would redact ordinary words
const MIN_SECRET_LEN: usize = 6;
/// Longest `op://` reference accepted
const MAX_REFERENCE_CHARS: usize = 256;

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
    /// registering with an invite is used without a restart
    pub fn new(
        config: &SecretsConfig,
        config_path: Option<PathBuf>,
        presence: Option<OnMac>,
    ) -> Self {
        let companions = Arc::new(Companions::new(config, config_path));
        let onepassword =
            OnePassword::new(config.op.clone()).with_companions(Arc::clone(&companions), presence);

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
    /// A reference in a `url` sits outside the path and the query
    #[error(
        "references in a `url` may appear only in path segments and query names or values, not in the scheme, credentials, host, port or fragment; e.g. url = \"https://host/mcp/{{{{ op://Vault/Item/key }}}}/message\""
    )]
    UrlReferenceMisplaced,
    /// A value read for a `url` is shorter than the redactor can match
    #[error(
        "a value read for the `url` is too short to be protected; use a key of at least {MIN_SECRET_LEN} bytes"
    )]
    UrlValueTooShort,
    /// A value read for an embedded `url` reference holds a character that
    /// URL parsing, escaping or a library's logging could change into a form
    /// the redactor does not know
    #[error(
        "a value read for the `url` may hold only ASCII letters, digits and - . _ ~ + / = : @ ! * , ; characters"
    )]
    UrlValueUnprotectable,
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

/// `text` with its `%XX` escapes decoded; `plus_is_space` also decodes the
/// `+` of form encoding
fn percent_decode(text: &str, plus_is_space: bool) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match escaped_byte(&bytes[index..]) {
            Some(byte) => {
                decoded.push(byte);
                index += 3;
            }
            None => {
                decoded.push(if plus_is_space && bytes[index] == b'+' {
                    b' '
                } else {
                    bytes[index]
                });
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
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
}

impl Unescape {
    /// Every combination worth matching text against
    const VIEWS: [Self; 4] = [
        Self {
            percent: true,
            json: false,
            plus_is_space: false,
        },
        Self {
            percent: true,
            json: false,
            plus_is_space: true,
        },
        Self {
            percent: false,
            json: true,
            plus_is_space: false,
        },
        Self {
            percent: true,
            json: true,
            plus_is_space: false,
        },
    ];
}

/// `text` with the escapes `mode` names decoded in one pass, and for each
/// decoded byte the span of `text` it came from; the bytes of a character an
/// escape stands for share its span
fn unescaped_with_spans(text: &str, mode: Unescape) -> (Vec<u8>, Vec<(usize, usize)>) {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut spans = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(byte) = escaped_byte(&bytes[index..]).filter(|_| mode.percent) {
            decoded.push(byte);
            spans.push((index, index + 3));
            index += 3;
        } else if let Some((character, width)) = json_escape(&bytes[index..]).filter(|_| mode.json)
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

/// A server `url` with its references replaced
pub struct ResolvedUrl {
    /// The URL to connect to; never to be logged or stored
    pub url: String,
    /// What the redactor learns: the keys and, when the whole URL was read
    /// from 1Password, the URL's normalized form, path and query
    pub secrets: Vec<String>,
    /// The values read from 1Password, with their encodings: what nothing an
    /// authorization server returns may hold when it is stored or shown
    pub keys: Vec<String>,
    /// The keys whose fragments the redactor also replaces, since a client
    /// may print only part of a key when it cuts a response short
    pub fragile: Vec<String>,
}

/// Where a `url` template's references sit
enum UrlShape {
    /// The template is one reference, so the value read is the whole URL
    Whole,
    /// References sit in path segments and query names or values; the URL
    /// is the template parsed with `tag`-based placeholders in their place
    Embedded { parsed: reqwest::Url, tag: String },
}

/// A server `url` template with its references checked for where they sit
///
/// Each reference is replaced by a unique alphanumeric placeholder and the
/// result is parsed as a URL, so the component a reference lands in is
/// known exactly. Values are filled into the parsed URL already encoded as
/// data, so a value can never become URL structure
pub struct UrlTemplate<'a> {
    pieces: Vec<Piece<'a>>,
    shape: UrlShape,
}

impl<'a> UrlTemplate<'a> {
    /// Checks `template` without reading anything: the references must
    /// close, and unless the template is one reference, it must be an
    /// `http(s)` URL with a literal host that holds references only in path
    /// segments and query names or values
    pub fn parse(template: &'a str) -> Result<Self, SecretError> {
        let template = template.trim();
        let pieces = pieces(template)?;
        if matches!(pieces.as_slice(), [Piece::Reference(_)]) {
            return Ok(Self {
                pieces,
                shape: UrlShape::Whole,
            });
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
            shape: UrlShape::Embedded { parsed, tag },
        })
    }

    /// Whether the template is one reference, whose value is the whole URL
    pub fn is_whole(&self) -> bool {
        matches!(self.shape, UrlShape::Whole)
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
        if values.iter().any(|value| value.len() < MIN_SECRET_LEN) {
            return Err(SecretError::UrlValueTooShort);
        }
        // only characters that no URL parser, escape or logger rewrites
        // leave nothing for IDNA, `+`-as-space, percent-decoding, backslash
        // normalization or JSON escaping to turn into an unmatched form
        if !matches!(self.shape, UrlShape::Whole)
            && values
                .iter()
                .any(|value| !value.bytes().all(is_embeddable_byte))
        {
            return Err(SecretError::UrlValueUnprotectable);
        }

        match &self.shape {
            UrlShape::Whole => {
                let [value] = values else {
                    return Err(SecretError::NotAUrl);
                };
                let url = reqwest::Url::parse(value.trim()).map_err(|_| SecretError::NotAUrl)?;
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none_or(str::is_empty)
                {
                    return Err(SecretError::NotAUrl);
                }

                // clients print the normalized form, the path and the query
                let mut secrets = url_keys(value);
                let path = url.path();
                let parts = [value.trim(), url.as_str(), path, path.trim_end_matches('/')]
                    .into_iter()
                    .chain(url.query());
                secrets.extend(parts.flat_map(variants));

                // servers echo the decoded path and query, and each query
                // value, which is where such a URL keeps its key
                let decoded_query = url.query().map(|query| percent_decode(query, false));
                let form_query = url.query().map(|query| percent_decode(query, true));
                let values: Vec<String> =
                    url.query_pairs().map(|(_, value)| value.into()).collect();
                let decoded = [
                    percent_decode(path, false),
                    percent_decode(path.trim_end_matches('/'), false),
                ]
                .into_iter()
                .chain(decoded_query)
                .chain(form_query)
                .chain(values.iter().cloned());
                secrets.extend(decoded.flat_map(|text| variants(&text)));
                let fragile = values.iter().flat_map(|value| url_keys(value)).collect();

                Ok(ResolvedUrl {
                    keys: url_keys(value),
                    secrets,
                    fragile,
                    url: url.into(),
                })
            }
            UrlShape::Embedded { parsed, tag } => {
                let mut url = parsed.clone();
                let path =
                    fill_placeholders(parsed.path(), tag, |index| path_encoded(&values[index]));
                url.set_path(&path);
                if let Some(query) = parsed.query() {
                    let query =
                        fill_placeholders(query, tag, |index| query_encoded(&values[index]));
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
    }
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

/// A value read for a `url` as text may print it: as read, with its escapes
/// decoded, with `+` as a space (form decoding), in the encodings the URL
/// holds it in, and each of those escaped the ways `variants` knows
fn url_keys(value: &str) -> Vec<String> {
    let decoded = percent_decode(value, false);
    let mut forms = vec![value.to_owned(), decoded, value.replace('+', " ")];
    forms.extend([path_encoded(value), query_encoded(value)]);
    let encoded = forms.split_off(3);
    let mut keys: Vec<String> = forms.iter().flat_map(|form| variants(form)).collect();
    keys.extend(
        encoded
            .iter()
            .flat_map(|form| [form.clone(), lower_hex(form)]),
    );
    keys.retain(|key| !key.is_empty());
    keys.sort();
    keys.dedup();

    keys
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
    companions: Option<Arc<Companions>>,
    on_mac: Option<OnMac>,
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
            companions: None,
            on_mac: None,
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
        self.companions = Some(companions);
        self.on_mac = on_mac;

        self
    }

    /// `values` with every reference replaced by what 1Password holds; a
    /// map without references is returned as is, without running `op`
    pub async fn resolve(
        &self,
        values: &BTreeMap<String, String>,
    ) -> Result<Resolved, SecretError> {
        let mut resolved = Resolved {
            values: BTreeMap::new(),
            secrets: Vec::new(),
        };

        for (key, value) in values {
            let text = self.resolve_text(value, &mut resolved.secrets).await?;
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
    /// clients print them. A URL that is a reference alone is a secret as a
    /// whole, so the redactor also learns its normalized form, path and query
    pub async fn resolve_url(&self, template: &str) -> Result<ResolvedUrl, SecretError> {
        let template = UrlTemplate::parse(template)?;
        let mut values = Vec::new();
        for reference in template.references() {
            values.push(self.value(reference).await?);
        }

        template.fill(&values)
    }

    async fn resolve_text(
        &self,
        value: &str,
        secrets: &mut Vec<String>,
    ) -> Result<String, SecretError> {
        let mut text = String::with_capacity(value.len());
        for piece in pieces(value)? {
            match piece {
                Piece::Text(literal) => text.push_str(literal),
                Piece::Reference(reference) => {
                    let secret = self.value(reference).await?;
                    text.push_str(&secret);
                    secrets.push(secret);
                }
            }
        }

        Ok(text)
    }

    async fn value(&self, reference: &str) -> Result<String, SecretError> {
        // held across the read on purpose: a second caller waits for the
        // first prompt's answer instead of raising its own
        let mut known = self.known.lock().await;
        if let Some(value) = known.get(reference) {
            return Ok(value.clone());
        }
        let value = self.read(reference).await?;
        known.insert(reference.to_owned(), value.clone());

        Ok(value)
    }

    async fn read(&self, reference: &str) -> Result<String, SecretError> {
        let peers = self
            .companions
            .as_ref()
            .map(|companions| companions.peers())
            .unwrap_or_default();
        let Some(companions) = self.companions.as_ref().filter(|_| !peers.is_empty()) else {
            return self.read_local(reference).await;
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
                    .read_local(&reference)
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

        // dropping the set on any exit aborts what is still running, which
        // kills the local `op` child and hangs up on the companions
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
            Ok(Ok(value)) => Ok(value),
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

    /// Whether `op` is surely signed out, so the next read puts 1Password's
    /// own prompt up
    ///
    /// `op whoami` answers from the current authorization and never puts a
    /// prompt up itself. Only its explicit signed-out answer counts: a
    /// timeout, a failed start or any other error may still read silently,
    /// so those answer `false` and the caller keeps asking for itself
    pub async fn signed_out(&self) -> bool {
        let whoami =
            tokio::time::timeout(WHOAMI_TIMEOUT, spawn::output(&self.program, &["whoami"]));

        matches!(
            whoami.await,
            Ok(Ok(output)) if !output.status.success()
                && String::from_utf8_lossy(&output.stderr).contains(SIGNED_OUT)
        )
    }

    /// Runs `op read` on this Mac, with no cache and no companions
    ///
    /// The companion side answers with this: every request asks anew
    pub async fn read_local(&self, reference: &str) -> Result<String, SecretError> {
        let args = ["read", "--no-newline", reference];
        let output = tokio::time::timeout(READ_TIMEOUT, spawn::output(&self.program, &args))
            .await
            .map_err(|_| SecretError::TimedOut {
                reference: reference.to_owned(),
                timeout: READ_TIMEOUT,
            })?
            .map_err(|source| SecretError::Spawn {
                program: self.program.clone(),
                source,
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

        String::from_utf8(output.stdout).map_err(|_| SecretError::Read {
            reference: reference.to_owned(),
            reason: "the value is not UTF-8".to_owned(),
        })
    }
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
    /// its percent and JSON string escapes are decoded
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
            || (text.contains(['%', '+', '\\'])
                && Unescape::VIEWS
                    .into_iter()
                    .any(|mode| holds(&unescaped_with_spans(text, mode).0)))
    }

    /// `text` with every known secret replaced, ignoring ASCII case and
    /// however its percent or JSON string escapes are cased or mixed with
    /// plain characters
    pub fn scrub(&self, text: &str) -> String {
        let known = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut hits = known.spans(text.to_ascii_lowercase().as_bytes());

        // the view is built only for text that has an escape
        if text.contains(['%', '\\']) {
            for mode in Unescape::VIEWS
                .into_iter()
                .filter(|mode| !mode.plus_is_space)
            {
                let (mut decoded, spans) = unescaped_with_spans(text, mode);
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
            &["a/b=c:d@e,f+h", "a/b=c:d@e,f+h", "a/b=c:d@e,f+h"],
        )?;
        let parsed = reqwest::Url::parse(&resolved.url).map_err(|_| SecretError::NotAUrl)?;

        assert_eq!(parsed.host_str(), Some("h.example"));
        assert_eq!(parsed.fragment(), None);
        assert_eq!(parsed.path(), "/mcp/a%2Fb=c:d@e,f+h/message/");
        assert_eq!(
            parsed.query(),
            Some("k=a%2Fb%3Dc%3Ad%40e%2Cf%2Bh&a%2Fb%3Dc%3Ad%40e%2Cf%2Bh=1")
        );

        Ok(())
    }

    #[test]
    fn unprotectable_values_are_refused() {
        for value in [
            "has space1234",
            "sëcret123",
            "tenant\\SecretKey123",
            "abc\"def\"ghi123",
            "key'quote123",
            "a<b>c^{d}|e[f]123",
            "k`tick#hash?q%r&s$t(u)",
            "%41%42%43%44",
            "50%off-secret",
        ] {
            assert!(
                matches!(
                    filled("https://h.example/mcp/{{ op://a/b/c }}", &[value]),
                    Err(SecretError::UrlValueUnprotectable)
                ),
                "{value}"
            );
        }
        assert!(filled("https://h.example/mcp/{{ op://a/b/c }}", &["acct:key~1234"]).is_ok());
    }

    #[test]
    fn a_literal_percent_before_a_value_cannot_complete_an_escape() -> Result<(), SecretError> {
        let resolved = filled("https://host/mcp/%{{ op://a/b/c }}", &["2Fsecret-1234"])?;

        assert_eq!(resolved.url, "https://host/mcp/%252Fsecret-1234");

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
