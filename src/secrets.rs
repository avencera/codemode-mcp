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
    collections::{BTreeMap, HashMap},
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
    /// A resolved `url` is not a URL; the value is left out of the message
    #[error("the `url` is not a valid URL once its references are read")]
    NotAUrl,
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

/// The parts of a URL that can hold a key: userinfo, path and query as a
/// whole and piece by piece, plus the URL itself in the encodings an
/// authorization server echoes back
fn url_secrets(url: &str) -> Vec<String> {
    let mut secrets = vec![url.to_owned()];
    secrets.extend(encodings(url));

    let Ok(parsed) = reqwest::Url::parse(url) else {
        return secrets;
    };
    // rmcp builds `.well-known` URLs from the path without its last `/`
    let path = parsed.path();
    secrets.push(path.to_owned());
    secrets.push(path.trim_end_matches('/').to_owned());
    secrets.extend(path.split('/').map(str::to_owned));
    if let Some(query) = parsed.query() {
        secrets.push(query.to_owned());
        let raw_values = query
            .split('&')
            .map(|pair| pair.split_once('=').map_or(pair, |(_, value)| value));
        secrets.extend(raw_values.map(str::to_owned));
    }
    secrets.extend(parsed.query_pairs().map(|(_, value)| value.into_owned()));
    if !parsed.username().is_empty() {
        secrets.push(parsed.username().to_owned());
    }
    secrets.extend(parsed.password().map(str::to_owned));

    secrets
}

/// `text` percent-encoded the ways a query string carries a URL: form
/// encoding (`application/x-www-form-urlencoded`), the unreserved set only,
/// and every non-alphanumeric byte
fn encodings(text: &str) -> [String; 3] {
    fn encode(text: &str, kept: &[u8]) -> String {
        let mut encoded = String::with_capacity(text.len() * 2);
        for byte in text.bytes() {
            if byte.is_ascii_alphanumeric() || kept.contains(&byte) {
                encoded.push(char::from(byte));
            } else {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }

        encoded
    }

    [
        encode(text, b"*-._"),
        encode(text, b"-._~"),
        encode(text, b""),
    ]
}

/// Whether the URL's host is `localhost` or an IP address, which every local
/// server shares and redacting would blank out of unrelated output
fn is_local_host(url: &reqwest::Url) -> bool {
    url.domain().is_none_or(|name| {
        let name = name.to_ascii_lowercase();

        name == "localhost" || name.ends_with(".localhost")
    })
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
    /// Everything in it that must stay out of text, for the redactor: `keys`
    /// and the host
    pub secrets: Vec<String>,
    /// What can hold a key, without the host, which an authorization server
    /// on the same host legitimately shares
    pub keys: Vec<String>,
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
    /// The whole URL is a secret when a reference stands in it, so the
    /// redactor also gets the URL's own parts: errors from the HTTP client
    /// print the normalized URL, host or path rather than what 1Password held
    pub async fn resolve_url(&self, template: &str) -> Result<ResolvedUrl, SecretError> {
        let mut read = Vec::new();
        let url = self.resolve_text(template, &mut read).await?;
        let url = url.trim().to_owned();
        let parsed = reqwest::Url::parse(&url).map_err(|_| SecretError::NotAUrl)?;
        let mut keys = read;
        let mut secrets = Vec::new();
        if !keys.is_empty() {
            keys.extend(url_secrets(&url));
            keys.extend(url_secrets(parsed.as_str()));
            secrets.extend(keys.iter().cloned());
            // reqwest prints the host
            if !is_local_host(&parsed) {
                secrets.extend(parsed.host_str().map(str::to_owned));
            }
        }

        Ok(ResolvedUrl { url, secrets, keys })
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
pub struct Redactor(RwLock<Vec<String>>);

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.0.read().unwrap_or_else(PoisonError::into_inner).len();

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
        let mut known = self.0.write().unwrap_or_else(PoisonError::into_inner);
        known.extend(
            secrets
                .into_iter()
                .filter(|secret| secret.len() >= MIN_SECRET_LEN),
        );
        // longest first, so a secret that contains another is replaced whole;
        // ties sort by text so `dedup` sees every duplicate and reconnects
        // do not grow the list
        known.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        known.dedup();
    }

    /// Whether `text` holds any secret that `keys` lists
    pub fn holds_any(text: &str, keys: &[String]) -> bool {
        keys.iter()
            .any(|key| key.len() >= MIN_SECRET_LEN && text.contains(key.as_str()))
    }

    /// `text` with every known secret replaced
    pub fn scrub(&self, text: &str) -> String {
        let known = self.0.read().unwrap_or_else(PoisonError::into_inner);

        known.iter().fold(text.to_owned(), |text, secret| {
            if text.contains(secret.as_str()) {
                text.replace(secret.as_str(), REDACTED)
            } else {
                text
            }
        })
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
}
