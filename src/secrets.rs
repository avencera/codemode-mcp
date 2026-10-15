//! Secrets in upstream configuration: `{{ op://vault/item/field }}`
//! references in `headers` and `env`, read through the 1Password CLI when a
//! server first connects, and the redactor that keeps configured and
//! resolved values out of text handed to scripts
//!
//! The braces follow `op inject`'s template syntax, so a value can mix text
//! and references, e.g. `Bearer {{ op://Dev/Context7/credential }}`

use std::{
    collections::{BTreeMap, HashMap},
    process::Stdio,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use tokio::{process::Command, sync::Mutex};

use crate::config::Config;

/// How long one `op read` may take; long enough for the 1Password app's
/// unlock or Touch ID prompt on the Mac
const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest upstream error text handed to a script
const MAX_ERROR_TEXT: usize = 2000;
/// Replacement for secrets found in upstream text
const REDACTED: &str = "[redacted]";
/// Shorter secrets would redact ordinary words
const MIN_SECRET_LEN: usize = 6;

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
fn is_reference(text: &str) -> bool {
    text.strip_prefix("op://").is_some_and(|path| {
        let segments: Vec<&str> = path.split('/').collect();

        (3..=4).contains(&segments.len())
            && segments.iter().all(|segment| !segment.trim().is_empty())
    })
}

/// Checks a configured value's references without reading them
pub fn check(value: &str) -> Result<(), SecretError> {
    pieces(value).map(|_| ())
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
#[derive(Clone)]
pub struct OnePassword {
    program: String,
    known: Arc<Mutex<HashMap<String, String>>>,
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
        }
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
            let mut text = String::with_capacity(value.len());
            for piece in pieces(value)? {
                match piece {
                    Piece::Text(literal) => text.push_str(literal),
                    Piece::Reference(reference) => {
                        let secret = self.value(reference).await?;
                        text.push_str(&secret);
                        resolved.secrets.push(secret);
                    }
                }
            }
            resolved.values.insert(key.clone(), text);
        }

        Ok(resolved)
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
        let mut command = Command::new(&self.program);
        command
            .args(["read", "--no-newline", reference])
            .stdin(Stdio::null())
            .kill_on_drop(true);

        let output = tokio::time::timeout(READ_TIMEOUT, command.output())
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
/// 1Password once a server has connected
#[derive(Default)]
pub struct Redactor(RwLock<Vec<String>>);

impl std::fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.0.read().unwrap_or_else(PoisonError::into_inner).len();

        write!(formatter, "Redactor({count} secrets)")
    }
}

impl Redactor {
    /// Starts with the secrets written into `config`
    pub fn new(config: &Config) -> Self {
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
            if let Some(url) = server.url.as_deref() {
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

        let redactor = Self::default();
        redactor.add(secrets);

        redactor
    }

    /// Redacts these too from now on
    pub fn add(&self, secrets: impl IntoIterator<Item = String>) {
        let mut known = self.0.write().unwrap_or_else(PoisonError::into_inner);
        known.extend(
            secrets
                .into_iter()
                .filter(|secret| secret.len() >= MIN_SECRET_LEN),
        );
        // longest first, so a secret that contains another is replaced whole
        known.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        known.dedup();
    }

    /// `text` with every known secret replaced, cut to a length fit for a
    /// script
    pub fn apply(&self, text: &str) -> String {
        let known = self.0.read().unwrap_or_else(PoisonError::into_inner);
        let mut text = known.iter().fold(text.to_owned(), |text, secret| {
            text.replace(secret.as_str(), REDACTED)
        });
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
