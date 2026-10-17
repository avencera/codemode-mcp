//! What `codemode-mcp op read`, `op inject` and `op run` do on this Mac
//! with values the daemon hands back: fill templates, write files only the
//! owner can read, and mask values in a command's output
//!
//! The daemon asks the owner to approve each batch on this Mac, a companion
//! Mac or a phone (see [`crate::companion::ProgramTarget`]); these helpers
//! never ask anyone and never run the local `op`

use std::{
    collections::HashMap,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::secrets::{self, SecretError, is_reference};

/// Mode of a file written with values unless the caller picks another
pub const DEFAULT_FILE_MODE: u32 = 0o600;

/// One `KEY=value` line of an env file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    /// The variable's name
    pub key: String,
    /// Its value as written: a whole `op://…` reference, text holding
    /// `{{ op://… }}` references, or plain text
    pub value: String,
}

impl EnvEntry {
    /// The references the value needs, in order
    pub fn references(&self) -> Result<Vec<String>, SecretError> {
        env_references(&self.value)
    }

    /// The value with its references replaced by `values`
    pub fn filled(&self, values: &HashMap<String, String>) -> Result<String, SecretError> {
        fill_env_value(&self.value, values)
    }
}

/// The references an environment value needs: the whole value when it is
/// one `op://…` reference, as `op run` reads it, otherwise each
/// `{{ op://… }}` in it
pub fn env_references(value: &str) -> Result<Vec<String>, SecretError> {
    if is_whole_reference(value) {
        return Ok(vec![value.trim().to_owned()]);
    }

    Ok(secrets::references(value)?
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// `value` with its references replaced by `values`, read as
/// [`env_references`] reads it
pub fn fill_env_value(
    value: &str,
    values: &HashMap<String, String>,
) -> Result<String, SecretError> {
    if is_whole_reference(value) {
        let reference = value.trim();

        return values
            .get(reference)
            .cloned()
            .ok_or_else(|| SecretError::Read {
                reference: reference.to_owned(),
                reason: "no value was read for it".to_owned(),
            });
    }

    fill_template(value, values)
}

/// `template` with each `{{ op://… }}` replaced by its value in `values`
pub fn fill_template(
    template: &str,
    values: &HashMap<String, String>,
) -> Result<String, SecretError> {
    secrets::fill(template, |reference| {
        values.get(reference).map(String::as_str)
    })
}

/// The references of `template`, each once, in order of first use
pub fn template_references(template: &str) -> Result<Vec<String>, SecretError> {
    Ok(unique(
        secrets::references(template)?
            .into_iter()
            .map(str::to_owned),
    ))
}

/// `references` with repeats dropped, keeping the first of each
pub fn unique(references: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();

    references
        .into_iter()
        .filter(|reference| seen.insert(reference.clone()))
        .collect()
}

fn is_whole_reference(value: &str) -> bool {
    let value = value.trim();

    value.starts_with("op://") && is_reference(value)
}

/// Reads an env file as `op run --env-file` does: `KEY=value` lines, with
/// blank lines, `#` comments and a leading `export ` ignored, and one pair of
/// matching quotes around a value removed. Nothing in a value is unescaped
pub fn parse_env(text: &str) -> Result<Vec<EnvEntry>, String> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected KEY=value", index + 1));
        };
        let key = key.trim();
        if !is_env_key(key) {
            return Err(format!(
                "line {}: {key:?} is not a variable name",
                index + 1
            ));
        }

        entries.push(EnvEntry {
            key: key.to_owned(),
            value: unquoted(value.trim()).to_owned(),
        });
    }

    Ok(entries)
}

/// Whether `key` is a variable name: a letter or `_`, then letters, digits
/// and `_`
pub fn is_env_key(key: &str) -> bool {
    let mut characters = key.chars();

    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn unquoted(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }

    value
}

/// Refuses an existing `path` unless `force`, so a command can stop before
/// it asks the owner for values it could not write
pub fn check_writable(path: &Path, force: bool) -> std::io::Result<()> {
    if !force && path.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} exists; pass --force to replace it", path.display()),
        ));
    }

    Ok(())
}

/// Writes `contents` to `path` with `mode`, replacing an existing file only
/// with `force`
///
/// The text goes to a new file beside `path`, created with `mode` before
/// anything is written, then renamed over it, so the values are never in a
/// file others could read, and a reader never sees half of it
pub fn write_private(path: &Path, contents: &str, mode: u32, force: bool) -> std::io::Result<()> {
    write_private_for(path, contents, mode, force, None)
}

/// [`write_private`], with the new file given `group` when there is one, so
/// the group bits of `mode` reach the group they were meant for; when that
/// group cannot be set they are dropped
pub fn write_private_for(
    path: &Path,
    contents: &str,
    mode: u32,
    force: bool,
    group: Option<u32>,
) -> std::io::Result<()> {
    check_writable(path, force)?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path.file_name().map_or_else(
        || "values".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    let staging = directory.join(format!(
        ".{name}.{}.tmp",
        hex::encode(rand::random::<[u8; 6]>())
    ));

    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&staging)?;
        // the file starts in the directory's group, which may hold anyone,
        // so it gets group bits only once it is in the group meant
        let mode = match group {
            Some(group) if std::os::unix::fs::fchown(&file, None, Some(group)).is_err() => {
                mode & 0o700
            }
            _ => mode,
        };
        // the umask may have taken bits off the mode asked for
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;

        if force {
            std::fs::rename(&staging, path)
        } else {
            // a link fails on an existing name, so a file that appeared
            // while the owner was approving is never replaced
            std::fs::hard_link(&staging, path)
        }
    })();
    // after a rename there is nothing left; after a link, the staging name
    let _ = std::fs::remove_file(&staging);

    written.map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists; pass --force to replace it", path.display()),
            )
        } else {
            error
        }
    })
}

/// Values shorter than this are not masked; one or two characters would
/// garble ordinary output
pub const MIN_MASKED_CHARS: usize = 3;

/// What replaces a value in a command's output
const MASK: &[u8] = b"[redacted]";

/// What masking one stream carries from one read to the next
#[derive(Debug, Default)]
struct Masking {
    /// Bytes at the start of the next read still inside a value already
    /// being masked
    carry: usize,
    /// Whether the last byte passed on was masked, so a value carrying on
    /// from it adds no second mask
    in_mask: bool,
}

/// Replaces values in a command's output, as `op run` conceals them
///
/// Each value is matched as written, and each line of a multi-line value on
/// its own, so a PEM key printed line by line is caught too. Output is
/// passed on as it arrives, holding back only a tail that could still grow
/// into a value
pub struct Masker {
    /// Longest first, so a value that holds another is replaced whole
    needles: Vec<Vec<u8>>,
}

impl Masker {
    /// Masks `values` and each of their lines
    pub fn new<'a>(values: impl IntoIterator<Item = &'a String>) -> Self {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for value in values {
            let lines = value.lines().map(|line| line.trim_end_matches('\r'));
            for needle in std::iter::once(value.as_str()).chain(lines) {
                if needle.chars().count() >= MIN_MASKED_CHARS
                    && !needles.iter().any(|known| known == needle.as_bytes())
                {
                    needles.push(needle.as_bytes().to_vec());
                }
            }
        }
        needles.sort_by_key(|needle| std::cmp::Reverse(needle.len()));

        Self { needles }
    }

    /// Masks what `buffer` holds, appending the result to `out`; returns how
    /// many bytes were consumed. Unless `last`, nothing from where a value
    /// could still be starting is passed on, so a shorter value that matches
    /// first never lets the rest of a longer one through, and only that tail
    /// is kept for the next call
    ///
    /// Every byte inside any value is covered, so overlapping values are
    /// masked whole, and each run of covered bytes becomes one mask. A value
    /// running past what is passed on carries over in `masking`
    fn mask_into(
        &self,
        buffer: &[u8],
        last: bool,
        masking: &mut Masking,
        out: &mut Vec<u8>,
    ) -> usize {
        let open = |at: usize| {
            let rest = &buffer[at..];
            self.needles
                .iter()
                .any(|needle| needle.len() > rest.len() && needle.starts_with(rest))
        };
        let end = if last {
            buffer.len()
        } else {
            (0..buffer.len())
                .find(|at| open(*at))
                .unwrap_or(buffer.len())
        };

        let mut covered = vec![false; buffer.len()];
        covered[..masking.carry.min(buffer.len())].fill(true);
        let mut reach = masking.carry;
        for start in 0..end {
            for needle in &self.needles {
                if buffer[start..].starts_with(needle) {
                    covered[start..start + needle.len()].fill(true);
                    reach = reach.max(start + needle.len());
                }
            }
        }

        for (&byte, &hidden) in buffer[..end].iter().zip(&covered) {
            if !hidden {
                out.push(byte);
            } else if !masking.in_mask {
                out.extend_from_slice(MASK);
            }
            masking.in_mask = hidden;
        }
        masking.carry = reach.saturating_sub(end);

        end
    }

    /// Copies `reader` to `writer` with every value masked
    pub async fn pipe(
        &self,
        mut reader: impl AsyncRead + Unpin,
        mut writer: impl AsyncWrite + Unpin,
    ) -> std::io::Result<()> {
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = vec![0_u8; 8192];
        let mut out = Vec::new();
        let mut masking = Masking::default();
        loop {
            let read = reader.read(&mut chunk).await?;
            let last = read == 0;
            pending.extend_from_slice(&chunk[..read]);
            out.clear();
            let consumed = self.mask_into(&pending, last, &mut masking, &mut out);
            pending.drain(..consumed);
            writer.write_all(&out).await?;
            writer.flush().await?;
            if last {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{fill_env_value, parse_env, template_references};

    #[test]
    fn env_files_read_whole_references_and_templates() -> Result<(), String> {
        let entries = parse_env(
            "# pushover\nexport USER_KEY=\"op://Personal/Pushover/user key\"\n\n\
             TOKEN=Bearer {{ op://Personal/Pushover/app token }}\nPLAIN='as is'\n",
        )?;
        let values = HashMap::from([
            (
                "op://Personal/Pushover/user key".to_owned(),
                "u-123".to_owned(),
            ),
            (
                "op://Personal/Pushover/app token".to_owned(),
                "a-456".to_owned(),
            ),
        ]);
        let filled: Vec<(String, String)> = entries
            .iter()
            .map(|entry| {
                fill_env_value(&entry.value, &values)
                    .map(|value| (entry.key.clone(), value))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;

        assert_eq!(
            filled,
            [
                ("USER_KEY".to_owned(), "u-123".to_owned()),
                ("TOKEN".to_owned(), "Bearer a-456".to_owned()),
                ("PLAIN".to_owned(), "as is".to_owned()),
            ]
        );
        assert!(parse_env("1BAD=x").is_err());

        Ok(())
    }

    #[tokio::test]
    async fn masking_catches_short_split_and_multi_line_values() -> std::io::Result<()> {
        let values = [
            "1234".to_owned(),
            "-----BEGIN KEY-----\nabcdef\n-----END KEY-----".to_owned(),
        ];
        let masker = super::Masker::new(&values);
        // a value split across reads, a value with no newline after it, and a
        // multi-line value printed line by line
        let (mut writer, reader) = tokio::io::duplex(64);
        let piping = tokio::spawn(async move {
            let mut out = Vec::new();
            masker.pipe(reader, &mut out).await.map(|()| out)
        });
        for part in [
            "pin 12",
            "34\nkey:\n-----BEGIN KEY-----\n",
            "abcdef\nprompt 1234",
        ] {
            tokio::io::AsyncWriteExt::write_all(&mut writer, part.as_bytes()).await?;
        }
        drop(writer);
        let out = piping.await.map_err(std::io::Error::other)??;

        assert_eq!(
            String::from_utf8_lossy(&out),
            "pin [redacted]\nkey:\n[redacted]\n[redacted]\nprompt [redacted]"
        );

        Ok(())
    }

    /// What `values` mask `chunks` into, fed as `pipe` feeds reads
    fn masked(values: &[&str], chunks: &[&str]) -> String {
        let values: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        let masker = super::Masker::new(&values);
        let mut pending = Vec::new();
        let mut out = Vec::new();
        let mut masking = super::Masking::default();
        for (index, chunk) in chunks.iter().chain([&""]).enumerate() {
            pending.extend_from_slice(chunk.as_bytes());
            let consumed =
                masker.mask_into(&pending, index == chunks.len(), &mut masking, &mut out);
            pending.drain(..consumed);
        }

        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn a_shorter_value_never_lets_the_rest_of_a_longer_one_through() {
        let values = ["abc", "abcdef0123456789"];
        assert_eq!(
            masked(&values, &["abc", "def0123456789 ok"]),
            "[redacted] ok"
        );
        assert_eq!(masked(&values, &["abc", "x abc"]), "[redacted]x [redacted]");
        // overlapping values are masked whole
        assert_eq!(
            masked(&["abcde", "cdefg"], &["abcd", "efg!"]),
            "[redacted]!"
        );
    }

    #[test]
    fn repeated_output_is_masked_as_it_arrives() {
        let values = ["aaa".to_owned()];
        let masker = super::Masker::new(&values);
        let mut masking = super::Masking::default();
        let mut out = Vec::new();
        let stream = vec![b'a'; 10_000];

        // all but the tail that could still start a value is passed on
        let consumed = masker.mask_into(&stream, false, &mut masking, &mut out);
        assert!(consumed >= stream.len() - 2, "{consumed}");
        assert_eq!(out, b"[redacted]");
        assert_eq!(
            masked(&["aaa", "secret-b"], &["aaaa", "aa", "aa x secret-", "b!"]),
            "[redacted] x [redacted]!"
        );
    }

    #[test]
    fn template_references_are_listed_once_in_order() -> Result<(), String> {
        let references =
            template_references("A={{ op://V/b/f }}\nB={{ op://V/a/f }}\nC={{op://V/b/f}}")
                .map_err(|error| error.to_string())?;

        assert_eq!(references, ["op://V/b/f", "op://V/a/f"]);

        Ok(())
    }
}
