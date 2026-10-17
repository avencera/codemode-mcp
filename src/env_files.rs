//! The `secrets` builtin server: writes 1Password values into an env file on
//! this Mac, so an agent setting up a program names the file and the
//! references and never sees a value
//!
//! The values are read as `codemode-mcp op inject` reads them: one approval
//! for the whole call, wherever the owner is, with the file's path in every
//! prompt. That prompt is the approval, so the gateway runs the call without
//! asking first. The file is merged, not replaced: the lines of the variables
//! named are replaced, new ones are added at the end, and every other line is
//! kept. The answer names the variables written, never their values, and the
//! values are added to the redactor so no later result shows them

use std::{
    collections::{BTreeMap, HashMap},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use companion_wire::wire::{MAX_KEEP_SECS, MAX_PROGRAM_ITEMS};
use rmcp::{
    RoleServer, ServerHandler, ServiceExt,
    handler::server::wrapper::{Json, Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig as McpServerConfig},
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

use crate::{
    companion::{ProgramAsk, ProgramTarget},
    op,
    secrets::{OnePassword, Redactor, is_reference},
};

const INSTRUCTIONS: &str = "Writes 1Password values into an env file on this Mac, such as a \
     stack's `*.secrets.env`, without showing you any value. Name the file and map each variable \
     to its op:// reference; the owner approves once, on this Mac, their phone or a companion \
     Mac, and sees the file's path. Other lines of the file are kept. Use this whenever a \
     program needs a secret: never ask for the value itself.";

/// Groups that hold every user, whose read bit is never kept: `staff` and
/// `everyone` on macOS, `users` on Linux
const CATCH_ALL_GROUPS: [u32; 3] = [20, 12, 100];

/// The error of a call its caller cancelled; nothing was written
const CANCELLED: &str = "the call was cancelled, so nothing was written";

/// One write at a time, so two calls for the same file never merge into
/// the same old text and drop each other's lines
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteEnvParams {
    /// Absolute path of the env file, named `.env`, `.env.<name>` or
    /// `<name>.env`, such as `/srv/stacks/lookout/superalert.secrets.env`;
    /// created mode 0600 when missing
    pub path: String,
    /// Each variable to write, mapped to one whole `op://vault/item/field`
    /// reference; plain values and text around references are refused
    pub vars: BTreeMap<String, String>,
    /// Why the program needs these values; every prompt shows it
    pub reason: String,
    /// Minutes for which the same references are handed out again without
    /// asking, up to 60; leave unset unless several calls in a row need them
    #[serde(default)]
    pub keep_minutes: Option<u64>,
}

/// The answer to `write_env`; never holds a value
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct EnvWritten {
    /// The file written
    pub path: String,
    /// Variables whose lines were replaced
    pub replaced: Vec<String>,
    /// Variables added at the end
    pub added: Vec<String>,
    /// Where the owner approved
    pub approved_on: String,
}

struct Inner {
    onepassword: OnePassword,
    redactor: Arc<Redactor>,
}

/// The MCP server, served in process over an in-memory pipe; cheap to clone
#[derive(Clone)]
pub struct SecretsServer(Arc<Inner>);

impl SecretsServer {
    /// A server reading values through `onepassword`; values read are added
    /// to `redactor`
    pub fn new(onepassword: OnePassword, redactor: Arc<Redactor>) -> Self {
        Self(Arc::new(Inner {
            onepassword,
            redactor,
        }))
    }

    /// Serves MCP on `io` until the other end closes it
    pub async fn serve_on<T>(self, io: T) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let service = self.serve(io).await?;
        service.waiting().await?;

        Ok(())
    }
}

/// The tool's error text
fn failed(message: impl std::fmt::Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

#[tool_router]
impl SecretsServer {
    #[tool(
        description = "Writes 1Password values into an env file on this Mac as KEY=value lines, \
                       without returning them. Give the file's absolute path, each variable's \
                       op:// reference and why the program needs them; the owner approves once \
                       and sees the path. Lines for other variables are kept. Use this instead \
                       of reading a value whenever a program can take it from a file. For a \
                       high-severity secret that should never be in a file, write its op:// \
                       reference into the file yourself and start the program with \
                       `codemode-mcp op run --env-file <file> -- <command>`."
    )]
    async fn write_env(
        &self,
        Parameters(params): Parameters<WriteEnvParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<Json<EnvWritten>, CallToolResult> {
        let path = env_path(&params.path).map_err(failed)?;
        let vars = checked_vars(&params.vars).map_err(failed)?;
        let keep = match params.keep_minutes {
            None => None,
            Some(minutes) => Some(
                minutes
                    .checked_mul(60)
                    .filter(|secs| (1..=MAX_KEEP_SECS).contains(secs))
                    .map(Duration::from_secs)
                    .ok_or_else(|| {
                        failed(format!("keep_minutes is 1 to {}", MAX_KEEP_SECS / 60))
                    })?,
            ),
        };

        let references = op::unique(vars.iter().map(|(_, reference)| reference.clone()));
        let ask = ProgramAsk {
            targets: references
                .iter()
                .cloned()
                .map(ProgramTarget::Reference)
                .collect(),
            reason: Some(params.reason),
            destination: Some(path.display().to_string()),
            keep,
        };
        // a caller that stops waiting takes the prompts down, and nothing is
        // written for it after a late approval
        let read = tokio::select! {
            read = self.0.onepassword.read_for_program(&ask) => read.map_err(failed)?,
            () = context.ct.cancelled() => return Err(failed(CANCELLED)),
        };
        self.0.redactor.add(
            read.values
                .iter()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
        let values: HashMap<String, String> = references.into_iter().zip(read.values).collect();
        let mut lines = Vec::with_capacity(vars.len());
        for (key, reference) in &vars {
            let value = values
                .get(reference)
                .ok_or_else(|| failed(format!("no value was read for {reference}")))?;
            lines.push((key.clone(), env_line(key, value).map_err(failed)?));
        }

        let _turn = tokio::select! {
            turn = TURN.lock() => turn,
            () = context.ct.cancelled() => return Err(failed(CANCELLED)),
        };
        // read again after the approval, which may have taken minutes, so an
        // edit made meanwhile is kept
        let existing = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(failed(format!("cannot read {}: {error}", path.display()))),
        };
        let merged = merge(&existing, &lines);
        // a file already closed to others and shared with a service's group
        // stays readable to that group; one open to everyone was never
        // deliberately shared, and on macOS the usual group, staff, holds
        // every user
        let (mode, group) = match std::fs::metadata(&path) {
            Ok(metadata)
                if metadata.permissions().mode() & 0o007 == 0
                    && metadata.uid() == rustix::process::geteuid().as_raw()
                    && !CATCH_ALL_GROUPS.contains(&metadata.gid()) =>
            {
                (
                    (metadata.permissions().mode() & 0o770) | op::DEFAULT_FILE_MODE,
                    Some(metadata.gid()),
                )
            }
            _ => (op::DEFAULT_FILE_MODE, None),
        };
        op::write_private_for(&path, &merged.text, mode, true, group)
            .map_err(|error| failed(format!("cannot write {}: {error}", path.display())))?;

        Ok(Json(EnvWritten {
            path: path.display().to_string(),
            replaced: merged.replaced,
            added: merged.added,
            approved_on: read.source,
        }))
    }
}

#[tool_handler]
impl ServerHandler for SecretsServer {
    fn get_info(&self) -> McpServerConfig {
        McpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
    }
}

/// The file `text` names, checked before anyone is asked: absolute, named as
/// an env file, in a directory that exists, and a regular file when it
/// exists already. A link is followed, so the prompt names the file written
fn env_path(text: &str) -> Result<PathBuf, String> {
    let path = Path::new(text.trim());
    if !path.is_absolute() {
        return Err(format!("{text} is not an absolute path"));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !is_env_name(name) {
        return Err(format!(
            "{text} is not an env file; name it `.env`, `.env.<name>` or `<name>.env`"
        ));
    }
    let parent = path.parent().unwrap_or(Path::new("/"));
    let directory = std::fs::canonicalize(parent)
        .map_err(|error| format!("{} cannot be used: {error}", parent.display()))?;
    if !directory.is_dir() {
        return Err(format!("{} is not a directory", parent.display()));
    }

    let path = directory.join(name);
    match std::fs::canonicalize(&path) {
        Ok(target) if target.is_file() => {
            let name = target
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if is_env_name(name) {
                Ok(target)
            } else {
                Err(format!(
                    "{text} links to {}, which is not an env file",
                    target.display()
                ))
            }
        }
        Ok(target) => Err(format!("{} is not a regular file", target.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if path.symlink_metadata().is_ok() {
                Err(format!("{text} is a link to nothing"))
            } else {
                Ok(path)
            }
        }
        Err(error) => Err(format!("{text} cannot be used: {error}")),
    }
}

/// Whether `name` is an env file's name, which keeps the tool from adding
/// lines to a script or a config of another format. Example and template
/// files such as `.env.example`, usually kept in git, are not
fn is_env_name(name: &str) -> bool {
    let env =
        name == ".env" || name.starts_with(".env.") || (name.ends_with(".env") && name.len() > 4);
    let template = name
        .split('.')
        .any(|part| matches!(part, "example" | "sample" | "template" | "dist" | "tpl"));

    env && !template
}

/// `vars` as variable names and references, when every name is a variable
/// name, every value one whole `op://` reference, and there are between one
/// and [`MAX_PROGRAM_ITEMS`] of them
///
/// Text around a reference, or a plain value, would put into the file what
/// the owner's prompt never showed, such as a URL that sends the value
/// elsewhere
fn checked_vars(vars: &BTreeMap<String, String>) -> Result<Vec<(String, String)>, String> {
    if vars.is_empty() || vars.len() > MAX_PROGRAM_ITEMS {
        return Err(format!(
            "write 1 to {MAX_PROGRAM_ITEMS} variables at a time"
        ));
    }

    vars.iter()
        .map(|(key, value)| {
            let reference = value.trim();
            if !op::is_env_key(key) {
                Err(format!("{key:?} is not a variable name"))
            } else if !is_reference(reference) {
                Err(format!(
                    "the value for {key} is not one op://vault/item/field reference; write \
                     anything else into the file yourself, or fill a template with `codemode-mcp \
                     op inject`"
                ))
            } else {
                Ok((key.clone(), reference.to_owned()))
            }
        })
        .collect()
}

/// `KEY=value`, with the value single-quoted unless it needs no quotes, as
/// Docker Compose, `op run` and a shell all read it. A shell expands `~` in
/// an assignment and zsh a leading `=`, so neither is left unquoted
fn env_line(key: &str, value: &str) -> Result<String, String> {
    if value.contains(['\n', '\r']) {
        return Err(format!(
            "the value for {key} spans lines, which an env file cannot hold; use `codemode-mcp \
             op inject` with a template of the file instead"
        ));
    }
    let plain = !value.is_empty()
        && !value.starts_with('=')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-.:/+=@,%".contains(character));
    if plain {
        return Ok(format!("{key}={value}"));
    }
    if value.contains('\'') {
        return Err(format!(
            "the value for {key} holds a single quote, which this file cannot hold unescaped; \
             use `codemode-mcp op inject` with a template of the file instead"
        ));
    }

    Ok(format!("{key}='{value}'"))
}

/// The text of a merged env file and what changed in it
#[derive(Debug, PartialEq, Eq)]
struct Merged {
    text: String,
    replaced: Vec<String>,
    added: Vec<String>,
}

/// `existing` with the line of each variable in `lines` replaced, keeping
/// what comes before its name such as `export `, and later lines of the same
/// variable dropped; variables it did not have are added at the end, with
/// the file's own line ending
///
/// A quoted value may span lines, as Docker Compose allows, so a line inside
/// one is never read as a variable, and the rest of a replaced one goes
fn merge(existing: &str, lines: &[(String, String)]) -> Merged {
    let wanted: HashMap<&str, &str> = lines
        .iter()
        .map(|(key, line)| (key.as_str(), line.as_str()))
        .collect();
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut written = std::collections::HashSet::new();
    let mut replaced = Vec::new();
    let mut text = String::with_capacity(existing.len());
    // the quote of a value left open by an earlier line, and whether that
    // value is being replaced
    let mut open: Option<(char, bool)> = None;

    for line in existing.split_inclusive('\n') {
        if let Some((quote, dropping)) = open {
            if closes(line, quote) {
                open = None;
            }
            if !dropping {
                text.push_str(line);
            }
            continue;
        }
        let Some((prefix, key, value)) = assignment(line) else {
            text.push_str(line);
            continue;
        };
        match wanted.get_key_value(key) {
            Some((key, new)) => {
                open = opens(value).map(|quote| (quote, true));
                if written.insert(*key) {
                    replaced.push((*key).to_owned());
                    text.push_str(prefix);
                    text.push_str(new);
                    text.push_str(newline);
                }
            }
            None => {
                open = opens(value).map(|quote| (quote, false));
                text.push_str(line);
            }
        }
    }

    let mut added = Vec::new();
    for (key, line) in lines {
        if written.insert(key.as_str()) {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push_str(newline);
            }
            text.push_str(line);
            text.push_str(newline);
            added.push(key.clone());
        }
    }

    Merged {
        text,
        replaced,
        added,
    }
}

/// What comes before the name, the name and the value of a `KEY=value`
/// line, allowing a byte order mark, indentation and `export`
fn assignment(line: &str) -> Option<(&str, &str, &str)> {
    let body = line.strip_prefix('\u{feff}').unwrap_or(line).trim_start();
    let body = match body.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
        _ => body,
    };
    let (key, value) = body.split_once('=')?;
    let key = key.trim_end();
    if !op::is_env_key(key) {
        return None;
    }

    Some((
        &line[..line.len() - body.len()],
        key,
        value.trim_end_matches(['\r', '\n']),
    ))
}

/// The quote a value opens and does not close on its own line
fn opens(value: &str) -> Option<char> {
    let value = value.trim_start();
    let quote = value
        .chars()
        .next()
        .filter(|first| matches!(first, '"' | '\''))?;

    (!closes(&value[1..], quote)).then_some(quote)
}

/// Whether `text` holds the closing `quote`; inside double quotes a
/// backslash escapes the next character
fn closes(text: &str, quote: char) -> bool {
    let mut escaped = false;
    for character in text.chars() {
        if escaped {
            escaped = false;
        } else if character == '\\' && quote == '"' {
            escaped = true;
        } else if character == quote {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn lines(pairs: &[(&str, &str)]) -> Result<Vec<(String, String)>, String> {
        pairs
            .iter()
            .map(|(key, value)| Ok(((*key).to_owned(), env_line(key, value)?)))
            .collect()
    }

    #[test]
    fn merging_replaces_named_lines_and_keeps_the_rest() -> TestResult {
        let existing = "# pushover\nexport TOKEN=old\nOTHER=kept\nTOKEN=again\nLAST=x";
        let merged = merge(existing, &lines(&[("TOKEN", "new"), ("USER", "u s")])?);

        assert_eq!(
            merged.text,
            "# pushover\nexport TOKEN=new\nOTHER=kept\nLAST=x\nUSER='u s'\n"
        );
        assert_eq!(merged.replaced, ["TOKEN"]);
        assert_eq!(merged.added, ["USER"]);

        // the rest of a replaced multi-line value goes, a quoted line that
        // looks like a variable is kept, and CRLF, a BOM and `export<TAB>`
        // are read
        let existing = "\u{feff}KEY=\"-----BEGIN\r\nabc\r\n-----END\"\r\nNOTE='a\r\nTOKEN=inside'\r\nexport\tTOKEN=old\r\n";
        let merged = merge(existing, &lines(&[("KEY", "k"), ("TOKEN", "t")])?);
        assert_eq!(
            merged.text,
            "\u{feff}KEY=k\r\nNOTE='a\r\nTOKEN=inside'\r\nexport\tTOKEN=t\r\n"
        );
        assert_eq!(merged.replaced, ["KEY", "TOKEN"]);
        assert!(merged.added.is_empty());

        Ok(())
    }

    #[test]
    fn values_are_quoted_only_when_needed_and_refused_when_they_cannot_be() -> TestResult {
        assert_eq!(env_line("A", "abc-123_=/")?, "A=abc-123_=/");
        assert_eq!(env_line("A", "a b#c$d")?, "A='a b#c$d'");
        assert_eq!(env_line("A", "")?, "A=''");
        assert_eq!(env_line("A", "x:~/y")?, "A='x:~/y'");
        assert_eq!(env_line("A", "=ls")?, "A='=ls'");
        assert!(env_line("A", "it's").is_err());
        assert!(env_line("A", "two\nlines").is_err());

        Ok(())
    }

    #[test]
    fn only_env_files_in_existing_directories_are_written() -> TestResult {
        let directory = std::env::temp_dir().join(format!("codemode-env-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let root = std::fs::canonicalize(&directory)?;
        let path = |name: &str| root.join(name).display().to_string();

        assert_eq!(
            env_path(&path("app.secrets.env"))?,
            root.join("app.secrets.env")
        );
        assert!(env_path(&path(".env")).is_ok());
        assert!(env_path(&path(".env.local")).is_ok());
        assert!(env_path(&path("run.sh")).is_err());
        assert!(env_path(&path(".env.example")).is_err());
        assert!(env_path(&path("app.template.env")).is_err());
        assert!(env_path(&path(".env/inside")).is_err());
        assert!(env_path("relative.env").is_err());
        assert!(env_path(&path("missing/app.env")).is_err());

        // a link is followed, and must end at an env file
        std::fs::write(root.join("profile"), "")?;
        std::os::unix::fs::symlink(root.join("profile"), root.join("sneaky.env"))?;
        assert!(env_path(&path("sneaky.env")).is_err());
        std::fs::write(root.join("real.env"), "")?;
        std::os::unix::fs::symlink(root.join("real.env"), root.join("link.env"))?;
        assert_eq!(env_path(&path("link.env"))?, root.join("real.env"));
        std::fs::remove_dir_all(&directory)?;

        Ok(())
    }
}
