//! TOML configuration for the daemon and its upstream servers

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;

use crate::policy::Policy;

/// Reasons a configuration file could not be loaded
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read
    #[error("failed to read config {path}: {source}")]
    Read {
        /// Path that was read
        path: PathBuf,
        /// Underlying I/O error
        source: std::io::Error,
    },
    /// The file is not valid TOML or has unknown fields
    #[error("failed to parse config {path}: {source}")]
    Parse {
        /// Path that was parsed
        path: PathBuf,
        /// Underlying TOML error
        source: toml::de::Error,
    },
    /// The file parsed but a value is unusable
    #[error("invalid config: {0}")]
    Invalid(String),
    /// No home directory is known, so the default path cannot be derived
    #[error("cannot locate the default config path because $HOME is not set")]
    NoHome,
}

/// Top-level daemon configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the HTTP server binds to
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Host names accepted in the `Host` header on top of the built-in rules
    /// (loopback, private and Tailscale addresses, `*.ts.net`, `*.local` and
    /// single-label names)
    #[serde(default)]
    pub extra_allowed_hosts: Vec<String>,
    /// Path of the Monty worker binary; resolved against `$PATH` and a few
    /// well-known locations when unset
    #[serde(default)]
    pub worker_path: Option<PathBuf>,
    /// How long one upstream tool call may run before it is cancelled
    #[serde(default = "default_tool_timeout_secs")]
    pub tool_timeout_secs: u64,
    /// Sandbox and execution limits
    #[serde(default)]
    pub limits: Limits,
    /// Upstream MCP servers by name
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            extra_allowed_hosts: Vec::new(),
            worker_path: None,
            tool_timeout_secs: default_tool_timeout_secs(),
            limits: Limits::default(),
            servers: BTreeMap::new(),
        }
    }
}

impl Config {
    /// Default location of the configuration file
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let home = std::env::var_os("HOME").ok_or(ConfigError::NoHome)?;

        Ok(PathBuf::from(home).join(".config/codemode-mcp/config.toml"))
    }

    /// Reads and validates the file at `path`
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;

        Self::parse(&text, path)
    }

    /// Parses and validates configuration text; `path` is used in errors only
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate()?;

        Ok(config)
    }

    /// Upstream call timeout as a duration
    pub fn tool_timeout(&self) -> Duration {
        Duration::from_secs(self.tool_timeout_secs)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.tool_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "tool_timeout_secs must be positive".into(),
            ));
        }
        self.limits.validate()?;

        for (name, server) in &self.servers {
            if name.is_empty() {
                return Err(ConfigError::Invalid(
                    "server names must not be empty".into(),
                ));
            }
            server.validate(name)?;
        }

        Ok(())
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 7681))
}

fn default_tool_timeout_secs() -> u64 {
    120
}

/// Sandbox and scheduling limits for script executions
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Heap budget for one script, in bytes
    pub max_memory_bytes: usize,
    /// Interpreter CPU time one script may use; time spent waiting on tools
    /// does not count
    pub script_time_budget_secs: u64,
    /// Wall-clock cap for one execution, including time spent in tool calls
    /// but not time spent waiting for an approval
    pub execution_timeout_secs: u64,
    /// Host round trips (tool calls, sleeps, name lookups) one script may use
    pub max_suspensions: usize,
    /// Total time one script may spend in `asyncio.sleep` or `time.sleep`
    pub max_total_sleep_secs: u64,
    /// How long `execute` and `wait` block before answering `pending`
    pub execute_wait_secs: u64,
    /// Concurrent Monty worker processes, each able to use up to
    /// `max_memory_bytes`
    pub max_workers: usize,
    /// Executions that may wait for a free worker before new ones are
    /// refused with a "busy" error
    pub max_queued_executions: usize,
    /// How long finished results stay available to `wait`
    pub result_ttl_secs: u64,
    /// Cap on captured `print` output per execution, in bytes
    pub max_output_bytes: usize,
    /// Cap on the JSON result of one execution, in bytes; the rest is cut
    /// off and marked truncated
    pub max_result_bytes: usize,
    /// Total size of finished results kept for `wait`; the oldest are
    /// dropped first
    pub max_retained_result_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024,
            script_time_budget_secs: 30,
            execution_timeout_secs: 10 * 60,
            max_suspensions: 1000,
            max_total_sleep_secs: 300,
            execute_wait_secs: 25,
            max_workers: 16,
            max_queued_executions: 64,
            result_ttl_secs: 30 * 60,
            max_output_bytes: 64 * 1024,
            max_result_bytes: 256 * 1024,
            max_retained_result_bytes: 32 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Wait budget as a duration
    pub fn execute_wait(&self) -> Duration {
        Duration::from_secs(self.execute_wait_secs)
    }

    /// Result retention as a duration
    pub fn result_ttl(&self) -> Duration {
        Duration::from_secs(self.result_ttl_secs)
    }

    /// Wall-clock cap per execution as a duration
    pub fn execution_timeout(&self) -> Duration {
        Duration::from_secs(self.execution_timeout_secs)
    }

    /// Cap on the text of one response to the agent: the result and the
    /// printed output, plus room for the envelope and diagnostics
    pub fn max_response_bytes(&self) -> usize {
        self.max_result_bytes
            .saturating_add(self.max_output_bytes)
            .saturating_add(16 * 1024)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let positive = [
            ("max_memory_bytes", self.max_memory_bytes as u64),
            ("script_time_budget_secs", self.script_time_budget_secs),
            ("execution_timeout_secs", self.execution_timeout_secs),
            ("max_suspensions", self.max_suspensions as u64),
            ("max_workers", self.max_workers as u64),
            ("max_result_bytes", self.max_result_bytes as u64),
            (
                "max_retained_result_bytes",
                self.max_retained_result_bytes as u64,
            ),
            ("execute_wait_secs", self.execute_wait_secs),
        ];
        for (field, value) in positive {
            if value == 0 {
                return Err(ConfigError::Invalid(format!(
                    "limits.{field} must be positive"
                )));
            }
        }

        Ok(())
    }
}

/// One upstream MCP server
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Executable for a stdio server
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments for a stdio server
    #[serde(default)]
    pub args: Vec<String>,
    /// Extra environment for a stdio server
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Working directory for a stdio server
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Endpoint of a Streamable HTTP server
    #[serde(default)]
    pub url: Option<String>,
    /// Static headers sent with every HTTP request
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Default policy for every tool of this server
    #[serde(default)]
    pub policy: Policy,
    /// Per-tool overrides keyed by the upstream tool name
    #[serde(default)]
    pub tools: BTreeMap<String, ToolOverride>,
}

/// Per-tool settings that override the server defaults
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolOverride {
    /// Policy for this tool
    pub policy: Policy,
}

/// How to reach a server, derived from [`ServerConfig`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport<'a> {
    /// Spawn a child process and speak MCP over its stdio
    Stdio {
        /// Executable
        command: &'a str,
    },
    /// Connect to a Streamable HTTP endpoint
    Http {
        /// Endpoint URL
        url: &'a str,
    },
}

impl ServerConfig {
    /// The transport this server uses; validation guarantees exactly one
    pub fn transport(&self) -> Option<Transport<'_>> {
        match (&self.command, &self.url) {
            (Some(command), None) => Some(Transport::Stdio { command }),
            (None, Some(url)) => Some(Transport::Http { url }),
            _ => None,
        }
    }

    /// Policy for a tool, preferring a per-tool override
    pub fn policy_for(&self, tool: &str) -> Policy {
        self.tools.get(tool).map_or(self.policy, |tool| tool.policy)
    }

    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        match (&self.command, &self.url) {
            (Some(_), Some(_)) => Err(ConfigError::Invalid(format!(
                "servers.{name}: set either `command` or `url`, not both"
            ))),
            (None, None) => Err(ConfigError::Invalid(format!(
                "servers.{name}: one of `command` or `url` is required"
            ))),
            (Some(_), None) if !self.headers.is_empty() => Err(ConfigError::Invalid(format!(
                "servers.{name}: `headers` only applies to `url` servers"
            ))),
            (None, Some(_))
                if !self.args.is_empty() || !self.env.is_empty() || self.cwd.is_some() =>
            {
                Err(ConfigError::Invalid(format!(
                    "servers.{name}: `args`, `env` and `cwd` only apply to `command` servers"
                )))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("test.toml"))
    }

    #[test]
    fn parses_both_transports_and_overrides() -> Result<(), ConfigError> {
        let config = parse(
            r#"
            listen = "127.0.0.1:9000"

            [servers.docs]
            url = "https://example.com/mcp"
            headers = { "x-team" = "a" }

            [servers.op]
            command = "op-mcp"
            args = ["--stdio"]
            policy = "ask"

            [servers.op.tools.delete_item]
            policy = "deny"
            "#,
        )?;

        assert_eq!(config.listen.port(), 9000);
        assert_eq!(
            config.servers["docs"].transport(),
            Some(Transport::Http {
                url: "https://example.com/mcp"
            })
        );
        assert_eq!(config.servers["op"].policy_for("list"), Policy::Ask);
        assert_eq!(config.servers["op"].policy_for("delete_item"), Policy::Deny);

        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_ambiguous_servers() {
        assert!(parse("surprise = 1").is_err());
        assert!(parse("[servers.a]\ncommand = \"x\"\nurl = \"http://y\"").is_err());
        assert!(parse("[servers.a]\npolicy = \"allow\"").is_err());
    }
}
