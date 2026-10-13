//! Derived usage signals: the `stats` numbers and the weekly `review` report

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write,
    time::Duration,
};

use rusqlite::{Connection, params};
use serde::Serialize;

use crate::{store::now_ms, usage::EXEC_CLIENT};

mod strictness;

pub use strictness::{
    ABANDONED_SHARE_LIMIT, ClientStrictness, JSON_LOADS_LIMIT, MIN_ERROR_RUNS, MIN_RULE_ERRORS,
    MISMATCH_LIMIT, PROBE_LIMIT, RUNTIME_ERROR_LIMIT, RuleStats, Strictness,
    UNRESOLVED_SHARE_LIMIT,
};

/// Error fingerprints listed at most
const TOP_FINGERPRINTS: usize = 10;
/// Runs shown with their full attempt sequence
const WORST_RUNS: usize = 5;
/// Calls of one client without a session further apart than this start a new run
const RUN_GAP_MS: i64 = 10 * 60 * 1000;
/// Rows listed in the other review tables
const TOP_ROWS: usize = 20;

/// Longest window accepted; well past any retention, and keeps the
/// millisecond arithmetic far from overflow
const MAX_WINDOW: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Parses a window such as `30m`, `12h`, `7d` or `2w`
pub fn parse_since(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    let split = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("`{text}` is not a duration like 7d, 12h or 30m"))?;
    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" | "" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err(format!("unknown unit `{unit}`; use s, m, h, d or w")),
    };

    Ok(Duration::from_secs(number.saturating_mul(seconds)).min(MAX_WINDOW))
}

/// Headline numbers for one client
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientStats {
    /// Client name from the request `_meta`, `initialize` or `user-agent`
    pub client: String,
    /// Agent-facing calls
    pub calls: i64,
    /// Distinct runs: app sessions, or for calls without one stretches of
    /// calls with gaps under 10 minutes (approximate)
    pub runs: i64,
    /// Calls per agent-facing tool
    pub by_tool: BTreeMap<String, i64>,
    /// Finished executions
    pub executions: i64,
    /// Executions that ended `ok`
    pub succeeded: i64,
    /// Mean executions per run up to and including the first success, over
    /// runs that succeeded
    pub mean_attempts: Option<f64>,
    /// Calls that were issued a new session
    pub sessions_minted: i64,
    /// Calls that passed a valid session
    pub session_calls: i64,
    /// Sessions with a single call in the window
    ///
    /// Agents often make parallel calls before their first answer, and each
    /// mints a session, so a "minted while another was active" count would
    /// mostly flag parallel lanes and concurrent agents; a lone call is the
    /// clearer sign of a session nobody passed back, though a one-shot task
    /// produces one too
    pub sessions_used_once: i64,
}

impl ClientStats {
    /// Share of executions that succeeded
    pub fn success_rate(&self) -> Option<f64> {
        (self.executions > 0).then(|| self.succeeded as f64 / self.executions as f64)
    }
}

/// Timing of one upstream tool
#[derive(Debug, Clone, Serialize)]
pub struct SlowTool {
    /// `<server>.<tool>`
    pub tool: String,
    /// Calls made
    pub calls: i64,
    /// Mean duration
    pub mean_ms: f64,
    /// Longest duration
    pub max_ms: i64,
}

/// Approval counts
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApprovalStats {
    /// Requests created
    pub requested: i64,
    /// Approved
    pub approved: i64,
    /// Denied on the page
    pub denied: i64,
    /// Denied automatically after the timeout
    pub expired: i64,
    /// Withdrawn because the execution ended first
    pub abandoned: i64,
    /// Median time from request to an approve or deny decision
    pub median_wait_ms: Option<i64>,
}

/// Everything `stats` and `/stats` show
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    /// Start of the window, ms since the epoch
    pub since_ms: i64,
    /// Per client, busiest first
    pub clients: Vec<ClientStats>,
    /// Most frequent error fingerprints with counts
    pub fingerprints: Vec<(String, i64)>,
    /// Upstream tools by mean duration, slowest first
    pub slow_tools: Vec<SlowTool>,
    /// Approval counts
    pub approvals: ApprovalStats,
    /// Whether the type rules are too strict or too loose
    pub strictness: Strictness,
}

/// One execution in a run's attempt sequence
#[derive(Debug, Clone)]
struct Attempt {
    run: String,
    client: String,
    outcome: String,
    detail: Option<String>,
    script: String,
}

/// Splits activity without a session into runs
///
/// A run is an app session when the call carried one. Otherwise it is one client's
/// calls and executions with gaps under 10 minutes, so it is approximate:
/// two sessions of one client that overlap or follow closely merge
struct Runs {
    /// Start of each run per client, ascending
    starts: HashMap<String, Vec<i64>>,
}

impl Runs {
    /// `events` are (client, time) pairs of session-less activity, ordered
    /// by time
    fn new(events: impl IntoIterator<Item = (String, i64)>) -> Self {
        let mut starts: HashMap<String, Vec<i64>> = HashMap::new();
        let mut previous: HashMap<String, i64> = HashMap::new();
        for (client, at_ms) in events {
            let continues = previous
                .insert(client.clone(), at_ms)
                .is_some_and(|before| at_ms - before < RUN_GAP_MS);
            if !continues {
                starts.entry(client).or_default().push(at_ms);
            }
        }

        Self { starts }
    }

    /// Identifier of the run an event belongs to; the event must have been
    /// passed to [`Runs::new`] when it has no session
    fn key(&self, session: Option<&str>, client: &str, at_ms: i64) -> String {
        if let Some(session) = session {
            return session.to_owned();
        }
        let start = self.starts.get(client).and_then(|starts| {
            let after = starts.partition_point(|start| *start <= at_ms);

            after.checked_sub(1).map(|index| starts[index])
        });

        format!("{client} from {}", central_time(start.unwrap_or(at_ms)))
    }
}

/// Reads usage records from `since` until now
pub struct Reporter<'a> {
    connection: &'a Connection,
    since_ms: i64,
}

impl<'a> Reporter<'a> {
    /// Reports over the last `since`
    pub fn new(connection: &'a Connection, since: Duration) -> Self {
        Self {
            connection,
            since_ms: now_ms().saturating_sub(since.as_millis() as i64),
        }
    }

    /// The headline numbers
    pub fn stats(&self) -> Result<Stats, rusqlite::Error> {
        Ok(Stats {
            since_ms: self.since_ms,
            clients: self.clients()?,
            fingerprints: self.fingerprints()?,
            slow_tools: self.slow_tools()?,
            approvals: self.approvals()?,
            strictness: self.strictness()?,
        })
    }

    fn clients(&self) -> Result<Vec<ClientStats>, rusqlite::Error> {
        let mut clients: BTreeMap<String, ClientStats> = BTreeMap::new();

        let mut statement = self.connection.prepare(
            "SELECT COALESCE(client_name, 'unknown'), tool, COUNT(*) FROM calls \
             WHERE at_ms >= ?1 GROUP BY 1, 2",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (client, tool, count) = row?;
            let entry = clients.entry(client.clone()).or_default();
            entry.client = client;
            entry.calls += count;
            entry.by_tool.insert(tool, count);
        }

        let mut statement = self.connection.prepare(
            "SELECT COALESCE(client_name, 'unknown'), session_state, COUNT(*) FROM calls \
             WHERE at_ms >= ?1 AND session_state IS NOT NULL GROUP BY 1, 2",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (client, state, count) = row?;
            let entry = clients.entry(client.clone()).or_default();
            entry.client = client;
            match state.as_str() {
                "reused" => entry.session_calls += count,
                "minted" | "reminted" => entry.sessions_minted += count,
                _ => {}
            }
        }

        let mut statement = self.connection.prepare(
            "SELECT client, COUNT(*) FROM ( \
                 SELECT COALESCE(client_name, 'unknown') AS client, session FROM calls \
                 WHERE at_ms >= ?1 AND session IS NOT NULL \
                 GROUP BY 1, 2 HAVING COUNT(*) = 1 \
             ) GROUP BY 1",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (client, count) = row?;
            let entry = clients.entry(client.clone()).or_default();
            entry.client = client;
            entry.sessions_used_once += count;
        }

        let runs = self.runs()?;
        let mut statement = self.connection.prepare(
            "SELECT session, COALESCE(client_name, 'unknown'), at_ms FROM calls \
             WHERE at_ms >= ?1 \
             UNION ALL \
             SELECT session, COALESCE(client_name, 'unknown'), started_ms FROM executions \
             WHERE started_ms >= ?1 AND client_name IS NOT ?2",
        )?;
        let rows = statement.query_map(params![self.since_ms, EXEC_CLIENT], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
        for row in rows {
            let (session, client, at_ms) = row?;
            seen.entry(client.clone()).or_default().insert(runs.key(
                session.as_deref(),
                &client,
                at_ms,
            ));
        }
        for (client, keys) in seen {
            clients.entry(client).or_default().runs = keys.len() as i64;
        }

        let mut statement = self.connection.prepare(
            "SELECT COALESCE(client_name, 'unknown'), COUNT(*), SUM(outcome = 'ok') \
             FROM executions WHERE started_ms >= ?1 GROUP BY 1",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (client, executions, succeeded) = row?;
            let entry = clients.entry(client.clone()).or_default();
            entry.client = client;
            entry.executions = executions;
            entry.succeeded = succeeded;
        }

        let mut attempts_until: HashMap<String, Vec<usize>> = HashMap::new();
        for sequence in self.attempts()?.values() {
            if let Some(position) = sequence.iter().position(|attempt| attempt.outcome == "ok") {
                attempts_until
                    .entry(sequence[0].client.clone())
                    .or_default()
                    .push(position + 1);
            }
        }
        for (client, counts) in attempts_until {
            clients.entry(client).or_default().mean_attempts =
                Some(counts.iter().sum::<usize>() as f64 / counts.len() as f64);
        }

        let mut clients: Vec<ClientStats> = clients.into_values().collect();
        clients.sort_by_key(|client| std::cmp::Reverse(client.calls));

        Ok(clients)
    }

    /// Activity of session-less callers, which `Runs` splits by time gaps;
    /// the `exec` CLI is left out because it is no agent
    fn runs(&self) -> Result<Runs, rusqlite::Error> {
        let mut statement = self.connection.prepare(
            "SELECT COALESCE(client_name, 'unknown'), at_ms FROM calls \
             WHERE at_ms >= ?1 AND session IS NULL AND client_name IS NOT ?2 \
             UNION ALL \
             SELECT COALESCE(client_name, 'unknown'), started_ms FROM executions \
             WHERE started_ms >= ?1 AND session IS NULL AND client_name IS NOT ?2 \
             ORDER BY 2",
        )?;
        let events = statement
            .query_map(params![self.since_ms, EXEC_CLIENT], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Runs::new(events))
    }

    /// Executions of each run in order; the `exec` CLI is left out
    fn attempts(&self) -> Result<BTreeMap<String, Vec<Attempt>>, rusqlite::Error> {
        let runs = self.runs()?;
        let mut statement = self.connection.prepare(
            "SELECT session, COALESCE(client_name, 'unknown'), started_ms, outcome, detail, script \
             FROM executions WHERE started_ms >= ?1 AND client_name IS NOT ?2 \
             ORDER BY started_ms",
        )?;
        let rows = statement.query_map(params![self.since_ms, EXEC_CLIENT], |row| {
            let session: Option<String> = row.get(0)?;
            let client: String = row.get(1)?;
            let started_ms: i64 = row.get(2)?;

            Ok(Attempt {
                run: runs.key(session.as_deref(), &client, started_ms),
                client,
                outcome: row.get(3)?,
                detail: row.get(4)?,
                script: row.get(5)?,
            })
        })?;

        let mut attempts: BTreeMap<String, Vec<Attempt>> = BTreeMap::new();
        for attempt in rows {
            let attempt = attempt?;
            attempts
                .entry(attempt.run.clone())
                .or_default()
                .push(attempt);
        }

        Ok(attempts)
    }

    fn fingerprints(&self) -> Result<Vec<(String, i64)>, rusqlite::Error> {
        let mut statement = self.connection.prepare(
            "SELECT fingerprint, COUNT(*) FROM ( \
                 SELECT fingerprint FROM executions \
                 WHERE started_ms >= ?1 AND fingerprint IS NOT NULL \
                 UNION ALL \
                 SELECT fingerprint FROM calls \
                 WHERE at_ms >= ?1 AND tool = 'describe_tools' AND fingerprint IS NOT NULL \
             ) GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?2",
        )?;
        let rows = statement.query_map(params![self.since_ms, TOP_FINGERPRINTS as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        rows.collect()
    }

    fn slow_tools(&self) -> Result<Vec<SlowTool>, rusqlite::Error> {
        // calls refused before they reached the upstream are logged with zero
        // duration and would drag the means down
        let mut statement = self.connection.prepare(
            "SELECT server || '.' || tool, COUNT(*), AVG(duration_ms), MAX(duration_ms) \
             FROM upstream_calls WHERE at_ms >= ?1 AND outcome != 'denied' \
             AND (duration_ms > 0 OR outcome = 'ok') \
             GROUP BY server, tool ORDER BY 3 DESC LIMIT 10",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok(SlowTool {
                tool: row.get(0)?,
                calls: row.get(1)?,
                mean_ms: row.get(2)?,
                max_ms: row.get(3)?,
            })
        })?;

        rows.collect()
    }

    fn approvals(&self) -> Result<ApprovalStats, rusqlite::Error> {
        let mut statement = self.connection.prepare(
            "SELECT decision, created_ms, decided_ms FROM approvals WHERE created_ms >= ?1",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        })?;

        let mut stats = ApprovalStats::default();
        let mut waits = Vec::new();
        for row in rows {
            let (decision, created, decided) = row?;
            stats.requested += 1;
            match decision.as_deref() {
                Some("approved") => stats.approved += 1,
                Some("denied") => stats.denied += 1,
                Some("expired") => stats.expired += 1,
                Some("abandoned") => stats.abandoned += 1,
                _ => {}
            }
            if matches!(decision.as_deref(), Some("approved" | "denied"))
                && let Some(decided) = decided
            {
                waits.push(decided - created);
            }
        }
        waits.sort_unstable();
        stats.median_wait_ms = waits.get(waits.len() / 2).copied();

        Ok(stats)
    }

    /// The weekly Markdown review; `server_prefixes` are the Python name
    /// prefixes (`<server>_`) of configured servers, used to spot
    /// hallucinated tool names
    pub fn review(&self, server_prefixes: &[String]) -> Result<String, rusqlite::Error> {
        let stats = self.stats()?;
        let mut out = String::new();
        let _ = writeln!(out, "# codemode-mcp usage review\n");
        let _ = writeln!(
            out,
            "Runs (approximate when session-less): a run is an app session when the call carried \
             one, otherwise one client's calls with gaps under 10 minutes.\n"
        );
        let _ = writeln!(
            out,
            "Window: last {} (since {})\n",
            human_duration(now_ms() - self.since_ms),
            central_time(self.since_ms)
        );

        self.client_section(&mut out, &stats);
        session_section(&mut out, &stats);
        self.fingerprint_section(&mut out, &stats)?;
        self.retry_section(&mut out)?;
        self.hallucination_section(&mut out, server_prefixes)?;
        self.undescribed_section(&mut out)?;
        self.search_section(&mut out)?;
        strictness::render_section(&mut out, &stats.strictness);
        approval_section(&mut out, &stats.approvals);

        Ok(out)
    }

    fn client_section(&self, out: &mut String, stats: &Stats) {
        let _ = writeln!(out, "## Per-client summary\n");
        if stats.clients.is_empty() {
            let _ = writeln!(out, "No calls in this window.\n");
            return;
        }
        let _ = writeln!(
            out,
            "| Client | Runs | Calls | search | describe | execute | wait | Executions | Success rate | Mean attempts to success |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|---|---|---|---|");
        for client in &stats.clients {
            let count = |tool: &str| client.by_tool.get(tool).copied().unwrap_or(0);
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                cell(&client.client),
                client.runs,
                client.calls,
                count("search_tools"),
                count("describe_tools"),
                count("execute"),
                count("wait"),
                client.executions,
                percent(client.success_rate()),
                client
                    .mean_attempts
                    .map_or_else(|| "-".to_owned(), |mean| format!("{mean:.1}")),
            );
        }
        out.push('\n');
    }

    fn fingerprint_section(&self, out: &mut String, stats: &Stats) -> Result<(), rusqlite::Error> {
        let _ = writeln!(out, "## Top error fingerprints\n");
        if stats.fingerprints.is_empty() {
            let _ = writeln!(out, "No errors in this window.\n");
            return Ok(());
        }

        for (index, (fingerprint, count)) in stats.fingerprints.iter().enumerate() {
            let _ = writeln!(
                out,
                "### {}. `{}` ({count}x)\n",
                index + 1,
                inline(fingerprint)
            );
            let example = self
                .connection
                .query_row(
                    "SELECT script, detail FROM executions \
                     WHERE fingerprint = ?1 AND started_ms >= ?2 \
                     ORDER BY started_ms DESC LIMIT 1",
                    params![fingerprint, self.since_ms],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .or_else(|_| {
                    self.connection.query_row(
                        "SELECT COALESCE(input, ''), detail FROM calls \
                         WHERE fingerprint = ?1 AND at_ms >= ?2 ORDER BY at_ms DESC LIMIT 1",
                        params![fingerprint, self.since_ms],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                    )
                });
            match example {
                Ok((script, detail)) => {
                    let _ = writeln!(out, "Example:\n");
                    code_block(out, &script);
                    let _ = writeln!(out, "Error: {}\n", detail.as_deref().map_or("-", str::trim));
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    fn retry_section(&self, out: &mut String) -> Result<(), rusqlite::Error> {
        let _ = writeln!(
            out,
            "## Runs with the most failed executes before success\n"
        );
        let mut ranked: Vec<(usize, bool, Vec<Attempt>)> = self
            .attempts()?
            .into_values()
            .filter_map(|sequence| {
                let success = sequence.iter().position(|attempt| attempt.outcome == "ok");
                let failed = success.unwrap_or(sequence.len());
                (failed > 0).then_some((failed, success.is_some(), sequence))
            })
            .collect();
        ranked.sort_by_key(|ranked| std::cmp::Reverse(ranked.0));
        if ranked.is_empty() {
            let _ = writeln!(out, "No run needed a retry.\n");
            return Ok(());
        }

        for (failed, succeeded, sequence) in ranked.into_iter().take(WORST_RUNS) {
            let first = &sequence[0];
            let ending = if succeeded {
                "then succeeded"
            } else {
                "abandoned"
            };
            let _ = writeln!(
                out,
                "### {} run `{}`: {failed} failed, {ending}\n",
                cell(&first.client),
                inline(&first.run)
            );
            for (index, attempt) in sequence.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{}. **{}**{}\n",
                    index + 1,
                    attempt.outcome,
                    attempt
                        .detail
                        .as_deref()
                        .map(|detail| format!(": {}", inline(detail)))
                        .unwrap_or_default()
                );
                code_block(out, &attempt.script);
                if attempt.outcome == "ok" {
                    break;
                }
            }
        }

        Ok(())
    }

    fn hallucination_section(
        &self,
        out: &mut String,
        prefixes: &[String],
    ) -> Result<(), rusqlite::Error> {
        let _ = writeln!(out, "## Hallucinated tool names\n");
        let mut statement = self.connection.prepare(
            "SELECT detail FROM executions \
             WHERE started_ms >= ?1 AND outcome = 'name_error' AND detail IS NOT NULL \
             UNION ALL \
             SELECT detail FROM calls \
             WHERE at_ms >= ?1 AND tool = 'describe_tools' AND outcome = 'name_error' \
             AND detail IS NOT NULL",
        )?;
        let details: Vec<String> = statement
            .query_map(params![self.since_ms], |row| row.get(0))?
            .collect::<Result<_, _>>()?;

        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for detail in &details {
            let names = detail
                .split_once(':')
                .map_or(detail.as_str(), |(_, names)| names);
            for name in names
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            {
                let tool_shaped = if prefixes.is_empty() {
                    name.contains('_')
                } else {
                    prefixes
                        .iter()
                        .any(|prefix| name.starts_with(prefix.as_str()))
                };
                if tool_shaped {
                    *counts.entry(name.to_owned()).or_default() += 1;
                }
            }
        }
        if counts.is_empty() {
            let _ = writeln!(out, "None.\n");
            return Ok(());
        }

        let mut counts: Vec<(String, i64)> = counts.into_iter().collect();
        counts.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        let _ = writeln!(out, "| Name | Times |\n|---|---|");
        for (name, count) in counts.into_iter().take(TOP_ROWS) {
            let _ = writeln!(out, "| `{}` | {count} |", inline(&name));
        }
        out.push('\n');

        Ok(())
    }

    fn undescribed_section(&self, out: &mut String) -> Result<(), rusqlite::Error> {
        let _ = writeln!(
            out,
            "## Executes that called tools never described in that run\n"
        );
        let runs = self.runs()?;
        let mut described: HashMap<String, HashSet<String>> = HashMap::new();
        let mut statement = self.connection.prepare(
            "SELECT session, COALESCE(client_name, 'unknown'), at_ms, input FROM calls \
             WHERE at_ms >= ?1 AND tool = 'describe_tools'",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (session, client, at_ms, input) = row?;
            let names: Vec<String> = input
                .and_then(|input| serde_json::from_str(&input).ok())
                .unwrap_or_default();
            described
                .entry(runs.key(session.as_deref(), &client, at_ms))
                .or_default()
                .extend(names);
        }

        let mut statement = self.connection.prepare(
            "SELECT DISTINCT u.function, e.session, COALESCE(e.client_name, 'unknown'), \
                    e.started_ms, e.id \
             FROM upstream_calls u JOIN executions e ON e.id = u.execution_id \
             WHERE e.started_ms >= ?1 AND e.client_name IS NOT ?2",
        )?;
        let rows = statement.query_map(params![self.since_ms, EXEC_CLIENT], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut unseen: BTreeMap<String, (HashSet<String>, HashSet<String>)> = BTreeMap::new();
        for row in rows {
            let (function, session, client, started_ms, execution) = row?;
            let run = runs.key(session.as_deref(), &client, started_ms);
            if described
                .get(&run)
                .is_some_and(|names| names.contains(&function))
            {
                continue;
            }
            let entry = unseen.entry(function).or_default();
            entry.0.insert(execution);
            entry.1.insert(run);
        }
        if unseen.is_empty() {
            let _ = writeln!(out, "None.\n");
            return Ok(());
        }

        let _ = writeln!(out, "| Tool | Executions | Runs |\n|---|---|---|");
        for (function, (executions, runs)) in unseen.into_iter().take(TOP_ROWS) {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} |",
                inline(&function),
                executions.len(),
                runs.len()
            );
        }
        out.push('\n');

        Ok(())
    }

    fn search_section(&self, out: &mut String) -> Result<(), rusqlite::Error> {
        let _ = writeln!(out, "## Empty searches\n");
        let mut statement = self.connection.prepare(
            "SELECT COALESCE(input, ''), COUNT(*) FROM calls \
             WHERE at_ms >= ?1 AND tool = 'search_tools' AND detail = 'results: 0' \
             GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?2",
        )?;
        let empty: Vec<(String, i64)> = statement
            .query_map(params![self.since_ms, TOP_ROWS as i64], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?
            .collect::<Result<_, _>>()?;
        query_table(out, &empty, "Times");

        let _ = writeln!(out, "## Repeated searches (same query, same run)\n");
        let runs = self.runs()?;
        let mut statement = self.connection.prepare(
            "SELECT session, COALESCE(client_name, 'unknown'), at_ms, COALESCE(input, '') \
             FROM calls WHERE at_ms >= ?1 AND tool = 'search_tools'",
        )?;
        let rows = statement.query_map(params![self.since_ms], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut per_run: HashMap<(String, String), i64> = HashMap::new();
        for row in rows {
            let (session, client, at_ms, query) = row?;
            *per_run
                .entry((runs.key(session.as_deref(), &client, at_ms), query))
                .or_default() += 1;
        }
        let mut totals: HashMap<String, i64> = HashMap::new();
        for ((_, query), times) in per_run {
            if times > 1 {
                *totals.entry(query).or_default() += times;
            }
        }
        let mut repeated: Vec<(String, i64)> = totals.into_iter().collect();
        repeated.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        repeated.truncate(TOP_ROWS);
        query_table(out, &repeated, "Times");

        Ok(())
    }
}

fn session_section(out: &mut String, stats: &Stats) {
    let _ = writeln!(out, "## Session reuse\n");
    if stats
        .clients
        .iter()
        .all(|client| client.sessions_minted == 0 && client.session_calls == 0)
    {
        let _ = writeln!(out, "No calls carried a session in this window.\n");
        return;
    }
    let _ = writeln!(
        out,
        "Forgotten: a new session was issued although the same client had an active one within \
         the last hour (parallel agents of one client count too).\n"
    );
    let _ = writeln!(
        out,
        "| Client | Sessions minted | Calls with a passed session | Sessions used once |\n|---|---|---|---|"
    );
    for client in &stats.clients {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            cell(&client.client),
            client.sessions_minted,
            client.session_calls,
            client.sessions_used_once
        );
    }
    out.push('\n');
}

fn approval_section(out: &mut String, stats: &ApprovalStats) {
    let _ = writeln!(out, "## Approvals\n");
    let _ = writeln!(
        out,
        "- Requested: {}\n- Approved: {}\n- Denied: {}\n- Expired: {}\n- Withdrawn: {}\n- Median wait for a decision: {}\n",
        stats.requested,
        stats.approved,
        stats.denied,
        stats.expired,
        stats.abandoned,
        stats
            .median_wait_ms
            .map_or_else(|| "-".to_owned(), human_duration),
    );
}

fn query_table(out: &mut String, rows: &[(String, i64)], label: &str) {
    if rows.is_empty() {
        let _ = writeln!(out, "None.\n");
        return;
    }
    let _ = writeln!(out, "| Query | {label} |\n|---|---|");
    for (query, count) in rows {
        let _ = writeln!(out, "| `{}` | {count} |", inline(query));
    }
    out.push('\n');
}

/// Renders the headline numbers as plain text for the terminal
pub fn render_stats(stats: &Stats) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Since {} ago (runs are approximate when session-less)\n",
        human_duration(now_ms() - stats.since_ms)
    );
    if stats.clients.is_empty() {
        let _ = writeln!(out, "No calls recorded.");
    }
    for client in &stats.clients {
        let tools: Vec<String> = client
            .by_tool
            .iter()
            .map(|(tool, count)| format!("{tool} {count}"))
            .collect();
        let _ = writeln!(
            out,
            "{}: {} calls in {} runs ({})\n  executions {}, success rate {}, mean attempts to success {}\n  \
             session reuse: {} minted, {} calls with a passed session, {} used once",
            client.client,
            client.calls,
            client.runs,
            tools.join(", "),
            client.executions,
            percent(client.success_rate()),
            client
                .mean_attempts
                .map_or_else(|| "-".to_owned(), |mean| format!("{mean:.1}")),
            client.sessions_minted,
            client.session_calls,
            client.sessions_used_once,
        );
    }

    let _ = writeln!(out, "\nTop error fingerprints:");
    if stats.fingerprints.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for (fingerprint, count) in &stats.fingerprints {
        let _ = writeln!(out, "  {count:>5}  {fingerprint}");
    }

    let _ = writeln!(out, "\nSlowest upstream tools:");
    if stats.slow_tools.is_empty() {
        let _ = writeln!(out, "  none");
    }
    for tool in &stats.slow_tools {
        let _ = writeln!(
            out,
            "  {:>8.0} ms mean  {:>8} ms max  {:>5} calls  {}",
            tool.mean_ms, tool.max_ms, tool.calls, tool.tool
        );
    }

    let approvals = &stats.approvals;
    let _ = writeln!(
        out,
        "\nApprovals: {} requested, {} approved, {} denied, {} expired, median wait {}",
        approvals.requested,
        approvals.approved,
        approvals.denied,
        approvals.expired,
        approvals
            .median_wait_ms
            .map_or_else(|| "-".to_owned(), human_duration),
    );
    strictness::render_text(&mut out, &stats.strictness);

    out
}

/// `0.75` as `75%`, `-` when unknown
pub fn percent(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{:.0}%", value * 100.0))
}

/// Formats a millisecond timestamp in US Central time, the owner's zone
pub fn central_time(ms: i64) -> String {
    jiff::Timestamp::from_millisecond(ms)
        .and_then(|at| at.in_tz("America/Chicago"))
        .map_or_else(
            |_| format!("{ms} ms epoch"),
            |at| at.strftime("%Y-%m-%d %H:%M %Z").to_string(),
        )
}

/// Milliseconds as a short human duration
pub fn human_duration(ms: i64) -> String {
    let seconds = ms.max(0) / 1000;
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86400 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86400),
    }
}

/// Text for a Markdown table cell
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// Text inside single backticks
fn inline(text: &str) -> String {
    cell(text).replace('`', "'")
}

/// A fenced Python block whose fence the content cannot close
fn code_block(out: &mut String, code: &str) {
    let mut fence = "```".to_owned();
    while code.contains(&fence) {
        fence.push('`');
    }
    let _ = writeln!(out, "{fence}python\n{}\n{fence}\n", code.trim_end());
}
