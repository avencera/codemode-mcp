//! Whether the type rules are too strict or not strict enough
//!
//! Strictness exists so agents make fewer mistakes with fewer wasted turns.
//! Two families of signals say when it misses: type errors that agents do
//! not get past and schemas that reject real data say the rules are too
//! strict; runtime errors, probe executes and parsing JSON text say they are
//! too loose. The verdict compares both against the thresholds below, which
//! `docs/design.md` explains

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;

use serde::Serialize;
use turso::params;

use super::{Attempt, Reporter, TOP_ROWS, cell, inline, percent};
use crate::{
    script_shape::{is_probe, parses_json_text},
    usage::EXEC_CLIENT,
};

/// Fewest errors of one rule before its unresolved share says anything
pub const MIN_RULE_ERRORS: i64 = 5;
/// Share of a rule's errors the next execute did not fix, from which the
/// rule looks too strict
pub const UNRESOLVED_SHARE_LIMIT: f64 = 0.4;
/// Fewest runs that hit a type error before the abandoned share says anything
pub const MIN_ERROR_RUNS: i64 = 5;
/// Share of runs with a type error that never succeeded afterwards, from
/// which the rules look too strict
pub const ABANDONED_SHARE_LIMIT: f64 = 0.3;
/// `output_mismatch` calls of one tool from which its schema looks wrong
pub const MISMATCH_LIMIT: i64 = 3;
/// Executes that only look at a tool's result, from which typing looks too loose
pub const PROBE_LIMIT: i64 = 5;
/// Runtime errors typing should have caught, from which typing looks too loose
pub const RUNTIME_ERROR_LIMIT: i64 = 5;
/// Scripts parsing JSON text, from which typing looks too loose
pub const JSON_TEXT_LIMIT: i64 = 5;
/// Untyped tools named in the verdict
const VERDICT_TOOLS: usize = 3;

/// Exceptions a typed result would have made impossible
const TYPED_EXCEPTIONS: [&str; 3] = ["KeyError", "TypeError", "AttributeError"];

/// Type errors of one rule
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleStats {
    /// ty rule name, or `ban:any`, `ban:cast`, `ban:type-ignore`
    pub rule: String,
    /// Type errors that reported the rule
    pub errors: i64,
    /// Errors after which the next execute of the run no longer reported it
    pub resolved: i64,
}

impl RuleStats {
    /// Errors the next execute did not fix, including those that ended the run
    pub fn unresolved(&self) -> i64 {
        self.errors - self.resolved
    }

    /// Share of errors left unresolved
    pub fn unresolved_share(&self) -> f64 {
        self.unresolved() as f64 / self.errors.max(1) as f64
    }
}

/// Strictness signals of one client
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClientStrictness {
    /// Client name
    pub client: String,
    /// Finished executions
    pub executions: i64,
    /// Type errors per rule, most frequent first
    pub rules: Vec<RuleStats>,
    /// Runs with at least one type error
    pub error_runs: i64,
    /// Of those, runs with no successful execute after their last type error
    pub abandoned_runs: i64,
    /// `output_mismatch` calls per `<server>.<tool>`, most frequent first
    pub mismatches: Vec<(String, i64)>,
    /// Runtime errors typing should have caught
    pub typed_runtime_errors: i64,
    /// Executes that only call tools and return the result as is
    pub probes: i64,
    /// Scripts that parse JSON text with `json.loads` or `json_parse`
    pub json_text: i64,
    /// Calls to tools that return a `JsonValue`, most frequent first
    pub untyped_calls: Vec<(String, i64)>,
}

impl ClientStrictness {
    /// Share of runs with a type error that never recovered
    pub fn abandoned_share(&self) -> Option<f64> {
        (self.error_runs > 0).then(|| self.abandoned_runs as f64 / self.error_runs as f64)
    }
}

/// Strictness signals per client, with the verdict over all of them
#[derive(Debug, Clone, Default, Serialize)]
pub struct Strictness {
    /// Per client, most executions first
    pub clients: Vec<ClientStrictness>,
    /// One line: too strict, too loose, mixed or fine
    pub verdict: String,
}

impl Reporter<'_> {
    /// The strictness signals over the window
    pub(super) fn strictness(&self) -> Result<Strictness, turso::Error> {
        let tools = self.called_functions()?;
        let mut clients: BTreeMap<String, ClientStrictness> = BTreeMap::new();
        let mut rules: HashMap<(String, String), RuleStats> = HashMap::new();

        for sequence in self.attempts()?.values() {
            let Some(first) = sequence.first() else {
                continue;
            };
            let entry = clients.entry(first.client.clone()).or_default();
            entry.client.clone_from(&first.client);
            entry.executions += sequence.len() as i64;

            for (index, attempt) in sequence.iter().enumerate() {
                if attempt.outcome == "type_error" {
                    let next = sequence.get(index + 1);
                    for rule in type_error_rules(attempt) {
                        let stats = rules
                            .entry((first.client.clone(), rule.clone()))
                            .or_insert_with(|| RuleStats {
                                rule,
                                ..RuleStats::default()
                            });
                        stats.errors += 1;
                        stats.resolved += i64::from(next.is_some_and(|next| {
                            next.outcome != "type_error"
                                || !type_error_rules(next).contains(&stats.rule)
                        }));
                    }
                }
                if attempt.outcome == "runtime_error" && catchable_by_types(attempt) {
                    entry.typed_runtime_errors += 1;
                }
                if attempt.outcome == "ok" && is_probe(&attempt.script, &tools) {
                    entry.probes += 1;
                }
                if parses_json_text(&attempt.script) {
                    entry.json_text += 1;
                }
            }

            let last_error = sequence
                .iter()
                .rposition(|attempt| attempt.outcome == "type_error");
            if let Some(last_error) = last_error {
                entry.error_runs += 1;
                let recovered = sequence[last_error + 1..]
                    .iter()
                    .any(|attempt| attempt.outcome == "ok");
                entry.abandoned_runs += i64::from(!recovered);
            }
        }

        for ((client, _), stats) in rules {
            clients.entry(client).or_default().rules.push(stats);
        }
        for (client, tool, count) in self.mismatches()? {
            clients
                .entry(client)
                .or_default()
                .mismatches
                .push((tool, count));
        }
        for (client, tool, count) in self.untyped_calls()? {
            clients
                .entry(client)
                .or_default()
                .untyped_calls
                .push((tool, count));
        }

        let mut clients: Vec<ClientStrictness> = clients
            .into_iter()
            .map(|(name, mut client)| {
                client.client = name;
                client.rules.sort_by(|left, right| {
                    right
                        .errors
                        .cmp(&left.errors)
                        .then_with(|| left.rule.cmp(&right.rule))
                });
                client.mismatches.sort_by(by_count);
                client.untyped_calls.sort_by(by_count);

                client
            })
            .collect();
        clients.sort_by_key(|client| std::cmp::Reverse(client.executions));
        let verdict = verdict(&clients);

        Ok(Strictness { clients, verdict })
    }

    /// Python names of the tools called in the window
    fn called_functions(&self) -> Result<HashSet<String>, turso::Error> {
        let functions: Vec<String> = self.connection.query_map(
            "SELECT DISTINCT function FROM upstream_calls WHERE at_ms >= ?1",
            params![self.since_ms],
            |row| row.get(0),
        )?;

        Ok(functions.into_iter().collect())
    }

    /// `(client, tool, calls)` of results that broke their schema
    fn mismatches(&self) -> Result<Vec<(String, String, i64)>, turso::Error> {
        self.tool_counts("u.outcome = 'output_mismatch'")
    }

    /// `(client, tool, calls)` of tools whose results reach scripts as a
    /// `JsonValue`
    fn untyped_calls(&self) -> Result<Vec<(String, String, i64)>, turso::Error> {
        self.tool_counts("u.output = 'untyped'")
    }

    fn tool_counts(&self, condition: &str) -> Result<Vec<(String, String, i64)>, turso::Error> {
        let rows = self.connection.query_map(
            &format!(
                "SELECT COALESCE(e.client_name, 'unknown'), u.server || '.' || u.tool, COUNT(*) \
             FROM upstream_calls u LEFT JOIN executions e ON e.id = u.execution_id \
             WHERE u.at_ms >= ?1 AND e.client_name IS NOT ?2 AND {condition} \
             GROUP BY 1, 2"
            ),
            params![self.since_ms, EXEC_CLIENT],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        Ok(rows)
    }
}

fn by_count(left: &(String, i64), right: &(String, i64)) -> std::cmp::Ordering {
    right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
}

/// Rules a failed type check reported: the log keeps them as
/// `rule, rule: first message`
fn type_error_rules(attempt: &Attempt) -> Vec<String> {
    let Some(detail) = attempt.detail.as_deref() else {
        return Vec::new();
    };
    let rules = detail.split_once(": ").map_or(detail, |(rules, _)| rules);

    rules
        .split(", ")
        .filter(|rule| {
            !rule.is_empty()
                && rule
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "-_:".contains(character))
        })
        .map(str::to_owned)
        .collect()
}

/// Whether a runtime error is one a typed result would have prevented: a
/// wrong key, type or attribute on a tool result, or a message that names
/// a tool result
fn catchable_by_types(attempt: &Attempt) -> bool {
    let Some(detail) = attempt.detail.as_deref() else {
        return false;
    };
    let kind = detail.split(':').next().unwrap_or_default().trim();

    TYPED_EXCEPTIONS.contains(&kind) || detail.to_lowercase().contains("tool result")
}

/// One heuristic line over every client
fn verdict(clients: &[ClientStrictness]) -> String {
    if clients.iter().all(|client| client.executions == 0) {
        return "No executions in this window, so no verdict.".to_owned();
    }

    let mut strict = Vec::new();
    let mut rules: HashMap<&str, (i64, i64)> = HashMap::new();
    for stats in clients.iter().flat_map(|client| &client.rules) {
        let entry = rules.entry(stats.rule.as_str()).or_default();
        entry.0 += stats.errors;
        entry.1 += stats.unresolved();
    }
    let mut unresolved: Vec<(&str, f64)> = rules
        .into_iter()
        .filter(|(_, (errors, _))| *errors >= MIN_RULE_ERRORS)
        .map(|(rule, (errors, open))| (rule, open as f64 / errors as f64))
        .filter(|(_, share)| *share >= UNRESOLVED_SHARE_LIMIT)
        .collect();
    unresolved.sort_by(|left, right| right.1.total_cmp(&left.1).then(left.0.cmp(right.0)));
    if let Some((rule, share)) = unresolved.first() {
        strict.push(format!(
            "`{rule}` errors are {} unresolved",
            percent(Some(*share))
        ));
    }

    let error_runs: i64 = clients.iter().map(|client| client.error_runs).sum();
    let abandoned: i64 = clients.iter().map(|client| client.abandoned_runs).sum();
    if error_runs >= MIN_ERROR_RUNS && abandoned as f64 / error_runs as f64 >= ABANDONED_SHARE_LIMIT
    {
        strict.push(format!(
            "{} of runs with a type error were abandoned",
            percent(Some(abandoned as f64 / error_runs as f64))
        ));
    }
    let mut mismatches: HashMap<&str, i64> = HashMap::new();
    for (tool, count) in clients.iter().flat_map(|client| &client.mismatches) {
        *mismatches.entry(tool.as_str()).or_default() += count;
    }
    let worst = mismatches
        .into_iter()
        .filter(|(_, count)| *count >= MISMATCH_LIMIT)
        .max_by(|left, right| left.1.cmp(&right.1).then(right.0.cmp(left.0)));
    if let Some((tool, count)) = worst {
        strict.push(format!("`{tool}` broke its schema {count} times"));
    }

    let mut loose = Vec::new();
    let total = |pick: fn(&ClientStrictness) -> i64| clients.iter().map(pick).sum::<i64>();
    let probes = total(|client| client.probes);
    if probes >= PROBE_LIMIT {
        let mut untyped: HashMap<&str, i64> = HashMap::new();
        for (tool, count) in clients.iter().flat_map(|client| &client.untyped_calls) {
            *untyped.entry(tool.as_str()).or_default() += count;
        }
        let mut untyped: Vec<(&str, i64)> = untyped.into_iter().collect();
        untyped.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
        let names: Vec<String> = untyped
            .iter()
            .take(VERDICT_TOOLS)
            .map(|(tool, _)| format!("`{tool}`"))
            .collect();
        loose.push(if names.is_empty() {
            format!("{probes} probe executes")
        } else {
            format!("{probes} probe executes, top untyped: {}", names.join(", "))
        });
    }
    let runtime = total(|client| client.typed_runtime_errors);
    if runtime >= RUNTIME_ERROR_LIMIT {
        loose.push(format!(
            "{runtime} runtime errors typing should have caught"
        ));
    }
    let loads = total(|client| client.json_text);
    if loads >= JSON_TEXT_LIMIT {
        loose.push(format!("{loads} scripts parse JSON themselves"));
    }

    match (strict.is_empty(), loose.is_empty()) {
        (true, true) => "Looks balanced: no signal is over its threshold.".to_owned(),
        (false, true) => format!("Looks too strict: {}.", strict.join("; ")),
        (true, false) => format!("Looks too loose: {}.", loose.join("; ")),
        (false, false) => format!(
            "Mixed: too strict ({}) and too loose ({}).",
            strict.join("; "),
            loose.join("; ")
        ),
    }
}

/// The review's "Type strictness" section
pub(super) fn render_section(out: &mut String, strictness: &Strictness) {
    let _ = writeln!(out, "## Type strictness\n");
    if strictness.clients.is_empty() {
        let _ = writeln!(out, "{}\n", strictness.verdict);
        return;
    }
    let _ = writeln!(
        out,
        "A type error is resolved when the next execute of the run no longer reports its \
         rule. Thresholds are named constants in `usage/report/strictness.rs` and documented \
         in `docs/design.md`.\n"
    );

    for client in &strictness.clients {
        let _ = writeln!(out, "### {}\n", cell(&client.client));
        let _ = writeln!(out, "Too strict:\n");
        if client.rules.is_empty() {
            let _ = writeln!(out, "- No type errors.");
        } else {
            let _ = writeln!(
                out,
                "| Rule | Errors | Resolved by next execute | Unresolved |\n|---|---|---|---|"
            );
            for rule in client.rules.iter().take(TOP_ROWS) {
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} | {} |",
                    inline(&rule.rule),
                    rule.errors,
                    rule.resolved,
                    percent(Some(rule.unresolved_share())),
                );
            }
        }
        let _ = writeln!(
            out,
            "\n- Runs abandoned after a type error: {} of {} ({})",
            client.abandoned_runs,
            client.error_runs,
            percent(client.abandoned_share()),
        );
        let _ = writeln!(
            out,
            "- `output_mismatch` by tool: {}\n",
            list(&client.mismatches),
        );

        let _ = writeln!(out, "Not strict enough:\n");
        let _ = writeln!(
            out,
            "- Runtime errors typing should have caught: {}\n- Probe executes: {}\n- \
             Scripts parsing JSON text: {}\n- Calls to tools still returning `JsonValue`: {}\n",
            client.typed_runtime_errors,
            client.probes,
            client.json_text,
            list(&client.untyped_calls),
        );
    }
    let _ = writeln!(out, "**Verdict:** {}\n", strictness.verdict);
}

/// The strictness lines of the terminal `stats`
pub(super) fn render_text(out: &mut String, strictness: &Strictness) {
    let _ = writeln!(out, "\nType strictness: {}", strictness.verdict);
    for client in &strictness.clients {
        let type_errors: i64 = client.rules.iter().map(|rule| rule.errors).sum();
        let mismatches: i64 = client.mismatches.iter().map(|(_, count)| count).sum();
        let _ = writeln!(
            out,
            "  {}: {type_errors} type errors, {} runs abandoned after one, {mismatches} output \
             mismatches; {} typed runtime errors, {} probes, {} JSON text parses",
            client.client,
            client.abandoned_runs,
            client.typed_runtime_errors,
            client.probes,
            client.json_text,
        );
    }
}

/// `tool (n), tool (n)` or `none`
fn list(rows: &[(String, i64)]) -> String {
    if rows.is_empty() {
        return "none".to_owned();
    }

    rows.iter()
        .take(TOP_ROWS)
        .map(|(name, count)| format!("`{}` ({count})", inline(name)))
        .collect::<Vec<_>>()
        .join(", ")
}
