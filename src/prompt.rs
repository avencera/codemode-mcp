//! Text of the Touch ID prompt that approves a tool call at the Mac
//!
//! A fingerprint approves without the approval page, so the prompt is all
//! the owner reads. It names the tool and the grant, which the daemon
//! knows, and the client, thread and reason, which the agent supplies. The
//! agent's parts are quoted and stripped of characters that could make them
//! read as the daemon's own text

/// Longest thread title shown
pub const THREAD_CHARS: usize = 60;
/// Longest reason shown
pub const REASON_CHARS: usize = 160;
/// Longest destination shown
const DESTINATION_CHARS: usize = 256;
/// Longest client name shown
const CLIENT_CHARS: usize = 40;
/// Longest tool name shown
const TOOL_CHARS: usize = 80;

/// What the agent said about a call, all optional
#[derive(Debug, Clone, Copy, Default)]
pub struct Asker<'a> {
    /// Client name the agent's app reported
    pub client: &'a str,
    /// Title of the agent's thread or task
    pub thread: Option<&'a str>,
    /// Why the agent wants the call
    pub reason: Option<&'a str>,
}

/// Text of the Touch ID prompt approving `calls` (each tool with how many
/// of its calls one decision answers) with `grant` (such as `once` or `and
/// all fixture tools not marked per-call, for 60 min`), asked for by `asker`
///
/// macOS shows it as "codemode-mcp is trying to …", so it starts with a verb
pub fn prompt_text(calls: &[(String, usize)], grant: &str, asker: Asker<'_>) -> String {
    let mut text = format!(
        "approve {} {grant}, asked by {}",
        calls_text(calls),
        quoted(asker.client, CLIENT_CHARS)
    );
    if let Some(thread) = asker.thread.filter(|thread| !thread.trim().is_empty()) {
        text.push_str(" in ");
        text.push_str(&quoted(thread.trim(), THREAD_CHARS));
    }
    match asker.reason.filter(|reason| !reason.trim().is_empty()) {
        Some(reason) => {
            text.push_str(": ");
            text.push_str(&quoted(reason.trim(), REASON_CHARS));
        }
        None => text.push_str(", no reason given"),
    }

    text
}

/// What a program-read prompt names
#[derive(Debug, Clone, Copy)]
pub struct ProgramPrompt<'a> {
    /// The references, all shown whole
    pub items: &'a [String],
    /// Where the program runs, such as `this Mac` or `main`
    pub place: &'a str,
    /// Why, in the program's words
    pub reason: Option<&'a str>,
    /// Where the values go, such as a file path
    pub destination: Option<&'a str>,
    /// How long the gateway may hand them out again without asking
    pub keep_secs: Option<u64>,
}

/// Text of the Touch ID prompt approving a program read
///
/// macOS shows it as "codemode-mcp is trying to …", so it starts with a verb.
/// Every reference is shown whole, since one fingerprint releases each of
/// them; they are checked references, one line each. The reason and the
/// destination are the program's claims and are quoted
pub fn program_prompt_text(prompt: &ProgramPrompt<'_>) -> String {
    let items = prompt.items;
    let shown: Vec<String> = items
        .iter()
        .map(|item| one_line(item, usize::MAX))
        .collect();
    let noun = if items.len() == 1 { "value" } else { "values" };
    let mut text = format!(
        "send {} 1Password {noun} to a program on {}",
        items.len(),
        prompt.place
    );
    if let Some(destination) = prompt.destination.filter(|text| !text.trim().is_empty()) {
        text.push_str(" for ");
        text.push_str(&quoted(destination.trim(), DESTINATION_CHARS));
    }
    text.push_str(": ");
    text.push_str(&shown.join(", "));
    match prompt.reason.filter(|reason| !reason.trim().is_empty()) {
        Some(reason) => {
            text.push_str(", for ");
            text.push_str(&quoted(reason.trim(), REASON_CHARS));
        }
        None => text.push_str(", no reason given"),
    }
    if let Some(keep_secs) = prompt.keep_secs {
        // a grant answers only reads for the same destination
        let place = if prompt.destination.is_some() {
            " for the same destination"
        } else {
            ""
        };
        text.push_str(&format!(
            ", and again{place} without asking for {} min",
            keep_secs.div_ceil(60)
        ));
    }

    text
}

/// Text of the Touch ID prompt for a program's find at `place`: every query
/// and the reason quoted, as the program's claims
pub fn find_prompt_text(queries: &[String], place: &str, reason: Option<&str>) -> String {
    let queries: Vec<String> = queries
        .iter()
        .map(|query| quoted(query.trim(), REASON_CHARS))
        .collect();
    let mut text = format!(
        "show a program on {place} which 1Password items match {}, with their references but \
         no values",
        queries.join(" or ")
    );
    match reason.filter(|reason| !reason.trim().is_empty()) {
        Some(reason) => {
            text.push_str(", for ");
            text.push_str(&quoted(reason.trim(), REASON_CHARS));
        }
        None => text.push_str(", no reason given"),
    }

    text
}

/// The tools of a batch, such as `calendar.delete_event ×3,
/// reminders.delete_reminder`; a count shows only when it is above one
pub fn calls_text(calls: &[(String, usize)]) -> String {
    calls
        .iter()
        .map(|(tool, count)| {
            let tool = printable(tool, TOOL_CHARS);
            match count {
                1 => tool,
                count => format!("{tool} ×{count}"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The first `limit` characters in double quotes, with quotes and
/// backslashes escaped, so the text cannot close its quotes and continue as
/// prompt text
fn quoted(text: &str, limit: usize) -> String {
    let mut quoted = String::from("\"");
    for character in printable(text, limit).chars() {
        if matches!(character, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');

    quoted
}

/// The first `limit` characters, cut with `…`, as [`one_line`] shows them
fn printable(text: &str, limit: usize) -> String {
    let mut shown = one_line(text, limit);
    if text.chars().nth(limit).is_some() {
        shown.push('…');
    }

    shown
}

/// The first `limit` characters with line breaks shown as `⏎` and other
/// control, invisible and direction-changing characters as `?`, so the text
/// stays on one line and reads in the order it is stored
pub fn one_line(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .map(|character| match character {
            '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}' => '⏎',
            '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' => '?',
            other if other.is_control() => '?',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Asker, prompt_text};

    #[test]
    fn prompts_name_the_grant_thread_and_reason() {
        assert_eq!(
            prompt_text(
                &[("onepassword.list_environments".to_owned(), 1)],
                "for 60 min",
                Asker {
                    client: "claude-code",
                    thread: Some("Fix Mac approval flow"),
                    reason: Some("list env names for .env"),
                },
            ),
            r#"approve onepassword.list_environments for 60 min, asked by "claude-code" in "Fix Mac approval flow": "list env names for .env""#
        );
        assert_eq!(
            prompt_text(
                &[("fixture.add".to_owned(), 1)],
                "once",
                Asker {
                    client: "codex",
                    ..Asker::default()
                }
            ),
            r#"approve fixture.add once, asked by "codex", no reason given"#
        );
    }

    #[test]
    fn agent_text_cannot_pass_for_prompt_text() {
        let text = prompt_text(
            &[("mail.send".to_owned(), 1)],
            "once",
            Asker {
                client: "evil\u{202e}tneilc",
                thread: Some("t\" for 1 min, asked by \"you"),
                reason: Some("ok\nApprove \u{2028}all"),
            },
        );

        assert_eq!(
            text,
            r#"approve mail.send once, asked by "evil?tneilc" in "t\" for 1 min, asked by \"you": "ok⏎Approve ⏎all""#
        );
    }

    #[test]
    fn long_reasons_are_cut_and_marked() {
        let text = prompt_text(
            &[("fixture.add".to_owned(), 1)],
            "once",
            Asker {
                client: "codex",
                thread: None,
                reason: Some(&"x".repeat(500)),
            },
        );

        assert!(text.ends_with(&format!("{}…\"", "x".repeat(160))), "{text}");
    }
}
