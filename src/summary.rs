//! One-line summaries of a tool call's arguments for the Touch ID prompt
//!
//! A fingerprint approves without the approval page, so the prompt is all
//! the owner sees. Summaries are built from the argument values, never
//! written by a model, so an agent cannot word its way past them. A tool may
//! set a `summary` template in its config; any argument the template leaves
//! out is still named, so a template cannot hide one

use serde_json::{Map, Value};

/// Longest generic summary, before `+N more`
const SUMMARY_CHARS: usize = 200;
/// Longest rendered template; a piece past it is left out and its argument
/// named after the template
const TEMPLATE_CHARS: usize = 300;
/// Longest string argument shown whole; a longer one is cut and sized
const STRING_CHARS: usize = 40;
/// Characters kept of a string that is cut
const CUT_STRING_CHARS: usize = 30;
/// Object keys named before the rest are elided
const OBJECT_KEYS: usize = 3;

/// Why a summary template is unusable
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// A `{` without its `}`
    #[error("`{{` at character {0} is not closed; write `{{{{` for a literal brace")]
    Unclosed(usize),
    /// A `}` without its `{`
    #[error("`}}` at character {0} closes nothing; write `}}}}` for a literal brace")]
    Unopened(usize),
    /// `{}` names no argument
    #[error("`{{}}` at character {0} names no argument")]
    Empty(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Argument(String),
}

/// A parsed `summary` template: text with `{argument}` placeholders, and
/// `{{` / `}}` for literal braces
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template(Vec<Piece>);

impl Template {
    /// Parses `text`
    pub fn parse(text: &str) -> Result<Self, TemplateError> {
        let mut pieces = Vec::new();
        let mut literal = String::new();
        let mut characters = text.chars().enumerate().peekable();
        while let Some((at, character)) = characters.next() {
            match character {
                '{' if characters.next_if(|(_, next)| *next == '{').is_some() => literal.push('{'),
                '}' if characters.next_if(|(_, next)| *next == '}').is_some() => literal.push('}'),
                '}' => return Err(TemplateError::Unopened(at)),
                '{' => {
                    let mut name = String::new();
                    loop {
                        match characters.next() {
                            Some((_, '}')) => break,
                            Some((_, '{')) | None => return Err(TemplateError::Unclosed(at)),
                            Some((_, character)) => name.push(character),
                        }
                    }
                    let name = name.trim().to_owned();
                    if name.is_empty() {
                        return Err(TemplateError::Empty(at));
                    }
                    if !literal.is_empty() {
                        pieces.push(Piece::Text(std::mem::take(&mut literal)));
                    }
                    pieces.push(Piece::Argument(name));
                }
                other => literal.push(other),
            }
        }
        if !literal.is_empty() {
            pieces.push(Piece::Text(literal));
        }

        Ok(Self(pieces))
    }

    /// The template filled from `arguments`, followed by the names of any
    /// arguments it does not show, including those cut off by the length
    /// limit and those passed as `null`
    pub fn render(&self, arguments: &Map<String, Value>) -> String {
        let mut rendered = String::new();
        let mut shown: Vec<&str> = Vec::new();
        for piece in &self.0 {
            let (text, argument) = match piece {
                Piece::Text(text) => (text.clone(), None),
                Piece::Argument(name) => match arguments.get(name) {
                    Some(value) => (summarize_value(value), Some(name.as_str())),
                    None => ("none".to_owned(), None),
                },
            };
            if rendered.chars().count() + text.chars().count() > TEMPLATE_CHARS {
                rendered.push('…');

                break;
            }
            rendered.push_str(&text);
            shown.extend(argument);
        }

        let unshown: Vec<String> = arguments
            .keys()
            .filter(|name| !shown.contains(&name.as_str()))
            .map(|name| argument_name(name))
            .collect();
        if !unshown.is_empty() {
            rendered.push_str(" (also ");
            rendered.push_str(&unshown.join(", "));
            rendered.push(')');
        }

        rendered
    }
}

/// Text of the Touch ID prompt for one call of `waiting_for` by the client
/// labelled `client`, with `details` from a template or
/// [`summarize_arguments`]
///
/// Every part an agent can choose (the client label, argument names and
/// values) goes through [`printable`], and the self-reported client label is
/// quoted, so none of it can pass for text of the prompt itself
pub fn prompt_text(waiting_for: &str, client: &str, details: Option<&str>) -> String {
    let mut text = format!(
        "approve one call of {} by client {}",
        printable(waiting_for, 80),
        quoted(client, 40)
    );
    if let Some(details) = details.filter(|details| !details.is_empty()) {
        text.push_str(": ");
        text.push_str(details);
    }

    text
}

/// One `name: value` per argument: short values whole, long strings cut
/// with their length, lists and objects by size and keys
pub fn summarize_arguments(arguments: &Map<String, Value>) -> String {
    let mut summary = String::new();
    for (index, (name, value)) in arguments.iter().enumerate() {
        let part = format!("{}: {}", argument_name(name), summarize_value(value));
        if !summary.is_empty() && summary.chars().count() + part.chars().count() > SUMMARY_CHARS {
            summary.push_str(&format!(", +{} more", arguments.len() - index));

            break;
        }
        if !summary.is_empty() {
            summary.push_str(", ");
        }
        summary.push_str(&part);
    }

    summary
}

fn summarize_value(value: &Value) -> String {
    match value {
        Value::String(text) => {
            let length = text.chars().count();
            if length <= STRING_CHARS {
                quoted(text, STRING_CHARS)
            } else {
                format!("{}… ({length} chars)", quoted(text, CUT_STRING_CHARS))
            }
        }
        Value::Array(items) => match items.len() {
            1 => "1 item".to_owned(),
            count => format!("{count} items"),
        },
        Value::Object(fields) => {
            let mut keys: Vec<String> = fields
                .keys()
                .take(OBJECT_KEYS)
                .map(|key| argument_name(key))
                .collect();
            if fields.len() > OBJECT_KEYS {
                keys.push("…".to_owned());
            }
            format!("{{{}}}", keys.join(", "))
        }
        other => printable(&other.to_string(), STRING_CHARS),
    }
}

/// An argument or key name: bare when it is a plain identifier, quoted
/// otherwise, so a name cannot carry punctuation that reads as a value
fn argument_name(name: &str) -> String {
    let plain = !name.is_empty()
        && name.chars().count() <= 30
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character));
    if plain {
        name.to_owned()
    } else {
        quoted(name, 30)
    }
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

/// The first `limit` characters with line breaks shown as `⏎` and other
/// control, invisible and direction-changing characters as `?`, so the text
/// stays on one line and reads in the order it is stored
fn printable(text: &str, limit: usize) -> String {
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
    use serde_json::{Map, Value, json};

    use super::{Template, TemplateError, prompt_text, summarize_arguments};

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn summaries_show_short_values_and_size_long_ones() {
        assert_eq!(
            summarize_arguments(&object(
                json!({ "to": "ana@example.com", "count": 3, "dry_run": false })
            )),
            r#"count: 3, dry_run: false, to: "ana@example.com""#
        );
        assert_eq!(
            summarize_arguments(&object(json!({
                "body": "x".repeat(500),
                "cc": ["a", "b"],
                "meta": { "a": 1, "b": 2, "c": 3, "d": 4 },
            }))),
            r#"body: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"… (500 chars), cc: 2 items, meta: {a, b, c, …}"#
        );
    }

    #[test]
    fn summaries_cannot_fake_prompt_text() {
        assert_eq!(
            summarize_arguments(&object(
                json!({ "note": "ok\nApprove \u{202e}all\u{2028}x" })
            )),
            r#"note: "ok⏎Approve ?all⏎x""#
        );
        // a value cannot close its quotes, and a name cannot carry punctuation
        assert_eq!(
            summarize_arguments(&object(json!({ "note": "\" (dry run) \"", "a\": \"b": 1 }))),
            r#""a\": \"b": 1, note: "\" (dry run) \"""#
        );
        assert_eq!(
            prompt_text("mail.send", "evil\u{202e}tneilc", None),
            r#"approve one call of mail.send by client "evil?tneilc""#
        );
    }

    #[test]
    fn long_summaries_count_what_they_leave_out() {
        let arguments: Map<String, Value> = (0..20)
            .map(|index| (format!("field{index:02}"), json!("a value of some length")))
            .collect();
        let text = summarize_arguments(&arguments);

        assert!(text.chars().count() < 230, "{text}");
        assert!(text.ends_with(", +15 more"), "{text}");
    }

    #[test]
    fn templates_fill_placeholders_and_name_what_they_leave_out() -> Result<(), TemplateError> {
        let template = Template::parse("send to {to}: {subject} {{draft}}")?;
        let arguments = object(json!({
            "to": "ana@example.com",
            "subject": "Q3",
            "bcc": "boss@example.com",
            "thread": null,
        }));

        // `thread: null` may mean "clear it", so it is named like any other
        assert_eq!(
            template.render(&arguments),
            r#"send to "ana@example.com": "Q3" {draft} (also bcc, thread)"#
        );
        assert_eq!(
            template.render(&object(json!({ "to": "ana@example.com" }))),
            r#"send to "ana@example.com": none {draft}"#
        );

        Ok(())
    }

    #[test]
    fn arguments_cut_off_by_the_length_limit_are_named() -> Result<(), TemplateError> {
        let template = Template::parse("{a} {b} {c} {d} {e} {f} {g} {h} -> {destination}")?;
        let mut arguments: Map<String, Value> = ["a", "b", "c", "d", "e", "f", "g", "h"]
            .iter()
            .map(|name| ((*name).to_owned(), json!("y".repeat(40))))
            .collect();
        arguments.insert("destination".to_owned(), json!("attacker@example.com"));
        let rendered = template.render(&arguments);

        assert!(rendered.ends_with("(also destination, h)"), "{rendered}");
        assert!(!rendered.contains("attacker"), "{rendered}");

        Ok(())
    }

    #[test]
    fn malformed_templates_are_refused() {
        assert_eq!(Template::parse("to {to"), Err(TemplateError::Unclosed(3)));
        assert_eq!(Template::parse("to }"), Err(TemplateError::Unopened(3)));
        assert_eq!(Template::parse("to { }"), Err(TemplateError::Empty(3)));
        assert_eq!(Template::parse("{a{b}"), Err(TemplateError::Unclosed(0)));
    }
}
