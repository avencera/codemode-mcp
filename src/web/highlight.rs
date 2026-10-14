//! Syntax highlighting for the script and arguments on the approval page
//!
//! Highlighting happens here rather than in the browser so the page keeps its
//! script-free rendering and its strict content security policy. Every
//! character of the input is emitted exactly once, escaped and in order, so
//! the colors can never hide or reorder what the approver reads

use ruff_python_ast::{PySourceType, token::TokenKind};
use ruff_python_parser::parse_unchecked_source;
use ruff_text_size::Ranged;

use super::escape;
use crate::bans::on_parser_stack;

/// A Python script as escaped HTML with `<span>` classes for the page's palette
///
/// Uses the sandbox's own parser, so strings, f-strings and comments split
/// where Monty splits them. Falls back to plain escaped text when no parser
/// thread can be started
pub fn python(source: &str) -> String {
    on_parser_stack(|| python_here(source)).unwrap_or_else(|| escape(source))
}

fn python_here(source: &str) -> String {
    // unchecked so a script with a syntax error is still colored up to it;
    // the parser, unlike the bare lexer, turns soft keywords used as names
    // back into names
    let parsed = parse_unchecked_source(source, PySourceType::Python);
    let tokens = parsed.tokens();
    let mut html = Spans::new(source);
    let mut previous = TokenKind::Unknown;
    for (index, token) in tokens.iter().enumerate() {
        let kind = token.kind();
        let next = tokens.get(index + 1).map(|next| next.kind());
        let class = match kind {
            TokenKind::Comment => Some("com"),
            TokenKind::String
            | TokenKind::FStringStart
            | TokenKind::FStringMiddle
            | TokenKind::FStringEnd
            | TokenKind::TStringStart
            | TokenKind::TStringMiddle
            | TokenKind::TStringEnd => Some("str"),
            TokenKind::Int | TokenKind::Float | TokenKind::Complex => Some("num"),
            TokenKind::True | TokenKind::False | TokenKind::None => Some("lit"),
            TokenKind::Name if matches!(previous, TokenKind::Def | TokenKind::Class) => Some("def"),
            TokenKind::Name if next == Some(TokenKind::Lpar) => Some("call"),
            kind if kind.is_keyword() => Some("kw"),
            _ => None,
        };
        if let Some(class) = class {
            html.span(token.start().to_usize(), token.end().to_usize(), class);
        }
        if !kind.is_trivia() {
            previous = kind;
        }
    }

    html.finish()
}

/// Pretty-printed JSON as escaped HTML with `<span>` classes
///
/// Expects `serde_json` output, so it only tells keys, strings, numbers and
/// literals apart; anything else passes through uncolored
pub fn json(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut html = Spans::new(source);
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let start = index;
        match byte {
            b'"' => {
                index += 1;
                while let Some(&byte) = bytes.get(index) {
                    match byte {
                        b'"' => break,
                        b'\\' => index += 2,
                        _ => index += 1,
                    }
                }
                index = (index + 1).min(bytes.len());
                let key = source
                    .get(index..)
                    .is_some_and(|rest| rest.trim_start().starts_with(':'));
                html.span(start, index, if key { "key" } else { "str" });
            }
            b'-' | b'0'..=b'9' => {
                while bytes.get(index).is_some_and(|byte| {
                    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                }) {
                    index += 1;
                }
                html.span(start, index, "num");
            }
            b't' | b'f' | b'n' => {
                while bytes.get(index).is_some_and(u8::is_ascii_alphabetic) {
                    index += 1;
                }
                html.span(start, index, "lit");
            }
            _ => index += 1,
        }
    }

    html.finish()
}

/// Escaped HTML built from `source` and the byte ranges to wrap in spans
struct Spans<'a> {
    source: &'a str,
    out: String,
    /// Bytes of `source` before this are already in `out`
    cursor: usize,
}

impl<'a> Spans<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            out: String::with_capacity(source.len() * 2),
            cursor: 0,
        }
    }

    /// Wraps `start..end` in a span; a range that overlaps text already
    /// written or does not fall on character boundaries stays plain
    fn span(&mut self, start: usize, end: usize, class: &str) {
        if start < self.cursor || start >= end {
            return;
        }
        let (Some(gap), Some(text)) = (
            self.source.get(self.cursor..start),
            self.source.get(start..end),
        ) else {
            return;
        };

        self.out.push_str(&escape(gap));
        self.out.push_str(&format!(r#"<span class="{class}">"#));
        self.out.push_str(&escape(text));
        self.out.push_str("</span>");
        self.cursor = end;
    }

    fn finish(mut self) -> String {
        self.out
            .push_str(&escape(self.source.get(self.cursor..).unwrap_or_default()));

        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::{json, python};

    /// The text a browser shows for highlighted HTML
    fn shown(html: &str) -> String {
        let mut text = String::new();
        let mut rest = html;
        while let Some(open) = rest.find('<') {
            text.push_str(&rest[..open]);
            let close = rest[open..]
                .find('>')
                .map_or(rest.len(), |close| open + close + 1);
            rest = &rest[close..];
        }
        text.push_str(rest);

        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&")
    }

    #[test]
    fn python_shows_every_character_and_colors_tokens() {
        let source = concat!(
            "import json  # <script>alert(1)</script>\n",
            "@cache\n",
            "async def run(match: str, type=None) -> dict:\n",
            "    '''doc \"quote\" # not a comment'''\n",
            "    x = f\"{match!r:>{10}} {'nested'} \\\" é\" + rb'\\'' + 0x1F + 1.5j\n",
            "    return await tool(q=x, ok=True)\n",
            "bad = 'unterminated\n",
            "\t)(\n",
        );

        let html = python(source);

        assert_eq!(shown(&html), source);
        assert!(!html.contains("<script>"), "{html}");
        assert!(
            html.contains(r#"<span class="com"># &lt;script&gt;alert(1)&lt;/script&gt;</span>"#),
            "{html}"
        );
        assert!(html.contains(r#"<span class="kw">async</span>"#), "{html}");
        assert!(html.contains(r#"<span class="def">run</span>"#), "{html}");
        assert!(html.contains(r#"<span class="call">tool</span>"#), "{html}");
        assert!(html.contains(r#"<span class="lit">True</span>"#), "{html}");
        assert!(html.contains(r#"<span class="num">0x1F</span>"#), "{html}");
        // soft keywords used as names stay names
        assert!(!html.contains(r#"<span class="kw">match</span>"#), "{html}");
        assert!(!html.contains(r#"<span class="kw">type</span>"#), "{html}");
        assert!(
            html.contains(r#"<span class="str">&#39;&#39;&#39;doc &quot;quote&quot; # not a comment&#39;&#39;&#39;</span>"#),
            "{html}"
        );
    }

    #[test]
    fn json_shows_every_character_and_colors_tokens() {
        let source = serde_json::to_string_pretty(&serde_json::json!({
            "q": "a \"quoted\" <b>: é",
            "n": -1.5e3,
            "list": [true, false, null, 12345678901234567890u64],
            "nested": { "k:": "v" },
        }))
        .unwrap_or_default();

        let html = json(&source);

        assert_eq!(shown(&html), source);
        assert!(!html.contains("<b>"), "{html}");
        assert!(
            html.contains(r#"<span class="key">&quot;k:&quot;</span>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="str">&quot;v&quot;</span>"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="num">-1500.0</span>"#),
            "{html}"
        );
        assert!(html.contains(r#"<span class="lit">null</span>"#), "{html}");
    }
}
