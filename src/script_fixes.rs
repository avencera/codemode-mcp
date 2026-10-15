//! Harmless agent habits the host fixes before a script is checked
//!
//! `JsonValue` is predefined, but agents import it from `typing` out of habit;
//! the checker then reports a missing member and the sandbox fails the import,
//! costing a retry for nothing. The import is blanked instead, keeping every
//! line and column where it was so diagnostics still point at the agent's
//! source.

use std::borrow::Cow;

use ruff_python_ast::{
    Stmt, StmtImportFrom,
    visitor::{Visitor, walk_stmt},
};
use ruff_python_parser::parse_module;
use ruff_text_size::{Ranged, TextRange, TextSize};

use crate::{bans::on_parser_stack, stubs::JSON_VALUE};

/// `source` with every `from typing import JsonValue` taken out
///
/// An aliased import (`as J`) is kept, since the script uses the alias. A
/// script that does not parse is returned as is; the checker reports it
pub fn apply(source: &str) -> Cow<'_, str> {
    let edits = on_parser_stack(|| edits(source)).unwrap_or_default();
    if edits.is_empty() {
        return Cow::Borrowed(source);
    }

    Cow::Owned(rewrite(source, &edits))
}

/// A span to blank, optionally starting with `pass` so a statement that
/// disappears entirely still leaves a statement behind
#[derive(Debug, Clone, Copy)]
struct Edit {
    range: TextRange,
    pass: bool,
}

fn edits(source: &str) -> Vec<Edit> {
    let Ok(parsed) = parse_module(source) else {
        return Vec::new();
    };
    let mut finder = Finder::default();
    for statement in &parsed.syntax().body {
        finder.visit_stmt(statement);
    }

    finder.edits
}

#[derive(Default)]
struct Finder {
    edits: Vec<Edit>,
}

impl Finder {
    fn import_from(&mut self, import: &StmtImportFrom) {
        let from_typing = import.level == 0
            && import
                .module
                .as_ref()
                .is_some_and(|module| matches!(module.as_str(), "typing" | "typing_extensions"));
        if !from_typing {
            return;
        }

        let predefined: Vec<bool> = import
            .names
            .iter()
            .map(|alias| {
                alias.name.as_str() == JSON_VALUE
                    && alias
                        .asname
                        .as_ref()
                        .is_none_or(|bound| bound.as_str() == JSON_VALUE)
            })
            .collect();
        if !predefined.contains(&true) {
            return;
        }
        if predefined.iter().all(|taken| *taken) {
            self.edits.push(Edit {
                range: import.range(),
                pass: true,
            });

            return;
        }

        for (position, alias) in import.names.iter().enumerate() {
            if !predefined[position] {
                continue;
            }
            // the comma goes with the name: the one before it, or for the
            // first name the one after
            let range = match position.checked_sub(1) {
                Some(before) => TextRange::new(import.names[before].end(), alias.end()),
                None => TextRange::new(alias.start(), import.names[1].start()),
            };
            self.edits.push(Edit { range, pass: false });
        }
    }
}

impl<'a> Visitor<'a> for Finder {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        if let Stmt::ImportFrom(import) = stmt {
            self.import_from(import);
        }
        walk_stmt(self, stmt);
    }
}

/// Replaces each edited span with spaces, keeping line breaks and the
/// backslash of a line continuation so nothing after it moves or rejoins
fn rewrite(source: &str, edits: &[Edit]) -> String {
    let mut out = String::with_capacity(source.len());
    let mut cursor = TextSize::from(0);
    let mut sorted = edits.to_vec();
    sorted.sort_by_key(|edit| edit.range.start());

    for edit in sorted {
        let start = edit.range.start().max(cursor);
        if start >= edit.range.end() {
            continue;
        }
        out.push_str(&source[TextRange::new(cursor, start)]);

        let span = &source[TextRange::new(start, edit.range.end())];
        let mut blanked = String::with_capacity(span.len());
        let mut characters = span.chars().peekable();
        while let Some(character) = characters.next() {
            let continuation = character == '\\' && matches!(characters.peek(), Some('\n' | '\r'));
            if matches!(character, '\n' | '\r') || continuation {
                blanked.push(character);
            } else {
                blanked.push(' ');
            }
        }
        if edit.pass {
            blanked.replace_range(..4, "pass");
        }
        out.push_str(&blanked);
        cursor = edit.range.end();
    }
    out.push_str(&source[usize::from(cursor)..]);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predefined_imports_are_blanked_in_place() {
        let cases = [
            (
                "from typing import JsonValue\nx: JsonValue = 1\nx",
                "pass                        \nx: JsonValue = 1\nx",
            ),
            (
                "from typing import Literal, JsonValue\nx = 1",
                "from typing import Literal           \nx = 1",
            ),
            (
                "from typing import JsonValue, Literal\nx = 1",
                "from typing import            Literal\nx = 1",
            ),
            (
                "from typing import (\n    Literal,\n    JsonValue,\n)\nx = 1",
                "from typing import (\n    Literal \n             ,\n)\nx = 1",
            ),
            (
                "from typing import Literal, \\\n    JsonValue\nx = 1",
                "from typing import Literal  \\\n             \nx = 1",
            ),
            (
                "if True:\n    from typing import JsonValue\nx = 1",
                "if True:\n    pass                        \nx = 1",
            ),
            (
                "from typing_extensions import JsonValue\nx = 1",
                "pass                                   \nx = 1",
            ),
            (
                "import re; from typing import JsonValue; x = 1",
                "import re; pass                        ; x = 1",
            ),
        ];
        for (script, expected) in cases {
            assert_eq!(apply(script), expected, "{script}");
            assert!(parse_module(&apply(script)).is_ok(), "{script}");
        }
    }

    #[test]
    fn other_imports_and_aliases_are_left_alone() {
        for script in [
            "from typing import JsonValue as J\nx: J = 1",
            "from typing_extensions import Literal\nx = 1",
            "from mod import JsonValue\nx = 1",
            "x = \"from typing import JsonValue\"",
            "from typing import (\n",
        ] {
            assert!(matches!(apply(script), Cow::Borrowed(_)), "{script}");
        }
    }
}
