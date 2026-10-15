//! Escape hatches from the type checker that scripts may not use
//!
//! Tool results and parameters are typed so a script's mistakes surface
//! before it runs. `Any`, `cast` and `# type: ignore` each switch that off
//! for a value, and an agent that is cornered by a type error reaches for
//! them first, so they are refused before the checker runs. `json.loads` is
//! refused too: it returns `Any`, and `json_parse` does the same job typed. The script is
//! read with the parser Monty uses, which tells real comments from text in
//! strings and sees through import aliases.

use std::collections::HashMap;

use ruff_python_ast::{
    Expr, ExprContext, Stmt,
    token::TokenKind,
    visitor::{Visitor, walk_expr, walk_stmt},
};
use ruff_python_parser::parse_module;
use ruff_text_size::{Ranged, TextRange};

/// Stack for parsing and walking a script. The parser and the AST visitors
/// recurse once per nesting level, so `1+1+…` with a few hundred thousand
/// terms overflows a 2 MiB tokio worker stack and aborts the daemon. Scripts
/// are capped at `limits.max_script_bytes`; at the default cap a debug build
/// needs well over 32 MiB here. The reservation is virtual: pages are only
/// committed as a deep script touches them
const PARSER_STACK_BYTES: usize = 256 * 1024 * 1024;

/// A module whose members include a banned one
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Module {
    /// `typing` or `typing_extensions`, which export `Any` and `cast`
    Typing,
    /// `json`, whose `loads` returns `Any`
    Json,
}

impl Module {
    fn named(name: &str) -> Option<Self> {
        match name {
            "typing" | "typing_extensions" => Some(Self::Typing),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// The banned members, which a star import binds under their own names
    fn banned(self) -> &'static [(&'static str, BanKind)] {
        match self {
            Self::Typing => &[("Any", BanKind::Any), ("cast", BanKind::Cast)],
            Self::Json => &[("loads", BanKind::JsonLoads)],
        }
    }

    fn member(self, name: &str) -> Option<BanKind> {
        self.banned()
            .iter()
            .find(|(member, _)| *member == name)
            .map(|(_, kind)| *kind)
    }
}

/// Which escape hatch a script used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanKind {
    /// A use of `Any`, imported or reached through a `typing` module alias
    Any,
    /// A use of `cast`, imported or reached through a `typing` module alias
    Cast,
    /// A `# type: ignore` or `# ty: ignore` comment
    TypeIgnore,
    /// A use of `json.loads`, imported or reached through a `json` alias
    JsonLoads,
}

impl BanKind {
    /// Rule id in diagnostics and in the usage log
    pub fn rule(self) -> &'static str {
        match self {
            Self::Any => "ban:any",
            Self::Cast => "ban:cast",
            Self::TypeIgnore => "ban:type-ignore",
            Self::JsonLoads => "ban:json-loads",
        }
    }

    /// What the diagnostic says, kept short because the hint carries the fix
    fn message(self) -> &'static str {
        match self {
            Self::Any => "`Any` is not allowed in scripts",
            Self::Cast => "`cast` is not allowed in scripts",
            Self::TypeIgnore => "`type: ignore` comments are not allowed in scripts",
            Self::JsonLoads => {
                "`json.loads` returns an untyped value and is not allowed in scripts"
            }
        }
    }
}

/// One use of an escape hatch
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ban {
    /// Which hatch
    pub kind: BanKind,
    /// 1-based line
    pub line: usize,
    /// 1-based column, in characters
    pub column: usize,
    /// Characters the diagnostic underlines
    pub width: usize,
    /// The source line, for the diagnostic
    pub source_line: String,
}

/// Every escape hatch `source` uses, in source order
///
/// A script that does not parse reports nothing here: it never runs, and the
/// type checker's own syntax error is the better message
pub fn find(source: &str) -> Vec<Ban> {
    on_parser_stack(|| find_here(source)).unwrap_or_default()
}

/// Runs `work` on a thread with room for deeply nested scripts
///
/// `None` when no such thread could be started; callers then skip their
/// check, which the sandbox's own parser backs up
pub(crate) fn on_parser_stack<T: Send>(work: impl FnOnce() -> T + Send) -> Option<T> {
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("script-parser".to_owned())
            .stack_size(PARSER_STACK_BYTES)
            .spawn_scoped(scope, work);

        match spawned {
            Ok(handle) => handle.join().ok(),
            Err(error) => {
                tracing::warn!(%error, "could not start the script parser thread");
                None
            }
        }
    })
}

fn find_here(source: &str) -> Vec<Ban> {
    let Ok(parsed) = parse_module(source) else {
        return Vec::new();
    };

    let mut imports = Imports::default();
    imports.visit_body(&parsed.syntax().body);
    let mut uses = Uses {
        modules: imports.modules,
        names: imports.names,
        found: Vec::new(),
    };
    uses.visit_body(&parsed.syntax().body);

    let mut ranges = uses.found;
    for token in parsed.tokens().iter() {
        if token.kind() == TokenKind::Comment && suppresses_types(&source[token.range()]) {
            ranges.push((BanKind::TypeIgnore, token.range()));
        }
    }
    ranges.sort_by_key(|(_, range)| range.start());

    ranges
        .into_iter()
        .map(|(kind, range)| locate(source, kind, range))
        .collect()
}

/// The diagnostics for `bans`, shaped like the type checker's so scripts
/// and the usage log treat them alike
pub fn diagnostics(bans: &[Ban]) -> String {
    let mut out = String::new();
    for ban in bans {
        let gutter = " ".repeat(ban.line.to_string().len());
        out.push_str(&format!(
            "error[{rule}]: {message}\n{gutter}--> script.py:{line}:{column}\n{gutter} |\n{line} | {source}\n{gutter} | {pad}{marks}\n\n",
            rule = ban.kind.rule(),
            message = ban.kind.message(),
            line = ban.line,
            column = ban.column,
            source = ban.source_line,
            pad = " ".repeat(ban.column.saturating_sub(1)),
            marks = "^".repeat(ban.width.max(1)),
        ));
    }

    out
}

fn locate(source: &str, kind: BanKind, range: TextRange) -> Ban {
    let start = usize::from(range.start());
    let before = &source[..start];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |at| at + 1);
    let column = source[line_start..start].chars().count() + 1;
    let source_line = source[line_start..]
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_owned();
    let width = source[range].chars().count();

    Ban {
        kind,
        line,
        column,
        width,
        source_line,
    }
}

/// Whether a comment carries a `type: ignore` or `ty: ignore` directive
///
/// Each `#`-separated part counts, because checkers accept the directive
/// after other comment text
fn suppresses_types(comment: &str) -> bool {
    comment.split('#').any(|part| {
        let part = part.trim();

        ["type:", "ty:"].iter().any(|prefix| {
            part.strip_prefix(prefix)
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix("ignore"))
                .is_some_and(|rest| {
                    !rest.starts_with(|next: char| next.is_alphanumeric() || next == '_')
                })
        })
    })
}

/// First pass: the names banned members are bound to, and the names their
/// modules are imported under
///
/// Only bindings are collected: an import nobody uses switches nothing off,
/// and refusing it would cost the agent a retry for no gain
#[derive(Default)]
struct Imports {
    modules: HashMap<String, Module>,
    names: HashMap<String, BanKind>,
}

impl Imports {
    fn visit_body(&mut self, body: &[Stmt]) {
        for statement in body {
            self.visit_stmt(statement);
        }
    }
}

impl<'a> Visitor<'a> for Imports {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    if let Some(module) = Module::named(alias.name.as_str()) {
                        let bound = alias.asname.as_ref().unwrap_or(&alias.name);
                        self.modules.insert(bound.as_str().to_owned(), module);
                    }
                }
            }
            Stmt::ImportFrom(import) if import.level == 0 => {
                let Some(module) = import
                    .module
                    .as_ref()
                    .and_then(|module| Module::named(module.as_str()))
                else {
                    return walk_stmt(self, stmt);
                };
                for alias in &import.names {
                    if alias.name.as_str() == "*" {
                        for (member, kind) in module.banned() {
                            self.names.insert((*member).to_owned(), *kind);
                        }
                    } else if let Some(kind) = module.member(alias.name.as_str()) {
                        let bound = alias.asname.as_ref().unwrap_or(&alias.name);
                        self.names.insert(bound.as_str().to_owned(), kind);
                    }
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }
}

/// Second pass: uses of those bindings, and banned members reached through
/// a module alias, such as `<typing alias>.Any`
struct Uses {
    modules: HashMap<String, Module>,
    names: HashMap<String, BanKind>,
    found: Vec<(BanKind, TextRange)>,
}

impl Uses {
    fn visit_body(&mut self, body: &[Stmt]) {
        for statement in body {
            self.visit_stmt(statement);
        }
    }
}

impl<'a> Visitor<'a> for Uses {
    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(name) if name.ctx == ExprContext::Load => {
                if let Some(kind) = self.names.get(name.id.as_str()) {
                    self.found.push((*kind, name.range()));
                }
            }
            Expr::Attribute(attribute) => {
                if let Expr::Name(name) = attribute.value.as_ref()
                    && let Some(module) = self.modules.get(name.id.as_str())
                    && let Some(kind) = module.member(attribute.attr.as_str())
                {
                    self.found.push((kind, attribute.range()));
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}
