//! Questions the review asks about a script's shape
//!
//! Both answer a "was the typing loose enough to send the agent exploring"
//! signal: a probe execute exists only to look at a tool's result, and
//! `json.loads` is how an agent turns text into an untyped value of its own

use std::collections::HashSet;

use ruff_python_ast::{
    Expr, Stmt,
    visitor::{Visitor, walk_expr},
};
use ruff_python_parser::parse_module;

/// Whether the script only calls tools and hands the result back
///
/// Imports and blank lines do not count. The body must be a single awaited
/// tool call, or a gather of bare tool calls, returned as is: either as the
/// last expression, or assigned and then returned by name. `tools` are the
/// Python names of the tools, such as `exa_web_search_exa`
pub fn is_probe(source: &str, tools: &HashSet<String>) -> bool {
    let Ok(parsed) = parse_module(source) else {
        return false;
    };
    let body: Vec<&Stmt> = parsed
        .syntax()
        .body
        .iter()
        .filter(|statement| !matches!(statement, Stmt::Import(_) | Stmt::ImportFrom(_)))
        .collect();

    match body.as_slice() {
        [Stmt::Expr(call)] => tool_calls(&call.value, tools),
        [Stmt::Assign(assign), Stmt::Expr(result)] => {
            tool_calls(&assign.value, tools) && only_names(&result.value)
        }
        [Stmt::AnnAssign(assign), Stmt::Expr(result)] => assign
            .value
            .as_ref()
            .is_some_and(|value| tool_calls(value, tools) && only_names(&result.value)),
        _ => false,
    }
}

/// Whether the script calls `json.loads`, however `json` was imported
pub fn uses_json_loads(source: &str) -> bool {
    let Ok(parsed) = parse_module(source) else {
        return false;
    };
    let mut finder = JsonLoads::default();
    for statement in &parsed.syntax().body {
        finder.visit_stmt(statement);
    }

    finder.found
}

/// `await tool(...)` or `await asyncio.gather(tool(...), tool(...))`
fn tool_calls(expr: &Expr, tools: &HashSet<String>) -> bool {
    let Expr::Await(awaited) = expr else {
        return false;
    };
    let Expr::Call(call) = awaited.value.as_ref() else {
        return false;
    };
    if names_tool(&call.func, tools) {
        return true;
    }

    let gather = match call.func.as_ref() {
        Expr::Attribute(attribute) => attribute.attr.as_str() == "gather",
        Expr::Name(name) => name.id.as_str() == "gather",
        _ => false,
    };

    gather
        && !call.arguments.args.is_empty()
        && call
            .arguments
            .args
            .iter()
            .all(|argument| matches!(argument, Expr::Call(inner) if names_tool(&inner.func, tools)))
}

fn names_tool(func: &Expr, tools: &HashSet<String>) -> bool {
    matches!(func, Expr::Name(name) if tools.contains(name.id.as_str()))
}

/// A bare name, or a tuple or list of bare names
fn only_names(expr: &Expr) -> bool {
    match expr {
        Expr::Name(_) => true,
        Expr::Tuple(tuple) => tuple.elts.iter().all(only_names),
        Expr::List(list) => list.elts.iter().all(only_names),
        _ => false,
    }
}

#[derive(Default)]
struct JsonLoads {
    /// Names `json` is bound to
    modules: HashSet<String>,
    /// Names `json.loads` is bound to
    functions: HashSet<String>,
    found: bool,
}

impl<'a> Visitor<'a> for JsonLoads {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::Import(import) => {
                for alias in &import.names {
                    if alias.name.as_str() == "json" {
                        let bound = alias.asname.as_ref().unwrap_or(&alias.name);
                        self.modules.insert(bound.as_str().to_owned());
                    }
                }
            }
            Stmt::ImportFrom(import)
                if import.level == 0
                    && import
                        .module
                        .as_ref()
                        .is_some_and(|module| module.as_str() == "json") =>
            {
                for alias in &import.names {
                    if alias.name.as_str() == "loads" {
                        let bound = alias.asname.as_ref().unwrap_or(&alias.name);
                        self.functions.insert(bound.as_str().to_owned());
                    }
                }
            }
            _ => {}
        }
        ruff_python_ast::visitor::walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        if let Expr::Call(call) = expr {
            self.found |= match call.func.as_ref() {
                Expr::Attribute(attribute) => {
                    attribute.attr.as_str() == "loads"
                        && matches!(
                            attribute.value.as_ref(),
                            Expr::Name(name) if self.modules.contains(name.id.as_str())
                        )
                }
                Expr::Name(name) => self.functions.contains(name.id.as_str()),
                _ => false,
            };
        }
        walk_expr(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> HashSet<String> {
        ["exa_search", "hb_list"].map(str::to_owned).into()
    }

    #[test]
    fn probes_are_a_lone_call_or_a_bare_gather() {
        for script in [
            "await exa_search(query=\"x\")",
            "import asyncio\nimport json\nawait asyncio.gather(exa_search(query=\"x\"), hb_list())",
            "r = await hb_list()\nr",
            "a, b = await asyncio.gather(hb_list(), hb_list())\n(a, b)",
        ] {
            assert!(is_probe(script, &tools()), "{script}");
        }
        for script in [
            "r = await hb_list()\nr[\"tasks\"]",
            "r = await hb_list()\nlen(r)",
            "await other(query=\"x\")",
            "await asyncio.gather(hb_list(), asyncio.sleep(1))",
            "x = 1\nawait hb_list()",
            "await hb_list(\n",
        ] {
            assert!(!is_probe(script, &tools()), "{script}");
        }
    }

    #[test]
    fn json_loads_is_found_under_any_import_form() {
        for script in [
            "import json\njson.loads(x)",
            "import json as j\nj.loads(x)",
            "from json import loads\nloads(x)",
            "from json import loads as parse\nparse(x)",
        ] {
            assert!(uses_json_loads(script), "{script}");
        }
        for script in [
            "import json\njson.dumps(x)",
            "x = \"json.loads(y)\"",
            "# json.loads(y)\n1",
            "loads(x)",
        ] {
            assert!(!uses_json_loads(script), "{script}");
        }
    }
}
