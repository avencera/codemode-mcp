//! Instructions shown to agents
//!
//! The script rules are macros so the same text can be spliced into the
//! `execute` tool description (which needs a literal) and into runtime strings

macro_rules! tool_call_rule {
    () => {
        "Tools are async functions taking keyword arguments only: `r = await server_tool(arg=...)`. \
         Use the types from the describe_tools stubs (TypedDict/Literal) as given."
    };
}

macro_rules! script_rules {
    () => {
        concat!(
            "Scripts are typed Python in a sandboxed Monty subset. They are type-checked before running; \
             fix reported errors and retry.\n\
             - Annotate function params/returns and non-obvious variables.\n\
             - ",
            $crate::guidance::tool_call_rule!(),
            "\n\
             - Results are typed. A tool with no declared result type returns `JsonValue` (predefined, never \
             imported); narrow it with isinstance:\n  \
             `v = r.get(\"k\") if isinstance(r, dict) else None`\n  \
             `name = v if isinstance(v, str) else \"\"`\n  \
             `Any`, `cast` and `# type: ignore` are rejected.\n\
             - A helper may return any JSON-like value as `JsonValue`, `dict[str, str]` and `list[dict[str, int]]` \
             included. A variable annotated `dict[str, JsonValue]` or `list[JsonValue]` is stricter: build it \
             with that annotation from the start.\n\
             - Allowed: top-level `await`; `async def` helpers; `await asyncio.gather(a(), b())` for concurrency \
             (no keyword args such as return_exceptions); if/for/while; list/dict/set comprehensions; f-strings; \
             try/except/finally with built-in exceptions (a refused or unapproved tool call raises \
             PermissionError, caught as `except OSError`; an error from the tool itself raises RuntimeError); dict, list, set, tuple, str, int, float, bool, None; \
             `@dataclass` only if really needed (eq=/frozen= options only).\n\
             - Stdlib only: asyncio, json, re, datetime, math, itertools, functools, collections, base64, \
             hashlib, random, time, typing. No third-party packages; no file or network access except through tools.\n\
             - Avoid: classes with inheritance, @property/@classmethod/@staticmethod, generators/yield, match, del, \
             async with/async for, user-defined exception classes, eval/exec.\n\
             - Import what you use (`import asyncio`, `import json`); nothing is pre-imported.\n\
             - The script runs at the top level, not inside a function: never `return`; the last expression is \
             the result. Make it JSON-serializable (dict/list/str/int/float/bool/None). \
             Return only the fields asked for (titles, URLs, short excerpts), never whole pages or documents. \
             Use print() for intermediate notes. Keep scripts short and focused."
        )
    };
}

macro_rules! session_rule {
    () => {
        "Pass the `session` value from your previous codemode result on every call; \
         the first call gets one automatically."
    };
}

pub(crate) use {script_rules, session_rule, tool_call_rule};

/// Rule about calling tools, repeated at the top of `describe_tools` output
pub const TOOL_CALL_RULE: &str = tool_call_rule!();

/// Rule about passing the app session back, repeated at the top of
/// `describe_tools` output
pub const SESSION_RULE: &str = session_rule!();

/// Server-level instructions sent when an agent connects
pub const INSTRUCTIONS: &str = concat!(
    "Many upstream tools are reachable through scripts. Workflow: search_tools to find tools by keyword, \
     describe_tools to get their typed Python signatures, then execute a script that calls them. \
     execute returns status \"pending\" with an execution_id if the script is slow; call wait(execution_id). \
     Some tools need the user's approval: a pending answer with approval_url and waiting_for means pass its \
     message and the approval_url on to the user, then call wait. ",
    session_rule!(),
    "\n\n",
    script_rules!()
);
