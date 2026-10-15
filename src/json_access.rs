//! Path accessors for `JsonValue` results, predefined in every script
//!
//! Narrowing a `JsonValue` by hand takes an `isinstance` check per level, and
//! the checker's view of `isinstance(v, dict)` on the covariant alias is an
//! intersection with `Unknown` in it, which reads badly and switches checking
//! off for what it touches. `json_str(r, "$.hits[0].url")` instead returns a
//! plain `str` or raises naming the path, in the shape of an output-schema
//! mismatch.
//!
//! The accessors are Python fed into each sandbox session ahead of the
//! script rather than host functions: a host call is a suspension and a round
//! trip to the worker, and a loop over a few hundred rows would spend the
//! execution's suspension budget

/// Names the accessors take in every script; no tool may use them
pub const NAMES: [&str; 8] = [
    "json_get",
    "json_str",
    "json_int",
    "json_float",
    "json_bool",
    "json_list",
    "json_dict",
    "json_parse",
];

/// Declarations for the type checker, after the `JsonValue` alias
pub const CHECK_STUBS: &str = r#"
def json_get(value: object, path: str = "$") -> JsonValue: ...
def json_str(value: object, path: str = "$") -> str: ...
def json_int(value: object, path: str = "$") -> int: ...
def json_float(value: object, path: str = "$") -> float: ...
def json_bool(value: object, path: str = "$") -> bool: ...
def json_list(value: object, path: str = "$") -> list[JsonValue]: ...
def json_dict(value: object, path: str = "$") -> dict[str, JsonValue]: ...
def json_parse(text: str) -> JsonValue: ...
"#;

/// The same declarations documented, for `describe_tools`
pub const DOCUMENTED: &str = r#"
# Predefined, never imported. A path is `$`, then `.key`, `[index]` or `["odd key"]` steps,
# such as "$.hits[0].url". A wrong type raises TypeError, a missing key KeyError and a
# missing index IndexError, each naming where the path stopped; a malformed path raises
# ValueError.
def json_str(value: object, path: str = "$") -> str: ...
def json_int(value: object, path: str = "$") -> int: ...
def json_float(value: object, path: str = "$") -> float:
    """An int is accepted and converted"""
    ...
def json_bool(value: object, path: str = "$") -> bool: ...
def json_list(value: object, path: str = "$") -> list[JsonValue]: ...
def json_dict(value: object, path: str = "$") -> dict[str, JsonValue]: ...
def json_get(value: object, path: str = "$") -> JsonValue:
    """The value at `path`, or None when a step is missing or not a container"""
    ...
def json_parse(text: str) -> JsonValue:
    """Parses JSON text; use it instead of json.loads, which returns an untyped value"""
    ...
"#;

/// The accessors, fed to each session before the script with type checking
/// skipped: [`CHECK_STUBS`] already declares them, and a second definition in
/// the checked source would clash with it
pub const PRELUDE: &str = r#"
import json as _json_module


def _json_steps(path: str) -> list[str | int]:
    text = path[1:] if path.startswith("$") else path
    if text and text[0] != "." and text[0] != "[":
        text = "." + text
    steps: list[str | int] = []
    i = 0
    while i < len(text):
        if text[i] == ".":
            end = i + 1
            while end < len(text) and text[end] != "." and text[end] != "[":
                end += 1
            if end == i + 1:
                raise ValueError(f"JSON path {path}: empty key after '.'")
            steps.append(text[i + 1 : end])
            i = end
        elif text[i] == "[":
            quote = text[i + 1] if i + 1 < len(text) else ""
            if quote == '"' or quote == "'":
                # a quoted key may hold `]` or `.`, so scan to its closing quote
                close = text.find(quote, i + 2)
                if close < 0 or close + 1 >= len(text) or text[close + 1] != "]":
                    raise ValueError(f"JSON path {path}: a quoted key must end with {quote}]")
                steps.append(text[i + 2 : close])
                i = close + 2
            else:
                end = text.find("]", i)
                if end < 0:
                    raise ValueError(f"JSON path {path}: '[' is never closed")
                inner = text[i + 1 : end]
                try:
                    steps.append(int(inner))
                except ValueError:
                    raise ValueError(f"JSON path {path}: [{inner}] is neither an index nor a quoted key")
                i = end + 1
        else:
            raise ValueError(f"JSON path {path}: expected '.' or '[' at {text[i:]}")
    return steps


def _json_kind(value: object) -> str:
    if value is None:
        return "None"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return "a non-JSON value"


def _json_walk(value: object, path: str, strict: bool) -> tuple[bool, object, str]:
    current = value
    where = "$"
    for step in _json_steps(path):
        if isinstance(step, int):
            if not isinstance(current, list):
                if strict:
                    raise TypeError(f"at {where}: expected list, got {_json_kind(current)}")
                return (False, None, where)
            if step >= len(current) or step < -len(current):
                if strict:
                    raise IndexError(f"at {where}: no index {step} in a list of {len(current)}")
                return (False, None, where)
            current = current[step]
            where = f"{where}[{step}]"
        else:
            if not isinstance(current, dict):
                if strict:
                    raise TypeError(f"at {where}: expected dict, got {_json_kind(current)}")
                return (False, None, where)
            if step not in current:
                if strict:
                    raise KeyError(f"at {where}: no key {step}")
                return (False, None, where)
            current = current[step]
            where = f"{where}.{step}"
    return (True, current, where)


def json_get(value: object, path: str = "$") -> object:
    found, current, where = _json_walk(value, path, False)
    return current if found else None


def json_str(value: object, path: str = "$") -> str:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, str):
        return current
    raise TypeError(f"at {where}: expected str, got {_json_kind(current)}")


def json_int(value: object, path: str = "$") -> int:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, int) and not isinstance(current, bool):
        return current
    raise TypeError(f"at {where}: expected int, got {_json_kind(current)}")


def json_float(value: object, path: str = "$") -> float:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, bool):
        raise TypeError(f"at {where}: expected float, got bool")
    if isinstance(current, int) or isinstance(current, float):
        return float(current)
    raise TypeError(f"at {where}: expected float, got {_json_kind(current)}")


def json_bool(value: object, path: str = "$") -> bool:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, bool):
        return current
    raise TypeError(f"at {where}: expected bool, got {_json_kind(current)}")


def json_list(value: object, path: str = "$") -> list[object]:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, list):
        return current
    raise TypeError(f"at {where}: expected list, got {_json_kind(current)}")


def json_dict(value: object, path: str = "$") -> dict[str, object]:
    found, current, where = _json_walk(value, path, True)
    if isinstance(current, dict):
        return current
    raise TypeError(f"at {where}: expected dict, got {_json_kind(current)}")


def json_parse(text: str) -> object:
    return _json_module.loads(text)
"#;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// A name defined in the prelude but missing from the stubs fails the
    /// check, and one declared but never defined passes it and then raises
    /// `NameError`, so every list must hold the same accessors
    #[test]
    fn every_accessor_is_defined_declared_documented_and_reserved() {
        let defined: BTreeSet<&str> = PRELUDE
            .lines()
            .filter_map(|line| line.strip_prefix("def "))
            .filter_map(|rest| rest.split('(').next())
            .filter(|name| name.starts_with("json_"))
            .collect();
        let reserved: BTreeSet<&str> = NAMES.into_iter().collect();
        assert_eq!(defined, reserved);

        for name in NAMES {
            let declaration = format!("def {name}(");
            assert!(CHECK_STUBS.contains(&declaration), "{name} is not declared");
            assert!(
                DOCUMENTED.contains(&declaration),
                "{name} is not documented"
            );
        }
    }
}
