//! What a tool result is expected to look like, and the check that it does
//!
//! The check understands the subset of JSON Schema that `stubs` turns into
//! types, so the declared return type and the validated data cannot drift
//! apart. Keywords outside that subset (`pattern`, `minimum`, `format` and so
//! on) pass: the check exists to keep a wrong type from reaching a script,
//! not to enforce every constraint a server documents

use std::{fmt, sync::Arc};

use serde_json::{Map, Value};

/// Deepest `$ref` chain followed without consuming any data, so a schema
/// that refers to itself cannot loop forever
const MAX_REF_DEPTH: usize = 32;
/// Characters of an offending scalar quoted in a mismatch
const MAX_QUOTED_CHARS: usize = 40;

/// How a tool's result reaches the script
#[derive(Debug, Clone, Default)]
pub enum OutputSpec {
    /// Nothing is declared: a JSON object or array in the text is parsed,
    /// anything else stays text, and the script sees a `JsonValue`
    #[default]
    Untyped,
    /// The text blocks joined, never parsed
    Text,
    /// The result follows this JSON Schema, which was checked before the
    /// script saw it
    Schema(Arc<Map<String, Value>>),
}

impl OutputSpec {
    /// Name stored with each upstream call, so the review can tell which
    /// tools still hand scripts a `JsonValue`
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Untyped => "untyped",
            Self::Text => "text",
            Self::Schema(_) => "schema",
        }
    }
}

/// Where a result broke its schema
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// JSON path of the offending value, such as `$.hits[0].url`
    pub path: String,
    /// What the schema asked for
    pub expected: String,
    /// What arrived
    pub actual: String,
}

impl fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at {}: expected {}, got {}",
            self.path, self.expected, self.actual
        )
    }
}

/// Checks `value` against `schema`, reporting the first mismatch
pub fn validate(schema: &Map<String, Value>, value: &Value) -> Result<(), Mismatch> {
    Checker { root: schema }.check(schema, value, "$", 0)
}

struct Checker<'a> {
    root: &'a Map<String, Value>,
}

impl Checker<'_> {
    fn check(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &str,
        refs: usize,
    ) -> Result<(), Mismatch> {
        // before `$ref`: a nullable reference is `X | None` in the stub
        if value.is_null() && schema.get("nullable").and_then(Value::as_bool) == Some(true) {
            return Ok(());
        }
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
            && refs < MAX_REF_DEPTH
            && let Some(target) = reference
                .strip_prefix('#')
                .and_then(|pointer| self.root_pointer(pointer))
                .and_then(Value::as_object)
        {
            self.check(target, value, path, refs + 1)?;
        }

        self.check_type(schema, value, path)?;
        self.check_values(schema, value, path)?;
        self.check_combinators(schema, value, path, refs)?;

        match value {
            Value::Object(object) => self.check_object(schema, object, path, refs),
            Value::Array(items) => self.check_array(schema, items, path, refs),
            _ => Ok(()),
        }
    }

    fn root_pointer(&self, pointer: &str) -> Option<&Value> {
        if pointer.is_empty() {
            return None;
        }
        let mut current: Option<&Value> = None;
        for (index, segment) in pointer.trim_start_matches('/').split('/').enumerate() {
            let segment = segment.replace("~1", "/").replace("~0", "~");
            current = match (index, current) {
                (0, _) => self.root.get(&segment),
                (_, Some(Value::Object(object))) => object.get(&segment),
                (_, Some(Value::Array(items))) => {
                    segment.parse::<usize>().ok().and_then(|at| items.get(at))
                }
                _ => None,
            };
        }

        current
    }

    fn check_type(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &str,
    ) -> Result<(), Mismatch> {
        let allowed: Vec<&str> = match schema.get("type") {
            Some(Value::String(name)) => vec![name.as_str()],
            Some(Value::Array(names)) => names.iter().filter_map(Value::as_str).collect(),
            // the stub makes a TypedDict or list from these alone, so the
            // value must be one
            None if schema.contains_key("properties") && !has_combinator(schema) => vec!["object"],
            None if schema.contains_key("items") && !has_combinator(schema) => vec!["array"],
            _ => return Ok(()),
        };
        // an unrecognized type name constrains nothing, like any unknown keyword
        let recognized = |name: &&str| {
            matches!(
                *name,
                "string" | "integer" | "number" | "boolean" | "null" | "array" | "object"
            )
        };
        let known: Vec<&str> = allowed.iter().copied().filter(recognized).collect();
        if known.len() != allowed.len() || known.is_empty() {
            return Ok(());
        }
        if known.iter().any(|name| has_type(value, name)) {
            return Ok(());
        }

        Err(Mismatch {
            path: path.to_owned(),
            expected: known.join(" or "),
            actual: describe_actual(value),
        })
    }

    fn check_values(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &str,
    ) -> Result<(), Mismatch> {
        if let Some(constant) = schema.get("const")
            && !json_equal(constant, value)
        {
            return Err(Mismatch {
                path: path.to_owned(),
                expected: format!("the constant {}", quote(constant)),
                actual: describe_actual(value),
            });
        }
        if let Some(Value::Array(allowed)) = schema.get("enum")
            && !allowed.iter().any(|candidate| json_equal(candidate, value))
        {
            let names: Vec<String> = allowed.iter().map(quote).collect();

            return Err(Mismatch {
                path: path.to_owned(),
                expected: format!("one of {}", names.join(", ")),
                actual: describe_actual(value),
            });
        }

        Ok(())
    }

    fn check_combinators(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &str,
        refs: usize,
    ) -> Result<(), Mismatch> {
        if let Some(Value::Array(members)) = schema.get("allOf") {
            for member in members.iter().filter_map(Value::as_object) {
                self.check(member, value, path, refs)?;
            }
        }
        for key in ["anyOf", "oneOf"] {
            let Some(Value::Array(members)) = schema.get(key) else {
                continue;
            };
            let mut deepest: Option<Mismatch> = None;
            let mut matched = members.is_empty();
            for member in members {
                // a non-object member (`true`) accepts anything
                let Some(member) = member.as_object() else {
                    matched = true;
                    break;
                };
                match self.check(member, value, path, refs) {
                    Ok(()) => {
                        matched = true;
                        break;
                    }
                    Err(mismatch) => {
                        // the branch that got furthest says the most about what is wrong
                        let better = deepest
                            .as_ref()
                            .is_none_or(|best| mismatch.path.len() > best.path.len());
                        if better {
                            deepest = Some(mismatch);
                        }
                    }
                }
            }
            if !matched && let Some(mismatch) = deepest {
                return Err(mismatch);
            }
        }

        Ok(())
    }

    fn check_object(
        &self,
        schema: &Map<String, Value>,
        object: &Map<String, Value>,
        path: &str,
        refs: usize,
    ) -> Result<(), Mismatch> {
        if let Some(Value::Array(names)) = schema.get("required") {
            for name in names.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    return Err(Mismatch {
                        path: path.to_owned(),
                        expected: format!("an object with the property `{name}`"),
                        actual: format!("an object with the properties {}", property_names(object)),
                    });
                }
            }
        }

        let properties = schema.get("properties").and_then(Value::as_object);
        let additional = schema
            .get("additionalProperties")
            .and_then(Value::as_object);
        for (name, member) in object {
            let declared = properties
                .and_then(|properties| properties.get(name))
                .and_then(Value::as_object);
            let Some(member_schema) = declared.or(additional) else {
                continue;
            };
            let member_path = format!("{path}.{name}");
            self.check(member_schema, member, &member_path, refs)?;
        }

        Ok(())
    }

    fn check_array(
        &self,
        schema: &Map<String, Value>,
        items: &[Value],
        path: &str,
        refs: usize,
    ) -> Result<(), Mismatch> {
        let tuple = schema
            .get("prefixItems")
            .and_then(Value::as_array)
            .or_else(|| schema.get("items").and_then(Value::as_array));
        if let Some(tuple) = tuple {
            for (index, (member_schema, item)) in tuple.iter().zip(items).enumerate() {
                if let Some(member_schema) = member_schema.as_object() {
                    self.check(member_schema, item, &format!("{path}[{index}]"), refs)?;
                }
            }

            return Ok(());
        }
        let Some(item_schema) = schema.get("items").and_then(Value::as_object) else {
            return Ok(());
        };
        for (index, item) in items.iter().enumerate() {
            self.check(item_schema, item, &format!("{path}[{index}]"), refs)?;
        }

        Ok(())
    }
}

/// Whether `value` is of the JSON Schema type `name`
fn has_type(value: &Value, name: &str) -> bool {
    match (name, value) {
        ("string", Value::String(_))
        | ("boolean", Value::Bool(_))
        | ("null", Value::Null)
        | ("array", Value::Array(_))
        | ("object", Value::Object(_))
        | ("number", Value::Number(_)) => true,
        // JSON Schema counts 5.0 as an integer
        ("integer", Value::Number(number)) => {
            number.is_i64()
                || number.is_u64()
                || number.as_f64().is_some_and(|float| float.fract() == 0.0)
        }
        _ => false,
    }
}

/// Equality that treats `1` and `1.0` as the same number, as JSON Schema does
fn json_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => {
            left == right || left.as_f64().is_some() && left.as_f64() == right.as_f64()
        }
        _ => left == right,
    }
}

/// The JSON type of a value, with the value itself when it is a short scalar
fn describe_actual(value: &Value) -> String {
    let kind = match value {
        Value::Null => return "null".to_owned(),
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => return "an array".to_owned(),
        Value::Object(_) => return "an object".to_owned(),
    };

    format!("{kind} {}", quote(value))
}

/// A scalar as JSON text, cut short
fn quote(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() <= MAX_QUOTED_CHARS {
        return text;
    }
    let head: String = text.chars().take(MAX_QUOTED_CHARS).collect();

    format!("{head}...")
}

/// Property names of an object, for a message, in order and cut short
fn property_names(object: &Map<String, Value>) -> String {
    const SHOWN: usize = 8;

    let mut names: Vec<String> = object
        .keys()
        .take(SHOWN)
        .map(|name| format!("`{name}`"))
        .collect();
    if object.len() > SHOWN {
        names.push("...".to_owned());
    }
    if names.is_empty() {
        return "(none)".to_owned();
    }

    names.join(", ")
}

/// Whether `schema` combines other schemas, which then decide its type
fn has_combinator(schema: &Map<String, Value>) -> bool {
    ["anyOf", "oneOf", "allOf", "$ref"]
        .iter()
        .any(|keyword| schema.contains_key(*keyword))
}
