//! Conversions between JSON (MCP) and Monty (script) values

use std::collections::HashSet;

use monty_types::{MontyObject, ObjectRef};
use num_bigint::BigInt;
use serde_json::{Map, Number, Value};

/// Deepest nesting converted; self-referential or absurdly deep values would
/// otherwise recurse without bound
const MAX_DEPTH: usize = 64;
/// Appended to text cut off by a size limit
const TRUNCATED_TEXT: &str = "...[truncated]";
/// Key of the marker entry that ends a truncated dict
const TRUNCATED_KEY: &str = "__truncated__";
/// Node ceiling for results
const RESULT_MAX_NODES: usize = 200_000;
/// Size ceiling for the arguments of a single tool call
const ARGUMENT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Node ceiling for the arguments of a single tool call
const ARGUMENT_MAX_NODES: usize = 1_000_000;
/// Node ceiling for one upstream tool result handed to a script
const TOOL_RESULT_MAX_NODES: usize = 1_000_000;
/// Longest text a non-string dict key may expand to; tuple keys can share
/// substructure, so their repr is measured before it is built
const MAX_KEY_REPR_BYTES: usize = 4096;

/// Why a script value could not be turned into JSON
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// NaN and infinities have no JSON form
    #[error("cannot send {0} as JSON; use a finite number")]
    NonFinite(String),
    /// Two dict keys stringify to the same JSON key
    #[error("dict keys collide: more than one key becomes the JSON key {0:?}")]
    KeyCollision(String),
    /// The value expands to more data than allowed
    #[error("value is too large to send (limit {0} bytes)")]
    TooLarge(usize),
    /// The value nests deeper than [`MAX_DEPTH`]
    #[error("value is nested more than {MAX_DEPTH} levels deep")]
    TooDeep,
    /// The value has more elements than allowed
    #[error("value has more than {0} elements")]
    TooManyNodes(usize),
    /// A non-string dict key would expand to an enormous string
    #[error("a dict key is too large to use as a JSON key (limit {MAX_KEY_REPR_BYTES} bytes)")]
    KeyTooLarge,
}

/// How much a conversion may emit
///
/// Shared substructure of a script value counts once per expansion, so a
/// small value can describe an enormous document
#[derive(Debug, Clone, Copy)]
pub struct ConvertLimits {
    max_bytes: usize,
    max_nodes: usize,
}

impl ConvertLimits {
    /// Limits for a script's final result
    pub fn result(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            max_nodes: RESULT_MAX_NODES,
        }
    }

    fn arguments() -> Self {
        Self {
            max_bytes: ARGUMENT_MAX_BYTES,
            max_nodes: ARGUMENT_MAX_NODES,
        }
    }
}

/// A converted script result
#[derive(Debug, Clone)]
pub struct Converted {
    /// The JSON value, cut short when a limit was hit
    pub value: Value,
    /// Whether anything was left out
    pub truncated: bool,
    /// Human-readable remarks about lossy steps
    pub notes: Vec<String>,
}

/// Converts a JSON value into the Python value a script receives
///
/// The value is measured first, so an upstream answering with something huge
/// or absurdly nested costs a bounded walk instead of a sandbox-sized copy
/// or a stack overflow
pub fn json_to_monty(value: &Value, max_bytes: usize) -> Result<MontyObject, ConvertError> {
    measure_json(value, max_bytes, TOOL_RESULT_MAX_NODES)?;

    Ok(json_to_monty_unchecked(value))
}

/// Checks depth, element count and approximate size without recursion
fn measure_json(value: &Value, max_bytes: usize, max_nodes: usize) -> Result<(), ConvertError> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        if depth >= MAX_DEPTH {
            return Err(ConvertError::TooDeep);
        }
        nodes += 1;
        if nodes > max_nodes {
            return Err(ConvertError::TooManyNodes(max_nodes));
        }
        bytes = bytes.saturating_add(match value {
            Value::Null | Value::Bool(_) => 4,
            Value::Number(number) => number.to_string().len(),
            Value::String(text) => text.len() + 2,
            Value::Array(items) => {
                stack.extend(items.iter().map(|item| (item, depth + 1)));

                2 + items.len()
            }
            Value::Object(map) => {
                stack.extend(map.values().map(|item| (item, depth + 1)));

                2 + map.keys().map(|key| key.len() + 4).sum::<usize>()
            }
        });
        if bytes > max_bytes {
            return Err(ConvertError::TooLarge(max_bytes));
        }
    }

    Ok(())
}

/// Recursive conversion; only called on values [`measure_json`] accepted,
/// so the depth is bounded
fn json_to_monty_unchecked(value: &Value) -> MontyObject {
    match value {
        Value::Null => MontyObject::none(),
        Value::Bool(flag) => MontyObject::bool(*flag),
        Value::Number(number) => number_to_monty(number),
        Value::String(text) => MontyObject::string(text.clone()),
        Value::Array(items) => MontyObject::list(items.iter().map(json_to_monty_unchecked)),
        Value::Object(map) => MontyObject::dict(map.iter().map(|(key, value)| {
            (
                MontyObject::string(key.clone()),
                json_to_monty_unchecked(value),
            )
        })),
    }
}

/// Whether the repr of `value` stays within `budget` bytes, without ever
/// building a repr of a container; shared substructure is walked once per
/// expansion, so the walk stops as soon as the budget runs out
fn repr_fits(value: ObjectRef<'_>, budget: &mut usize, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let cost = match value.items() {
        Some(items) => {
            let overhead = 2 + 2 * items.len();
            if overhead > *budget {
                return false;
            }
            *budget -= overhead;

            return items
                .into_iter()
                .all(|item| repr_fits(item, budget, depth + 1));
        }
        None => match value.as_str() {
            Some(text) => text.len() + 2,
            None => value.py_repr().len(),
        },
    };
    if cost > *budget {
        return false;
    }
    *budget -= cost;

    true
}

fn number_to_monty(number: &Number) -> MontyObject {
    if let Some(value) = number.as_i64() {
        return MontyObject::int(value);
    }
    if let Some(value) = number.as_u64() {
        return MontyObject::bigint(BigInt::from(value));
    }

    // with arbitrary precision the original digits survive; an integer that
    // parses as a big integer stays exact, anything else is a float
    match number.to_string().parse::<BigInt>() {
        Ok(value) => MontyObject::bigint(value),
        Err(_) => MontyObject::float(number.as_f64().unwrap_or(f64::NAN)),
    }
}

/// Converts a script result into JSON, stopping at `limits`
///
/// Values JSON cannot express (bytes, dates, sets of unhashable data) become
/// their Python `repr`; non-finite floats become `null` with a note. Fails
/// only when dict keys collide after turning them into strings
pub fn monty_to_json(
    value: ObjectRef<'_>,
    limits: ConvertLimits,
) -> Result<Converted, ConvertError> {
    let mut walker = Walker::new(limits, false);
    let value = walker.convert(value, 0)?;
    let mut notes = Vec::new();
    if walker.non_finite > 0 {
        notes.push(format!(
            "{} non-finite float value(s) (NaN or infinity) became null",
            walker.non_finite
        ));
    }
    if walker.truncated {
        notes.push(format!(
            "result truncated at about {} bytes; return less data or summarize it in the script",
            limits.max_bytes
        ));
    }

    Ok(Converted {
        value,
        truncated: walker.truncated,
        notes,
    })
}

/// Converts a script value into the JSON argument of a tool call
///
/// Strict: anything lossy or oversized is an error the script can catch
pub fn monty_to_argument(value: ObjectRef<'_>) -> Result<Value, ConvertError> {
    Walker::new(ConvertLimits::arguments(), true).convert(value, 0)
}

struct Walker {
    limits: ConvertLimits,
    strict: bool,
    nodes: usize,
    bytes: usize,
    exhausted: bool,
    truncated: bool,
    marked: bool,
    non_finite: usize,
}

impl Walker {
    fn new(limits: ConvertLimits, strict: bool) -> Self {
        Self {
            limits,
            strict,
            nodes: 0,
            bytes: 0,
            exhausted: false,
            truncated: false,
            marked: false,
            non_finite: 0,
        }
    }

    /// Counts one emitted node of roughly `cost` bytes; false once over budget
    fn charge(&mut self, cost: usize) -> bool {
        self.nodes += 1;
        self.bytes = self.bytes.saturating_add(cost);
        if self.nodes > self.limits.max_nodes || self.bytes > self.limits.max_bytes {
            self.exhausted = true;
            self.truncated = true;
        }

        !self.exhausted
    }

    fn stop(&self) -> Result<Value, ConvertError> {
        if self.strict {
            Err(ConvertError::TooLarge(self.limits.max_bytes))
        } else {
            Ok(Value::Null)
        }
    }

    fn convert(&mut self, value: ObjectRef<'_>, depth: usize) -> Result<Value, ConvertError> {
        if self.exhausted {
            return self.stop();
        }
        if depth >= MAX_DEPTH {
            if self.strict {
                return Err(ConvertError::TooDeep);
            }
            self.truncated = true;

            return Ok(Value::String("[nested too deeply]".to_owned()));
        }

        match value.type_name() {
            "NoneType" => Ok(self.scalar(4, Value::Null)),
            "bool" => Ok(self.scalar(5, value.as_bool().map_or(Value::Null, Value::Bool))),
            "int" => Ok(self.integer(value)),
            "float" => self.float(value),
            "str" => self.text(value.as_str().unwrap_or_default()),
            "dict" => self.dict(value, depth),
            name => {
                // instances of script classes (dataclasses) expose their
                // fields as pairs; builtin class objects do not count
                if name != "type"
                    && let Some(pairs) = value.pairs()
                {
                    return self.object(pairs, depth);
                }
                match value.items() {
                    Some(items) => self.list(items, depth),
                    // repr of a container would expand shared substructure
                    // without bound, so only leaves get here
                    None => self.text(&value.py_repr()),
                }
            }
        }
    }

    fn scalar(&mut self, cost: usize, value: Value) -> Value {
        if self.charge(cost) {
            value
        } else {
            Value::Null
        }
    }

    fn integer(&mut self, value: ObjectRef<'_>) -> Value {
        if let Some(small) = value.as_int() {
            return self.scalar(8, Value::from(small));
        }

        // wider than 64 bits: the repr is the exact decimal expansion
        let digits = value.py_repr();
        if !self.charge(digits.len()) {
            return Value::Null;
        }

        serde_json::from_str(&digits).unwrap_or(Value::String(digits))
    }

    fn float(&mut self, value: ObjectRef<'_>) -> Result<Value, ConvertError> {
        let Some(number) = value.as_float() else {
            return Ok(self.scalar(4, Value::Null));
        };
        if !number.is_finite() {
            if self.strict {
                return Err(ConvertError::NonFinite(value.py_repr()));
            }
            self.non_finite += 1;

            return Ok(self.scalar(4, Value::Null));
        }

        Ok(self.scalar(12, Value::from(number)))
    }

    fn text(&mut self, text: &str) -> Result<Value, ConvertError> {
        let room = self.limits.max_bytes.saturating_sub(self.bytes);
        if self.nodes >= self.limits.max_nodes {
            self.exhausted = true;
            self.truncated = true;

            return self.stop();
        }
        if text.len() + 2 > room {
            self.exhausted = true;
            self.truncated = true;
            if self.strict {
                return Err(ConvertError::TooLarge(self.limits.max_bytes));
            }
            let mut end = room.saturating_sub(2).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }

            return Ok(Value::String(format!("{}{TRUNCATED_TEXT}", &text[..end])));
        }
        self.nodes += 1;
        self.bytes += text.len() + 2;

        Ok(Value::String(text.to_owned()))
    }

    fn list(&mut self, items: Vec<ObjectRef<'_>>, depth: usize) -> Result<Value, ConvertError> {
        if !self.charge(2) {
            return self.stop();
        }
        let mut out = Vec::with_capacity(items.len().min(1024));
        for item in items {
            if self.exhausted {
                break;
            }
            out.push(self.convert(item, depth + 1)?);
        }
        if self.exhausted && !self.marked && !self.strict {
            self.marked = true;
            out.push(Value::String(TRUNCATED_TEXT.to_owned()));
        }

        Ok(Value::Array(out))
    }

    fn dict(&mut self, value: ObjectRef<'_>, depth: usize) -> Result<Value, ConvertError> {
        self.object(value.pairs().unwrap_or_default(), depth)
    }

    fn object(
        &mut self,
        pairs: Vec<(ObjectRef<'_>, ObjectRef<'_>)>,
        depth: usize,
    ) -> Result<Value, ConvertError> {
        if !self.charge(2) {
            return self.stop();
        }
        let mut map = Map::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (key, value) in pairs {
            if self.exhausted {
                break;
            }
            // str(key) of a non-string key matches its repr for every type
            // JSON-ish scripts use as keys (int, float, bool, None, tuple)
            let key = match key.as_str() {
                Some(text) => text.to_owned(),
                None => {
                    let mut budget = MAX_KEY_REPR_BYTES;
                    if !repr_fits(key, &mut budget, 0) {
                        return Err(ConvertError::KeyTooLarge);
                    }

                    key.py_repr()
                }
            };
            if !seen.insert(key.clone()) {
                return Err(ConvertError::KeyCollision(key));
            }
            if !self.charge(key.len() + 3) {
                break;
            }
            let value = self.convert(value, depth + 1)?;
            map.insert(key, value);
        }
        if self.exhausted && !self.marked && !self.strict {
            self.marked = true;
            map.insert(TRUNCATED_KEY.to_owned(), Value::Bool(true));
        }

        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn convert(value: &MontyObject) -> Result<Converted, ConvertError> {
        monty_to_json(value.as_ref(), ConvertLimits::result(1024))
    }

    #[test]
    fn json_round_trips_through_monty() -> Result<(), ConvertError> {
        let original: Value = serde_json::from_str(
            r#"{"name": "x", "n": [1, 2.5, null, true], "big": 123456789012345678901234567890,
                "max": 18446744073709551615, "nested": {"deep": {"k": "v"}}}"#,
        )
        .map_err(|_| ConvertError::TooDeep)?;

        let back = convert(&json_to_monty(&original, 1 << 20)?)?;

        assert_eq!(back.value, original);
        assert!(!back.truncated);

        Ok(())
    }

    #[test]
    fn oversized_or_deep_tool_results_are_refused_before_conversion() {
        let wide = Value::Array(vec![Value::String("x".repeat(1000)); 100]);
        let mut deep = json!(1);
        for _ in 0..200 {
            deep = json!([deep]);
        }

        assert!(matches!(
            json_to_monty(&wide, 10_000),
            Err(ConvertError::TooLarge(10_000))
        ));
        assert!(json_to_monty(&wide, 1_000_000).is_ok());
        assert!(matches!(
            json_to_monty(&deep, 1_000_000),
            Err(ConvertError::TooDeep)
        ));
    }

    #[test]
    fn shared_tuple_keys_are_refused_instead_of_expanded() {
        let mut key = MontyObject::tuple([MontyObject::int(1)]);
        // in the sandbox these levels share one object; here they are copies
        for _ in 0..16 {
            key = MontyObject::tuple([key.clone(), key]);
        }
        let value = MontyObject::dict([(key, MontyObject::int(1))]);

        assert!(matches!(convert(&value), Err(ConvertError::KeyTooLarge)));
    }

    #[test]
    fn non_finite_floats_are_strict_errors_and_lenient_nulls() -> Result<(), ConvertError> {
        let value = MontyObject::list([MontyObject::float(f64::NAN), MontyObject::int(1)]);

        let lenient = convert(&value)?;

        assert_eq!(lenient.value, json!([null, 1]));
        assert!(lenient.notes.iter().any(|note| note.contains("non-finite")));
        assert!(matches!(
            monty_to_argument(MontyObject::float(f64::INFINITY).as_ref()),
            Err(ConvertError::NonFinite(_))
        ));

        Ok(())
    }

    #[test]
    fn colliding_keys_are_rejected_and_other_keys_stringified() -> Result<(), ConvertError> {
        let colliding = MontyObject::dict([
            (MontyObject::int(1), MontyObject::int(1)),
            (MontyObject::string("1"), MontyObject::int(2)),
        ]);
        let distinct = MontyObject::dict([(MontyObject::int(1), MontyObject::bool(true))]);

        assert!(matches!(
            convert(&colliding),
            Err(ConvertError::KeyCollision(_))
        ));
        assert_eq!(convert(&distinct)?.value, json!({"1": true}));

        Ok(())
    }
}
