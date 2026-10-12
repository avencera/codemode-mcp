//! Python stub generation from MCP tool JSON Schemas
//!
//! The stubs serve two readers: Monty's type checker (compact, no
//! docstrings) and agents calling `describe_tools` (full documentation)

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value};

/// Names every generated stub may use from `typing`
pub const STUB_HEADER: &str = "from typing import Any, Literal, NotRequired, TypedDict\n";

/// Reserved words that cannot be keyword argument names
const PYTHON_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

/// Generated declarations for one tool
#[derive(Debug, Clone)]
pub struct ToolStub {
    /// Declarations for type checking, without docstrings
    pub check: String,
    /// Declarations with full documentation, for agents
    pub describe: String,
    /// Optional parameters that do not accept JSON `null`; a script passing
    /// `None` for one of these means "omitted"
    pub omit_if_none: BTreeSet<String>,
    /// Some parameter names are not valid Python identifiers, so they are
    /// passed through `**kwargs`
    pub non_identifier_params: bool,
    /// The stub is a permissive stand-in because the generated one was rejected
    pub degraded: bool,
}

/// Allocates globally unique type names across all generated tools
#[derive(Debug, Default)]
pub struct StubBook {
    used: HashSet<String>,
}

impl StubBook {
    /// Creates an empty book
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates the stub for one tool
    ///
    /// `function` must already be a valid Python identifier
    pub fn tool(
        &mut self,
        function: &str,
        description: Option<&str>,
        input_schema: &Map<String, Value>,
        output_schema: Option<&Map<String, Value>>,
    ) -> ToolStub {
        self.used.insert(function.to_owned());
        let prefix = pascal_case(function);
        let mut generator = StubGenerator::new(&mut self.used, prefix.clone());

        generator.set_root(Value::Object(input_schema.clone()));
        let shape = generator.root_shape(input_schema);
        let properties = generator.properties(&shape.object, &prefix);
        let non_identifier = properties
            .iter()
            .any(|property| !is_identifier(&property.name));

        let mut omit_if_none = BTreeSet::new();
        for property in properties.iter().filter(|property| !property.required) {
            if !property.accepts_null {
                omit_if_none.insert(property.name.clone());
            }
        }

        let return_type = match output_schema {
            Some(schema) => {
                generator.set_root(Value::Object(schema.clone()));
                let hint = format!("{prefix}Result");

                generator.type_of(&Value::Object(schema.clone()), &hint)
            }
            None => "Any".to_owned(),
        };

        let declarations = generator.take_declarations();
        let signature = Signature {
            function,
            properties: &properties,
            open: shape.open,
            return_type: &return_type,
        };
        let check = render_check(&declarations, &signature.render());
        let describe = render_describe(&declarations, &signature, description, shape.variants);

        ToolStub {
            check,
            describe,
            omit_if_none,
            non_identifier_params: non_identifier,
            degraded: false,
        }
    }
}

/// Characters of the input schema kept in a degraded stub's docstring
const FALLBACK_SCHEMA_CHARS: usize = 6000;

/// Stub that always type-checks, used when a generated stub is rejected
///
/// The parameters are not checked, so the docstring carries the input schema
/// to keep names and types discoverable
pub fn fallback_stub(
    function: &str,
    description: Option<&str>,
    input_schema: &Map<String, Value>,
) -> ToolStub {
    let signature = format!("async def {function}(**kwargs: Any) -> Any");
    let check = format!("{signature}: ...\n");

    let mut schema = serde_json::to_string(input_schema).unwrap_or_default();
    if schema.chars().count() > FALLBACK_SCHEMA_CHARS {
        schema = schema.chars().take(FALLBACK_SCHEMA_CHARS).collect();
        schema.push_str("...");
    }
    let mut doc = description.map(str::trim).unwrap_or_default().to_owned();
    if !doc.is_empty() {
        doc.push_str("\n\n");
    }
    doc.push_str(&format!(
        "DEGRADED: the typed signature could not be generated, so arguments are not \
         type-checked. Pass the parameters below as keyword arguments.\n\
         Parameters (JSON Schema): {schema}"
    ));
    let describe = format!(
        "# degraded: typed signature unavailable for {function}\n{signature}:\n{}    ...\n",
        docstring(&doc, 1)
    );

    ToolStub {
        check,
        describe,
        omit_if_none: BTreeSet::new(),
        non_identifier_params: false,
        degraded: true,
    }
}

#[derive(Debug)]
struct TypedDictDecl {
    name: String,
    doc: Option<String>,
    fields: Vec<Property>,
}

/// The input schema reduced to an object: known properties plus whether
/// other arguments may be passed
struct RootShape {
    /// Synthetic object schema with `properties` and `required`
    object: Map<String, Value>,
    /// The tool may accept arguments beyond the known properties
    open: bool,
    /// The properties were merged from alternative argument shapes
    variants: bool,
}

/// Accumulator while flattening `$ref`, `allOf` and `oneOf`/`anyOf`
#[derive(Default)]
struct Flat {
    properties: Map<String, Value>,
    required: BTreeSet<String>,
    open: bool,
    variants: bool,
    /// A `properties` list was seen, so the object is closed unless it says otherwise
    has_properties: bool,
    /// Something marked this schema as an object
    object_like: bool,
}

impl Flat {
    fn merge(&mut self, other: Self) {
        self.properties.extend(other.properties);
        self.required.extend(other.required);
        self.open |= other.open;
        self.variants |= other.variants;
        self.has_properties |= other.has_properties;
        self.object_like |= other.object_like;
    }
}

/// Deepest `$ref`/`allOf`/`oneOf` chain followed at the root of an input schema
const MAX_ROOT_DEPTH: usize = 8;

#[derive(Debug, Clone)]
struct Property {
    name: String,
    ty: String,
    required: bool,
    doc: Option<String>,
    accepts_null: bool,
}

struct StubGenerator<'a> {
    used: &'a mut HashSet<String>,
    prefix: String,
    root: Value,
    declarations: Vec<TypedDictDecl>,
    ref_types: HashMap<String, String>,
    in_progress: HashSet<String>,
}

impl<'a> StubGenerator<'a> {
    fn new(used: &'a mut HashSet<String>, prefix: String) -> Self {
        Self {
            used,
            prefix,
            root: Value::Null,
            declarations: Vec::new(),
            ref_types: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    /// Switches the document `$ref`s resolve against
    fn set_root(&mut self, root: Value) {
        self.root = root;
        self.ref_types.clear();
        self.in_progress.clear();
    }

    fn take_declarations(&mut self) -> Vec<TypedDictDecl> {
        std::mem::take(&mut self.declarations)
    }

    fn unique_name(&mut self, hint: &str) -> String {
        let base = if hint.is_empty() {
            "Object".to_owned()
        } else {
            hint.to_owned()
        };
        let mut candidate = base.clone();
        let mut counter = 2;
        while !self.used.insert(candidate.clone()) {
            candidate = format!("{base}{counter}");
            counter += 1;
        }

        candidate
    }

    fn resolve(&self, reference: &str) -> Option<Value> {
        let pointer = reference.strip_prefix('#')?;

        self.root.pointer(pointer).cloned()
    }

    /// Reduces an input schema to known properties, resolving a root `$ref`,
    /// merging `allOf`, and widening `oneOf`/`anyOf` and open objects
    fn root_shape(&mut self, input: &Map<String, Value>) -> RootShape {
        let mut flat = self.flatten(input, 0);
        // a required name without a declared property can only be passed loosely
        let undeclared = flat
            .required
            .iter()
            .any(|name| !flat.properties.contains_key(name));
        let unknown = !flat.has_properties && !flat.variants;

        let open = flat.open || undeclared || unknown;
        let variants = flat.variants;
        let mut object = Map::new();
        object.insert("type".to_owned(), Value::String("object".to_owned()));
        object.insert(
            "properties".to_owned(),
            Value::Object(std::mem::take(&mut flat.properties)),
        );
        object.insert(
            "required".to_owned(),
            Value::Array(flat.required.into_iter().map(Value::String).collect()),
        );

        RootShape {
            object,
            open,
            variants,
        }
    }

    fn flatten(&mut self, schema: &Map<String, Value>, depth: usize) -> Flat {
        let mut flat = Flat::default();
        if depth > MAX_ROOT_DEPTH {
            flat.open = true;

            return flat;
        }

        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            match self.resolve(reference) {
                Some(Value::Object(target)) => {
                    let inner = self.flatten(&target, depth + 1);
                    flat.merge(inner);
                    flat.object_like = true;
                }
                _ => flat.open = true,
            }
        }

        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            flat.properties.extend(
                properties
                    .iter()
                    .map(|(name, schema)| (name.clone(), schema.clone())),
            );
            flat.has_properties = true;
            flat.object_like = true;
        }
        if let Some(names) = schema.get("required").and_then(Value::as_array) {
            flat.required
                .extend(names.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        // absent means "closed" for the schemas MCP servers generate; an
        // explicit `true` or schema means extra arguments are meaningful
        if schema
            .get("additionalProperties")
            .is_some_and(|value| *value != Value::Bool(false))
        {
            flat.open = true;
        }

        if let Some(members) = schema.get("allOf").and_then(Value::as_array) {
            for member in members {
                match member.as_object() {
                    Some(member) => {
                        let inner = self.flatten(member, depth + 1);
                        flat.merge(inner);
                    }
                    None => flat.open = true,
                }
            }
            flat.object_like = true;
        }

        for key in ["oneOf", "anyOf"] {
            let Some(members) = schema.get(key).and_then(Value::as_array) else {
                continue;
            };
            let mut shapes = Vec::new();
            let mut all_objects = true;
            for member in members {
                match member
                    .as_object()
                    .map(|member| self.flatten(member, depth + 1))
                {
                    Some(shape) if shape.object_like => shapes.push(shape),
                    _ => all_objects = false,
                }
            }
            flat.variants = true;
            flat.open = true;
            flat.object_like = true;
            if all_objects {
                Self::merge_variants(&mut flat, shapes);
            }
        }

        match schema.get("type") {
            Some(Value::String(name)) if name == "object" => flat.object_like = true,
            Some(Value::Array(names)) if names.iter().any(|name| name == "object") => {
                flat.object_like = true;
            }
            // a non-object root cannot be described by parameters
            Some(_) => flat.open = true,
            None => {}
        }

        flat
    }

    /// Unions the properties of alternative shapes; only names required by
    /// every alternative stay required
    fn merge_variants(flat: &mut Flat, shapes: Vec<Flat>) {
        let mut required: Option<BTreeSet<String>> = None;
        for shape in shapes {
            for (name, schema) in shape.properties {
                match flat.properties.get(&name) {
                    Some(existing) if *existing != schema => {
                        let merged = serde_json::json!({"anyOf": [existing, schema]});
                        flat.properties.insert(name, merged);
                    }
                    Some(_) => {}
                    None => {
                        flat.properties.insert(name, schema);
                    }
                }
            }
            flat.has_properties |= shape.has_properties;
            required = Some(match required {
                Some(common) => common.intersection(&shape.required).cloned().collect(),
                None => shape.required,
            });
        }
        flat.required.extend(required.unwrap_or_default());
    }

    fn properties(&mut self, object: &Map<String, Value>, hint: &str) -> Vec<Property> {
        let Some(properties) = object.get("properties").and_then(Value::as_object) else {
            return Vec::new();
        };
        let required: HashSet<&str> = object
            .get("required")
            .and_then(Value::as_array)
            .map(|names| names.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        let mut result: Vec<Property> = properties
            .iter()
            .map(|(name, schema)| {
                let nested_hint = format!("{hint}{}", pascal_case(name));
                let ty = self.type_of(schema, &nested_hint);
                let accepts_null = ty == "Any" || union_members(&ty).contains(&"None");

                Property {
                    name: name.clone(),
                    ty,
                    required: required.contains(name.as_str()),
                    doc: self.property_doc(schema),
                    accepts_null,
                }
            })
            .collect();

        // required parameters first so the signature reads naturally
        result.sort_by_key(|property| !property.required);

        result
    }

    fn property_doc(&self, schema: &Value) -> Option<String> {
        let object = schema.as_object()?;
        let target = match object.get("$ref").and_then(Value::as_str) {
            Some(reference) => self.resolve(reference),
            None => None,
        };
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .or_else(|| target.as_ref()?.get("description")?.as_str())
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned);
        let default = object
            .get("default")
            .map(|value| format!("default: {}", compact_json(value)));

        match (description, default) {
            (Some(text), Some(default)) => Some(format!("{text} ({default})")),
            (Some(text), None) => Some(text),
            (None, Some(default)) => Some(default),
            (None, None) => None,
        }
    }

    fn type_of(&mut self, schema: &Value, hint: &str) -> String {
        let Some(object) = schema.as_object() else {
            return "Any".to_owned();
        };
        let ty = self.base_type(object, hint);

        if object.get("nullable").and_then(Value::as_bool) == Some(true) {
            return union([ty, "None".to_owned()]);
        }

        ty
    }

    fn base_type(&mut self, object: &Map<String, Value>, hint: &str) -> String {
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            return self.ref_type(reference);
        }
        if let Some(literal) = object.get("const").and_then(literal_of) {
            return format!("Literal[{literal}]");
        }
        if let Some(values) = object.get("enum").and_then(Value::as_array)
            && let Some(ty) = literal_union(values)
        {
            return ty;
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(members) = object.get(key).and_then(Value::as_array) {
                let mut types = Vec::with_capacity(members.len());
                for (index, member) in members.iter().enumerate() {
                    types.push(self.type_of(member, &format!("{hint}Option{}", index + 1)));
                }

                return union(types);
            }
        }
        if let Some(members) = object.get("allOf").and_then(Value::as_array) {
            return self.all_of(object, members, hint);
        }

        match object.get("type") {
            Some(Value::String(name)) => self.typed(name, object, hint),
            Some(Value::Array(names)) => {
                let mut types = Vec::with_capacity(names.len());
                for name in names.iter().filter_map(Value::as_str) {
                    types.push(self.typed(name, object, hint));
                }

                union(types)
            }
            _ if object.contains_key("properties") => self.object_type(object, hint),
            _ if object.contains_key("items") || object.contains_key("prefixItems") => {
                self.array_type(object, hint)
            }
            _ => "Any".to_owned(),
        }
    }

    fn typed(&mut self, name: &str, object: &Map<String, Value>, hint: &str) -> String {
        match name {
            "string" => "str".to_owned(),
            "integer" => "int".to_owned(),
            "number" => "float".to_owned(),
            "boolean" => "bool".to_owned(),
            "null" => "None".to_owned(),
            "array" => self.array_type(object, hint),
            "object" => self.object_type(object, hint),
            _ => "Any".to_owned(),
        }
    }

    fn array_type(&mut self, object: &Map<String, Value>, hint: &str) -> String {
        let tuple_items = object
            .get("prefixItems")
            .and_then(Value::as_array)
            .or_else(|| object.get("items").and_then(Value::as_array));
        if let Some(items) = tuple_items {
            let mut types = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                types.push(self.type_of(item, &format!("{hint}Item{}", index + 1)));
            }

            return if types.is_empty() {
                "list[Any]".to_owned()
            } else {
                format!("tuple[{}]", types.join(", "))
            };
        }

        match object.get("items") {
            Some(items) => format!("list[{}]", self.type_of(items, &format!("{hint}Item"))),
            None => "list[Any]".to_owned(),
        }
    }

    fn object_type(&mut self, object: &Map<String, Value>, hint: &str) -> String {
        let has_properties = object
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| !properties.is_empty());
        if has_properties {
            let name = self.unique_name(hint);
            self.build_typed_dict(name.clone(), object);

            return name;
        }

        match object.get("additionalProperties") {
            Some(schema @ Value::Object(_)) => {
                format!(
                    "dict[str, {}]",
                    self.type_of(schema, &format!("{hint}Value"))
                )
            }
            _ => "dict[str, Any]".to_owned(),
        }
    }

    fn build_typed_dict(&mut self, name: String, object: &Map<String, Value>) {
        let fields = self.properties(object, &name);
        let doc = object
            .get("description")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned);

        self.declarations.push(TypedDictDecl { name, doc, fields });
    }

    fn ref_type(&mut self, reference: &str) -> String {
        if let Some(ty) = self.ref_types.get(reference) {
            return ty.clone();
        }
        // a cycle through something other than an object: give up on precision
        if self.in_progress.contains(reference) {
            return "Any".to_owned();
        }
        let Some(target) = self.resolve(reference) else {
            return "Any".to_owned();
        };
        let definition = reference.rsplit('/').next().unwrap_or("Definition");
        let hint = format!("{}{}", self.prefix, pascal_case(definition));

        if let Some(object) = plain_object_with_properties(&target) {
            // register the name first so recursive properties resolve to it
            let name = self.unique_name(&hint);
            self.ref_types.insert(reference.to_owned(), name.clone());
            self.build_typed_dict(name.clone(), object);

            return name;
        }

        self.in_progress.insert(reference.to_owned());
        let ty = self.type_of(&target, &hint);
        self.in_progress.remove(reference);
        self.ref_types.insert(reference.to_owned(), ty.clone());

        ty
    }

    fn all_of(&mut self, outer: &Map<String, Value>, members: &[Value], hint: &str) -> String {
        let mut merged = Map::new();
        let mut required: Vec<Value> = Vec::new();

        let mut sources: Vec<Value> = Vec::new();
        for member in members {
            let resolved = match member.get("$ref").and_then(Value::as_str) {
                Some(reference) => self.resolve(reference).unwrap_or(Value::Null),
                None => member.clone(),
            };
            sources.push(resolved);
        }
        sources.push(Value::Object(outer.clone()));

        for source in &sources {
            let Some(source) = source.as_object() else {
                return "Any".to_owned();
            };
            if let Some(properties) = source.get("properties").and_then(Value::as_object) {
                merged.extend(
                    properties
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone())),
                );
            } else if source
                .keys()
                .any(|key| matches!(key.as_str(), "anyOf" | "oneOf" | "enum" | "items"))
                || source
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name != "object")
            {
                return "Any".to_owned();
            }
            if let Some(names) = source.get("required").and_then(Value::as_array) {
                required.extend(names.iter().cloned());
            }
        }
        if merged.is_empty() {
            return "Any".to_owned();
        }

        let mut synthetic = Map::new();
        synthetic.insert("type".to_owned(), Value::String("object".to_owned()));
        synthetic.insert("properties".to_owned(), Value::Object(merged));
        synthetic.insert("required".to_owned(), Value::Array(required));
        if let Some(description) = outer.get("description") {
            synthetic.insert("description".to_owned(), description.clone());
        }

        self.object_type(&synthetic, hint)
    }
}

fn plain_object_with_properties(schema: &Value) -> Option<&Map<String, Value>> {
    let object = schema.as_object()?;
    let combinators = ["anyOf", "oneOf", "allOf", "enum", "const", "$ref"];
    if combinators.iter().any(|key| object.contains_key(*key)) {
        return None;
    }
    let is_object = match object.get("type") {
        None => true,
        Some(Value::String(name)) => name == "object",
        Some(_) => false,
    };
    let has_properties = object
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| !properties.is_empty());

    (is_object && has_properties).then_some(object)
}

/// Python literal for a JSON scalar usable inside `Literal[...]`
fn literal_of(value: &Value) -> Option<String> {
    match value {
        Value::String(_) => serde_json::to_string(value).ok(),
        Value::Bool(true) => Some("True".to_owned()),
        Value::Bool(false) => Some("False".to_owned()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(number.to_string()),
        Value::Null => Some("None".to_owned()),
        _ => None,
    }
}

fn literal_union(values: &[Value]) -> Option<String> {
    let mut literals = Vec::new();
    let mut nullable = false;
    for value in values {
        match literal_of(value)? {
            none if none == "None" => nullable = true,
            literal => literals.push(literal),
        }
    }
    if literals.is_empty() {
        return nullable.then(|| "None".to_owned());
    }

    let ty = format!("Literal[{}]", literals.join(", "));

    Some(if nullable {
        union([ty, "None".to_owned()])
    } else {
        ty
    })
}

/// Joins types into a union, dropping duplicates; `Any` absorbs everything
fn union(types: impl IntoIterator<Item = String>) -> String {
    let mut seen: Vec<String> = Vec::new();
    for ty in types {
        for member in union_members(&ty) {
            if !seen.iter().any(|existing| existing == member) {
                seen.push(member.to_owned());
            }
        }
    }
    if seen.is_empty() || seen.iter().any(|member| member == "Any") {
        return "Any".to_owned();
    }
    // None reads best at the end
    if let Some(position) = seen.iter().position(|member| member == "None") {
        let none = seen.remove(position);
        seen.push(none);
    }

    seen.join(" | ")
}

/// Splits a rendered type on top-level `|`
fn union_members(ty: &str) -> Vec<&str> {
    let mut depth = 0usize;
    let mut start = 0;
    let mut members = Vec::new();
    for (index, character) in ty.char_indices() {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                members.push(ty[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    members.push(ty[start..].trim());

    members
}

/// Everything needed to render one tool's `async def`
struct Signature<'a> {
    function: &'a str,
    properties: &'a [Property],
    /// Extra keyword arguments are accepted beyond the declared ones
    open: bool,
    return_type: &'a str,
}

impl Signature<'_> {
    /// Properties usable as plain keyword parameters
    fn identifiers(&self) -> impl Iterator<Item = &Property> {
        self.properties
            .iter()
            .filter(|property| is_identifier(&property.name))
    }

    /// Properties whose names can only travel through `**kwargs`
    fn awkward(&self) -> impl Iterator<Item = &Property> {
        self.properties
            .iter()
            .filter(|property| !is_identifier(&property.name))
    }

    fn takes_kwargs(&self) -> bool {
        self.open || self.awkward().next().is_some()
    }

    fn render(&self) -> String {
        let mut parameters: Vec<String> = self
            .identifiers()
            .map(|property| {
                if property.required {
                    format!("{}: {}", property.name, property.ty)
                } else if property.accepts_null {
                    format!("{}: {} = None", property.name, property.ty)
                } else {
                    format!("{}: {} | None = None", property.name, property.ty)
                }
            })
            .collect();
        if !parameters.is_empty() {
            parameters.insert(0, "*".to_owned());
        }
        if self.takes_kwargs() {
            parameters.push("**kwargs: Any".to_owned());
        }

        format!(
            "async def {}({}) -> {}",
            self.function,
            parameters.join(", "),
            self.return_type
        )
    }
}

fn render_check(declarations: &[TypedDictDecl], signature: &str) -> String {
    let mut out = String::new();
    for declaration in declarations {
        render_typed_dict(&mut out, declaration, false);
        out.push('\n');
    }
    out.push_str(signature);
    out.push_str(": ...\n");

    out
}

fn render_describe(
    declarations: &[TypedDictDecl],
    signature: &Signature<'_>,
    description: Option<&str>,
    variants: bool,
) -> String {
    let mut out = String::new();
    for declaration in declarations {
        render_typed_dict(&mut out, declaration, true);
        out.push('\n');
    }

    let mut doc = description.map(str::trim).unwrap_or_default().to_owned();
    let documented: Vec<&Property> = signature
        .identifiers()
        .filter(|property| property.doc.is_some())
        .collect();
    if !documented.is_empty() {
        append_section(&mut doc, "Args:");
        for property in documented {
            let line = format!(
                "{}: {}",
                property.name,
                property.doc.as_deref().unwrap_or("")
            );
            doc.push_str(&indent_continuation(&line, "    ", "        "));
            doc.push('\n');
        }
    }

    let awkward: Vec<&Property> = signature.awkward().collect();
    if !awkward.is_empty() {
        append_section(
            &mut doc,
            "Keyword arguments whose names are not Python identifiers; pass them as **{\"name\": value}:",
        );
        for property in awkward {
            let requirement = if property.required {
                "required"
            } else {
                "optional"
            };
            let line = format!(
                "\"{}\": {} ({requirement}) {}",
                property.name,
                property.ty,
                property.doc.as_deref().unwrap_or("")
            );
            doc.push_str(&indent_continuation(line.trim_end(), "    ", "        "));
            doc.push('\n');
        }
    }
    if variants {
        append_section(
            &mut doc,
            "The tool accepts alternative argument shapes. Parameters above are merged from all of \
             them, so which are required depends on the variant; further keyword arguments are \
             passed through.",
        );
    } else if signature.open {
        append_section(
            &mut doc,
            "Further keyword arguments are accepted and passed through to the tool.",
        );
    }

    out.push_str(&signature.render());
    if doc.trim().is_empty() {
        out.push_str(": ...\n");
    } else {
        out.push_str(":\n");
        out.push_str(&docstring(doc.trim_end(), 1));
        out.push_str("    ...\n");
    }

    out
}

/// Starts a new paragraph in a docstring under construction
fn append_section(doc: &mut String, heading: &str) {
    if !doc.is_empty() {
        doc.push_str("\n\n");
    }
    doc.push_str(heading);
    doc.push('\n');
}

fn render_typed_dict(out: &mut String, declaration: &TypedDictDecl, with_docs: bool) {
    let class_syntax = declaration
        .fields
        .iter()
        .all(|field| is_identifier(&field.name));

    if !class_syntax {
        let entries: Vec<String> = declaration
            .fields
            .iter()
            .map(|field| {
                let key = serde_json::to_string(&field.name).unwrap_or_else(|_| "\"\"".to_owned());
                format!("{key}: {}", field_type(field))
            })
            .collect();
        out.push_str(&format!(
            "{name} = TypedDict(\"{name}\", {{{entries}}})\n",
            name = declaration.name,
            entries = entries.join(", ")
        ));

        return;
    }

    out.push_str(&format!("class {}(TypedDict):\n", declaration.name));
    let mut wrote_body = false;
    if with_docs && let Some(doc) = &declaration.doc {
        out.push_str(&docstring(doc, 1));
        wrote_body = true;
    }
    for field in &declaration.fields {
        out.push_str(&format!("    {}: {}\n", field.name, field_type(field)));
        wrote_body = true;
        if with_docs && let Some(doc) = &field.doc {
            out.push_str(&docstring(doc, 1));
        }
    }
    if !wrote_body {
        out.push_str("    pass\n");
    }
}

fn field_type(field: &Property) -> String {
    if field.required {
        field.ty.clone()
    } else {
        format!("NotRequired[{}]", field.ty)
    }
}

/// Renders `text` as a triple-quoted docstring indented `level` steps
fn docstring(text: &str, level: usize) -> String {
    let indent = "    ".repeat(level);
    let escaped = text.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    let mut lines = escaped.lines();
    let mut out = String::new();

    out.push_str(&indent);
    out.push_str("\"\"\"");
    out.push_str(lines.next().unwrap_or("").trim_end());
    for line in lines {
        out.push('\n');
        if !line.trim().is_empty() {
            out.push_str(&indent);
            out.push_str(line.trim_end());
        }
    }
    out.push('\n');
    out.push_str(&indent);
    out.push_str("\"\"\"\n");

    out
}

/// Indents every line after the first so wrapped text stays under its label
fn indent_continuation(text: &str, first: &str, rest: &str) -> String {
    let mut out = String::new();
    for (index, line) in text.lines().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(if index == 0 { first } else { rest });
        out.push_str(line.trim_end());
    }

    out
}

fn compact_json(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() > 80 {
        let head: String = text.chars().take(77).collect();

        return format!("{head}...");
    }

    text
}

/// Whether `name` can be used as a Python keyword argument
pub fn is_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    let valid_start = characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic());

    valid_start
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        && !PYTHON_KEYWORDS.contains(&name)
}

/// Converts an identifier or phrase to `PascalCase`
pub fn pascal_case(text: &str) -> String {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn nested_objects_enums_unions_and_refs_become_typed_stubs() {
        let input = schema(json!({
            "type": "object",
            "required": ["query", "mode"],
            "properties": {
                "query": {"type": "string", "description": "What to find"},
                "mode": {"enum": ["fast", "deep"]},
                "limit": {"type": ["integer", "null"], "default": 5},
                "filter": {"$ref": "#/$defs/Filter"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "either": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            },
            "$defs": {
                "Filter": {
                    "type": "object",
                    "description": "Narrow the search",
                    "required": ["field"],
                    "properties": {
                        "field": {"type": "string"},
                        "parent": {"$ref": "#/$defs/Filter"},
                        "bad-key": {"type": "boolean"},
                    },
                },
            },
        }));
        let output = schema(json!({
            "type": "object",
            "required": ["total"],
            "properties": {"total": {"type": "integer"}},
        }));

        let stub = StubBook::new().tool(
            "docs_search",
            Some("Search the docs\nsecond line"),
            &input,
            Some(&output),
        );

        assert!(
            stub.check
                .contains("DocsSearchFilter = TypedDict(\"DocsSearchFilter\""),
            "{}",
            stub.check
        );
        assert!(
            stub.check
                .contains("\"parent\": NotRequired[DocsSearchFilter]"),
            "{}",
            stub.check
        );
        assert!(
            stub.check.contains("mode: Literal[\"fast\", \"deep\"]"),
            "{}",
            stub.check
        );
        assert!(
            stub.check.contains("limit: int | None = None"),
            "{}",
            stub.check
        );
        assert!(
            stub.check.contains("either: str | int | None = None"),
            "{}",
            stub.check
        );
        assert!(
            stub.check.ends_with("-> DocsSearchResult: ...\n"),
            "{}",
            stub.check
        );
        assert!(
            stub.describe.contains("Search the docs\n    second line"),
            "{}",
            stub.describe
        );
        assert!(
            stub.describe.contains("query: What to find"),
            "{}",
            stub.describe
        );
        assert!(stub.omit_if_none.contains("either") && !stub.omit_if_none.contains("limit"));
    }

    #[test]
    fn awkward_parameter_names_stay_typed_beside_kwargs() {
        let input = schema(json!({
            "type": "object",
            "required": ["q"],
            "properties": {"q": {"type": "string"}, "class": {"type": "string"}},
        }));

        let stub = StubBook::new().tool("t_x", None, &input, None);

        assert!(stub.non_identifier_params);
        assert!(
            stub.check
                .contains("async def t_x(*, q: str, **kwargs: Any) -> Any"),
            "{}",
            stub.check
        );
        assert!(
            stub.describe.contains("\"class\": str (optional)"),
            "{}",
            stub.describe
        );
    }

    #[test]
    fn root_ref_and_all_of_resolve_to_one_parameter_list() {
        let input = schema(json!({
            "$ref": "#/$defs/Args",
            "$defs": {
                "Args": {
                    "allOf": [
                        {"$ref": "#/$defs/Base"},
                        {"type": "object", "properties": {"limit": {"type": "integer"}}},
                    ],
                },
                "Base": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                },
            },
        }));

        let stub = StubBook::new().tool("t_x", None, &input, None);

        assert!(
            stub.check
                .contains("async def t_x(*, query: str, limit: int | None = None) -> Any"),
            "{}",
            stub.check
        );
    }

    #[test]
    fn one_of_open_objects_and_unknown_shapes_accept_extra_keywords() {
        let one_of = schema(json!({
            "oneOf": [
                {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
                {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
            ],
        }));
        let open = schema(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "additionalProperties": true,
        }));
        let closed = schema(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "additionalProperties": false,
        }));
        let unknown = schema(json!({"type": "object"}));

        let mut book = StubBook::new();
        let one_of = book.tool("t_one", None, &one_of, None);
        let open = book.tool("t_open", None, &open, None);
        let closed = book.tool("t_closed", None, &closed, None);
        let unknown = book.tool("t_unknown", None, &unknown, None);

        assert!(
            one_of.check.contains(
                "async def t_one(*, id: str | None = None, name: str | None = None, **kwargs: Any)"
            ),
            "{}",
            one_of.check
        );
        assert!(one_of.describe.contains("id: str"), "{}", one_of.describe);
        assert!(
            open.check
                .contains("(*, a: str | None = None, **kwargs: Any)")
        );
        assert!(!closed.check.contains("kwargs"));
        assert!(unknown.check.contains("async def t_unknown(**kwargs: Any)"));
    }

    #[test]
    fn fallback_stub_keeps_parameters_and_marks_the_tool_degraded() {
        let input = schema(json!({
            "type": "object",
            "properties": {"query": {"type": "string"}},
        }));

        let stub = fallback_stub("t_x", Some("Search"), &input);

        assert!(stub.degraded);
        assert!(stub.check.contains("**kwargs: Any"));
        assert!(stub.describe.contains("# degraded"), "{}", stub.describe);
        assert!(stub.describe.contains("\"query\""), "{}", stub.describe);
    }
}
