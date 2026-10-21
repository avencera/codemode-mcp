//! The merged tool catalog: namespacing, stubs and search

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    config::{Config, OutputMode, ServerConfig, ToolOverride},
    json_access,
    output::OutputSpec,
    policy::{GrantMode, Policy},
    search::{SearchIndex, SearchText},
    stubs::{
        Declaration, JSON_VALUE_ALIAS, STUB_HEADER, StubBook, StubOutput, TYPE_KEYWORD, ToolStub,
        branded_outputs, fallback_stub,
    },
};

/// Tools one upstream currently offers
#[derive(Debug, Clone)]
pub struct ServerSnapshot {
    /// Server name from the config
    pub name: String,
    /// Last tool list received from the server
    pub tools: Vec<Tool>,
    /// Instructions the server sent in its handshake
    pub instructions: Option<String>,
    /// Whether the server is connected right now
    pub available: bool,
}

/// One tool of a hub's server, as its spokes get it
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportedTool {
    /// The tool with the input scripts pass: configured arguments left out,
    /// configured parameter types marked in. Its output schema is unset;
    /// `output` says what scripts get
    pub tool: Tool,
    /// The hub's policy for it, which the hub enforces itself
    pub policy: Policy,
    /// How far one approval of it reaches
    pub grant: GrantMode,
    /// What scripts get back
    pub output: OutputSpec,
}

impl PartialEq for OutputSpec {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Untyped, Self::Untyped) | (Self::Text, Self::Text) => true,
            (Self::Schema(left), Self::Schema(right)) => left == right,
            _ => false,
        }
    }
}

/// The tools of `snapshot` a spoke may call, as [`Catalog::build`] would
/// show them here; denied tools are left out, since they can never run
pub fn export_tools(config: &Config, snapshot: &ServerSnapshot) -> Vec<ExportedTool> {
    let server = config.servers.get(&snapshot.name);

    snapshot
        .tools
        .iter()
        .filter_map(|tool| {
            let policy = server.map_or(Policy::Allow, |server| server.policy_for(&tool.name));
            if policy == Policy::Deny {
                return None;
            }
            let tool_override = server.and_then(|server| server.tool_override(&tool.name));
            let input = branded_input(
                &snapshot.name,
                &tool.name,
                shown_input(&tool.input_schema, server),
                tool_override,
            )
            .into_owned();
            let mut exported = tool.clone();
            exported.input_schema = Arc::new(input);
            exported.output_schema = None;

            Some(ExportedTool {
                policy,
                grant: server
                    .map_or_else(GrantMode::default, |server| server.grant_for(&tool.name)),
                output: effective_output(&snapshot.name, tool, tool_override),
                tool: exported,
            })
        })
        .collect()
}

/// One callable tool
#[derive(Debug, Clone)]
pub struct ToolEntry {
    /// Python name scripts call, `<server>_<tool>` sanitized
    pub function: String,
    /// Upstream server name
    pub server: String,
    /// Tool name as the upstream knows it
    pub tool: String,
    /// Full description
    pub description: String,
    /// Parameter names
    pub params: Vec<String>,
    /// Generated Python declarations
    pub stub: ToolStub,
    /// Policy after applying per-tool overrides
    pub policy: Policy,
    /// What scripts get back: the upstream's or the config's schema, the
    /// joined text, or an untyped `JsonValue`
    pub output: OutputSpec,
    /// The typed stub was rejected by the type checker and replaced by a
    /// permissive one
    pub degraded: bool,
    /// Whether the owning server is connected
    pub available: bool,
}

impl ToolEntry {
    /// First non-empty description line, trimmed to a reasonable length
    pub fn summary(&self) -> String {
        let line = self
            .description
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("");

        if line.chars().count() > 200 {
            let head: String = line.chars().take(197).collect();

            return format!("{head}...");
        }

        line.to_owned()
    }
}

/// Immutable snapshot of every known tool; rebuilt when an upstream changes
#[derive(Debug, Default)]
pub struct Catalog {
    entries: Vec<ToolEntry>,
    by_function: HashMap<String, usize>,
    /// Positions of the entries search and describe may show
    visible: Vec<usize>,
    index: SearchIndex,
    check_stubs: String,
    /// Names of the branded string types the stubs declare
    brands: HashSet<String>,
    /// Each server's handshake instructions as stub comments, by server name
    notes: HashMap<String, String>,
}

impl Catalog {
    /// Builds the catalog; tools named in `fallback` get a permissive stub
    /// because their generated one was rejected by the type checker
    pub fn build(
        config: &Config,
        snapshots: &[ServerSnapshot],
        fallback: &HashSet<String>,
    ) -> Self {
        let mut entries = Vec::new();
        let names = function_names(snapshots);
        let mut book = StubBook::new();

        // results are typed before any parameter is, so a parameter's docs
        // can name the tool whose result it takes
        let outputs: Vec<Vec<OutputSpec>> = snapshots
            .iter()
            .map(|snapshot| {
                let server = config.servers.get(&snapshot.name);

                snapshot
                    .tools
                    .iter()
                    .map(|tool| {
                        effective_output(
                            &snapshot.name,
                            tool,
                            server.and_then(|server| server.tool_override(&tool.name)),
                        )
                    })
                    .collect()
            })
            .collect();
        for (function_names, outputs) in names.iter().zip(&outputs) {
            for (function, output) in function_names.iter().zip(outputs) {
                if let OutputSpec::Schema(schema) = output {
                    book.add_brand_sources(branded_outputs(function, schema));
                }
            }
        }

        for ((snapshot, function_names), outputs) in snapshots.iter().zip(&names).zip(outputs) {
            let server = config.servers.get(&snapshot.name);
            if let Some(server) = server
                && !snapshot.tools.is_empty()
            {
                for configured in server.tools.keys() {
                    if !snapshot.tools.iter().any(|tool| tool.name == *configured) {
                        tracing::warn!(
                            server = %snapshot.name,
                            tool = %configured,
                            "policy override names a tool the server does not list"
                        );
                    }
                }
            }

            for ((tool, function), output) in snapshot.tools.iter().zip(function_names).zip(outputs)
            {
                let function = function.clone();
                // configured arguments come out first, so a brand can only
                // land on a parameter the script still passes
                let input = branded_input(
                    &snapshot.name,
                    &tool.name,
                    shown_input(&tool.input_schema, server),
                    server.and_then(|server| server.tool_override(&tool.name)),
                );
                let description = tool
                    .description
                    .as_deref()
                    .or(tool.title.as_deref())
                    .unwrap_or("")
                    .to_owned();
                // only the docstring carries the note, so search ranks tools
                // by what they do
                let documented = match server.and_then(|server| approval_note(server, &tool.name)) {
                    Some(note) if description.trim().is_empty() => note.to_owned(),
                    Some(note) => format!("{}\n\n{note}", description.trim_end()),
                    None => description.clone(),
                };
                let degraded = fallback.contains(&function);
                let stub = if degraded {
                    fallback_stub(&function, Some(&documented), &input)
                } else {
                    let stub_output = match &output {
                        OutputSpec::Schema(schema) => StubOutput::Schema(schema),
                        OutputSpec::Text => StubOutput::Text,
                        OutputSpec::Untyped => StubOutput::Untyped,
                    };

                    book.tool(&function, Some(&documented), &input, stub_output)
                };
                let params = input
                    .get("properties")
                    .and_then(|properties| properties.as_object())
                    .map(|properties| properties.keys().cloned().collect())
                    .unwrap_or_default();

                entries.push(ToolEntry {
                    function,
                    server: snapshot.name.clone(),
                    tool: tool.name.to_string(),
                    description,
                    params,
                    stub,
                    policy: server.map_or(Policy::Allow, |server| server.policy_for(&tool.name)),
                    output,
                    degraded,
                    available: snapshot.available,
                });
            }
        }

        // denied tools can never run, so agents should not spend effort on them
        let visible: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.policy != Policy::Deny)
            .map(|(position, _)| position)
            .collect();
        let index = SearchIndex::build(visible.iter().map(|position| {
            let entry = &entries[*position];

            SearchText {
                name: &entry.function,
                description: &entry.description,
                params: &entry.params,
                aliases: config
                    .servers
                    .get(&entry.server)
                    .map_or(&[][..], |server| server.aliases.as_slice()),
            }
        }));
        let by_function = entries
            .iter()
            .enumerate()
            .map(|(position, entry)| (entry.function.clone(), position))
            .collect();
        let mut check_stubs = format!(
            "{STUB_HEADER}{JSON_VALUE_ALIAS}{}",
            json_access::CHECK_STUBS
        );
        let mut declared = BTreeSet::new();
        for entry in &entries {
            for declaration in &entry.stub.declarations {
                if declared.insert(declaration.name.clone()) {
                    check_stubs.push('\n');
                    check_stubs.push_str(&declaration.check);
                }
            }
        }
        for entry in &entries {
            check_stubs.push('\n');
            check_stubs.push_str(&entry.stub.signature);
        }

        let notes = snapshots
            .iter()
            .filter_map(|snapshot| {
                let note = server_note(&snapshot.name, snapshot.instructions.as_deref()?)?;

                Some((snapshot.name.clone(), note))
            })
            .collect();

        Self {
            entries,
            by_function,
            visible,
            index,
            check_stubs,
            brands: book.brands(),
            notes,
        }
    }

    /// Whether `name` is a branded string type the stubs declare
    ///
    /// The sandbox has no such name, so a script that calls one as a
    /// constructor would otherwise fail in a confusing way
    pub fn is_brand(&self, name: &str) -> bool {
        self.brands.contains(name)
    }

    /// Every tool, in server then tool order
    pub fn entries(&self) -> &[ToolEntry] {
        &self.entries
    }

    /// Looks up a tool by its server and upstream name, as a spoke names
    /// the hub's tools
    pub fn find(&self, server: &str, tool: &str) -> Option<&ToolEntry> {
        self.entries
            .iter()
            .find(|entry| entry.server == server && entry.tool == tool)
    }

    /// Looks up a tool by its Python name
    pub fn get(&self, function: &str) -> Option<&ToolEntry> {
        self.by_function
            .get(function)
            .map(|position| &self.entries[*position])
    }

    /// Type-checker declarations for every tool
    pub fn check_stubs(&self) -> &str {
        &self.check_stubs
    }

    /// Declarations for a single tool, usable to validate it in isolation
    pub fn check_stub_for(entry: &ToolEntry) -> String {
        format!("{STUB_HEADER}{JSON_VALUE_ALIAS}\n{}", entry.stub.check())
    }

    /// Ranks tools against `query`; an empty query lists tools in catalog
    /// order. Denied tools are left out
    pub fn search(&self, query: &str, limit: usize) -> Vec<&ToolEntry> {
        if query.trim().is_empty() {
            return self
                .visible
                .iter()
                .take(limit)
                .map(|position| &self.entries[*position])
                .collect();
        }

        self.index
            .query(query, limit)
            .into_iter()
            .map(|(document, _)| &self.entries[self.visible[document]])
            .collect()
    }

    /// Documented declarations for the named tools, plus the names not found
    ///
    /// Denied tools count as not found. A type several tools share is
    /// declared once
    pub fn describe<'a>(&self, names: &'a [String]) -> (String, Vec<&'a str>) {
        let mut missing = Vec::new();
        let mut seen = BTreeSet::new();
        let mut declared: BTreeSet<&str> = BTreeSet::new();
        let mut types = String::new();
        let mut bodies = String::new();
        let mut needs_kwargs_note = false;
        let mut needs_json_value = false;
        let mut servers: BTreeSet<&str> = BTreeSet::new();

        for name in names {
            match self
                .get(name.trim())
                .filter(|entry| entry.policy != Policy::Deny)
            {
                Some(entry) if seen.insert(entry.function.clone()) => {
                    servers.insert(&entry.server);
                    needs_kwargs_note |= entry.stub.non_identifier_params;
                    needs_json_value |= entry.stub.uses_json_value;
                    declare_once(&mut types, &mut declared, &entry.stub.declarations);
                    bodies.push('\n');
                    bodies.push_str(&entry.stub.documented);
                }
                Some(_) => {}
                None => missing.push(name.as_str()),
            }
        }

        let mut out = String::from(STUB_HEADER);
        if needs_json_value {
            out.push_str(JSON_VALUE_ALIAS);
            out.push_str(json_access::DOCUMENTED);
        }
        if needs_kwargs_note {
            out.push_str(KWARGS_NOTE);
        }
        // rules such as "call authenticate first" often live only here, and
        // an agent reads the stubs of the tool it wants, not its siblings'
        for server in servers {
            if let Some(note) = self.notes.get(server) {
                out.push_str(note);
            }
        }
        out.push_str(&types);
        out.push_str(&bodies);

        (out, missing)
    }
}

/// Appends the documented form of each declaration not yet in `declared`
fn declare_once<'a>(
    out: &mut String,
    declared: &mut BTreeSet<&'a str>,
    declarations: &'a [Arc<Declaration>],
) {
    for declaration in declarations {
        if declared.insert(&declaration.name) {
            out.push('\n');
            out.push_str(&declaration.describe);
        }
    }
}

/// The tool's input schema with the configured brands written into it
///
/// Only a parameter declared directly in `properties` with a string type can
/// be branded; a name that is missing or has another type is reported and
/// left as the upstream declares it
fn branded_input<'a>(
    server: &str,
    tool: &str,
    input: Cow<'a, Map<String, Value>>,
    tool_override: Option<&ToolOverride>,
) -> Cow<'a, Map<String, Value>> {
    let Some(over) = tool_override.filter(|over| !over.param_types.is_empty()) else {
        return input;
    };
    let mut schema = input.into_owned();

    for (param, brand) in &over.param_types {
        let property = schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|properties| properties.get_mut(param))
            .and_then(serde_json::Value::as_object_mut);
        let Some(property) = property else {
            tracing::warn!(
                server,
                tool,
                param,
                "param_types names a parameter the tool does not declare"
            );

            continue;
        };
        if !allows_string(property) {
            tracing::warn!(
                server,
                tool,
                param,
                "param_types only brands string parameters; this one is typed otherwise"
            );

            continue;
        }

        property.insert(
            TYPE_KEYWORD.to_owned(),
            serde_json::Value::String(brand.clone()),
        );
    }

    Cow::Owned(schema)
}

/// Whether a property schema declares a `string` type, alone or in a list
fn allows_string(property: &serde_json::Map<String, serde_json::Value>) -> bool {
    match property.get("type") {
        Some(serde_json::Value::String(name)) => name == "string",
        Some(serde_json::Value::Array(names)) => names.iter().any(|name| name == "string"),
        _ => false,
    }
}

/// The effective output of a tool: text when the config says so, else the
/// schema the upstream declares or the config supplies
///
/// The config's schema only fills in for an upstream that declares none,
/// unless it is forced
fn effective_output(
    server: &str,
    tool: &rmcp::model::Tool,
    tool_override: Option<&ToolOverride>,
) -> OutputSpec {
    if tool_override.is_some_and(|over| over.output == Some(OutputMode::Text)) {
        return OutputSpec::Text;
    }
    let configured =
        tool_override.and_then(|over| over.output_schema.as_ref().map(|schema| (over, schema)));

    match (&tool.output_schema, configured) {
        (Some(_), Some((over, schema))) if over.force_output_schema => {
            OutputSpec::Schema(Arc::new(schema.clone()))
        }
        (Some(declared), Some(_)) => {
            tracing::info!(
                server,
                tool = %tool.name,
                "using the output schema the server declares; the configured one only applies when forced"
            );

            OutputSpec::Schema(Arc::clone(declared))
        }
        (Some(declared), None) => OutputSpec::Schema(Arc::clone(declared)),
        (None, Some((_, schema))) => OutputSpec::Schema(Arc::new(schema.clone())),
        (None, None) => OutputSpec::Untyped,
    }
}

/// The input schema scripts see: arguments the server config supplies are
/// left out, so a script cannot pass a wrong one
fn shown_input<'a>(
    schema: &'a Map<String, Value>,
    server: Option<&ServerConfig>,
) -> Cow<'a, Map<String, Value>> {
    let Some(fixed) = server
        .map(|server| &server.arguments)
        .filter(|fixed| !fixed.is_empty())
    else {
        return Cow::Borrowed(schema);
    };
    let declares_one = schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| fixed.keys().any(|name| properties.contains_key(name)));
    if !declares_one {
        return Cow::Borrowed(schema);
    }

    let mut shown = schema.clone();
    if let Some(Value::Object(properties)) = shown.get_mut("properties") {
        properties.retain(|name, _| !fixed.contains_key(name));
    }
    if let Some(Value::Array(required)) = shown.get_mut("required") {
        required.retain(|name| name.as_str().is_none_or(|name| !fixed.contains_key(name)));
    }

    Cow::Owned(shown)
}

/// Longest server note `describe` repeats; instructions are upstream text
/// and some servers send pages of it
const NOTE_LIMIT: usize = 2000;

/// A server's instructions as Python comments, or nothing when they are blank
fn server_note(server: &str, instructions: &str) -> Option<String> {
    let instructions = instructions.trim();
    if instructions.is_empty() {
        return None;
    }

    let mut text: String = instructions.chars().take(NOTE_LIMIT).collect();
    if text.len() < instructions.len() {
        text.push('…');
    }
    let mut note = format!("# Instructions from the {server} server:\n");
    for line in text.lines() {
        note.push_str(format!("#   {line}").trim_end());
        note.push('\n');
    }

    Some(note)
}

/// Shown when a described tool has parameters that are not Python identifiers
const KWARGS_NOTE: &str = "# Parameters whose names are not valid Python identifiers (for example \
    `page-size`) are passed as **{\"page-size\": value}.\n";

/// Appended to a short hash so renamed colliding tools stay recognizable
const HASH_HEX_DIGITS: usize = 6;

/// Chooses the Python name of every tool, in the shape of `snapshots`
///
/// Names that collide after sanitizing are resolved by sorting, not by the
/// order tools arrived in: a tool whose own name needs no sanitizing keeps the
/// plain name, the rest get a short stable hash of `server` and `tool`
/// What an agent should know about approving a call of `tool`, when it
/// needs approval
fn approval_note(server: &ServerConfig, tool: &str) -> Option<&'static str> {
    if server.policy_for(tool) != Policy::Ask {
        return None;
    }

    Some(match server.grant_for(tool) {
        GrantMode::PerCall => {
            "Needs the user's approval for every call. To make several calls, start them \
             together with asyncio.gather instead of awaiting each in a loop: the user then \
             approves the whole set at once, and a loop asks once per call."
        }
        GrantMode::Session => {
            "Needs the user's approval; one approval can cover this server's tools for a while."
        }
    })
}

fn function_names(snapshots: &[ServerSnapshot]) -> Vec<Vec<String>> {
    struct Candidate<'a> {
        slot: (usize, usize),
        base: String,
        exact: bool,
        server: &'a str,
        tool: &'a str,
    }

    let mut candidates: Vec<Candidate<'_>> = Vec::new();
    for (server_index, snapshot) in snapshots.iter().enumerate() {
        for (tool_index, tool) in snapshot.tools.iter().enumerate() {
            let raw = format!("{}_{}", snapshot.name, tool.name);
            let base = sanitize_identifier(&raw);

            candidates.push(Candidate {
                slot: (server_index, tool_index),
                exact: base == raw,
                base,
                server: &snapshot.name,
                tool: &tool.name,
            });
        }
    }
    candidates.sort_by(|left, right| {
        (&left.base, !left.exact, left.server, left.tool).cmp(&(
            &right.base,
            !right.exact,
            right.server,
            right.tool,
        ))
    });

    let mut names: Vec<Vec<String>> = snapshots
        .iter()
        .map(|snapshot| vec![String::new(); snapshot.tools.len()])
        .collect();
    // the accessors are predefined in every script, so a tool named like one
    // is renamed as if another tool held the name
    let mut taken: HashSet<String> = json_access::NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    for candidate in candidates {
        let mut name = candidate.base.clone();
        if taken.contains(&name) {
            let hash = stable_hash(candidate.server, candidate.tool);
            name = format!("{}_{hash}", candidate.base);
        }
        // a hash clash or a tool literally named like a suffixed one
        let mut counter = 2;
        let stem = name.clone();
        while taken.contains(&name) {
            name = format!("{stem}_{counter}");
            counter += 1;
        }
        taken.insert(name.clone());
        names[candidate.slot.0][candidate.slot.1] = name;
    }

    names
}

/// First digits of an FNV-1a hash; unlike `DefaultHasher` it never changes
/// between Rust releases, so names stay stable across upgrades
fn stable_hash(server: &str, tool: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in server.bytes().chain([0]).chain(tool.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }

    format!("{hash:016x}")[..HASH_HEX_DIGITS].to_owned()
}

/// Start of every Python tool name of `server` (`<server>_`), before any
/// collision suffix
pub fn function_prefix(server: &str) -> String {
    sanitize_identifier(&format!("{server}_"))
}

/// Makes a valid Python identifier from arbitrary text
fn sanitize_identifier(raw: &str) -> String {
    let mut base: String = raw
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if base.starts_with(|character: char| character.is_ascii_digit()) {
        base.insert(0, '_');
    }

    base
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;

    fn tool(name: &str, description: &str) -> Tool {
        let schema =
            json!({"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]});
        let schema = schema.as_object().cloned().unwrap_or_default();

        Tool::new(name.to_owned(), description.to_owned(), Arc::new(schema))
    }

    #[test]
    fn collision_names_do_not_depend_on_tool_order() {
        let build = |tools: Vec<Tool>| {
            let snapshots = [ServerSnapshot {
                name: "docs".into(),
                tools,
                instructions: None,
                available: true,
            }];
            let catalog = Catalog::build(&Config::default(), &snapshots, &HashSet::new());

            catalog
                .entries()
                .iter()
                .map(|entry| (entry.tool.clone(), entry.function.clone()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };

        let forward = build(vec![
            tool("web-search", "Search the web"),
            tool("web_search", "Same after sanitizing"),
        ]);
        let reversed = build(vec![
            tool("web_search", "Same after sanitizing"),
            tool("web-search", "Search the web"),
        ]);

        assert_eq!(forward, reversed);
        assert_eq!(forward["web_search"], "docs_web_search");
        assert!(forward["web-search"].starts_with("docs_web_search_"));
        assert_ne!(forward["web-search"], forward["web_search"]);
    }

    #[test]
    fn denied_tools_are_hidden_from_search_and_describe() -> Result<(), crate::config::ConfigError>
    {
        let config = Config::parse(
            "[servers.docs]\ncommand = \"x\"\n[servers.docs.tools.drop_all]\npolicy = \"deny\"",
            std::path::Path::new("test.toml"),
        )?;
        let snapshots = [ServerSnapshot {
            name: "docs".into(),
            tools: vec![tool("drop_all", "Drop everything"), tool("list", "List")],
            instructions: None,
            available: true,
        }];

        let catalog = Catalog::build(&config, &snapshots, &HashSet::new());

        assert!(catalog.search("drop", 10).is_empty());
        assert_eq!(catalog.search("", 10).len(), 1);
        let names = ["docs_drop_all".to_owned()];
        let (text, missing) = catalog.describe(&names);
        assert_eq!(missing, ["docs_drop_all"]);
        assert!(!text.contains("drop"));
        // still callable at the policy layer, which reports the denial
        assert!(catalog.get("docs_drop_all").is_some());

        Ok(())
    }
}
