//! The hub's side: the `/hub/v1` routes, the spokes it trusts, and the
//! requests it holds for them
//!
//! A request a spoke asked for is held here until the owner decides it, and
//! a spoke follows it with [`WaitFor`]. A held call of the hub's own tool is
//! kept with its request, so the call that runs once it is approved is the
//! one the owner saw. Both survive a restart of either side: a spoke parks
//! on its copy of the request, and the hub restores the requests spokes
//! asked for (see [`Hub::restore`]) and checks a presented approval against
//! its stored row when the held call is gone: the row must be a hub tool's
//! request, for the same arguments, still in time. Each approval runs one
//! call, which the store records, so a restart does not let it run twice

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Query, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::{
    API, CATALOG_HEADER, CATALOG_WAIT, CallAnswer, ConfigAnswer, ConfigRead, ForwardedCall,
    GateAnswer, GateCall, HubError, HubErrorKind, ProgramReadCall, Refusal, Register, Registration,
    SPOKE_HEADER, WaitAnswer, WaitFor,
};
use crate::{
    admin::{OpFindRequest, op_find_response, op_read_response},
    approvals::{
        AdminAction, AdminRequest, Approvals, Gate, GateRequest, OwnerRequest, RemoteGate,
        SPOKE_SECRETS, Verdict, Waiting, confirmation_code, hex,
    },
    budget::Budget,
    companion::{FindAsk, ProgramAsk},
    config::Config,
    durable::Sensitivity,
    gateway::{CallContext, Gateway, Plan, PreparedCall},
    host::{is_direct_local, is_tailnet_address},
    prompt::one_line,
    secrets::approved::Consumer,
    store::{Store, now_ms, spokes::StoredSpoke},
    usage::{Caller, Machine},
};

/// How long a long poll for a verdict waits before answering "pending"
const WAIT_POLL: Duration = Duration::from_secs(25);
/// How long a decided request stays held for its spoke to run the call;
/// later, the stored row answers
const HELD_AFTER_DECISION: Duration = Duration::from_secs(10 * 60);
/// Longest spoke name or id accepted
const MAX_NAME_CHARS: usize = 64;
/// Most references one config read may name
const MAX_CONFIG_REFERENCES: usize = 32;
/// Longest reference accepted
const MAX_REFERENCE_CHARS: usize = 256;

/// The hub's state for its spokes
pub struct Hub {
    gateway: Arc<Gateway>,
    store: Store,
    config: Arc<Config>,
    state: Mutex<HubState>,
}

#[derive(Default)]
struct HubState {
    /// Trusted spokes by id; the store is the record, this the cache
    trusted: HashMap<String, StoredSpoke>,
    /// Open requests to trust a spoke, by spoke id
    trust_requests: HashMap<String, TrustRequest>,
    /// Requests spokes asked for, by request id
    held: HashMap<String, Held>,
}

struct TrustRequest {
    url: String,
    code: String,
    /// The tailnet address that asked
    address: String,
    /// Why the owner refused, once they did
    denied: Option<String>,
}

struct Held {
    spoke: String,
    verdict: watch::Receiver<Option<Verdict>>,
    /// The hub's own tool call waiting on the request
    call: Option<PreparedCall>,
}

impl Hub {
    /// The hub over `gateway`, trusting the spokes `store` lists
    pub fn new(gateway: Arc<Gateway>, store: Store, config: Arc<Config>) -> Arc<Self> {
        let trusted = match store.spokes() {
            Ok(spokes) => spokes
                .into_iter()
                .map(|spoke| (spoke.id.clone(), spoke))
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "could not read the trusted spokes");

                HashMap::new()
            }
        };

        Arc::new(Self {
            gateway,
            store,
            config,
            state: Mutex::new(HubState {
                trusted,
                ..HubState::default()
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn approvals(&self) -> &Arc<Approvals> {
        self.gateway.approvals()
    }

    /// Holds again the requests spokes asked for before a restart, and
    /// carries out a trust request's answer; call before
    /// `Approvals::abandon_orphans`, which withdraws whatever nothing took
    pub fn restore(self: &Arc<Self>, trust_requests: Vec<(Waiting, AdminAction)>) {
        for (waiting, action) in trust_requests {
            if let AdminAction::TrustSpoke { id, address, .. } = &action {
                self.state().trust_requests.insert(
                    id.clone(),
                    TrustRequest {
                        url: waiting.url().to_owned(),
                        code: String::new(),
                        address: address.clone(),
                        denied: None,
                    },
                );
            }
            self.attach_trust(waiting, action);
        }

        let approvals = Arc::clone(self.approvals());
        for waiting in approvals.restore_spoke_requests() {
            let spoke = approvals
                .stored(waiting.id())
                .and_then(|stored| stored.spoke)
                .unwrap_or_default();
            self.hold(&spoke, waiting, None);
        }
    }

    /// Every trusted spoke, oldest first
    pub fn spokes(&self) -> Vec<StoredSpoke> {
        let mut spokes: Vec<StoredSpoke> = self.state().trusted.values().cloned().collect();
        spokes.sort_by_key(|spoke| spoke.trusted_ms);

        spokes
    }

    /// Stops trusting the spoke with this id or name; `Err` when none or
    /// several match
    pub fn remove(&self, which: &str) -> Result<StoredSpoke, String> {
        let matching: Vec<StoredSpoke> = self
            .spokes()
            .into_iter()
            .filter(|spoke| spoke.id == which || spoke.name == which)
            .collect();
        let spoke = match matching.as_slice() {
            [spoke] => spoke.clone(),
            [] => return Err(format!("no trusted spoke has the id or name `{which}`")),
            _ => {
                return Err(format!(
                    "several spokes are named `{which}`; remove one by its id"
                ));
            }
        };
        self.store
            .remove_spoke(&spoke.id)
            .map_err(|error| error.to_string())?;
        self.state().trusted.remove(&spoke.id);

        Ok(spoke)
    }

    /// Carries out the owner's answer to a request to trust a spoke
    pub fn attach_trust(self: &Arc<Self>, waiting: Waiting, action: AdminAction) {
        let AdminAction::TrustSpoke {
            id,
            name,
            version,
            address,
        } = action
        else {
            return;
        };
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let request = waiting.id().to_owned();
            let verdict = waiting.decision().await;
            let Some(hub) = weak.upgrade() else {
                return;
            };
            match verdict {
                Verdict::Approved { .. } => {
                    let spoke = StoredSpoke {
                        id: id.clone(),
                        name,
                        version: Some(version),
                        trusted_ms: now_ms(),
                        approval_id: Some(request.clone()),
                        last_seen_ms: Some(now_ms()),
                        address: Some(address),
                    };
                    match hub.store.trust_spoke(&spoke) {
                        Ok(()) => tracing::info!(spoke = %spoke.name, "spoke trusted"),
                        Err(error) => tracing::warn!(%error, "could not record a trusted spoke"),
                    }
                    let mut state = hub.state();
                    state.trust_requests.remove(&id);
                    state.trusted.insert(id, spoke);
                }
                Verdict::Denied { reason } => {
                    if let Some(open) = hub.state().trust_requests.get_mut(&id) {
                        open.denied = Some(reason);
                    }
                }
            }
            if let Err(error) = hub.store.complete_action(&request) {
                tracing::warn!(%error, "could not record a finished trust request");
            }
        });
    }

    /// Keeps a spoke's request until it is decided, and a while after, so
    /// the spoke can follow it and run the held call
    fn hold(self: &Arc<Self>, spoke: &str, waiting: Waiting, call: Option<PreparedCall>) {
        let id = waiting.id().to_owned();
        let (sender, receiver) = watch::channel(None);
        self.state().held.insert(
            id.clone(),
            Held {
                spoke: spoke.to_owned(),
                verdict: receiver,
                call,
            },
        );
        let weak: Weak<Self> = Arc::downgrade(self);
        tokio::spawn(async move {
            let verdict = waiting.decision().await;
            let _ = sender.send(Some(verdict));
            tokio::time::sleep(HELD_AFTER_DECISION).await;
            if let Some(hub) = weak.upgrade() {
                hub.state().held.remove(&id);
            }
        });
    }

    fn register(self: &Arc<Self>, peer: SocketAddr, register: Register) -> Registration {
        let id = register.id;
        let name = register.name;
        let version = one_line(&register.version, MAX_NAME_CHARS);
        let address = peer.ip().to_canonical().to_string();

        if self.trusted(&id, peer.ip()).is_some() {
            if let Err(error) = self.store.spoke_seen(&id, &version) {
                tracing::warn!(%error, "could not record a spoke's registration");
            }
            if let Some(spoke) = self.state().trusted.get_mut(&id) {
                spoke.version = Some(version);
                spoke.last_seen_ms = Some(now_ms());
            }

            return Registration::Trusted {
                public_base: self.config.public_base(),
            };
        }

        // every check and the new request happen under one lock, so two
        // registrations at once cannot both pass the one-per-address limit
        let mut state = self.state();
        if let Some(open) = state.trust_requests.get(&id) {
            // the link and code belong to the address that asked; a copied
            // id elsewhere waits with neither
            if open.address != address {
                return Registration::Pending {
                    url: String::new(),
                    code: String::new(),
                };
            }

            return match &open.denied {
                Some(reason) => {
                    let reason = reason.clone();
                    state.trust_requests.remove(&id);

                    Registration::Denied { reason }
                }
                None => Registration::Pending {
                    url: open.url.clone(),
                    code: open.code.clone(),
                },
            };
        }
        // one open question per tailnet node, so a peer making up ids
        // cannot pile prompts on the owner. The other id's link and code
        // stay with it: this one waits its turn with neither
        let busy = state
            .trust_requests
            .values()
            .any(|open| open.address == address && open.denied.is_none());
        if busy {
            return Registration::Pending {
                url: String::new(),
                code: String::new(),
            };
        }

        let code = confirmation_code();
        let mut details = Map::new();
        details.insert("spoke".to_owned(), Value::String(name.clone()));
        details.insert("address".to_owned(), Value::String(address.clone()));
        details.insert("version".to_owned(), Value::String(version.clone()));
        // a trusted id at another address is asked about again, naming
        // where the owner trusted it before
        let moved = state.trusted.get(&id).map(|known| {
            format!(
                " It was trusted as “{}” at {}",
                known.name,
                known.address.as_deref().unwrap_or("another address")
            )
        });
        let action = AdminAction::TrustSpoke {
            id: id.clone(),
            name: name.clone(),
            version,
            address: address.clone(),
        };
        let waiting = self.approvals().request_admin(AdminRequest {
            action: action.clone(),
            title: format!(
                "Trust “{name}” at {address} as a spoke? It could call every server of this \
                 Mac and ask for its 1Password values.{moved}",
                moved = moved.unwrap_or_default(),
            ),
            details,
            code: code.clone(),
        });
        let url = waiting.url().to_owned();
        tracing::info!(spoke = %name, %code, "a spoke asked to be trusted");
        state.trust_requests.insert(
            id,
            TrustRequest {
                url: url.clone(),
                code: code.clone(),
                address,
                denied: None,
            },
        );
        drop(state);
        self.attach_trust(waiting, action);

        Registration::Pending { url, code }
    }

    /// The caller of a call a spoke passed on: its session is scoped to the
    /// spoke, and the spoke is named as its machine
    fn caller(spoke: &StoredSpoke, mut caller: Caller) -> Caller {
        caller.session = caller.session.map(|session| {
            hex(&Sha256::digest(
                format!("{}\0{session}", spoke.id).as_bytes(),
            ))
        });
        caller.machine = Some(Machine {
            id: spoke.id.clone(),
            name: spoke.name.clone(),
        });

        caller
    }

    /// A call of `spoke`'s execution, under an id of the spoke's own, so
    /// it never joins another caller's batch of requests
    fn context(
        &self,
        spoke: &StoredSpoke,
        caller: Caller,
        execution_id: &str,
        script: &str,
    ) -> CallContext {
        CallContext {
            execution_id: Arc::from(spoke_execution(spoke, execution_id)),
            catalog: self.gateway.catalog(),
            budget: Budget::new(self.config.limits.execution_timeout()),
            caller,
            script: Arc::from(script),
        }
    }

    /// Refuses arguments that set what the hub's config fixes for `server`:
    /// they are hidden from stubs, so only a spoke sending its own JSON can
    /// set them, and the upstream would take its value over the hub's
    fn fixed_override(
        &self,
        function: &str,
        server: &str,
        arguments: &Map<String, Value>,
    ) -> Option<HubError> {
        let fixed = self
            .config
            .servers
            .get(server)?
            .arguments
            .keys()
            .find(|name| arguments.contains_key(*name))?;

        Some(HubError {
            kind: HubErrorKind::Denied,
            message: format!("`{function}` cannot set `{fixed}`, which the hub fixes"),
        })
    }

    /// The function of a tool the hub shares with spokes; `None` for one it
    /// keeps to itself, like a `deny` tool or the `secrets` builtin
    fn exported(&self, context: &CallContext, server: &str, tool: &str) -> Option<String> {
        let shared = self.gateway.hub_catalog().servers.iter().any(|shared| {
            shared.name == server
                && shared
                    .tools
                    .iter()
                    .any(|exported| exported.tool.name == tool)
        });

        shared
            .then(|| context.catalog.find(server, tool))
            .flatten()
            .map(|entry| entry.function.clone())
    }

    async fn gate(self: &Arc<Self>, spoke: &StoredSpoke, call: GateCall) -> GateAnswer {
        let caller = Self::caller(spoke, call.caller);
        let sensitivity = Sensitivity::of(call.sensitive);

        if !call.hub_tool {
            if !plain_name(&call.server) || !plain_name(&call.tool) {
                return GateAnswer::Refused(unknown(&call.server, &call.tool));
            }
            // the spoke's own server, apart from a hub server of the same
            // name: in the prompt, in grants and in the stored request
            let server = format!("{}:{}", spoke.name, call.server);
            let script: Arc<str> = Arc::from(call.script.as_str());
            let execution_id = spoke_execution(spoke, &call.execution_id);
            let gate = self.approvals().gate_here(GateRequest {
                caller: &caller,
                execution_id: &execution_id,
                server: &server,
                tool: &call.tool,
                arguments: &call.arguments,
                script: &script,
                grant_mode: call.grant_mode,
                sensitivity,
                summary: call.summary.as_deref(),
            });

            return GateAnswer::Gate(match gate {
                Gate::Open { approval_id } => RemoteGate::Open { approval_id },
                Gate::Closed { reason } => RemoteGate::Closed { reason },
                Gate::Wait(waiting) => self.wait_answer(spoke, waiting, None),
                // the hub decides here and asks no one further
                Gate::Unreachable(unreachable) => RemoteGate::Closed {
                    reason: unreachable.reason,
                },
            });
        }

        let context = self.context(spoke, caller, &call.execution_id, &call.script);
        let Some(function) = self.exported(&context, &call.server, &call.tool) else {
            return GateAnswer::Refused(unknown(&call.server, &call.tool));
        };
        if let Some(error) = self.fixed_override(&function, &call.server, &call.arguments) {
            return GateAnswer::Refused(error);
        }
        let digest = arguments_digest(&call.arguments);
        let plan = self
            .gateway
            .prepare_with(&context, &function, call.arguments, sensitivity, None)
            .await;

        match plan {
            Ok(Plan::Run { approval_id, .. }) => GateAnswer::Gate(RemoteGate::Open {
                approval_id: approval_id.unwrap_or_default(),
            }),
            Ok(Plan::Gated {
                call: prepared,
                waiting,
            }) => {
                // the stored row stands in for the held call after a
                // restart, for these arguments only; a sensitive request
                // keeps no trace of them and is asked again instead
                if !(call.sensitive || prepared.sensitive)
                    && let Err(error) = self.store.bind_hub_call(waiting.id(), &digest)
                {
                    tracing::warn!(%error, "could not record a hub call's arguments");
                }

                GateAnswer::Gate(self.wait_answer(spoke, waiting, Some(prepared)))
            }
            Err(error) => GateAnswer::Refused(HubError::from(&error)),
        }
    }

    fn wait_answer(
        self: &Arc<Self>,
        spoke: &StoredSpoke,
        waiting: Waiting,
        call: Option<PreparedCall>,
    ) -> RemoteGate {
        let id = waiting.id().to_owned();
        let expires_ms = self
            .approvals()
            .info(&id)
            .map_or_else(now_ms, |info| info.expires_ms);
        self.hold(&spoke.id, waiting, call);

        RemoteGate::Wait { id, expires_ms }
    }

    async fn wait(&self, spoke: &StoredSpoke, id: &str) -> WaitAnswer {
        let held = {
            let state = self.state();
            state
                .held
                .get(id)
                .filter(|held| held.spoke == spoke.id)
                .map(|held| held.verdict.clone())
        };
        if let Some(mut verdict) = held {
            let current = verdict.borrow().clone();
            if current.is_some() {
                return WaitAnswer { verdict: current };
            }
            let _ = tokio::time::timeout(WAIT_POLL, verdict.changed()).await;

            return WaitAnswer {
                verdict: verdict.borrow().clone(),
            };
        }

        // not held: decided long ago, or asked before a restart that lost it
        let mine = self
            .approvals()
            .stored(id)
            .is_some_and(|stored| stored.spoke.as_deref() == Some(spoke.id.as_str()));
        let verdict = match mine.then(|| self.approvals().verdict_of(id)).flatten() {
            Some(verdict) => verdict,
            None => Some(Verdict::Denied {
                reason: "the hub has no such request".to_owned(),
            }),
        };

        WaitAnswer { verdict }
    }

    async fn call(self: &Arc<Self>, spoke: &StoredSpoke, call: ForwardedCall) -> CallAnswer {
        let caller = Self::caller(spoke, call.caller);
        let context = self.context(spoke, caller, &call.execution_id, &call.script);
        let Some(function) = self.exported(&context, &call.server, &call.tool) else {
            return CallAnswer::Error(unknown(&call.server, &call.tool));
        };
        if let Some(error) = self.fixed_override(&function, &call.server, &call.arguments) {
            return CallAnswer::Error(error);
        }
        let spoke_sensitive = call.sensitive;
        let refused = |message: &str| {
            CallAnswer::Error(HubError {
                kind: HubErrorKind::Denied,
                message: format!("`{function}` {message}"),
            })
        };

        let (prepared, approval_id) = match call.approval {
            Some(id) => {
                let approved =
                    self.approved_call(spoke, &id, &call.server, &call.tool, &call.arguments);
                if let Err(message) = approved {
                    return refused(message);
                }
                // checked first, so a call the approval does not cover
                // leaves it for the one it does
                match self.store.consume_approval(&id) {
                    Ok(true) => {}
                    Ok(false) => return refused("was approved for one call, which has run"),
                    Err(error) => {
                        tracing::warn!(%error, "could not record a hub call's approval as used");

                        return refused("could not be checked; run it again");
                    }
                }
                match approved {
                    Ok(Some(held)) => (held, Some(id)),
                    Ok(None) => {
                        // the held call went with a restart; the stored
                        // approval stands in for asking again
                        let plan = self
                            .gateway
                            .prepare_with(
                                &context,
                                &function,
                                call.arguments,
                                Sensitivity::PLAIN,
                                Some(id),
                            )
                            .await;
                        match plan {
                            Ok(Plan::Run { call, approval_id }) => (call, approval_id),
                            Ok(Plan::Gated { .. }) => return refused("needs approval"),
                            Err(error) => return CallAnswer::Error(HubError::from(&error)),
                        }
                    }
                    Err(message) => return refused(message),
                }
            }
            None => {
                let plan = self
                    .gateway
                    .prepare_with(
                        &context,
                        &function,
                        call.arguments,
                        Sensitivity::PLAIN,
                        None,
                    )
                    .await;
                match plan {
                    Ok(Plan::Run { call, approval_id }) => (call, approval_id),
                    // a grant that covered the call when the spoke asked
                    // ended since; dropping the request withdraws it
                    Ok(Plan::Gated { .. }) => {
                        return refused("needs approval again; the grant that covered it ended");
                    }
                    Err(error) => return CallAnswer::Error(HubError::from(&error)),
                }
            }
        };

        // a spoke on an older catalog would keep a now sensitive result on
        // its disk; it refetches on this answer's catalog version
        if prepared.sensitive && !spoke_sensitive {
            return refused(
                "is sensitive on the hub now; run it again once this machine has the hub's new \
                 catalog",
            );
        }

        match self
            .gateway
            .invoke_value(&context, prepared, approval_id)
            .await
        {
            Ok(value) => CallAnswer::Value(value),
            Err(error) => CallAnswer::Error(HubError::from(&error)),
        }
    }

    /// The held call approved request `id` lets the spoke run: `Ok(None)`
    /// when it is approved for exactly this call but the call is no longer
    /// held, so `arguments` may stand in for it
    fn approved_call(
        &self,
        spoke: &StoredSpoke,
        id: &str,
        server: &str,
        tool: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Option<PreparedCall>, &'static str> {
        let stored = self
            .approvals()
            .stored(id)
            .ok_or("was not approved for this call")?;
        // an approval runs its call before the request's deadline, held or
        // not, so a spoke cannot save it for later
        if !stored.expires_ms.is_some_and(|expires| expires > now_ms()) {
            return Err("was approved too long ago; run it again");
        }

        {
            let mut state = self.state();
            // a request held again after a restart has no call with it, and
            // is checked against its stored row below
            if let Some(held) = state
                .held
                .get_mut(id)
                .filter(|held| held.spoke == spoke.id && held.call.is_some())
            {
                let approved = matches!(*held.verdict.borrow(), Some(Verdict::Approved { .. }));
                let matches = held
                    .call
                    .as_ref()
                    .is_some_and(|call| call.server == server && call.tool == tool);
                if !approved || !matches {
                    return Err("was not approved for this call");
                }

                return Ok(held.call.take());
            }
        }

        // only a hub tool's request carries a digest, so a request for the
        // spoke's own tool never runs a hub tool
        let fits = stored.spoke.as_deref() == Some(spoke.id.as_str())
            && stored.server == server
            && stored.tool == tool
            && stored.decision.as_deref() == Some("approved")
            && stored.hub_call.as_deref() == Some(arguments_digest(arguments).as_str());
        if !fits {
            return Err("was not approved for this call");
        }

        Ok(None)
    }

    async fn read_config(&self, spoke: &StoredSpoke, read: ConfigRead) -> ConfigAnswer {
        let references: Vec<String> = read
            .references
            .iter()
            .map(|reference| reference.trim().to_owned())
            .collect();
        let well_formed = !references.is_empty()
            && references.len() <= MAX_CONFIG_REFERENCES
            && references.iter().all(|reference| {
                reference.starts_with("op://")
                    && reference.chars().count() <= MAX_REFERENCE_CHARS
                    && one_line(reference, usize::MAX) == *reference
            });
        if !well_formed {
            return ConfigAnswer::Error(format!(
                "a config read names 1 to {MAX_CONFIG_REFERENCES} op:// references"
            ));
        }
        if !plain_name(&read.server) {
            return ConfigAnswer::Error(
                "a server name is letters, digits, `-`, `_` and `.`".to_owned(),
            );
        }
        let server = read.server;
        let consumer =
            Consumer::of_spoke(&spoke.id, format!("{}/{server}", spoke.name), &read.digest);
        let onepassword = &self.gateway.secrets().onepassword;

        if !onepassword.approved_for(&consumer, &references) {
            let mut details = Map::new();
            details.insert("spoke".to_owned(), Value::String(spoke.name.clone()));
            details.insert("server".to_owned(), Value::String(server.clone()));
            details.insert(
                "references".to_owned(),
                Value::Array(references.iter().cloned().map(Value::String).collect()),
            );
            let waiting = self.approvals().request_owner(OwnerRequest {
                title: format!(
                    "Give {} to the server “{server}” on {}, from now on",
                    references.join(", "),
                    spoke.name
                ),
                details,
                tool: SPOKE_SECRETS,
                machine: Some(Machine {
                    id: spoke.id.clone(),
                    name: spoke.name.clone(),
                }),
            });
            match waiting.decision().await {
                Verdict::Approved { .. } => onepassword.approve_for(&consumer, &references),
                Verdict::Denied { reason } => return ConfigAnswer::Error(reason),
            }
        }

        let mut values = Vec::with_capacity(references.len());
        for reference in &references {
            match onepassword.read_reference(reference).await {
                Ok(value) => values.push(value),
                Err(error) => return ConfigAnswer::Error(error.to_string()),
            }
        }

        ConfigAnswer::Values(values)
    }

    /// The spoke trusted as `id`, when `peer` is the address the owner
    /// trusted it at; the id alone, which the spoke sends with every
    /// request, is not enough
    fn trusted(&self, id: &str, peer: IpAddr) -> Option<StoredSpoke> {
        let peer = peer.to_canonical().to_string();

        self.state()
            .trusted
            .get(id)
            .filter(|spoke| spoke.address.as_deref() == Some(peer.as_str()))
            .cloned()
    }
}

/// The hub's id for an execution of `spoke`
fn spoke_execution(spoke: &StoredSpoke, execution_id: &str) -> String {
    format!("{}/{execution_id}", spoke.id)
}

/// Whether `name` is a host, server or tool name and nothing more, fit to
/// show in the owner's prompts as it is
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_CHARS
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
}

/// Digest of a call's arguments; `Map` keeps its keys sorted, so equal
/// arguments serialize alike
fn arguments_digest(arguments: &Map<String, Value>) -> String {
    let encoded = serde_json::to_vec(arguments).unwrap_or_default();

    hex(&Sha256::digest(&encoded))
}

fn unknown(server: &str, tool: &str) -> HubError {
    HubError {
        kind: HubErrorKind::Unknown,
        message: format!("the hub has no tool `{tool}` on a server `{server}` it shares"),
    }
}

/// A spoke program's reason as every prompt quotes it, naming the spoke:
/// a search prompt on a Mac or companion names only the place it searches,
/// and the reason is all that reaches it
fn spoke_reason(spoke: &StoredSpoke, reason: Option<String>) -> String {
    match reason {
        Some(reason) => format!("{}: {reason}", spoke.name),
        None => format!("a program on {}", spoke.name),
    }
}

/// Where a spoke's program values go, as the hub's prompts show it
fn destination_on(spoke: &StoredSpoke, destination: Option<String>) -> String {
    match destination {
        Some(destination) => format!("{}:{destination}", spoke.name),
        None => format!("the spoke {}", spoke.name),
    }
}

/// The `/hub/v1` routes; `stopping` ends held catalog requests when the
/// listener stops
pub fn router(hub: Arc<Hub>, stopping: CancellationToken) -> Router {
    Router::new()
        .route(&format!("{API}/register"), post(register))
        .route(
            &format!("{API}/catalog"),
            get(catalog).layer(Extension(stopping)),
        )
        .route(&format!("{API}/gate"), post(gate))
        .route(&format!("{API}/call"), post(call))
        .route(&format!("{API}/approvals/wait"), post(wait))
        .route(&format!("{API}/op/read"), post(op_read))
        .route(&format!("{API}/op/find"), post(op_find))
        .route(&format!("{API}/op/config"), post(op_config))
        // only the routes above: a `layer` would also wrap the fallback,
        // which the merge makes the main listener's
        .route_layer(from_fn_with_state(Arc::clone(&hub), guard))
        .with_state(hub)
}

fn refuse(status: StatusCode, error: &str) -> Response {
    (
        status,
        Json(Refusal {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

/// Lets in only tailnet peers and processes on this machine, and past
/// `register` only trusted spokes; every answer carries the catalog version
async fn guard(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    // the main listener also answers on the LAN, and `tailscale serve`
    // proxies the tailnet in from loopback with its headers
    let allowed = is_tailnet_address(peer.ip()) || is_direct_local(Some(peer), request.headers());
    if !allowed {
        return refuse(
            StatusCode::FORBIDDEN,
            "the hub answers only Tailscale peers; reach it at its tailnet name or address",
        );
    }

    if request.uri().path() != format!("{API}/register") {
        let spoke = request
            .headers()
            .get(SPOKE_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|id| hub.trusted(id, peer.ip()));
        let Some(spoke) = spoke else {
            return refuse(
                StatusCode::FORBIDDEN,
                "this spoke is not trusted; it asks the owner when it registers",
            );
        };
        request.extensions_mut().insert(spoke);
    }

    let mut response = next.run(request).await;
    if let Ok(version) = HeaderValue::from_str(&hub.gateway.hub_catalog().version) {
        response.headers_mut().insert(CATALOG_HEADER, version);
    }

    response
}

async fn register(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(register): Json<Register>,
) -> Response {
    let id_ok = !register.id.is_empty()
        && register.id.len() <= MAX_NAME_CHARS
        && register
            .id
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-');
    // the name is in the owner's prompts, so it may not dress up as
    // anything but a host name
    if !id_ok || !plain_name(&register.name) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "a spoke registers with its id and a host name of letters, digits, `-`, `_` and `.`",
        );
    }

    Json(hub.register(peer, register)).into_response()
}

/// Query of `GET /hub/v1/catalog`
#[derive(serde::Deserialize)]
struct CatalogQuery {
    /// The version the spoke holds; the answer waits for another one
    after: Option<String>,
}

/// The catalog, or with `after`, the catalog once it changes, so a spoke
/// learns of a server signing in or reconnecting at once; `null` when it
/// stays the same for [`CATALOG_WAIT`], and the spoke asks again
async fn catalog(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(spoke): Extension<StoredSpoke>,
    Extension(stopping): Extension<CancellationToken>,
    Query(query): Query<CatalogQuery>,
) -> Response {
    let Some(after) = query.after else {
        return Json(&*hub.gateway.hub_catalog()).into_response();
    };

    let changed = tokio::select! {
        changed = hub.gateway.hub_catalog_after(&after, CATALOG_WAIT) => changed,
        // a stop waits for answers in flight, so a held one would hold it up
        // for the rest of its wait
        () = stopping.cancelled() => None,
    };
    // the guard checked trust before the wait; a spoke removed during it
    // gets nothing more
    if hub.trusted(&spoke.id, peer.ip()).is_none() {
        return refuse(
            StatusCode::FORBIDDEN,
            "this spoke is not trusted; it asks the owner when it registers",
        );
    }

    Json(changed.as_deref()).into_response()
}

async fn gate(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(call): Json<GateCall>,
) -> Response {
    Json(hub.gate(&spoke, call).await).into_response()
}

async fn call(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(call): Json<ForwardedCall>,
) -> Response {
    Json(hub.call(&spoke, call).await).into_response()
}

async fn wait(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(wait): Json<WaitFor>,
) -> Response {
    Json(hub.wait(&spoke, &wait.id).await).into_response()
}

async fn op_read(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(read): Json<ProgramReadCall>,
) -> Response {
    let request = read.request;
    let answer = hub
        .gateway
        .secrets()
        .onepassword
        .read_for_program(&ProgramAsk {
            targets: request.targets,
            reason: Some(spoke_reason(&spoke, request.reason)),
            destination: Some(destination_on(&spoke, request.destination)),
            keep: request.keep_secs.map(Duration::from_secs),
            phones_only: read.phones_only,
            keep_scope: Some(spoke.id.clone()),
        })
        .await;

    Json(op_read_response(answer)).into_response()
}

async fn op_find(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(find): Json<OpFindRequest>,
) -> Response {
    let reason = Some(spoke_reason(&spoke, find.reason));
    let answer = hub
        .gateway
        .secrets()
        .onepassword
        .find_for_program(&FindAsk {
            query: find.query,
            reason,
            // spokes that share a name never share a batch or kept answers
            scope: Some(spoke.id.clone()),
        })
        .await;

    Json(op_find_response(answer)).into_response()
}

async fn op_config(
    State(hub): State<Arc<Hub>>,
    Extension(spoke): Extension<StoredSpoke>,
    Json(read): Json<ConfigRead>,
) -> Response {
    Json(hub.read_config(&spoke, read).await).into_response()
}
