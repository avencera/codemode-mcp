//! The spoke's side: its identity, its registration with the hub, and every
//! request it sends there
//!
//! The spoke's id is a random UUID kept in its state directory, so the hub's
//! trust outlives restarts and reinstalls that keep the state. It is sent
//! only to the hub, which answers it only from the tailnet address the owner
//! trusted it at; Tailscale vouches for that address, so a copied id is not
//! enough from another machine

use std::{
    io::Write,
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex, PoisonError, Weak},
    time::Duration,
};

use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::{Notify, watch};

use super::{
    API, CATALOG_HEADER, CallAnswer, ConfigAnswer, ConfigRead, ForwardedCall, GateAnswer, GateCall,
    HubCatalog, ProgramReadCall, Refusal, Register, Registration, SPOKE_HEADER, WaitAnswer,
    WaitFor,
};
use crate::{
    admin::{OpFindRequest, OpFindResponse, OpReadRequest, OpReadResponse},
    approvals::{GateRequest, Remote, RemoteGate, Unreachable, Verdict},
    companion::{self, FindAsk, ProgramAsk, ProgramFound, ProgramRead, ProgramReadError},
    config::HubConfig,
    gateway::Gateway,
    notify::BoxFuture,
    secrets::approved::Consumer,
    usage::Machine,
};

/// File in the state directory holding the spoke's id
pub const ID_FILE: &str = "spoke.id";
/// How long a request that needs no person may take
const QUICK: Duration = Duration::from_secs(30);
/// How long a request that may wait for the owner may take: a long poll,
/// or a read the owner approves on a device
const PATIENT: Duration = Duration::from_secs(15 * 60);
/// How often a spoke the owner has not answered yet asks again
const PENDING_POLL: Duration = Duration::from_secs(5);
/// How often a trusted spoke checks the hub's catalog when nothing changed
const CATALOG_POLL: Duration = Duration::from_secs(60);
/// Longest pause between attempts to reach a hub that does not answer
const UNREACHABLE_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long a read of a server's `op://` references waits for the owner
/// to trust this spoke before it fails; a failed read waits out the
/// upstream's long retry for secrets
const TRUST_WAIT: Duration = Duration::from_secs(10 * 60);

/// Resolves the hub's name to its IPv4 addresses when it has any, so every
/// request leaves from this spoke's IPv4 tailnet address: the hub answers a
/// spoke only from the address it was trusted at, and MagicDNS names have
/// both kinds
struct PreferIpv4;

impl reqwest::dns::Resolve for PreferIpv4 {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let ipv4: Vec<SocketAddr> = found.iter().copied().filter(SocketAddr::is_ipv4).collect();
            let chosen = if ipv4.is_empty() { found } else { ipv4 };

            Ok(Box::new(chosen.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Why a request to the hub failed
#[derive(Debug, Clone, thiserror::Error)]
pub enum HubClientError {
    /// The hub could not be reached or sent something unreadable
    #[error("could not reach the hub at {base}: {reason}")]
    Unreachable {
        /// The hub's address
        base: String,
        /// What went wrong
        reason: String,
    },
    /// The hub did not answer in time
    #[error("the hub did not answer within {0:?}")]
    TimedOut(Duration),
    /// The hub has not trusted this spoke, or no longer does
    #[error("the hub has not trusted this machine yet; the owner is asked when it registers")]
    Untrusted,
    /// The hub refused the request
    #[error("the hub refused: {0}")]
    Refused(String),
}

/// A spoke's link to its hub
pub struct HubClient {
    http: reqwest::Client,
    base: String,
    machine: Machine,
    filter: HubConfig,
    /// The hub's approval pages, once it said where they are
    public_base: Mutex<Option<String>>,
    /// The catalog version the hub last sent
    catalog_version: Mutex<Option<String>>,
    /// Woken when an answer carries a catalog version other than the one
    /// this spoke holds
    catalog_changed: Arc<Notify>,
    /// Whether the hub trusts this spoke, as of its last answer
    trusted: watch::Sender<bool>,
}

impl HubClient {
    /// The link to the hub `config` names, with this spoke's id from
    /// `state_dir`, created on first use
    pub fn new(hub: &HubConfig, state_dir: &Path) -> Result<Arc<Self>, String> {
        let id = load_or_create_id(state_dir)?;
        // the hub answers only on the tailnet, never through a proxy
        let http = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(PreferIpv4)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| error.to_string())?;

        Ok(Arc::new(Self {
            http,
            base: hub.base_url(),
            machine: Machine {
                id,
                name: companion::short_hostname(),
            },
            filter: hub.clone(),
            public_base: Mutex::new(None),
            catalog_version: Mutex::new(None),
            catalog_changed: Arc::new(Notify::new()),
            trusted: watch::Sender::new(false),
        }))
    }

    /// This spoke, as the hub knows it
    pub fn machine(&self) -> &Machine {
        &self.machine
    }

    /// The hub's address
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Whether the hub has trusted this spoke, as of the last answer
    pub fn is_trusted(&self) -> bool {
        *self.trusted.borrow()
    }

    /// Whether the hub's server `name` reaches this spoke
    pub fn includes(&self, name: &str) -> bool {
        self.filter.includes(name)
    }

    async fn send<R: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        timeout: Duration,
    ) -> Result<R, HubClientError> {
        // a timeout keeps its kind, so a script's timeout handling sees it
        let unreachable = |error: reqwest::Error| {
            if error.is_timeout() {
                HubClientError::TimedOut(timeout)
            } else {
                HubClientError::Unreachable {
                    base: self.base.clone(),
                    reason: error.to_string(),
                }
            }
        };
        let response = request
            .header(SPOKE_HEADER, &self.machine.id)
            .timeout(timeout)
            .send()
            .await
            .map_err(unreachable)?;
        self.saw_catalog(
            response
                .headers()
                .get(CATALOG_HEADER)
                .and_then(|value| value.to_str().ok()),
        );

        let status = response.status();
        if status.is_success() {
            return response.json().await.map_err(unreachable);
        }
        let reason = response
            .json::<Refusal>()
            .await
            .map_or_else(|_| status.to_string(), |refusal| refusal.error);
        if status == StatusCode::FORBIDDEN && reason.contains("not trusted") {
            self.trusted.send_replace(false);

            return Err(HubClientError::Untrusted);
        }

        Err(HubClientError::Refused(reason))
    }

    async fn post<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<R, HubClientError> {
        let request = self
            .http
            .post(format!("{}{API}{path}", self.base))
            .json(body);

        self.send(request, timeout).await
    }

    fn saw_catalog(&self, version: Option<&str>) {
        let Some(version) = version else {
            return;
        };
        let changed = self
            .catalog_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            != Some(version);
        if changed {
            self.catalog_changed.notify_one();
        }
    }

    /// Registers with the hub, which asks the owner to trust a new spoke
    pub async fn register(&self) -> Result<Registration, HubClientError> {
        let registration: Registration = self
            .post(
                "/register",
                &Register {
                    id: self.machine.id.clone(),
                    name: self.machine.name.clone(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                QUICK,
            )
            .await?;
        if let Registration::Trusted { public_base } = &registration {
            self.trusted.send_replace(true);
            *self
                .public_base
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(public_base.clone());
        }

        Ok(registration)
    }

    /// The hub's servers this spoke may call, as the hub lists them
    pub async fn catalog(&self) -> Result<HubCatalog, HubClientError> {
        let request = self.http.get(format!("{}{API}/catalog", self.base));
        let catalog: HubCatalog = self.send(request, QUICK).await?;
        *self
            .catalog_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(catalog.version.clone());

        Ok(catalog)
    }

    /// Asks the hub whether a call may run now
    pub async fn gate(&self, call: &GateCall) -> Result<GateAnswer, HubClientError> {
        self.post("/gate", call, QUICK).await
    }

    /// Runs a call of the hub's tool there; `tool_timeout` is the longer of
    /// the spoke's limit and the one the hub lists for the server
    ///
    /// The hub may first queue the call behind the server's
    /// `max_concurrent` for up to that timeout, so the wait covers that too
    pub async fn call(
        &self,
        call: &ForwardedCall,
        tool_timeout: Duration,
    ) -> Result<CallAnswer, HubClientError> {
        self.post("/call", call, tool_timeout.saturating_mul(2) + QUICK)
            .await
    }

    /// The hub's verdict on request `id`, after a long poll; `None` while it
    /// is pending
    pub async fn wait(&self, id: &str) -> Result<Option<Verdict>, HubClientError> {
        let answer: WaitAnswer = self
            .post(
                "/approvals/wait",
                &WaitFor { id: id.to_owned() },
                QUICK + QUICK,
            )
            .await?;

        Ok(answer.verdict)
    }

    /// A program's read, approved and read on the hub; the values come back
    /// over the tailnet
    pub async fn read_for_program(
        &self,
        ask: &ProgramAsk,
    ) -> Result<ProgramRead, ProgramReadError> {
        let call = ProgramReadCall {
            request: OpReadRequest {
                targets: ask.targets.clone(),
                reason: ask.reason.clone(),
                destination: ask.destination.clone(),
                keep_secs: ask.keep.map(|keep| keep.as_secs()),
            },
            phones_only: ask.phones_only,
        };
        let answer: OpReadResponse = self
            .post("/op/read", &call, PATIENT)
            .await
            .map_err(|error| ProgramReadError::Failed(error.to_string()))?;

        answer.into_program_read()
    }

    /// A program's find, approved and run on the hub
    pub async fn find_for_program(&self, ask: &FindAsk) -> Result<ProgramFound, ProgramReadError> {
        let request = OpFindRequest {
            query: ask.query.clone(),
            reason: ask.reason.clone(),
        };
        let answer: OpFindResponse = self
            .post("/op/find", &request, PATIENT)
            .await
            .map_err(|error| ProgramReadError::Failed(error.to_string()))?;

        answer.into_program_found()
    }

    /// The values of `references` for the server `consumer` of this spoke,
    /// which the hub asks the owner to approve once and remembers
    pub async fn config_values(
        &self,
        consumer: &Consumer,
        references: &[String],
    ) -> Result<Vec<String>, HubClientError> {
        // a server starts with the gateway, before a new spoke is trusted;
        // its read waits for the owner rather than failing into the long
        // retry
        let mut trusted = self.trusted.subscribe();
        let _ = tokio::time::timeout(TRUST_WAIT, trusted.wait_for(|trusted| *trusted)).await;
        let read = ConfigRead {
            server: consumer.name.clone(),
            digest: consumer.digest().to_owned(),
            references: references.to_vec(),
        };
        let answer: ConfigAnswer = self.post("/op/config", &read, PATIENT).await?;

        match answer {
            ConfigAnswer::Values(values) if values.len() == references.len() => Ok(values),
            ConfigAnswer::Values(_) => Err(HubClientError::Refused(
                "the hub sent the wrong number of values".to_owned(),
            )),
            ConfigAnswer::Error(reason) => Err(HubClientError::Refused(reason)),
        }
    }

    /// Keeps this spoke registered and its view of the hub's catalog
    /// current for as long as `gateway` lives
    ///
    /// Until the owner trusts it, the spoke asks again every few seconds; a
    /// refusal stops it until the next start, so the owner is not asked
    /// again and again
    pub async fn run(self: Arc<Self>, gateway: Weak<Gateway>) {
        let mut pause = Duration::from_secs(1);
        let mut announced = false;
        loop {
            if gateway.strong_count() == 0 {
                return;
            }
            if !self.is_trusted() {
                match self.register().await {
                    Ok(Registration::Trusted { .. }) => {
                        tracing::info!(hub = %self.base, "the hub trusts this spoke");
                        pause = Duration::from_secs(1);
                    }
                    Ok(Registration::Pending { url, code }) => {
                        // no link: another request from this machine is open,
                        // and this spoke's own comes once that one is answered
                        if url.is_empty() {
                            tracing::debug!(
                                hub = %self.base,
                                "another trust request from this machine is open on the hub"
                            );
                        } else if !announced {
                            tracing::warn!(
                                hub = %self.base,
                                %url,
                                %code,
                                "waiting for the owner to trust this spoke on the hub"
                            );
                            announced = true;
                        }
                        tokio::time::sleep(PENDING_POLL).await;
                        continue;
                    }
                    Ok(Registration::Denied { reason }) => {
                        tracing::error!(
                            hub = %self.base,
                            %reason,
                            "the hub refused to trust this spoke; restart the service to ask again"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not register with the hub; trying again");
                        tokio::time::sleep(pause).await;
                        pause = (pause * 2).min(UNREACHABLE_BACKOFF_MAX);
                        continue;
                    }
                }
            }

            match self.catalog().await {
                Ok(catalog) => {
                    let Some(gateway) = gateway.upgrade() else {
                        return;
                    };
                    gateway.set_hub_catalog(catalog);
                    pause = Duration::from_secs(1);
                }
                Err(HubClientError::Untrusted) => {
                    tracing::warn!("the hub no longer trusts this spoke");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "could not read the hub's catalog; trying again");
                    tokio::time::sleep(pause).await;
                    pause = (pause * 2).min(UNREACHABLE_BACKOFF_MAX);
                    continue;
                }
            }

            tokio::select! {
                () = self.catalog_changed.notified() => {}
                () = tokio::time::sleep(CATALOG_POLL) => {}
            }
        }
    }
}

impl Remote for HubClient {
    fn gate<'a>(
        &'a self,
        request: &'a GateRequest<'a>,
    ) -> BoxFuture<'a, Result<RemoteGate, Unreachable>> {
        Box::pin(async move {
            let call = GateCall {
                caller: request.caller.clone(),
                execution_id: request.execution_id.to_owned(),
                script: request.script.to_string(),
                server: request.server.to_owned(),
                tool: request.tool.to_owned(),
                arguments: request.arguments.clone(),
                hub_tool: false,
                grant_mode: request.grant_mode,
                sensitive: request.sensitivity.is_sensitive(),
                summary: request.summary.map(str::to_owned),
            };

            match HubClient::gate(self, &call).await {
                Ok(GateAnswer::Gate(gate)) => Ok(gate),
                Ok(GateAnswer::Refused(error)) => Ok(RemoteGate::Closed {
                    reason: error.message,
                }),
                Err(error) => Err(Unreachable {
                    timed_out: matches!(error, HubClientError::TimedOut(_)),
                    reason: error.to_string(),
                }),
            }
        })
    }

    fn decision<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<Option<Verdict>, String>> {
        Box::pin(async move { self.wait(id).await.map_err(|error| error.to_string()) })
    }

    fn approval_url(&self, id: &str) -> String {
        let base = self
            .public_base
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| self.base.clone());

        format!("{}/approve/{id}", base.trim_end_matches('/'))
    }
}

/// The spoke's id from `state_dir`, created on first use; the file is
/// private, since the id is what the hub trusts
fn load_or_create_id(state_dir: &Path) -> Result<String, String> {
    let path = state_dir.join(ID_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => return Ok(text.trim().to_owned()),
        Ok(_) => {
            return Err(format!(
                "{} is empty; remove it to make a new id",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    }

    let id = uuid::Uuid::new_v4().to_string();
    // create_new: two daemons racing on first start must not swap ids
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(id.as_bytes())
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;

    Ok(id)
}
