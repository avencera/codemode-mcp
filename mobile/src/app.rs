//! The app actor: the supervisor of the connection and request actors, and
//! the only writer of [`AppState`]
//!
//! It takes the UI's actions and its children's reports, changes the state,
//! and sends each change to the reconciler as an [`Update`]. Anything slow
//! (pairing, unpairing, Keychain calls) runs in a spawned task whose result
//! comes back as a message

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError, RwLock, mpsc},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use companion_wire::{
    ASK_TIMEOUT,
    mobile::{
        PhoneRead, PhoneRequest, PushEnvironment as WirePushEnvironment, PushToken, RequestId,
    },
    wire::{CompanionResponse, PairCheck},
};
use iroh::SecretKey;
use ractor::{Actor, ActorCell, ActorProcessingErr, ActorRef, SupervisionEvent};
use tokio::sync::oneshot;

use crate::{
    connection::{ConnArgs, ConnMsg, ConnectionActor},
    ffi::{
        AppAction, AppState, ConnectionState, PairingState, PendingRead, Platform, PushEnvironment,
        ReadStatus, Reconciler, Update,
    },
    pairing,
    record::{GatewayRecord, load_key},
    request::{RequestActor, RequestArgs, RequestMsg, Secret},
};

/// How long a read opened from a push may take to arrive once the app is up
/// before it counts as gone; the gateway sends it as soon as the phone dials
const PUSH_WAIT: Duration = Duration::from_secs(20);
/// How long unpairing waits for the gateway before forgetting it anyway
const UNPAIR_TIMEOUT: Duration = Duration::from_secs(5);

/// How a read's stream ended without an answer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// The gateway stopped it: another source answered, or it gave up
    Withdrawn,
    /// The link dropped; the gateway offers the read again on the next one
    Interrupted,
}

/// A read as it arrives, with where its answer goes
pub struct Incoming {
    /// The read
    pub read: PhoneRead,
    /// Its stream's number
    pub seq: u64,
    /// Where the answer goes
    pub responder: oneshot::Sender<CompanionResponse>,
}

/// What the app actor is told
pub enum AppMsg {
    /// The UI asked for something
    Action(AppAction),
    /// The owner entered the value of a read
    Answer {
        /// The read
        id: String,
        /// The value
        value: Secret,
    },
    /// The pairing registered, or failed to
    Registered(Result<GatewayRecord, String>),
    /// The gateway's pairing check finished
    Checked(Result<PairCheck, String>),
    /// The unpairing finished
    Unpaired,
    /// The link changed
    Connection(ConnectionState),
    /// The gateway sent a read
    Incoming(Box<Incoming>),
    /// A read's stream ended without an answer
    StreamEnded {
        /// The read
        id: RequestId,
        /// Its stream's number
        seq: u64,
        /// How
        end: StreamEnd,
    },
    /// A read moved on
    ReadChanged {
        /// The read
        id: String,
        /// Where it stands
        status: ReadStatus,
    },
    /// The wait for a read opened from a push is over
    PushWaitOver(String),
}

/// The state the UI reads and the channel its updates go out on
pub struct Shared {
    state: RwLock<AppState>,
    updates: Mutex<Option<mpsc::Sender<Update>>>,
}

impl Shared {
    /// The state at launch: the paired gateway, if any, and nothing else
    pub fn new(record: Option<&GatewayRecord>) -> Self {
        Self {
            state: RwLock::new(AppState {
                gateway: record.map(GatewayRecord::info),
                connection: ConnectionState::Offline,
                reads: Vec::new(),
                pairing: PairingState::Idle,
            }),
            updates: Mutex::new(None),
        }
    }

    /// A copy of the state
    pub fn state(&self) -> AppState {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sends later updates to `reconciler` from a thread of its own, so a
    /// slow UI never holds an actor
    pub fn listen(&self, reconciler: Box<dyn Reconciler>) {
        let (sender, receiver) = mpsc::channel::<Update>();
        let spawned = std::thread::Builder::new()
            .name("companion-reconcile".to_owned())
            .spawn(move || {
                for update in receiver {
                    reconciler.reconcile(update);
                }
            });
        if let Err(error) = spawned {
            tracing::error!(%error, "cannot start the reconcile thread");

            return;
        }

        // the last listener's thread ends once its sender is dropped here
        *self.updates.lock().unwrap_or_else(PoisonError::into_inner) = Some(sender);
    }

    /// Changes the state and sends the update `change` answers, if any
    fn change(&self, change: impl FnOnce(&mut AppState) -> Option<Update>) {
        let update = {
            let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
            change(&mut state)
        };
        let Some(update) = update else {
            return;
        };
        if let Some(sender) = self
            .updates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(update);
        }
    }

    fn set_connection(&self, connection: ConnectionState) {
        self.change(|state| {
            (state.connection != connection).then(|| {
                state.connection = connection.clone();

                Update::Connection(connection)
            })
        });
    }

    fn set_pairing(&self, pairing: PairingState) {
        self.change(|state| {
            state.pairing = pairing.clone();

            Some(Update::Pairing(pairing))
        });
    }

    fn set_gateway(&self, record: Option<&GatewayRecord>) {
        let gateway = record.map(GatewayRecord::info);
        self.change(|state| {
            state.gateway = gateway.clone();

            Some(Update::Gateway(gateway))
        });
    }

    fn change_reads(&self, change: impl FnOnce(&mut Vec<PendingRead>) -> bool) {
        self.change(|state| change(&mut state.reads).then(|| Update::Reads(state.reads.clone())));
    }

    fn read_status(&self, id: &str) -> Option<ReadStatus> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .reads
            .iter()
            .find(|read| read.id == id)
            .map(|read| read.status.clone())
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        })
}

/// What the app actor starts with
pub struct AppArgs {
    /// The app's platform calls
    pub platform: Arc<dyn Platform>,
    /// The state the UI reads
    pub shared: Arc<Shared>,
    /// The paired gateway, from the Keychain
    pub record: Option<GatewayRecord>,
}

pub struct AppActorState {
    platform: Arc<dyn Platform>,
    shared: Arc<Shared>,
    record: Option<GatewayRecord>,
    connection: Option<ActorRef<ConnMsg>>,
    requests: HashMap<String, ActorRef<RequestMsg>>,
    foreground: bool,
    push: Option<PushToken>,
    pairing: bool,
}

pub struct App;

impl App {
    /// Starts the connection actor for the paired gateway, supervised by
    /// this actor; it connects once the app is in the foreground
    async fn start_connection(myself: &ActorRef<AppMsg>, state: &mut AppActorState) {
        let Some(record) = state.record.clone() else {
            return;
        };
        let platform = Arc::clone(&state.platform);
        let key = tokio::task::spawn_blocking(move || load_key(platform.as_ref()))
            .await
            .ok()
            .flatten();
        let Some(key) = key else {
            tracing::error!("the paired gateway's iroh key is missing");

            return;
        };

        Self::spawn_connection(myself, state, record, key).await;
    }

    async fn spawn_connection(
        myself: &ActorRef<AppMsg>,
        state: &mut AppActorState,
        record: GatewayRecord,
        key: SecretKey,
    ) {
        let args = ConnArgs {
            key,
            record,
            app: myself.clone(),
        };
        match Actor::spawn_linked(None, ConnectionActor, args, myself.get_cell()).await {
            Ok((connection, _)) => {
                if state.foreground {
                    let _ = connection.cast(ConnMsg::Connect);
                }
                state.connection = Some(connection);
            }
            Err(error) => {
                tracing::error!(%error, "cannot start the connection actor");
                state.shared.set_connection(ConnectionState::Retrying {
                    in_secs: 0,
                    error: error.to_string(),
                });
            }
        }
    }

    /// Tells the gateway where to push, on the current link
    fn send_push_token(state: &AppActorState) {
        let Some(connection) = state.connection.clone() else {
            return;
        };
        let token = state.push.clone();
        tokio::spawn(async move {
            let sent = ractor::call_t!(
                connection,
                |reply| ConnMsg::Request(PhoneRequest::PushToken(token.clone()), reply),
                10_000
            );
            if let Ok(Err(error)) | Err(error) = sent.map_err(|error| error.to_string()) {
                tracing::warn!(%error, "the gateway did not take the push token");
            }
        });
    }

    async fn action(myself: &ActorRef<AppMsg>, state: &mut AppActorState, action: AppAction) {
        match action {
            AppAction::Pair { scanned } => {
                if state.pairing || state.record.is_some() {
                    return;
                }
                match pairing::find_ticket(&scanned) {
                    Ok(ticket) => {
                        state.pairing = true;
                        state.shared.set_pairing(PairingState::Registering);
                        tokio::spawn(pairing::run(
                            Arc::clone(&state.platform),
                            ticket,
                            state.push.clone(),
                            myself.clone(),
                        ));
                    }
                    Err(message) => state.shared.set_pairing(PairingState::Failed { message }),
                }
            }
            AppAction::Allow { id } => {
                let reference = state
                    .shared
                    .state()
                    .reads
                    .into_iter()
                    .find(|read| read.id == id && !read.status.is_finished())
                    .map(|read| read.reference);
                if let Some(reference) = reference {
                    Self::list(state, &reference, true).await;
                }
            }
            AppAction::Disallow { reference } => Self::list(state, &reference, false).await,
            AppAction::Approve { id } => {
                // one Face ID prompt at a time
                let prompting = state
                    .shared
                    .state()
                    .reads
                    .iter()
                    .any(|read| read.status == ReadStatus::Approving);
                if !prompting && let Some(request) = state.requests.get(&id) {
                    let _ = request.cast(RequestMsg::Approve);
                }
            }
            AppAction::Deny { id } => match state.requests.get(&id) {
                Some(request) => {
                    let _ = request.cast(RequestMsg::Deny);
                }
                // opened from a push and never arrived; the gateway's own
                // deadline ends it there
                None => state.shared.change_reads(|reads| {
                    reads
                        .iter_mut()
                        .find(|read| read.id == id && read.status == ReadStatus::Connecting)
                        .map(|read| read.status = ReadStatus::Denied)
                        .is_some()
                }),
            },
            AppAction::Dismiss { id } => state.shared.change_reads(|reads| {
                let before = reads.len();
                reads.retain(|read| read.id != id || !read.status.is_finished());

                reads.len() != before
            }),
            AppAction::Unpair => {
                if state.record.is_none() {
                    return;
                }
                let connection = state.connection.take();
                let platform = Arc::clone(&state.platform);
                let myself = myself.clone();
                tokio::spawn(async move {
                    if let Some(connection) = connection {
                        let told = ractor::call_t!(
                            connection,
                            |reply| ConnMsg::Request(PhoneRequest::Unpair, reply),
                            u64::try_from(UNPAIR_TIMEOUT.as_millis()).unwrap_or(u64::MAX)
                        );
                        if !matches!(told, Ok(Ok(_))) {
                            tracing::warn!("the gateway was not told of the unpairing");
                        }
                        connection.stop(None);
                    }
                    let _ = tokio::task::spawn_blocking(move || {
                        GatewayRecord::forget(platform.as_ref());
                    })
                    .await;
                    let _ = myself.cast(AppMsg::Unpaired);
                });
            }
            AppAction::Foreground => {
                state.foreground = true;
                if let Some(connection) = &state.connection {
                    let _ = connection.cast(ConnMsg::Connect);
                }
            }
            AppAction::Background => {
                state.foreground = false;
                if let Some(connection) = &state.connection {
                    let _ = connection.cast(ConnMsg::Disconnect);
                }
            }
            AppAction::OpenedFromPush {
                id,
                reference,
                gateway,
            } => {
                let listed = state
                    .record
                    .as_ref()
                    .is_some_and(|record| record.allows(&reference));
                state.shared.change_reads(|reads| {
                    if reads.iter().any(|read| read.id == id) {
                        return false;
                    }
                    reads.push(PendingRead {
                        id: id.clone(),
                        reference,
                        gateway_name: gateway,
                        expires_at_ms: now_ms()
                            + i64::try_from(ASK_TIMEOUT.as_millis()).unwrap_or(i64::MAX),
                        status: ReadStatus::Connecting,
                        sealed: false,
                        listed,
                    });

                    true
                });
                myself.send_after(PUSH_WAIT, move || AppMsg::PushWaitOver(id));
                state.foreground = true;
                if let Some(connection) = &state.connection {
                    let _ = connection.cast(ConnMsg::Connect);
                }
            }
            AppAction::PushToken { token, environment } => {
                let environment = match environment {
                    PushEnvironment::Development => WirePushEnvironment::Development,
                    PushEnvironment::Production => WirePushEnvironment::Production,
                };
                let push = token.map(|token| PushToken { token, environment });
                if push == state.push {
                    return;
                }
                state.push = push;
                if state.shared.state().connection == ConnectionState::Connected {
                    Self::send_push_token(state);
                }
            }
        }
    }

    /// Starts a request actor for a new read, or hands a read offered again
    /// after a reconnect to the one it already has
    /// Puts `reference` on the allow list or takes it off, keeps the list
    /// in the Keychain, and tells the reads of it still open
    async fn list(state: &mut AppActorState, reference: &str, listed: bool) {
        let reference = reference.trim();
        let Some(record) = state.record.as_mut() else {
            return;
        };

        if record.allows(reference) != listed {
            if listed {
                record.allow.push(reference.to_owned());
            } else {
                record.allow.retain(|allowed| allowed.trim() != reference);
            }
            let platform = Arc::clone(&state.platform);
            let saved = record.clone();
            let kept = tokio::task::spawn_blocking(move || saved.save(platform.as_ref())).await;
            // the change holds until the app quits either way; only keeping
            // it failed
            if let Ok(Err(error)) = kept {
                tracing::warn!(%error, "could not keep the allow list");
            }
            state.shared.set_gateway(Some(record));
        }

        let mut changed = Vec::new();
        state.shared.change_reads(|reads| {
            let open = reads
                .iter_mut()
                .filter(|read| read.reference.trim() == reference && !read.status.is_finished());
            for read in open {
                read.listed = listed;
                changed.push(read.id.clone());
            }

            !changed.is_empty()
        });
        for id in changed {
            if let Some(request) = state.requests.get(&id) {
                let _ = request.cast(RequestMsg::Listed(listed));
            }
        }
    }

    async fn incoming(myself: &ActorRef<AppMsg>, state: &mut AppActorState, incoming: Incoming) {
        let Incoming {
            read,
            seq,
            responder,
        } = incoming;
        let id = read.id.to_string();
        if let Some(request) = state.requests.get(&id) {
            let _ = request.cast(RequestMsg::Replace { seq, responder });

            return;
        }
        let Some(record) = state.record.clone() else {
            return;
        };

        let expires_at_ms = now_ms() + i64::try_from(read.expires_in_ms).unwrap_or(i64::MAX);
        let pending = PendingRead {
            id: id.clone(),
            reference: read.reference.clone(),
            gateway_name: record.name.clone(),
            expires_at_ms,
            status: ReadStatus::Waiting,
            sealed: read.sealed.is_some(),
            listed: record.allows(&read.reference),
        };
        state.shared.change_reads(|reads| {
            match reads.iter_mut().find(|read| read.id == id) {
                Some(existing) => *existing = pending,
                None => reads.push(pending),
            }

            true
        });

        let args = RequestArgs {
            read,
            seq,
            responder,
            record,
            platform: Arc::clone(&state.platform),
            app: myself.clone(),
        };
        match Actor::spawn_linked(None, RequestActor, args, myself.get_cell()).await {
            Ok((request, _)) => {
                state.requests.insert(id, request);
            }
            Err(error) => {
                tracing::error!(%error, "cannot start a request actor");
                let message = error.to_string();
                state.shared.change_reads(|reads| {
                    reads
                        .iter_mut()
                        .find(|read| read.id == id)
                        .map(|read| read.status = ReadStatus::Failed { message })
                        .is_some()
                });
            }
        }
    }
}

impl Actor for App {
    type Msg = AppMsg;
    type State = AppActorState;
    type Arguments = AppArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(AppActorState {
            platform: args.platform,
            shared: args.shared,
            record: args.record,
            connection: None,
            requests: HashMap::new(),
            foreground: false,
            push: None,
            pairing: false,
        })
    }

    async fn post_start(
        &self,
        myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Self::start_connection(&myself, state).await;

        Ok(())
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            AppMsg::Action(action) => Self::action(&myself, state, action).await,
            AppMsg::Registered(Ok(record)) => {
                state.record = Some(record);
                state.shared.set_gateway(state.record.as_ref());
                state.shared.set_pairing(PairingState::Checking);
                Self::start_connection(&myself, state).await;
            }
            AppMsg::Registered(Err(message)) => {
                state.pairing = false;
                state.shared.set_pairing(PairingState::Failed { message });
            }
            AppMsg::Checked(checked) => {
                state.pairing = false;
                let message = match checked {
                    Ok(check) => pairing::describe(&check),
                    Err(error) => {
                        format!("Paired, but the gateway's check did not finish: {error}")
                    }
                };
                state.shared.set_pairing(PairingState::Done { message });
            }
            AppMsg::Unpaired => {
                state.record = None;
                for (_, request) in state.requests.drain() {
                    request.stop(None);
                }
                state.shared.set_gateway(None);
                state.shared.set_connection(ConnectionState::Offline);
                state.shared.change_reads(|reads| {
                    let had = !reads.is_empty();
                    reads.clear();

                    had
                });
                state.shared.set_pairing(PairingState::Idle);
            }
            AppMsg::Connection(connection) => {
                let connected = connection == ConnectionState::Connected;
                state.shared.set_connection(connection);
                if connected && state.push.is_some() {
                    Self::send_push_token(state);
                }
            }
            AppMsg::Incoming(incoming) => Self::incoming(&myself, state, *incoming).await,
            AppMsg::Answer { id, value } => {
                if let Some(request) = state.requests.get(&id) {
                    let _ = request.cast(RequestMsg::Answer(value));
                }
            }
            AppMsg::StreamEnded { id, seq, end } => {
                if let Some(request) = state.requests.get(id.as_str()) {
                    let _ = request.cast(RequestMsg::StreamEnded { seq, end });
                }
            }
            AppMsg::ReadChanged { id, status } => {
                if status.is_finished() {
                    state.requests.remove(&id);
                }
                state.shared.change_reads(|reads| {
                    reads
                        .iter_mut()
                        .find(|read| read.id == id)
                        .map(|read| read.status = status)
                        .is_some()
                });
            }
            AppMsg::PushWaitOver(id) => {
                if state.shared.read_status(&id) == Some(ReadStatus::Connecting) {
                    state.shared.change_reads(|reads| {
                        reads
                            .iter_mut()
                            .find(|read| read.id == id)
                            .map(|read| read.status = ReadStatus::Expired)
                            .is_some()
                    });
                }
            }
        }

        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let SupervisionEvent::ActorFailed(cell, error) = event else {
            return Ok(());
        };
        tracing::error!(%error, "a child actor failed");

        if is(&cell, state.connection.as_ref()) {
            // the endpoint could not bind, or the actor broke; start over
            state.connection = None;
            state.shared.set_connection(ConnectionState::Retrying {
                in_secs: 1,
                error: error.to_string(),
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
            Self::start_connection(&myself, state).await;

            return Ok(());
        }

        let failed = state
            .requests
            .iter()
            .find(|(_, request)| request.get_id() == cell.get_id())
            .map(|(id, _)| id.clone());
        if let Some(id) = failed {
            state.requests.remove(&id);
            let message = error.to_string();
            state.shared.change_reads(|reads| {
                reads
                    .iter_mut()
                    .find(|read| read.id == id)
                    .map(|read| read.status = ReadStatus::Failed { message })
                    .is_some()
            });
        }

        Ok(())
    }
}

fn is(cell: &ActorCell, actor: Option<&ActorRef<ConnMsg>>) -> bool {
    actor.is_some_and(|actor| actor.get_id() == cell.get_id())
}
