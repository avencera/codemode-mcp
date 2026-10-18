//! The app actor: the supervisor of the connection and request actors, and
//! the only writer of [`AppState`]
//!
//! It takes the UI's actions and its children's reports, changes the state,
//! and sends each change to the reconciler as an [`Update`]. Anything slow
//! (pairing, unpairing, Keychain calls) runs in a spawned task whose result
//! comes back as a message

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, PoisonError, RwLock, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use companion_wire::{
    ASK_TIMEOUT,
    mobile::{
        PhoneProgramRead, PhoneRequest, ProgramItem as WireProgramItem,
        PushEnvironment as WirePushEnvironment, PushToken, RequestId,
    },
    wire::{
        CompanionErrorCode, CompanionFault, CompanionResponse, MAX_DESCRIPTION_CHARS,
        MAX_DESTINATION_CHARS, MAX_PROGRAM_ITEMS, MAX_REASON_CHARS, PairCheck,
    },
};
use iroh::SecretKey;
use ractor::{Actor, ActorCell, ActorProcessingErr, ActorRef, SupervisionEvent};
use tokio::sync::oneshot;

use crate::{
    connection::{ConnArgs, ConnMsg, ConnectionActor},
    ffi::{
        AppAction, AppState, ConnectionState, PairingState, PendingRead, Platform, ProgramItem,
        ProgramRead, PushEnvironment, ReadStatus, Reconciler, Update,
    },
    pairing,
    record::{GatewayRecord, load_key},
    request::{Asked, Entered, RequestActor, RequestArgs, RequestMsg, Secret, keep_secs},
};

/// How long a read opened from a push may take to arrive once the link is
/// up before it counts as gone; the gateway sends every read still waiting
/// as soon as the phone dials, so one that does not come was answered
/// elsewhere or given up
const PUSH_WAIT: Duration = Duration::from_secs(5);
/// How long unpairing waits for the gateway before forgetting it anyway
const UNPAIR_TIMEOUT: Duration = Duration::from_secs(5);
/// Seconds before the connection actor is started again after it would not
/// start or failed
const RESTART_SECS: u32 = 1;
/// Longest reference a program read's prompt shows in full
const MAX_REFERENCE_CHARS: usize = 256;
/// Longest summary of a program read's items a push placeholder shows
const MAX_SUMMARY_CHARS: usize = 200;

/// How a read's stream ended without an answer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// The answer reached the gateway
    Delivered,
    /// The gateway stopped it: another source answered, or it gave up
    Withdrawn,
    /// The link dropped, before or while the answer went; the gateway offers
    /// the read again on the next one
    Interrupted,
}

/// A read as it arrives, with where its answer goes
pub struct Incoming {
    /// The read
    pub asked: Asked,
    /// Its stream's number
    pub seq: u64,
    /// Where the answer goes
    pub responder: oneshot::Sender<CompanionResponse>,
}

/// An approval that may ask Face ID, run at once or, while another read's
/// prompt is up, once that one ends
enum Approval {
    /// The owner tapped Approve
    Approve(String),
    /// The owner sent a program read, with the values entered by item index
    Program {
        /// The read
        id: String,
        /// The values
        entered: HashMap<u32, Entered>,
    },
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
    /// The owner approved a program read, with the values entered by item
    /// index
    AnswerProgram {
        /// The read
        id: String,
        /// The values
        entered: HashMap<u32, Entered>,
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
    /// The wait for a read opened from a push is over: its deadline passed,
    /// or, with a link number, that link has been up a while without it
    PushWaitOver {
        /// The read
        id: String,
        /// The link the wait was for, if any
        link: Option<u64>,
    },
    /// Start the connection actor again, unless one runs or the gateway was
    /// forgotten meanwhile
    StartConnection,
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

/// The first `limit` characters with line breaks shown as `⏎` and other
/// control, invisible and direction-changing characters as `?`, cut with `…`,
/// so text a program chose stays on one line and reads in the order it is
/// stored; the gateway's prompts clean text the same way
fn one_line(text: &str, limit: usize) -> String {
    let mut shown: String = text
        .chars()
        .take(limit)
        .map(|character| match character {
            '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}' => '⏎',
            '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' => '?',
            other if other.is_control() => '?',
            other => other,
        })
        .collect();
    if text.chars().nth(limit).is_some() {
        shown.push('…');
    }

    shown
}

/// A program read as its prompt shows it, with a one-line summary for the
/// row's `reference`
fn program_prompt(program: &PhoneProgramRead) -> (String, ProgramRead) {
    let items: Vec<ProgramItem> = program
        .items
        .iter()
        .map(|item| match item {
            WireProgramItem::Reference { reference, sealed } => ProgramItem::Reference {
                reference: one_line(reference, MAX_REFERENCE_CHARS),
                sealed: sealed.is_some(),
            },
            WireProgramItem::Describe { description } => ProgramItem::Describe {
                description: one_line(description, MAX_DESCRIPTION_CHARS),
            },
        })
        .collect();
    let named: Vec<&str> = items
        .iter()
        .map(|item| match item {
            ProgramItem::Reference { reference, .. } => reference.as_str(),
            ProgramItem::Describe { description } => description.as_str(),
        })
        .collect();
    let summary = match named.as_slice() {
        [one] => (*one).to_owned(),
        many => format!("{} values: {}", many.len(), many.join(", ")),
    };
    let reason = program
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(|reason| one_line(reason, MAX_REASON_CHARS));
    let destination = program
        .destination
        .as_deref()
        .map(str::trim)
        .filter(|destination| !destination.is_empty())
        .map(|destination| one_line(destination, MAX_DESTINATION_CHARS));
    let prompt = ProgramRead {
        reason,
        destination,
        keep_secs: keep_secs(program),
        items,
    };

    (summary, prompt)
}

/// Why the phone cannot answer a program read as sent, if it cannot
fn malformed(program: &PhoneProgramRead) -> Option<String> {
    if program.items.is_empty() {
        return Some("the program read names no items".to_owned());
    }
    if program.items.len() > MAX_PROGRAM_ITEMS {
        return Some(format!(
            "the program read names {} items, more than {MAX_PROGRAM_ITEMS}",
            program.items.len()
        ));
    }

    None
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
    /// Every request actor still running, finished or not: one holding an
    /// answer for a dropped link stays until the gateway offers the read
    /// again
    requests: HashMap<String, ActorRef<RequestMsg>>,
    /// The read whose Face ID prompt is up; one at a time
    approving: Option<String>,
    /// Approvals made while a prompt was up, run in order once it ends
    queued: VecDeque<Approval>,
    foreground: bool,
    /// Where the gateway pushes: `None` until iOS has said, `Some(None)`
    /// once notifications are off, so that is sent too
    push: Option<Option<PushToken>>,
    /// Reads denied while still on their way from a push, kept until the
    /// gateway's deadline has passed
    denied: HashMap<String, Instant>,
    pairing: bool,
    /// Counts changes to the link, so a wait meant for one link is not
    /// ended by its timer after that link dropped
    link: u64,
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
        // the Keychain is unreadable until the first unlock after a restart,
        // so a missing key is tried again too
        let Some(key) = key else {
            Self::restart_connection(myself, state, "the paired gateway's key is not readable");

            return;
        };

        Self::spawn_connection(myself, state, record, key).await;
    }

    /// Starts the connection actor again shortly; ractor tells a supervisor
    /// nothing about a child whose `pre_start` failed, so nothing else would
    fn restart_connection(myself: &ActorRef<AppMsg>, state: &mut AppActorState, error: &str) {
        tracing::error!(%error, "the connection is starting again");
        state.connection = None;
        state.shared.set_connection(ConnectionState::Retrying {
            in_secs: RESTART_SECS,
            error: error.to_owned(),
        });
        myself.send_after(Duration::from_secs(RESTART_SECS.into()), || {
            AppMsg::StartConnection
        });
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
            Err(error) => Self::restart_connection(myself, state, &error.to_string()),
        }
    }

    /// Tells the gateway where to push, on the current link
    fn send_push_token(state: &AppActorState) {
        let Some(connection) = state.connection.clone() else {
            return;
        };
        let token = state.push.clone().flatten();
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
                            state.push.clone().flatten(),
                            myself.clone(),
                        ));
                    }
                    Err(message) => state.shared.set_pairing(PairingState::Failed { message }),
                }
            }
            AppAction::Approve { id } => Self::approve(state, Approval::Approve(id)).await,
            AppAction::Deny { id } => match state.requests.get(&id) {
                Some(request) => {
                    let _ = request.cast(RequestMsg::Deny);
                }
                // opened from a push and not here yet: the read is answered
                // with the denial when it arrives
                None => {
                    if state.shared.read_status(&id) != Some(ReadStatus::Connecting) {
                        return;
                    }
                    // kept apart from the row, which Done removes
                    state.denied.retain(|_, at| at.elapsed() < ASK_TIMEOUT);
                    state.denied.insert(id.clone(), Instant::now());
                    state.shared.change_reads(|reads| {
                        reads
                            .iter_mut()
                            .find(|read| read.id == id)
                            .map(|read| read.status = ReadStatus::Denied)
                            .is_some()
                    });
                }
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
                expires_at_ms,
            } => {
                let pushed = PendingRead {
                    id,
                    reference,
                    gateway_name: gateway,
                    expires_at_ms: 0,
                    status: ReadStatus::Connecting,
                    sealed: false,
                    program: None,
                };
                Self::opened_from_push(myself, state, pushed, expires_at_ms);
            }
            AppAction::OpenedFromProgramPush {
                id,
                summary,
                gateway,
                expires_at_ms,
            } => {
                let pushed = PendingRead {
                    id,
                    reference: one_line(&summary, MAX_SUMMARY_CHARS),
                    gateway_name: gateway,
                    expires_at_ms: 0,
                    status: ReadStatus::Connecting,
                    sealed: false,
                    program: Some(ProgramRead {
                        reason: None,
                        destination: None,
                        keep_secs: None,
                        items: Vec::new(),
                    }),
                };
                Self::opened_from_push(myself, state, pushed, expires_at_ms);
            }
            AppAction::PushToken { token, environment } => {
                let environment = match environment {
                    PushEnvironment::Development => WirePushEnvironment::Development,
                    PushEnvironment::Production => WirePushEnvironment::Production,
                };
                let push = Some(token.map(|token| PushToken { token, environment }));
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

    /// Runs `approval`, or queues it while another read's Face ID prompt is
    /// up: one prompt at a time, and a tap made meanwhile is not lost
    async fn approve(state: &mut AppActorState, approval: Approval) {
        if state.approving.is_some() {
            state.queued.push_back(approval);

            return;
        }

        Self::start_approval(state, approval).await;
    }

    /// Runs what was queued while a prompt was up, until one asks Face ID
    async fn run_queued(state: &mut AppActorState) {
        while state.approving.is_none() {
            let Some(approval) = state.queued.pop_front() else {
                return;
            };
            Self::start_approval(state, approval).await;
        }
    }

    /// Hands `approval` to its request, which answers whether Face ID is up
    /// before the next action is taken, so two quick taps cannot both start
    /// a prompt
    async fn start_approval(state: &mut AppActorState, approval: Approval) {
        let (id, started) = match approval {
            Approval::Approve(id) => {
                let Some(request) = state.requests.get(&id) else {
                    return;
                };
                let started = ractor::call_t!(request, RequestMsg::Approve, 2_000);

                (id, started)
            }
            Approval::Program { id, entered } => {
                let Some(request) = state.requests.get(&id) else {
                    return;
                };
                let started = ractor::call_t!(
                    request,
                    |reply| RequestMsg::AnswerProgram { entered, reply },
                    2_000
                );

                (id, started)
            }
        };

        if matches!(started, Ok(true)) {
            state.approving = Some(id);
        }
    }

    /// Shows the read a tapped push names until the gateway sends it, and
    /// dials; `pushed` comes without its deadline, which the push may give
    fn opened_from_push(
        myself: &ActorRef<AppMsg>,
        state: &mut AppActorState,
        pushed: PendingRead,
        expires_at_ms: Option<i64>,
    ) {
        let now = now_ms();
        let longest = now + i64::try_from(ASK_TIMEOUT.as_millis()).unwrap_or(i64::MAX);
        let expires_at_ms = expires_at_ms.map_or(longest, |at| at.min(longest));
        // tapped after the gateway stopped waiting: say so at once; the phone
        // still dials, and a read that comes anyway (the clocks disagree)
        // takes this row's place
        let status = if expires_at_ms <= now {
            ReadStatus::Expired
        } else {
            ReadStatus::Connecting
        };

        let id = pushed.id.clone();
        state.shared.change_reads(|reads| {
            if reads.iter().any(|read| read.id == id) {
                return false;
            }
            reads.push(PendingRead {
                expires_at_ms,
                status,
                ..pushed
            });

            true
        });

        let left = Duration::from_millis(u64::try_from(expires_at_ms - now).unwrap_or(0));
        let waiting = id.clone();
        myself.send_after(left, move || AppMsg::PushWaitOver {
            id: waiting,
            link: None,
        });

        if state.shared.state().connection == ConnectionState::Connected {
            let link = Some(state.link);
            myself.send_after(PUSH_WAIT, move || AppMsg::PushWaitOver { id, link });
        }

        state.foreground = true;
        if let Some(connection) = &state.connection {
            let _ = connection.cast(ConnMsg::Connect);
        }
    }

    /// Starts a request actor for a new read, or hands a read offered again
    /// after a reconnect to the one it already has
    async fn incoming(myself: &ActorRef<AppMsg>, state: &mut AppActorState, incoming: Incoming) {
        let Incoming {
            asked,
            seq,
            responder,
        } = incoming;
        let id = asked.id().to_string();
        if let Some(request) = state.requests.get(&id) {
            let _ = request.cast(RequestMsg::Replace { seq, responder });

            return;
        }
        // denied while it was still on its way from a push; kept until the
        // deadline, so a read offered again after a dropped link is denied
        // again rather than asked about anew
        if state
            .denied
            .get(&id)
            .is_some_and(|at| at.elapsed() < ASK_TIMEOUT)
        {
            let _ = responder.send(CompanionResponse::Error(CompanionFault {
                code: CompanionErrorCode::Denied,
                message: "not approved on this phone".to_owned(),
            }));

            return;
        }
        let Some(record) = state.record.clone() else {
            return;
        };

        let expires_at_ms = now_ms() + i64::try_from(asked.expires_in_ms()).unwrap_or(i64::MAX);
        let (reference, sealed, program) = match &asked {
            Asked::Read(read) => (read.reference.clone(), read.sealed.is_some(), None),
            Asked::Program(program) => {
                if let Some(message) = malformed(program) {
                    tracing::warn!(%message, "the gateway sent a program read this phone refuses");
                    let _ = responder.send(CompanionResponse::Error(CompanionFault {
                        code: CompanionErrorCode::NotAllowed,
                        message,
                    }));

                    return;
                }
                let (summary, prompt) = program_prompt(program);
                let sealed = prompt.items.iter().all(ProgramItem::is_sealed);

                (summary, sealed, Some(prompt))
            }
        };
        let pending = PendingRead {
            id: id.clone(),
            reference,
            gateway_name: record.name.clone(),
            expires_at_ms,
            status: ReadStatus::Waiting,
            sealed,
            program,
        };
        state.shared.change_reads(|reads| {
            match reads.iter_mut().find(|read| read.id == id) {
                Some(existing) => *existing = pending,
                None => reads.push(pending),
            }

            true
        });

        let args = RequestArgs {
            asked,
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
            approving: None,
            queued: VecDeque::new(),
            foreground: false,
            push: None,
            denied: HashMap::new(),
            pairing: false,
            link: 0,
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
                // one restarted while the gateway was being told
                if let Some(connection) = state.connection.take() {
                    connection.stop(None);
                }
                for (_, request) in state.requests.drain() {
                    request.stop(None);
                }
                state.queued.clear();
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
                state.link = state.link.wrapping_add(1);
                if !connected {
                    return Ok(());
                }
                if state.push.is_some() {
                    Self::send_push_token(state);
                }
                // reads opened from a push have a short while to arrive on
                // the new link
                let link = Some(state.link);
                for read in state.shared.state().reads {
                    if read.status == ReadStatus::Connecting {
                        myself.send_after(PUSH_WAIT, move || AppMsg::PushWaitOver {
                            id: read.id,
                            link,
                        });
                    }
                }
            }
            AppMsg::Incoming(incoming) => Self::incoming(&myself, state, *incoming).await,
            AppMsg::Answer { id, value } => {
                if let Some(request) = state.requests.get(&id) {
                    let _ = request.cast(RequestMsg::Answer(value));
                }
            }
            AppMsg::AnswerProgram { id, entered } => {
                Self::approve(state, Approval::Program { id, entered }).await;
            }
            AppMsg::StreamEnded { id, seq, end } => {
                if let Some(request) = state.requests.get(id.as_str()) {
                    let _ = request.cast(RequestMsg::StreamEnded { seq, end });
                }
            }
            AppMsg::ReadChanged { id, status } => {
                if status != ReadStatus::Approving
                    && state.approving.as_deref() == Some(id.as_str())
                {
                    state.approving = None;
                }
                state.shared.change_reads(|reads| {
                    reads
                        .iter_mut()
                        .find(|read| read.id == id)
                        .map(|read| read.status = status)
                        .is_some()
                });
                Self::run_queued(state).await;
            }
            AppMsg::PushWaitOver { id, link } => {
                // the link dropped and the gateway waits for the next one
                if link.is_some_and(|link| link != state.link) {
                    return Ok(());
                }
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
            AppMsg::StartConnection if state.connection.is_none() => {
                Self::start_connection(&myself, state).await;
            }
            AppMsg::StartConnection => {}
        }

        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        myself: ActorRef<Self::Msg>,
        event: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let (cell, error) = match event {
            SupervisionEvent::ActorFailed(cell, error) => (cell, error),
            // a request that stopped is done with its read
            SupervisionEvent::ActorTerminated(cell, ..) => {
                state
                    .requests
                    .retain(|_, request| request.get_id() != cell.get_id());

                return Ok(());
            }
            _ => return Ok(()),
        };
        tracing::error!(%error, "a child actor failed");

        if is(&cell, state.connection.as_ref()) {
            Self::restart_connection(&myself, state, &error.to_string());

            return Ok(());
        }

        let failed = state
            .requests
            .iter()
            .find(|(_, request)| request.get_id() == cell.get_id())
            .map(|(id, _)| id.clone());
        if let Some(id) = failed {
            state.requests.remove(&id);
            if state.approving.as_deref() == Some(id.as_str()) {
                state.approving = None;
            }
            let message = error.to_string();
            state.shared.change_reads(|reads| {
                reads
                    .iter_mut()
                    .find(|read| read.id == id)
                    .map(|read| read.status = ReadStatus::Failed { message })
                    .is_some()
            });
            Self::run_queued(state).await;
        }

        Ok(())
    }
}

fn is(cell: &ActorCell, actor: Option<&ActorRef<ConnMsg>>) -> bool {
    actor.is_some_and(|actor| actor.get_id() == cell.get_id())
}
