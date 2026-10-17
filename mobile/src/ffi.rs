//! What Swift sees: the one root object, the state it renders, the actions
//! it sends and the platform calls it answers
//!
//! The UI never changes state itself. It sends an [`AppAction`] through
//! [`FfiApp::dispatch`] and renders what comes back through its
//! [`Reconciler`]

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use ractor::{Actor, ActorRef};

use crate::{
    app::{App, AppArgs, AppMsg, Shared},
    record::GatewayRecord,
    request::Secret,
};

/// What the app shows
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AppState {
    /// The gateway this phone answers; `None` until it is paired
    pub gateway: Option<GatewayInfo>,
    /// The link to the gateway
    pub connection: ConnectionState,
    /// Reads asked of this phone, newest last, including finished ones until
    /// they are dismissed
    pub reads: Vec<PendingRead>,
    /// Where a pairing stands
    pub pairing: PairingState,
}

/// The paired gateway
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GatewayInfo {
    /// The gateway Mac's short name
    pub name: String,
    /// The gateway's endpoint id
    pub id: String,
    /// The name the gateway lists this phone under
    pub phone_name: String,
}

/// The link to the gateway
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    /// Not connected, and not trying: no gateway, or the app is in the
    /// background
    Offline,
    /// Dialing
    Connecting,
    /// Reads can arrive
    Connected,
    /// The last dial failed; the next starts after `in_secs`
    Retrying {
        /// Seconds to the next dial
        in_secs: u32,
        /// Why the last one failed
        error: String,
    },
}

/// One read the gateway asked this phone to approve
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingRead {
    /// The id the push named
    pub id: String,
    /// The `op://` reference; for a program read, one line naming its items
    pub reference: String,
    /// The gateway Mac's short name
    pub gateway_name: String,
    /// When the gateway gives up, in ms since the epoch on this phone's clock
    pub expires_at_ms: i64,
    /// Whether the gateway sent a copy Face ID can open; without one the
    /// owner enters the value. For a program read, whether every item has
    /// one
    pub sealed: bool,
    /// Where it stands
    pub status: ReadStatus,
    /// Set when a program on the gateway Mac asked, rather than the
    /// gateway's own config; its values go to that program
    pub program: Option<ProgramRead>,
}

/// What a program on the gateway Mac asked for, as the prompt shows it
///
/// Every text here is cleaned to one line: line breaks show as `⏎`, and
/// control, invisible and direction-changing characters as `?`
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProgramRead {
    /// Why the program wants the values, in its own words; a claim to show
    /// quoted, not a fact
    pub reason: Option<String>,
    /// Where the program says the values go, such as a file it writes or
    /// the environment of a command it runs
    pub destination: Option<String>,
    /// How long, in seconds, programs on the gateway may get the same values
    /// again without asking, at most an hour; `None` when every request asks
    pub keep_secs: Option<u64>,
    /// The values asked for, in the order they are sent; empty while a read
    /// opened from a push has not arrived
    pub items: Vec<ProgramItem>,
}

/// One value of a [`ProgramRead`]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ProgramItem {
    /// An `op://` reference
    Reference {
        /// The reference
        reference: String,
        /// Whether the gateway sent a copy Face ID can open; without one the
        /// owner enters the value
        sealed: bool,
    },
    /// Only the program's description of the item; the owner picks it in
    /// 1Password and enters the value
    Describe {
        /// The description
        description: String,
    },
}

impl ProgramItem {
    /// Whether Face ID can open this item's value
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Reference { sealed: true, .. })
    }
}

/// Where one read stands
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ReadStatus {
    /// Opened from a push; the gateway has not sent the read yet
    Connecting,
    /// Waiting for the owner
    Waiting,
    /// Face ID is up
    Approving,
    /// The value was sent
    Approved,
    /// The owner refused
    Denied,
    /// The gateway gave up waiting
    Expired,
    /// Another source answered first, so the gateway no longer wants it
    Withdrawn,
    /// Opening the value failed
    Failed {
        /// Why
        message: String,
    },
}

impl ReadStatus {
    /// Whether nothing more happens to the read
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::Connecting | Self::Waiting | Self::Approving)
    }
}

/// Where a pairing stands
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PairingState {
    /// No pairing under way
    Idle,
    /// Registering with the gateway
    Registering,
    /// Registered; the gateway is checking with one read
    Checking,
    /// Finished
    Done {
        /// What the check found
        message: String,
    },
    /// Nothing was paired, or the check failed
    Failed {
        /// Why
        message: String,
    },
}

/// Which APNs environment issued a push token
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PushEnvironment {
    /// Builds installed from Xcode
    Development,
    /// TestFlight and App Store builds
    Production,
}

/// What the UI asks for
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AppAction {
    /// Pair with the invite in scanned text: a `cmcp2…` ticket alone, or
    /// the install command `companion invite` prints
    Pair {
        /// What the camera read
        scanned: String,
    },
    /// Open the read's value with Face ID and send it; for a program read,
    /// open every item with one Face ID, which answers only when each item
    /// has a sealed copy (see [`FfiApp::answer_program`])
    Approve {
        /// The read
        id: String,
    },
    /// Refuse the read
    Deny {
        /// The read
        id: String,
    },
    /// Remove a finished read from the list
    Dismiss {
        /// The read
        id: String,
    },
    /// Tell the gateway to forget this phone, then drop its keys
    Unpair,
    /// The app came to the foreground: connect
    Foreground,
    /// The app went to the background: hang up before iOS suspends it
    Background,
    /// The app was opened from a push for this read
    OpenedFromPush {
        /// The request id in the push
        id: String,
        /// The reference in the push
        reference: String,
        /// The gateway name in the push
        gateway: String,
        /// When the gateway stops waiting, in Unix milliseconds, if the
        /// push says
        expires_at_ms: Option<i64>,
    },
    /// The app was opened from a push for a program read
    OpenedFromProgramPush {
        /// The request id in the push
        id: String,
        /// The push's one line naming the items
        summary: String,
        /// The gateway name in the push
        gateway: String,
        /// When the gateway stops waiting, in Unix milliseconds, if the
        /// push says
        expires_at_ms: Option<i64>,
    },
    /// APNs gave this token, or `None` when notifications are off
    PushToken {
        /// The device token as lowercase hex
        token: Option<String>,
        /// Which environment issued it
        environment: PushEnvironment,
    },
}

/// One change to [`AppState`], sent to the [`Reconciler`]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Update {
    /// The paired gateway changed
    Gateway(Option<GatewayInfo>),
    /// The link changed
    Connection(ConnectionState),
    /// The reads changed
    Reads(Vec<PendingRead>),
    /// The pairing moved on
    Pairing(PairingState),
}

/// Receives each [`Update`]; Swift applies it on the main actor
#[uniffi::export(callback_interface)]
pub trait Reconciler: Send + Sync + 'static {
    /// Applies one update
    fn reconcile(&self, update: Update);
}

/// Why a platform call failed
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformError {
    /// The Keychain or Secure Enclave refused
    #[error("{message}")]
    Failed {
        /// What failed
        message: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            message: error.reason,
        }
    }
}

/// Why a sealed value was not opened
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OpenError {
    /// The owner tapped Deny on the Face ID prompt; only this answers
    /// `Denied`, which ends the read on every device
    #[error("not approved on this phone")]
    Denied,
    /// Anything else: Face ID was interrupted, did not match or is
    /// unavailable, the key is gone, or the ciphertext does not open. The
    /// gateway hears `ReadFailed` and keeps asking its other sources
    #[error("{message}")]
    Failed {
        /// What failed
        message: String,
    },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for OpenError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed {
            message: error.reason,
        }
    }
}

/// Everything Face ID needs to open one value: the reason it shows, and the
/// HPKE pieces. `info` binds the reference and gateway, so the value opens
/// only for the read the prompt names
#[derive(Clone, uniffi::Record)]
pub struct OpenRequest {
    /// The read, so [`Platform::cancel_open`] can name it
    pub id: String,
    /// The reference the prompt names
    pub reference: String,
    /// The gateway the prompt names
    pub gateway_name: String,
    /// HPKE `info`
    pub info: Vec<u8>,
    /// The encapsulated key
    pub enc: Vec<u8>,
    /// The sealed value
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for OpenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenRequest")
            .field("id", &self.id)
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

/// One sealed value of an [`OpenBatch`]
#[derive(Clone, uniffi::Record)]
pub struct SealedItem {
    /// The reference the value was sealed under
    pub reference: String,
    /// HPKE `info`, binding the reference and gateway
    pub info: Vec<u8>,
    /// The encapsulated key
    pub enc: Vec<u8>,
    /// The sealed value
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SealedItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedItem")
            .field("reference", &self.reference)
            .finish_non_exhaustive()
    }
}

/// Everything one Face ID needs to open the sealed values of a program read
#[derive(Clone, uniffi::Record)]
pub struct OpenBatch {
    /// The read, so [`Platform::cancel_open`] can name it
    pub id: String,
    /// The gateway the program runs on
    pub gateway_name: String,
    /// How many values go to the program, entered ones included, for the
    /// reason Face ID shows
    pub total: u32,
    /// How long, in seconds, the gateway may hand the values out again
    /// without asking, for the reason Face ID shows
    pub keep_secs: Option<u64>,
    /// The values to open, answered in this order
    pub items: Vec<SealedItem>,
}

impl std::fmt::Debug for OpenBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenBatch")
            .field("id", &self.id)
            .field("total", &self.total)
            .field("keep_secs", &self.keep_secs)
            .field("items", &self.items)
            .finish_non_exhaustive()
    }
}

/// The calls only the app can make; Rust never sees the Secure Enclave key
///
/// Every call may block (Face ID waits for the owner), so Rust makes them
/// off its actors' threads
#[uniffi::export(callback_interface)]
pub trait Platform: Send + Sync + 'static {
    /// The Keychain item `key`, this device only
    fn load_secret(&self, key: String) -> Option<Vec<u8>>;
    /// Stores the Keychain item `key`, this device only
    fn save_secret(&self, key: String, value: Vec<u8>) -> Result<(), PlatformError>;
    /// Deletes the Keychain item `key`
    fn delete_secret(&self, key: String);
    /// Makes a new Secure Enclave P-256 key, usable only after Face ID with
    /// the biometry enrolled now, replacing any earlier one; answers its
    /// public key as an uncompressed point
    fn create_seal_key(&self) -> Result<Vec<u8>, PlatformError>;
    /// Deletes the Secure Enclave key
    fn delete_seal_key(&self);
    /// Asks Face ID with a reason naming the reference and gateway, then
    /// opens the value with the Secure Enclave key
    fn open_sealed(&self, request: OpenRequest) -> Result<String, OpenError>;
    /// Asks Face ID once, with a reason saying the values go to a program on
    /// the gateway, then opens every item with the Secure Enclave key; the
    /// values come back in the order of `batch.items`
    fn open_sealed_batch(&self, batch: OpenBatch) -> Result<Vec<String>, OpenError>;
    /// Takes down the Face ID prompt of read `id`, if it is up
    fn cancel_open(&self, id: String);
    /// This phone's name, as the gateway lists it
    fn device_name(&self) -> String;
}

/// The core's own runtime; Swift calls in from its threads, so every actor
/// runs here rather than on whatever runtime the call happens to come from
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("companion-core")
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            // nothing works without it, and there is nothing to fall back to
            Err(error) => panic!("cannot start the tokio runtime: {error}"),
        }
    })
}

/// The root object Swift holds for the life of the app
#[derive(uniffi::Object)]
pub struct FfiApp {
    actor: ActorRef<AppMsg>,
    shared: Arc<Shared>,
}

#[uniffi::export]
impl FfiApp {
    /// Starts the core with the app's platform calls; the paired gateway,
    /// if any, is loaded from the Keychain
    #[uniffi::constructor]
    pub fn new(platform: Box<dyn Platform>) -> Arc<Self> {
        let platform: Arc<dyn Platform> = Arc::from(platform);
        let record = GatewayRecord::load(platform.as_ref());
        let shared = Arc::new(Shared::new(record.as_ref()));
        let args = AppArgs {
            platform,
            shared: Arc::clone(&shared),
            record,
        };
        let spawned = runtime().block_on(Actor::spawn(None, App, args));
        let actor = match spawned {
            Ok((actor, _)) => actor,
            Err(error) => panic!("cannot start the app actor: {error}"),
        };

        Arc::new(Self { actor, shared })
    }

    /// What the app shows now
    pub fn state(&self) -> AppState {
        self.shared.state()
    }

    /// Asks for `action`; its effects arrive through the reconciler
    pub fn dispatch(&self, action: AppAction) {
        if let Err(error) = self.actor.cast(AppMsg::Action(action)) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Sends `value`, which the owner pasted or filled in, as the answer to
    /// the read `id`; its own call rather than an [`AppAction`], so the value
    /// never sits in a type that derives `Debug`
    pub fn answer(&self, id: String, value: String) {
        if let Err(error) = self.actor.cast(AppMsg::Answer {
            id,
            value: Secret(value),
        }) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Approves the program read `id`: sends `entered`, the values the owner
    /// pasted or filled in keyed by item index, and opens every other item
    /// with one Face ID. Nothing is sent unless each item has an entered
    /// value or a sealed copy. Its own call for the same reason as
    /// [`FfiApp::answer`]
    pub fn answer_program(&self, id: String, entered: HashMap<u32, String>) {
        let entered = entered
            .into_iter()
            .map(|(index, value)| (index, Secret(value)))
            .collect();
        if let Err(error) = self.actor.cast(AppMsg::AnswerProgram { id, entered }) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Sends every later [`Update`] to `reconciler`, replacing the last one
    pub fn listen_for_updates(&self, reconciler: Box<dyn Reconciler>) {
        self.shared.listen(reconciler);
    }
}

impl FfiApp {
    /// Starts the core on the current tokio runtime, for tests
    pub async fn start(platform: Arc<dyn Platform>) -> Result<Arc<Self>, ractor::SpawnErr> {
        let record = GatewayRecord::load(platform.as_ref());
        let shared = Arc::new(Shared::new(record.as_ref()));
        let args = AppArgs {
            platform,
            shared: Arc::clone(&shared),
            record,
        };
        let (actor, _) = Actor::spawn(None, App, args).await?;

        Ok(Arc::new(Self { actor, shared }))
    }
}

impl Drop for FfiApp {
    fn drop(&mut self) {
        self.actor.stop(None);
    }
}
