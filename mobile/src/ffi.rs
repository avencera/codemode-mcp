//! What Swift sees: the one root object, the state it renders, the actions
//! it sends and the platform calls it answers
//!
//! The UI never changes state itself. It sends an [`AppAction`] through
//! [`FfiApp::dispatch`] and renders what comes back through its
//! [`Reconciler`]

use std::sync::{Arc, OnceLock};

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
    /// The references this phone answers without asking first, matched
    /// exactly: the gateway's at pairing, plus each one the owner allowed
    pub allow: Vec<String>,
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
    /// The `op://` reference
    pub reference: String,
    /// The gateway Mac's short name
    pub gateway_name: String,
    /// When the gateway gives up, in ms since the epoch on this phone's clock
    pub expires_at_ms: i64,
    /// Whether the gateway sent a copy Face ID can open; without one the
    /// owner enters the value
    pub sealed: bool,
    /// Whether the reference is on the allow list; one that is not can be
    /// answered only once the owner allows it
    pub listed: bool,
    /// Where it stands
    pub status: ReadStatus,
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
    /// Add the read's reference to the allow list, so it can be answered
    /// now and is not asked about again
    Allow {
        /// The read
        id: String,
    },
    /// Take `reference` off the allow list, so a later read of it waits
    /// for the owner to allow it again
    Disallow {
        /// The reference, as the allow list shows it
        reference: String,
    },
    /// Open the read's value with Face ID and send it
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
    /// The owner cancelled Face ID, or it was taken down
    #[error("not approved on this phone")]
    Denied,
    /// The key is gone or the ciphertext does not open
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
