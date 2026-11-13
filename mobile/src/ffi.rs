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

use companion_wire::{
    mobile::LoginField as WireLoginField,
    takeover::{PhoneMessage, Secret as WireSecret},
    wire::ProgramValue,
};
use ractor::{Actor, ActorRef};

use crate::{
    app::{App, AppArgs, AppMsg, Shared},
    record::GatewayRecord,
    request::{Entered, Secret},
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
    /// Handoffs asked of this phone, newest last, including finished ones
    /// until they are dismissed
    pub handoffs: Vec<PendingHandoff>,
    /// The browser session the owner has taken over, if any; its images
    /// arrive as [`Update::Screen`] and are not kept here
    pub takeover: Option<TakeoverState>,
    /// The browser sessions of the gateway and of the machines it vouches
    /// for, as last listed
    pub sessions: BrowserSessions,
}

/// The browser sessions the owner takes over or starts: the gateway's, and
/// each machine's the gateway lists, which the phone dials itself
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct BrowserSessions {
    /// Where the gateway's listing stands
    pub status: SessionsStatus,
    /// The gateway's sessions running, by name, from the last listing
    pub running: Vec<BrowserSession>,
    /// The gateway's sessions with a saved profile that are not running,
    /// which [`AppAction::StartSession`] launches signed in as before
    pub saved: Vec<SavedSession>,
    /// The other machines with browser sessions, by name, each listed on
    /// its own link; empty until the gateway lists them
    pub machines: Vec<MachineSessions>,
}

/// Where a browser session runs
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum SessionHost {
    /// The paired gateway
    Gateway,
    /// A machine the gateway vouches for, such as a Linux spoke
    Machine {
        /// The name the gateway lists it under, such as `code`
        name: String,
    },
}

/// One machine's browser sessions, in a section of their own
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MachineSessions {
    /// The name the gateway lists it under, such as `code`
    pub name: String,
    /// Where its listing stands; [`SessionsStatus::Unreachable`] when the
    /// phone could not dial it
    pub status: SessionsStatus,
    /// Its sessions running, by name
    pub running: Vec<BrowserSession>,
    /// Its sessions with a saved profile that are not running
    pub saved: Vec<SavedSession>,
}

/// Where a listing of the browser sessions stands
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Enum)]
pub enum SessionsStatus {
    /// Never listed
    #[default]
    Idle,
    /// Asking the gateway; the last listing still shows
    Loading,
    /// Listed
    Listed,
    /// The machine answered but could not list them
    Failed {
        /// Why, one line
        message: String,
    },
    /// The phone could not dial the machine in time
    Unreachable {
        /// Why, one line
        message: String,
    },
}

/// A browser session running on the gateway Mac
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserSession {
    /// Its name, such as `github`
    pub name: String,
    /// The address of its active tab, when the gateway could read it
    pub url: Option<String>,
    /// The title of its active tab, when the gateway could read it
    pub title: Option<String>,
}

/// A browser session on the gateway Mac that is not running but has a saved
/// profile
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SavedSession {
    /// Its name, such as `discord`
    pub name: String,
    /// The `https` page it was last on, where tapping it starts it again;
    /// `None` when the gateway does not know, so the owner gives an address
    pub last_page: Option<String>,
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

/// A value the owner entered for one item of a program read; no `Debug`, so
/// it never reaches a log
#[derive(uniffi::Enum)]
pub enum EnteredValue {
    /// Text pasted or filled in with AutoFill
    Text {
        /// The value
        value: String,
    },
    /// A file shared from 1Password, such as a `.p12`
    File {
        /// Its bytes, at most [`max_file_bytes`]
        bytes: Vec<u8>,
    },
}

/// Most bytes a shared file may hold: it goes to the gateway base64 encoded,
/// a third larger, in an answer of at most [`companion_wire::MAX_BODY_BYTES`]
pub const MAX_FILE_BYTES: u32 = 44 * 1024;

/// [`MAX_FILE_BYTES`], for the app to refuse a larger file before sending
#[uniffi::export]
pub fn max_file_bytes() -> u32 {
    MAX_FILE_BYTES
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
    /// Set when the values sign in to a website in the gateway's browser
    pub sign_in: Option<SignIn>,
}

/// The website a program read signs in to, cleaned to one line like the
/// rest of the prompt
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignIn {
    /// The site and account as the prompt names them, such as
    /// `github.com · praveenperera`
    pub title: String,
    /// The site, such as `github.com`
    pub site: String,
    /// The account, when the gateway knows it
    pub account: Option<String>,
    /// The browser session the values go to, such as `github`
    pub session: Option<String>,
}

/// Which login field a value goes into, so the app offers the matching
/// AutoFill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum LoginField {
    /// A username or email address
    Username,
    /// A password
    Password,
    /// A one-time code
    Code,
}

impl From<WireLoginField> for LoginField {
    fn from(field: WireLoginField) -> Self {
        match field {
            WireLoginField::Username => Self::Username,
            WireLoginField::Password => Self::Password,
            WireLoginField::Code => Self::Code,
        }
    }
}

impl From<LoginField> for WireLoginField {
    fn from(field: LoginField) -> Self {
        match field {
            LoginField::Username => Self::Username,
            LoginField::Password => Self::Password,
            LoginField::Code => Self::Code,
        }
    }
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
        /// The login field it goes into, for a sign-in
        field: Option<LoginField>,
    },
    /// Only the program's description of the item; the owner picks it in
    /// 1Password and enters the value
    Describe {
        /// The description
        description: String,
        /// The login field it goes into, for a sign-in
        field: Option<LoginField>,
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

/// A handoff the gateway asked this phone for: an agent wants the owner to
/// do a step in a browser session, such as a passkey or a captcha
///
/// Every text here is cleaned to one line, as a [`ProgramRead`]'s is
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingHandoff {
    /// The id the push named, which a takeover opens with
    pub id: String,
    /// The browser session, such as `github`
    pub session: String,
    /// What the agent needs done, in its own words; a claim to show quoted
    pub reason: Option<String>,
    /// The page the session shows, when the gateway could read it
    pub url: Option<String>,
    /// The gateway Mac's short name
    pub gateway_name: String,
    /// Where the session runs, which a takeover for it dials
    pub host: SessionHost,
    /// When the gateway gives up, in ms since the epoch on this phone's clock
    pub expires_at_ms: i64,
    /// Where it stands
    pub status: HandoffStatus,
}

/// Where one handoff stands
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum HandoffStatus {
    /// Waiting for the owner to take over or cancel
    Waiting,
    /// The owner cancelled it here
    Cancelled,
    /// The gateway gave up waiting
    Expired,
    /// It ended elsewhere: a takeover finished it, another phone answered,
    /// or the agent stopped waiting
    Over,
}

impl HandoffStatus {
    /// Whether nothing more happens to the handoff
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::Waiting)
    }
}

/// The browser session the owner has taken over
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TakeoverState {
    /// The browser session, such as `github`
    pub session: String,
    /// Where it runs
    pub host: SessionHost,
    /// The handoff it answers, if it was opened for one
    pub handoff: Option<String>,
    /// The link to the session
    pub status: TakeoverStatus,
    /// The page and its focused element, once the gateway has said
    pub page: Option<TakeoverPage>,
    /// The last thing the gateway refused or filled, until the page changes
    pub notice: Option<TakeoverNotice>,
}

/// The link of a takeover
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TakeoverStatus {
    /// Waiting for the screen's size, or dialing
    Connecting,
    /// The page is live
    Live,
    /// The link dropped or a dial failed; the next starts after `in_secs`
    Retrying {
        /// Seconds to the next dial
        in_secs: u32,
        /// Why
        error: String,
    },
    /// The app is in the background; it dials again in the foreground
    Paused,
    /// The gateway ended it
    Ended {
        /// Why
        reason: TakeoverEnd,
        /// More detail, such as why the browser could not be reached
        message: Option<String>,
    },
}

/// Why a takeover ended
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TakeoverEnd {
    /// The owner tapped Done
    Done,
    /// The owner tapped Cancel
    Cancelled,
    /// Its handoff ended elsewhere: another phone answered, the agent
    /// stopped waiting, or it expired
    HandoffOver,
    /// The browser session closed or could not be reached
    BrowserGone,
    /// The gateway is stopping
    Shutdown,
    /// The phone could not keep it going
    Failed,
}

/// The page of a takeover
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TakeoverPage {
    /// The address of the top-level page
    pub url: String,
    /// The page's title
    pub title: String,
    /// The element with keyboard focus, when it takes text
    pub focus: Option<TakeoverFocus>,
    /// Login values this phone can fill from sealed copies
    pub offers: Vec<FillOffer>,
}

/// The element with keyboard focus on a taken-over page
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TakeoverFocus {
    /// The login field it looks like, if any
    pub field: Option<LoginField>,
    /// Whether it takes text, so the app raises the keyboard
    pub editable: bool,
    /// Whether it hides its text, as a password field does
    pub secure: bool,
    /// Whether it asks for digits, so the app shows the number pad
    pub numeric: bool,
    /// Origin of the frame holding it
    pub origin: String,
    /// Whether that frame is on another site than the page
    pub cross_site: bool,
}

/// A login value the gateway sent a sealed copy of for a taken-over page;
/// [`TakeoverInput::FillOffer`] opens it with Face ID and fills it
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FillOffer {
    /// The field it fills
    pub field: LoginField,
    /// The `op://` reference
    pub reference: String,
    /// The 1Password item
    pub item: String,
    /// The account, such as the login's username
    pub account: Option<String>,
}

/// What the gateway last said about the owner's input
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TakeoverNotice {
    /// Something was not done; the takeover goes on
    Refused {
        /// Why, never holding a value
        message: String,
    },
    /// A value went into this field
    Filled {
        /// The field
        field: LoginField,
    },
}

/// One image of a taken-over page
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct ScreenImage {
    /// Counts up within one link; [`TakeoverInput::Drawn`] and taps name it
    pub seq: u32,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// The JPEG image
    pub jpeg: Vec<u8>,
}

impl std::fmt::Debug for ScreenImage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScreenImage")
            .field("seq", &self.seq)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("jpeg", &self.jpeg.len())
            .finish()
    }
}

/// A key on the takeover's key bar
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TakeoverKey {
    /// Return
    Enter,
    /// Tab
    Tab,
    /// Delete the character before the caret
    Backspace,
    /// Escape
    Escape,
}

/// What the owner does on a takeover, besides typing and filling (see
/// [`FfiApp::takeover_text`] and [`FfiApp::takeover_fill`]); points are
/// fractions of the image, from 0 at the top left to 1 at the bottom right
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum TakeoverInput {
    /// The image area's size changed, or it first appeared; the takeover
    /// dials once it knows it
    Resize {
        /// Width in points
        width: u32,
        /// Height in points
        height: u32,
        /// Pixels per point
        scale: f64,
    },
    /// Image `seq` is on screen, so the gateway may send the next
    Drawn {
        /// The image
        seq: u32,
    },
    /// A tap on image `seq`
    Tap {
        /// From the left
        x: f64,
        /// From the top
        y: f64,
        /// The image
        seq: u32,
    },
    /// A long press on image `seq`
    LongPress {
        /// From the left
        x: f64,
        /// From the top
        y: f64,
        /// The image
        seq: u32,
    },
    /// Scroll the page under the point by `dx` and `dy`, as fractions of
    /// the image; positive scrolls right and down
    Scroll {
        /// From the left
        x: f64,
        /// From the top
        y: f64,
        /// Horizontal distance
        dx: f64,
        /// Vertical distance
        dy: f64,
        /// The image
        seq: u32,
    },
    /// A key from the key bar
    Key {
        /// Which
        key: TakeoverKey,
    },
    /// Back in the session's history
    Back,
    /// Load the page again
    Reload,
    /// Load `url`, an `https` address, in the page
    Go {
        /// The address
        url: String,
    },
    /// Open the offer for `reference` with Face ID and fill it
    FillOffer {
        /// The offer's reference
        reference: String,
    },
    /// The owner finished: ends the takeover and its handoff as done
    Done,
    /// The owner gave up: ends the takeover and its handoff as cancelled
    Cancel,
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
    /// Refuse the handoff `id`
    CancelHandoff {
        /// The handoff
        id: String,
    },
    /// Take over browser `session`, for handoff `handoff` if set: from the
    /// handoff's Take over, its push, or a `codemode-companion://takeover`
    /// link. Replaces any takeover already open
    OpenTakeover {
        /// The browser session
        session: String,
        /// The handoff it answers
        handoff: Option<String>,
        /// Where the session runs; a machine the phone has not heard of yet
        /// is looked up in a new listing first
        host: SessionHost,
    },
    /// Start browser `session` at `url`, an `https` address, and take it
    /// over: the gateway launches the session with its saved profile when it
    /// is not running, or loads `url` in it when it is. Replaces any
    /// takeover already open
    StartSession {
        /// The browser session, new or saved
        session: String,
        /// Where to start it
        url: String,
        /// The machine to start it on
        host: SessionHost,
    },
    /// Leave the takeover without ending it or its handoff, which may be
    /// taken over again later; also closes one the gateway ended
    CloseTakeover,
    /// Ask the gateway for its browser sessions, then each machine it lists
    /// for its own
    RefreshSessions,
    /// Quit browser `session` on `host`, keeping its saved profile, then
    /// list that machine's sessions again; a takeover of it is left
    CloseSession {
        /// The browser session
        session: String,
        /// Where it runs
        host: SessionHost,
    },
    /// Move the saved profile of browser `session`, which is not running,
    /// to the Trash of `host`, then list that machine's sessions again
    RemoveSession {
        /// The browser session
        session: String,
        /// Where it runs
        host: SessionHost,
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
    /// The handoffs changed
    Handoffs(Vec<PendingHandoff>),
    /// The takeover changed, or ended with `None`
    Takeover(Option<TakeoverState>),
    /// The browser sessions changed
    Sessions(BrowserSessions),
    /// A new image of the taken-over page; the app reports it drawn with
    /// [`TakeoverInput::Drawn`]
    Screen(ScreenImage),
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

/// Where an opened value goes, which the Face ID prompt names
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum OpenDestination {
    /// codemode-mcp on the gateway, which asked to read it
    Gateway {
        /// The gateway's name
        name: String,
    },
    /// The focused field of a taken-over page, on the machine the session
    /// runs on: the gateway or one it vouches for
    Page {
        /// The browser session
        session: String,
        /// The machine's name
        machine: String,
    },
}

/// Everything Face ID needs to open one value: the reason it shows, and the
/// HPKE pieces. `info` binds the reference and the gateway that sealed it,
/// so the value opens only for an offer of that gateway's
#[derive(Clone, uniffi::Record)]
pub struct OpenRequest {
    /// The read, so [`Platform::cancel_open`] can name it
    pub id: String,
    /// The reference the prompt names
    pub reference: String,
    /// Where the value goes, which the prompt names; for a page on a spoke
    /// that is the spoke, though the gateway sealed it
    pub destination: OpenDestination,
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
    /// pasted, filled in or shared from 1Password keyed by item index, and
    /// opens every other item with one Face ID. Nothing is sent unless each
    /// item has an entered value or a sealed copy. Its own call for the same
    /// reason as [`FfiApp::answer`]
    pub fn answer_program(&self, id: String, entered: HashMap<u32, EnteredValue>) {
        let entered = entered
            .into_iter()
            .map(|(index, value)| {
                let value = match value {
                    EnteredValue::Text { value } => ProgramValue::from(value),
                    EnteredValue::File { bytes } => ProgramValue::from(bytes),
                };

                (index, Entered(value))
            })
            .collect();
        if let Err(error) = self.actor.cast(AppMsg::AnswerProgram { id, entered }) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Sends what the owner does on the takeover
    pub fn takeover(&self, input: TakeoverInput) {
        if let Err(error) = self.actor.cast(AppMsg::Takeover(input)) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Types `text` into the taken-over page's focused element; its own
    /// call, as [`FfiApp::answer`] is, so the text never sits in a type
    /// that derives `Debug`
    pub fn takeover_text(&self, text: String) {
        let message = PhoneMessage::Text {
            text: WireSecret::new(text),
        };
        if let Err(error) = self.actor.cast(AppMsg::TakeoverSend(message)) {
            tracing::error!(%error, "the app actor is gone");
        }
    }

    /// Fills `value`, typed or from AutoFill, into the taken-over page's
    /// focused `field`, replacing what it holds, and presses Return after
    /// it with `submit`
    pub fn takeover_fill(&self, field: LoginField, value: String, submit: bool) {
        let message = PhoneMessage::Fill {
            field: field.into(),
            value: WireSecret::new(value),
            submit,
            // typed or picked by the owner while they watch the page
            site: None,
        };
        if let Err(error) = self.actor.cast(AppMsg::TakeoverSend(message)) {
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
