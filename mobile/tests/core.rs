//! The core's actors against an in-process gateway endpoint
//!
//! The fake gateway speaks the real pairing and phone protocols from
//! `companion-wire`; the fake platform holds the Keychain in memory and opens
//! seals with a software key where the app uses the Secure Enclave

use std::{
    collections::HashMap,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use companion_core::ffi::{
    AppAction, AppState, BrowserSession, ConnectionState, EnteredValue, FfiApp, HandoffStatus,
    LoginField, OpenBatch, OpenDestination, OpenError, OpenRequest, PairingState, PendingRead,
    Platform, PlatformError, ProgramItem as ShownItem, PushEnvironment, ReadStatus, Reconciler,
    SavedSession, ScreenImage, SessionHost, SessionsStatus, TakeoverInput, TakeoverNotice,
    TakeoverStatus, Update,
};
use companion_wire::{
    MAX_BODY_BYTES, MOBILE_ALPN, PAIR_ALPN,
    mobile::{
        HandoffAnswer, LoginField as WireField, PhoneHandoff, PhoneHandoffRequest,
        PhoneProgramRead, PhoneProgramRequest, PhoneRead, PhoneRequest, PhoneResponse, ProgramItem,
        PushToken, RequestId, SealKey, Sealed, SignIn,
    },
    seal::{SoftwareKey, seal},
    takeover::{
        BrowserMachine, EndReason, FillOffer, Focus, GatewayMessage, HEADER_BYTES, PhoneMessage,
        Point, RunningSession, Screen, ScreenHeader, Secret as WireSecret, TAKEOVER_ALPN, Viewport,
        decode_phone, encode_message, encode_screen, read_header,
    },
    ticket::{InviteSecret, InviteTicket},
    totp::Totp,
    wire::{
        CompanionErrorCode, CompanionResponse, PairCheck, PairRequest, PairResponse, ProgramValue,
        Registered,
    },
};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::sync::{mpsc, watch};

type TestResult = Result<(), Box<dyn Error>>;

/// Text the owner entered for a program read, by item index
fn typed(values: &[(u32, &str)]) -> HashMap<u32, EnteredValue> {
    values
        .iter()
        .map(|(index, value)| {
            (
                *index,
                EnteredValue::Text {
                    value: (*value).to_owned(),
                },
            )
        })
        .collect()
}

/// A program read's answer of text values
fn texts(values: &[&str]) -> CompanionResponse {
    CompanionResponse::Values(
        values
            .iter()
            .map(|value| ProgramValue::from((*value).to_owned()))
            .collect(),
    )
}

const REFERENCE: &str = "op://Dev/fixture/credential";
const VALUE: &str = "value-from-1password";
const TOKEN: &str = "abcdef0123456789";

/// How Face ID answers
#[derive(Clone, Copy, PartialEq, Eq)]
enum FaceId {
    Approve,
    /// The owner taps Deny
    Cancel,
    /// iOS takes the prompt down, as for a call or the app leaving the
    /// screen
    Interrupted,
    /// Stays up until the core takes it down
    Hold,
}

/// The app's side: an in-memory Keychain and a software seal key
struct FakePlatform {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    seal: Mutex<Option<SoftwareKey>>,
    face_id: Mutex<FaceId>,
    /// The reference and destination each prompt named
    prompts: Mutex<Vec<(String, OpenDestination)>>,
    /// The references, value count and gateway each program read's prompt
    /// named
    batch_prompts: Mutex<Vec<(Vec<String>, u32, String)>>,
    /// Reads whose prompt the core took down
    cancelled: Mutex<Vec<String>>,
    released: Condvar,
}

impl FakePlatform {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            secrets: Mutex::new(HashMap::new()),
            seal: Mutex::new(None),
            face_id: Mutex::new(FaceId::Approve),
            prompts: Mutex::new(Vec::new()),
            batch_prompts: Mutex::new(Vec::new()),
            cancelled: Mutex::new(Vec::new()),
            released: Condvar::new(),
        })
    }

    fn set_face_id(&self, face_id: FaceId) {
        if let Ok(mut slot) = self.face_id.lock() {
            *slot = face_id;
        }
    }

    fn prompts(&self) -> Vec<(String, OpenDestination)> {
        self.prompts.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn batch_prompts(&self) -> Vec<(Vec<String>, u32, String)> {
        self.batch_prompts
            .lock()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Answers as Face ID is set to; `Ok` when the value may be opened
    fn face_id(&self, id: &str) -> Result<(), OpenError> {
        let face_id = self
            .face_id
            .lock()
            .map_or(FaceId::Cancel, |face_id| *face_id);
        match face_id {
            FaceId::Approve => Ok(()),
            FaceId::Cancel => Err(OpenError::Denied),
            FaceId::Interrupted => Err(OpenError::Failed {
                message: "Face ID was interrupted".to_owned(),
            }),
            FaceId::Hold => {
                let Ok(cancelled) = self.cancelled.lock() else {
                    return Err(OpenError::Denied);
                };
                let _ = self.released.wait_timeout_while(
                    cancelled,
                    Duration::from_secs(10),
                    |cancelled| !cancelled.iter().any(|cancelled| cancelled == id),
                );

                Err(OpenError::Denied)
            }
        }
    }

    /// Opens one value with the software seal key
    fn open(&self, info: &[u8], enc: &[u8], ciphertext: &[u8]) -> Result<String, OpenError> {
        let seal = self.seal.lock().map_err(|_| OpenError::Denied)?;
        let key = seal.as_ref().ok_or(OpenError::Failed {
            message: "no seal key".to_owned(),
        })?;
        let value =
            key.open_with_info(info, enc, ciphertext)
                .map_err(|error| OpenError::Failed {
                    message: error.to_string(),
                })?;

        String::from_utf8(value).map_err(|error| OpenError::Failed {
            message: error.to_string(),
        })
    }

    fn cancelled(&self) -> Vec<String> {
        self.cancelled.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn keychain_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .secrets
            .lock()
            .map(|secrets| secrets.keys().cloned().collect())
            .unwrap_or_default();
        keys.sort();

        keys
    }

    fn public_seal_key(&self) -> Option<SealKey> {
        self.seal
            .lock()
            .ok()
            .and_then(|key| key.as_ref().map(|key| key.public().clone()))
    }
}

/// Lets the tests keep their own handle on the platform they hand over
struct Shared(Arc<FakePlatform>);

impl Platform for Shared {
    fn load_secret(&self, key: String) -> Option<Vec<u8>> {
        self.0.secrets.lock().ok()?.get(&key).cloned()
    }

    fn save_secret(&self, key: String, value: Vec<u8>) -> Result<(), PlatformError> {
        if let Ok(mut secrets) = self.0.secrets.lock() {
            secrets.insert(key, value);
        }

        Ok(())
    }

    fn delete_secret(&self, key: String) {
        if let Ok(mut secrets) = self.0.secrets.lock() {
            secrets.remove(&key);
        }
    }

    fn create_seal_key(&self) -> Result<Vec<u8>, PlatformError> {
        let key = SoftwareKey::generate().map_err(|error| PlatformError::Failed {
            message: error.to_string(),
        })?;
        let public = key.public().as_bytes().to_vec();
        if let Ok(mut slot) = self.0.seal.lock() {
            *slot = Some(key);
        }

        Ok(public)
    }

    fn delete_seal_key(&self) {
        if let Ok(mut slot) = self.0.seal.lock() {
            *slot = None;
        }
    }

    fn open_sealed(&self, request: OpenRequest) -> Result<String, OpenError> {
        if let Ok(mut prompts) = self.0.prompts.lock() {
            prompts.push((request.reference.clone(), request.destination.clone()));
        }
        self.0.face_id(&request.id)?;

        self.0
            .open(&request.info, &request.enc, &request.ciphertext)
    }

    fn open_sealed_batch(&self, batch: OpenBatch) -> Result<Vec<String>, OpenError> {
        if let Ok(mut prompts) = self.0.batch_prompts.lock() {
            let references = batch
                .items
                .iter()
                .map(|item| item.reference.clone())
                .collect();
            prompts.push((references, batch.total, batch.gateway_name.clone()));
        }
        self.0.face_id(&batch.id)?;

        batch
            .items
            .iter()
            .map(|item| self.0.open(&item.info, &item.enc, &item.ciphertext))
            .collect()
    }

    fn cancel_open(&self, id: String) {
        if let Ok(mut cancelled) = self.0.cancelled.lock() {
            cancelled.push(id);
        }
        self.0.released.notify_all();
    }

    fn device_name(&self) -> String {
        "iPhone".to_owned()
    }
}

/// Records every update, to show they arrive
#[derive(Default)]
struct Recorder(Mutex<Vec<Update>>);

/// The handle the core holds
struct Recording(Arc<Recorder>);

impl Reconciler for Recording {
    fn reconcile(&self, update: Update) {
        if let Ok(mut updates) = self.0.0.lock() {
            updates.push(update);
        }
    }
}

/// The gateway's side, in this process
#[derive(Clone)]
struct FakeGateway {
    endpoint: Endpoint,
    address: SocketAddr,
    secret: Arc<InviteSecret>,
    /// The phone's seal key once it registered
    seal_key: Arc<Mutex<Option<SealKey>>>,
    /// The phone's live mobile connection
    link: watch::Sender<Option<Connection>>,
    /// What the phone asked of its own
    requests: Arc<Mutex<Vec<PhoneRequest>>>,
    /// The references the gateway names at pairing, which the phone no
    /// longer keeps
    references: Vec<String>,
    /// Takeover connections the phone dialed, in order
    takeover_sender: mpsc::UnboundedSender<Connection>,
    takeovers: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Connection>>>,
}

impl FakeGateway {
    async fn start() -> Result<Self, Box<dyn Error>> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(iroh::SecretKey::generate())
            .alpns(vec![
                PAIR_ALPN.to_vec(),
                MOBILE_ALPN.to_vec(),
                TAKEOVER_ALPN.to_vec(),
            ])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await?;
        let address = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .ok_or("no IPv4 socket")?;
        let (takeover_sender, takeovers) = mpsc::unbounded_channel();
        let gateway = Self {
            endpoint,
            address,
            secret: Arc::new(InviteSecret::generate()),
            seal_key: Arc::new(Mutex::new(None)),
            link: watch::channel(None).0,
            requests: Arc::new(Mutex::new(Vec::new())),
            references: vec![REFERENCE.to_owned()],
            takeover_sender,
            takeovers: Arc::new(tokio::sync::Mutex::new(takeovers)),
        };

        let accepting = gateway.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.endpoint.accept().await {
                let gateway = accepting.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    if connection.alpn() == PAIR_ALPN {
                        gateway.pairing(connection).await;
                    } else if connection.alpn() == TAKEOVER_ALPN {
                        let _ = gateway.takeover_sender.send(connection);
                    } else {
                        gateway.mobile(connection).await;
                    }
                });
            }
        });

        Ok(gateway)
    }

    fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// The install command `companion invite` prints, as the QR code holds it
    fn invite(&self) -> String {
        let ticket = InviteTicket {
            gateway: self.id(),
            secret: (*self.secret).clone(),
            addrs: vec![self.address],
        };

        format!(
            "curl -LSfs https://github.com/x/codemode-mcp/releases/latest/download/install.sh | sh -s -- --pair {}",
            ticket.encode()
        )
    }

    fn requests(&self) -> Vec<PhoneRequest> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }

    async fn pairing(&self, connection: Connection) {
        let Ok((mut send, mut receive)) = connection.accept_bi().await else {
            return;
        };
        let Ok(body) = receive.read_to_end(MAX_BODY_BYTES).await else {
            return;
        };
        let Ok(PairRequest::Register(registration)) = serde_json::from_slice(&body) else {
            return;
        };
        let accepted = registration.secret == self.secret.to_hex()
            && registration.id == connection.remote_id();
        let response = match (&registration.phone, accepted) {
            (Some(phone), true) => {
                if let Ok(mut slot) = self.seal_key.lock() {
                    *slot = Some(phone.seal_key.clone());
                }
                if let (Some(push), Ok(mut requests)) = (&phone.push, self.requests.lock()) {
                    requests.push(PhoneRequest::PushToken(Some(push.clone())));
                }
                PairResponse::Registered(Registered {
                    gateway_name: "mini".to_owned(),
                    name: registration.name.clone(),
                    references: self.references.clone(),
                    already_listed: false,
                })
            }
            _ => PairResponse::Refused {
                message: "bad registration".to_owned(),
            },
        };
        let _ = respond(&mut send, &response).await;

        // the check: one read through the phone
        let Ok((mut send, mut receive)) = connection.accept_bi().await else {
            return;
        };
        let Ok(body) = receive.read_to_end(MAX_BODY_BYTES).await else {
            return;
        };
        if !matches!(serde_json::from_slice(&body), Ok(PairRequest::Check)) {
            return;
        }
        let check = match self.read(REFERENCE, 30_000).await {
            Ok(CompanionResponse::Value(value)) => PairCheck::Read {
                reference: REFERENCE.to_owned(),
                bytes: value.len(),
            },
            Ok(CompanionResponse::Error(fault)) => PairCheck::Failed {
                reference: REFERENCE.to_owned(),
                message: fault.message,
            },
            Ok(CompanionResponse::Values(_)) => PairCheck::Failed {
                reference: REFERENCE.to_owned(),
                message: "values answered a single read".to_owned(),
            },
            Err(error) => PairCheck::Failed {
                reference: REFERENCE.to_owned(),
                message: error,
            },
        };
        let _ = respond(&mut send, &PairResponse::Checked(check)).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
    }

    async fn mobile(&self, connection: Connection) {
        self.link.send_replace(Some(connection.clone()));
        while let Ok((mut send, mut receive)) = connection.accept_bi().await {
            let Ok(body) = receive.read_to_end(MAX_BODY_BYTES).await else {
                return;
            };
            let Ok(request) = serde_json::from_slice::<PhoneRequest>(&body) else {
                return;
            };
            if let Ok(mut requests) = self.requests.lock() {
                requests.push(request);
            }
            let _ = respond(&mut send, &PhoneResponse::Done).await;
        }
    }

    /// `value` sealed to the phone under `reference`, as the gateway keeps it
    fn seal(&self, reference: &str, value: &str) -> Result<Sealed, String> {
        let key = self
            .seal_key
            .lock()
            .ok()
            .and_then(|key| key.clone())
            .ok_or("no phone registered")?;

        seal(&key, &self.id(), reference, value.as_bytes()).map_err(|error| error.to_string())
    }

    /// Reads `reference` through the phone with a copy sealed to it, as the
    /// gateway's race does
    async fn read(&self, reference: &str, expires_in_ms: u64) -> Result<CompanionResponse, String> {
        let sealed = self.seal(reference, VALUE)?;

        self.offer(reference, Some(sealed), expires_in_ms).await
    }

    /// Sends one read over the phone's link and waits for its answer
    async fn offer(
        &self,
        reference: &str,
        sealed: Option<Sealed>,
        expires_in_ms: u64,
    ) -> Result<CompanionResponse, String> {
        self.offer_as(RequestId::generate(), reference, sealed, expires_in_ms)
            .await
    }

    /// [`Self::offer`] under a chosen request id, as a push names it or a
    /// re-offer after a dropped link repeats it
    async fn offer_as(
        &self,
        id: RequestId,
        reference: &str,
        sealed: Option<Sealed>,
        expires_in_ms: u64,
    ) -> Result<CompanionResponse, String> {
        let read = PhoneRead {
            id,
            reference: reference.to_owned(),
            sealed,
            expires_in_ms,
        };

        self.ask(&read).await
    }

    /// Sends a program's batch over the phone's link, as `codemode-mcp op
    /// read` asks for it, and waits for the answer
    async fn offer_program(
        &self,
        id: RequestId,
        items: Vec<ProgramItem>,
        reason: Option<&str>,
    ) -> Result<CompanionResponse, String> {
        self.offer_program_read(PhoneProgramRead {
            id,
            items,
            reason: reason.map(str::to_owned),
            destination: None,
            keep_secs: None,
            sign_in: None,
            expires_in_ms: 30_000,
        })
        .await
    }

    /// [`Self::offer_program`] with every field chosen
    async fn offer_program_read(
        &self,
        program_read: PhoneProgramRead,
    ) -> Result<CompanionResponse, String> {
        self.ask(&PhoneProgramRequest { program_read }).await
    }

    /// Offers a handoff over the phone's link, as `browser.handoff` does,
    /// and waits for the phone's answer on its stream
    async fn offer_handoff(&self, handoff: PhoneHandoff) -> Result<HandoffAnswer, String> {
        self.ask(&PhoneHandoffRequest { handoff }).await
    }

    /// The next takeover the phone dials, with the stream it opens on it
    async fn next_takeover(&self) -> Result<(Connection, SendStream, RecvStream), Box<dyn Error>> {
        let mut takeovers = self.takeovers.lock().await;
        let connection = tokio::time::timeout(Duration::from_secs(10), takeovers.recv())
            .await?
            .ok_or("the gateway stopped")?;
        let (send, receive) = connection.accept_bi().await?;

        Ok((connection, send, receive))
    }

    /// Opens a stream on the phone's link, sends `request` and waits for
    /// the answer
    async fn ask<R: serde::de::DeserializeOwned>(
        &self,
        request: &impl serde::Serialize,
    ) -> Result<R, String> {
        let connection = self
            .link
            .subscribe()
            .wait_for(Option::is_some)
            .await
            .map_err(|error| error.to_string())?
            .clone()
            .ok_or("no link")?;
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| error.to_string())?;
        send.write_all(&serde_json::to_vec(request).map_err(|error| error.to_string())?)
            .await
            .map_err(|error| error.to_string())?;
        send.finish().map_err(|error| error.to_string())?;
        let body = receive
            .read_to_end(MAX_BODY_BYTES)
            .await
            .map_err(|error| error.to_string())?;

        serde_json::from_slice(&body).map_err(|error| error.to_string())
    }

    /// Hangs up on the phone, as a gateway restart does
    fn drop_link(&self) {
        if let Some(connection) = self.link.send_replace(None) {
            connection.close(0_u32.into(), b"restart");
        }
    }
}

async fn respond(
    send: &mut iroh::endpoint::SendStream,
    response: &impl serde::Serialize,
) -> TestResult {
    send.write_all(&serde_json::to_vec(response)?).await?;
    send.finish()?;

    Ok(())
}

/// Waits up to ten seconds for the app's state to satisfy `ready`
async fn until(
    app: &FfiApp,
    ready: impl Fn(&AppState) -> bool,
) -> Result<AppState, Box<dyn Error>> {
    for _ in 0..200 {
        let state = app.state();
        if ready(&state) {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Err(format!("the state never got there: {:?}", app.state()).into())
}

fn waiting(state: &AppState) -> Option<String> {
    state
        .reads
        .iter()
        .find(|read| read.status == ReadStatus::Waiting)
        .map(|read| read.id.clone())
}

/// A phone paired with `gateway`, with the pairing's check approved
async fn paired(
    gateway: &FakeGateway,
) -> Result<(Arc<FfiApp>, Arc<FakePlatform>, Arc<Recorder>), Box<dyn Error>> {
    let platform = FakePlatform::new();
    let app = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    let recorder = Arc::new(Recorder::default());
    app.listen_for_updates(Box::new(Recording(Arc::clone(&recorder))));

    app.dispatch(AppAction::PushToken {
        token: Some(TOKEN.to_owned()),
        environment: PushEnvironment::Development,
    });
    app.dispatch(AppAction::Foreground);
    app.dispatch(AppAction::Pair {
        scanned: gateway.invite(),
    });

    // the check arrives as an ordinary read
    let state = until(&app, |state| waiting(state).is_some()).await?;
    assert_eq!(state.pairing, PairingState::Checking);
    assert_eq!(state.connection, ConnectionState::Connected);
    let id = waiting(&state).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id });
    until(&app, |state| {
        matches!(state.pairing, PairingState::Done { .. })
    })
    .await?;

    Ok((app, platform, recorder))
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_registers_the_phone_and_its_check_is_approved_with_face_id() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, recorder) = paired(&gateway).await?;

    let state = app.state();
    let PairingState::Done { message } = &state.pairing else {
        return Err("not done".into());
    };
    assert!(
        message.contains(&format!("{} bytes", VALUE.len())),
        "{message}"
    );
    let gateway_info = state.gateway.ok_or("no gateway")?;
    assert_eq!(gateway_info.name, "mini");

    // Face ID named the reference and the gateway
    assert_eq!(
        platform.prompts(),
        [(
            REFERENCE.to_owned(),
            OpenDestination::Gateway {
                name: "mini".to_owned()
            }
        )]
    );
    // the keys stay on the phone: the gateway only got the public half
    assert_eq!(platform.keychain_keys(), ["gateway", "iroh-key"]);
    assert_eq!(
        *gateway.seal_key.lock().map_err(|_| "poisoned")?,
        platform.public_seal_key()
    );
    // the push token went with the registration, and again once connected
    let token = PhoneRequest::PushToken(Some(PushToken {
        token: TOKEN.to_owned(),
        environment: companion_wire::mobile::PushEnvironment::Development,
    }));
    assert!(
        gateway.requests().contains(&token),
        "{:?}",
        gateway.requests()
    );
    // the UI heard about it
    let updates = recorder.0.lock().map(|u| u.clone()).unwrap_or_default();
    assert!(
        updates
            .iter()
            .any(|update| matches!(update, Update::Pairing(PairingState::Done { .. })))
    );

    // the value is in no state, update or Debug output
    assert!(!format!("{:?}", app.state()).contains(VALUE));
    assert!(!format!("{updates:?}").contains(VALUE));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_or_cancelled_read_sends_no_value() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;

    // Deny without Face ID
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Deny { id: id.clone() });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("a value was sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::Denied);
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Denied)
    })
    .await?;

    // Approve, then cancel Face ID
    platform.set_face_id(FaceId::Cancel);
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("a value was sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::Denied);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entered_value_answers_a_read_with_or_without_a_sealed_copy() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, recorder) = paired(&gateway).await?;
    let entered = "pasted-from-autofill";

    // no copy: Approve has nothing to open, and the entered value goes
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer(REFERENCE, None, 30_000).await }
    });
    let state = until(&app, |state| waiting(state).is_some()).await?;
    let id = waiting(&state).ok_or("no read")?;
    assert!(state.reads.iter().any(|read| read.id == id && !read.sealed));
    app.dispatch(AppAction::Approve { id: id.clone() });
    app.answer(id.clone(), entered.to_owned());
    assert_eq!(
        reading.await??,
        CompanionResponse::Value(entered.to_owned())
    );
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Approved)
    })
    .await?;
    // only the pairing's check asked Face ID
    assert_eq!(platform.prompts().len(), 1);

    // a stale copy: the entered value takes the Face ID prompt down and wins
    platform.set_face_id(FaceId::Hold);
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let state = until(&app, |state| waiting(state).is_some()).await?;
    let id = waiting(&state).ok_or("no read")?;
    assert!(state.reads.iter().any(|read| read.id == id && read.sealed));
    app.dispatch(AppAction::Approve { id: id.clone() });
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Approving)
    })
    .await?;
    app.answer(id.clone(), entered.to_owned());
    assert_eq!(
        reading.await??,
        CompanionResponse::Value(entered.to_owned())
    );
    assert!(platform.cancelled().contains(&id));

    // the entered value is in no state, update or Debug output
    let updates = recorder.0.lock().map(|u| u.clone()).unwrap_or_default();
    assert!(!format!("{:?}{updates:?}", app.state()).contains(entered));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_made_while_the_link_is_down_goes_when_the_read_is_offered_again() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _, _) = paired(&gateway).await?;
    let entered = "entered-offline";
    let id = RequestId::generate();

    let first = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_as(id, REFERENCE, None, 30_000).await }
    });
    until(&app, |state| waiting(state).is_some()).await?;

    // the link drops and the owner answers before the gateway asks again
    gateway.drop_link();
    assert!(first.await?.is_err());
    app.answer(id.to_string(), entered.to_owned());
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id.as_str() && read.status == ReadStatus::Approved)
    })
    .await?;

    let again = gateway.offer_as(id, REFERENCE, None, 30_000).await?;
    assert_eq!(again, CompanionResponse::Value(entered.to_owned()));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_tapped_after_the_read_is_gone_does_not_wait_on_the_gateway() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _, _) = paired(&gateway).await?;
    let status = |id: &RequestId| {
        let state = app.state();
        state
            .reads
            .iter()
            .find(|read| read.id == id.as_str())
            .map(|read| read.status.clone())
    };

    // past the deadline the push carries: expired as soon as it is shown
    let late = RequestId::generate();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    app.dispatch(AppAction::OpenedFromPush {
        id: late.to_string(),
        reference: REFERENCE.to_owned(),
        gateway: "mini".to_owned(),
        expires_at_ms: Some(now - 1_000),
    });
    until(&app, |_| status(&late).is_some()).await?;
    assert_eq!(status(&late), Some(ReadStatus::Expired));

    // within the deadline but answered elsewhere: the gateway never offers
    // it on the link, so it expires soon after, not at the deadline
    let gone = RequestId::generate();
    let started = Instant::now();
    app.dispatch(AppAction::OpenedFromPush {
        id: gone.to_string(),
        reference: REFERENCE.to_owned(),
        gateway: "mini".to_owned(),
        expires_at_ms: Some(now + 60_000),
    });
    until(&app, |_| status(&gone).is_some()).await?;
    assert_eq!(status(&gone), Some(ReadStatus::Connecting));
    until(&app, |_| status(&gone) == Some(ReadStatus::Expired)).await?;
    assert!(started.elapsed() < Duration::from_secs(10));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_drops_does_not_end_the_wait_for_a_pushed_read() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _, _) = paired(&gateway).await?;
    let id = RequestId::generate();
    let status = || {
        let state = app.state();
        state
            .reads
            .iter()
            .find(|read| read.id == id.as_str())
            .map(|read| read.status.clone())
    };

    let started = Instant::now();
    app.dispatch(AppAction::OpenedFromPush {
        id: id.to_string(),
        reference: REFERENCE.to_owned(),
        gateway: "mini".to_owned(),
        expires_at_ms: None,
    });
    until(&app, |_| status().is_some()).await?;

    // the link drops a second in; the phone dials again after its backoff,
    // and the gateway offers the read on that link
    tokio::time::sleep(Duration::from_secs(1)).await;
    gateway.drop_link();
    until(&app, |state| state.connection != ConnectionState::Connected).await?;
    until(&app, |state| state.connection == ConnectionState::Connected).await?;

    // past the first link's wait, the read is still awaited
    tokio::time::sleep(Duration::from_secs(6).saturating_sub(started.elapsed())).await;
    assert_eq!(status(), Some(ReadStatus::Connecting));
    let offered = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_as(id, REFERENCE, None, 30_000).await }
    });
    until(&app, |_| status() == Some(ReadStatus::Waiting)).await?;
    app.dispatch(AppAction::Deny { id: id.to_string() });
    assert!(matches!(offered.await??, CompanionResponse::Error(_)));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_denied_before_it_arrives_is_answered_with_the_denial() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    let prompts = platform.prompts().len();
    let id = RequestId::generate();

    // tapped from the push, denied and dismissed while the read is on its
    // way
    app.dispatch(AppAction::OpenedFromPush {
        id: id.to_string(),
        reference: REFERENCE.to_owned(),
        gateway: "mini".to_owned(),
        expires_at_ms: None,
    });
    app.dispatch(AppAction::Deny { id: id.to_string() });
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id.as_str() && read.status == ReadStatus::Denied)
    })
    .await?;
    app.dispatch(AppAction::Dismiss { id: id.to_string() });
    until(&app, |state| {
        state.reads.iter().all(|read| read.id != id.as_str())
    })
    .await?;

    // and offered again, as after a link that dropped while the denial went
    for _ in 0..2 {
        let response = gateway
            .offer_as(id.clone(), REFERENCE, None, 30_000)
            .await?;
        let CompanionResponse::Error(fault) = response else {
            return Err("a value was sent".into());
        };
        assert_eq!(fault.code, CompanionErrorCode::Denied);
        assert!(waiting(&app.state()).is_none());
    }
    assert_eq!(platform.prompts().len(), prompts);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn turning_notifications_off_clears_the_gateways_token() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    app.dispatch(AppAction::Background);
    until(&app, |state| state.connection == ConnectionState::Offline).await?;
    drop(app);

    // relaunched with notifications off: iOS reports no token, which the
    // gateway must hear even though the phone never had one this launch
    let relaunched = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    relaunched.dispatch(AppAction::PushToken {
        token: None,
        environment: PushEnvironment::Development,
    });
    relaunched.dispatch(AppAction::Foreground);
    for _ in 0..200 {
        if gateway.requests().contains(&PhoneRequest::PushToken(None)) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Err(format!("the gateway never heard: {:?}", gateway.requests()).into())
}

#[tokio::test(flavor = "multi_thread")]
async fn any_reference_is_answered_with_one_approval_and_old_records_still_load() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    let other = "op://Dev/other/credential";
    let prompts = platform.prompts().len();

    // a reference the gateway did not name at pairing opens with Face ID
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(other, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id });
    assert_eq!(reading.await??, CompanionResponse::Value(VALUE.to_owned()));
    assert_eq!(
        platform.prompts()[prompts..],
        [(
            other.to_owned(),
            OpenDestination::Gateway {
                name: "mini".to_owned()
            }
        )]
    );

    // and without a copy, with the value the owner enters
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer(other, None, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.answer(id, "entered".to_owned());
    assert_eq!(
        reading.await??,
        CompanionResponse::Value("entered".to_owned())
    );

    // a record kept by an app that had an allow list still loads
    drop(app);
    let mut record: serde_json::Value = serde_json::from_slice(
        &platform
            .secrets
            .lock()
            .map_err(|_| "poisoned")?
            .get("gateway")
            .cloned()
            .ok_or("no record")?,
    )?;
    record["allow"] = serde_json::json!([REFERENCE, other]);
    platform
        .secrets
        .lock()
        .map_err(|_| "poisoned")?
        .insert("gateway".to_owned(), serde_json::to_vec(&record)?);
    let relaunched = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    assert_eq!(
        relaunched.state().gateway.map(|gateway| gateway.name),
        Some("mini".to_owned())
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_expires_and_takes_its_prompt_down() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    platform.set_face_id(FaceId::Hold);

    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 1_500).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    let read = app
        .state()
        .reads
        .into_iter()
        .find(|read| read.id == id)
        .ok_or("no read")?;
    assert!(read.expires_at_ms > 0);
    app.dispatch(AppAction::Approve { id: id.clone() });
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Approving)
    })
    .await?;

    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Expired)
    })
    .await?;
    assert_eq!(platform.cancelled(), [id]);
    // the gateway gets no value, only a reset stream
    assert!(reading.await?.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_the_gateway_gives_up_is_withdrawn() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    platform.set_face_id(FaceId::Hold);

    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id: id.clone() });
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Approving)
    })
    .await?;

    // another source answered: the gateway drops the stream
    reading.abort();
    until(&app, |state| {
        state
            .reads
            .iter()
            .any(|read| read.id == id && read.status == ReadStatus::Withdrawn)
    })
    .await?;
    assert_eq!(platform.cancelled(), std::slice::from_ref(&id));

    // finished reads can be dismissed
    app.dispatch(AppAction::Dismiss { id: id.clone() });
    until(&app, |state| state.reads.iter().all(|read| read.id != id)).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_phone_dials_again_when_the_link_drops_and_after_a_relaunch() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, recorder) = paired(&gateway).await?;
    let dials = || {
        recorder.0.lock().map_or(0, |updates| {
            updates
                .iter()
                .filter(|update| **update == Update::Connection(ConnectionState::Connecting))
                .count()
        })
    };
    let before = dials();

    // on loopback the new dial lands within milliseconds, so the updates
    // show it rather than the state
    gateway.drop_link();
    for _ in 0..200 {
        if dials() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(dials(), before + 1);
    until(&app, |state| state.connection == ConnectionState::Connected).await?;
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id });
    assert_eq!(reading.await??, CompanionResponse::Value(VALUE.to_owned()));

    // backgrounded, the link is hung up
    app.dispatch(AppAction::Background);
    until(&app, |state| state.connection == ConnectionState::Offline).await?;
    drop(app);

    // a relaunch finds the pairing in the Keychain and connects in the
    // foreground
    let relaunched = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    assert_eq!(
        relaunched.state().gateway.map(|gateway| gateway.name),
        Some("mini".to_owned())
    );
    relaunched.dispatch(AppAction::Foreground);
    until(&relaunched, |state| {
        state.connection == ConnectionState::Connected
    })
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unpairing_tells_the_gateway_and_drops_every_key() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;

    app.dispatch(AppAction::Unpair);
    until(&app, |state| state.gateway.is_none()).await?;
    assert!(
        gateway.requests().contains(&PhoneRequest::Unpair),
        "{:?}",
        gateway.requests()
    );
    assert!(platform.keychain_keys().is_empty());
    assert!(platform.public_seal_key().is_none());
    assert_eq!(app.state().connection, ConnectionState::Offline);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_scan_without_an_invite_fails_without_touching_the_keychain() -> TestResult {
    let platform = FakePlatform::new();
    let app = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    app.dispatch(AppAction::Pair {
        scanned: "https://example.com".to_owned(),
    });
    until(&app, |state| {
        matches!(state.pairing, PairingState::Failed { .. })
    })
    .await?;
    assert!(platform.keychain_keys().is_empty());

    Ok(())
}

/// The read `id` as the app shows it
fn shown(app: &FfiApp, id: &RequestId) -> Option<PendingRead> {
    app.state()
        .reads
        .into_iter()
        .find(|read| read.id == id.as_str())
}

/// An `op://` reference item, with a copy sealed under it when `value` is set
fn reference_item(
    gateway: &FakeGateway,
    reference: &str,
    value: Option<&str>,
) -> Result<ProgramItem, String> {
    let sealed = value
        .map(|value| gateway.seal(reference, value))
        .transpose()?;

    Ok(ProgramItem::Reference {
        reference: reference.to_owned(),
        sealed,
        field: None,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_read_opens_its_sealed_items_with_one_face_id() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, recorder) = paired(&gateway).await?;
    let others = ["op://Dev/smtp/password", "op://Dev/pushover/token"];
    let values = ["first-value", "second-value", "third-value"];
    let id = RequestId::generate();

    let items = vec![
        reference_item(&gateway, REFERENCE, Some(values[0]))?,
        reference_item(&gateway, others[0], Some(values[1]))?,
        reference_item(&gateway, others[1], Some(values[2]))?,
    ];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move {
            gateway
                .offer_program_read(PhoneProgramRead {
                    id,
                    items,
                    reason: Some("deploy\nApprove all \u{202e}now".to_owned()),
                    destination: Some(format!("/srv/app.env\n{}", "d".repeat(300))),
                    keep_secs: Some(2 * 60 * 60),
                    sign_in: None,
                    expires_in_ms: 30_000,
                })
                .await
        }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;

    // the prompt names every item, and the reason stays on one line
    let read = shown(&app, &id).ok_or("no read")?;
    let program = read.program.ok_or("not a program read")?;
    assert_eq!(program.reason.as_deref(), Some("deploy⏎Approve all ?now"));
    // the destination too, cut to its limit, and the keep held to an hour
    let destination = program.destination.ok_or("no destination")?;
    assert!(destination.starts_with("/srv/app.env⏎ddd"), "{destination}");
    assert_eq!(destination.chars().count(), 256 + 1);
    assert!(destination.ends_with('…'));
    assert_eq!(program.keep_secs, Some(60 * 60));
    let references: Vec<ShownItem> = [REFERENCE, others[0], others[1]]
        .into_iter()
        .map(|reference| ShownItem::Reference {
            reference: reference.to_owned(),
            sealed: true,
            field: None,
        })
        .collect();
    assert_eq!(program.items, references);
    assert!(read.sealed);

    // one Approve opens all three
    app.dispatch(AppAction::Approve { id: id.to_string() });
    assert_eq!(reading.await??, texts(&values));
    let all = [REFERENCE, others[0], others[1]]
        .map(str::to_owned)
        .to_vec();
    assert_eq!(platform.batch_prompts(), [(all, 3, "mini".to_owned())]);
    // only the pairing's check asked Face ID for a single value
    assert_eq!(platform.prompts().len(), 1);
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Approved)
    })
    .await?;

    // the values are in no state, update or Debug output
    let updates = recorder.0.lock().map(|u| u.clone()).unwrap_or_default();
    let shown = format!("{:?}{updates:?}", app.state());
    assert!(values.iter().all(|value| !shown.contains(value)));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_read_sends_entered_values_with_opened_ones_in_item_order() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    let id = RequestId::generate();

    // sealed, unsealed and described: Face ID opens only the first
    let items = vec![
        reference_item(&gateway, REFERENCE, Some(VALUE))?,
        reference_item(&gateway, "op://Dev/new/credential", None)?,
        ProgramItem::Describe {
            description: "Pushover app token".to_owned(),
            field: None,
        },
    ];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    let read = shown(&app, &id).ok_or("no read")?;
    assert!(!read.sealed);
    let program = read.program.ok_or("not a program read")?;
    assert_eq!(program.reason, None);
    assert_eq!(
        program.items[2],
        ShownItem::Describe {
            description: "Pushover app token".to_owned(),
            field: None,
        }
    );

    // with an item still blank nothing goes and Face ID is not asked
    app.dispatch(AppAction::Approve { id: id.to_string() });
    app.answer_program(id.to_string(), typed(&[(1, "entered-1")]));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!reading.is_finished());
    assert!(platform.batch_prompts().is_empty());

    // a described item may be answered with a file shared from 1Password,
    // which goes as its bytes
    let p12 = vec![0x30, 0x82, 0x00, 0xff];
    let mut entered = typed(&[(1, "entered-1")]);
    entered.insert(2, EnteredValue::File { bytes: p12.clone() });
    app.answer_program(id.to_string(), entered);
    assert_eq!(
        reading.await??,
        CompanionResponse::Values(vec![
            ProgramValue::from(VALUE.to_owned()),
            ProgramValue::from("entered-1".to_owned()),
            ProgramValue::from(p12),
        ])
    );
    assert_eq!(platform.batch_prompts().len(), 1);
    assert_eq!(platform.batch_prompts()[0].1, 3);

    // every value entered, the sealed one replaced: no Face ID at all
    let id = RequestId::generate();
    let items = vec![
        reference_item(&gateway, REFERENCE, Some(VALUE))?,
        ProgramItem::Describe {
            description: "Pushover user key".to_owned(),
            field: None,
        },
    ];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    app.answer_program(id.to_string(), typed(&[(0, "fresher"), (1, "user-key")]));
    assert_eq!(reading.await??, texts(&["fresher", "user-key"]));
    assert_eq!(platform.batch_prompts().len(), 1);

    // values that do not fit in one answer are refused, not cut
    let id = RequestId::generate();
    let items = (0..2)
        .map(|index| ProgramItem::Describe {
            description: format!("large value {index}"),
            field: None,
        })
        .collect();
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    let large = "x".repeat(MAX_BODY_BYTES / 2);
    app.answer_program(
        id.to_string(),
        typed(&[(0, large.as_str()), (1, large.as_str())]),
    );
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("values over the limit were sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::ReadFailed);
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| matches!(read.status, ReadStatus::Failed { .. }))
    })
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_read_from_a_push_can_be_denied_and_takes_its_prompt_down() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    let id = RequestId::generate();

    // tapped from the push: a placeholder naming the items until it arrives
    app.dispatch(AppAction::OpenedFromProgramPush {
        id: id.to_string(),
        summary: "2 values: op://Dev/fixture/credential, Pushover app token".to_owned(),
        gateway: "mini".to_owned(),
        expires_at_ms: None,
    });
    until(&app, |_| shown(&app, &id).is_some()).await?;
    let placeholder = shown(&app, &id).ok_or("no read")?;
    assert_eq!(placeholder.status, ReadStatus::Connecting);
    assert!(
        placeholder
            .program
            .is_some_and(|program| program.items.is_empty())
    );

    // Face ID is up when the owner denies: the prompt goes and nothing is sent
    platform.set_face_id(FaceId::Hold);
    let items = vec![
        reference_item(&gateway, REFERENCE, Some(VALUE))?,
        reference_item(&gateway, "op://Dev/other/credential", Some(VALUE))?,
    ];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, Some("send mail")).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    let program = shown(&app, &id)
        .and_then(|read| read.program)
        .ok_or("not a program read")?;
    assert_eq!(program.items.len(), 2);
    app.dispatch(AppAction::Approve { id: id.to_string() });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Approving)
    })
    .await?;
    app.dispatch(AppAction::Deny { id: id.to_string() });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("values were sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::Denied);
    assert!(platform.cancelled().contains(&id.to_string()));

    // cancelling Face ID denies too
    platform.set_face_id(FaceId::Cancel);
    let id = RequestId::generate();
    let items = vec![reference_item(&gateway, REFERENCE, Some(VALUE))?];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    app.dispatch(AppAction::Approve { id: id.to_string() });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("values were sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::Denied);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_interrupted_face_id_fails_the_read_without_denying_it() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    platform.set_face_id(FaceId::Interrupted);

    // a single read
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(REFERENCE, 30_000).await }
    });
    let id = waiting(&until(&app, |state| waiting(state).is_some()).await?).ok_or("no read")?;
    app.dispatch(AppAction::Approve { id });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("a value was sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::ReadFailed);

    // a program read, whose denial would end it on every device
    let id = RequestId::generate();
    let items = vec![reference_item(&gateway, REFERENCE, Some(VALUE))?];
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = id.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    app.dispatch(AppAction::Approve { id: id.to_string() });
    let CompanionResponse::Error(fault) = reading.await?? else {
        return Err("values were sent".into());
    };
    assert_eq!(fault.code, CompanionErrorCode::ReadFailed);
    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| matches!(read.status, ReadStatus::Failed { .. }))
    })
    .await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approval_made_while_another_prompt_is_up_runs_when_it_ends() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    platform.set_face_id(FaceId::Hold);

    // the first read's Face ID stays up
    let first = RequestId::generate();
    let items = vec![reference_item(&gateway, REFERENCE, Some(VALUE))?];
    let first_reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = first.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &first).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    app.dispatch(AppAction::Approve {
        id: first.to_string(),
    });
    until(&app, |_| {
        shown(&app, &first).is_some_and(|read| read.status == ReadStatus::Approving)
    })
    .await?;

    // the second is sent meanwhile; it waits rather than being dropped
    let second = RequestId::generate();
    let items = vec![
        reference_item(&gateway, REFERENCE, Some(VALUE))?,
        ProgramItem::Describe {
            description: "Pushover app token".to_owned(),
            field: None,
        },
    ];
    let second_reading = tokio::spawn({
        let gateway = gateway.clone();
        let id = second.clone();
        async move { gateway.offer_program(id, items, None).await }
    });
    until(&app, |_| {
        shown(&app, &second).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    app.answer_program(second.to_string(), typed(&[(1, "app-token")]));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(platform.batch_prompts().len(), 1);
    assert!(!second_reading.is_finished());

    // once the first prompt ends, the second asks Face ID and goes
    platform.set_face_id(FaceId::Approve);
    app.dispatch(AppAction::Deny {
        id: first.to_string(),
    });
    assert!(matches!(first_reading.await??, CompanionResponse::Error(_)));
    assert_eq!(second_reading.await??, texts(&[VALUE, "app-token"]));
    assert_eq!(platform.batch_prompts().len(), 2);

    Ok(())
}

/// What a fake gateway reads the bytes of when a test types or fills
const TYPED: &str = "hunter2";

/// The next message the phone sends on a takeover
async fn read_phone(receive: &mut RecvStream) -> Result<PhoneMessage, Box<dyn Error>> {
    let mut header = [0_u8; HEADER_BYTES];
    tokio::time::timeout(Duration::from_secs(10), receive.read_exact(&mut header)).await??;
    let (kind, length) = read_header(header)?;
    let mut body = vec![0_u8; length];
    receive.read_exact(&mut body).await?;

    Ok(decode_phone(kind, &body)?)
}

fn updates(recorder: &Recorder) -> Vec<Update> {
    recorder.0.lock().map(|u| u.clone()).unwrap_or_default()
}

fn takeover_status(state: &AppState) -> Option<TakeoverStatus> {
    state
        .takeover
        .as_ref()
        .map(|takeover| takeover.status.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_shows_the_page_paces_its_images_and_sends_the_owners_input() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, recorder) = paired(&gateway).await?;
    let handoff = RequestId::generate();

    app.dispatch(AppAction::OpenTakeover {
        session: "github".to_owned(),
        handoff: Some(handoff.to_string()),
        host: SessionHost::Gateway,
    });
    let state = until(&app, |state| state.takeover.is_some()).await?;
    let takeover = state.takeover.ok_or("no takeover")?;
    assert_eq!(takeover.session, "github");
    assert_eq!(takeover.handoff, Some(handoff.to_string()));
    assert_eq!(takeover.status, TakeoverStatus::Connecting);
    // nothing is dialed before the app says how big the image area is
    app.takeover(TakeoverInput::Resize {
        width: 390,
        height: 664,
        scale: 2.0,
    });

    let open = PhoneMessage::Open {
        session: "github".to_owned(),
        handoff: Some(handoff.clone()),
        viewport: Viewport {
            width: 390,
            height: 664,
            scale: 2.0,
        },
        start: None,
    };
    let (connection, _, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, open);

    // a link that drops is dialed again, and the takeover opens anew on it
    connection.close(0_u32.into(), b"restart");
    until(&app, |state| {
        matches!(
            takeover_status(state),
            Some(TakeoverStatus::Retrying { .. })
        )
    })
    .await?;
    let (_connection, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, open);

    let reference = "op://Private/GitHub/password";
    let page = GatewayMessage::Page {
        url: "https://github.com/login".to_owned(),
        title: "Sign in to GitHub".to_owned(),
        focus: Some(Focus {
            field: Some(WireField::Password),
            editable: true,
            secure: true,
            numeric: false,
            origin: "https://github.com".to_owned(),
            cross_site: false,
        }),
        offers: vec![FillOffer {
            field: WireField::Password,
            reference: reference.to_owned(),
            sealed: gateway.seal(reference, TYPED)?,
            item: "GitHub".to_owned(),
            account: Some("praveenperera".to_owned()),
            site: "github.com".to_owned(),
        }],
    };
    send.write_all(&encode_message(&page)?).await?;
    let jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 1, 2, 3];
    let screen = Screen {
        header: ScreenHeader {
            seq: 0,
            width: 780,
            height: 1328,
        },
        jpeg: jpeg.clone(),
    };
    send.write_all(&encode_screen(&screen)?).await?;

    let state = until(&app, |state| {
        state
            .takeover
            .as_ref()
            .is_some_and(|takeover| takeover.page.is_some())
    })
    .await?;
    let takeover = state.takeover.ok_or("no takeover")?;
    assert_eq!(takeover.status, TakeoverStatus::Live);
    let page = takeover.page.ok_or("no page")?;
    assert_eq!(page.url, "https://github.com/login");
    assert_eq!(page.title, "Sign in to GitHub");
    let focus = page.focus.ok_or("no focus")?;
    assert_eq!(focus.field, Some(LoginField::Password));
    assert!(focus.editable && focus.secure && !focus.numeric);
    assert_eq!(page.offers.len(), 1);
    assert_eq!(page.offers[0].reference, reference);
    assert_eq!(page.offers[0].field, LoginField::Password);
    assert_eq!(page.offers[0].account.as_deref(), Some("praveenperera"));

    // the image reaches the app, and is acknowledged once it is drawn
    let mut image = None;
    for _ in 0..200 {
        image = updates(&recorder)
            .into_iter()
            .find_map(|update| match update {
                Update::Screen(image) => Some(image),
                _ => None,
            });
        if image.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        image,
        Some(ScreenImage {
            seq: 0,
            width: 780,
            height: 1328,
            jpeg,
        })
    );
    app.takeover(TakeoverInput::Drawn { seq: 0 });
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::Ack { seq: 0 }
    );
    // an image drawn twice is acknowledged once, and a tap goes as fractions
    // of the image
    app.takeover(TakeoverInput::Drawn { seq: 0 });
    app.takeover(TakeoverInput::Tap {
        x: 0.5,
        y: 0.25,
        seq: 0,
    });
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::Tap {
            at: Point { x: 0.5, y: 0.25 },
            seq: 0,
        }
    );
    app.takeover_text(TYPED.to_owned());
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::Text {
            text: WireSecret::new(TYPED.to_owned()),
        }
    );

    // Fill from 1Password opens the offer's sealed copy with Face ID
    app.takeover(TakeoverInput::FillOffer {
        reference: reference.to_owned(),
    });
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::Fill {
            field: WireField::Password,
            value: WireSecret::new(TYPED.to_owned()),
            submit: false,
            site: Some("github.com".to_owned()),
        }
    );
    // Face ID names the page the value goes into
    assert_eq!(
        platform.prompts().last(),
        Some(&(
            reference.to_owned(),
            OpenDestination::Page {
                session: "github".to_owned(),
                machine: "mini".to_owned()
            }
        ))
    );
    send.write_all(&encode_message(&GatewayMessage::Filled {
        field: WireField::Password,
    })?)
    .await?;
    until(&app, |state| {
        state.takeover.as_ref().is_some_and(|takeover| {
            takeover.notice
                == Some(TakeoverNotice::Filled {
                    field: LoginField::Password,
                })
        })
    })
    .await?;

    // Done ends it; the gateway's Ended closes the screen
    app.takeover(TakeoverInput::Done);
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Done);
    send.write_all(&encode_message(&GatewayMessage::Ended {
        reason: EndReason::Done,
        message: None,
    })?)
    .await?;
    until(&app, |state| state.takeover.is_none()).await?;

    // nothing typed or filled is in any state, update or Debug output
    assert!(!format!("{:?}", app.state()).contains(TYPED));
    assert!(!format!("{:?}", updates(&recorder)).contains(TYPED));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handoff_offered_again_shows_once_and_cancel_answers_it() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _, _) = paired(&gateway).await?;
    let id = RequestId::generate();
    let handoff = PhoneHandoff {
        id: id.clone(),
        session: "github".to_owned(),
        reason: Some("Approve the passkey prompt\nplease".to_owned()),
        url: Some("https://github.com/sessions/two-factor".to_owned()),
        expires_in_ms: 60_000,
        machine: None,
    };

    let first = tokio::spawn({
        let gateway = gateway.clone();
        let handoff = handoff.clone();
        async move { gateway.offer_handoff(handoff).await }
    });
    let state = until(&app, |state| {
        state
            .handoffs
            .iter()
            .any(|shown| shown.status == HandoffStatus::Waiting)
    })
    .await?;
    let [card] = state.handoffs.as_slice() else {
        return Err(format!("not one handoff: {:?}", state.handoffs).into());
    };
    assert_eq!(card.id, id.to_string());
    assert_eq!(card.session, "github");
    // the agent's words stay on one line
    assert_eq!(
        card.reason.as_deref(),
        Some("Approve the passkey prompt⏎please")
    );
    assert_eq!(
        card.url.as_deref(),
        Some("https://github.com/sessions/two-factor")
    );
    assert_eq!(card.gateway_name, "mini");

    // the link drops before the owner answers; the gateway offers it again
    gateway.drop_link();
    assert!(first.await?.is_err());
    let second = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer_handoff(handoff).await }
    });
    app.dispatch(AppAction::CancelHandoff { id: id.to_string() });
    assert_eq!(second.await??, HandoffAnswer::Cancelled);
    let state = until(&app, |state| {
        state
            .handoffs
            .iter()
            .any(|shown| shown.status == HandoffStatus::Cancelled)
    })
    .await?;
    assert_eq!(state.handoffs.len(), 1, "{:?}", state.handoffs);

    // one the gateway stops (a takeover or another phone ended it) is over
    let other = RequestId::generate();
    let connection = gateway.link.borrow().clone().ok_or("no link")?;
    let (mut send, mut receive) = connection.open_bi().await?;
    let request = PhoneHandoffRequest {
        handoff: PhoneHandoff {
            id: other.clone(),
            session: "github".to_owned(),
            reason: None,
            url: None,
            expires_in_ms: 60_000,
            machine: None,
        },
    };
    send.write_all(&serde_json::to_vec(&request)?).await?;
    send.finish()?;
    until(&app, |state| {
        state
            .handoffs
            .iter()
            .any(|shown| shown.id == other.to_string() && shown.status == HandoffStatus::Waiting)
    })
    .await?;
    receive.stop(0_u32.into())?;
    until(&app, |state| {
        state
            .handoffs
            .iter()
            .any(|shown| shown.id == other.to_string() && shown.status == HandoffStatus::Over)
    })
    .await?;

    // finished handoffs are dismissed one by one
    app.dispatch(AppAction::Dismiss { id: id.to_string() });
    let state = until(&app, |state| state.handoffs.len() == 1).await?;
    assert_eq!(state.handoffs[0].id, other.to_string());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_names_its_site_and_each_items_login_field() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _, _) = paired(&gateway).await?;
    let id = RequestId::generate();
    let read = PhoneProgramRead {
        id: id.clone(),
        items: vec![
            ProgramItem::Describe {
                description: "github.com username".to_owned(),
                field: Some(WireField::Username),
            },
            ProgramItem::Describe {
                description: "github.com password".to_owned(),
                field: Some(WireField::Password),
            },
        ],
        reason: Some("sign in to GitHub".to_owned()),
        destination: None,
        keep_secs: None,
        sign_in: Some(SignIn {
            site: "github.com".to_owned(),
            account: Some("praveenperera".to_owned()),
            session: Some("github".to_owned()),
        }),
        expires_in_ms: 30_000,
    };
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer_program_read(read).await }
    });

    until(&app, |_| {
        shown(&app, &id).is_some_and(|read| read.status == ReadStatus::Waiting)
    })
    .await?;
    let read = shown(&app, &id).ok_or("no read")?;
    assert_eq!(read.reference, "github.com · praveenperera");
    let program = read.program.ok_or("not a program read")?;
    let sign_in = program.sign_in.ok_or("no sign-in")?;
    assert_eq!(sign_in.title, "github.com · praveenperera");
    assert_eq!(sign_in.session.as_deref(), Some("github"));
    let fields: Vec<Option<LoginField>> = program
        .items
        .iter()
        .map(|item| match item {
            ShownItem::Reference { field, .. } | ShownItem::Describe { field, .. } => *field,
        })
        .collect();
    assert_eq!(
        fields,
        [Some(LoginField::Username), Some(LoginField::Password)]
    );

    // one Send answers both, as AutoFill filled them
    app.answer_program(id.to_string(), typed(&[(0, "praveenperera"), (1, TYPED)]));
    assert_eq!(reading.await??, texts(&["praveenperera", TYPED]));

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sessions_are_listed_started_and_closed() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _platform, _recorder) = paired(&gateway).await?;

    // a gateway from before listings closes the link, as it does any link
    // that does not start with an Open
    app.dispatch(AppAction::RefreshSessions);
    let (old, _, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Sessions);
    old.close(1_u32.into(), b"expected open");
    let state = until(&app, |state| {
        matches!(state.sessions.status, SessionsStatus::Failed { .. })
    })
    .await?;
    assert_eq!(
        state.sessions.status,
        SessionsStatus::Failed {
            message: "mini's codemode-mcp is too old to list sessions; update it".to_owned()
        }
    );

    app.dispatch(AppAction::RefreshSessions);
    let (_listing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Sessions);
    let listed = GatewayMessage::Sessions {
        running: vec![RunningSession {
            name: "github".to_owned(),
            url: Some("https://github.com/".to_owned()),
            title: Some("GitHub".to_owned()),
        }],
        saved: vec!["discord".to_owned()],
        last_pages: [(
            "discord".to_owned(),
            "https://discord.com/channels/@me".to_owned(),
        )]
        .into(),
        machines: Vec::new(),
    };
    send.write_all(&encode_message(&listed)?).await?;
    let state = until(&app, |state| {
        state.sessions.status == SessionsStatus::Listed
    })
    .await?;
    assert_eq!(
        state.sessions.running,
        [BrowserSession {
            name: "github".to_owned(),
            url: Some("https://github.com/".to_owned()),
            title: Some("GitHub".to_owned()),
        }]
    );
    assert_eq!(
        state.sessions.saved,
        [SavedSession {
            name: "discord".to_owned(),
            last_page: Some("https://discord.com/channels/@me".to_owned()),
        }]
    );

    app.dispatch(AppAction::StartSession {
        session: "discord".to_owned(),
        url: "https://discord.com/login".to_owned(),
        host: SessionHost::Gateway,
    });
    app.takeover(TakeoverInput::Resize {
        width: 390,
        height: 664,
        scale: 3.0,
    });
    let open = |start: Option<&str>| PhoneMessage::Open {
        session: "discord".to_owned(),
        handoff: None,
        viewport: Viewport {
            width: 390,
            height: 664,
            scale: 3.0,
        },
        start: start.map(str::to_owned),
    };
    let (connection, _, mut receive) = gateway.next_takeover().await?;
    assert_eq!(
        read_phone(&mut receive).await?,
        open(Some("https://discord.com/login"))
    );

    // a redial takes the session over as it is: starting it again would
    // load the address over whatever the owner had done on the page
    connection.close(0_u32.into(), b"restart");
    let (_connection, _, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, open(None));

    // closing the session leaves its takeover, which would only end with
    // the browser, and lists the sessions as they are after
    app.dispatch(AppAction::CloseSession {
        session: "discord".to_owned(),
        host: SessionHost::Gateway,
    });
    let (_closing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::CloseSession {
            session: "discord".to_owned()
        }
    );
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: vec!["discord".to_owned(), "github".to_owned()],
        last_pages: Default::default(),
        machines: Vec::new(),
    };
    send.write_all(&encode_message(&listed)?).await?;
    let state = until(&app, |state| {
        state.sessions.status == SessionsStatus::Listed && state.sessions.running.is_empty()
    })
    .await?;
    assert_eq!(state.takeover, None);
    let names = |state: &AppState| {
        state
            .sessions
            .saved
            .iter()
            .map(|saved| saved.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&state), ["discord", "github"]);

    // removing a saved one is asked on a link of its own too
    app.dispatch(AppAction::RemoveSession {
        session: "discord".to_owned(),
        host: SessionHost::Gateway,
    });
    let (_removing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(
        read_phone(&mut receive).await?,
        PhoneMessage::RemoveSession {
            session: "discord".to_owned()
        }
    );
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: vec!["github".to_owned()],
        last_pages: Default::default(),
        machines: Vec::new(),
    };
    send.write_all(&encode_message(&listed)?).await?;
    let state = until(&app, |state| names(state) == ["github"]).await?;
    assert_eq!(state.sessions.status, SessionsStatus::Listed);

    Ok(())
}

/// A takeover link the fake spoke took, held open by whoever holds it
type SpokeLink = (PhoneMessage, Connection, SendStream, RecvStream);

/// A spoke's takeover endpoint, named `code`, and the machine the gateway
/// lists for it
async fn spoke_endpoint() -> Result<(Endpoint, BrowserMachine), Box<dyn Error>> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(iroh::SecretKey::generate())
        .alpns(vec![TAKEOVER_ALPN.to_vec()])
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
        .bind()
        .await?;
    let address = endpoint
        .bound_sockets()
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or("no IPv4 socket")?;
    let machine = BrowserMachine {
        name: "code".to_owned(),
        id: endpoint.id(),
        addrs: vec![address],
        relay: None,
    };

    Ok((endpoint, machine))
}

/// A spoke that passes on every link with its first message, a listing's
/// too, so a test answers them in the order it likes
async fn held_spoke() -> Result<(BrowserMachine, mpsc::UnboundedReceiver<SpokeLink>), Box<dyn Error>>
{
    let (endpoint, machine) = spoke_endpoint().await?;
    let (links, held) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let links = links.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok((send, mut receive)) = connection.accept_bi().await else {
                    return;
                };
                if let Ok(first) = read_phone(&mut receive).await {
                    let _ = links.send((first, connection, send, receive));
                }
            });
        }
    });

    Ok((machine, held))
}

/// The next link a [`held_spoke`] took
async fn held(links: &mut mpsc::UnboundedReceiver<SpokeLink>) -> Result<SpokeLink, Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(10), links.recv())
        .await?
        .ok_or_else(|| "the spoke stopped".into())
}

/// A spoke's takeover endpoint: lists `running` to every listing, and
/// passes on each Open with its link, which stays up while it is held
async fn fake_spoke(
    running: &'static str,
) -> Result<(BrowserMachine, mpsc::UnboundedReceiver<SpokeLink>), Box<dyn Error>> {
    let (endpoint, machine) = spoke_endpoint().await?;
    let (opens, opened) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let opens = opens.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok((mut send, mut receive)) = connection.accept_bi().await else {
                    return;
                };
                let Ok(first) = read_phone(&mut receive).await else {
                    return;
                };
                if first != PhoneMessage::Sessions {
                    let _ = opens.send((first, connection, send, receive));

                    return;
                }
                let listed = GatewayMessage::Sessions {
                    running: vec![RunningSession {
                        name: running.to_owned(),
                        url: None,
                        title: None,
                    }],
                    saved: Vec::new(),
                    last_pages: Default::default(),
                    machines: Vec::new(),
                };
                if let Ok(frame) = encode_message(&listed) {
                    let _ = send.write_all(&frame).await;
                }
                let _ = connection.closed().await;
            });
        }
    });

    Ok((machine, opened))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gateways_machines_are_listed_and_dialed_on_their_own() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _platform, _recorder) = paired(&gateway).await?;
    let (spoke, mut opened) = fake_spoke("ci").await?;
    let on_spoke = SessionHost::Machine {
        id: spoke.id.to_string(),
        name: "code".to_owned(),
    };
    // a machine that is off: its port answers nothing
    let off = BrowserMachine {
        name: "attic".to_owned(),
        id: iroh::SecretKey::generate().public(),
        addrs: vec![SocketAddr::from(([127, 0, 0, 1], 9))],
        relay: None,
    };

    // a takeover of a machine the phone has not heard of asks the gateway
    // for a listing first, and dials the machine the listing names
    app.dispatch(AppAction::OpenTakeover {
        session: "ci".to_owned(),
        handoff: None,
        host: on_spoke.clone(),
    });
    app.takeover(TakeoverInput::Resize {
        width: 390,
        height: 664,
        scale: 3.0,
    });
    let (_listing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Sessions);
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: vec!["github".to_owned()],
        last_pages: Default::default(),
        machines: vec![spoke.clone(), off.clone()],
    };
    send.write_all(&encode_message(&listed)?).await?;

    let (open, _link, _send, _receive) =
        tokio::time::timeout(Duration::from_secs(10), opened.recv())
            .await?
            .ok_or("the spoke stopped")?;
    assert_eq!(
        open,
        PhoneMessage::Open {
            session: "ci".to_owned(),
            handoff: None,
            viewport: Viewport {
                width: 390,
                height: 664,
                scale: 3.0,
            },
            start: None,
        }
    );
    assert_eq!(
        app.state().takeover.map(|takeover| takeover.host),
        Some(on_spoke.clone())
    );

    // each machine has its own section; the one that is off shows as
    // unreachable, without holding up the others
    let state = until(&app, |state| {
        state
            .sessions
            .machines
            .iter()
            .all(|section| section.status != SessionsStatus::Loading)
    })
    .await?;
    let names: Vec<&str> = state
        .sessions
        .machines
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    assert_eq!(names, ["attic", "code"]);
    assert!(matches!(
        &state.sessions.machines[0].status,
        SessionsStatus::Unreachable { message } if message.starts_with("attic is unreachable")
    ));
    assert_eq!(state.sessions.machines[1].status, SessionsStatus::Listed);
    assert_eq!(
        state.sessions.machines[1].running,
        [BrowserSession {
            name: "ci".to_owned(),
            url: None,
            title: None,
        }]
    );
    assert_eq!(state.sessions.saved[0].name, "github");

    // a handoff of a machine's session shows where it runs
    let id = RequestId::generate();
    let handoff = PhoneHandoff {
        id: id.clone(),
        session: "ci".to_owned(),
        reason: None,
        url: None,
        expires_in_ms: 60_000,
        machine: Some(spoke),
    };
    let answered = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer_handoff(handoff).await }
    });
    let state = until(&app, |state| !state.handoffs.is_empty()).await?;
    assert_eq!(state.handoffs[0].host, on_spoke);
    app.dispatch(AppAction::CancelHandoff { id: id.to_string() });
    assert_eq!(answered.await??, HandoffAnswer::Cancelled);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_time_code_filled_on_a_machine_is_computed_on_the_phone() -> TestResult {
    // the RFC 6238 SHA1 test seed, as 1Password keeps it for a login
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let reference = "op://Private/GitHub/one-time password";
    let gateway = FakeGateway::start().await?;
    let (app, platform, _recorder) = paired(&gateway).await?;
    let (spoke, mut opened) = fake_spoke("ci").await?;

    app.dispatch(AppAction::OpenTakeover {
        session: "ci".to_owned(),
        handoff: None,
        host: SessionHost::Machine {
            id: spoke.id.to_string(),
            name: "code".to_owned(),
        },
    });
    app.takeover(TakeoverInput::Resize {
        width: 390,
        height: 664,
        scale: 3.0,
    });
    let (_listing, mut send, _receive) = gateway.next_takeover().await?;
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: Vec::new(),
        last_pages: Default::default(),
        machines: vec![spoke.clone()],
    };
    send.write_all(&encode_message(&listed)?).await?;
    let (_open, _link, mut send, mut receive) =
        tokio::time::timeout(Duration::from_secs(10), opened.recv())
            .await?
            .ok_or("the spoke stopped")?;

    // the gateway sealed the seed for the spoke's page, as it does every
    // offer, and the spoke offers it for the code field
    let page = GatewayMessage::Page {
        url: "https://github.com/sessions/two-factor".to_owned(),
        title: "Two-factor authentication".to_owned(),
        focus: Some(Focus {
            field: Some(WireField::Code),
            editable: true,
            secure: false,
            numeric: true,
            origin: "https://github.com".to_owned(),
            cross_site: false,
        }),
        offers: vec![FillOffer {
            field: WireField::Code,
            reference: reference.to_owned(),
            sealed: gateway.seal(reference, SEED)?,
            item: "GitHub".to_owned(),
            account: Some("praveenperera".to_owned()),
            site: "github.com".to_owned(),
        }],
    };
    send.write_all(&encode_message(&page)?).await?;
    until(&app, |state| {
        state
            .takeover
            .as_ref()
            .and_then(|takeover| takeover.page.as_ref())
            .is_some_and(|page| !page.offers.is_empty())
    })
    .await?;

    // the spoke gets the current code, never the seed
    app.takeover(TakeoverInput::FillOffer {
        reference: reference.to_owned(),
    });
    let PhoneMessage::Fill {
        field,
        value,
        submit,
        site,
    } = read_phone(&mut receive).await?
    else {
        return Err("the spoke got no fill".into());
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let totp = Totp::parse(SEED)?;
    // the code may have been computed in the period before this one
    let current = [totp.at(now), totp.at(now.saturating_sub(30))];
    assert_eq!(field, WireField::Code);
    assert_eq!(value.expose().len(), 6);
    assert!(current.iter().any(|code| code == value.expose()));
    assert!(!submit);
    assert_eq!(site.as_deref(), Some("github.com"));
    // Face ID names the spoke the value goes to, though the gateway sealed
    // it
    assert_eq!(
        platform.prompts().pop(),
        Some((
            reference.to_owned(),
            OpenDestination::Page {
                session: "ci".to_owned(),
                machine: "code".to_owned()
            }
        ))
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn two_machines_of_one_name_are_kept_apart_by_id() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _platform, _recorder) = paired(&gateway).await?;
    let (first, mut first_opened) = fake_spoke("ci").await?;
    let (second, mut second_opened) = fake_spoke("deploy").await?;
    assert_eq!(first.name, second.name);
    let host = |machine: &BrowserMachine| SessionHost::Machine {
        id: machine.id.to_string(),
        name: machine.name.clone(),
    };

    app.dispatch(AppAction::RefreshSessions);
    let (_listing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Sessions);
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: Vec::new(),
        last_pages: Default::default(),
        machines: vec![first.clone(), second.clone()],
    };
    send.write_all(&encode_message(&listed)?).await?;

    // each has a section of its own, with its own sessions
    let state = until(&app, |state| {
        state.sessions.machines.len() == 2
            && state
                .sessions
                .machines
                .iter()
                .all(|section| section.status == SessionsStatus::Listed)
    })
    .await?;
    let sections: Vec<(String, String, Vec<String>)> = state
        .sessions
        .machines
        .iter()
        .map(|section| {
            let running = section.running.iter().map(|session| session.name.clone());
            (section.id.clone(), section.name.clone(), running.collect())
        })
        .collect();
    // two of one name show in id order
    let mut expected = vec![
        (
            first.id.to_string(),
            "code".to_owned(),
            vec!["ci".to_owned()],
        ),
        (
            second.id.to_string(),
            "code".to_owned(),
            vec!["deploy".to_owned()],
        ),
    ];
    expected.sort();
    assert_eq!(sections, expected);

    // a handoff from the second names it, and leaves the first where it is
    let id = RequestId::generate();
    let handoff = PhoneHandoff {
        id: id.clone(),
        session: "deploy".to_owned(),
        reason: None,
        url: None,
        expires_in_ms: 60_000,
        machine: Some(second.clone()),
    };
    let answered = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.offer_handoff(handoff).await }
    });
    let state = until(&app, |state| !state.handoffs.is_empty()).await?;
    assert_eq!(state.handoffs[0].host, host(&second));

    // so a takeover on the first dials the first
    app.dispatch(AppAction::OpenTakeover {
        session: "ci".to_owned(),
        handoff: None,
        host: host(&first),
    });
    app.takeover(TakeoverInput::Resize {
        width: 390,
        height: 664,
        scale: 3.0,
    });
    let (open, _link, _send, _receive) =
        tokio::time::timeout(Duration::from_secs(10), first_opened.recv())
            .await?
            .ok_or("the first spoke stopped")?;
    assert!(
        matches!(&open, PhoneMessage::Open { session, .. } if session == "ci"),
        "{open:?}"
    );
    assert!(second_opened.try_recv().is_err());

    app.dispatch(AppAction::CancelHandoff { id: id.to_string() });
    assert_eq!(answered.await??, HandoffAnswer::Cancelled);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listing_answered_after_a_close_does_not_bring_the_session_back() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, _platform, _recorder) = paired(&gateway).await?;
    let (spoke, mut links) = held_spoke().await?;
    let on_spoke = SessionHost::Machine {
        id: spoke.id.to_string(),
        name: spoke.name.clone(),
    };
    let running = |names: &[&str]| GatewayMessage::Sessions {
        running: names
            .iter()
            .map(|name| RunningSession {
                name: (*name).to_owned(),
                url: None,
                title: None,
            })
            .collect(),
        saved: Vec::new(),
        last_pages: Default::default(),
        machines: Vec::new(),
    };
    let shown = |state: &AppState| {
        let section = state.sessions.machines.first()?;
        let names = section.running.iter().map(|session| session.name.clone());

        (section.status == SessionsStatus::Listed).then(|| names.collect::<Vec<_>>())
    };

    // the gateway's listing names the spoke, which the phone then lists in
    // the background
    app.dispatch(AppAction::RefreshSessions);
    let (_listing, mut send, mut receive) = gateway.next_takeover().await?;
    assert_eq!(read_phone(&mut receive).await?, PhoneMessage::Sessions);
    let listed = GatewayMessage::Sessions {
        running: Vec::new(),
        saved: Vec::new(),
        last_pages: Default::default(),
        machines: vec![spoke],
    };
    send.write_all(&encode_message(&listed)?).await?;
    let (first, background, mut background_send, _background_receive) = held(&mut links).await?;
    assert_eq!(first, PhoneMessage::Sessions);

    // the owner closes a session there before that listing answers, and
    // the close answers first
    app.dispatch(AppAction::CloseSession {
        session: "ci".to_owned(),
        host: on_spoke,
    });
    let (first, _closing, mut closing_send, _closing_receive) = held(&mut links).await?;
    assert_eq!(
        first,
        PhoneMessage::CloseSession {
            session: "ci".to_owned()
        }
    );
    closing_send
        .write_all(&encode_message(&running(&["deploy"]))?)
        .await?;
    until(&app, |state| {
        shown(state) == Some(vec!["deploy".to_owned()])
    })
    .await?;

    // the listing from before the close answers last, and is dropped
    background_send
        .write_all(&encode_message(&running(&["ci", "deploy"]))?)
        .await?;
    tokio::time::timeout(Duration::from_secs(10), background.closed()).await?;
    for _ in 0..25 {
        assert_eq!(shown(&app.state()), Some(vec!["deploy".to_owned()]));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    Ok(())
}
