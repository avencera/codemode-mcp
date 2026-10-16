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
    time::Duration,
};

use companion_core::ffi::{
    AppAction, AppState, ConnectionState, FfiApp, OpenError, OpenRequest, PairingState, Platform,
    PlatformError, PushEnvironment, ReadStatus, Reconciler, Update,
};
use companion_wire::{
    MAX_BODY_BYTES, MOBILE_ALPN, PAIR_ALPN,
    mobile::{PhoneRead, PhoneRequest, PhoneResponse, PushToken, RequestId, SealKey, Sealed},
    seal::{SoftwareKey, seal},
    ticket::{InviteSecret, InviteTicket},
    wire::{
        CompanionErrorCode, CompanionResponse, PairCheck, PairRequest, PairResponse, Registered,
    },
};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn Error>>;

const REFERENCE: &str = "op://Dev/fixture/credential";
const VALUE: &str = "value-from-1password";
const TOKEN: &str = "abcdef0123456789";

/// How Face ID answers
#[derive(Clone, Copy, PartialEq, Eq)]
enum FaceId {
    Approve,
    Cancel,
    /// Stays up until the core takes it down
    Hold,
}

/// The app's side: an in-memory Keychain and a software seal key
struct FakePlatform {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
    seal: Mutex<Option<SoftwareKey>>,
    face_id: Mutex<FaceId>,
    /// The reference and gateway each prompt named
    prompts: Mutex<Vec<(String, String)>>,
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
            cancelled: Mutex::new(Vec::new()),
            released: Condvar::new(),
        })
    }

    fn set_face_id(&self, face_id: FaceId) {
        if let Ok(mut slot) = self.face_id.lock() {
            *slot = face_id;
        }
    }

    fn prompts(&self) -> Vec<(String, String)> {
        self.prompts.lock().map(|p| p.clone()).unwrap_or_default()
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
            prompts.push((request.reference.clone(), request.gateway_name.clone()));
        }
        let face_id = self
            .0
            .face_id
            .lock()
            .map_or(FaceId::Cancel, |face_id| *face_id);
        match face_id {
            FaceId::Approve => {}
            FaceId::Cancel => return Err(OpenError::Denied),
            FaceId::Hold => {
                let Ok(cancelled) = self.0.cancelled.lock() else {
                    return Err(OpenError::Denied);
                };
                let _ = self.0.released.wait_timeout_while(
                    cancelled,
                    Duration::from_secs(10),
                    |cancelled| !cancelled.contains(&request.id),
                );

                return Err(OpenError::Denied);
            }
        }

        let seal = self.0.seal.lock().map_err(|_| OpenError::Denied)?;
        let key = seal.as_ref().ok_or(OpenError::Failed {
            message: "no seal key".to_owned(),
        })?;
        let value = key
            .open_with_info(&request.info, &request.enc, &request.ciphertext)
            .map_err(|error| OpenError::Failed {
                message: error.to_string(),
            })?;

        String::from_utf8(value).map_err(|error| OpenError::Failed {
            message: error.to_string(),
        })
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
    /// The references the phone may answer
    allow: Vec<String>,
}

impl FakeGateway {
    async fn start() -> Result<Self, Box<dyn Error>> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(iroh::SecretKey::generate())
            .alpns(vec![PAIR_ALPN.to_vec(), MOBILE_ALPN.to_vec()])
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await?;
        let address = endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .ok_or("no IPv4 socket")?;
        let gateway = Self {
            endpoint,
            address,
            secret: Arc::new(InviteSecret::generate()),
            seal_key: Arc::new(Mutex::new(None)),
            link: watch::channel(None).0,
            requests: Arc::new(Mutex::new(Vec::new())),
            allow: vec![REFERENCE.to_owned()],
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
                    references: self.allow.clone(),
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

    /// Reads `reference` through the phone with a copy sealed to it, as the
    /// gateway's race does
    async fn read(&self, reference: &str, expires_in_ms: u64) -> Result<CompanionResponse, String> {
        let key = self
            .seal_key
            .lock()
            .ok()
            .and_then(|key| key.clone())
            .ok_or("no phone registered")?;
        let sealed = seal(&key, &self.id(), reference, VALUE.as_bytes())
            .map_err(|error| error.to_string())?;

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
        let connection = self
            .link
            .subscribe()
            .wait_for(Option::is_some)
            .await
            .map_err(|error| error.to_string())?
            .clone()
            .ok_or("no link")?;

        let read = PhoneRead {
            id,
            reference: reference.to_owned(),
            sealed,
            expires_in_ms,
        };
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| error.to_string())?;
        send.write_all(&serde_json::to_vec(&read).map_err(|error| error.to_string())?)
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
    assert_eq!(gateway_info.allow, [REFERENCE]);

    // Face ID named the reference and the gateway
    assert_eq!(
        platform.prompts(),
        [(REFERENCE.to_owned(), "mini".to_owned())]
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
async fn a_new_reference_waits_until_allowed_and_can_be_removed_again() -> TestResult {
    let gateway = FakeGateway::start().await?;
    let (app, platform, _) = paired(&gateway).await?;
    let other = "op://Dev/other/credential";
    let prompts = platform.prompts().len();

    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(other, 30_000).await }
    });
    let state = until(&app, |state| waiting(state).is_some()).await?;
    let id = waiting(&state).ok_or("no read")?;
    assert!(state.reads.iter().any(|read| read.id == id && !read.listed));

    // neither answer goes until the owner allows the reference
    app.dispatch(AppAction::Approve { id: id.clone() });
    app.answer(id.clone(), "too-early".to_owned());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!reading.is_finished());
    assert_eq!(platform.prompts().len(), prompts);

    app.dispatch(AppAction::Allow { id: id.clone() });
    until(&app, |state| {
        state.reads.iter().any(|read| read.id == id && read.listed)
    })
    .await?;
    app.dispatch(AppAction::Approve { id });
    assert_eq!(reading.await??, CompanionResponse::Value(VALUE.to_owned()));

    // it is remembered: the next read of it is answered without asking
    // again, and the list keeps it across a relaunch
    let reading = tokio::spawn({
        let gateway = gateway.clone();
        async move { gateway.read(other, 30_000).await }
    });
    let state = until(&app, |state| waiting(state).is_some()).await?;
    let id = waiting(&state).ok_or("no read")?;
    assert!(state.reads.iter().any(|read| read.id == id && read.listed));
    app.dispatch(AppAction::Approve { id });
    assert_eq!(reading.await??, CompanionResponse::Value(VALUE.to_owned()));

    drop(app);
    let relaunched = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    let allow = relaunched.state().gateway.ok_or("no gateway")?.allow;
    assert_eq!(allow, [REFERENCE, other]);

    // removing it from the list sticks too
    relaunched.dispatch(AppAction::Disallow {
        reference: other.to_owned(),
    });
    until(&relaunched, |state| {
        state
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.allow == [REFERENCE])
    })
    .await?;
    drop(relaunched);
    let relaunched = FfiApp::start(Arc::new(Shared(Arc::clone(&platform)))).await?;
    let allow = relaunched.state().gateway.ok_or("no gateway")?.allow;
    assert_eq!(allow, [REFERENCE]);

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
