//! Reading references through a phone: a fake phone (an iroh endpoint with a
//! software P-256 key standing in for the Secure Enclave) that dials the
//! gateway when a fake APNs server receives the push for it, as the app does
//! when the owner taps the notification

use std::{
    error::Error,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use codemode_mcp::{
    app::App,
    companion::{
        self, CompanionErrorCode, CompanionFault, CompanionResponse, InviteTicket, MOBILE_ALPN,
        PAIR_ALPN, PairCheck, PairRequest, PairResponse, ProgramValue, Registration, Role,
        mobile::{
            PhoneHandoffRequest, PhoneProgramRead, PhoneProgramRequest, PhoneRead,
            PhoneRegistration, PhoneRequest, PhoneResponse, ProgramItem, PushEnvironment,
            PushToken,
        },
    },
    config::Config,
    logins::{FieldKind, FocusedField},
    mac::TouchId,
    secrets::PHONE_GRACE,
};
use companion_wire::{
    mobile::{LoginField, RequestId},
    seal::SoftwareKey,
    takeover::{
        EndReason, GatewayFrame, GatewayMessage, HEADER_BYTES, PhoneMessage, Point, RunningSession,
        Secret, TAKEOVER_ALPN, Viewport, decode_gateway, encode_message, read_header,
    },
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, TransportAddr,
    endpoint::{Connection, presets},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{
    fake_cdp::{FakeCdp, Field},
    harness::{
        FakeMac, Harness, Setup, Stop, TestResult, approval_id, execute, temp_state_dir, text_of,
    },
    secrets::{VALUE, fake_op, reads},
};

const REFERENCE: &str = "op://Dev/fixture/credential";
const TOKEN: &str = "00aa11bb22cc33dd44ee55ff66778899";
const KEY_ID: &str = "KEYID12345";
const TEAM_ID: &str = "Q8UP8C53Y8";

/// How the fake phone answers a read
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Opens the sealed value, as an approved Face ID does
    Open,
    /// Refuses, as a cancelled Face ID does
    Deny,
    /// Leaves the prompt up until the gateway takes it down
    Hang,
    /// Sends this value, as the owner pasting or filling it in does
    Enter(&'static str),
}

/// A read as the fake phone received it
#[derive(Clone, Debug)]
struct Seen {
    id: String,
    reference: String,
    expires_in_ms: u64,
    /// The read came with a copy sealed to the phone
    sealed: bool,
    /// The gateway stopped the stream before the phone answered
    withdrawn: bool,
    /// A program read's items: each reference, or the description in
    /// quotes, with ` (sealed)` when a copy came with it; empty for a read
    /// of one reference
    items: Vec<String>,
    /// A program read's reason
    reason: Option<String>,
}

/// One push as the fake APNs server received it
#[derive(Clone, Debug)]
struct Push {
    token: String,
    headers: HeaderMap,
    body: Value,
}

/// An APNs stand-in that records each push and hands its body to the phone
struct FakeApns {
    address: SocketAddr,
    pushes: Arc<Mutex<Vec<Push>>>,
    key_file: PathBuf,
    /// The public half of the provider key, for checking the JWT
    public: Vec<u8>,
}

#[derive(Clone)]
struct ApnsState {
    pushes: Arc<Mutex<Vec<Push>>>,
    wake: mpsc::UnboundedSender<Value>,
}

async fn record_push(
    State(state): State<ApnsState>,
    UrlPath(token): UrlPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> StatusCode {
    if let Ok(mut pushes) = state.pushes.lock() {
        pushes.push(Push {
            token,
            headers,
            body: body.clone(),
        });
    }
    let _ = state.wake.send(body);

    StatusCode::OK
}

impl FakeApns {
    async fn start(wake: mpsc::UnboundedSender<Value>) -> Result<Self, Box<dyn Error>> {
        // the `.p8` Apple would issue: a PKCS#8 P-256 key in PEM
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| "cannot generate a P-256 key")?;
        let public = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .map_err(|_| "cannot read the generated key")?
            .public_key()
            .as_ref()
            .to_vec();
        let encoded = STANDARD.encode(pkcs8.as_ref());
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(std::str::from_utf8)
            .collect::<Result<_, _>>()?;
        let directory = temp_state_dir();
        std::fs::create_dir_all(&directory)?;
        let key_file = directory.join("AuthKey.p8");
        std::fs::write(
            &key_file,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                lines.join("\n")
            ),
        )?;

        let pushes = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/3/device/{token}", post(record_push))
            .with_state(ApnsState {
                pushes: Arc::clone(&pushes),
                wake,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok(Self {
            address,
            pushes,
            key_file,
            public,
        })
    }

    fn pushes(&self) -> Vec<Push> {
        self.pushes
            .lock()
            .map(|pushes| pushes.clone())
            .unwrap_or_default()
    }

    /// The claims of a push's provider token, once its signature checks out
    /// against the key the gateway was given
    fn verify(&self, push: &Push) -> Result<(String, Value), Box<dyn Error>> {
        let bearer = push
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                value
                    .strip_prefix("bearer ")
                    .or(value.strip_prefix("Bearer "))
            })
            .ok_or("the push has no bearer token")?;
        let kid = jsonwebtoken::decode_header(bearer)?
            .kid
            .ok_or("the token names no key")?;
        let (x, y) = self.public[1..].split_at(32);
        let key = DecodingKey::from_ec_components(
            &URL_SAFE_NO_PAD.encode(x),
            &URL_SAFE_NO_PAD.encode(y),
        )?;
        // APNs tokens carry `iat` only
        let mut validation = Validation::new(Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let claims = jsonwebtoken::decode::<Value>(bearer, &key, &validation)?.claims;

        Ok((kid, claims))
    }
}

/// The phone: its iroh identity, its seal key and what it saw
#[derive(Clone)]
struct FakePhone {
    endpoint: Endpoint,
    key: Arc<SoftwareKey>,
    gateway: EndpointId,
    gateway_address: SocketAddr,
    answer: Arc<Mutex<Answer>>,
    /// A file that must exist before the phone opens a value, so a test can
    /// order the answer after another source has started
    gate: Arc<Mutex<Option<PathBuf>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakePhone {
    async fn start(
        gateway: EndpointId,
        gateway_address: SocketAddr,
    ) -> Result<Self, Box<dyn Error>> {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(iroh::SecretKey::generate())
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await?;

        Ok(Self {
            endpoint,
            key: Arc::new(SoftwareKey::generate()?),
            gateway,
            gateway_address,
            answer: Arc::new(Mutex::new(Answer::Open)),
            gate: Arc::new(Mutex::new(None)),
            seen: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    fn set_answer(&self, answer: Answer) {
        if let Ok(mut slot) = self.answer.lock() {
            *slot = answer;
        }
    }

    fn answer_once(&self, path: PathBuf) {
        if let Ok(mut slot) = self.gate.lock() {
            *slot = Some(path);
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    }

    async fn dial(&self, alpn: &[u8]) -> Result<Connection, Box<dyn Error>> {
        let address =
            EndpointAddr::from_parts(self.gateway, [TransportAddr::Ip(self.gateway_address)]);

        Ok(self.endpoint.connect(address, alpn).await?)
    }

    /// Dials the gateway and answers the reads it sends until it hangs up
    async fn connect(&self) -> Result<Connection, Box<dyn Error>> {
        let connection = self.dial(MOBILE_ALPN).await?;
        let phone = self.clone();
        let serving = connection.clone();
        tokio::spawn(async move { phone.serve(serving).await });

        Ok(connection)
    }

    /// Dials once for each push, as the app does when it is opened from one
    fn answer_pushes(&self, mut wake: mpsc::UnboundedReceiver<Value>) {
        let phone = self.clone();
        tokio::spawn(async move {
            while wake.recv().await.is_some() {
                let _ = phone.connect().await;
            }
        });
    }

    async fn serve(&self, connection: Connection) {
        while let Ok((mut send, mut receive)) = connection.accept_bi().await {
            let Ok(body) = receive.read_to_end(64 * 1024).await else {
                return;
            };
            if let Ok(request) = serde_json::from_slice::<PhoneHandoffRequest>(&body) {
                // answered through the takeover, as the app does
                if let Ok(mut seen) = self.seen.lock() {
                    seen.push(Seen {
                        id: request.handoff.id.to_string(),
                        reference: format!("handoff {}", request.handoff.session),
                        expires_in_ms: request.handoff.expires_in_ms,
                        sealed: false,
                        withdrawn: false,
                        items: Vec::new(),
                        reason: request.handoff.reason,
                    });
                }
                let _ = send.stopped().await;
                continue;
            }
            let Ok(read) = serde_json::from_slice::<PhoneRead>(&body) else {
                let Ok(program) = serde_json::from_slice::<PhoneProgramRequest>(&body) else {
                    return;
                };
                let response = self.answer_program(&program.program_read);
                let Ok(bytes) = serde_json::to_vec(&response) else {
                    return;
                };
                if send.write_all(&bytes).await.is_err() || send.finish().is_err() {
                    return;
                }
                continue;
            };
            let index = self.seen.lock().map_or(0, |mut seen| {
                seen.push(Seen {
                    id: read.id.to_string(),
                    reference: read.reference.clone(),
                    expires_in_ms: read.expires_in_ms,
                    sealed: read.sealed.is_some(),
                    withdrawn: false,
                    items: Vec::new(),
                    reason: None,
                });

                seen.len() - 1
            });
            let answer = self.answer.lock().map_or(Answer::Deny, |answer| *answer);
            let gate = self.gate.lock().ok().and_then(|gate| gate.clone());
            if let Some(gate) = gate {
                for _ in 0..500 {
                    if gate.exists() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }

            let response = match answer {
                Answer::Open => match read
                    .sealed
                    .as_ref()
                    .ok_or_else(|| "no sealed copy".to_owned())
                    .and_then(|sealed| {
                        self.key
                            .open(&self.gateway, &read.reference, sealed)
                            .map_err(|error| error.to_string())
                    }) {
                    Ok(value) => {
                        CompanionResponse::Value(String::from_utf8_lossy(&value).into_owned())
                    }
                    Err(message) => CompanionResponse::Error(CompanionFault {
                        code: CompanionErrorCode::ReadFailed,
                        message,
                    }),
                },
                Answer::Enter(value) => CompanionResponse::Value(value.to_owned()),
                Answer::Deny => CompanionResponse::Error(CompanionFault {
                    code: CompanionErrorCode::Denied,
                    message: "not approved on this phone".to_owned(),
                }),
                Answer::Hang => {
                    let _ = send.stopped().await;
                    if let Ok(mut seen) = self.seen.lock()
                        && let Some(seen) = seen.get_mut(index)
                    {
                        seen.withdrawn = true;
                    }

                    continue;
                }
            };
            let Ok(bytes) = serde_json::to_vec(&response) else {
                return;
            };
            if send.write_all(&bytes).await.is_err() || send.finish().is_err() {
                return;
            }
        }
    }

    /// Answers a program read as the app does: sealed copies are opened
    /// with one Face ID, and each item without one gets the value of
    /// [`Answer::Enter`]
    fn answer_program(&self, read: &PhoneProgramRead) -> CompanionResponse {
        let items = read
            .items
            .iter()
            .map(|item| match item {
                ProgramItem::Reference {
                    reference, sealed, ..
                } => {
                    format!(
                        "{reference}{}",
                        if sealed.is_some() { " (sealed)" } else { "" }
                    )
                }
                ProgramItem::Describe { description, .. } => format!("\"{description}\""),
            })
            .collect();
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(Seen {
                id: read.id.to_string(),
                reference: String::new(),
                expires_in_ms: read.expires_in_ms,
                sealed: false,
                withdrawn: false,
                items,
                reason: read.reason.clone(),
            });
        }
        let answer = self.answer.lock().map_or(Answer::Deny, |answer| *answer);
        let entered = match answer {
            Answer::Enter(value) => Some(value),
            Answer::Open => None,
            Answer::Deny | Answer::Hang => {
                return CompanionResponse::Error(CompanionFault {
                    code: CompanionErrorCode::Denied,
                    message: "not approved on this phone".to_owned(),
                });
            }
        };

        let mut values = Vec::new();
        for item in &read.items {
            let value = match (item, entered) {
                (
                    ProgramItem::Reference {
                        reference,
                        sealed: Some(sealed),
                        ..
                    },
                    _,
                ) => self
                    .key
                    .open(&self.gateway, reference, sealed)
                    .map(|value| String::from_utf8_lossy(&value).into_owned())
                    .map_err(|error| error.to_string()),
                (_, Some(entered)) => Ok(entered.to_owned()),
                (_, None) => Err("no sealed copy and nothing entered".to_owned()),
            };
            match value {
                Ok(value) => values.push(ProgramValue::from(value)),
                Err(message) => {
                    return CompanionResponse::Error(CompanionFault {
                        code: CompanionErrorCode::ReadFailed,
                        message,
                    });
                }
            }
        }

        CompanionResponse::Values(values)
    }

    /// Sends one request of the phone's own and reads the answer
    async fn request(
        &self,
        connection: &Connection,
        request: &PhoneRequest,
    ) -> Result<PhoneResponse, Box<dyn Error>> {
        let (mut send, mut receive) = connection.open_bi().await?;
        send.write_all(&serde_json::to_vec(request)?).await?;
        send.finish()?;

        Ok(serde_json::from_slice(
            &receive.read_to_end(64 * 1024).await?,
        )?)
    }

    fn push_token() -> PushToken {
        PushToken {
            token: TOKEN.to_owned(),
            environment: PushEnvironment::Development,
        }
    }
}

/// A port nothing listens on, for the gateway's `secrets.listen`
fn free_port() -> Result<u16, Box<dyn Error>> {
    Ok(std::net::UdpSocket::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// An `op` that answers like [`fake_op`] after `delay_secs`
fn slow_op(delay_secs: u64) -> Result<PathBuf, Box<dyn Error>> {
    let (inner, _) = fake_op()?;
    let program = inner.with_file_name("slow-op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\nsleep {delay_secs}\nexec '{inner}' \"$@\"\n",
            inner = inner.display()
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok(program)
}

/// An `op` that logs its pid and never answers
fn hanging_op() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let program = directory.join("op");
    let pid = directory.join("pid");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\necho $$ > '{pid}.tmp'\nmv '{pid}.tmp' '{pid}'\nexec sleep 60\n",
            pid = pid.display()
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok((program, pid))
}

/// A gateway with the fake phone listed, the fake APNs server configured,
/// and the phone's copy of [`REFERENCE`] already sealed by the twin server's
/// first read through the gateway's own `op`
struct Rig {
    harness: Harness,
    phone: FakePhone,
    apns: FakeApns,
    /// `op` reads the gateway made itself
    local_log: PathBuf,
    /// The Mac companion's prompts, when the rig has one
    companion_mac: Option<Arc<FakeMac>>,
    /// The gateway's own Mac, where the owner is while the rig starts
    gateway_mac: Arc<FakeMac>,
    companion: Option<companion::CompanionHandle>,
}

#[derive(Default)]
struct Options {
    /// Also list a Mac companion whose Touch ID prompt stays up
    with_mac_companion: bool,
    /// Also serve `logins`, with a notifier so its fills can be approved
    /// on the passkey page while the owner is away
    logins: bool,
    /// Also serve `browser`, on the sessions of this `agent-browser`
    browser: Option<PathBuf>,
    /// The sessions' profiles, for `browser_profiles`
    browser_profiles: Option<PathBuf>,
}

impl Rig {
    async fn start(options: Options) -> Result<Option<Self>, Box<dyn Error>> {
        let directory = temp_state_dir();
        std::fs::create_dir_all(&directory)?;
        let gateway_key = directory.join("gateway.key");
        let gateway = companion::load_or_create(Role::Gateway, Some(&gateway_key))?.public();
        let listen = SocketAddr::from(([127, 0, 0, 1], free_port()?));

        let (wake, woken) = mpsc::unbounded_channel();
        let apns = FakeApns::start(wake).await?;
        let phone = FakePhone::start(gateway, listen).await?;
        phone.answer_pushes(woken);

        let (companion, companion_mac, companion_line) = if options.with_mac_companion {
            let (companion_op, _) = fake_op()?;
            let mac = Arc::new(FakeMac::default());
            mac.set_answer(None);
            let text = format!(
                "[companion]\n\
                 gateway = \"{gateway}\"\n\
                 gateway_name = \"main\"\n\
                 listen = \"127.0.0.1:0\"\n\
                 discovery = false\n\
                 identity_file = \"{key}\"\n\
                 op = \"{op}\"\n",
                key = directory.join("companion.key").display(),
                op = companion_op.display(),
            );
            let config = Config::parse(&text, Path::new("companion.toml"))?;
            let handle = companion::serve(
                config.companion.ok_or("the companion section is missing")?,
                Some(Arc::clone(&mac) as Arc<dyn codemode_mcp::mac::Mac>),
            )
            .await?;
            let address = handle
                .bound_addrs()
                .into_iter()
                .find(SocketAddr::is_ipv4)
                .ok_or("the companion bound no IPv4 socket")?;
            let line = format!(
                "companions = [{{ name = \"mba\", id = \"{}\", addrs = [\"{address}\"] }}]\n",
                handle.id()
            );

            (Some(handle), Some(mac), line)
        } else {
            (None, None, String::new())
        };

        let (local_op, local_log) = fake_op()?;
        // the owner is at the gateway for the first read, so its own `op`
        // runs and its value is sealed to the phone
        let gateway_mac = Arc::new(FakeMac::default());
        gateway_mac.set_present(true);
        let mut top = options
            .browser
            .as_ref()
            .map(|path| format!("agent_browser_path = \"{}\"\n", path.display()))
            .unwrap_or_default();
        if let Some(profiles) = &options.browser_profiles {
            top.push_str(&format!("browser_profiles = \"{}\"\n", profiles.display()));
        }
        let extra = format!(
            "[secrets]\n\
             op = \"{op}\"\n\
             discovery = false\n\
             listen = \"{listen}\"\n\
             identity_file = \"{key}\"\n\
             {companion_line}\
             phones = [{{ name = \"iphone\", id = \"{phone}\", seal_key = \"{seal}\" }}]\n\
             apns = {{ key_file = \"{key_file}\", key_id = \"{KEY_ID}\", team_id = \"{TEAM_ID}\", server = \"http://{apns}\" }}\n\n\
             [servers.secrets]\n\
             builtin = \"secrets\"\n\n\
             [servers.twin]\n\
             command = \"{fixture}\"\n\
             env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n\n\
             {logins}\n\
             {browser}",
            browser = if options.browser.is_some() {
                "[servers.browser]\n\
                 builtin = \"browser\"\n\
                 policy = \"ask\"\n\
                 tools.fill.grant = \"per_call\"\n\
                 tools.handoff.policy = \"allow\"\n"
            } else {
                ""
            },
            op = local_op.display(),
            key = gateway_key.display(),
            phone = phone.id(),
            seal = phone.key.public().to_base64(),
            key_file = apns.key_file.display(),
            apns = apns.address,
            fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
            logins = if options.logins {
                "[servers.logins]\n\
                 builtin = \"logins\"\n\
                 policy = \"ask\"\n\
                 tools.fill.grant = \"per_call\"\n"
            } else {
                ""
            },
        );
        let Some(harness) = Harness::with(Setup {
            extra: &extra,
            top: &top,
            notify: options.logins || options.browser.is_some(),
            mac: Some(Arc::clone(&gateway_mac)),
            ..Setup::default()
        })
        .await?
        else {
            return Ok(None);
        };
        // the twin server read once as it connected
        assert_eq!(reads(&local_log, REFERENCE), 1);

        // the phone dials in once, as the app does after pairing, and tells
        // the gateway where to push; then its app is suspended
        harness
            .app
            .gateway()
            .companions()
            .listen_for_phones()
            .await?;
        let connection = phone.connect().await?;
        let registered = phone
            .request(
                &connection,
                &PhoneRequest::PushToken(Some(FakePhone::push_token())),
            )
            .await?;
        assert_eq!(registered, PhoneResponse::Done);
        connection.close(0_u32.into(), b"suspended");

        Ok(Some(Self {
            harness,
            phone,
            apns,
            local_log,
            companion_mac,
            gateway_mac,
            companion,
        }))
    }

    async fn check(&self) -> Result<Value, Box<dyn Error>> {
        let (status, checked) = self
            .harness
            .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
            .await?;
        assert_eq!(status, 200, "{checked}");

        Ok(checked)
    }

    /// The phone's entry in a `companion check` answer
    fn phone_entry(checked: &Value) -> Value {
        checked["companions"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["name"] == "iphone"))
            .cloned()
            .unwrap_or(Value::Null)
    }

    async fn stop(self) -> TestResult {
        if let Some(companion) = self.companion {
            companion.shutdown().await;
        }

        self.harness.stop().await
    }
}

/// Every byte under `directory`, to show a value was never written there
fn files_contain(directory: &Path, needle: &[u8]) -> Result<bool, Box<dyn Error>> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if files_contain(&path, needle)? {
                return Ok(true);
            }
        } else if std::fs::read(&path)?
            .windows(needle.len())
            .any(|window| window == needle)
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_wakes_the_phone_and_it_opens_the_copy_sealed_to_it() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let checked = rig.check().await?;
    assert_eq!(
        Rig::phone_entry(&checked),
        json!({ "name": "iphone", "result": { "ok": { "bytes": VALUE.len() } } }),
        "{checked}"
    );

    // the read the phone got is the one the push named
    let pushes = rig.apns.pushes();
    let seen = rig.phone.seen();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!(seen.len(), 1, "{seen:?}");
    let push = &pushes[0];
    assert_eq!(push.body["request"], seen[0].id.as_str());
    assert_eq!(push.body["reference"], REFERENCE);
    assert_eq!(seen[0].reference, REFERENCE);
    assert!(
        seen[0].expires_in_ms > 0
            && u128::from(seen[0].expires_in_ms) <= companion::ASK_TIMEOUT.as_millis(),
        "{seen:?}"
    );
    assert!(push.body["gateway"].is_string());
    // the deadline, so a push tapped after it shows the read as gone
    let expires = push.body["expires"].as_u64().ok_or("no deadline")?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let longest = u64::try_from(companion::ASK_TIMEOUT.as_millis())?;
    assert!(expires > now && expires <= now + longest, "{expires} {now}");
    assert_eq!(push.body["aps"]["interruption-level"], "time-sensitive");

    // addressed and signed as APNs requires
    assert_eq!(push.token, TOKEN);
    let header = |name: &str| push.headers.get(name).and_then(|value| value.to_str().ok());
    assert_eq!(
        header("apns-topic"),
        Some("com.avencera.codemode-mcp.companion")
    );
    assert_eq!(header("apns-push-type"), Some("alert"));
    assert_eq!(header("apns-collapse-id"), Some(seen[0].id.as_str()));
    let (kid, claims) = rig.apns.verify(push)?;
    assert_eq!(kid, KEY_ID);
    assert_eq!(claims["iss"], TEAM_ID);

    // the value travels only inside the seal and the phone's answer
    assert!(!push.body.to_string().contains(VALUE));
    assert!(!checked.to_string().contains(VALUE), "{checked}");
    assert!(
        !files_contain(rig.harness.app.state_dir(), VALUE.as_bytes())?,
        "the value was written to the state directory"
    );

    // a refusal on the phone reads nothing
    rig.phone.set_answer(Answer::Deny);
    let checked = rig.check().await?;
    let message = Rig::phone_entry(&checked)["result"]["error"]["message"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_default();
    assert!(message.contains("denied"), "{checked}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_is_not_listed_is_refused() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let stranger = FakePhone::start(rig.phone.gateway, rig.phone.gateway_address).await?;
    let refused = match stranger.dial(MOBILE_ALPN).await {
        Ok(connection) => stranger
            .request(
                &connection,
                &PhoneRequest::PushToken(Some(FakePhone::push_token())),
            )
            .await
            .is_err(),
        Err(_) => true,
    };
    assert!(refused, "an unlisted phone was served");

    // and it is never pushed to or asked
    let checked = rig.check().await?;
    assert!(
        Rig::phone_entry(&checked)["result"]["ok"].is_object(),
        "{checked}"
    );
    assert!(stranger.seen().is_empty());

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_answers_first_takes_the_other_prompts_down() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let Rig {
        harness,
        phone,
        apns,
        companion_mac,
        companion,
        ..
    } = rig;
    let companion_mac = companion_mac.ok_or("no companion")?;
    let dismissals = || {
        companion_mac
            .shown()
            .iter()
            .filter(|line| *line == "dismissed")
            .count()
    };
    // the boot read's local `op` answers at once, so whether the
    // companion's prompt came up before it won depends on timing
    let before = dismissals();

    // after a fresh restart the cache is empty: the owner is at the gateway, but
    // its 1Password prompt goes unanswered, and so does the companion's
    let (hanging, pid) = hanging_op()?;
    phone.answer_once(pid.clone());
    let harness = restart_fresh(harness, |config| {
        config.secrets.op = hanging.display().to_string();
    })
    .await?;

    let body = harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");
    assert_eq!(apns.pushes().len(), 1);
    assert_eq!(phone.seen().len(), 1);

    // the losers were taken down: the companion's prompt and the local
    // `op`
    let mut dismissed = 0;
    for _ in 0..40 {
        dismissed = dismissals();
        if dismissed == before + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(dismissed, before + 1, "{:?}", companion_mac.shown());
    let pid = std::fs::read_to_string(&pid)?;
    let mut alive = true;
    for _ in 0..40 {
        alive = std::process::Command::new("kill")
            .args(["-0", pid.trim()])
            .status()?
            .success();
        if !alive {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!alive, "the local op {} still runs", pid.trim());

    if let Some(companion) = companion {
        companion.shutdown().await;
    }
    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_answered_elsewhere_withdraws_the_phone_prompt() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let Rig {
        harness,
        phone,
        apns,
        local_log,
        ..
    } = rig;
    phone.set_answer(Answer::Hang);

    // after a restart the owner at the gateway answers 1Password within
    // the phones' grace, so the phone is never pushed or asked
    let quick = slow_op(1)?;
    let harness = restart_fresh(harness, |config| {
        config.secrets.op = quick.display().to_string();
    })
    .await?;
    let body = harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");
    tokio::time::sleep(PHONE_GRACE).await;
    assert!(apns.pushes().is_empty(), "{:?}", apns.pushes());
    assert!(phone.seen().is_empty(), "{:?}", phone.seen());

    // and again, slowly enough that the phone has its prompt up first
    let slow = slow_op(PHONE_GRACE.as_secs() + 2)?;
    let harness = restart_fresh(harness, |config| {
        config.secrets.op = slow.display().to_string();
    })
    .await?;
    let body = harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");

    let mut seen = phone.seen();
    for _ in 0..40 {
        if seen.first().is_some_and(|seen| seen.withdrawn) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        seen = phone.seen();
    }
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].withdrawn, "the phone's prompt stayed up: {seen:?}");
    // the first boot's read; the slow `op` logs elsewhere
    assert_eq!(reads(&local_log, REFERENCE), 1);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_check_can_ask_one_device_and_finishes_when_it_answers() -> TestResult {
    // the Mac companion's prompt stays up until the 120 s limit, so a check
    // that asked it too would not return
    let Some(rig) = Rig::start(Options {
        with_mac_companion: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let companion_mac = rig.companion_mac.clone().ok_or("no companion")?;
    let asked = companion_mac.shown().len();

    let started = std::time::Instant::now();
    let (status, checked) = rig
        .harness
        .admin_json(
            "/admin/companion/check/one",
            &json!({ "reference": REFERENCE, "companion": "iphone" }),
        )
        .await?;
    assert_eq!(status, 200, "{checked}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the check waited for the Mac"
    );
    let entries = checked["companions"].as_array().ok_or("no entries")?;
    assert_eq!(entries.len(), 1, "{checked}");
    assert!(entries[0]["result"]["ok"].is_object(), "{checked}");
    assert_eq!(entries[0]["name"], "iphone", "{checked}");
    assert_eq!(companion_mac.shown().len(), asked, "the Mac was asked too");

    // an unknown name is refused before anyone is asked, naming the real ones
    let (status, refused) = rig
        .harness
        .admin_json(
            "/admin/companion/check/one",
            &json!({ "reference": REFERENCE, "companion": "ipad" }),
        )
        .await?;
    assert_eq!(status, 400, "{refused}");
    let message = refused["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("ipad") && message.contains("mba, iphone"),
        "{refused}"
    );
    assert_eq!(companion_mac.shown().len(), asked, "{refused}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_off_run_beside_the_daemon_asks_the_macs_but_not_the_phone() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let companion_mac = rig.companion_mac.clone().ok_or("no companion")?;
    let asked = || {
        companion_mac
            .shown()
            .iter()
            .filter(|line| line.starts_with("touch_id"))
            .count()
    };
    let before = asked();

    // an `exec` while the daemon holds `secrets.listen`; its own `op` is
    // slow enough that the companion is asked first, and that a phone
    // would be pushed once its grace ran out
    let slow = slow_op(PHONE_GRACE.as_secs() + 2)?;
    let mut config = (**rig.harness.app.config()).clone();
    config.secrets.op = slow.display().to_string();
    let one_off = App::start_without_approvals(config).await?;
    one_off.gateway().wait_ready(Duration::from_secs(30)).await;
    let report = serde_json::to_value(one_off.gateway().report())?;
    one_off.shutdown().await;

    // the twin server started with the value the run's own `op` read
    assert!(report[0]["tools"].as_u64() > Some(0), "{report}");
    assert_eq!(asked(), before + 1, "{:?}", companion_mac.shown());
    assert!(rig.apns.pushes().is_empty(), "{:?}", rig.apns.pushes());
    assert!(rig.phone.seen().is_empty(), "{:?}", rig.phone.seen());

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_entered_on_the_phone_is_sealed_for_the_next_read() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let Rig { harness, phone, .. } = rig;
    let other = "op://Dev/other/credential";
    let entered = "entered-on-the-phone";
    let use_other = |config: &mut Config, op: &Path| {
        config.secrets.op = op.display().to_string();
        if let Some(server) = config.servers.get_mut("twin") {
            server
                .env
                .insert("FIXTURE_SECRET".to_owned(), format!("{{{{ {other} }}}}"));
        }
    };

    // a reference nothing has read yet, and 1Password at the gateway goes
    // unanswered: the phone is asked without a copy and the owner enters it
    phone.set_answer(Answer::Enter(entered));
    let (hanging, _) = hanging_op()?;
    let harness = restart_fresh(harness, |config| use_other(config, &hanging)).await?;
    let body = harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], entered, "{body}");
    let seen = phone.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].reference, other);
    assert!(!seen[0].sealed, "{seen:?}");

    // after a restart the phone opens the copy of what it entered
    phone.set_answer(Answer::Open);
    let (hanging, _) = hanging_op()?;
    let harness = restart_fresh(harness, |config| use_other(config, &hanging)).await?;
    let body = harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], entered, "{body}");
    let seen = phone.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen[1].sealed, "{seen:?}");

    harness.stop().await
}

/// A gateway with no phone yet, listening at a fixed address, whose `twin`
/// server read [`REFERENCE`] at boot; the owner is at its Mac, which leaves
/// Touch ID prompts up until a test sets an answer
async fn inviting_gateway()
-> Result<Option<(Harness, EndpointId, SocketAddr, Arc<FakeMac>)>, Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let gateway_key = directory.join("gateway.key");
    let gateway = companion::load_or_create(Role::Gateway, Some(&gateway_key))?.public();
    let listen = SocketAddr::from(([127, 0, 0, 1], free_port()?));
    let (op, _) = fake_op()?;
    let gateway_mac = Arc::new(FakeMac::default());
    gateway_mac.set_present(true);
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\
         discovery = false\n\
         listen = \"{listen}\"\n\
         identity_file = \"{key}\"\n\n\
         [servers.twin]\n\
         command = \"{fixture}\"\n\
         env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n",
        op = op.display(),
        key = gateway_key.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let harness = Harness::with(Setup {
        extra: &extra,
        mac: Some(Arc::clone(&gateway_mac)),
        ..Setup::default()
    })
    .await?;

    Ok(harness.map(|harness| (harness, gateway, listen, gateway_mac)))
}

/// The Touch ID prompts the gateway's Mac showed
fn touch_prompts(mac: &FakeMac) -> Vec<String> {
    mac.shown()
        .into_iter()
        .filter(|shown| shown.starts_with("touch_id "))
        .collect()
}

const PAIRING_PROMPT: &str = "touch_id Let a new phone or Mac pair with codemode-mcp";

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_is_opened_only_with_touch_id_at_the_gateway() -> TestResult {
    let Some((harness, _, _, gateway_mac)) = inviting_gateway().await? else {
        return Ok(());
    };
    let body = json!({ "valid_secs": 60 });
    let open = || harness.admin_json("/admin/companion/invite/open", &body);

    // the owner is away: refused at once, without a prompt anyone could
    // approve by accident
    gateway_mac.set_present(false);
    let (status, refused) = open().await?;
    assert_eq!(status, 403, "{refused}");
    let message = refused["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("pairing needs Touch ID at the gateway Mac"),
        "{refused}"
    );
    assert!(touch_prompts(&gateway_mac).is_empty());

    // the owner is there but denies
    gateway_mac.set_present(true);
    gateway_mac.set_answer(Some(TouchId::Review));
    let (status, refused) = open().await?;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(touch_prompts(&gateway_mac), [PAIRING_PROMPT]);

    // the prompt is taken down, as when the screen locks
    gateway_mac.set_answer(Some(TouchId::Away));
    let (status, refused) = open().await?;
    assert_eq!(status, 403, "{refused}");

    // no ticket was handed out, and pairing was never even offered
    assert!(refused.get("ticket").is_none(), "{refused}");
    assert!(harness.app.gateway().companions().bound_addrs().is_empty());
    let path = harness.app.config().path().ok_or("no config file")?;
    assert!(Config::load(path)?.secrets.phones.is_empty());

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_pairs_a_phone_and_seals_what_was_read_before_it() -> TestResult {
    let Some((harness, gateway, listen, gateway_mac)) = inviting_gateway().await? else {
        return Ok(());
    };
    gateway_mac.set_answer(Some(TouchId::Approved));

    let (status, opened) = harness
        .admin_json("/admin/companion/invite/open", &json!({ "valid_secs": 60 }))
        .await?;
    assert_eq!(status, 200, "{opened}");
    let ticket = InviteTicket::decode(opened["ticket"].as_str().ok_or("no ticket")?)?;
    assert_eq!(ticket.gateway, gateway);
    let invite = opened["invite"].as_str().ok_or("no invite id")?.to_owned();
    assert_eq!(touch_prompts(&gateway_mac), [PAIRING_PROMPT]);

    // what the app does with the scanned ticket
    let phone = FakePhone::start(gateway, listen).await?;
    let pairing = phone.dial(PAIR_ALPN).await?;
    let register = PairRequest::Register(Box::new(Registration {
        secret: ticket.secret.to_hex(),
        id: phone.id(),
        name: "iPhone".to_owned(),
        addrs: Vec::new(),
        phone: Some(PhoneRegistration {
            seal_key: phone.key.public().clone(),
            push: Some(FakePhone::push_token()),
        }),
    }));
    let answer = |connection: Connection, request: PairRequest| async move {
        let (mut send, mut receive) = connection.open_bi().await?;
        send.write_all(&serde_json::to_vec(&request)?).await?;
        send.finish()?;
        let response: PairResponse =
            serde_json::from_slice(&receive.read_to_end(64 * 1024).await?)?;

        Ok::<_, Box<dyn Error>>(response)
    };
    // naming another phone's id is refused before the invite is spent
    let impostor = PairRequest::Register(Box::new(Registration {
        secret: ticket.secret.to_hex(),
        id: iroh::SecretKey::generate().public(),
        name: "iPhone".to_owned(),
        addrs: Vec::new(),
        phone: Some(PhoneRegistration {
            seal_key: phone.key.public().clone(),
            push: None,
        }),
    }));
    let refused = answer(phone.dial(PAIR_ALPN).await?, impostor).await?;
    assert!(
        matches!(refused, PairResponse::Refused { .. }),
        "{refused:?}"
    );

    let PairResponse::Registered(registered) = answer(pairing.clone(), register).await? else {
        return Err("the phone was not registered".into());
    };
    assert_eq!(registered.name, "iPhone");
    assert_eq!(registered.references, [REFERENCE]);

    // listed in the config file, under its id and seal key
    let path = harness.app.config().path().ok_or("no config file")?;
    let listed = Config::load(path)?.secrets.phones;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, phone.id());
    assert_eq!(&listed[0].seal_key, phone.key.public());

    // the value the twin server read at boot was sealed at pairing, so the
    // check reads it through the phone straight away
    let _mobile = phone.connect().await?;
    let PairResponse::Checked(check) = answer(pairing.clone(), PairRequest::Check).await? else {
        return Err("no check answer".into());
    };
    assert_eq!(
        check,
        PairCheck::Read {
            reference: REFERENCE.to_owned(),
            bytes: VALUE.len(),
        }
    );
    pairing.close(0_u32.into(), b"done");

    let mut status = Value::Null;
    for _ in 0..40 {
        let (_, body) = harness
            .admin_json(
                "/admin/companion/invite/status",
                &json!({ "invite": invite }),
            )
            .await?;
        status = body;
        if status["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(status["state"], "done", "{status}");
    assert_eq!(status["phone"], true, "{status}");
    assert_eq!(status["in_use"], true, "{status}");

    // pairing wrote its trust record, so the next daemon, reading the
    // config file it was listed in, uses it too
    let reloaded = Config::load(path)?;
    let harness = harness
        .restart_with(Stop::Drain, move |config| *config = reloaded)
        .await?;
    let companions = harness.app.gateway().companions();
    assert_eq!(companions.phones().len(), 1);
    assert!(companions.untrusted().is_empty());

    harness.stop().await
}

/// What `/healthz` lists as untrusted
async fn untrusted_in_health(harness: &Harness) -> Result<Value, Box<dyn Error>> {
    let health: Value = harness
        .http
        .get(format!("{}/healthz", harness.base()))
        .send()
        .await?
        .json()
        .await?;

    Ok(health["untrusted_devices"].clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_added_to_the_config_by_hand_is_used_only_once_trusted() -> TestResult {
    // the rig lists its phone before the daemon has a trust key, so that
    // phone is trusted as the config stood then
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let Rig {
        harness,
        phone,
        gateway_mac,
        ..
    } = rig;

    // another process of this user lists its own phone and waits for a
    // restart
    let stranger = FakePhone::start(phone.gateway, phone.gateway_address).await?;
    let path = harness
        .app
        .config()
        .path()
        .ok_or("no config file")?
        .to_owned();
    let text = std::fs::read_to_string(&path)?;
    let entry = format!(
        "{{ name = \"stranger\", id = \"{}\", seal_key = \"{}\" }}, ",
        stranger.id(),
        stranger.key.public().to_base64()
    );
    std::fs::write(
        &path,
        text.replacen("phones = [", &format!("phones = [{entry}"), 1),
    )?;
    // `companion list` shows it at once, untrusted, so its fingerprint can
    // be checked before anyone trusts it
    let (status, listed_now) = harness
        .admin_json("/admin/companion/list", &Value::Null)
        .await?;
    assert_eq!(status, 200, "{listed_now}");
    let appended = listed_now["devices"]
        .as_array()
        .and_then(|devices| devices.iter().find(|device| device["name"] == "stranger"))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(appended["trusted"], false, "{listed_now}");
    assert!(appended["fingerprint"].is_string(), "{listed_now}");

    let reloaded = Config::load(&path)?;
    assert_eq!(reloaded.secrets.phones.len(), 2);
    let harness = harness
        .restart_with(Stop::Drain, move |config| *config = reloaded)
        .await?;

    // listed but not used: named as untrusted, refused at the handshake,
    // never asked and never sealed to
    assert_eq!(untrusted_in_health(&harness).await?, json!(["stranger"]));
    let (status, listed) = harness
        .admin_json("/admin/companion/list", &Value::Null)
        .await?;
    assert_eq!(status, 200, "{listed}");
    let trusted = |name: &str| {
        listed["devices"]
            .as_array()
            .and_then(|devices| devices.iter().find(|device| device["name"] == name))
            .map(|device| device["trusted"].clone())
    };
    assert_eq!(trusted("iphone"), Some(json!(true)), "{listed}");
    assert_eq!(trusted("stranger"), Some(json!(false)), "{listed}");

    // renamed in the file, an untrusted phone is listed under the name
    // `companion trust` would take
    let listed_text = std::fs::read_to_string(&path)?;
    std::fs::write(
        &path,
        listed_text.replacen("name = \"stranger\"", "name = \"renamed\"", 1),
    )?;
    let (_, renamed) = harness
        .admin_json("/admin/companion/list", &Value::Null)
        .await?;
    let names: Vec<&str> = renamed["devices"]
        .as_array()
        .map(|devices| {
            devices
                .iter()
                .filter_map(|device| device["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, ["iphone", "renamed"], "{renamed}");
    std::fs::write(&path, listed_text)?;
    let refused = match stranger.dial(MOBILE_ALPN).await {
        Ok(connection) => stranger
            .request(
                &connection,
                &PhoneRequest::PushToken(Some(FakePhone::push_token())),
            )
            .await
            .is_err(),
        Err(_) => true,
    };
    assert!(refused, "an untrusted phone was served");
    let (status, checked) = harness
        .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
        .await?;
    assert_eq!(status, 200, "{checked}");
    let names: Vec<&str> = checked["companions"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, ["iphone"], "{checked}");
    assert!(
        Rig::phone_entry(&checked)["result"]["ok"].is_object(),
        "{checked}"
    );
    let one = json!({ "reference": REFERENCE, "companion": "stranger" });
    let check_stranger = || harness.admin_json("/admin/companion/check/one", &one);
    let (status, refused) = check_stranger().await?;
    assert_eq!(status, 400, "{refused}");
    assert!(stranger.seen().is_empty());

    // trusting it takes the owner's Touch ID at the gateway Mac
    let name = json!({ "name": "stranger" });
    let trust = || harness.admin_json("/admin/companion/trust", &name);
    gateway_mac.set_present(false);
    let (status, refused) = trust().await?;
    assert_eq!(status, 403, "{refused}");
    assert!(touch_prompts(&gateway_mac).is_empty());
    gateway_mac.set_present(true);
    gateway_mac.set_answer(Some(TouchId::Review));
    let (status, refused) = trust().await?;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(untrusted_in_health(&harness).await?, json!(["stranger"]));

    // the file as it is now decides: taken out of it since the start, the
    // phone is not offered for trust at all
    let listed_text = std::fs::read_to_string(&path)?;
    std::fs::write(&path, listed_text.replacen(&entry, "", 1))?;
    let prompts = touch_prompts(&gateway_mac).len();
    gateway_mac.set_answer(Some(TouchId::Approved));
    let (status, refused) = trust().await?;
    assert_eq!(status, 400, "{refused}");
    assert_eq!(touch_prompts(&gateway_mac).len(), prompts);
    std::fs::write(&path, listed_text)?;

    let (status, trusted_now) = trust().await?;
    assert_eq!(status, 200, "{trusted_now}");
    assert_eq!(trusted_now["device"]["kind"], "phone", "{trusted_now}");
    // the prompt shows the fingerprint `companion list` gives, so the owner
    // can tell this phone from another listed under the same name
    let fingerprint = trusted_now["device"]["fingerprint"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(fingerprint.split(' ').count(), 6, "{trusted_now}");
    assert_eq!(
        touch_prompts(&gateway_mac).last().cloned(),
        Some(format!(
            "touch_id Trust the phone “stranger” ({fingerprint}) to answer and receive \
             codemode-mcp secrets"
        ))
    );
    assert_eq!(untrusted_in_health(&harness).await?, json!([]));

    // in use without a restart, holding a copy of what was read before
    let _mobile = stranger.connect().await?;
    let (status, checked) = check_stranger().await?;
    assert_eq!(status, 200, "{checked}");
    assert_eq!(
        checked["companions"][0]["result"]["ok"]["bytes"],
        VALUE.len(),
        "{checked}"
    );
    let seen = stranger.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].sealed, "{seen:?}");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_program_read_is_answered_on_the_phone_with_one_approval() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    rig.gateway_mac.set_present(false);
    rig.phone
        .set_answer(Answer::Enter("pushover-token-entered"));

    let (status, body) = rig
        .harness
        .admin_json(
            "/admin/op/read",
            &json!({
                "targets": [{ "reference": REFERENCE }, { "describe": "Pushover app token" }],
                "reason": "freezerwatch alerts",
            }),
        )
        .await?;

    // the sealed copy opens and the described item is filled in, in order
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({ "values": { "source": "iphone", "values": [VALUE, "pushover-token-entered"] } })
    );
    let program = rig
        .phone
        .seen()
        .into_iter()
        .find(|seen| !seen.items.is_empty())
        .ok_or("the phone saw no program read")?;
    assert_eq!(
        program.items,
        [
            format!("{REFERENCE} (sealed)"),
            "\"Pushover app token\"".to_owned()
        ]
    );
    assert_eq!(program.reason.as_deref(), Some("freezerwatch alerts"));
    // the push names the batch, not one reference
    let push = rig
        .apns
        .pushes()
        .into_iter()
        .rev()
        .find(|push| push.body["kind"] == "program")
        .ok_or("no push for the program read")?;
    let summary = push.body["summary"].as_str().unwrap_or_default();
    assert!(summary.contains("Pushover app token"), "{summary}");
    assert!(summary.contains("freezerwatch alerts"), "{summary}");
    assert!(push.body.get("reference").is_none(), "{}", push.body);
    // the owner was away, so the gateway's own `op` never ran for it
    assert_eq!(reads(&rig.local_log, REFERENCE), 1);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_find_with_a_destination_is_entered_on_the_phone_while_a_companion_mac_waits()
-> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    // away from every Mac: the companion's prompt stays up, and only the
    // phone can answer
    rig.gateway_mac.set_present(false);
    rig.phone
        .set_answer(Answer::Enter("pushover-token-entered"));
    let directory = std::fs::canonicalize({
        let directory = temp_state_dir();
        std::fs::create_dir_all(&directory)?;
        directory
    })?;
    let out = directory.join("token.txt");
    let out_arg = out.display().to_string();

    let (ok, stdout, stderr) = rig
        .harness
        .cli(&[
            "op",
            "find",
            "pushover",
            "token",
            "--out-file",
            out_arg.as_str(),
            "--reason",
            "freezerwatch alerts",
        ])
        .await?;
    assert!(ok, "{stderr}");
    assert_eq!(
        serde_json::from_str::<Value>(&stdout)?,
        json!({ "written": out_arg })
    );
    assert_eq!(std::fs::read_to_string(&out)?, "pushover-token-entered\n");
    assert_eq!(std::fs::metadata(&out)?.permissions().mode() & 0o777, 0o600);
    let program = rig
        .phone
        .seen()
        .into_iter()
        .find(|seen| !seen.items.is_empty())
        .ok_or("the phone saw no program read")?;
    assert_eq!(program.items, ["\"pushover token\"".to_owned()]);

    // byte for byte, as a text file shared from 1Password needs
    let exact = directory.join("token.pem");
    let exact_arg = exact.display().to_string();
    let (ok, _, stderr) = rig
        .harness
        .cli(&[
            "op",
            "find",
            "pushover",
            "token",
            "--out-file",
            exact_arg.as_str(),
            "--no-newline",
        ])
        .await?;
    assert!(ok, "{stderr}");
    assert_eq!(std::fs::read(&exact)?, b"pushover-token-entered");

    // a script's find writes the entered value into an env file instead
    let env = directory.join("superalert.secrets.env");
    let code = format!(
        "await secrets_find_references(query=\"pushover token\", reason=\"freezerwatch alerts\", \
         env_file=\"{path}\", var=\"APP_TOKEN\")",
        path = env.display()
    );
    let body = rig.harness.execute_body(&code).await?;
    assert_eq!(body["status"], "completed", "{body}");
    assert_eq!(
        body["result"],
        json!({
            "items": [],
            "more": 0,
            "approved_on": "iphone",
            "written": { "path": env.display().to_string(), "var": "APP_TOKEN" },
        })
    );
    assert_eq!(
        std::fs::read_to_string(&env)?,
        "APP_TOKEN=pushover-token-entered\n"
    );

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_read_at_the_gateway_drops_the_text_the_phone_entered_for_it() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let cert = "op://Dev/signing/cert.p12";
    let read = json!({ "targets": [{ "reference": cert }], "reason": "signing" });

    // with the owner away, text is entered on the phone for the file by
    // mistake, and the gateway keeps a copy of it sealed to the phone
    rig.gateway_mac.set_present(false);
    rig.phone.set_answer(Answer::Enter("typed-by-mistake"));
    let (status, body) = rig.harness.admin_json("/admin/op/read", &read).await?;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["values"]["values"], json!(["typed-by-mistake"]));

    // back at the gateway, the owner approves its own `op` reading the
    // real file
    rig.gateway_mac.set_present(true);
    rig.gateway_mac.set_answer(Some(TouchId::Approved));
    let (status, body) = rig.harness.admin_json("/admin/op/read", &read).await?;
    assert_eq!(status, 200, "{body}");
    assert!(body["values"]["values"][0]["base64"].is_string(), "{body}");

    // so the phone is next asked with no copy to open, not the mistaken one
    rig.gateway_mac.set_present(false);
    rig.phone.set_answer(Answer::Enter("entered-again"));
    let (status, body) = rig.harness.admin_json("/admin/op/read", &read).await?;
    assert_eq!(status, 200, "{body}");
    let asked: Vec<Vec<String>> = rig
        .phone
        .seen()
        .into_iter()
        .filter(|seen| !seen.items.is_empty())
        .map(|seen| seen.items)
        .collect();
    assert_eq!(asked.last(), Some(&vec![cert.to_owned()]), "{asked:?}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_owner_away_the_login_for_a_page_is_picked_on_the_phone() -> TestResult {
    let Some(rig) = Rig::start(Options {
        with_mac_companion: true,
        logins: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = rig.harness.enroll_passkey().await?;
    rig.gateway_mac.set_present(false);
    rig.gateway_mac.set_focused(FocusedField {
        kind: FieldKind::Secure,
        pages: vec!["https://accounts.example.co.uk/signin".to_owned()],
        browser: Some("Safari".to_owned()),
        ..FocusedField::default()
    });
    rig.phone.set_answer(Answer::Enter("picked-on-the-phone"));
    let companion_mac = rig.companion_mac.clone().ok_or("no companion Mac")?;
    let before = companion_mac.shown();

    // 1Password cannot be searched with the owner away, so the owner
    // approves the page, then picks its login on the phone
    let pending = rig
        .harness
        .execute_body(r#"await logins_fill(field="password")"#)
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    // the approval page leads with what the gateway found, not only the
    // arguments
    let id = approval_id(&pending)?;
    let page = rig
        .harness
        .http
        .get(format!("{}/approve/{id}", rig.harness.base()))
        .send()
        .await?
        .text()
        .await?;
    assert!(
        page.contains(
            r#"<p class="summary">password into accounts.example.co.uk in Safari, picked on the phone</p>"#
        ),
        "{page}"
    );
    let (status, body) = rig
        .harness
        .approve_with_passkey(&mut passkey, &id, "once")
        .await?;
    assert_eq!(status, 200, "{body}");
    let execution = pending["execution_id"].as_str().unwrap_or_default();
    let done: Value = serde_json::from_str(&text_of(&rig.harness.wait_done(execution).await?))?;
    assert_eq!(
        done["result"],
        json!({ "field": "password", "host": "accounts.example.co.uk" }),
        "{done}"
    );
    assert_eq!(rig.gateway_mac.typed(), "picked-on-the-phone");
    assert!(!done.to_string().contains("picked-on-the-phone"), "{done}");

    let program = rig
        .phone
        .seen()
        .into_iter()
        .find(|seen| !seen.items.is_empty())
        .ok_or("the phone saw no program read")?;
    assert_eq!(program.items, ["\"password for example.co.uk\"".to_owned()]);
    assert_eq!(
        program.reason.as_deref(),
        Some("sign in on accounts.example.co.uk")
    );
    // a Mac can only search, which would answer no value, so the companion
    // Mac is never asked
    assert_eq!(companion_mac.shown(), before);

    rig.stop().await
}

/// Restarts cleanly after forgetting the secrets, as `service restart
/// --fresh` does, so the next daemon reads each again instead of taking them
/// over
async fn restart_fresh(
    harness: Harness,
    change: impl FnOnce(&mut Config),
) -> Result<Harness, Box<dyn Error>> {
    let (status, body) = harness
        .admin_json("/admin/secrets/forget", &Value::Null)
        .await?;
    assert_eq!(status, 200, "{body}");

    harness.restart_with(Stop::Drain, change).await
}

/// A takeover link the test drives as the app would
struct Takeover {
    send: iroh::endpoint::SendStream,
    receive: iroh::endpoint::RecvStream,
}

impl Takeover {
    /// A link with nothing sent on it yet
    async fn dial(phone: &FakePhone) -> Result<Self, Box<dyn Error>> {
        let connection = phone.dial(TAKEOVER_ALPN).await?;
        let (send, receive) = connection.open_bi().await?;

        Ok(Self { send, receive })
    }

    async fn open(
        phone: &FakePhone,
        session: &str,
        handoff: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let handoff = handoff
            .map(|id| RequestId::try_from(id.to_owned()))
            .transpose()?;
        Self::opened(phone, session, handoff, None).await
    }

    /// A takeover of `session` that starts it at `url`, as New session does
    async fn start(phone: &FakePhone, session: &str, url: &str) -> Result<Self, Box<dyn Error>> {
        Self::opened(phone, session, None, Some(url.to_owned())).await
    }

    async fn opened(
        phone: &FakePhone,
        session: &str,
        handoff: Option<RequestId>,
        start: Option<String>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut takeover = Self::dial(phone).await?;
        takeover
            .send(&PhoneMessage::Open {
                session: session.to_owned(),
                handoff,
                viewport: Viewport {
                    width: 390,
                    height: 844,
                    scale: 3.0,
                },
                start,
            })
            .await?;

        Ok(takeover)
    }

    async fn send(&mut self, message: &PhoneMessage) -> Result<(), Box<dyn Error>> {
        self.send.write_all(&encode_message(message)?).await?;

        Ok(())
    }

    async fn next(&mut self) -> Result<GatewayFrame, Box<dyn Error>> {
        let mut header = [0; HEADER_BYTES];
        tokio::time::timeout(
            Duration::from_secs(10),
            self.receive.read_exact(&mut header),
        )
        .await??;
        let (kind, length) = read_header(header)?;
        let mut body = vec![0; length];
        self.receive.read_exact(&mut body).await?;

        Ok(decode_gateway(kind, &body)?)
    }

    /// Frames until one `pick` takes, acknowledging each image
    async fn until<T>(
        &mut self,
        mut pick: impl FnMut(&GatewayFrame) -> Option<T>,
    ) -> Result<T, Box<dyn Error>> {
        loop {
            let frame = self.next().await?;
            if let Some(picked) = pick(&frame) {
                return Ok(picked);
            }
            if let GatewayFrame::Screen(screen) = &frame {
                self.send(&PhoneMessage::Ack {
                    seq: screen.header.seq,
                })
                .await?;
            }
        }
    }
}

async fn eventually<T>(mut probe: impl FnMut() -> Option<T>) -> Result<T, Box<dyn Error>> {
    for _ in 0..500 {
        if let Some(found) = probe() {
            return Ok(found);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    Err("timed out".into())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handoff_is_taken_over_on_the_phone_and_ends_when_the_owner_is_done() -> TestResult {
    let cdp = FakeCdp::start("https://github.com/login").await?;
    let Some(rig) = Rig::start(Options {
        browser: Some(cdp.program.clone()),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let pending = rig
        .harness
        .execute_body(r#"await browser_handoff(session="test", reason="approve the passkey")"#)
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    // the push wakes the phone, which is offered the handoff
    let handoff = eventually(|| {
        rig.phone
            .seen()
            .into_iter()
            .find(|seen| seen.reference == "handoff test")
    })
    .await?;
    assert_eq!(handoff.reason.as_deref(), Some("approve the passkey"));
    let push = rig
        .apns
        .pushes()
        .into_iter()
        .find(|push| push.body["kind"] == "handoff")
        .ok_or("no handoff push")?;
    assert_eq!(push.body["session"], "test", "{}", push.body);
    assert_eq!(push.body["request"], handoff.id.as_str(), "{}", push.body);

    let mut takeover = Takeover::open(&rig.phone, "test", Some(&handoff.id)).await?;
    // the page and its images, each image drawn and acknowledged before the
    // next comes
    let mut url = None;
    let mut last = None;
    let mut images = Vec::new();
    let seq = takeover
        .until(|frame| {
            match frame {
                GatewayFrame::Message(GatewayMessage::Page { url: page, .. }) => {
                    url = Some(page.clone());
                }
                GatewayFrame::Screen(screen) => {
                    last = Some(screen.header.seq);
                    images.push((
                        screen.header.width,
                        screen.header.height,
                        screen.jpeg.clone(),
                    ));
                }
                GatewayFrame::Message(_) => {}
            }

            last.filter(|seq| *seq == 2 && url.is_some())
        })
        .await?;
    assert_eq!(url.as_deref(), Some("https://github.com/login"));
    // the browser's blurry screencast images are captured again at the
    // phone's scale, and the repeat each capture brings on is not sent
    assert!(
        images
            .iter()
            .all(|(width, height, _)| (*width, *height) == (1170, 2532))
    );
    let distinct: std::collections::HashSet<_> = images.iter().map(|(.., jpeg)| jpeg).collect();
    assert_eq!(distinct.len(), 3);
    takeover
        .send(&PhoneMessage::Tap {
            at: Point { x: 0.5, y: 0.25 },
            seq,
        })
        .await?;
    // a value chosen for another site, as when the page moved while Face
    // ID was up, is refused rather than filled
    cdp.focus(Some(Field::PASSWORD));
    takeover
        .send(&PhoneMessage::Fill {
            field: LoginField::Password,
            value: Secret::new("chosen-for-gitlab".to_owned()),
            submit: false,
            site: Some("gitlab.com".to_owned()),
        })
        .await?;
    let refused = takeover
        .until(|frame| match frame {
            GatewayFrame::Message(GatewayMessage::Refused { message }) => Some(message.clone()),
            _ => None,
        })
        .await?;
    assert!(refused.contains("chosen for gitlab.com"), "{refused}");
    assert_eq!(cdp.typed(), "");
    takeover.send(&PhoneMessage::Reload).await?;
    eventually(|| {
        cdp.log()
            .iter()
            .any(|line| line == "Page.reload")
            .then_some(())
    })
    .await?;

    takeover.send(&PhoneMessage::Done).await?;
    let ended = takeover
        .until(|frame| match frame {
            GatewayFrame::Message(GatewayMessage::Ended { reason, .. }) => Some(*reason),
            _ => None,
        })
        .await?;
    assert_eq!(ended, EndReason::Done);

    let execution = pending["execution_id"].as_str().unwrap_or_default();
    let done: Value = serde_json::from_str(&text_of(&rig.harness.wait_done(execution).await?))?;
    assert_eq!(
        done["result"],
        json!({ "outcome": "done", "url": "https://github.com/login" }),
        "{done}"
    );

    let log = cdp.log();
    // laid out as the phone at its size, the tap at the image's point in
    // page pixels, then the agent's layout back
    assert!(
        log.iter().any(
            |line| line.starts_with("Emulation.setDeviceMetricsOverride")
                && line.contains("\"mobile\":true")
                && line.contains("\"width\":390")
        ),
        "{log:#?}"
    );
    assert!(
        log.iter().any(|line| line.contains("mousePressed")
            && line.contains("\"x\":195.0")
            && line.contains("\"y\":211.0")),
        "{log:#?}"
    );
    let cleared = log
        .iter()
        .position(|line| line == "Emulation.clearDeviceMetricsOverride");
    let pressed = log.iter().position(|line| line.contains("mousePressed"));
    assert!(cleared > pressed, "{log:#?}");
    assert!(log.contains(&"Page.stopScreencast".to_owned()), "{log:#?}");
    let captures = log
        .iter()
        .filter(|line| *line == "Page.captureScreenshot")
        .count();
    assert_eq!(captures, 3, "{log:#?}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_owner_away_one_phone_request_signs_in_and_each_field_is_filled_once() -> TestResult
{
    const ENTERED: &str = "entered-on-the-phone";
    let cdp = FakeCdp::start("https://github.com/login").await?;
    let Some(rig) = Rig::start(Options {
        browser: Some(cdp.program.clone()),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = rig.harness.enroll_passkey().await?;
    rig.gateway_mac.set_present(false);
    rig.phone.set_answer(Answer::Enter(ENTERED));

    // the page is checked before anyone is asked
    cdp.focus(Some(Field::USERNAME));
    let refused = text_of(
        &execute(
            &rig.harness.client,
            r#"await browser_fill(session="test", kind="password", site="github.com")"#,
        )
        .await?,
    );
    assert!(refused.contains("not a password field"), "{refused}");
    let refused = text_of(
        &execute(
            &rig.harness.client,
            r#"await browser_fill(session="test", kind="username", site="gitlab.com")"#,
        )
        .await?,
    );
    assert!(refused.contains("gitlab.com"), "{refused}");
    assert!(rig.phone.seen().iter().all(|seen| seen.items.is_empty()));

    let mut fill = async |kind: &str| -> Result<Value, Box<dyn Error>> {
        let pending = rig
            .harness
            .execute_body(&format!(
                r#"await browser_fill(session="test", kind="{kind}", site="github.com", submit={})"#,
                if kind == "password" { "True" } else { "False" }
            ))
            .await?;
        assert_eq!(pending["status"], "pending", "{pending}");
        let id = approval_id(&pending)?;
        let page = rig
            .harness
            .http
            .get(format!("{}/approve/{id}", rig.harness.base()))
            .send()
            .await?
            .text()
            .await?;
        assert!(
            page.contains(&format!(
                "{kind} into github.com (browser session test), from the user&#39;s phone"
            )),
            "{page}"
        );
        let (status, body) = rig
            .harness
            .approve_with_passkey(&mut passkey, &id, "once")
            .await?;
        assert_eq!(status, 200, "{body}");
        let execution = pending["execution_id"].as_str().unwrap_or_default();

        Ok(serde_json::from_str(&text_of(
            &rig.harness.wait_done(execution).await?,
        ))?)
    };

    let done = fill("username").await?;
    assert_eq!(
        done["result"],
        json!({ "filled": true, "url": "https://github.com/login" }),
        "{done}"
    );
    assert!(!done.to_string().contains(ENTERED), "{done}");
    assert_eq!(cdp.typed(), ENTERED);

    // one request for the whole sign-in
    let asked: Vec<Seen> = rig
        .phone
        .seen()
        .into_iter()
        .filter(|seen| !seen.items.is_empty())
        .collect();
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].items,
        [
            "\"username for github.com\"".to_owned(),
            "\"password for github.com\"".to_owned()
        ]
    );
    assert_eq!(
        asked[0].reason.as_deref(),
        Some("sign in to github.com in browser session test")
    );

    // the password comes from that request, not a second one
    cdp.focus(Some(Field::PASSWORD));
    let done = fill("password").await?;
    assert_eq!(done["result"]["filled"], true, "{done}");
    assert_eq!(cdp.typed(), format!("{ENTERED}{ENTERED}"));
    assert_eq!(
        rig.phone
            .seen()
            .iter()
            .filter(|seen| !seen.items.is_empty())
            .count(),
        1
    );
    let log = cdp.log();
    assert!(
        log.iter()
            .any(|line| line.starts_with("Input.dispatchKeyEvent") && line.contains("Enter")),
        "{log:#?}"
    );
    assert!(!log.iter().any(|line| line.contains(ENTERED)), "{log:#?}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_phone_lists_the_browser_sessions_and_starts_one_with_its_saved_profile() -> TestResult
{
    let cdp = FakeCdp::start("https://github.com/login").await?;
    // saved sessions' profiles, and a directory of agent-browser's that is
    // not one
    for saved in ["discord", "broken"] {
        std::fs::create_dir_all(cdp.profiles.join(saved))?;
        std::fs::write(cdp.profiles.join(saved).join("Local State"), "{}")?;
    }
    std::fs::create_dir_all(cdp.profiles.join("screenshots"))?;
    std::fs::write(cdp.profiles.join("screenshots").join("github.png"), "")?;
    let Some(rig) = Rig::start(Options {
        browser: Some(cdp.program.clone()),
        browser_profiles: Some(cdp.profiles.clone()),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    // `gone` is listed by agent-browser but has no browser and no profile;
    // `broken` has a profile, but agent-browser does not say whether its
    // browser runs, so it is not offered to start, which could relaunch it
    let mut listing = Takeover::dial(&rig.phone).await?;
    listing.send(&PhoneMessage::Sessions).await?;
    let GatewayFrame::Message(GatewayMessage::Sessions { running, saved }) = listing.next().await?
    else {
        return Err("no session list".into());
    };
    assert_eq!(
        running,
        [RunningSession {
            name: "test".to_owned(),
            url: Some("https://github.com/login".to_owned()),
            title: Some("Sign in".to_owned()),
        }]
    );
    assert_eq!(saved, ["discord"]);

    // only an https address starts a session, a session agent-browser says
    // nothing clear about is not started, and a directory that is not a
    // profile is not made one
    for (session, url, why) in [
        ("discord", "file:///etc/hosts", "https"),
        ("broken", "https://example.com/", "did not say"),
        (
            "screenshots",
            "https://example.com/",
            "not a browser profile",
        ),
    ] {
        let mut refused = Takeover::start(&rig.phone, session, url).await?;
        let (reason, message) = refused
            .until(|frame| match frame {
                GatewayFrame::Message(GatewayMessage::Ended { reason, message }) => {
                    Some((*reason, message.clone().unwrap_or_default()))
                }
                _ => None,
            })
            .await?;
        assert_eq!(reason, EndReason::BrowserGone);
        assert!(message.contains(why), "{session}: {message}");
    }
    assert!(cdp.opens().is_empty(), "{:?}", cdp.opens());

    // the saved session launches with its profile and is taken over
    let mut started = Takeover::start(&rig.phone, "discord", "https://discord.com/login").await?;
    started
        .until(|frame| matches!(frame, GatewayFrame::Screen(_)).then_some(()))
        .await?;
    drop(started);
    // a running session only loads the address: launch options would make
    // agent-browser relaunch its browser and lose the page
    let mut again = Takeover::start(&rig.phone, "test", "https://github.com/").await?;
    again
        .until(|frame| matches!(frame, GatewayFrame::Screen(_)).then_some(()))
        .await?;
    assert_eq!(
        cdp.opens(),
        [
            format!(
                "--session discord --profile {} --engine chrome open https://discord.com/login",
                cdp.profiles.join("discord").display()
            ),
            "--session test open https://github.com/".to_owned(),
        ]
    );

    rig.stop().await
}
