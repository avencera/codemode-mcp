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
        PAIR_ALPN, PairCheck, PairRequest, PairResponse, Registration, Role,
        mobile::{
            PhoneProgramRead, PhoneProgramRequest, PhoneRead, PhoneRegistration, PhoneRequest,
            PhoneResponse, ProgramItem, PushEnvironment, PushToken,
        },
    },
    config::Config,
    mac::TouchId,
    secrets::PHONE_GRACE,
};
use companion_wire::seal::SoftwareKey;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, TransportAddr,
    endpoint::{Connection, presets},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{
    harness::{FakeMac, Harness, Setup, Stop, TestResult, temp_state_dir},
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
                ProgramItem::Reference { reference, sealed } => {
                    format!(
                        "{reference}{}",
                        if sealed.is_some() { " (sealed)" } else { "" }
                    )
                }
                ProgramItem::Describe { description } => format!("\"{description}\""),
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
                Ok(value) => values.push(value),
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

struct Options {
    /// Also list a Mac companion whose Touch ID prompt stays up
    with_mac_companion: bool,
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
        let extra = format!(
            "[secrets]\n\
             op = \"{op}\"\n\
             discovery = false\n\
             listen = \"{listen}\"\n\
             identity_file = \"{key}\"\n\
             {companion_line}\
             phones = [{{ name = \"iphone\", id = \"{phone}\", seal_key = \"{seal}\" }}]\n\
             apns = {{ key_file = \"{key_file}\", key_id = \"{KEY_ID}\", team_id = \"{TEAM_ID}\", server = \"http://{apns}\" }}\n\n\
             [servers.twin]\n\
             command = \"{fixture}\"\n\
             env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n",
            op = local_op.display(),
            key = gateway_key.display(),
            phone = phone.id(),
            seal = phone.key.public().to_base64(),
            key_file = apns.key_file.display(),
            apns = apns.address,
            fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
        );
        let Some(harness) = Harness::with(Setup {
            extra: &extra,
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
        seen[0].expires_in_ms > 0 && seen[0].expires_in_ms <= 120_000,
        "{seen:?}"
    );
    assert!(push.body["gateway"].is_string());
    // the deadline, so a push tapped after it shows the read as gone
    let expires = push.body["expires"].as_u64().ok_or("no deadline")?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    assert!(expires > now && expires <= now + 120_000, "{expires} {now}");
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

    gateway_mac.set_answer(Some(TouchId::Approved));
    let (status, trusted_now) = trust().await?;
    assert_eq!(status, 200, "{trusted_now}");
    assert_eq!(trusted_now["device"]["kind"], "phone", "{trusted_now}");
    // the prompt shows the fingerprint `companion list` gives, so the owner
    // can tell this phone from another listed under the same name
    let fingerprint = trusted_now["device"]["fingerprint"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(fingerprint.len(), 19, "{trusted_now}");
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
