//! The gateway's side of takeovers and handoffs: the link a phone dials to
//! drive a browser session, and the handoff requests offered to phones
//!
//! A takeover connection on [`companion_wire::takeover::TAKEOVER_ALPN`] is let in only from a listed,
//! trusted phone, like the phone's own connection. It carries one stream of
//! frames (see [`companion_wire::takeover`]); what the frames do to the
//! browser is up to the [`TakeoverHost`] the daemon registers
//!
//! A hub also lists the spokes whose browser sessions the phones may take
//! over ([`BrowserMachines`]), as each last reported its takeover endpoint;
//! a spoke serves its own takeovers the same way (see [`super::spoke`])

use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, OnceLock, PoisonError, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use companion_wire::{
    mobile::{HandoffAnswer, PhoneHandoff, PhoneHandoffRequest, RequestId, Sealed},
    takeover::{
        BrowserMachine, EndReason, GatewayFrame, GatewayMessage, HEADER_BYTES, PhoneMessage,
        RunningSession, Viewport, decode_phone, encode_message, encode_screen, read_header,
    },
};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use zeroize::Zeroizing;

use super::{CompanionFailure, Companions, apns::Subject};
use crate::config::MAX_BROWSER_REPORT_SECS;

/// How long a spoke's report of its takeover endpoint stands; a spoke
/// reports at least every [`MAX_BROWSER_REPORT_SECS`], so one that missed
/// two reports is taken to be gone
const FRESH: Duration = Duration::from_secs(3 * MAX_BROWSER_REPORT_SECS);

/// How long a phone may take to open its stream and say what it takes over
const OPEN_WINDOW: Duration = Duration::from_secs(30);

/// Messages from the phone waiting for the browser
const INPUT_BACKLOG: usize = 64;

/// Frames waiting for the link to the phone; images are paced by the
/// phone's acknowledgements, so few wait
const OUTPUT_BACKLOG: usize = 16;

/// The phone driving a takeover, as the machine it dialed knows it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverPhone {
    /// Its name in the hub's config, for logs
    pub name: String,
    /// Its iroh endpoint id, which only it can answer as
    pub id: EndpointId,
}

/// What a phone opened a takeover with
#[derive(Debug, Clone)]
pub struct TakeoverOpen {
    /// The browser session it asks for
    pub session: String,
    /// The handoff it answers
    pub handoff: Option<RequestId>,
    /// Its screen area for the page
    pub viewport: Viewport,
    /// The `https` address to start the session at, unchecked
    pub start: Option<String>,
}

/// The browser sessions a phone may take over or start
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionList {
    /// The sessions running now
    pub running: Vec<RunningSession>,
    /// The saved profiles of sessions not running
    pub saved: Vec<String>,
    /// The `https` page each saved session was last on, by name
    pub last_pages: BTreeMap<String, String>,
}

/// The images a takeover sent the phone, for the log at its end
#[derive(Default)]
struct Traffic {
    images: AtomicU32,
    bytes: AtomicU64,
    /// When the first went out
    first: OnceLock<Instant>,
}

impl Traffic {
    fn image(&self, bytes: usize) {
        self.images.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        let _ = self.first.set(Instant::now());
    }
}

/// Runs the takeovers phones open
#[async_trait]
pub trait TakeoverHost: Send + Sync {
    /// Runs one takeover by `phone` until it ends; `input` closes when the
    /// phone's link drops, and closing `output` ends the link
    async fn takeover(
        &self,
        phone: TakeoverPhone,
        open: TakeoverOpen,
        input: mpsc::Receiver<PhoneMessage>,
        output: mpsc::Sender<GatewayFrame>,
    );

    /// The browser sessions, for a phone's list
    async fn sessions(&self) -> Result<SessionList, String>;

    /// Quits `session`'s browser, as named by the phone, keeping its saved
    /// profile
    async fn close_session(&self, session: &str) -> Result<(), String>;

    /// Moves the saved profile of `session`, as named by the phone, to the
    /// Trash; refused while its browser runs
    async fn remove_session(&self, session: &str) -> Result<(), String>;
}

/// What a phone asks of the sessions before they are listed
enum SessionChange<'a> {
    Close(&'a str),
    Remove(&'a str),
}

/// What a handoff offered to the phones shows
#[derive(Debug, Clone)]
pub struct HandoffOffer {
    /// The handoff's id
    pub id: RequestId,
    /// The session to take over
    pub session: String,
    /// The agent's reason, one line
    pub reason: Option<String>,
    /// The page the session shows
    pub url: Option<String>,
    /// The spoke the session runs on, which the phone dials to take it
    /// over; `None` for this gateway's own session
    pub machine: Option<BrowserMachine>,
}

struct Reported {
    machine: BrowserMachine,
    seen: Instant,
}

/// The spokes whose browser sessions the phones may take over, by spoke
/// id, as each last reported its takeover endpoint; a hub lists the ones
/// seen lately with its own sessions
#[derive(Default)]
pub struct BrowserMachines(Mutex<HashMap<String, Reported>>);

impl BrowserMachines {
    /// Records that spoke `spoke` answers takeovers as `machine` now
    pub fn report(&self, spoke: &str, machine: BrowserMachine) {
        let reported = Reported {
            machine,
            seen: Instant::now(),
        };
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spoke.to_owned(), reported);
    }

    /// Forgets spoke `spoke`, which is no longer trusted
    pub fn forget(&self, spoke: &str) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(spoke);
    }

    /// The spokes seen lately, by name
    pub fn recent(&self) -> Vec<BrowserMachine> {
        let mut machines: Vec<BrowserMachine> = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|reported| reported.seen.elapsed() < FRESH)
            .map(|reported| reported.machine.clone())
            .collect();
        machines.sort_by(|one, other| one.name.cmp(&other.name));

        machines
    }

    /// Spoke `spoke`'s endpoint, when it was seen lately
    pub fn of(&self, spoke: &str) -> Option<BrowserMachine> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(spoke)
            .filter(|reported| reported.seen.elapsed() < FRESH)
            .map(|reported| reported.machine.clone())
    }
}

/// One frame's kind and body; the body is wiped when dropped, since a
/// phone's message may hold typed text or a login value
async fn read_frame(receive: &mut RecvStream) -> Result<(u8, Zeroizing<Vec<u8>>), String> {
    let mut header = [0_u8; HEADER_BYTES];
    receive
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    let (kind, length) = read_header(header).map_err(|error| error.to_string())?;
    let mut body = Zeroizing::new(vec![0_u8; length]);
    receive
        .read_exact(&mut body)
        .await
        .map_err(|error| error.to_string())?;

    Ok((kind, body))
}

/// Answers a phone's [`PhoneMessage::Sessions`], or its change to a
/// session once it is made, with the list and the other `machines`, or
/// with [`GatewayMessage::Ended`] saying why there is none. Without a
/// `host` only the machines are listed
async fn answer_sessions(
    host: Option<&dyn TakeoverHost>,
    machines: Vec<BrowserMachine>,
    change: Option<SessionChange<'_>>,
    send: &mut SendStream,
) {
    let listed = match host {
        Some(host) => {
            let changed = match change {
                Some(SessionChange::Close(session)) => host.close_session(session).await,
                Some(SessionChange::Remove(session)) => host.remove_session(session).await,
                None => Ok(()),
            };
            match changed {
                Ok(()) => host.sessions().await,
                Err(message) => Err(message),
            }
        }
        None => Ok(SessionList::default()),
    };
    let message = match listed {
        Ok(list) => GatewayMessage::Sessions {
            running: list.running,
            saved: list.saved,
            last_pages: list.last_pages,
            machines,
        },
        Err(message) => GatewayMessage::Ended {
            reason: EndReason::BrowserGone,
            message: Some(message),
        },
    };
    let Ok(bytes) = encode_message(&message) else {
        return;
    };
    if send.write_all(&bytes).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(OPEN_WINDOW, send.stopped()).await;
    }
}

/// Serves a takeover connection from `phone`, which the caller has let in:
/// one takeover on `host` until either side ends it, or one answer to a
/// list or a change to a session. `machines` are the other machines a list
/// names; a connection with neither a host nor machines is refused
pub(crate) async fn serve_takeover(
    connection: Connection,
    phone: TakeoverPhone,
    host: Option<Arc<dyn TakeoverHost>>,
    machines: Vec<BrowserMachine>,
) {
    if host.is_none() && machines.is_empty() {
        connection.close(1_u32.into(), b"no browser");

        return;
    }
    let Ok(Ok((mut send, mut receive))) =
        tokio::time::timeout(OPEN_WINDOW, connection.accept_bi()).await
    else {
        return;
    };
    let opened = tokio::time::timeout(OPEN_WINDOW, read_frame(&mut receive)).await;
    let first = match opened {
        Ok(Ok((kind, body))) => decode_phone(kind, &body).ok(),
        _ => None,
    };
    let (open, host) = match (first, host) {
        (Some(PhoneMessage::Sessions), host) => {
            answer_sessions(host.as_deref(), machines, None, &mut send).await;
            connection.close(0_u32.into(), b"listed");

            return;
        }
        (Some(PhoneMessage::CloseSession { session }), Some(host)) => {
            tracing::info!(phone = %phone.name, %session, "closing a session for a phone");
            let change = SessionChange::Close(&session);
            answer_sessions(Some(host.as_ref()), machines, Some(change), &mut send).await;
            connection.close(0_u32.into(), b"listed");

            return;
        }
        (Some(PhoneMessage::RemoveSession { session }), Some(host)) => {
            tracing::info!(phone = %phone.name, %session, "removing a session for a phone");
            let change = SessionChange::Remove(&session);
            answer_sessions(Some(host.as_ref()), machines, Some(change), &mut send).await;
            connection.close(0_u32.into(), b"listed");

            return;
        }
        (
            Some(PhoneMessage::Open {
                session,
                handoff,
                viewport,
                start,
            }),
            Some(host),
        ) => (
            TakeoverOpen {
                session,
                handoff,
                viewport,
                start,
            },
            host,
        ),
        // only spokes' sessions are listed here, and none of them is this
        // machine's to open or change
        (Some(PhoneMessage::Open { .. } | PhoneMessage::CloseSession { .. }), None)
        | (Some(PhoneMessage::RemoveSession { .. }), None) => {
            connection.close(1_u32.into(), b"no browser");

            return;
        }
        _ => {
            connection.close(1_u32.into(), b"expected open");

            return;
        }
    };
    tracing::info!(phone = %phone.name, session = %open.session, "takeover opened");

    let (input, input_receiver) = mpsc::channel(INPUT_BACKLOG);
    let (output, mut output_receiver) = mpsc::channel::<GatewayFrame>(OUTPUT_BACKLOG);
    let mut tasks = JoinSet::new();
    // the phone's messages, until it hangs up or sends something
    // unreadable; dropping `input` tells the host
    tasks.spawn(async move {
        loop {
            let message = match read_frame(&mut receive).await {
                Ok((kind, body)) => decode_phone(kind, &body),
                Err(_) => break,
            };
            let Ok(message) = message else {
                break;
            };
            if input.send(message).await.is_err() {
                break;
            }
        }
    });
    let sent = Arc::new(Traffic::default());
    let counting = Arc::clone(&sent);
    tasks.spawn(async move {
        while let Some(frame) = output_receiver.recv().await {
            let image = matches!(frame, GatewayFrame::Screen(_));
            let bytes = match &frame {
                GatewayFrame::Message(message) => encode_message(message),
                GatewayFrame::Screen(screen) => encode_screen(screen),
            };
            let Ok(bytes) = bytes else {
                continue;
            };
            if send.write_all(&bytes).await.is_err() {
                return;
            }
            if image {
                counting.image(bytes.len());
            }
        }
        let _ = send.finish();
        let _ = send.stopped().await;
    });

    let name = phone.name.clone();
    let opened = Instant::now();
    host.takeover(phone, open, input_receiver, output).await;
    // the writer sends what is left, then the link closes
    let _ = tokio::time::timeout(OPEN_WINDOW, async {
        while let Some(finished) = tasks.join_next().await {
            if finished.is_ok() {
                tasks.abort_all();
            }
        }
    })
    .await;
    // how the link carried it, to tell a slow path from a slow page
    let path = connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| {
            let kind = if path.is_relay() { "relay" } else { "direct" };
            (kind, path.rtt().as_millis())
        });
    let (path, rtt_ms) = path.unwrap_or(("none", 0));
    let images = sent.images.load(Ordering::Relaxed);
    let kb = sent.bytes.load(Ordering::Relaxed) / 1024;
    let first_ms = sent
        .first
        .get()
        .map_or(0, |first| first.duration_since(opened).as_millis());
    let secs = opened.elapsed().as_secs_f64();
    connection.close(0_u32.into(), b"ended");
    tracing::info!(
        phone = %name,
        images,
        kb,
        first_ms,
        per_sec = format!("{:.1}", f64::from(images) / secs.max(0.001)),
        path,
        rtt_ms,
        "takeover ended"
    );
}

impl Companions {
    /// Lets `host` run the takeovers phones open from now on
    pub fn host_takeovers(&self, host: Weak<dyn TakeoverHost>) {
        *self
            .takeovers
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(host);
    }

    fn takeover_host(&self) -> Option<Arc<dyn TakeoverHost>> {
        self.takeovers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade)
    }

    /// The copy of `reference` sealed to the phone `phone`, when the gateway
    /// has one
    pub fn phone_seal(&self, phone: EndpointId, reference: &str) -> Option<Sealed> {
        self.store
            .as_ref()
            .and_then(|store| store.seal(&phone.to_string(), reference).ok().flatten())
    }

    /// The spokes whose browser sessions the phones may take over
    pub fn browser_machines(&self) -> &BrowserMachines {
        &self.browser_machines
    }

    /// Serves a takeover connection a phone dialed: refused unless the phone
    /// is listed, then one takeover until either side ends it
    pub(super) async fn takeover_connection(&self, connection: Connection) {
        let remote = connection.remote_id();
        let Some(phone) = self.phones().into_iter().find(|phone| phone.id == remote) else {
            tracing::warn!(%remote, "refused a takeover from a phone that is not paired");
            connection.close(1_u32.into(), b"not paired");

            return;
        };
        let phone = TakeoverPhone {
            name: phone.name,
            id: phone.id,
        };

        serve_takeover(
            connection,
            phone,
            self.takeover_host(),
            self.browser_machines.recent(),
        )
        .await;
    }

    /// Offers `handoff` to every phone, pushing to wake them, until one
    /// answers on its request or `deadline` passes; a phone that answers
    /// with a takeover instead is seen by the caller, which then drops this
    pub async fn offer_handoff(
        self: &Arc<Self>,
        handoff: &HandoffOffer,
        deadline: Instant,
    ) -> Result<HandoffAnswer, CompanionFailure> {
        let phones = self.phones();
        if phones.is_empty() {
            return Err(CompanionFailure::Handoff(
                "no phone is paired (`codemode-mcp companion invite`)".to_owned(),
            ));
        }

        let mut asks = JoinSet::new();
        for phone in phones {
            let companions = Arc::clone(self);
            let handoff = handoff.clone();
            asks.spawn(async move {
                let subject = Subject::Handoff {
                    session: handoff.session.clone(),
                    reason: handoff
                        .reason
                        .clone()
                        .unwrap_or_else(|| "An agent needs you".to_owned()),
                    machine: handoff.machine.as_ref().map(|machine| machine.name.clone()),
                };
                let encode = |expires_in_ms| {
                    serde_json::to_vec(&PhoneHandoffRequest {
                        handoff: PhoneHandoff {
                            id: handoff.id.clone(),
                            session: handoff.session.clone(),
                            reason: handoff.reason.clone(),
                            url: handoff.url.clone(),
                            expires_in_ms,
                            machine: handoff.machine.clone(),
                        },
                    })
                    .map_err(|error| error.to_string())
                };

                companions
                    .ask_until::<HandoffAnswer>(&phone, &handoff.id, subject, deadline, encode)
                    .await
            });
        }

        let mut failure = None;
        while let Some(asked) = asks.join_next().await {
            match asked {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(error)) => failure = Some(error),
                Err(error) => {
                    failure = Some(CompanionFailure::Handoff(format!(
                        "a phone's request stopped unexpectedly: {error}"
                    )));
                }
            }
        }

        Err(failure
            .unwrap_or_else(|| CompanionFailure::Handoff("no phone took the handoff".to_owned())))
    }
}
