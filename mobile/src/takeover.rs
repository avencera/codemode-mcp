//! The takeover actor: one live view of a browser session on the gateway
//! Mac, from the owner's Take over (or a handoff's push or link) until Done,
//! Cancel, leaving it, or the gateway ending it
//!
//! It dials the gateway on [`TAKEOVER_ALPN`] as the paired phone, from the
//! connection actor's endpoint, opens one stream and sends
//! [`PhoneMessage::Open`] once the app has said how big the image area is.
//! Frames are read and written in spawned tasks that report back as
//! messages, so a handler never waits on the network. Each image goes to the
//! app and on to Swift, and is acknowledged only once Swift says it is drawn,
//! so the gateway sends images no faster than the phone shows them. A link
//! that drops while the app is in the foreground is dialed again with the
//! connection's backoff, and the takeover opens anew on it

use std::sync::Arc;
use zeroize::Zeroizing;

use companion_wire::{
    mobile::{LoginField as WireLoginField, RequestId, seal_info},
    takeover::{
        EndReason, FillOffer as WireFillOffer, Focus, GatewayFrame, GatewayMessage, HEADER_BYTES,
        Key, MAX_TEXT_CHARS, PhoneMessage, Point, RunningSession, Secret as WireSecret,
        TAKEOVER_ALPN, Viewport, decode_gateway, encode_message, read_header,
    },
};
use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use tokio::sync::mpsc;

use crate::{
    app::{AppMsg, one_line},
    connection::backoff,
    ffi::{
        FillOffer, OpenError, OpenRequest, Platform, ScreenImage, TakeoverEnd, TakeoverFocus,
        TakeoverInput, TakeoverKey, TakeoverNotice, TakeoverPage, TakeoverStatus,
    },
    net,
    record::GatewayRecord,
    request::Secret,
};

/// Longest page address or title the takeover shows
const MAX_PAGE_TEXT_CHARS: usize = 1024;

/// Longest the endpoint lookup may take; the connection actor answers at
/// once unless it is restarting
const ENDPOINT_TIMEOUT_MS: u64 = 2_000;

/// What the takeover tells the app, which keeps it in [`crate::ffi::AppState`]
pub enum TakeoverEvent {
    /// The link changed, or the gateway ended the takeover
    Status(TakeoverStatus),
    /// The page or its focus changed
    Page(TakeoverPage),
    /// The gateway refused or filled something
    Notice(TakeoverNotice),
    /// A new image
    Screen(ScreenImage),
}

/// An open stream of a takeover, which the actor's tasks read and write
pub struct Link {
    connection: Connection,
    send: SendStream,
    receive: RecvStream,
}

/// What the takeover actor is told
pub enum TakeoverMsg {
    /// The owner did something
    Input(TakeoverInput),
    /// Text or a fill for the gateway, which carries a [`WireSecret`]
    Send(PhoneMessage),
    /// The app came to the foreground: dial
    Foreground,
    /// The app went to the background: hang up
    Background,
    /// Dial again after a failed dial or a dropped link
    Retry,
    /// A dial finished
    Dialed(Result<Link, String>),
    /// Link `link` brought a frame
    Frame {
        /// Which link
        link: u64,
        /// What came
        frame: GatewayFrame,
    },
    /// Link `link` dropped, and why
    Lost {
        /// Which link
        link: u64,
        /// Why
        error: String,
    },
    /// Face ID finished opening the offer for `field`
    Opened {
        /// The field it fills
        field: WireLoginField,
        /// The site the offer was for, which the gateway checks the page
        /// is still on
        site: String,
        /// The value
        opened: Result<Secret, OpenError>,
    },
}

/// What the takeover actor starts with
pub struct TakeoverArgs {
    /// The browser session
    pub session: String,
    /// The handoff it answers
    pub handoff: Option<RequestId>,
    /// The `https` address to start the session at, for New session
    pub start: Option<String>,
    /// Tells this takeover's reports apart from those of one it replaced
    pub generation: u64,
    /// The gateway to dial
    pub record: GatewayRecord,
    /// For Face ID
    pub platform: Arc<dyn Platform>,
    /// Where reports go, and the endpoint comes from
    pub app: ActorRef<AppMsg>,
    /// Whether the app is in the foreground
    pub foreground: bool,
}

/// The current link: the connection, and where frames to send go
struct Live {
    id: u64,
    connection: Connection,
    /// Frames to send; each is wiped once written, since text and fills
    /// travel in them
    writer: mpsc::UnboundedSender<Zeroizing<Vec<u8>>>,
    /// Whether any frame came on it, which shows the gateway took the Open
    answered: bool,
}

pub struct TakeoverState {
    session: String,
    handoff: Option<RequestId>,
    /// The address to start the session at, until a link gets through: a
    /// redial takes the session over as it is, keeping its page
    start: Option<String>,
    generation: u64,
    record: GatewayRecord,
    platform: Arc<dyn Platform>,
    app: ActorRef<AppMsg>,
    /// The image area, once the app has said; nothing is dialed before
    viewport: Option<Viewport>,
    live: Option<Live>,
    /// Numbers links, so a report from a dropped one is ignored
    links: u64,
    dialing: bool,
    /// Whether the app is in the foreground
    wanted: bool,
    /// Dials that failed or links that dropped unanswered, in a row
    failures: u32,
    /// The newest image handed to the app on this link and not yet
    /// acknowledged
    unacked: Option<u32>,
    /// Done or Cancel tapped while the link was down, sent right after the
    /// next Open
    ending: Option<PhoneMessage>,
    /// The fill offers of the current page, with their sealed copies
    offers: Vec<WireFillOffer>,
    /// Whether Face ID is up for an offer
    opening: bool,
}

impl TakeoverState {
    fn report(&self, event: TakeoverEvent) {
        let _ = self.app.cast(AppMsg::TakeoverEvent {
            generation: self.generation,
            event,
        });
    }

    /// The id Face ID's prompt for an offer goes by, so it can be taken down
    fn open_id(&self) -> String {
        format!("takeover {}", self.session)
    }

    /// Sends `message` on the current link; one made while it is down is
    /// dropped, except Done and Cancel, which wait for the next link
    fn send(&mut self, message: PhoneMessage) {
        let Some(live) = &self.live else {
            if matches!(message, PhoneMessage::Done | PhoneMessage::Cancel) {
                self.ending = Some(message);
            }

            return;
        };

        match encode_message(&message) {
            // a dropped link reports itself through its tasks
            Ok(frame) => {
                let _ = live.writer.send(Zeroizing::new(frame));
            }
            Err(error) => tracing::warn!(%error, "a takeover message did not encode"),
        }
    }

    fn refuse(&self, message: &str) {
        self.report(TakeoverEvent::Notice(TakeoverNotice::Refused {
            message: message.to_owned(),
        }));
    }

    /// Hangs up the current link, if any
    fn hang_up(&mut self, reason: &'static [u8]) {
        self.unacked = None;
        if let Some(live) = self.live.take() {
            live.connection.close(0_u32.into(), reason);
        }
    }
}

pub struct TakeoverActor;

impl TakeoverActor {
    fn dial(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState) {
        if state.dialing || state.live.is_some() || !state.wanted {
            return;
        }
        let Some(viewport) = state.viewport else {
            return;
        };
        state.dialing = true;
        state.report(TakeoverEvent::Status(TakeoverStatus::Connecting));

        let open = PhoneMessage::Open {
            session: state.session.clone(),
            handoff: state.handoff.clone(),
            viewport,
            start: state.start.clone(),
        };
        // kept until a dial gets through, so a failed one loses nothing
        let mut first = vec![open];
        first.extend(state.ending.clone());
        let app = state.app.clone();
        let address = state.record.endpoint_addr();
        let myself = myself.clone();
        tokio::spawn(async move {
            let dialed = connect(app, address, first).await;
            let _ = myself.cast(TakeoverMsg::Dialed(dialed));
        });
    }

    /// Counts a failure and dials again after the backoff
    fn retry_later(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState, error: String) {
        state.failures = state.failures.saturating_add(1);
        let delay = backoff(state.failures);
        tracing::info!(%error, ?delay, "no takeover link");
        state.report(TakeoverEvent::Status(TakeoverStatus::Retrying {
            in_secs: u32::try_from(delay.as_secs()).unwrap_or(u32::MAX),
            error,
        }));
        myself.send_after(delay, || TakeoverMsg::Retry);
    }

    fn linked(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState, link: Link) {
        if !state.wanted {
            link.connection.close(0_u32.into(), b"background");

            return;
        }
        // the Open and any Done or Cancel waiting on it went with the dial;
        // the session is started, so a redial takes it over as it is
        state.ending = None;
        state.start = None;
        state.links = state.links.wrapping_add(1);
        let id = state.links;
        let (writer, frames) = mpsc::unbounded_channel();
        tokio::spawn(write_frames(link.send, frames, myself.clone(), id));
        tokio::spawn(read_frames(link.receive, myself.clone(), id));
        state.live = Some(Live {
            id,
            connection: link.connection,
            writer,
            answered: false,
        });
    }

    fn frame(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState, frame: GatewayFrame) {
        if let Some(live) = state.live.as_mut().filter(|live| !live.answered) {
            live.answered = true;
            state.failures = 0;
            state.report(TakeoverEvent::Status(TakeoverStatus::Live));
        }

        let message = match frame {
            GatewayFrame::Screen(screen) => {
                state.unacked = Some(screen.header.seq);
                state.report(TakeoverEvent::Screen(ScreenImage {
                    seq: screen.header.seq,
                    width: screen.header.width,
                    height: screen.header.height,
                    jpeg: screen.jpeg,
                }));

                return;
            }
            GatewayFrame::Message(message) => message,
        };

        match message {
            GatewayMessage::Page {
                url,
                title,
                focus,
                offers,
            } => {
                let page = TakeoverPage {
                    url: one_line(&url, MAX_PAGE_TEXT_CHARS),
                    title: one_line(&title, MAX_PAGE_TEXT_CHARS),
                    focus: focus.map(shown_focus),
                    offers: offers.iter().map(shown_offer).collect(),
                };
                state.offers = offers;
                state.report(TakeoverEvent::Page(page));
            }
            GatewayMessage::Filled { field } => {
                state.report(TakeoverEvent::Notice(TakeoverNotice::Filled {
                    field: field.into(),
                }));
            }
            GatewayMessage::Refused { message } => {
                state.report(TakeoverEvent::Notice(TakeoverNotice::Refused {
                    message: one_line(&message, MAX_PAGE_TEXT_CHARS),
                }));
            }
            // the answer to a listing, which goes on a link of its own
            GatewayMessage::Sessions { .. } => {}
            GatewayMessage::Ended { reason, message } => {
                state.hang_up(b"ended");
                state.report(TakeoverEvent::Status(TakeoverStatus::Ended {
                    reason: shown_end(reason),
                    message: message.map(|message| one_line(&message, MAX_PAGE_TEXT_CHARS)),
                }));
                myself.stop(None);
            }
        }
    }

    fn input(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState, input: TakeoverInput) {
        let message = match input {
            TakeoverInput::Resize {
                width,
                height,
                scale,
            } => {
                let viewport = Viewport {
                    width,
                    height,
                    scale,
                };
                let changed = state.viewport != Some(viewport);
                state.viewport = Some(viewport);
                if state.live.is_none() {
                    Self::dial(myself, state);

                    return;
                }
                if !changed {
                    return;
                }

                PhoneMessage::Resize { viewport }
            }
            TakeoverInput::Drawn { seq } => {
                // an image from a link that dropped since is not the one
                // this link waits on
                if state.unacked != Some(seq) {
                    return;
                }
                state.unacked = None;

                PhoneMessage::Ack { seq }
            }
            TakeoverInput::Tap { x, y, seq } => PhoneMessage::Tap {
                at: point(x, y),
                seq,
            },
            TakeoverInput::LongPress { x, y, seq } => PhoneMessage::LongPress {
                at: point(x, y),
                seq,
            },
            TakeoverInput::Scroll { x, y, dx, dy, seq } => PhoneMessage::Scroll {
                at: point(x, y),
                dx: finite(dx),
                dy: finite(dy),
                seq,
            },
            TakeoverInput::Key { key } => PhoneMessage::Key { key: wire_key(key) },
            TakeoverInput::Back => PhoneMessage::Back,
            TakeoverInput::Reload => PhoneMessage::Reload,
            TakeoverInput::Go { url } => PhoneMessage::Go { url },
            TakeoverInput::FillOffer { reference } => {
                Self::open_offer(myself, state, &reference);

                return;
            }
            TakeoverInput::Done => PhoneMessage::Done,
            TakeoverInput::Cancel => PhoneMessage::Cancel,
        };

        state.send(message);
    }

    /// Opens the sealed copy of the offer for `reference` with Face ID; the
    /// seal's `info` binds the gateway and the reference, so only the value
    /// the offer names opens
    fn open_offer(myself: &ActorRef<TakeoverMsg>, state: &mut TakeoverState, reference: &str) {
        if state.opening {
            return;
        }
        let Some(offer) = state
            .offers
            .iter()
            .find(|offer| offer.reference == reference)
        else {
            state.refuse("the page no longer offers that value");

            return;
        };

        let request = OpenRequest {
            id: state.open_id(),
            reference: offer.reference.clone(),
            gateway_name: state.record.name.clone(),
            info: seal_info(&state.record.id, &offer.reference),
            enc: offer.sealed.enc.clone(),
            ciphertext: offer.sealed.ciphertext.clone(),
        };
        let field = offer.field;
        let site = offer.site.clone();
        state.opening = true;

        let platform = Arc::clone(&state.platform);
        let myself = myself.clone();
        tokio::spawn(async move {
            let opened = tokio::task::spawn_blocking(move || platform.open_sealed(request))
                .await
                .unwrap_or_else(|error| {
                    Err(OpenError::Failed {
                        message: error.to_string(),
                    })
                })
                .map(Secret);
            let _ = myself.cast(TakeoverMsg::Opened {
                field,
                site,
                opened,
            });
        });
    }

    /// Sends text or a fill, within the wire's length limit; long text goes
    /// in pieces, while a fill is one value and is refused instead
    fn send_secret(state: &mut TakeoverState, message: PhoneMessage) {
        if state.live.is_none() {
            state.refuse("the page is not connected, so nothing was typed");

            return;
        }

        match message {
            PhoneMessage::Text { text } => {
                let characters: Vec<char> = text.into_inner().chars().collect();
                for piece in characters.chunks(MAX_TEXT_CHARS) {
                    state.send(PhoneMessage::Text {
                        text: WireSecret::new(piece.iter().collect()),
                    });
                }
            }
            PhoneMessage::Fill { ref value, .. }
                if value.expose().chars().count() > MAX_TEXT_CHARS =>
            {
                state.refuse("the value is too long to fill");
            }
            other => state.send(other),
        }
    }
}

impl Actor for TakeoverActor {
    type Msg = TakeoverMsg;
    type State = TakeoverState;
    type Arguments = TakeoverArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(TakeoverState {
            session: args.session,
            handoff: args.handoff,
            start: args.start,
            generation: args.generation,
            record: args.record,
            platform: args.platform,
            app: args.app,
            viewport: None,
            live: None,
            links: 0,
            dialing: false,
            wanted: args.foreground,
            failures: 0,
            unacked: None,
            ending: None,
            offers: Vec::new(),
            opening: false,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            TakeoverMsg::Input(input) => Self::input(&myself, state, input),
            TakeoverMsg::Send(message) => Self::send_secret(state, message),
            TakeoverMsg::Foreground => {
                state.wanted = true;
                state.failures = 0;
                Self::dial(&myself, state);
            }
            TakeoverMsg::Background => {
                state.wanted = false;
                state.failures = 0;
                state.hang_up(b"background");
                state.report(TakeoverEvent::Status(TakeoverStatus::Paused));
            }
            // a retry queued before the app went to the background must not
            // bring the link back
            TakeoverMsg::Retry if state.wanted => Self::dial(&myself, state),
            TakeoverMsg::Retry => {}
            TakeoverMsg::Dialed(dialed) => {
                state.dialing = false;
                match dialed {
                    Ok(link) => Self::linked(&myself, state, link),
                    Err(_) if !state.wanted => {}
                    Err(error) => Self::retry_later(&myself, state, error),
                }
            }
            TakeoverMsg::Frame { link, frame } => {
                if state.live.as_ref().is_some_and(|live| live.id == link) {
                    Self::frame(&myself, state, frame);
                }
            }
            TakeoverMsg::Lost { link, error } => {
                if !state.live.as_ref().is_some_and(|live| live.id == link) {
                    return Ok(());
                }
                state.hang_up(b"lost");
                if state.wanted {
                    Self::retry_later(&myself, state, error);
                }
            }
            TakeoverMsg::Opened {
                field,
                site,
                opened,
            } => {
                state.opening = false;
                match opened {
                    Ok(Secret(value)) => Self::send_secret(
                        state,
                        PhoneMessage::Fill {
                            field,
                            value: WireSecret::new(value),
                            submit: false,
                            site: Some(site),
                        },
                    ),
                    // the owner said no; nothing to explain
                    Err(OpenError::Denied) => {}
                    Err(OpenError::Failed { message }) => state.refuse(&message),
                }
            }
        }

        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if state.opening {
            state.platform.cancel_open(state.open_id());
        }
        state.hang_up(b"closed");

        Ok(())
    }
}

/// Dials the gateway on the takeover ALPN from the connection actor's
/// endpoint, opens the stream and sends `first`, the Open and anything
/// waiting on it
async fn connect(
    app: ActorRef<AppMsg>,
    address: iroh::EndpointAddr,
    first: Vec<PhoneMessage>,
) -> Result<Link, String> {
    let endpoint = ractor::call_t!(app, AppMsg::Endpoint, ENDPOINT_TIMEOUT_MS)
        .map_err(|error| error.to_string())?
        .ok_or("not paired with a gateway")?;

    let connection =
        tokio::time::timeout(net::DIAL_TIMEOUT, endpoint.connect(address, TAKEOVER_ALPN))
            .await
            .map_err(|_| "the gateway did not answer in time".to_owned())?
            .map_err(|error| error.to_string())?;
    let (mut send, receive) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    for message in &first {
        let frame = encode_message(message).map_err(|error| error.to_string())?;
        send.write_all(&frame)
            .await
            .map_err(|error| error.to_string())?;
    }

    Ok(Link {
        connection,
        send,
        receive,
    })
}

/// How long the gateway may take to list its sessions, which it caps at
/// about 13 seconds
const LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the gateway may take to close a session, which it caps at 45
/// seconds, before it lists them
const CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// How long a link whose stream ended may take to say why it closed
const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The gateway's browser sessions, as it listed them
#[derive(Debug, Clone)]
pub struct Listing {
    /// The sessions running
    pub running: Vec<RunningSession>,
    /// The saved sessions not running, by name
    pub saved: Vec<String>,
    /// The `https` page each saved session was last on, by name
    pub last_pages: std::collections::BTreeMap<String, String>,
}

/// What the phone asks of the gateway's sessions before they are listed
#[derive(Debug, Clone)]
pub enum SessionChange {
    /// Quit a session's browser
    Close(String),
    /// Move a saved session's profile to the gateway's Trash
    Remove(String),
}

/// The gateway's browser sessions, after making `change` if set: dials as a
/// takeover does, asks with [`PhoneMessage::Sessions`],
/// [`PhoneMessage::CloseSession`] or [`PhoneMessage::RemoveSession`], and
/// reads the one answer
pub async fn list_sessions(
    app: ActorRef<AppMsg>,
    address: iroh::EndpointAddr,
    change: Option<SessionChange>,
) -> Result<Listing, String> {
    let (first, timeout, asked) = match change {
        Some(SessionChange::Close(session)) => (
            PhoneMessage::CloseSession { session },
            CLOSE_TIMEOUT + LIST_TIMEOUT,
            "close sessions",
        ),
        Some(SessionChange::Remove(session)) => (
            PhoneMessage::RemoveSession { session },
            LIST_TIMEOUT + LIST_TIMEOUT,
            "remove sessions",
        ),
        None => (PhoneMessage::Sessions, LIST_TIMEOUT, "list sessions"),
    };
    let mut link = connect(app, address, vec![first]).await?;
    let _ = link.send.finish();
    let answer = tokio::time::timeout(timeout, read_frame(&mut link.receive))
        .await
        .map_err(|_| format!("the gateway did not {asked} in time"))?;
    let answer = match answer {
        Ok(frame) => frame,
        // a gateway that cannot answer closes the link, its reason the close's
        Err(error) => return Err(refusal(&link.connection, asked).await.unwrap_or(error)),
    };
    link.connection.close(0_u32.into(), b"listed");

    match answer {
        GatewayFrame::Message(GatewayMessage::Sessions {
            running,
            saved,
            last_pages,
        }) => Ok(Listing {
            running,
            saved,
            last_pages,
        }),
        GatewayFrame::Message(GatewayMessage::Ended {
            message: Some(message),
            ..
        }) => Err(message),
        _ => Err("the gateway answered something else; update codemode-mcp on it".to_owned()),
    }
}

/// Why the gateway closed `connection`, in the owner's words, when it closed
/// it for a reason a listing can meet: an older gateway, which takes only an
/// Open and could not do what was `asked`, or one without the `browser`
/// server
async fn refusal(connection: &Connection, asked: &str) -> Option<String> {
    let closed = tokio::time::timeout(CLOSE_WAIT, connection.closed())
        .await
        .ok()?;
    let ConnectionError::ApplicationClosed(close) = closed else {
        return None;
    };

    match close.reason.as_ref() {
        b"expected open" => Some(format!(
            "The gateway's codemode-mcp is too old to {asked}; update it"
        )),
        b"no browser" => Some("The gateway has no `browser` server configured".to_owned()),
        _ => None,
    }
}

/// Writes each frame the actor queues, until the actor drops the link
async fn write_frames(
    mut send: SendStream,
    mut frames: mpsc::UnboundedReceiver<Zeroizing<Vec<u8>>>,
    actor: ActorRef<TakeoverMsg>,
    link: u64,
) {
    while let Some(frame) = frames.recv().await {
        if let Err(error) = send.write_all(&frame).await {
            let _ = actor.cast(TakeoverMsg::Lost {
                link,
                error: error.to_string(),
            });

            return;
        }
    }
    let _ = send.finish();
}

/// Reads frames until the stream ends or breaks
async fn read_frames(mut receive: RecvStream, actor: ActorRef<TakeoverMsg>, link: u64) {
    let error = loop {
        match read_frame(&mut receive).await {
            Ok(frame) => {
                if actor.cast(TakeoverMsg::Frame { link, frame }).is_err() {
                    return;
                }
            }
            Err(error) => break error,
        }
    };
    let _ = actor.cast(TakeoverMsg::Lost { link, error });
}

async fn read_frame(receive: &mut RecvStream) -> Result<GatewayFrame, String> {
    let mut header = [0_u8; HEADER_BYTES];
    receive
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    let (kind, length) = read_header(header).map_err(|error| error.to_string())?;
    let mut body = vec![0_u8; length];
    receive
        .read_exact(&mut body)
        .await
        .map_err(|error| error.to_string())?;

    decode_gateway(kind, &body).map_err(|error| error.to_string())
}

/// A point clamped to the image, so a gesture that ran off its edge still
/// lands on the page
fn point(x: f64, y: f64) -> Point {
    Point {
        x: finite(x).clamp(0.0, 1.0),
        y: finite(y).clamp(0.0, 1.0),
    }
}

/// `value`, or 0 when it is not a number JSON can carry
fn finite(value: f64) -> f64 {
    if value.is_finite() { value } else { 0.0 }
}

fn wire_key(key: TakeoverKey) -> Key {
    match key {
        TakeoverKey::Enter => Key::Enter,
        TakeoverKey::Tab => Key::Tab,
        TakeoverKey::Backspace => Key::Backspace,
        TakeoverKey::Escape => Key::Escape,
    }
}

fn shown_focus(focus: Focus) -> TakeoverFocus {
    TakeoverFocus {
        field: focus.field.map(Into::into),
        editable: focus.editable,
        secure: focus.secure,
        numeric: focus.numeric,
        origin: one_line(&focus.origin, MAX_PAGE_TEXT_CHARS),
        cross_site: focus.cross_site,
    }
}

fn shown_offer(offer: &WireFillOffer) -> FillOffer {
    FillOffer {
        field: offer.field.into(),
        reference: offer.reference.clone(),
        item: one_line(&offer.item, MAX_PAGE_TEXT_CHARS),
        account: offer
            .account
            .as_deref()
            .map(|account| one_line(account, MAX_PAGE_TEXT_CHARS)),
    }
}

fn shown_end(reason: EndReason) -> TakeoverEnd {
    match reason {
        EndReason::Done => TakeoverEnd::Done,
        EndReason::Cancelled => TakeoverEnd::Cancelled,
        EndReason::HandoffOver => TakeoverEnd::HandoffOver,
        EndReason::BrowserGone => TakeoverEnd::BrowserGone,
        EndReason::Shutdown => TakeoverEnd::Shutdown,
    }
}
