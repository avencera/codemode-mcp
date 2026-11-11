//! One takeover: the owner drives an agent-browser session's page from the
//! phone
//!
//! While it runs, the page is laid out at the phone's size as a mobile
//! device, and its screencast goes to the phone one image at a time: the
//! browser is acknowledged only once the phone has drawn the last image,
//! so a slow link gets fewer images instead of a queue. The page's address
//! and focused element are read every [`POLL`] and after each input, and
//! sent when they change. Ending restores the page's size
//!
//! This module knows nothing of the link to the phone: the caller hands it
//! the phone's messages and sends what it answers

use std::{collections::VecDeque, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use companion_wire::{
    mobile::{HandoffAnswer, LoginField},
    takeover::{
        EndReason, FillOffer, Focus, GatewayFrame, GatewayMessage, MAX_TEXT_CHARS, PhoneMessage,
        Point, Screen, ScreenHeader, Viewport,
    },
};
use serde_json::json;
use tokio::sync::{broadcast::error::RecvError, mpsc, watch};
use zeroize::Zeroizing;

use super::{
    cdp::CdpError,
    login_value,
    page::{Page, PageError, PageState},
};
use crate::{logins::site_of, secrets::Redactor};

/// How often the page's address and focus are read while nothing happens
const POLL: Duration = Duration::from_millis(800);

/// How soon they are read again after an input
const AFTER_INPUT: Duration = Duration::from_millis(150);

/// Largest pixels per point the page is drawn at, to keep images small
const MAX_SCALE: f64 = 2.0;

/// Smallest and largest side of the area the phone may ask for, in points
const SIDE: std::ops::RangeInclusive<u32> = 200..=2000;

/// JPEG quality of the screencast
const QUALITY: u32 = 60;

/// Images whose page size is kept, for taps on an image already replaced
const KEPT_IMAGES: usize = 8;

/// How a takeover ended
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It ended, and the phone is told why
    Ended(EndReason, Option<String>),
    /// The phone's link dropped; a handoff it answers waits for it to come
    /// back
    PhoneGone,
}

impl Outcome {
    /// The answer to the handoff the takeover was for, when the owner gave
    /// one
    pub fn answer(&self) -> Option<HandoffAnswer> {
        match self {
            Self::Ended(EndReason::Done, _) => Some(HandoffAnswer::Done),
            Self::Ended(EndReason::Cancelled, _) => Some(HandoffAnswer::Cancelled),
            _ => None,
        }
    }
}

/// The fills the phone could open on a site
pub type OffersFor = Box<dyn Fn(&str) -> Vec<FillOffer> + Send + Sync>;

/// What a takeover needs besides the page and the link
pub struct Context {
    /// The fills the phone could open for a site
    pub offers: OffersFor,
    /// Becomes true once the handoff this takeover answers is over
    pub handoff_over: Option<watch::Receiver<bool>>,
    /// Values filled are added here, so no server's answer shows them
    pub redactor: Arc<Redactor>,
}

/// What the phone was last told about the page
#[derive(Default, PartialEq)]
struct Shown {
    url: String,
    title: String,
    focus: Option<Focus>,
    site: Option<String>,
}

struct Takeover<'a> {
    page: &'a Page,
    output: &'a mpsc::Sender<GatewayFrame>,
    context: &'a Context,
    viewport: Viewport,
    /// The page size of recent images, by seq
    sizes: VecDeque<(u32, f64, f64)>,
    next_seq: u32,
    /// The browser's id of the image the phone has not acknowledged yet
    unacked: Option<(u32, i64)>,
    shown: Shown,
    /// The last state read, for fills
    state: Option<PageState>,
}

/// Runs a takeover of `page` until the owner ends it, the phone goes, the
/// handoff is over or the browser does
pub async fn run(
    page: Page,
    viewport: Viewport,
    mut input: mpsc::Receiver<PhoneMessage>,
    output: mpsc::Sender<GatewayFrame>,
    context: Context,
) -> Outcome {
    let mut takeover = Takeover {
        page: &page,
        output: &output,
        context: &context,
        viewport,
        sizes: VecDeque::new(),
        next_seq: 0,
        unacked: None,
        shown: Shown::default(),
        state: None,
    };
    let outcome = takeover.drive(&mut input).await;
    takeover.restore().await;

    if let Outcome::Ended(reason, message) = &outcome {
        let ended = GatewayMessage::Ended {
            reason: *reason,
            message: message.clone(),
        };
        let _ = output.send(GatewayFrame::Message(ended)).await;
    }

    outcome
}

impl Takeover<'_> {
    async fn drive(&mut self, input: &mut mpsc::Receiver<PhoneMessage>) -> Outcome {
        let mut events = self.page.browser().events();
        if let Err(error) = self.lay_out().await {
            return gone(error);
        }
        if let Err(error) = self.start_screencast().await {
            return gone(error);
        }
        let mut handoff_over = self.context.handoff_over.clone();
        let mut next_read = tokio::time::Instant::now();

        loop {
            let over = async {
                match &mut handoff_over {
                    Some(over) => {
                        let _ = over.wait_for(|over| *over).await;
                    }
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                message = input.recv() => {
                    let Some(message) = message else {
                        return Outcome::PhoneGone;
                    };
                    match self.handle(message).await {
                        Ok(Some(outcome)) => return outcome,
                        Ok(None) => {}
                        Err(error) => return gone(error),
                    }
                    next_read = tokio::time::Instant::now() + AFTER_INPUT;
                }
                event = events.recv() => match event {
                    Ok(event) if event.session.as_deref() == Some(self.page.session().id()) => {
                        match event.method.as_str() {
                            "Page.screencastFrame" => {
                                if let Err(error) = self.screen(&event.params).await {
                                    return gone(error);
                                }
                            }
                            "Inspector.detached" | "Inspector.targetCrashed" => {
                                return Outcome::Ended(EndReason::BrowserGone, Some("the page closed".to_owned()));
                            }
                            _ => {}
                        }
                    }
                    Ok(event) if event.method == "Target.targetDestroyed"
                        && event.params["targetId"].as_str() == Some(self.page.session().target()) => {
                        return Outcome::Ended(EndReason::BrowserGone, Some("the tab closed".to_owned()));
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => {
                        return Outcome::Ended(EndReason::BrowserGone, Some("the browser closed".to_owned()));
                    }
                },
                () = tokio::time::sleep_until(next_read) => {
                    if let Err(error) = self.refresh().await {
                        return gone(error);
                    }
                    next_read = tokio::time::Instant::now() + POLL;
                }
                () = over => return Outcome::Ended(EndReason::HandoffOver, None),
                () = self.page.browser().closed() => {
                    return Outcome::Ended(EndReason::BrowserGone, Some("the browser closed".to_owned()));
                }
            }
        }
    }

    /// Lays the page out at the phone's size, as a phone
    async fn lay_out(&self) -> Result<(), PageError> {
        let width = self.viewport.width.clamp(*SIDE.start(), *SIDE.end());
        let height = self.viewport.height.clamp(*SIDE.start(), *SIDE.end());
        let scale = self.viewport.scale.clamp(1.0, MAX_SCALE);
        self.page
            .session()
            .call(
                "Emulation.setDeviceMetricsOverride",
                json!({
                    "width": width,
                    "height": height,
                    "deviceScaleFactor": scale,
                    "mobile": true,
                    "screenWidth": width,
                    "screenHeight": height,
                }),
            )
            .await?;

        Ok(())
    }

    async fn start_screencast(&self) -> Result<(), PageError> {
        let scale = self.viewport.scale.clamp(1.0, MAX_SCALE);
        let pixels =
            |points: u32| (f64::from(points.clamp(*SIDE.start(), *SIDE.end())) * scale).round();
        self.page
            .session()
            .call(
                "Page.startScreencast",
                json!({
                    "format": "jpeg",
                    "quality": QUALITY,
                    "maxWidth": pixels(self.viewport.width),
                    "maxHeight": pixels(self.viewport.height),
                    "everyNthFrame": 1,
                }),
            )
            .await?;

        Ok(())
    }

    /// Puts the page back as the agent had it
    async fn restore(&self) {
        let session = self.page.session();
        let _ = session.call("Page.stopScreencast", json!({})).await;
        let _ = session
            .call("Emulation.clearDeviceMetricsOverride", json!({}))
            .await;
    }

    /// Sends one screencast image to the phone; the browser is acknowledged
    /// once the phone has drawn it
    async fn screen(&mut self, params: &serde_json::Value) -> Result<(), PageError> {
        let Some(browser_id) = params["sessionId"].as_i64() else {
            return Ok(());
        };
        let Some(jpeg) = params["data"]
            .as_str()
            .and_then(|data| STANDARD.decode(data).ok())
        else {
            return self.ack_browser(browser_id).await;
        };
        let metadata = &params["metadata"];
        let page_width = metadata["deviceWidth"].as_f64().unwrap_or_default();
        let page_height = metadata["deviceHeight"].as_f64().unwrap_or_default();
        let (width, height) = jpeg_size(&jpeg).unwrap_or_default();

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.sizes.push_back((seq, page_width, page_height));
        while self.sizes.len() > KEPT_IMAGES {
            self.sizes.pop_front();
        }
        // one in flight at a time: the browser sends the next image only
        // after it is acknowledged, so an older one is never waiting here
        self.unacked = Some((seq, browser_id));
        let screen = Screen {
            header: ScreenHeader { seq, width, height },
            jpeg,
        };
        if self
            .output
            .send(GatewayFrame::Screen(screen))
            .await
            .is_err()
        {
            return Err(PageError::Refused("the phone is gone".to_owned()));
        }

        Ok(())
    }

    async fn ack_browser(&self, browser_id: i64) -> Result<(), PageError> {
        self.page
            .session()
            .call(
                "Page.screencastFrameAck",
                json!({ "sessionId": browser_id }),
            )
            .await?;

        Ok(())
    }

    /// The page point at `at` on image `seq`, in CSS pixels
    fn point(&self, at: Point, seq: u32) -> Option<(f64, f64)> {
        let (_, width, height) = self
            .sizes
            .iter()
            .rev()
            .find(|(kept, _, _)| *kept == seq)
            .or_else(|| self.sizes.back())?;
        let x = at.x.clamp(0.0, 1.0) * width;
        let y = at.y.clamp(0.0, 1.0) * height;

        Some((x, y))
    }

    async fn click(&self, x: f64, y: f64, button: &str) -> Result<(), PageError> {
        let session = self.page.session();
        let buttons = if button == "right" { 2 } else { 1 };
        session
            .call(
                "Input.dispatchMouseEvent",
                json!({ "type": "mouseMoved", "x": x, "y": y }),
            )
            .await?;
        for kind in ["mousePressed", "mouseReleased"] {
            session
                .call(
                    "Input.dispatchMouseEvent",
                    json!({
                        "type": kind,
                        "x": x,
                        "y": y,
                        "button": button,
                        "buttons": if kind == "mousePressed" { buttons } else { 0 },
                        "clickCount": 1,
                    }),
                )
                .await?;
        }

        Ok(())
    }

    /// Acts on one message; `Some` when it ends the takeover
    async fn handle(&mut self, message: PhoneMessage) -> Result<Option<Outcome>, PageError> {
        match message {
            PhoneMessage::Open { .. } => {}
            PhoneMessage::Ack { seq } => {
                if let Some((unacked, browser_id)) = self.unacked
                    && unacked == seq
                {
                    self.unacked = None;
                    self.ack_browser(browser_id).await?;
                }
            }
            PhoneMessage::Resize { viewport } => {
                self.viewport = viewport;
                self.lay_out().await?;
                // the image size follows the new area
                let session = self.page.session();
                let _ = session.call("Page.stopScreencast", json!({})).await;
                self.unacked = None;
                self.start_screencast().await?;
            }
            PhoneMessage::Tap { at, seq } => {
                if let Some((x, y)) = self.point(at, seq) {
                    self.click(x, y, "left").await?;
                }
            }
            PhoneMessage::LongPress { at, seq } => {
                if let Some((x, y)) = self.point(at, seq) {
                    self.click(x, y, "right").await?;
                }
            }
            PhoneMessage::Scroll { at, dx, dy, seq } => {
                if let (Some((x, y)), Some((_, width, height))) = (
                    self.point(at, seq),
                    self.sizes
                        .iter()
                        .rev()
                        .find(|(kept, _, _)| *kept == seq)
                        .copied()
                        .or(self.sizes.back().copied()),
                ) {
                    self.page
                        .session()
                        .call(
                            "Input.dispatchMouseEvent",
                            json!({
                                "type": "mouseWheel",
                                "x": x,
                                "y": y,
                                "deltaX": dx.clamp(-4.0, 4.0) * width,
                                "deltaY": dy.clamp(-4.0, 4.0) * height,
                            }),
                        )
                        .await?;
                }
            }
            PhoneMessage::Key { key } => self.page.press(key).await?,
            PhoneMessage::Back => self.back().await?,
            PhoneMessage::Text { text } => {
                let text = Zeroizing::new(text.into_inner());
                if text.chars().count() > MAX_TEXT_CHARS {
                    self.refuse(format!(
                        "text over {MAX_TEXT_CHARS} characters was not typed"
                    ))
                    .await;
                } else {
                    self.page.insert_text(&text).await?;
                }
            }
            PhoneMessage::Fill {
                field,
                value,
                submit,
                site,
            } => {
                let value = Zeroizing::new(value.into_inner());
                match self.fill(field, value, submit, site.as_deref()).await {
                    Ok(()) => {
                        let filled = GatewayMessage::Filled { field };
                        let _ = self.output.send(GatewayFrame::Message(filled)).await;
                    }
                    Err(PageError::Refused(reason)) => self.refuse(reason).await,
                    Err(error) => return Err(error),
                }
            }
            PhoneMessage::Done => return Ok(Some(Outcome::Ended(EndReason::Done, None))),
            PhoneMessage::Cancel => return Ok(Some(Outcome::Ended(EndReason::Cancelled, None))),
        }

        Ok(None)
    }

    async fn refuse(&self, message: String) {
        let refused = GatewayMessage::Refused { message };
        let _ = self.output.send(GatewayFrame::Message(refused)).await;
    }

    /// Fills `field` with what the owner gave, checked as an agent's fill is,
    /// on the site the page is on
    async fn fill(
        &mut self,
        field: LoginField,
        value: Zeroizing<String>,
        submit: bool,
        chosen_for: Option<&str>,
    ) -> Result<(), PageError> {
        let state = self.page.state().await?;
        let site = page_site(&state.url)
            .ok_or_else(|| PageError::Refused("the page is not an https site".to_owned()))?;
        if let Some(chosen_for) = chosen_for.filter(|chosen_for| *chosen_for != site) {
            return Err(PageError::Refused(format!(
                "the value was chosen for {chosen_for}, but the page is now on {site}, so it was \
                 not filled"
            )));
        }
        state.check(field, &site)?;
        let typed =
            login_value(field, value, &self.context.redactor).map_err(PageError::Refused)?;
        let Some(focused) = &state.focus else {
            return Err(PageError::Refused("nothing has focus".to_owned()));
        };
        self.page.replace_text(focused, &typed, submit).await?;
        self.state = Some(state);

        Ok(())
    }

    async fn back(&self) -> Result<(), PageError> {
        let history = self
            .page
            .session()
            .call("Page.getNavigationHistory", json!({}))
            .await?;
        let current = history["currentIndex"].as_u64().unwrap_or_default();
        let Some(previous) = current.checked_sub(1) else {
            return Ok(());
        };
        let Some(entry) = history["entries"]
            .get(usize::try_from(previous).unwrap_or(usize::MAX))
            .and_then(|entry| entry["id"].as_i64())
        else {
            return Ok(());
        };
        self.page
            .session()
            .call("Page.navigateToHistoryEntry", json!({ "entryId": entry }))
            .await?;

        Ok(())
    }

    /// Reads the page and tells the phone what changed
    async fn refresh(&mut self) -> Result<(), PageError> {
        let state = match self.page.state().await {
            Ok(state) => state,
            // a page between documents has no frame tree for a moment
            Err(PageError::Cdp(CdpError::Command { .. })) => return Ok(()),
            Err(error) => return Err(error),
        };
        let focus = state.focus.as_ref().map(|focused| {
            let element = &focused.element;
            let cross_site = page_site(&state.url).is_some_and(|site| {
                focused.frames.iter().any(|origin| {
                    reqwest::Url::parse(origin)
                        .ok()
                        .and_then(|url| url.host_str().map(site_of))
                        .is_none_or(|frame_site| frame_site != site)
                })
            });

            Focus {
                field: element.login_field(),
                editable: element.editable,
                secure: element.secure(),
                numeric: element.numeric(),
                origin: focused.origin.clone(),
                cross_site,
            }
        });
        let site = page_site(&state.url);
        let shown = Shown {
            url: state.url.clone(),
            title: state.title.clone(),
            focus: focus.clone(),
            site: site.clone(),
        };
        if shown != self.shown {
            let offers = match &site {
                Some(site) => (self.context.offers)(site),
                None => Vec::new(),
            };
            let page = GatewayMessage::Page {
                url: state.url.clone(),
                title: state.title.clone(),
                focus,
                offers,
            };
            if self.output.send(GatewayFrame::Message(page)).await.is_err() {
                return Err(PageError::Refused("the phone is gone".to_owned()));
            }
            self.shown = shown;
        }
        self.state = Some(state);

        Ok(())
    }
}

/// The site of an `https` page on the default port
fn page_site(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    if url.scheme() != "https" || url.port().is_some() {
        return None;
    }

    url.host_str().map(site_of)
}

fn gone(error: PageError) -> Outcome {
    Outcome::Ended(EndReason::BrowserGone, Some(error.to_string()))
}

/// The pixel size of a JPEG, from its start-of-frame marker
fn jpeg_size(jpeg: &[u8]) -> Option<(u32, u32)> {
    let mut at = 2;
    while at + 9 < jpeg.len() {
        if jpeg[at] != 0xff {
            return None;
        }
        let marker = jpeg[at + 1];
        let length = usize::from(u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]));
        // SOF0 to SOF15, except DHT, JPG and DAC
        if (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            let height = u16::from_be_bytes([jpeg[at + 5], jpeg[at + 6]]);
            let width = u16::from_be_bytes([jpeg[at + 7], jpeg[at + 8]]);

            return Some((u32::from(width), u32::from(height)));
        }
        at += 2 + length;
    }

    None
}
