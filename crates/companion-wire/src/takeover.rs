//! What a phone and the gateway send each other while the owner takes over
//! a browser session of the gateway Mac, on [`TAKEOVER_ALPN`]
//!
//! The phone dials one connection per takeover and opens one bidirectional
//! stream on it. Its first message is [`PhoneMessage::Open`]; from then on
//! the gateway sends the live page as [`Screen`] images and what changed on
//! it as [`GatewayMessage`]s, and the phone sends the owner's taps, scrolls,
//! keys and text. The gateway sends the next image only once the phone has
//! acknowledged the last, so a slow link gets fewer images rather than a
//! growing queue
//!
//! Every frame on the stream is a 4-byte big-endian length, then a kind
//! byte and that many bytes less one of body:
//!
//! - [`MESSAGE`]: a JSON [`PhoneMessage`] or [`GatewayMessage`], tagged by
//!   its variant as serde's default does, such as `{"tap": {...}}` or
//!   `"done"`. Not an internal `type` tag: serde buffers such a message
//!   before reading it, and a buffered number fails to read as one when
//!   `serde_json`'s `arbitrary_precision` is on, as it is in the gateway
//! - [`SCREEN`]: a 2-byte big-endian length, that much JSON
//!   [`ScreenHeader`], then the JPEG image
//!
//! Text the owner types and values they fill travel as [`Secret`], whose
//! `Debug` never shows them; the gateway inserts them into the page and
//! keeps nothing

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::mobile::{LoginField, RequestId, Sealed};

/// Protocol name of a takeover, which the phone dials and the gateway
/// accepts only from the phones its config lists
pub const TAKEOVER_ALPN: &[u8] = b"codemode-mcp/takeover/1";

/// Kind byte of a JSON message
pub const MESSAGE: u8 = 0;

/// Kind byte of a screen image
pub const SCREEN: u8 = 1;

/// Bytes before every frame's body: its length and kind
pub const HEADER_BYTES: usize = 5;

/// Longest JSON message either side sends; a sealed copy offered for a fill
/// is the largest
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Longest screen image, header included; a phone-sized JPEG is far below
pub const MAX_SCREEN_BYTES: usize = 4 * 1024 * 1024;

/// Longest text the owner may type or fill in one message
pub const MAX_TEXT_CHARS: usize = 4096;

/// Text the owner typed or a value they fill, which never shows in `Debug`
/// and is wiped when dropped
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Secret {
    /// Wraps `text`
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The text
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The text, unwrapped; the caller then owns wiping it
    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Secret({} chars)", self.0.chars().count())
    }
}

/// The phone's screen area for the page, in points, and its pixels per
/// point; the gateway lays the page out at this size as a mobile device
/// while the takeover is open
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Viewport {
    /// Width in points
    pub width: u32,
    /// Height in points
    pub height: u32,
    /// Pixels per point, such as 3 on most iPhones
    pub scale: f64,
}

/// A point on the image the phone shows, as fractions of its width and
/// height from the top left, so the phone needs no knowledge of the page's
/// own coordinates
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Point {
    /// From 0 at the left edge to 1 at the right
    pub x: f64,
    /// From 0 at the top edge to 1 at the bottom
    pub y: f64,
}

/// A key on the phone's key bar
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Key {
    /// Return
    Enter,
    /// Tab
    Tab,
    /// Shift-Tab, back to the previous field
    ShiftTab,
    /// Delete the character before the caret
    Backspace,
    /// Escape
    Escape,
}

/// What the phone sends on a takeover
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneMessage {
    /// The first message: which session to take over and how big to draw it
    Open {
        /// The browser session, such as `github`
        session: String,
        /// The handoff this takeover answers, from the push or the request;
        /// Done and Cancel then end that handoff
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff: Option<RequestId>,
        /// The phone's screen area for the page
        viewport: Viewport,
    },
    /// The phone drew the image `seq`, so the gateway may send the next
    Ack {
        /// The image's [`ScreenHeader::seq`]
        seq: u32,
    },
    /// The phone's screen area changed, such as on rotation
    Resize {
        /// The new area
        viewport: Viewport,
    },
    /// A tap: a left click at `at`
    Tap {
        /// Where, on the image `seq`
        at: Point,
        /// The image the owner tapped
        seq: u32,
    },
    /// A long press: a right click at `at`
    LongPress {
        /// Where, on the image `seq`
        at: Point,
        /// The image the owner pressed
        seq: u32,
    },
    /// A swipe: scroll the page under `at` by `dx` and `dy`, as fractions of
    /// the image's width and height; positive scrolls right and down
    Scroll {
        /// Where, on the image `seq`
        at: Point,
        /// Horizontal distance
        dx: f64,
        /// Vertical distance
        dy: f64,
        /// The image the owner swiped
        seq: u32,
    },
    /// A key from the key bar, sent to the focused element
    Key {
        /// Which
        key: Key,
    },
    /// Go back in the session's history
    Back,
    /// Load the page again
    Reload,
    /// Text the owner typed, inserted at the caret of the focused element
    Text {
        /// The text, at most [`MAX_TEXT_CHARS`]
        text: Secret,
    },
    /// A login value for the focused field, checked as an agent's fill is: an
    /// `https` page, a field of that kind, and no frame from another site.
    /// It replaces what the field holds
    Fill {
        /// The field it is for
        field: LoginField,
        /// The value: typed, from AutoFill, or a sealed copy the gateway
        /// offered, opened with Face ID. For a code, a seed (`otpauth://` or base32)
        /// is turned into the current code by the gateway
        value: Secret,
        /// Press Return after it
        #[serde(default)]
        submit: bool,
        /// The site the owner chose the value for, such as an offer's
        /// [`FillOffer::site`]; the fill is refused when the page is no
        /// longer on it, as when the page moved while Face ID was up
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
    },
    /// The owner finished; ends the takeover and its handoff as done
    Done,
    /// The owner gave up; ends the takeover and its handoff as cancelled
    Cancel,
}

/// Why the gateway ended a takeover
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The owner tapped Done
    Done,
    /// The owner tapped Cancel
    Cancelled,
    /// The handoff ended elsewhere: another phone answered it, the agent
    /// stopped waiting, or it expired
    HandoffOver,
    /// The browser session closed, or its page could not be reached
    BrowserGone,
    /// The gateway is stopping
    Shutdown,
}

/// The element with keyboard focus on the page
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Focus {
    /// The login field it looks like, when it looks like one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<LoginField>,
    /// Whether it takes text, so the phone raises the keyboard
    pub editable: bool,
    /// Whether it hides its text, as a password field does
    pub secure: bool,
    /// Whether it asks for digits, so the phone shows the number pad
    pub numeric: bool,
    /// Origin of the frame holding it, such as `https://github.com`
    pub origin: String,
    /// Whether that frame is on another site than the page
    pub cross_site: bool,
}

/// A login value the phone holds a sealed copy of for the page's site, which
/// it may open with Face ID and send back as [`PhoneMessage::Fill`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FillOffer {
    /// The field it fills
    pub field: LoginField,
    /// The `op://` reference, which the seal's `info` binds
    pub reference: String,
    /// The value, sealed to this phone
    pub sealed: Sealed,
    /// The 1Password item, such as `GitHub (Personal)`
    pub item: String,
    /// The account, such as the login's username
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The site the value is saved for, such as `github.com`; the phone
    /// sends it back with the fill, which the gateway refuses once the page
    /// is on another site
    pub site: String,
}

/// What the gateway sends on a takeover besides the images
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMessage {
    /// The page and its focused element, sent after [`PhoneMessage::Open`]
    /// and whenever either changes
    Page {
        /// The address of the top-level page
        url: String,
        /// The page's title
        #[serde(default, skip_serializing_if = "String::is_empty")]
        title: String,
        /// The element with keyboard focus; `None` when nothing that takes
        /// text has it
        #[serde(default, skip_serializing_if = "Option::is_none")]
        focus: Option<Focus>,
        /// Login values the phone can fill from sealed copies on this site
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        offers: Vec<FillOffer>,
    },
    /// A fill went in
    Filled {
        /// The field filled
        field: LoginField,
    },
    /// Something the owner asked for was not done; the takeover goes on
    Refused {
        /// Why, never holding a value
        message: String,
    },
    /// The takeover is over, and the gateway closes the stream next
    Ended {
        /// Why
        reason: EndReason,
        /// More detail, such as why the browser could not be reached
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

/// How the page in a [`Screen`] maps to its image
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScreenHeader {
    /// Counts up from 0 within a takeover; the phone acknowledges it and
    /// names it with each tap
    pub seq: u32,
    /// Width of the image in pixels
    pub width: u32,
    /// Height of the image in pixels
    pub height: u32,
}

/// One image of the page
#[derive(Clone, PartialEq)]
pub struct Screen {
    /// How it maps to the page
    pub header: ScreenHeader,
    /// The JPEG image
    pub jpeg: Vec<u8>,
}

impl std::fmt::Debug for Screen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Screen")
            .field("header", &self.header)
            .field("jpeg", &self.jpeg.len())
            .finish()
    }
}

/// What the gateway sends: a message or an image
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayFrame {
    /// A message
    Message(GatewayMessage),
    /// An image of the page
    Screen(Screen),
}

/// Why a frame could not be written or read
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Longer than the protocol allows for its kind
    #[error("a {kind} frame of {bytes} bytes is over the limit")]
    TooLarge {
        /// `message` or `screen`
        kind: &'static str,
        /// Its length
        bytes: usize,
    },
    /// A kind byte this side does not know, or one the other side may not
    /// send
    #[error("unexpected frame kind {0}")]
    UnknownKind(u8),
    /// The body was not what its kind says
    #[error("malformed frame: {0}")]
    Malformed(String),
}

/// The kind and body length of the frame `header` starts
pub fn read_header(header: [u8; HEADER_BYTES]) -> Result<(u8, usize), FrameError> {
    let [a, b, c, d, kind] = header;
    let length = u32::from_be_bytes([a, b, c, d]) as usize;
    // the length counts the kind byte
    let body = length
        .checked_sub(1)
        .ok_or_else(|| FrameError::Malformed("a frame has no kind".to_owned()))?;
    let limit = match kind {
        MESSAGE => MAX_MESSAGE_BYTES,
        SCREEN => MAX_SCREEN_BYTES,
        other => return Err(FrameError::UnknownKind(other)),
    };
    if body > limit {
        return Err(FrameError::TooLarge {
            kind: kind_name(kind),
            bytes: body,
        });
    }

    Ok((kind, body))
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        SCREEN => "screen",
        _ => "message",
    }
}

fn frame(kind: u8, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    let limit = match kind {
        SCREEN => MAX_SCREEN_BYTES,
        _ => MAX_MESSAGE_BYTES,
    };
    if body.len() > limit {
        return Err(FrameError::TooLarge {
            kind: kind_name(kind),
            bytes: body.len(),
        });
    }
    // under the limits, so it fits in a u32 with the kind byte
    let length = u32::try_from(body.len() + 1).map_err(|_| FrameError::TooLarge {
        kind: kind_name(kind),
        bytes: body.len(),
    })?;

    let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(body);

    Ok(bytes)
}

/// A JSON message as one frame
pub fn encode_message(message: &impl Serialize) -> Result<Vec<u8>, FrameError> {
    let body =
        serde_json::to_vec(message).map_err(|error| FrameError::Malformed(error.to_string()))?;

    frame(MESSAGE, &body)
}

/// An image as one frame
pub fn encode_screen(screen: &Screen) -> Result<Vec<u8>, FrameError> {
    let header = serde_json::to_vec(&screen.header)
        .map_err(|error| FrameError::Malformed(error.to_string()))?;
    let header_length = u16::try_from(header.len())
        .map_err(|_| FrameError::Malformed("the screen header is too long".to_owned()))?;

    let mut body = Vec::with_capacity(2 + header.len() + screen.jpeg.len());
    body.extend_from_slice(&header_length.to_be_bytes());
    body.extend_from_slice(&header);
    body.extend_from_slice(&screen.jpeg);

    frame(SCREEN, &body)
}

fn decode_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|error| FrameError::Malformed(error.to_string()))
}

/// Reads the body of a frame the gateway sent
pub fn decode_gateway(kind: u8, body: &[u8]) -> Result<GatewayFrame, FrameError> {
    match kind {
        MESSAGE => decode_json(body).map(GatewayFrame::Message),
        SCREEN => {
            let (length, rest) = body
                .split_first_chunk::<2>()
                .ok_or_else(|| FrameError::Malformed("a screen has no header".to_owned()))?;
            let length = usize::from(u16::from_be_bytes(*length));
            if rest.len() < length {
                return Err(FrameError::Malformed(
                    "a screen's header runs past its end".to_owned(),
                ));
            }
            let (header, jpeg) = rest.split_at(length);

            Ok(GatewayFrame::Screen(Screen {
                header: decode_json(header)?,
                jpeg: jpeg.to_vec(),
            }))
        }
        other => Err(FrameError::UnknownKind(other)),
    }
}

/// Reads the body of a frame the phone sent; a phone sends only messages
pub fn decode_phone(kind: u8, body: &[u8]) -> Result<PhoneMessage, FrameError> {
    match kind {
        MESSAGE => decode_json(body),
        other => Err(FrameError::UnknownKind(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(frame: &[u8]) -> (u8, &[u8]) {
        let (header, body) = frame.split_at(HEADER_BYTES);
        let header: [u8; HEADER_BYTES] = header.try_into().unwrap_or_default();
        let (kind, length) = read_header(header).unwrap_or((u8::MAX, usize::MAX));
        assert_eq!(length, body.len());

        (kind, body)
    }

    #[test]
    fn frames_read_back_as_written() {
        let screen = Screen {
            header: ScreenHeader {
                seq: 7,
                width: 1179,
                height: 2556,
            },
            jpeg: vec![0xff, 0xd8, 0xff, 0xe0, 0, 1],
        };
        let written = encode_screen(&screen).unwrap_or_default();
        let (kind, body) = split(&written);
        assert_eq!(
            decode_gateway(kind, body).ok(),
            Some(GatewayFrame::Screen(screen))
        );

        let fill = PhoneMessage::Fill {
            field: LoginField::Code,
            value: Secret::new("123456".to_owned()),
            submit: true,
            site: Some("github.com".to_owned()),
        };
        let written = encode_message(&fill).unwrap_or_default();
        let (kind, body) = split(&written);
        assert_eq!(decode_phone(kind, body).ok(), Some(fill.clone()));
        assert!(!format!("{fill:?}").contains("123456"));
        // a phone may not send images
        assert_eq!(
            decode_phone(SCREEN, body),
            Err(FrameError::UnknownKind(SCREEN))
        );
    }

    #[test]
    fn oversized_and_unknown_frames_are_refused_from_the_header() {
        let too_long = u32::try_from(MAX_MESSAGE_BYTES + 2).unwrap_or(u32::MAX);
        let [a, b, c, d] = too_long.to_be_bytes();
        assert!(matches!(
            read_header([a, b, c, d, MESSAGE]),
            Err(FrameError::TooLarge { .. })
        ));
        assert_eq!(
            read_header([0, 0, 0, 1, 9]),
            Err(FrameError::UnknownKind(9))
        );
        assert!(read_header([0, 0, 0, 0, MESSAGE]).is_err());
    }
}
