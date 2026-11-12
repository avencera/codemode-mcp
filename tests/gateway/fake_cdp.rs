//! A stand-in for an agent-browser session: a DevTools endpoint that answers
//! the commands the `browser` builtin sends with a page the test sets, and
//! an `agent-browser` script that points at it

use std::{
    error::Error,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_tungstenite::tungstenite::Message;

use super::harness::temp_state_dir;

/// The page's CDP session id, as `Target.attachToTarget` answers it
const SESSION: &str = "page-session";
/// The active tab's target id
const TARGET: &str = "page-target";
/// Screencast images sent before the browser waits for its acknowledgement;
/// a real one sends the next only after the last is acknowledged
const IMAGES: u32 = 3;
/// The page's size in CSS pixels, as screencast images report it
const PAGE: (u16, u16) = (390, 844);
/// The device scale a capture is drawn at, the phone's
const SCALE: u16 = 3;

/// The focused element, as the page's `DESCRIBE` script reports it
#[derive(Clone)]
pub struct Field {
    pub input_type: &'static str,
    pub autocomplete: &'static str,
    pub name: &'static str,
}

impl Field {
    pub const PASSWORD: Self = Self {
        input_type: "password",
        autocomplete: "current-password",
        name: "password",
    };
    pub const USERNAME: Self = Self {
        input_type: "text",
        autocomplete: "username",
        name: "login",
    };
}

struct State {
    url: String,
    focus: Option<Field>,
    /// Every command, as `method` or `method params` for input and layout
    log: Vec<String>,
    /// Text inserted into the page
    typed: String,
    images: u32,
    /// A capture drew the page again, so the next screencast image repeats
    /// the last, as Chrome's does
    echo: bool,
}

/// The browser; its log shows what the gateway did to the page
#[derive(Clone)]
pub struct FakeCdp {
    state: Arc<Mutex<State>>,
    /// The `agent-browser` script for the gateway's `agent_browser_path`
    pub program: PathBuf,
}

impl FakeCdp {
    /// A browser showing `url` with nothing focused
    pub async fn start(url: &str) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            url: url.to_owned(),
            focus: None,
            log: Vec::new(),
            typed: String::new(),
            images: 0,
            echo: false,
        }));
        let serving = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&serving);
                tokio::spawn(async move {
                    if let Ok(socket) = tokio_tungstenite::accept_async(stream).await {
                        serve(socket, state).await;
                    }
                });
            }
        });

        Ok(Self {
            state,
            program: agent_browser(address)?,
        })
    }

    fn with<T>(&self, change: impl FnOnce(&mut State) -> T) -> T {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        change(&mut state)
    }

    pub fn focus(&self, field: Option<Field>) {
        self.with(|state| state.focus = field);
    }

    pub fn log(&self) -> Vec<String> {
        self.with(|state| state.log.clone())
    }

    pub fn typed(&self) -> String {
        self.with(|state| state.typed.clone())
    }
}

/// An `agent-browser` that knows one session, `test`, at `address`
fn agent_browser(address: SocketAddr) -> Result<PathBuf, Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let program = directory.join("agent-browser");
    let tabs = json!({
        "success": true,
        "data": { "tabs": [{ "active": true, "targetId": TARGET, "title": "Sign in" }] },
        "error": null,
    });
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             [ \"$2\" = test ] || {{ echo 'no such session' >&2; exit 1; }}\n\
             case \"$*\" in\n\
             *cdp-url*) echo 'ws://127.0.0.1:{port}/devtools/browser/fake' ;;\n\
             *'tab list'*) echo '{tabs}' ;;\n\
             *) exit 2 ;;\n\
             esac\n",
            port = address.port(),
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok(program)
}

type Socket = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn serve(socket: Socket, state: Arc<Mutex<State>>) {
    let (mut sink, mut stream) = socket.split();
    let (outgoing, mut queued) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        while let Some(message) = queued.recv().await {
            if sink.send(Message::text(message.to_string())).await.is_err() {
                return;
            }
        }
    });

    while let Some(Ok(message)) = stream.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let Ok(command) = serde_json::from_str::<Value>(text.as_str()) else {
            continue;
        };
        let id = command["id"].clone();
        let method = command["method"].as_str().unwrap_or_default().to_owned();
        let params = &command["params"];
        let (result, frame) = {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            answer(&mut state, &method, params)
        };
        let _ = outgoing.send(json!({ "id": id, "result": result }));
        if let Some(frame) = frame {
            let _ = outgoing.send(json!({
                "method": "Page.screencastFrame",
                "sessionId": SESSION,
                "params": {
                    "data": STANDARD.encode(frame),
                    "sessionId": 1,
                    "metadata": { "deviceWidth": PAGE.0, "deviceHeight": PAGE.1 },
                },
            }));
        }
    }
}

/// A JPEG header of `width` by `height` pixels, which `tag` tells apart from
/// another of the same size
fn jpeg(width: u16, height: u16, tag: u32) -> Vec<u8> {
    let [height_high, height_low] = height.to_be_bytes();
    let [width_high, width_low] = width.to_be_bytes();
    let mut jpeg = vec![
        0xFF,
        0xD8,
        0xFF,
        0xC0,
        0x00,
        0x08,
        0x08,
        height_high,
        height_low,
        width_high,
        width_low,
        0x00,
        0xFF,
        0xFE,
        0x00,
        0x06,
    ];
    jpeg.extend(tag.to_be_bytes());
    jpeg.extend([0xFF, 0xD9]);
    jpeg
}

/// The answer to `method`, and the screencast image that follows it, which
/// is drawn at one pixel per CSS pixel as headless Chrome's are
fn answer(state: &mut State, method: &str, params: &Value) -> (Value, Option<Vec<u8>>) {
    match method {
        "Emulation.setDeviceMetricsOverride" | "Input.dispatchMouseEvent" => {
            state.log.push(format!("{method} {params}"));
        }
        "Input.dispatchKeyEvent" => state.log.push(format!("{method} {}", params["key"])),
        // the text itself is kept apart, so the log can be shown in a failure
        "Input.insertText" => {
            state.log.push(method.to_owned());
            state
                .typed
                .push_str(params["text"].as_str().unwrap_or_default());
        }
        _ => state.log.push(method.to_owned()),
    }

    let result = match method {
        "Target.attachToTarget" => json!({ "sessionId": SESSION }),
        "Page.getFrameTree" => {
            json!({ "frameTree": { "frame": { "id": "main", "url": state.url } } })
        }
        "Target.getTargetInfo" => json!({ "targetInfo": { "title": "Sign in" } }),
        "Page.createIsolatedWorld" => json!({ "executionContextId": 7 }),
        "Runtime.evaluate" if params["expression"] == "location.href" => {
            json!({ "result": { "type": "string", "value": state.url } })
        }
        "Runtime.evaluate" => match state.focus {
            Some(_) => json!({ "result": { "type": "object", "objectId": "focused" } }),
            None => json!({ "result": { "type": "object", "subtype": "null", "value": null } }),
        },
        // the focus checks around a fill: the checked field keeps focus
        "Runtime.callFunctionOn"
            if params["functionDeclaration"]
                .as_str()
                .is_some_and(|function| function.contains("activeElement !== el")) =>
        {
            json!({ "result": { "type": "boolean", "value": state.focus.is_some() } })
        }
        "Page.captureScreenshot" => {
            state.echo = true;
            let shot = jpeg(PAGE.0 * SCALE, PAGE.1 * SCALE, state.images);
            json!({ "data": STANDARD.encode(shot) })
        }
        "Runtime.callFunctionOn" if params["returnByValue"] == true => {
            let origin = reqwest::Url::parse(&state.url)
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or_default();
            let field = state.focus.clone().unwrap_or(Field::USERNAME);
            json!({ "result": { "type": "object", "value": {
                "tag": "input",
                "frame": false,
                "type": field.input_type,
                "autocomplete": field.autocomplete,
                "inputmode": "",
                "name": field.name,
                "id": field.name,
                "maxLength": -1,
                "editable": true,
                "origins": [origin],
            } } })
        }
        _ => json!({}),
    };
    let image = match method {
        "Page.startScreencast" => {
            state.images = 1;
            Some(state.images)
        }
        // the repeat a capture brings on, which is not a new image
        "Page.screencastFrameAck" if state.echo => {
            state.echo = false;
            Some(state.images)
        }
        "Page.screencastFrameAck" if state.images < IMAGES => {
            state.images += 1;
            Some(state.images)
        }
        _ => None,
    };

    (result, image.map(|tag| jpeg(PAGE.0, PAGE.1, tag)))
}
