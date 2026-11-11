//! A small Chrome DevTools Protocol client over the browser's WebSocket
//!
//! Hand-rolled rather than a CDP crate: the `browser` builtin needs a few
//! commands and events on one page, and the generated clients pull in the
//! whole protocol. One connection to the browser endpoint serves every
//! session attached to it with `flatten`, so commands and events carry a
//! `sessionId`
//!
//! Commands may carry a login value (`Input.insertText`), so nothing here
//! logs a command's params or a reply

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};
use zeroize::Zeroizing;

/// How long one command may take before it fails
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// Events kept for a slow listener before it misses some; screencast images
/// are the bulk, and a takeover acknowledges each before the next comes
const EVENT_BACKLOG: usize = 256;

/// Largest message the browser may send, such as a screencast image
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// Why a CDP command failed; never holds a command's params
#[derive(Debug, Clone, thiserror::Error)]
pub enum CdpError {
    /// The connection could not be made, or broke
    #[error("the browser connection failed: {0}")]
    Connection(String),
    /// The browser answered with an error
    #[error("{method} failed: {message}")]
    Command {
        /// The command
        method: String,
        /// The browser's message
        message: String,
    },
    /// No answer in time
    #[error("{0} got no answer in time")]
    TimedOut(String),
}

/// One event the browser sent
#[derive(Debug, Clone)]
pub struct Event {
    /// The session it belongs to; `None` for the browser's own
    pub session: Option<String>,
    /// Such as `Page.screencastFrame`
    pub method: String,
    /// Its params
    pub params: Arc<Value>,
}

type Reply = Result<Value, CdpError>;

struct Shared {
    outgoing: mpsc::UnboundedSender<Zeroizing<String>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    events: broadcast::Sender<Event>,
    next_id: AtomicU64,
    /// Set once the connection is gone
    closed: watch::Sender<bool>,
}

impl Shared {
    fn fail_pending(&self, reason: &str) {
        let pending: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for (_, waiter) in pending {
            let _ = waiter.send(Err(CdpError::Connection(reason.to_owned())));
        }
    }
}

/// A connection to a browser's DevTools endpoint; cheap to clone, and closed
/// once every clone is dropped
#[derive(Clone)]
pub struct Browser(Arc<Shared>);

impl Browser {
    /// Connects to `url`, a `ws://127.0.0.1:…/devtools/browser/…` endpoint
    pub async fn connect(url: &str) -> Result<Self, CdpError> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let (socket, _) = tokio::time::timeout(
            COMMAND_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(url, Some(config), false),
        )
        .await
        .map_err(|_| CdpError::TimedOut("connecting to the browser".to_owned()))?
        .map_err(|error| CdpError::Connection(error.to_string()))?;
        let (mut sink, mut stream) = socket.split();

        let (outgoing, mut queued) = mpsc::unbounded_channel::<Zeroizing<String>>();
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        let (closed, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            outgoing,
            pending: Mutex::new(HashMap::new()),
            events,
            next_id: AtomicU64::new(1),
            closed,
        });

        // the writer ends when every `Browser` is dropped, which closes the
        // socket and so ends the reader too
        tokio::spawn(async move {
            while let Some(text) = queued.recv().await {
                // the socket takes its own copy; ours is wiped on drop
                if sink.send(Message::text(text.as_str())).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let reader = Arc::downgrade(&shared);
        tokio::spawn(async move {
            let reason = loop {
                let Some(message) = stream.next().await else {
                    break "the browser closed the connection".to_owned();
                };
                let text = match message {
                    Ok(Message::Text(text)) => text,
                    Ok(Message::Close(_)) => break "the browser closed the connection".to_owned(),
                    Ok(_) => continue,
                    Err(error) => break error.to_string(),
                };
                let Some(shared) = reader.upgrade() else {
                    return;
                };
                dispatch(&shared, text.as_str());
            };
            if let Some(shared) = reader.upgrade() {
                shared.closed.send_replace(true);
                shared.fail_pending(&reason);
            }
        });

        Ok(Self(shared))
    }

    /// Sends `method` with `params` to `session` (the browser itself when
    /// `None`) and waits for the answer
    pub async fn call(
        &self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        let id = self.0.next_id.fetch_add(1, Ordering::Relaxed);
        // moved in rather than through `json!`, which would copy the params
        // and leave the original, which may hold a login value, unwiped
        let mut command = serde_json::Map::new();
        command.insert("id".to_owned(), Value::from(id));
        command.insert("method".to_owned(), Value::from(method));
        command.insert("params".to_owned(), params);
        if let Some(session) = session {
            command.insert("sessionId".to_owned(), Value::from(session));
        }
        let command = Value::Object(command);
        let text = Zeroizing::new(command.to_string());
        wipe(command);

        let (reply, answer) = oneshot::channel();
        self.0
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, reply);
        if *self.0.closed.borrow() || self.0.outgoing.send(text).is_err() {
            self.forget(id);

            return Err(CdpError::Connection(
                "the browser connection is closed".to_owned(),
            ));
        }

        match tokio::time::timeout(COMMAND_TIMEOUT, answer).await {
            Ok(Ok(reply)) => reply.map_err(|error| match error {
                CdpError::Command { message, .. } => CdpError::Command {
                    method: method.to_owned(),
                    message,
                },
                other => other,
            }),
            Ok(Err(_)) => Err(CdpError::Connection(
                "the browser connection closed".to_owned(),
            )),
            Err(_) => {
                self.forget(id);

                Err(CdpError::TimedOut(method.to_owned()))
            }
        }
    }

    fn forget(&self, id: u64) {
        self.0
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    /// Every event from now on
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.0.events.subscribe()
    }

    /// Resolves once the connection is gone
    pub async fn closed(&self) {
        let mut closed = self.0.closed.subscribe();
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Attaches to the page `target`, as its own session
    pub async fn attach(&self, target: &str) -> Result<Session, CdpError> {
        let attached = self
            .call(
                None,
                "Target.attachToTarget",
                json!({ "targetId": target, "flatten": true }),
            )
            .await?;
        let id = attached["sessionId"]
            .as_str()
            .ok_or_else(|| CdpError::Command {
                method: "Target.attachToTarget".to_owned(),
                message: "no session id in the answer".to_owned(),
            })?
            .to_owned();

        Ok(Session {
            browser: self.clone(),
            id,
            target: target.to_owned(),
        })
    }
}

/// Hands one message from the browser to its waiter or the event listeners
fn dispatch(shared: &Shared, text: &str) {
    let Ok(mut message) = serde_json::from_str::<Value>(text) else {
        return;
    };
    if let Some(id) = message.get("id").and_then(Value::as_u64) {
        let waiter = shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        let Some(waiter) = waiter else {
            return;
        };
        let reply = match message.get_mut("error") {
            Some(error) => Err(CdpError::Command {
                method: String::new(),
                message: error["message"]
                    .as_str()
                    .unwrap_or("unknown error")
                    .to_owned(),
            }),
            None => Ok(message
                .get_mut("result")
                .map(Value::take)
                .unwrap_or(Value::Null)),
        };
        let _ = waiter.send(reply);

        return;
    }

    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return;
    };
    let event = Event {
        session: message
            .get("sessionId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        method: method.to_owned(),
        params: Arc::new(
            message
                .get_mut("params")
                .map(Value::take)
                .unwrap_or(Value::Null),
        ),
    };
    // nobody listening is fine
    let _ = shared.events.send(event);
}

/// Overwrites every string in `value` before it is dropped
fn wipe(value: Value) {
    match value {
        Value::String(text) => drop(Zeroizing::new(text)),
        Value::Array(items) => items.into_iter().for_each(wipe),
        Value::Object(fields) => fields.into_iter().for_each(|(_, value)| wipe(value)),
        _ => {}
    }
}

/// One page attached as its own session; detached when dropped
pub struct Session {
    browser: Browser,
    id: String,
    target: String,
}

impl Session {
    /// Sends `method` to this page
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.browser.call(Some(&self.id), method, params).await
    }

    /// The connection this session is on
    pub fn browser(&self) -> &Browser {
        &self.browser
    }

    /// The session's id, which its events carry
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The page's target id
    pub fn target(&self) -> &str {
        &self.target
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let browser = self.browser.clone();
        let session = self.id.clone();
        // no runtime while the process exits is fine: the socket closes too
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = browser
                    .call(
                        None,
                        "Target.detachFromTarget",
                        json!({ "sessionId": session }),
                    )
                    .await;
            });
        }
    }
}
