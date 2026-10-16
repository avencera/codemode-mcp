//! The gateway's side of its phones: sealing values to them, waking them
//! with a push, accepting their connections and asking them to open a value
//!
//! A phone cannot be dialed while its app is suspended, so a read pushes a
//! notification naming the request, waits for the phone to dial in on
//! [`MOBILE_ALPN`], and opens a stream carrying the request on that
//! connection. Only phones listed in `secrets.phones` get past the handshake;
//! the protocol is not even offered while none is listed

use std::{
    collections::HashMap,
    sync::{Arc, PoisonError},
    time::{Duration, SystemTime},
};

use companion_wire::{
    MOBILE_ALPN,
    mobile::{PhoneRead, PhoneRequest, PhoneResponse, RequestId},
    seal,
};
use iroh::{EndpointId, endpoint::Connection};
use tokio::{sync::watch, time::Instant};

use super::{
    ASK_TIMEOUT, CompanionFailure, CompanionResponse, Companions, MAX_BODY_BYTES,
    MAX_PHONE_READ_BYTES, answer,
    apns::{Alert, PushFailure},
    read_request, short_hostname,
};
use crate::config::PhonePeer;

/// How long a phone may take to send a request on a stream it opened
const REQUEST_WINDOW: Duration = Duration::from_secs(30);

/// The newest connection of each phone that dialed in, by endpoint id; reads
/// wait on it, so a phone that dials again after its app was suspended
/// picks up the reads still waiting
#[derive(Default)]
pub(super) struct Links(std::sync::Mutex<HashMap<EndpointId, watch::Sender<Option<Connection>>>>);

impl Links {
    fn link(&self, id: EndpointId) -> watch::Sender<Option<Connection>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id)
            .or_insert_with(|| watch::channel(None).0)
            .clone()
    }

    fn drop_phone(&self, id: EndpointId) {
        let removed = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if let Some(Some(connection)) = removed.map(|link| link.borrow().clone()) {
            connection.close(0_u32.into(), b"unpaired");
        }
    }
}

/// Why one attempt on a phone's connection ended without an answer
enum Offer {
    /// The connection broke; the phone may dial again
    Lost,
    /// The phone answered with something unreadable
    Exchange(String),
}

impl Companions {
    /// The phones, as configured plus any paired since
    pub fn phones(&self) -> Vec<PhonePeer> {
        self.phones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Starts answering a newly paired phone
    pub(super) fn add_phone(&self, phone: PhonePeer) {
        self.phones
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(phone);
        self.refresh_alpns();
    }

    /// Binds the endpoint and accepts the listed phones' connections, so a
    /// phone opened after a restart finds the gateway before the next read;
    /// does nothing while no phone is listed
    pub async fn listen_for_phones(self: &Arc<Self>) -> Result<(), CompanionFailure> {
        if self.phones().is_empty() {
            return Ok(());
        }
        let endpoint = self.endpoint().await?;
        self.start_accepting(endpoint);
        self.refresh_alpns();

        Ok(())
    }

    /// Whether the phone called `name` holds a sealed copy of `reference`
    pub fn has_seal(&self, name: &str, reference: &str) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        let Some(phone) = self.phones().into_iter().find(|phone| phone.name == name) else {
            return false;
        };

        matches!(store.seal(&phone.id.to_string(), reference), Ok(Some(_)))
    }

    /// Seals `value` to every phone, replacing older copies; the value
    /// itself is not kept. Failures are logged: a phone without a fresh
    /// copy answers with the old one or not at all, and the read that
    /// produced the value has succeeded either way
    pub async fn seal_for_phones(&self, reference: &str, value: &str) {
        let phones = self.phones();
        if phones.is_empty() {
            return;
        }
        let Some(store) = &self.store else {
            return;
        };
        let gateway = match self.id().await {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(%error, "cannot seal for the phones without this gateway's id");

                return;
            }
        };

        for phone in phones {
            let sealed = match seal::seal(&phone.seal_key, &gateway, reference, value.as_bytes()) {
                Ok(sealed) => sealed,
                Err(error) => {
                    tracing::warn!(phone = %phone.name, %error, "could not seal a value");

                    continue;
                }
            };
            if let Err(error) = store.put_seal(&phone.id.to_string(), reference, &sealed) {
                tracing::warn!(phone = %phone.name, %error, "could not store a sealed value");
            }
        }
    }

    /// Seals every value this process has read to `phone`, so a newly paired
    /// phone can answer at once instead of after each reference's next read
    pub(super) async fn backfill(&self, phone: &PhonePeer) {
        let Some(known) = self.known.get() else {
            return;
        };
        // a read in progress holds the cache until its prompt is answered
        let Ok(known) = tokio::time::timeout(REQUEST_WINDOW, known.lock()).await else {
            tracing::info!(phone = %phone.name, "a read was in progress; nothing sealed at pairing");

            return;
        };
        let values: Vec<(String, String)> = known
            .iter()
            .map(|(reference, value)| (reference.clone(), value.clone()))
            .collect();
        drop(known);

        let Some(store) = &self.store else {
            return;
        };
        let Ok(gateway) = self.id().await else {
            return;
        };
        for (reference, value) in values {
            match seal::seal(&phone.seal_key, &gateway, &reference, value.as_bytes()) {
                Ok(sealed) => {
                    if let Err(error) = store.put_seal(&phone.id.to_string(), &reference, &sealed) {
                        tracing::warn!(phone = %phone.name, %error, "could not store a sealed value");
                    }
                }
                Err(error) => tracing::warn!(phone = %phone.name, %error, "could not seal a value"),
            }
        }
    }

    /// Asks the phone called `name` for `reference`, sending its sealed copy
    /// if there is one: pushes to wake it, then waits up to `within` for it
    /// to dial in and answer; the phone's prompt shows the same deadline
    pub async fn read_phone(
        self: &Arc<Self>,
        name: &str,
        reference: &str,
        within: Duration,
    ) -> Result<String, CompanionFailure> {
        let phone = self
            .phones()
            .into_iter()
            .find(|phone| phone.name == name)
            .ok_or_else(|| CompanionFailure::Unknown(name.to_owned()))?;

        let within = within.min(ASK_TIMEOUT);
        let deadline = Instant::now() + within;
        tokio::time::timeout(within, self.ask_phone(&phone, reference, deadline))
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: phone.name.clone(),
                    timeout: within,
                })
            })
    }

    async fn ask_phone(
        self: &Arc<Self>,
        phone: &PhonePeer,
        reference: &str,
        deadline: Instant,
    ) -> Result<String, CompanionFailure> {
        let key = phone.id.to_string();
        // without a copy the owner enters the value on the phone
        let sealed = self
            .store
            .as_ref()
            .and_then(|store| store.seal(&key, reference).ok().flatten());
        let endpoint = self.endpoint().await?;
        self.start_accepting(endpoint);
        self.refresh_alpns();

        let id = RequestId::generate();
        let expires = SystemTime::now() + deadline.saturating_duration_since(Instant::now());
        self.wake(phone, &id, reference, expires);

        let mut link = self.links.link(phone.id).subscribe();
        let mut lost: Option<usize> = None;
        loop {
            let connection = link
                .wait_for(|current| {
                    current
                        .as_ref()
                        .is_some_and(|connection| Some(connection.stable_id()) != lost)
                })
                .await
                .map_err(|_| CompanionFailure::Exchange {
                    name: phone.name.clone(),
                    detail: "the gateway is shutting down".to_owned(),
                })?
                .clone();
            let Some(connection) = connection else {
                continue;
            };

            let read = PhoneRead {
                id: id.clone(),
                reference: reference.to_owned(),
                sealed: sealed.clone(),
                expires_in_ms: u64::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
            };
            match offer(&connection, &read).await {
                Ok(CompanionResponse::Value(value)) => {
                    tracing::info!(phone = %phone.name, %id, "phone answered a read");

                    return Ok(value);
                }
                Ok(CompanionResponse::Error(fault)) => {
                    return Err(CompanionFailure::Refused {
                        code: fault.code,
                        message: fault.message,
                    });
                }
                Err(Offer::Lost) => {
                    tracing::debug!(phone = %phone.name, %id, "phone connection lost mid-read");
                    lost = Some(connection.stable_id());
                }
                Err(Offer::Exchange(detail)) => {
                    return Err(CompanionFailure::Exchange {
                        name: phone.name.clone(),
                        detail,
                    });
                }
            }
        }
    }

    /// Sends the push that brings the phone's app up; a phone without a
    /// token, or a gateway without an APNs key, is only asked while the app
    /// is open
    fn wake(&self, phone: &PhonePeer, id: &RequestId, reference: &str, expires: SystemTime) {
        let (Some(apns), Some(store)) = (self.apns.clone(), self.store.clone()) else {
            return;
        };
        let key = phone.id.to_string();
        let token = match store.push_token(&key) {
            Ok(Some(token)) => token,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(phone = %phone.name, %error, "cannot read the phone's push token");

                return;
            }
        };
        let alert = Alert {
            request: id.clone(),
            reference: reference.to_owned(),
            gateway: short_hostname(),
            expires,
        };
        let name = phone.name.clone();

        // the read waits for the phone either way; the push only shortens it
        tokio::spawn(async move {
            match apns.push(&token, &alert).await {
                Ok(()) => tracing::info!(phone = %name, request = %alert.request, "phone woken"),
                Err(PushFailure::Gone) => {
                    tracing::warn!(phone = %name, "APNs no longer knows the phone's token");
                    // only that token: the phone may have sent a newer one
                    if let Err(error) = store.drop_push_token(&key, &token.token) {
                        tracing::warn!(%error, "could not forget the token");
                    }
                }
                Err(error) => tracing::warn!(phone = %name, %error, "could not wake the phone"),
            }
        });
    }

    /// Serves a connection a phone dialed: refused unless the phone is
    /// listed, then the phone's link until it hangs up or dials again
    pub(super) async fn phone_connection(&self, connection: Connection) {
        let remote = connection.remote_id();
        let Some(phone) = self.phones().into_iter().find(|phone| phone.id == remote) else {
            tracing::warn!(%remote, "refused a phone that is not paired");
            connection.close(1_u32.into(), b"not paired");

            return;
        };
        if connection.alpn() != MOBILE_ALPN {
            connection.close(1_u32.into(), b"unexpected protocol");

            return;
        }

        let link = self.links.link(remote);
        if let Some(previous) = link.send_replace(Some(connection.clone())) {
            previous.close(0_u32.into(), b"replaced");
        }
        tracing::info!(phone = %phone.name, "phone connected");

        // the phone's own requests, one per stream, until it hangs up
        while let Ok((mut send, mut receive)) = connection.accept_bi().await {
            let request = tokio::time::timeout(REQUEST_WINDOW, read_request(&mut receive)).await;
            let (response, unpaired) = match request {
                Ok(Some(request)) => self.phone_request(&phone, request),
                _ => (
                    PhoneResponse::Refused {
                        message: "expected a phone request".to_owned(),
                    },
                    false,
                ),
            };
            let _ = tokio::time::timeout(REQUEST_WINDOW, answer(&mut send, &response)).await;
            if unpaired {
                // the phone closes once it has the answer
                let _ = tokio::time::timeout(REQUEST_WINDOW, connection.closed()).await;
                self.links.drop_phone(remote);

                return;
            }
        }

        link.send_if_modified(|current| {
            let ours = current
                .as_ref()
                .is_some_and(|current| current.stable_id() == connection.stable_id());
            if ours {
                *current = None;
            }

            ours
        });
        tracing::info!(phone = %phone.name, "phone disconnected");
    }

    /// Answers one request of `phone`; also whether it unpaired
    fn phone_request(&self, phone: &PhonePeer, request: PhoneRequest) -> (PhoneResponse, bool) {
        let Some(store) = &self.store else {
            let refused = PhoneResponse::Refused {
                message: "this gateway keeps no state for phones".to_owned(),
            };

            return (refused, false);
        };
        let key = phone.id.to_string();

        match request {
            PhoneRequest::PushToken(token) => match store.put_push_token(&key, token.as_ref()) {
                Ok(()) => (PhoneResponse::Done, false),
                Err(error) => (
                    PhoneResponse::Refused {
                        message: error.to_string(),
                    },
                    false,
                ),
            },
            PhoneRequest::Unpair => {
                if let Err(error) = store.forget_phone(&key) {
                    let refused = PhoneResponse::Refused {
                        message: error.to_string(),
                    };

                    return (refused, false);
                }
                self.phones
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retain(|listed| listed.id != phone.id);
                self.refresh_alpns();
                // the config entry stays until the owner removes it, but the
                // phone has dropped its keys, so the id is dead
                tracing::warn!(
                    phone = %phone.name,
                    "phone unpaired; remove its [[secrets.phones]] entry from the config"
                );

                (PhoneResponse::Done, true)
            }
        }
    }
}

/// Opens a stream on `connection`, sends `read` and waits for the answer;
/// dropping the future stops the stream, which takes the phone's prompt down
async fn offer(connection: &Connection, read: &PhoneRead) -> Result<CompanionResponse, Offer> {
    let lost = |connection: &Connection, detail: String| {
        if connection.close_reason().is_some() {
            Offer::Lost
        } else {
            Offer::Exchange(detail)
        }
    };

    let mut request =
        serde_json::to_vec(read).map_err(|error| Offer::Exchange(error.to_string()))?;
    // a copy too large for the phone to take: the owner enters the value
    if request.len() > MAX_PHONE_READ_BYTES && read.sealed.is_some() {
        let unsealed = PhoneRead {
            sealed: None,
            ..read.clone()
        };
        request =
            serde_json::to_vec(&unsealed).map_err(|error| Offer::Exchange(error.to_string()))?;
    }
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| lost(connection, error.to_string()))?;
    send.write_all(&request)
        .await
        .map_err(|error| lost(connection, error.to_string()))?;
    send.finish()
        .map_err(|error| lost(connection, error.to_string()))?;
    let body = receive
        .read_to_end(MAX_BODY_BYTES)
        .await
        .map_err(|error| lost(connection, error.to_string()))?;

    serde_json::from_slice(&body)
        .map_err(|error| Offer::Exchange(format!("malformed answer: {error}")))
}
