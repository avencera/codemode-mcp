//! The companion's side: answering the gateway's requests on this Mac

use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::{Endpoint, EndpointId, endpoint::Connection};
use tokio::{sync::Mutex, task::JoinHandle};

use super::{
    ALPN, ASK_TIMEOUT, CompanionCreateRequest, CompanionCreateResponse, CompanionErrorCode,
    CompanionFault, CompanionRequest, CompanionResponse, HANDSHAKE_TIMEOUT, Hangup, IdentityError,
    MALFORMED_REQUEST, MAX_BODY_BYTES, NewItem, Role, bind_endpoint, load_or_create,
};
use crate::{
    config::CompanionConfig,
    mac::{Mac, MacNotification, TouchId},
    secrets::{CreateError, OnePassword, check_new_item, is_reference},
};

/// Cancel button of the Touch ID prompt; pressing it denies the read
const CANCEL_TITLE: &str = "Deny";

/// Longest a create runs once Touch ID approved it; `op` itself gives up on
/// each of its two steps sooner, and the gateway has stopped waiting long
/// before
const CREATE_DEADLINE: Duration = Duration::from_secs(300);

/// Why the companion could not start
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// This companion's key could not be loaded or created
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The iroh endpoint could not be bound
    #[error("{0}")]
    Bind(String),
}

/// A running companion
pub struct CompanionHandle {
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl CompanionHandle {
    /// The endpoint id the gateway must list under `secrets.companions`
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Addresses the endpoint is bound to, as the OS reports them (an
    /// unspecified address when listening on all interfaces)
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Stops accepting, hangs up on open connections and waits for the
    /// accept loop to end
    pub async fn shutdown(self) {
        self.endpoint.close().await;
        let _ = self.task.await;
    }
}

/// Starts answering the configured gateway
///
/// A read takes two things the gateway cannot fake. First, the allow list:
/// 1Password's own prompt does not name the item, and one approval lets `op`
/// read anything for about ten minutes, so without it a compromised gateway
/// could read every item. Second, a fingerprint for every request. While `op`
/// is authorized it would answer silently, so this Mac asks Touch ID itself,
/// naming the reference. Otherwise 1Password's own prompt is that
/// fingerprint, and a notification names the reference instead, so the owner
/// touches once either way. `mac` is `None` where there is no Touch ID, and
/// every request is then denied
pub async fn serve(
    config: CompanionConfig,
    mac: Option<Arc<dyn Mac>>,
) -> Result<CompanionHandle, ServeError> {
    let file = config.identity_file.clone();
    let key = tokio::task::spawn_blocking(move || load_or_create(Role::Companion, file.as_deref()))
        .await
        .map_err(|error| IdentityError::Keychain(error.to_string()))??;
    let endpoint = bind_endpoint(Role::Companion, key, config.discovery, config.listen)
        .await
        .map_err(ServeError::Bind)?;

    let companion = Arc::new(Companion {
        onepassword: OnePassword::new(config.op.clone()),
        config,
        mac,
        one_at_a_time: Arc::new(Mutex::new(())),
    });
    let accepting = endpoint.clone();
    let task = tokio::spawn(async move {
        // `None` once the endpoint is closed
        while let Some(incoming) = accepting.accept().await {
            let companion = Arc::clone(&companion);
            tokio::spawn(async move {
                let connecting = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await;
                match connecting {
                    Ok(Ok(connection)) => companion.connection(connection).await,
                    Ok(Err(error)) => tracing::debug!(%error, "companion handshake failed"),
                    Err(_) => tracing::debug!("companion handshake timed out"),
                }
            });
        }
    });

    Ok(CompanionHandle { endpoint, task })
}

struct Companion {
    config: CompanionConfig,
    mac: Option<Arc<dyn Mac>>,
    onepassword: OnePassword,
    /// Held from the Touch ID prompt to the end of the read or create, so
    /// prompts never stack
    one_at_a_time: Arc<Mutex<()>>,
}

impl Companion {
    async fn connection(self: &Arc<Self>, connection: Connection) {
        let remote = connection.remote_id();
        if remote != self.config.gateway || connection.alpn() != ALPN {
            tracing::warn!(%remote, "refused a connection that is not from the paired gateway");
            connection.close(1_u32.into(), b"not paired");

            return;
        }

        let connection = Hangup(connection);
        // one request per stream; a gateway that reuses the connection is
        // served until it hangs up
        while let Ok((mut send, mut receive)) = connection.0.accept_bi().await {
            let Ok(body) = receive.read_to_end(MAX_BODY_BYTES).await else {
                tracing::warn!("companion request was unreadable or too large");

                return;
            };

            // the gateway hangs up when another source won, which also takes
            // down a Touch ID prompt that is still showing; a gateway that
            // only stops the stream, or never gives up, loses it the same way
            let response = tokio::select! {
                response = tokio::time::timeout(ASK_TIMEOUT, self.dispatch(&body)) => {
                    let Ok(response) = response else {
                        tracing::info!("companion request was not answered in time");

                        continue;
                    };

                    response
                }
                _ = send.stopped() => continue,
                _ = connection.0.closed() => return,
            };
            if send.write_all(&response).await.is_err() || send.finish().is_err() {
                return;
            }
        }
    }

    /// The serialized answer to one request body: a read, or a create
    async fn dispatch(self: &Arc<Self>, body: &[u8]) -> Vec<u8> {
        let bytes = if let Ok(create) = serde_json::from_slice::<CompanionCreateRequest>(body) {
            serde_json::to_vec(&self.create(create.create).await)
        } else {
            serde_json::to_vec(&self.answer(body).await)
        };

        // a failure to serialize leaves the stream empty, which the gateway
        // reports as an unusable answer
        bytes.unwrap_or_default()
    }

    async fn create(self: &Arc<Self>, item: NewItem) -> CompanionCreateResponse {
        let fault = |code, message: String| {
            CompanionCreateResponse::Error(CompanionFault { code, message })
        };

        if let Err(reason) = check_new_item(&item) {
            return fault(CompanionErrorCode::NotAllowed, reason);
        }
        let (vault, title) = (item.vault.as_str(), item.title.as_str());
        if !self.config.allows_create(vault) {
            tracing::warn!(
                vault,
                "refused to create an item in a vault that is not allowed"
            );

            return fault(
                CompanionErrorCode::NotAllowed,
                format!("this companion does not create items in {vault}"),
            );
        }

        // a second request waits for the first prompt's answer
        let turn = Arc::clone(&self.one_at_a_time).lock_owned().await;

        let Some(mac) = &self.mac else {
            return fault(
                CompanionErrorCode::Denied,
                "Touch ID is unavailable on this machine".to_owned(),
            );
        };
        // every create asks, whatever was approved before
        let reason = format!(
            "codemode-mcp on {} wants to create in {vault}: \"{title}\"",
            self.config.gateway_name
        );
        if mac.touch_id(&reason, CANCEL_TITLE).await != TouchId::Approved {
            tracing::info!(vault, title, "create not approved on this Mac");

            return fault(
                CompanionErrorCode::Denied,
                "not approved on this Mac".to_owned(),
            );
        }

        // from here on the item may be written, so the work must not be
        // cancelled when the gateway hangs up or the request times out: that
        // could kill `op item create` mid-run and leave an item the gateway
        // was told was not created. The task keeps the turn until it ends
        let companion = Arc::clone(self);
        let created = tokio::spawn(async move {
            let _turn = turn;
            let item = item;
            let created =
                tokio::time::timeout(CREATE_DEADLINE, companion.onepassword.create_local(&item))
                    .await;
            let (vault, title) = (item.vault.as_str(), item.title.as_str());

            match created {
                Ok(Ok(created)) => {
                    tracing::info!(vault, title, "create approved and done");

                    CompanionCreateResponse::Created(created)
                }
                Ok(Err(error @ CreateError::Exists { .. })) => {
                    tracing::info!(vault, title, "refused to create over an existing item");

                    fault(CompanionErrorCode::AlreadyExists, error.to_string())
                }
                Ok(Err(error @ CreateError::Unconfirmed { .. })) => {
                    tracing::warn!(vault, title, %error, "create not confirmed on this Mac");

                    fault(CompanionErrorCode::CreateUnconfirmed, error.to_string())
                }
                Ok(Err(error)) => {
                    tracing::warn!(vault, title, %error, "create failed on this Mac");

                    fault(CompanionErrorCode::CreateFailed, error.to_string())
                }
                Err(_) => {
                    tracing::warn!(vault, title, "create did not finish in time");

                    fault(
                        CompanionErrorCode::CreateUnconfirmed,
                        "the create did not finish in time".to_owned(),
                    )
                }
            }
        })
        .await;

        created.unwrap_or_else(|error| {
            tracing::warn!(%error, "create task failed");

            CompanionCreateResponse::Error(CompanionFault {
                code: CompanionErrorCode::CreateUnconfirmed,
                message: "the create stopped unexpectedly".to_owned(),
            })
        })
    }

    async fn answer(&self, body: &[u8]) -> CompanionResponse {
        let fault = |code, message: &str| {
            CompanionResponse::Error(CompanionFault {
                code,
                message: message.to_owned(),
            })
        };

        let Ok(request) = serde_json::from_slice::<CompanionRequest>(body) else {
            return fault(CompanionErrorCode::NotAllowed, MALFORMED_REQUEST);
        };
        let reference = request.reference.trim();
        if !is_reference(reference) || !self.config.allows(reference) {
            tracing::warn!(
                reference,
                "refused a reference that is not on the allow list"
            );

            return fault(
                CompanionErrorCode::NotAllowed,
                "the reference is not on this companion's allow list",
            );
        }

        // a second request waits for the first prompt's answer
        let _turn = self.one_at_a_time.lock().await;

        let Some(mac) = &self.mac else {
            return fault(
                CompanionErrorCode::Denied,
                "Touch ID is unavailable on this machine",
            );
        };
        let reason = format!(
            "codemode-mcp on {} wants to read {reference}",
            self.config.gateway_name
        );
        // still held turn: no other request can read between this check and
        // the read below and spend the approval 1Password is about to ask for
        let named_for_1password = if self.onepassword.signed_out().await {
            // 1Password is about to ask for a fingerprint itself, which
            // approves this read as well as ours would, so asking first only
            // makes the owner touch twice. Its prompt names neither the
            // gateway nor the reference, so a notification does
            let notification = MacNotification {
                title: reason.clone(),
                message: "Approve in 1Password to send it.".to_owned(),
                click: None,
            };
            match mac.notify(&notification).await {
                Ok(()) => true,
                Err(error) => {
                    // nothing else would name the reference, so ask as well
                    tracing::info!(%error, "could not name the read in a notification");

                    false
                }
            }
        } else {
            false
        };
        // the turn lock covers only this process: another `op` on this Mac
        // may have been approved while the notification went up, and then
        // 1Password reads silently, so this read is asked for after all
        let named_for_1password = named_for_1password && self.onepassword.signed_out().await;
        if !named_for_1password && mac.touch_id(&reason, CANCEL_TITLE).await != TouchId::Approved {
            tracing::info!(reference, "read not approved on this Mac");

            return fault(CompanionErrorCode::Denied, "not approved on this Mac");
        }

        match self.onepassword.read_local(reference).await {
            Ok(value) => {
                let response = CompanionResponse::Value(value);
                // the gateway reads at most MAX_BODY_BYTES, so a longer
                // answer would reach it only as an opaque exchange error
                if serde_json::to_vec(&response).map_or(true, |bytes| bytes.len() > MAX_BODY_BYTES)
                {
                    tracing::warn!(reference, "value is too large to send");

                    return fault(
                        CompanionErrorCode::ReadFailed,
                        "the value is too large to send",
                    );
                }
                tracing::info!(reference, "read approved and answered");

                response
            }
            Err(error) => {
                tracing::warn!(reference, %error, "read failed on this Mac");

                fault(CompanionErrorCode::ReadFailed, &error.to_string())
            }
        }
    }
}
