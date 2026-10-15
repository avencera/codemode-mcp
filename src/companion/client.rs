//! The gateway's side: asking companions to read a reference

use std::{path::PathBuf, sync::Arc, time::Duration};

use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use tokio::{
    sync::{Mutex, OnceCell},
    task::JoinSet,
};

use super::{
    ALPN, CompanionErrorCode, CompanionRequest, CompanionResponse, Hangup, IdentityError,
    MAX_BODY_BYTES, Role, bind_endpoint, load_or_create,
};
use crate::config::{CompanionPeer, SecretsConfig};

/// How long one companion request may take, including the owner's Touch ID
/// answer on the other Mac
const ASK_TIMEOUT: Duration = Duration::from_secs(120);

/// Why a companion did not send a value; none of the messages holds a value
#[derive(Debug, thiserror::Error)]
pub enum CompanionFailure {
    /// The name is not in `secrets.companions`
    #[error("no companion named {0}")]
    Unknown(String),
    /// The gateway's own key or endpoint could not be set up
    #[error("this gateway's identity is unavailable: {0}")]
    Identity(String),
    /// The companion could not be reached
    #[error("cannot reach {name}: {detail}")]
    Connect {
        /// Companion name
        name: String,
        /// What failed
        detail: String,
    },
    /// The exchange broke off or the answer was unreadable
    #[error("{name} sent no usable answer: {detail}")]
    Exchange {
        /// Companion name
        name: String,
        /// What failed
        detail: String,
    },
    /// The companion answered with a refusal
    #[error("{code}: {message}", code = .code.as_str())]
    Refused {
        /// Category the companion gave
        code: CompanionErrorCode,
        /// Its text
        message: String,
    },
    /// No answer within [`ASK_TIMEOUT`]
    #[error("{name} did not answer within {timeout:?}")]
    TimedOut {
        /// Companion name
        name: String,
        /// Limit that elapsed
        timeout: Duration,
    },
}

/// What a companion said to `companion check`; never the value itself
#[derive(Debug)]
pub struct CheckOutcome {
    /// Companion name
    pub name: String,
    /// Byte length of the value it read, or why it did not
    pub result: Result<usize, CompanionFailure>,
}

/// The companions of one gateway and the iroh endpoint that reaches them
///
/// The key is loaded and the endpoint bound on first use and kept, so a
/// gateway without companions never touches the keychain unless asked for
/// its id
pub struct Companions {
    peers: Vec<CompanionPeer>,
    discovery: bool,
    identity_file: Option<PathBuf>,
    secret_key: Mutex<Option<SecretKey>>,
    endpoint: OnceCell<Endpoint>,
}

impl Companions {
    /// The companions named in `config`
    pub fn new(config: &SecretsConfig) -> Self {
        Self {
            peers: config.companions.clone(),
            discovery: config.discovery,
            identity_file: config.identity_file.clone(),
            secret_key: Mutex::new(None),
            endpoint: OnceCell::new(),
        }
    }

    /// The configured companions
    pub fn peers(&self) -> &[CompanionPeer] {
        &self.peers
    }

    /// This gateway's endpoint id, creating its key when there is none
    pub async fn id(&self) -> Result<EndpointId, IdentityError> {
        Ok(self.key().await?.public())
    }

    async fn key(&self) -> Result<SecretKey, IdentityError> {
        // held across the load so concurrent callers share one load-or-create
        let mut stored = self.secret_key.lock().await;
        if let Some(key) = stored.as_ref() {
            return Ok(key.clone());
        }

        // the keychain call can block on a prompt
        let file = self.identity_file.clone();
        let loaded =
            tokio::task::spawn_blocking(move || load_or_create(Role::Gateway, file.as_deref()))
                .await
                .map_err(|error| IdentityError::Keychain(error.to_string()))??;
        *stored = Some(loaded.clone());

        Ok(loaded)
    }

    async fn endpoint(&self) -> Result<&Endpoint, CompanionFailure> {
        self.endpoint
            .get_or_try_init(|| async {
                let key = self
                    .key()
                    .await
                    .map_err(|error| CompanionFailure::Identity(error.to_string()))?;

                bind_endpoint(Role::Gateway, key, self.discovery, None)
                    .await
                    .map_err(CompanionFailure::Identity)
            })
            .await
    }

    /// Asks the companion called `name` to read `reference`
    pub async fn read(&self, name: &str, reference: &str) -> Result<String, CompanionFailure> {
        let peer = self
            .peers
            .iter()
            .find(|peer| peer.name == name)
            .ok_or_else(|| CompanionFailure::Unknown(name.to_owned()))?;

        tokio::time::timeout(ASK_TIMEOUT, self.exchange(peer, reference))
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: name.to_owned(),
                    timeout: ASK_TIMEOUT,
                })
            })
    }

    /// Asks every companion and reports how each answered, in configuration
    /// order, without keeping or returning a value
    pub async fn check(self: &Arc<Self>, reference: &str) -> Vec<CheckOutcome> {
        let mut answers = JoinSet::new();
        for (index, peer) in self.peers.iter().enumerate() {
            let companions = Arc::clone(self);
            let name = peer.name.clone();
            let reference = reference.to_owned();
            answers.spawn(async move {
                let result = companions
                    .read(&name, &reference)
                    .await
                    .map(|value| value.len());

                (index, CheckOutcome { name, result })
            });
        }

        let mut outcomes = Vec::new();
        while let Some(finished) = answers.join_next().await {
            if let Ok(outcome) = finished {
                outcomes.push(outcome);
            }
        }
        outcomes.sort_by_key(|(index, _)| *index);

        outcomes.into_iter().map(|(_, outcome)| outcome).collect()
    }

    async fn exchange(
        &self,
        peer: &CompanionPeer,
        reference: &str,
    ) -> Result<String, CompanionFailure> {
        let connect = |detail: String| CompanionFailure::Connect {
            name: peer.name.clone(),
            detail,
        };
        let exchange = |detail: String| CompanionFailure::Exchange {
            name: peer.name.clone(),
            detail,
        };

        let endpoint = self.endpoint().await?;
        let address =
            EndpointAddr::from_parts(peer.id, peer.addrs.iter().copied().map(TransportAddr::Ip));
        let connection = Hangup(
            endpoint
                .connect(address, ALPN)
                .await
                .map_err(|error| connect(error.to_string()))?,
        );

        let request = serde_json::to_vec(&CompanionRequest {
            reference: reference.to_owned(),
        })
        .map_err(|error| exchange(error.to_string()))?;
        let (mut send, mut receive) = connection
            .0
            .open_bi()
            .await
            .map_err(|error| exchange(error.to_string()))?;
        send.write_all(&request)
            .await
            .map_err(|error| exchange(error.to_string()))?;
        send.finish().map_err(|error| exchange(error.to_string()))?;

        let body = receive
            .read_to_end(MAX_BODY_BYTES)
            .await
            .map_err(|error| exchange(error.to_string()))?;

        match serde_json::from_slice(&body) {
            Ok(CompanionResponse::Value(value)) => Ok(value),
            Ok(CompanionResponse::Error(fault)) => Err(CompanionFailure::Refused {
                code: fault.code,
                message: fault.message,
            }),
            Err(error) => Err(exchange(format!("malformed answer: {error}"))),
        }
    }
}

impl std::fmt::Debug for Companions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Companions")
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}
