//! The gateway's side: asking companions to read a reference

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, OnceLock, PoisonError, RwLock},
    time::Duration,
};

use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use tokio::{
    sync::{Mutex, OnceCell},
    task::{JoinHandle, JoinSet},
};

use super::{
    ALPN, ASK_TIMEOUT, CompanionErrorCode, CompanionRequest, CompanionResponse, Hangup,
    IdentityError, MAX_BODY_BYTES, Role, apns::Apns, bind_endpoint, invite::Invites,
    load_or_create, phone::Links,
};
use crate::{
    config::{CompanionPeer, PhonePeer, SecretsConfig},
    store::Store,
};

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
    /// The phone holds no sealed copy of the reference: the gateway has not
    /// read it another way since the phone was paired
    #[error("{name} has no sealed copy of it yet")]
    NotSealed {
        /// Phone name
        name: String,
    },
    /// No answer within [`ASK_TIMEOUT`]
    #[error("{name} did not answer within {timeout:?}")]
    TimedOut {
        /// Companion name
        name: String,
        /// Limit that elapsed
        timeout: Duration,
    },
    /// An invite could not be opened
    #[error("{0}")]
    Invite(String),
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
/// its id. A companion registering with an invite joins the list while the
/// daemon runs
pub struct Companions {
    peers: RwLock<Vec<CompanionPeer>>,
    pub(super) phones: RwLock<Vec<PhonePeer>>,
    /// Where values sealed to the phones and their push tokens are kept;
    /// `None` outside the daemon, which then never asks a phone
    pub(super) store: Option<Store>,
    pub(super) apns: Option<Apns>,
    pub(super) links: Links,
    /// The reader's cache of values, shared so a newly paired phone gets
    /// copies of what was read before it
    pub(super) known: OnceLock<Arc<Mutex<HashMap<String, String>>>>,
    pub(super) discovery: bool,
    listen: Option<SocketAddr>,
    identity_file: Option<PathBuf>,
    /// The config file a registered companion is appended to
    pub(super) config_path: Option<PathBuf>,
    secret_key: Mutex<Option<SecretKey>>,
    pub(super) endpoint: OnceCell<Endpoint>,
    pub(super) invites: Invites,
    /// One registration at a time, so two cannot pick the same name
    pub(super) registering: Mutex<()>,
    /// Accepts the pairing protocol; started by the first invite
    pub(super) accepting: OnceLock<JoinHandle<()>>,
}

impl Companions {
    /// The companions and phones named in `config`; one registering with an
    /// invite is appended to `config_path`. Values sealed to the phones are
    /// kept in `store`
    pub fn new(config: &SecretsConfig, config_path: Option<PathBuf>, store: Option<Store>) -> Self {
        Self {
            peers: RwLock::new(config.companions.clone()),
            phones: RwLock::new(config.phones.clone()),
            store,
            apns: config.apns.clone().map(Apns::new),
            links: Links::default(),
            known: OnceLock::new(),
            discovery: config.discovery,
            listen: config.listen,
            identity_file: config.identity_file.clone(),
            config_path,
            secret_key: Mutex::new(None),
            endpoint: OnceCell::new(),
            invites: Invites::default(),
            registering: Mutex::new(()),
            accepting: OnceLock::new(),
        }
    }

    /// Shares the reader's cache, so pairing a phone seals what was read
    /// before it
    pub fn share_cache(&self, known: Arc<Mutex<HashMap<String, String>>>) {
        let _ = self.known.set(known);
    }

    /// The companions, as configured plus any registered since
    pub fn peers(&self) -> Vec<CompanionPeer> {
        self.peers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Starts using a newly registered companion
    pub(super) fn add_peer(&self, peer: CompanionPeer) {
        self.peers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(peer);
    }

    /// Closes the iroh endpoint, if it was bound, hanging up on phones and
    /// companions and freeing its port
    pub async fn close(&self) {
        if let Some(endpoint) = self.endpoint.get() {
            endpoint.close().await;
        }
    }

    /// Addresses this gateway's endpoint is bound to, once it is; empty
    /// before the first read or invite
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.endpoint
            .get()
            .map(Endpoint::bound_sockets)
            .unwrap_or_default()
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

    pub(super) async fn endpoint(&self) -> Result<&Endpoint, CompanionFailure> {
        self.endpoint
            .get_or_try_init(|| async {
                let key = self
                    .key()
                    .await
                    .map_err(|error| CompanionFailure::Identity(error.to_string()))?;

                bind_endpoint(Role::Gateway, key, self.discovery, self.listen)
                    .await
                    .map_err(CompanionFailure::Identity)
            })
            .await
    }

    /// Asks the companion called `name` to read `reference`
    pub async fn read(&self, name: &str, reference: &str) -> Result<String, CompanionFailure> {
        let peer = self
            .peers()
            .into_iter()
            .find(|peer| peer.name == name)
            .ok_or_else(|| CompanionFailure::Unknown(name.to_owned()))?;

        self.read_from(&peer, reference).await
    }

    /// Asks `peer`, listed or not, to read `reference`
    pub(super) async fn read_from(
        &self,
        peer: &CompanionPeer,
        reference: &str,
    ) -> Result<String, CompanionFailure> {
        tokio::time::timeout(ASK_TIMEOUT, self.exchange(peer, reference))
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: peer.name.clone(),
                    timeout: ASK_TIMEOUT,
                })
            })
    }

    /// Asks every companion, then every phone, and reports how each
    /// answered, in configuration order, without keeping or returning a
    /// value
    pub async fn check(self: &Arc<Self>, reference: &str) -> Vec<CheckOutcome> {
        let mut answers = JoinSet::new();
        let first_phone = self.peers().len();
        for (index, phone) in self.phones().into_iter().enumerate() {
            let companions = Arc::clone(self);
            let reference = reference.to_owned();
            answers.spawn(async move {
                let result = companions
                    .read_phone(&phone.name, &reference)
                    .await
                    .map(|value| value.len());

                (
                    first_phone + index,
                    CheckOutcome {
                        name: phone.name,
                        result,
                    },
                )
            });
        }
        for (index, peer) in self.peers().iter().enumerate() {
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
            .field("peers", &self.peers().len())
            .field("phones", &self.phones().len())
            .finish_non_exhaustive()
    }
}
