//! The gateway's side of an invite: within its lifetime one Mac may
//! register, which lists it under `secrets.companions` in the config file
//! and in the running daemon, then ask for a check that reads one reference
//! through it

use std::{
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use iroh::{Endpoint, EndpointId, endpoint::Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use super::{
    ASK_TIMEOUT, CompanionFailure, Companions, HANDSHAKE_TIMEOUT, Hangup, InviteSecret,
    InviteTicket, MOBILE_ALPN, PAIR_ALPN, PairCheck, PairRequest, PairResponse, Registered,
    Registration, answer,
    mobile::PhoneRegistration,
    pair::{append_section, gateway_entry, phone_entry, read_config},
    read_request,
};
use crate::config::{CompanionPeer, Config, MAX_MAC_NAME_CHARS, PhonePeer, is_mac_name};

/// Longest an invite stays open
pub const MAX_INVITE_LIFETIME: Duration = Duration::from_secs(600);

/// How long a new companion may take to open a stream and send its
/// registration, and later its check request
const REQUEST_WINDOW: Duration = Duration::from_secs(30);
/// Pairing connections handled at once; the rest are refused, so
/// connections that never authenticate cannot pile up while an invite is
/// open
const MAX_PAIRING_CONNECTIONS: usize = 8;
/// Most addresses a companion may have written to the gateway's config
const MAX_ADDRS: usize = 8;
/// How long the gateway waits for the check after a registration; the
/// companion installs its agent in between
const CHECK_WINDOW: Duration = Duration::from_secs(600);
/// How long the check keeps dialing a companion whose agent just started;
/// with discovery it takes a few seconds to be found
const CHECK_CONNECT_WINDOW: Duration = Duration::from_secs(60);
/// Pause between those dials
const CHECK_RETRY: Duration = Duration::from_secs(2);
/// How long the gateway waits for the companion to hang up after the last
/// answer; closing first could drop the answer in flight
const LINGER: Duration = Duration::from_secs(5);
/// How long a finished invite's status is kept for `companion invite`
const STATUS_KEPT: Duration = Duration::from_secs(3600);

/// Where an invite stands, as `companion invite` shows it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum InviteStatus {
    /// Waiting for a Mac to register
    Open {
        /// Seconds until it expires
        expires_in_secs: u64,
    },
    /// No Mac registered in time
    Expired,
    /// A Mac is registering now
    Registering,
    /// A Mac registered and the daemon uses it
    Registered {
        /// The name it is listed under
        name: String,
        /// Its endpoint id
        id: EndpointId,
        /// Whether it was listed before
        already_listed: bool,
        /// Whether it is a phone rather than a Mac
        #[serde(default)]
        phone: bool,
    },
    /// The registered Mac hung up, after a check or without one
    Done {
        /// The name it is listed under
        name: String,
        /// Its endpoint id
        id: EndpointId,
        /// Whether it was listed before
        already_listed: bool,
        /// How the check went; `None` when it never asked for one
        check: Option<PairCheck>,
        /// Whether the daemon reads through it now; a new companion is used
        /// only once the check reaches it, so one whose setup failed is not
        /// asked in place of the local `op`
        in_use: bool,
        /// Whether it is a phone rather than a Mac
        #[serde(default)]
        phone: bool,
    },
    /// A Mac used the invite but could not be listed
    Failed {
        /// Why
        message: String,
    },
}

/// An invite that was opened
#[derive(Debug)]
pub struct OpenedInvite {
    /// Names the invite to [`Companions::invite_status`]
    pub id: String,
    /// What the new companion pairs with
    pub ticket: InviteTicket,
    /// How long it stays open
    pub lifetime: Duration,
}

struct Invite {
    id: String,
    /// SHA-256 of the secret, so the secret itself is not kept
    secret: [u8; 32],
    opened: Instant,
    lifetime: Duration,
    /// The same deadline by the wall clock: `Instant` stops while the Mac
    /// sleeps, which would stretch an invite past its lifetime
    expires_at: SystemTime,
    gateway_name: String,
    references: Vec<String>,
    status: InviteStatus,
}

impl Invite {
    /// Time left by whichever clock has less
    fn remaining(&self) -> Duration {
        let by_uptime = self.lifetime.saturating_sub(self.opened.elapsed());
        let by_wall = self
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default();

        by_uptime.min(by_wall)
    }

    fn status(&self) -> InviteStatus {
        match &self.status {
            InviteStatus::Open { .. } => match self.remaining() {
                Duration::ZERO => InviteStatus::Expired,
                left => InviteStatus::Open {
                    // rounded up, so an open invite never reports zero
                    expires_in_secs: left.as_secs() + u64::from(left.subsec_nanos() > 0),
                },
            },
            status => status.clone(),
        }
    }
}

/// What a registration takes from the invite it used
struct Redeemed {
    id: String,
    gateway_name: String,
    references: Vec<String>,
}

/// The invites a gateway opened
#[derive(Default)]
pub(super) struct Invites(Mutex<Vec<Invite>>);

impl Invites {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Invite>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(
        &self,
        gateway_name: String,
        references: Vec<String>,
        lifetime: Duration,
    ) -> (String, InviteSecret) {
        let secret = InviteSecret::generate();
        let id = hex::encode(rand::random::<[u8; 8]>());

        let mut invites = self.lock();
        invites.retain(|invite| invite.opened.elapsed() < STATUS_KEPT);
        invites.push(Invite {
            id: id.clone(),
            secret: Sha256::digest(secret.as_bytes()).into(),
            opened: Instant::now(),
            lifetime,
            expires_at: SystemTime::now() + lifetime,
            gateway_name,
            references,
            status: InviteStatus::Open { expires_in_secs: 0 },
        });

        (id, secret)
    }

    /// Takes the invite `secret` belongs to, so it cannot be used again
    fn redeem(&self, secret: &InviteSecret) -> Result<Redeemed, String> {
        let hash: [u8; 32] = Sha256::digest(secret.as_bytes()).into();

        let mut invites = self.lock();
        let Some(invite) = invites.iter_mut().find(|invite| invite.secret == hash) else {
            return Err(
                "this gateway has no such invite; run `codemode-mcp companion invite` \
                        on it again"
                    .to_owned(),
            );
        };
        match invite.status() {
            InviteStatus::Open { .. } => {}
            InviteStatus::Expired => {
                return Err(
                    "this invite expired; run `codemode-mcp companion invite` on the \
                            gateway again"
                        .to_owned(),
                );
            }
            _ => {
                return Err(
                    "this invite was already used; run `codemode-mcp companion invite` \
                            on the gateway again"
                        .to_owned(),
                );
            }
        }
        invite.status = InviteStatus::Registering;

        Ok(Redeemed {
            id: invite.id.clone(),
            gateway_name: invite.gateway_name.clone(),
            references: invite.references.clone(),
        })
    }

    fn set(&self, id: &str, status: InviteStatus) {
        if let Some(invite) = self.lock().iter_mut().find(|invite| invite.id == id) {
            invite.status = status;
        }
    }

    fn status(&self, id: &str) -> Option<InviteStatus> {
        self.lock()
            .iter()
            .find(|invite| invite.id == id)
            .map(Invite::status)
    }

    /// Offers the pairing protocol on `endpoint` exactly while an invite is
    /// open, and the phone protocol while `phones` is set; decided and set
    /// under the lock, so an expiry that finds none open cannot undo an
    /// invite opened meanwhile
    fn offer_pairing(&self, endpoint: &Endpoint, phones: bool) {
        let invites = self.lock();
        let open = invites
            .iter()
            .any(|invite| matches!(invite.status(), InviteStatus::Open { .. }));
        let mut alpns = Vec::new();
        if open {
            alpns.push(PAIR_ALPN.to_vec());
        }
        if phones {
            alpns.push(MOBILE_ALPN.to_vec());
        }
        endpoint.set_alpns(alpns);
    }
}

impl Companions {
    /// Opens an invite that lets one Mac register within `lifetime` (at most
    /// [`MAX_INVITE_LIFETIME`]); `references` become its allow list
    pub async fn open_invite(
        self: &Arc<Self>,
        gateway_name: String,
        references: Vec<String>,
        lifetime: Duration,
    ) -> Result<OpenedInvite, CompanionFailure> {
        if self.config_path.is_none() {
            return Err(CompanionFailure::Invite(
                "the daemon was not started from a config file, so it cannot list a new companion"
                    .to_owned(),
            ));
        }
        let lifetime = lifetime.min(MAX_INVITE_LIFETIME);
        let endpoint = self.endpoint().await?;
        // without discovery the companion can only find this Mac by address
        let addrs: Vec<_> = if self.discovery {
            Vec::new()
        } else {
            endpoint.addr().ip_addrs().copied().collect()
        };
        if !self.discovery && addrs.is_empty() {
            return Err(CompanionFailure::Invite(
                "secrets.discovery is off and this Mac has no address to put in the ticket"
                    .to_owned(),
            ));
        }

        self.start_accepting(endpoint);
        let (id, secret) = self.invites.open(gateway_name, references, lifetime);
        self.refresh_alpns();
        // stops offering the pairing protocol once this invite expires,
        // unless another is still open
        let companions = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            if let Some(companions) = companions.upgrade() {
                companions.refresh_alpns();
            }
        });

        Ok(OpenedInvite {
            id,
            ticket: InviteTicket {
                gateway: endpoint.id(),
                secret,
                addrs,
            },
            lifetime,
        })
    }

    /// Where the invite `id` stands; `None` for an unknown or long finished
    /// invite
    pub fn invite_status(&self, id: &str) -> Option<InviteStatus> {
        self.invites.status(id)
    }

    /// Offers the pairing protocol exactly while an invite is open and the
    /// phone protocol while a phone is listed, so the gateway refuses every
    /// incoming connection the rest of the time
    pub(super) fn refresh_alpns(&self) {
        if let Some(endpoint) = self.endpoint.get() {
            self.invites
                .offer_pairing(endpoint, !self.phones().is_empty());
        }
    }

    pub(super) fn start_accepting(self: &Arc<Self>, endpoint: &Endpoint) {
        self.accepting.get_or_init(|| {
            let companions = Arc::downgrade(self);
            let endpoint = endpoint.clone();
            let slots = Arc::new(Semaphore::new(MAX_PAIRING_CONNECTIONS));

            tokio::spawn(async move {
                // `None` once the endpoint is closed
                while let Some(incoming) = endpoint.accept().await {
                    let Some(companions) = companions.upgrade() else {
                        return;
                    };
                    let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                        incoming.refuse();

                        continue;
                    };
                    tokio::spawn(async move {
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
                            Ok(Ok(connection)) if connection.alpn() == PAIR_ALPN => {
                                let _slot = slot;
                                companions.pairing(connection).await;
                            }
                            // a phone stays connected while its app is open,
                            // so it gives its handshake slot back
                            Ok(Ok(connection)) if connection.alpn() == MOBILE_ALPN => {
                                drop(slot);
                                companions.phone_connection(connection).await;
                            }
                            Ok(Ok(connection)) => {
                                connection.close(1_u32.into(), b"unexpected protocol");
                            }
                            Ok(Err(error)) => tracing::debug!(%error, "pairing handshake failed"),
                            Err(_) => tracing::debug!("pairing handshake timed out"),
                        }
                    });
                }
            })
        });
    }

    async fn pairing(self: &Arc<Self>, connection: Connection) {
        let connection = Hangup(connection);
        let Ok(Ok((mut send, mut receive))) =
            tokio::time::timeout(REQUEST_WINDOW, connection.0.accept_bi()).await
        else {
            return;
        };
        let request = tokio::time::timeout(REQUEST_WINDOW, read_request(&mut receive)).await;
        let Ok(Some(PairRequest::Register(registration))) = request else {
            refuse(&connection, &mut send, "expected a registration").await;

            return;
        };

        let phone = registration.phone.is_some();
        // a phone dials with the key it registers, so the id it names must
        // be the one the handshake proved; a Mac's agent answers on its own
        // key, which only its holder can do
        if phone && registration.id != connection.0.remote_id() {
            refuse(
                &connection,
                &mut send,
                "a phone must register the id it connects with",
            )
            .await;

            return;
        }
        let (invite, registered, references, mut pending) = match self.register(*registration).await
        {
            Ok(registration) => registration,
            Err(message) => {
                tracing::info!(%message, "refused a companion registration");
                refuse(&connection, &mut send, &message).await;

                return;
            }
        };
        let name = registered.name.clone();
        let id_status = self.invite_status(&invite);
        if !answer_within(&mut send, &PairResponse::Registered(registered)).await {
            self.finish(&invite, id_status, None, pending.is_none());

            return;
        }

        // the companion asks once its agent is running; it may also just
        // hang up, as a hand-run pairing does
        let check = match tokio::time::timeout(CHECK_WINDOW, connection.0.accept_bi()).await {
            Ok(Ok((mut send, mut receive))) => {
                match tokio::time::timeout(REQUEST_WINDOW, read_request(&mut receive)).await {
                    Ok(Some(PairRequest::Check)) => {
                        let (check, reached) = if phone {
                            (self.check_phone(&name, &references).await, true)
                        } else {
                            self.check_new(&name, pending.as_ref(), &references).await
                        };
                        if reached && let Some(peer) = pending.take() {
                            tracing::info!(name = %peer.name, "companion in use");
                            self.add_peer(peer);
                        }
                        if answer_within(&mut send, &PairResponse::Checked(check.clone())).await {
                            // the companion hangs up once it has the answer
                            let _ = tokio::time::timeout(LINGER, connection.0.closed()).await;
                        }

                        Some(check)
                    }
                    _ => {
                        refuse(&connection, &mut send, "expected a check").await;

                        None
                    }
                }
            }
            _ => None,
        };
        self.finish(&invite, id_status, check, pending.is_none());
    }

    /// Marks the invite done, keeping who registered with it
    fn finish(
        &self,
        invite: &str,
        status: Option<InviteStatus>,
        check: Option<PairCheck>,
        in_use: bool,
    ) {
        if let Some(InviteStatus::Registered {
            name,
            id,
            already_listed,
            phone,
        }) = status
        {
            self.invites.set(
                invite,
                InviteStatus::Done {
                    name,
                    id,
                    already_listed,
                    check,
                    in_use,
                    phone,
                },
            );
        }
    }

    /// Uses up the invite the registration's secret belongs to and lists the
    /// companion; answers the invite's id, what the companion needs, the
    /// references to check and the peer to start using once the check
    /// reaches it (`None` when the daemon uses it already)
    async fn register(
        &self,
        registration: Registration,
    ) -> Result<(String, Registered, Vec<String>, Option<CompanionPeer>), String> {
        let secret = InviteSecret::from_hex(&registration.secret)
            .ok_or_else(|| "the invite secret is malformed".to_owned())?;
        let invite = self.invites.redeem(&secret)?;
        self.refresh_alpns();

        let listed = match &registration.phone {
            Some(phone) => self
                .list_phone(&registration, phone, &invite)
                .await
                .map(|registered| (registered, None)),
            None => self.list(&registration, &invite).await,
        };
        match listed {
            Ok((registered, pending)) => {
                tracing::info!(
                    name = %registered.name,
                    id = %registration.id,
                    "companion registered"
                );
                self.invites.set(
                    &invite.id,
                    InviteStatus::Registered {
                        name: registered.name.clone(),
                        id: registration.id,
                        already_listed: registered.already_listed,
                        phone: registration.phone.is_some(),
                    },
                );

                Ok((invite.id, registered, invite.references, pending))
            }
            Err(message) => {
                self.invites.set(
                    &invite.id,
                    InviteStatus::Failed {
                        message: message.clone(),
                    },
                );

                Err(message)
            }
        }
    }

    /// Appends the companion to the config file; a companion already listed
    /// by id is left as it is. Answers the peer the daemon does not use yet
    async fn list(
        &self,
        registration: &Registration,
        invite: &Redeemed,
    ) -> Result<(Registered, Option<CompanionPeer>), String> {
        let _turn = self.registering.lock().await;
        let peers = self.peers();
        let registered = |name: &str, already_listed| Registered {
            gateway_name: invite.gateway_name.clone(),
            name: name.to_owned(),
            references: invite.references.clone(),
            already_listed,
        };

        if let Some(peer) = peers.iter().find(|peer| peer.id == registration.id) {
            return Ok((registered(&peer.name, true), None));
        }
        // addresses matter only to a gateway that dials them; capped so a
        // registration cannot write much into the config
        let addrs: Vec<_> = if self.discovery {
            Vec::new()
        } else {
            registration.addrs.iter().copied().take(MAX_ADDRS).collect()
        };
        if !self.discovery && addrs.is_empty() {
            return Err(
                "this gateway has discovery off, so the companion must send its addresses"
                    .to_owned(),
            );
        }
        let Some(path) = &self.config_path else {
            return Err("the gateway has no config file to list the companion in".to_owned());
        };

        // the file may have changed since the daemon loaded it
        let existing = read_config(path).map_err(|error| error.to_string())?;
        let in_file_secrets = Config::parse(&existing, path)
            .map_err(|error| error.to_string())?
            .secrets;
        let (in_file, in_file_phones) = (in_file_secrets.companions, in_file_secrets.phones);
        // listed by an earlier pairing whose check never reached it
        if let Some(peer) = in_file.iter().find(|peer| peer.id == registration.id) {
            return Ok((registered(&peer.name, true), Some(peer.clone())));
        }

        let phones = self.phones();
        let taken: Vec<&str> = peers
            .iter()
            .chain(&in_file)
            .map(|peer| peer.name.as_str())
            .chain(phones.iter().map(|phone| phone.name.as_str()))
            .chain(in_file_phones.iter().map(|phone| phone.name.as_str()))
            .collect();
        let name = unique_name(&registration.name, &taken);
        let entry = gateway_entry(&name, registration.id, &addrs);
        append_section(path, &existing, &entry).map_err(|error| {
            format!(
                "could not add the companion to {}: {error}; pair by hand with \
                 `codemode-mcp companion invite --manual`",
                path.display()
            )
        })?;
        let peer = CompanionPeer {
            name: name.clone(),
            id: registration.id,
            addrs,
        };

        Ok((registered(&name, false), Some(peer)))
    }

    /// Appends the phone to the config file and starts answering it at once:
    /// a phone is asked only for values sealed to it, so one whose setup
    /// failed costs nothing. Values this process has read are sealed to it
    /// now. A phone already listed by id keeps its entry
    async fn list_phone(
        &self,
        registration: &Registration,
        phone: &PhoneRegistration,
        invite: &Redeemed,
    ) -> Result<Registered, String> {
        let _turn = self.registering.lock().await;
        let registered = |name: &str, already_listed| Registered {
            gateway_name: invite.gateway_name.clone(),
            name: name.to_owned(),
            references: invite.references.clone(),
            already_listed,
        };
        let Some(store) = &self.store else {
            return Err("this gateway keeps no state for phones".to_owned());
        };
        let key = registration.id.to_string();
        let remember_push = || {
            store
                .put_push_token(&key, phone.push.as_ref())
                .map_err(|error| format!("could not keep the phone's push token: {error}"))
        };
        let same_key = |listed: &PhonePeer| {
            if listed.seal_key == phone.seal_key {
                Ok(())
            } else {
                Err(format!(
                    "{} is listed with another seal key; remove its [[secrets.phones]] entry \
                     and pair again",
                    listed.name
                ))
            }
        };

        if let Some(listed) = self
            .phones()
            .into_iter()
            .find(|listed| listed.id == registration.id)
        {
            same_key(&listed)?;
            remember_push()?;
            self.backfill(&listed).await;

            return Ok(registered(&listed.name, true));
        }
        let Some(path) = &self.config_path else {
            return Err("the gateway has no config file to list the phone in".to_owned());
        };
        // the file may have changed since the daemon loaded it
        let existing = read_config(path).map_err(|error| error.to_string())?;
        let in_file = Config::parse(&existing, path)
            .map_err(|error| error.to_string())?
            .secrets;
        if let Some(listed) = in_file
            .phones
            .iter()
            .find(|listed| listed.id == registration.id)
        {
            same_key(listed)?;
            remember_push()?;
            self.add_phone(listed.clone());
            self.backfill(listed).await;

            return Ok(registered(&listed.name, true));
        }

        let peers = self.peers();
        let phones = self.phones();
        let taken: Vec<&str> = peers
            .iter()
            .chain(&in_file.companions)
            .map(|peer| peer.name.as_str())
            .chain(
                phones
                    .iter()
                    .chain(&in_file.phones)
                    .map(|listed| listed.name.as_str()),
            )
            .collect();
        let name = unique_name(&registration.name, &taken);
        let entry = phone_entry(&name, registration.id, &phone.seal_key);
        append_section(path, &existing, &entry)
            .map_err(|error| format!("could not add the phone to {}: {error}", path.display()))?;
        remember_push()?;
        let listed = PhonePeer {
            name: name.clone(),
            id: registration.id,
            seal_key: phone.seal_key.clone(),
        };
        self.add_phone(listed.clone());
        self.backfill(&listed).await;

        Ok(registered(&name, false))
    }

    /// Reads the first reference sealed to the new phone through it; the
    /// value is dropped at once
    async fn check_phone(self: &Arc<Self>, name: &str, references: &[String]) -> PairCheck {
        if references.is_empty() {
            return PairCheck::Skipped;
        }
        let Some(reference) = references
            .iter()
            .find(|reference| self.has_seal(name, reference))
        else {
            return PairCheck::NothingSealed;
        };

        match self.read_phone(name, reference, ASK_TIMEOUT).await {
            Ok(value) => PairCheck::Read {
                reference: reference.clone(),
                bytes: value.len(),
            },
            Err(failure) => PairCheck::Failed {
                reference: reference.clone(),
                message: failure.to_string(),
            },
        }
    }

    /// Reads the first reference through the companion `name` (or `pending`,
    /// which is not listed yet), retrying while its agent comes up; the value
    /// is dropped at once. Also answers whether the companion was reached
    async fn check_new(
        &self,
        name: &str,
        pending: Option<&CompanionPeer>,
        references: &[String],
    ) -> (PairCheck, bool) {
        let Some(reference) = references.first() else {
            return (PairCheck::Skipped, true);
        };

        let started = Instant::now();
        loop {
            let read = match pending {
                Some(peer) => self.read_from(peer, reference).await,
                None => self.read(name, reference).await,
            };
            match read {
                Ok(value) => {
                    let check = PairCheck::Read {
                        reference: reference.clone(),
                        bytes: value.len(),
                    };

                    return (check, true);
                }
                Err(CompanionFailure::Connect { .. })
                    if started.elapsed() < CHECK_CONNECT_WINDOW =>
                {
                    tokio::time::sleep(CHECK_RETRY).await;
                }
                Err(failure) => {
                    // a refusal or a denied Touch ID still came from the
                    // companion, so it answers reads
                    let reached = !matches!(
                        failure,
                        CompanionFailure::Connect { .. } | CompanionFailure::TimedOut { .. }
                    );
                    let check = PairCheck::Failed {
                        reference: reference.clone(),
                        message: failure.to_string(),
                    };

                    return (check, reached);
                }
            }
        }
    }
}

/// Answers with a refusal, then waits for the companion to hang up so the
/// answer is not dropped with the connection
async fn refuse(connection: &Hangup, send: &mut iroh::endpoint::SendStream, message: &str) {
    let refusal = PairResponse::Refused {
        message: message.to_owned(),
    };
    if answer_within(send, &refusal).await {
        let _ = tokio::time::timeout(LINGER, connection.0.closed()).await;
    }
}

/// [`answer`], given up after [`REQUEST_WINDOW`]: a peer that never reads
/// would otherwise hold its pairing slot for good
async fn answer_within(send: &mut iroh::endpoint::SendStream, response: &PairResponse) -> bool {
    tokio::time::timeout(REQUEST_WINDOW, answer(send, response))
        .await
        .unwrap_or(false)
}

/// `wanted`, or with a `-2`, `-3`... suffix when another companion has it;
/// a name the config would refuse becomes `companion`
fn unique_name(wanted: &str, taken_names: &[&str]) -> String {
    let base = if is_mac_name(wanted) {
        wanted
    } else {
        "companion"
    };
    // `local` names the gateway's own `op` in read errors
    let taken = |name: &str| name == "local" || taken_names.contains(&name);
    if !taken(base) {
        return base.to_owned();
    }

    (2..)
        .map(|number| {
            let suffix = format!("-{number}");
            let kept: String = base
                .chars()
                .take(MAX_MAC_NAME_CHARS - suffix.len())
                .collect();

            format!("{kept}{suffix}")
        })
        .find(|name| !taken(name))
        .unwrap_or_else(|| base.to_owned())
}
