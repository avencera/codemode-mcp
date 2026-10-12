//! Passkey enrollment and assertions (WebAuthn)
//!
//! Ceremony state stays in memory, keyed by a random id with a short
//! lifetime; it is never serialized to the client
//!
//! The first passkey can be enrolled with a bare one-time link. Once one
//! exists, a new link only works after an existing passkey approves it, so
//! an agent that can run the CLI cannot add its own authenticator

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{
        CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication,
        PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
        RequestChallengeResponse, Url, Uuid,
    },
};

use crate::{
    approvals::{Choice, random_token},
    store::{Store, StoreError},
};

/// How long an enrollment link stays valid
pub const ENROLLMENT_TTL: Duration = Duration::from_secs(10 * 60);
/// How long a started registration or assertion may take to finish
const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
/// Longest label accepted for a passkey
const MAX_LABEL_CHARS: usize = 64;
/// Ceremonies in progress at most; the approval routes are unauthenticated,
/// so anyone holding an approval id could otherwise pile them up
const MAX_CEREMONIES: usize = 64;

/// Why a passkey operation failed; messages are safe to show on the page
#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// `public_origin` cannot serve as a WebAuthn relying party
    #[error("public_origin is not usable for passkeys: {0}")]
    Config(String),
    /// The enrollment link is unknown, used or expired
    #[error("this enrollment link is invalid or has expired")]
    UnknownToken,
    /// The ceremony id is unknown or expired
    #[error("this request has expired; reload the page and try again")]
    UnknownCeremony,
    /// Too many ceremonies are in progress
    #[error("too many passkey requests in progress; try again in a few minutes")]
    Busy,
    /// No passkey is enrolled
    #[error("no passkey enrolled; run `codemode-mcp passkey enroll`")]
    NoPasskeys,
    /// The label is empty or too long
    #[error("enter a label of 1 to {MAX_LABEL_CHARS} characters, without quotes")]
    Label,
    /// The link waits for approval with an existing passkey
    #[error("this enrollment link must first be approved with an existing passkey")]
    AwaitingApproval,
    /// The browser's response did not verify
    #[error("the passkey response could not be verified")]
    Rejected,
    /// Storage failed
    #[error("passkey storage failed")]
    Store(#[from] StoreError),
}

enum Ceremony {
    Register {
        token: String,
        state: PasskeyRegistration,
        expires_at: Instant,
    },
    Authenticate {
        approval_id: String,
        choice: Choice,
        state: PasskeyAuthentication,
        expires_at: Instant,
    },
}

impl Ceremony {
    fn expires_at(&self) -> Instant {
        match self {
            Self::Register { expires_at, .. } | Self::Authenticate { expires_at, .. } => {
                *expires_at
            }
        }
    }
}

/// What lets an enrollment link be used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnrollmentGate {
    /// Created while no passkey existed; valid only while that holds, so a
    /// link minted before the owner enrolled cannot add a second passkey
    FirstPasskey,
    /// Waits for an existing passkey to approve it
    AwaitingApproval,
    /// Approved with an existing passkey
    Approved,
}

struct Enrollment {
    label: String,
    gate: EnrollmentGate,
    expires_at: Instant,
}

/// What the enrollment page needs to know about a link
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentView {
    /// Label the passkey will get
    pub label: String,
    /// Whether registration can start now
    pub ready: bool,
}

/// A created enrollment link
#[derive(Debug, Clone)]
pub struct NewEnrollment {
    /// One-time token in the link
    pub token: String,
    /// Whether an existing passkey must approve it first
    pub needs_approval: bool,
}

/// Enrolled passkeys and the ceremonies in progress
pub struct Passkeys {
    webauthn: Webauthn,
    store: Store,
    ceremonies: Mutex<HashMap<String, Ceremony>>,
    enrollments: Mutex<HashMap<String, Enrollment>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Passkeys {
    /// Relying party for `public_origin`; its host is the RP id
    pub fn new(public_origin: &str, store: Store) -> Result<Self, PasskeyError> {
        let origin =
            Url::parse(public_origin).map_err(|error| PasskeyError::Config(error.to_string()))?;
        let rp_id = origin
            .domain()
            .ok_or_else(|| PasskeyError::Config("the origin needs a DNS name, not an IP".into()))?
            .to_owned();
        let webauthn = WebauthnBuilder::new(&rp_id, &origin)
            .and_then(|builder| builder.rp_name("codemode-mcp").build())
            .map_err(|error| PasskeyError::Config(error.to_string()))?;

        Ok(Self {
            webauthn,
            store,
            ceremonies: Mutex::new(HashMap::new()),
            enrollments: Mutex::new(HashMap::new()),
        })
    }

    /// The database holding the passkeys
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Creates a one-time enrollment token for a passkey named `label`
    ///
    /// With no passkey enrolled the link works at once; otherwise it waits
    /// for [`Passkeys::approve_enrollment`]
    pub fn create_enrollment(&self, label: &str) -> Result<NewEnrollment, PasskeyError> {
        let label = label.trim();
        // quotes could make the approval title read as something else
        if label.is_empty()
            || label.chars().count() > MAX_LABEL_CHARS
            || label
                .chars()
                .any(|character| character.is_control() || "\"'`".contains(character))
        {
            return Err(PasskeyError::Label);
        }
        let needs_approval = self.store.passkey_count()? > 0;

        let token = random_token();
        let mut enrollments = lock(&self.enrollments);
        enrollments.retain(|_, enrollment| enrollment.expires_at > Instant::now());
        enrollments.insert(
            token.clone(),
            Enrollment {
                label: label.to_owned(),
                gate: if needs_approval {
                    EnrollmentGate::AwaitingApproval
                } else {
                    EnrollmentGate::FirstPasskey
                },
                expires_at: Instant::now() + ENROLLMENT_TTL,
            },
        );

        Ok(NewEnrollment {
            token,
            needs_approval,
        })
    }

    /// Marks a link approved by an existing passkey; its lifetime restarts so
    /// a late approval still leaves time to enroll
    pub fn approve_enrollment(&self, token: &str) {
        if let Some(enrollment) = lock(&self.enrollments).get_mut(token)
            && enrollment.gate == EnrollmentGate::AwaitingApproval
            && enrollment.expires_at > Instant::now()
        {
            enrollment.gate = EnrollmentGate::Approved;
            enrollment.expires_at = Instant::now() + ENROLLMENT_TTL;
        }
    }

    /// Invalidates a link, e.g. after its approval was denied
    pub fn drop_enrollment(&self, token: &str) {
        lock(&self.enrollments).remove(token);
    }

    /// The link's label and whether it can be used now; `None` when it is
    /// unknown, used or expired
    pub fn enrollment(&self, token: &str) -> Result<Option<EnrollmentView>, PasskeyError> {
        let Some((label, gate)) = self.live_enrollment(token) else {
            return Ok(None);
        };
        let ready = self.gate_open(gate)?;
        // a first-passkey link is dead once any passkey exists
        if gate == EnrollmentGate::FirstPasskey && !ready {
            return Ok(None);
        }

        Ok(Some(EnrollmentView { label, ready }))
    }

    fn live_enrollment(&self, token: &str) -> Option<(String, EnrollmentGate)> {
        lock(&self.enrollments)
            .get(token)
            .filter(|enrollment| enrollment.expires_at > Instant::now())
            .map(|enrollment| (enrollment.label.clone(), enrollment.gate))
    }

    fn gate_open(&self, gate: EnrollmentGate) -> Result<bool, PasskeyError> {
        Ok(match gate {
            EnrollmentGate::FirstPasskey => self.store.passkey_count()? == 0,
            EnrollmentGate::AwaitingApproval => false,
            EnrollmentGate::Approved => true,
        })
    }

    /// Starts registering a passkey under the link's label
    pub fn start_registration(
        &self,
        token: &str,
    ) -> Result<(String, CreationChallengeResponse), PasskeyError> {
        let (label, gate) = self
            .live_enrollment(token)
            .ok_or(PasskeyError::UnknownToken)?;
        if !self.gate_open(gate)? {
            return Err(match gate {
                EnrollmentGate::FirstPasskey => PasskeyError::UnknownToken,
                _ => PasskeyError::AwaitingApproval,
            });
        }
        let label = label.as_str();

        let existing: Vec<CredentialID> = self
            .passkeys()?
            .into_iter()
            .map(|(_, passkey)| passkey.cred_id().clone())
            .collect();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                Uuid::new_v4(),
                "codemode-mcp",
                label,
                Some(existing).filter(|ids| !ids.is_empty()),
            )
            .map_err(|_| PasskeyError::Rejected)?;

        let id = self.insert(Ceremony::Register {
            token: token.to_owned(),
            state,
            expires_at: Instant::now() + CEREMONY_TTL,
        })?;

        Ok((id, challenge))
    }

    /// Verifies the browser's registration and stores the passkey, using up
    /// the enrollment token
    pub fn finish_registration(
        &self,
        token: &str,
        ceremony: &str,
        credential: &RegisterPublicKeyCredential,
    ) -> Result<i64, PasskeyError> {
        let Some(Ceremony::Register {
            token: expected,
            state,
            ..
        }) = self.take(ceremony)
        else {
            return Err(PasskeyError::UnknownCeremony);
        };
        if expected != token {
            return Err(PasskeyError::UnknownToken);
        }
        let enrollment = lock(&self.enrollments)
            .remove(token)
            .filter(|enrollment| enrollment.expires_at > Instant::now())
            .ok_or(PasskeyError::UnknownToken)?;
        if enrollment.gate == EnrollmentGate::AwaitingApproval {
            return Err(PasskeyError::AwaitingApproval);
        }

        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| PasskeyError::Rejected)?;
        let json = serde_json::to_string(&passkey)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;

        // a first-passkey link checks for an empty table in the same
        // transaction as the insert, so two such links cannot both succeed
        let only_if_none = enrollment.gate == EnrollmentGate::FirstPasskey;
        let id = self
            .store
            .add_passkey(&enrollment.label, &json, only_if_none)?
            .ok_or(PasskeyError::UnknownToken)?;
        // other first-passkey links must not come back to life if every
        // passkey is removed later
        lock(&self.enrollments).retain(|_, other| other.gate != EnrollmentGate::FirstPasskey);

        Ok(id)
    }

    /// Starts an assertion that will apply `choice` to approval `approval_id`
    ///
    /// The choice is bound here, server-side, so the signed response cannot
    /// be replayed for a broader grant
    pub fn start_authentication(
        &self,
        approval_id: &str,
        choice: Choice,
    ) -> Result<(String, RequestChallengeResponse), PasskeyError> {
        let passkeys: Vec<Passkey> = self
            .passkeys()?
            .into_iter()
            .map(|(_, passkey)| passkey)
            .collect();
        if passkeys.is_empty() {
            return Err(PasskeyError::NoPasskeys);
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| PasskeyError::Rejected)?;

        let id = self.insert(Ceremony::Authenticate {
            approval_id: approval_id.to_owned(),
            choice,
            state,
            expires_at: Instant::now() + CEREMONY_TTL,
        })?;

        Ok((id, challenge))
    }

    /// Verifies an assertion, returning the approval and choice it was
    /// started for
    pub fn finish_authentication(
        &self,
        ceremony: &str,
        credential: &PublicKeyCredential,
    ) -> Result<(String, Choice), PasskeyError> {
        let Some(Ceremony::Authenticate {
            approval_id,
            choice,
            state,
            ..
        }) = self.take(ceremony)
        else {
            return Err(PasskeyError::UnknownCeremony);
        };

        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &state)
            .map_err(|_| PasskeyError::Rejected)?;
        // the passkey may have been removed since the ceremony started
        let Some((id, mut passkey)) = self
            .passkeys()?
            .into_iter()
            .find(|(_, passkey)| passkey.cred_id() == result.cred_id())
        else {
            return Err(PasskeyError::Rejected);
        };
        // the counter moved, so store it to catch cloned authenticators
        let updated = match passkey.update_credential(&result) {
            Some(true) => serde_json::to_string(&passkey).ok(),
            _ => None,
        };
        self.store.touch_passkey(id, updated.as_deref())?;

        Ok((approval_id, choice))
    }

    fn passkeys(&self) -> Result<Vec<(i64, Passkey)>, PasskeyError> {
        let mut passkeys = Vec::new();
        for (id, json) in self.store.passkey_credentials()? {
            match serde_json::from_str::<Passkey>(&json) {
                Ok(passkey) => passkeys.push((id, passkey)),
                Err(error) => tracing::warn!(id, %error, "skipping unreadable passkey"),
            }
        }

        Ok(passkeys)
    }

    fn insert(&self, ceremony: Ceremony) -> Result<String, PasskeyError> {
        let id = random_token();
        let mut ceremonies = lock(&self.ceremonies);
        ceremonies.retain(|_, ceremony| ceremony.expires_at() > Instant::now());
        if ceremonies.len() >= MAX_CEREMONIES {
            return Err(PasskeyError::Busy);
        }
        ceremonies.insert(id.clone(), ceremony);

        Ok(id)
    }

    fn take(&self, id: &str) -> Option<Ceremony> {
        lock(&self.ceremonies)
            .remove(id)
            .filter(|ceremony| ceremony.expires_at() > Instant::now())
    }
}
