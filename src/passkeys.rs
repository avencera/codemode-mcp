//! Passkey enrollment and assertions (WebAuthn)
//!
//! Ceremony state stays in memory, keyed by a random id with a short
//! lifetime; it is never serialized to the client

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
    #[error("enter a label of 1 to {MAX_LABEL_CHARS} characters")]
    Label,
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
        label: String,
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

/// Enrolled passkeys and the ceremonies in progress
pub struct Passkeys {
    webauthn: Webauthn,
    store: Store,
    ceremonies: Mutex<HashMap<String, Ceremony>>,
    enrollments: Mutex<HashMap<String, Instant>>,
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

    /// Creates a one-time enrollment token
    pub fn create_enrollment(&self) -> String {
        let token = random_token();
        let mut enrollments = lock(&self.enrollments);
        enrollments.retain(|_, expires_at| *expires_at > Instant::now());
        enrollments.insert(token.clone(), Instant::now() + ENROLLMENT_TTL);

        token
    }

    /// Whether an enrollment token can still be used
    pub fn enrollment_valid(&self, token: &str) -> bool {
        lock(&self.enrollments)
            .get(token)
            .is_some_and(|expires_at| *expires_at > Instant::now())
    }

    /// Starts registering a passkey named `label`
    pub fn start_registration(
        &self,
        token: &str,
        label: &str,
    ) -> Result<(String, CreationChallengeResponse), PasskeyError> {
        if !self.enrollment_valid(token) {
            return Err(PasskeyError::UnknownToken);
        }
        let label = label.trim();
        if label.is_empty() || label.chars().count() > MAX_LABEL_CHARS {
            return Err(PasskeyError::Label);
        }

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
            label: label.to_owned(),
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
            label,
            state,
            ..
        }) = self.take(ceremony)
        else {
            return Err(PasskeyError::UnknownCeremony);
        };
        if expected != token || lock(&self.enrollments).remove(token).is_none() {
            return Err(PasskeyError::UnknownToken);
        }

        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| PasskeyError::Rejected)?;
        let json = serde_json::to_string(&passkey)
            .map_err(|error| StoreError::Corrupt(error.to_string()))?;

        Ok(self.store.add_passkey(&label, &json)?)
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
