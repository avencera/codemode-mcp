//! Passkey enrollment and assertions (WebAuthn)
//!
//! Enrollment links and ceremony state live in the database, keyed by a
//! hash of the token or by a random id, with a short lifetime, so a link
//! or a page opened before a restart still works; the ceremony state is
//! never sent to the client
//!
//! The first passkey can be enrolled with a bare one-time link. Once one
//! exists, a new link only works after an existing passkey approves it, so
//! an agent that can run the CLI cannot add its own authenticator

use std::time::Duration;

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
    store::{Store, StoreError, enrollments::StoredCeremony, now_ms, sessions::hash_token},
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
/// Stored kind of a registration ceremony
const REGISTER: &str = "register";
/// Stored kind of an assertion ceremony
const AUTHENTICATE: &str = "authenticate";

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
    #[error("no passkey enrolled; run `codemode-mcp passkey enroll --label NAME`")]
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

impl EnrollmentGate {
    /// Name stored in the database
    fn as_str(self) -> &'static str {
        match self {
            Self::FirstPasskey => "first_passkey",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Approved => "approved",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "first_passkey" => Some(Self::FirstPasskey),
            "awaiting_approval" => Some(Self::AwaitingApproval),
            "approved" => Some(Self::Approved),
            _ => None,
        }
    }
}

/// An enrollment link read back from the database
struct Enrollment {
    label: String,
    gate: EnrollmentGate,
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
    /// SHA-256 of the token, the only form that is stored
    pub hash: String,
    /// Whether an existing passkey must approve it first
    pub needs_approval: bool,
}

/// Enrolled passkeys, enrollment links and the ceremonies in progress
pub struct Passkeys {
    webauthn: Webauthn,
    store: Store,
}

fn millis(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
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

        Ok(Self { webauthn, store })
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
        let hash = hash_token(&token);
        let gate = if needs_approval {
            EnrollmentGate::AwaitingApproval
        } else {
            EnrollmentGate::FirstPasskey
        };
        self.store.put_enrollment(
            &hash,
            label,
            gate.as_str(),
            now_ms() + millis(ENROLLMENT_TTL),
        )?;

        Ok(NewEnrollment {
            token,
            hash,
            needs_approval,
        })
    }

    /// Marks a link approved by an existing passkey; its lifetime restarts so
    /// a late approval still leaves time to enroll
    pub fn approve_enrollment(&self, hash: &str) {
        let advanced = self.store.advance_enrollment(
            hash,
            EnrollmentGate::AwaitingApproval.as_str(),
            EnrollmentGate::Approved.as_str(),
            now_ms() + millis(ENROLLMENT_TTL),
        );
        if let Err(error) = advanced {
            tracing::warn!(%error, "could not mark an enrollment link approved");
        }
    }

    /// Invalidates a link, e.g. after its approval was denied
    pub fn drop_enrollment(&self, hash: &str) {
        if let Err(error) = self.store.take_enrollment(hash) {
            tracing::warn!(%error, "could not drop an enrollment link");
        }
    }

    /// The link's label and whether it can be used now; `None` when it is
    /// unknown, used or expired
    pub fn enrollment(&self, token: &str) -> Result<Option<EnrollmentView>, PasskeyError> {
        let Some(Enrollment { label, gate }) = self.live_enrollment(token)? else {
            return Ok(None);
        };
        let ready = self.gate_open(gate)?;
        // a first-passkey link is dead once any passkey exists
        if gate == EnrollmentGate::FirstPasskey && !ready {
            return Ok(None);
        }

        Ok(Some(EnrollmentView { label, ready }))
    }

    fn live_enrollment(&self, token: &str) -> Result<Option<Enrollment>, PasskeyError> {
        Ok(self
            .store
            .enrollment(&hash_token(token))?
            .and_then(|stored| {
                Some(Enrollment {
                    gate: EnrollmentGate::parse(&stored.gate)?,
                    label: stored.label,
                })
            }))
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
        let Enrollment { label, gate } = self
            .live_enrollment(token)?
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

        let id = self.insert(StoredCeremony {
            kind: REGISTER.to_owned(),
            subject: hash_token(token),
            choice: None,
            state: serde_json::to_string(&state)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
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
        let hash = hash_token(token);
        let stored = self
            .take(ceremony)?
            .filter(|stored| stored.kind == REGISTER)
            .ok_or(PasskeyError::UnknownCeremony)?;
        if stored.subject != hash {
            return Err(PasskeyError::UnknownToken);
        }
        let state: PasskeyRegistration =
            serde_json::from_str(&stored.state).map_err(|_| PasskeyError::UnknownCeremony)?;
        let enrollment = self
            .store
            .take_enrollment(&hash)?
            .ok_or(PasskeyError::UnknownToken)?;
        let gate = EnrollmentGate::parse(&enrollment.gate).ok_or(PasskeyError::UnknownToken)?;
        if gate == EnrollmentGate::AwaitingApproval {
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
        let only_if_none = gate == EnrollmentGate::FirstPasskey;
        let id = self
            .store
            .add_passkey(&enrollment.label, &json, only_if_none)?
            .ok_or(PasskeyError::UnknownToken)?;
        // other first-passkey links must not come back to life if every
        // passkey is removed later
        self.store
            .remove_enrollments_with_gate(EnrollmentGate::FirstPasskey.as_str())?;

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

        let id = self.insert(StoredCeremony {
            kind: AUTHENTICATE.to_owned(),
            subject: approval_id.to_owned(),
            choice: Some(choice.as_text()),
            state: serde_json::to_string(&state)
                .map_err(|error| StoreError::Corrupt(error.to_string()))?,
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
        let stored = self
            .take(ceremony)?
            .filter(|stored| stored.kind == AUTHENTICATE)
            .ok_or(PasskeyError::UnknownCeremony)?;
        let approval_id = stored.subject;
        let choice = stored
            .choice
            .as_deref()
            .and_then(Choice::parse)
            .ok_or(PasskeyError::UnknownCeremony)?;
        let state: PasskeyAuthentication =
            serde_json::from_str(&stored.state).map_err(|_| PasskeyError::UnknownCeremony)?;

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

    /// Stores a ceremony under a new random id
    fn insert(&self, ceremony: StoredCeremony) -> Result<String, PasskeyError> {
        let id = random_token();
        let stored = self.store.put_ceremony(
            &id,
            &ceremony,
            now_ms() + millis(CEREMONY_TTL),
            MAX_CEREMONIES,
        )?;

        stored.then_some(id).ok_or(PasskeyError::Busy)
    }

    fn take(&self, id: &str) -> Result<Option<StoredCeremony>, PasskeyError> {
        Ok(self.store.take_ceremony(id)?)
    }
}
