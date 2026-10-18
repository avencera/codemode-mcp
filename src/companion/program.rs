//! Values a program on the gateway Mac asks for, through `codemode-mcp op
//! read`, `op inject` and `op run`, approved wherever the owner is
//!
//! While the owner is at the gateway Mac it asks first: its own Touch ID
//! prompt names every item, then the local `op` reads them. The phones and
//! companion Macs are asked [`PHONE_GRACE`] later, or at once while the owner
//! is away. The first device to approve answers the whole batch, and a Deny
//! on any device ends it
//!
//! Unlike the gateway's own config reads, nothing comes from the cache and
//! the local `op` never runs without that prompt first: 1Password's prompt
//! names no item and one approval lets `op` read anything for about ten
//! minutes, so a program could otherwise read silently after any earlier
//! approval

use std::{sync::Arc, time::Duration};

use companion_wire::{
    mobile::{PhoneProgramRead, PhoneProgramRequest, ProgramItem, RequestId},
    wire::{
        MAX_DESCRIPTION_CHARS, MAX_DESTINATION_CHARS, MAX_KEEP_SECS, MAX_PROGRAM_ITEMS,
        MAX_REASON_CHARS,
    },
};
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, task::JoinSet, time::Instant};

use super::{
    ASK_TIMEOUT, CompanionErrorCode, CompanionFailure, CompanionProgramRequest, CompanionResponse,
    Companions, MALFORMED_REQUEST, MAX_PHONE_READ_BYTES, ProgramBatch, ProgramValue, apns::Subject,
};
use crate::{
    config::{CompanionPeer, PhonePeer},
    mac::TouchId,
    prompt,
    secrets::{OnePassword, PHONE_GRACE, is_reference},
};

/// Cancel button of the gateway Mac's own prompt
const CANCEL_TITLE: &str = "Deny";

/// One value a program asks for
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramTarget {
    /// An `op://` reference
    Reference(String),
    /// Only a description, such as `Pushover app token`, for a program that
    /// does not know the item; only a phone can answer it, where the owner
    /// picks the item with AutoFill
    Describe(String),
}

/// The values a program asked for, in its order, and the device that sent
/// them
pub struct ProgramValues {
    /// `this Mac`, or the name of the companion or phone that answered
    pub source: String,
    /// One value per target, as 1Password holds it, which may not be text
    pub values: Vec<ProgramValue>,
}

impl std::fmt::Debug for ProgramValues {
    // the values stay out of logs
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProgramValues")
            .field("source", &self.source)
            .field("values", &self.values.len())
            .finish()
    }
}

/// Why a program read gave no values; none of the text holds a value
#[derive(Debug, thiserror::Error)]
pub enum ProgramReadError {
    /// The request itself was refused before anyone was asked
    #[error("{0}")]
    Invalid(String),
    /// The owner said no on one of the devices
    #[error("{0}")]
    Denied(String),
    /// No device sent the values
    #[error("{0}")]
    Failed(String),
}

/// The references, trimmed, when every one is well formed and there are
/// between one and [`MAX_PROGRAM_ITEMS`] of them
pub fn checked_references(references: &[String]) -> Result<Vec<String>, String> {
    if references.is_empty() || references.len() > MAX_PROGRAM_ITEMS {
        return Err(format!(
            "a program read asks for 1 to {MAX_PROGRAM_ITEMS} values"
        ));
    }

    references
        .iter()
        .map(|reference| {
            let reference = reference.trim();
            if is_reference(reference) {
                Ok(reference.to_owned())
            } else {
                Err(format!(
                    "{} is not an op://vault/item/field reference",
                    prompt::one_line(reference, 80)
                ))
            }
        })
        .collect()
}

/// The targets, trimmed and checked like [`checked_references`]; a
/// description must be one line of at most [`MAX_DESCRIPTION_CHARS`]
pub fn checked_targets(targets: &[ProgramTarget]) -> Result<Vec<ProgramTarget>, String> {
    if targets.is_empty() || targets.len() > MAX_PROGRAM_ITEMS {
        return Err(format!(
            "a program read asks for 1 to {MAX_PROGRAM_ITEMS} values"
        ));
    }

    targets
        .iter()
        .map(|target| match target {
            ProgramTarget::Reference(reference) => {
                checked_references(std::slice::from_ref(reference))
                    .map(|mut checked| ProgramTarget::Reference(checked.remove(0)))
            }
            ProgramTarget::Describe(description) => {
                let description = description.trim();
                let readable = !description.is_empty()
                    && description.chars().count() <= MAX_DESCRIPTION_CHARS
                    && prompt::one_line(description, usize::MAX) == description;
                if readable {
                    Ok(ProgramTarget::Describe(description.to_owned()))
                } else {
                    Err(format!(
                        "a description is one line of 1 to {MAX_DESCRIPTION_CHARS} characters"
                    ))
                }
            }
        })
        .collect()
}

/// The reason as prompts may show it: one line, at most
/// [`MAX_REASON_CHARS`]; `None` when blank
pub fn clean_reason(reason: Option<&str>) -> Option<String> {
    reason
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(|reason| prompt::one_line(reason, MAX_REASON_CHARS))
}

/// What a program asks for, as the admin route and the `secrets` builtin
/// server pass it on
#[derive(Debug, Clone, Default)]
pub struct ProgramAsk {
    /// The values, in order
    pub targets: Vec<ProgramTarget>,
    /// Why, shown quoted as the program's claim
    pub reason: Option<String>,
    /// Where the values go, such as a file path; shown in every prompt
    pub destination: Option<String>,
    /// How long to hand the same values out again without asking, at most
    /// [`MAX_KEEP_SECS`]; said in every prompt
    pub keep: Option<Duration>,
}

/// What every prompt of one program read shows besides the items, cleaned
#[derive(Debug, Clone)]
struct Context {
    reason: Option<String>,
    destination: Option<String>,
    keep_secs: Option<u64>,
}

/// The destination; `None` when blank. One that a prompt could not show
/// whole and as is, being longer than [`MAX_DESTINATION_CHARS`], holding a
/// line break or control character, or starting or ending with whitespace,
/// is refused rather than cut or trimmed, since the prompt would then name
/// a different file from the one the values really go to
pub fn clean_destination(destination: Option<&str>) -> Result<Option<String>, String> {
    let Some(destination) = destination.filter(|destination| !destination.trim().is_empty()) else {
        return Ok(None);
    };
    if destination.chars().count() > MAX_DESTINATION_CHARS
        || destination.trim() != destination
        || prompt::one_line(destination, usize::MAX) != destination
    {
        return Err(format!(
            "a destination is one line of at most {MAX_DESTINATION_CHARS} characters, \
             with no space at either end"
        ));
    }

    Ok(Some(destination.to_owned()))
}

/// A keep window in seconds as prompts state it: unset or zero is none, and
/// at most [`MAX_KEEP_SECS`]
pub fn clean_keep(keep_secs: Option<u64>) -> Option<u64> {
    keep_secs
        .filter(|secs| *secs > 0)
        .map(|secs| secs.min(MAX_KEEP_SECS))
}

/// What the push and the prompts call the targets
fn shown(targets: &[ProgramTarget]) -> Vec<String> {
    targets
        .iter()
        .map(|target| match target {
            ProgramTarget::Reference(reference) => reference.clone(),
            ProgramTarget::Describe(description) => format!("\"{description}\""),
        })
        .collect()
}

/// The references of `targets`, when every target is one
fn all_references(targets: &[ProgramTarget]) -> Option<Vec<String>> {
    targets
        .iter()
        .map(|target| match target {
            ProgramTarget::Reference(reference) => Some(reference.clone()),
            ProgramTarget::Describe(_) => None,
        })
        .collect()
}

/// Why one device gave no values
enum Miss {
    /// The owner said no there, which ends the whole read
    Denied(String),
    /// Anything else; the other devices are still waited for
    Failed(String),
}

impl Miss {
    fn from_failure(source: &str, failure: CompanionFailure) -> Self {
        match failure {
            CompanionFailure::Refused {
                code: CompanionErrorCode::Denied,
                message,
            } => Self::Denied(format!("{source}: {message}")),
            other => Self::Failed(format!("{source}: {other}")),
        }
    }
}

impl OnePassword {
    /// Asks for `ask.targets` on behalf of a program, with its reason,
    /// destination and any keep window shown in every prompt; see the
    /// module docs for who is asked when
    ///
    /// A batch holding a description goes to the phones only, since the
    /// Macs have no way to enter a value. Values read for references are
    /// sealed to the phones afterwards, so the next request opens with Face
    /// ID there. With `ask.keep`, they are also kept in memory for that long
    /// and handed out again without asking
    pub async fn read_for_program(
        &self,
        ask: &ProgramAsk,
    ) -> Result<ProgramValues, ProgramReadError> {
        let targets = checked_targets(&ask.targets).map_err(ProgramReadError::Invalid)?;
        let context = Context {
            reason: clean_reason(ask.reason.as_deref()),
            destination: clean_destination(ask.destination.as_deref())
                .map_err(ProgramReadError::Invalid)?,
            keep_secs: clean_keep(ask.keep.map(|keep| keep.as_secs())),
        };
        let references = all_references(&targets);
        let forgotten = self.forgotten().await;
        if let Some(references) = &references
            && let Some(values) = self
                .kept_values(context.destination.as_deref(), references)
                .await
        {
            return Ok(ProgramValues {
                source: "kept from an earlier approval".to_owned(),
                values,
            });
        }
        let companions = self.companions().cloned();

        let local = match (self.on_mac(), &references) {
            (Some(on_mac), Some(_)) => {
                on_mac.config.touch_id && on_mac.mac.present(on_mac.config.idle()).await
            }
            _ => false,
        };
        let peers = match (&companions, &references) {
            (Some(companions), Some(_)) => companions.peers(),
            _ => Vec::new(),
        };
        let phones = companions
            .as_ref()
            .map(|companions| companions.phones())
            .unwrap_or_default();
        if !local && peers.is_empty() && phones.is_empty() {
            let message = if references.is_some() {
                "nobody can approve this: the owner is away from this Mac and no companion Mac or \
                 phone is paired (`codemode-mcp companion invite`)"
            } else {
                "only a phone can answer a description, and none is paired; pass op:// \
                 references instead"
            };

            return Err(ProgramReadError::Failed(message.to_owned()));
        }

        let mut sources: JoinSet<(String, Result<Vec<ProgramValue>, Miss>)> = JoinSet::new();
        // set once this Mac has failed, so the others need not sit out the
        // rest of the grace
        let (local_failed, grace_over) = watch::channel(!local);
        // held here too, since a sender dropped by a local read that
        // succeeded would end the grace early
        let local_failed = Arc::new(local_failed);
        if let (true, Some(references)) = (local, &references) {
            let local_failed = Arc::clone(&local_failed);
            let onepassword = self.clone();
            let references = references.clone();
            let context = context.clone();
            sources.spawn(async move {
                let values = onepassword.read_here(&references, &context).await;
                if values.is_err() {
                    local_failed.send_replace(true);
                }

                ("this Mac".to_owned(), values)
            });
        }
        // the owner at this Mac answers its prompt first, and a read answered
        // within the grace never reaches the other devices
        let grace = if local { PHONE_GRACE } else { Duration::ZERO };
        let wait_grace = move || {
            let mut grace_over = grace_over.clone();
            async move {
                let failed = grace_over.wait_for(|failed| *failed);
                let _ = tokio::time::timeout(grace, failed).await;
            }
        };
        let deadline = Instant::now() + ASK_TIMEOUT;
        if let (Some(references), Some(companions)) = (&references, &companions) {
            for peer in peers {
                let companions = Arc::clone(companions);
                let batch = ProgramBatch {
                    references: references.clone(),
                    reason: context.reason.clone(),
                    destination: context.destination.clone(),
                    keep_secs: context.keep_secs,
                };
                let waited = wait_grace();
                sources.spawn(async move {
                    waited.await;
                    let values = companions
                        .program_read_mac(&peer, batch)
                        .await
                        .map_err(|failure| Miss::from_failure(&peer.name, failure));

                    (peer.name, values)
                });
            }
        }
        for (phone, companions) in phones
            .into_iter()
            .filter_map(|phone| companions.clone().map(|companions| (phone, companions)))
        {
            let targets = targets.clone();
            let context = context.clone();
            let waited = wait_grace();
            sources.spawn(async move {
                waited.await;
                let values = companions
                    .program_read_phone(&phone, &targets, &context, deadline)
                    .await
                    .map_err(|failure| Miss::from_failure(&phone.name, failure));

                (phone.name, values)
            });
        }

        // dropping the set on any exit takes the other prompts down: the
        // local prompt and `op` die with their task, companion connections
        // hang up and phone streams stop
        let first = async {
            let mut failures = Vec::new();
            while let Some(finished) = sources.join_next().await {
                match finished {
                    Ok((source, Ok(values))) => return Ok(ProgramValues { source, values }),
                    Ok((_, Err(Miss::Denied(message)))) => {
                        return Err(ProgramReadError::Denied(message));
                    }
                    Ok((_, Err(Miss::Failed(message)))) => failures.push(message),
                    Err(error) => failures.push(format!("a read stopped unexpectedly: {error}")),
                }
            }

            Err(ProgramReadError::Failed(failures.join("; ")))
        };
        let outcome = tokio::time::timeout(ASK_TIMEOUT + grace, first)
            .await
            .unwrap_or_else(|_| {
                Err(ProgramReadError::Failed(format!(
                    "nobody approved within {:?}",
                    ASK_TIMEOUT + grace
                )))
            })?;

        // the losers' prompts come down now, not after the sealing below
        drop(sources);
        drop(local_failed);

        if let Some(companions) = &companions {
            for (target, value) in targets.iter().zip(&outcome.values) {
                // a phone hands back what it opens as text, so a file such as
                // a `.p12` is never sealed to it
                if let (ProgramTarget::Reference(reference), Some(text)) = (target, value.as_text())
                {
                    companions.seal_for_phones(reference, text).await;
                }
            }
        }
        if let (Some(keep_secs), Some(references)) = (context.keep_secs, &references) {
            self.keep(
                context.destination.as_deref(),
                references,
                &outcome.values,
                Duration::from_secs(keep_secs),
                forgotten,
            )
            .await;
        }

        Ok(outcome)
    }

    /// Asks on this Mac: its own Touch ID prompt naming every reference,
    /// then the local `op` for each
    async fn read_here(
        &self,
        references: &[String],
        context: &Context,
    ) -> Result<Vec<ProgramValue>, Miss> {
        let Some(on_mac) = self.on_mac() else {
            return Err(Miss::Failed("this Mac: no Touch ID".to_owned()));
        };
        let text = prompt::program_prompt_text(&prompt::ProgramPrompt {
            items: references,
            place: "this Mac",
            reason: context.reason.as_deref(),
            destination: context.destination.as_deref(),
            keep_secs: context.keep_secs,
        });
        match on_mac.mac.touch_id(&text, CANCEL_TITLE).await {
            TouchId::Approved => {}
            // its other button is Deny
            TouchId::Review => return Err(Miss::Denied("this Mac: not approved".to_owned())),
            TouchId::Away => {
                return Err(Miss::Failed(
                    "this Mac: the prompt was taken down, the owner seems away".to_owned(),
                ));
            }
            TouchId::Unavailable => {
                return Err(Miss::Failed("this Mac: Touch ID is unavailable".to_owned()));
            }
        }

        let mut values = Vec::with_capacity(references.len());
        for reference in references {
            let value = self
                .read_local(reference)
                .await
                .map_err(|error| Miss::Failed(format!("this Mac: {error}")))?;
            values.push(ProgramValue::from(value));
        }

        Ok(values)
    }
}

impl Companions {
    /// Asks the companion Mac `peer` for a program's batch
    async fn program_read_mac(
        &self,
        peer: &CompanionPeer,
        batch: ProgramBatch,
    ) -> Result<Vec<ProgramValue>, CompanionFailure> {
        let expected = batch.references.len();
        let request = serde_json::to_vec(&CompanionProgramRequest {
            program_read: batch,
        })
        .map_err(|error| CompanionFailure::Exchange {
            name: peer.name.clone(),
            detail: error.to_string(),
        })?;
        let body = tokio::time::timeout(ASK_TIMEOUT, self.send(peer, &request))
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: peer.name.clone(),
                    timeout: ASK_TIMEOUT,
                })
            })?;

        match serde_json::from_slice(&body) {
            Ok(CompanionResponse::Values(values)) if values.len() == expected => Ok(values),
            // a companion from before program reads finds no reference in
            // the request and says so the way it says any unreadable request
            Ok(CompanionResponse::Error(fault))
                if fault.code == CompanionErrorCode::NotAllowed
                    && fault.message == MALFORMED_REQUEST =>
            {
                Err(CompanionFailure::Exchange {
                    name: peer.name.clone(),
                    detail: "this companion predates program reads; run `codemode-mcp update` \
                             on that Mac"
                        .to_owned(),
                })
            }
            Ok(CompanionResponse::Error(fault)) => Err(CompanionFailure::Refused {
                code: fault.code,
                message: fault.message,
            }),
            Ok(_) => Err(CompanionFailure::Exchange {
                name: peer.name.clone(),
                detail: "answered with the wrong number of values".to_owned(),
            }),
            Err(error) => Err(CompanionFailure::Exchange {
                name: peer.name.clone(),
                detail: format!("malformed answer: {error}"),
            }),
        }
    }

    /// Asks `phone` for a program's batch, sending the sealed copies it has
    async fn program_read_phone(
        self: &Arc<Self>,
        phone: &PhonePeer,
        targets: &[ProgramTarget],
        context: &Context,
        deadline: Instant,
    ) -> Result<Vec<ProgramValue>, CompanionFailure> {
        let key = phone.id.to_string();
        let items: Vec<ProgramItem> = targets
            .iter()
            .map(|target| match target {
                ProgramTarget::Reference(reference) => ProgramItem::Reference {
                    reference: reference.clone(),
                    sealed: self
                        .store
                        .as_ref()
                        .and_then(|store| store.seal(&key, reference).ok().flatten()),
                },
                ProgramTarget::Describe(description) => ProgramItem::Describe {
                    description: description.clone(),
                },
            })
            .collect();
        let id = RequestId::generate();
        let encode = |expires_in_ms| {
            let mut read = PhoneProgramRead {
                id: id.clone(),
                items: items.clone(),
                reason: context.reason.clone(),
                destination: context.destination.clone(),
                keep_secs: context.keep_secs,
                expires_in_ms,
            };
            let mut request = serde_json::to_vec(&PhoneProgramRequest {
                program_read: read.clone(),
            })
            .map_err(|error| error.to_string())?;
            // too large for the phone to take: the largest copies are left
            // out first, and the owner enters those values instead
            while request.len() > MAX_PHONE_READ_BYTES {
                let largest = read
                    .items
                    .iter_mut()
                    .filter_map(|item| match item {
                        ProgramItem::Reference { sealed, .. } if sealed.is_some() => Some(sealed),
                        ProgramItem::Reference { .. } => None,
                        ProgramItem::Describe { .. } => None,
                    })
                    .max_by_key(|sealed| {
                        sealed
                            .as_ref()
                            .map_or(0, |sealed| sealed.ciphertext.len() + sealed.enc.len())
                    });
                let Some(largest) = largest else {
                    break;
                };
                *largest = None;
                request = serde_json::to_vec(&PhoneProgramRequest {
                    program_read: read.clone(),
                })
                .map_err(|error| error.to_string())?;
            }

            Ok(request)
        };
        let summary = summary(targets, context);

        let asked = self.ask_until(phone, &id, Subject::Program(summary), deadline, encode);
        let answer = tokio::time::timeout_at(deadline, asked)
            .await
            .unwrap_or_else(|_| {
                Err(CompanionFailure::TimedOut {
                    name: phone.name.clone(),
                    timeout: ASK_TIMEOUT,
                })
            })?;

        match answer {
            CompanionResponse::Values(values) if values.len() == targets.len() => Ok(values),
            CompanionResponse::Error(fault) => Err(CompanionFailure::Refused {
                code: fault.code,
                message: fault.message,
            }),
            _ => Err(CompanionFailure::Exchange {
                name: phone.name.clone(),
                detail: "answered with the wrong number of values".to_owned(),
            }),
        }
    }
}

/// The push's one line about a program read, such as `2 values into
/// superalert.secrets.env for "freezerwatch alerts": op://…, "Pushover app
/// token"`
fn summary(targets: &[ProgramTarget], context: &Context) -> String {
    let noun = if targets.len() == 1 {
        "value"
    } else {
        "values"
    };
    let mut text = format!("{} {noun}", targets.len());
    if let Some(destination) = &context.destination {
        // the file name says enough on a lock screen; the app shows the path
        let name = destination.rsplit('/').next().unwrap_or(destination);
        text.push_str(&format!(" into {name}"));
    }
    if let Some(reason) = &context.reason {
        text.push_str(&format!(" for \"{reason}\""));
    }
    text.push_str(": ");
    text.push_str(&shown(targets).join(", "));

    prompt::one_line(&text, 240)
}
