//! The one place that decides whether in-memory state may reach the disk
//!
//! Sensitive servers (1Password) keep their data off disk. Every store
//! function that writes a payload takes a [`Durable`] instead of the payload
//! itself, and the only way to make one is [`Durable::gate`], which drops the
//! payload for sensitive state before it is even built. A later caller that
//! forgets the rule cannot write a sensitive payload by accident, because
//! there is no other way to hand the store one

/// Whether state may hold data from a sensitive server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sensitivity(bool);

impl Sensitivity {
    /// State that holds nothing from a sensitive server
    pub const PLAIN: Self = Self(false);

    /// State that holds, or may hold, data from a sensitive server
    pub const SENSITIVE: Self = Self(true);

    /// `SENSITIVE` when `sensitive`, else `PLAIN`
    pub fn of(sensitive: bool) -> Self {
        Self(sensitive)
    }

    /// Whether the state is sensitive
    pub fn is_sensitive(self) -> bool {
        self.0
    }

    /// Sensitive when either side is
    pub fn or(self, other: Self) -> Self {
        Self(self.0 || other.0)
    }
}

/// A payload cleared for the database, or the fact that it was withheld
#[derive(Debug)]
pub struct Durable<T> {
    sensitivity: Sensitivity,
    payload: Option<T>,
}

impl<T> Durable<T> {
    /// Builds the payload only when `sensitivity` allows it to be stored
    pub fn gate(sensitivity: Sensitivity, payload: impl FnOnce() -> T) -> Self {
        Self {
            sensitivity,
            payload: (!sensitivity.is_sensitive()).then(payload),
        }
    }

    /// Whether the payload was withheld; stored as the row's `sensitive` flag
    pub fn withheld(&self) -> bool {
        self.sensitivity.is_sensitive()
    }

    /// The payload, `None` when it was withheld
    pub(crate) fn payload(&self) -> Option<&T> {
        self.payload.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sensitive_payload_is_never_built() {
        let mut built = false;
        let withheld = Durable::gate(Sensitivity::SENSITIVE, || {
            built = true;
            "secret"
        });
        let kept = Durable::gate(Sensitivity::of(false), || "plain");

        assert!(!built);
        assert!(withheld.withheld() && withheld.payload().is_none());
        assert_eq!(kept.payload(), Some(&"plain"));
    }
}
