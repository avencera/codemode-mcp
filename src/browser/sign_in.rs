//! Login values the phone sent for a sign-in that are not filled yet
//!
//! While the owner is away, the first fill of a sign-in asks the phone once
//! for every value the site's login needs, so one approval covers the
//! username, the password and, from a sealed seed, the code. The rest wait
//! here, in memory only, until filled or [`WINDOW`] passes, and each is
//! wiped as it is taken

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use companion_wire::mobile::LoginField;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::page::SessionName;

/// How long values wait for their fill after the phone sent them
pub const WINDOW: Duration = Duration::from_secs(5 * 60);

struct Held {
    values: HashMap<LoginField, Zeroizing<String>>,
    until: Instant,
}

type Waiting = Mutex<HashMap<(SessionName, String), Held>>;

/// The values waiting, by session and site
#[derive(Default)]
pub struct SignIns(Arc<Waiting>);

impl SignIns {
    /// Keeps `values` for `session` on `site`, replacing what was kept
    pub fn hold(
        &self,
        session: &SessionName,
        site: &str,
        values: HashMap<LoginField, Zeroizing<String>>,
    ) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        held.retain(|_, held| held.until > now);
        if values.is_empty() {
            held.remove(&(session.clone(), site.to_owned()));

            return;
        }
        let until = now + WINDOW;
        held.insert((session.clone(), site.to_owned()), Held { values, until });

        // wiped when the window ends, even if no other sign-in comes along
        let waiting = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            tokio::time::sleep_until(until).await;
            let Some(waiting) = waiting.upgrade() else {
                return;
            };
            let now = Instant::now();
            waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|_, held| held.until > now);
        });
    }

    /// Takes `field`'s value for `session` on `site`, if one waits
    pub fn take(
        &self,
        session: &SessionName,
        site: &str,
        field: LoginField,
    ) -> Option<Zeroizing<String>> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        held.retain(|_, held| held.until > now && !held.values.is_empty());
        let key = (session.clone(), site.to_owned());
        let value = held.get_mut(&key)?.values.remove(&field);
        if held.get(&key).is_some_and(|held| held.values.is_empty()) {
            held.remove(&key);
        }

        value
    }
}
