//! A wall-clock allowance that can be paused while a script waits on a human

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use tokio::sync::Notify;

/// Wall-clock time one execution may use
///
/// Time spent while at least one [`PauseGuard`] is alive does not count, so a
/// script waiting for an approval is not killed for the wait. Clones share the
/// same clock
#[derive(Debug, Clone)]
pub struct Budget {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    limit: Duration,
    state: Mutex<State>,
    resumed: Notify,
}

#[derive(Debug)]
struct State {
    /// Time consumed before the current running stretch began
    spent: Duration,
    /// Start of the current running stretch; `None` while paused
    since: Option<Instant>,
    /// Live pause guards; the clock runs only when this is zero
    pauses: usize,
}

impl Budget {
    /// Starts a budget of `limit` now
    pub fn new(limit: Duration) -> Self {
        Self {
            shared: Arc::new(Shared {
                limit,
                state: Mutex::new(State {
                    spent: Duration::ZERO,
                    since: Some(Instant::now()),
                    pauses: 0,
                }),
                resumed: Notify::new(),
            }),
        }
    }

    /// Stops the clock until the returned guard (and any other) is dropped
    pub fn pause(&self) -> PauseGuard {
        let mut state = self.state();
        if state.pauses == 0
            && let Some(since) = state.since.take()
        {
            state.spent += since.elapsed();
        }
        state.pauses += 1;

        PauseGuard {
            budget: self.clone(),
        }
    }

    /// Time left; zero once exhausted
    pub fn remaining(&self) -> Duration {
        self.remaining_locked(&self.state())
    }

    /// Resolves when the allowance is used up; never while paused
    pub async fn expired(&self) {
        loop {
            let (remaining, paused) = {
                let state = self.state();

                (self.remaining_locked(&state), state.since.is_none())
            };
            if paused {
                self.shared.resumed.notified().await;
            } else if remaining.is_zero() {
                return;
            } else {
                tokio::time::sleep(remaining).await;
            }
        }
    }

    fn remaining_locked(&self, state: &State) -> Duration {
        let spent = state.spent + state.since.map_or(Duration::ZERO, |since| since.elapsed());

        self.shared.limit.saturating_sub(spent)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Keeps a [`Budget`] paused while alive
#[derive(Debug)]
pub struct PauseGuard {
    budget: Budget,
}

impl Drop for PauseGuard {
    fn drop(&mut self) {
        let mut state = self.budget.state();
        state.pauses = state.pauses.saturating_sub(1);
        if state.pauses == 0 {
            state.since = Some(Instant::now());
            self.budget.shared.resumed.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn paused_time_does_not_count() {
        let budget = Budget::new(Duration::from_millis(300));

        let pause = budget.pause();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let remaining_while_paused = budget.remaining();
        drop(pause);

        assert!(
            remaining_while_paused > Duration::from_millis(200),
            "{remaining_while_paused:?}"
        );
        let started = Instant::now();
        budget.expired().await;
        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "expired after only {:?}",
            started.elapsed()
        );
    }
}
