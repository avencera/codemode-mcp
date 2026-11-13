//! A spoke's own takeover endpoint: the hub's phones dial it to drive this
//! machine's browser sessions
//!
//! A spoke with a `browser` builtin binds an iroh endpoint of its own that
//! takes [`TAKEOVER_ALPN`] only, with an identity kept in
//! `<state_dir>/browser.key`, since a spoke has no Keychain. Every
//! `[hub] browser_report_secs` it reports the endpoint's id and addresses
//! to the hub, which lists it to its phones as a browser machine and
//! answers with its paired phones. Only those are let in, so the hub
//! vouches both ways: a phone dials the endpoint the hub listed, and the
//! spoke admits the phones the hub paired
//!
//! Until the hub first answers, no phone is let in. An answer stands for
//! [`LAPSE_REPORTS`] reports: once that many go unanswered, as while the
//! hub is down or no longer trusts this spoke, no phone is let in until it
//! answers again. A phone the hub stops vouching for, unpaired there or
//! lapsed, has its takeovers here closed at once, not only its next dial
//! refused

use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Weak},
    time::Duration,
};

use companion_wire::takeover::TAKEOVER_ALPN;
use iroh::{Endpoint, EndpointId, endpoint::Connection};
use tokio::{sync::watch, time::Instant};

use super::{
    HANDSHAKE_TIMEOUT, Role, bind_endpoint,
    identity::load_or_create,
    takeover::{TakeoverHost, TakeoverPhone, serve_takeover},
};
use crate::hub::{BrowserEndpoint, client::HubClient};

/// How many reports may go unanswered before the hub's last answer no
/// longer lets any phone in
const LAPSE_REPORTS: u32 = 3;

/// File in the state directory holding the endpoint's key
pub const IDENTITY_FILE: &str = "browser.key";

/// Most direct addresses reported; a machine with more is dialed through
/// the first ones or its relay
const MAX_ADDRS: usize = 16;

/// The phones the hub vouched for in its last answer, and until when that
/// answer stands
#[derive(Debug, Clone, Default)]
struct Vouched {
    phones: Vec<TakeoverPhone>,
    /// `None` until the hub first answers
    until: Option<Instant>,
}

impl Vouched {
    /// The phone `id`, while the hub's answer stands and names it
    fn phone(&self, id: EndpointId, now: Instant) -> Option<&TakeoverPhone> {
        let standing = self.until.is_some_and(|until| now < until);

        self.phones.iter().find(|phone| standing && phone.id == id)
    }
}

/// The endpoint, the phones it lets in and the browser it serves them
pub struct SpokeTakeovers {
    endpoint: Endpoint,
    /// The hub's paired phones, as of its last answer; every takeover
    /// watches it, so a phone the hub stops vouching for is cut off
    vouched: watch::Sender<Vouched>,
    /// How often the hub is asked for its phones
    every: Duration,
    /// Held weakly, since the browser outlives no gateway
    host: Weak<dyn TakeoverHost>,
}

impl SpokeTakeovers {
    /// Binds the endpoint with the key in `state_dir`, on `listen` or any
    /// free port, with n0's relays and discovery when `discovery` is set,
    /// and serves `host`'s sessions to the phones the hub vouches for,
    /// asking it for them `every` so often
    pub async fn bind(
        state_dir: &Path,
        discovery: bool,
        listen: Option<SocketAddr>,
        every: Duration,
        host: Weak<dyn TakeoverHost>,
    ) -> Result<Arc<Self>, String> {
        let file = state_dir.join(IDENTITY_FILE);
        let key = load_or_create(Role::Gateway, Some(&file)).map_err(|error| error.to_string())?;
        let endpoint = bind_endpoint(Role::Gateway, key, discovery, listen).await?;
        endpoint.set_alpns(vec![TAKEOVER_ALPN.to_vec()]);
        // the id a `machine=` takeover link names this spoke by
        tracing::info!(id = %endpoint.id(), "Serving takeovers of this spoke's browser sessions");
        let takeovers = Arc::new(Self {
            endpoint: endpoint.clone(),
            vouched: watch::Sender::new(Vouched::default()),
            every,
            host,
        });

        let serving = Arc::downgrade(&takeovers);
        tokio::spawn(async move {
            // `None` once the endpoint is closed
            while let Some(incoming) = endpoint.accept().await {
                let Some(takeovers) = serving.upgrade() else {
                    return;
                };
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await {
                        Ok(Ok(connection)) => takeovers.connection(connection).await,
                        Ok(Err(error)) => tracing::debug!(%error, "takeover handshake failed"),
                        Err(_) => tracing::debug!("takeover handshake timed out"),
                    }
                });
            }
        });

        Ok(takeovers)
    }

    /// The endpoint as the hub lists it to the phones
    pub fn endpoint(&self) -> BrowserEndpoint {
        let addr = self.endpoint.addr();
        let mut addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        // a socket bound to one address, such as `browser_listen`, is
        // dialed there even before the interfaces are known
        for bound in self.endpoint.bound_sockets() {
            if !bound.ip().is_unspecified() && !addrs.contains(&bound) {
                addrs.push(bound);
            }
        }
        addrs.truncate(MAX_ADDRS);

        BrowserEndpoint {
            id: self.endpoint.id(),
            addrs,
            relay: addr.relay_urls().next().map(ToString::to_string),
        }
    }

    /// Lets in `phones` from now on, and only them, until
    /// [`LAPSE_REPORTS`] reports go unanswered; the takeovers of any other
    /// phone are closed
    fn vouch(&self, phones: Vec<TakeoverPhone>) {
        let until = Instant::now() + self.every * LAPSE_REPORTS;
        self.vouched.send_replace(Vouched {
            phones,
            until: Some(until),
        });
    }

    /// Reports the endpoint to `hub` once it trusts this spoke, and then
    /// every so often, taking in the phones it answers with, for as long as
    /// this endpoint lives
    pub async fn report_to(self: Arc<Self>, hub: Arc<HubClient>) {
        let every = self.every;
        let takeovers = Arc::downgrade(&self);
        drop(self);
        loop {
            hub.trusted().await;
            let Some(current) = takeovers.upgrade() else {
                return;
            };
            match hub.report_browser(&current.endpoint()).await {
                Ok(vouched) => current.vouch(vouched.phones),
                // the last answer lapses on its own
                Err(error) => tracing::debug!(%error, "could not report the browser endpoint"),
            }
            drop(current);
            tokio::time::sleep(every).await;
        }
    }

    /// Closes the endpoint, ending its takeovers and freeing its port
    pub async fn close(&self) {
        self.endpoint.close().await;
    }

    async fn connection(&self, connection: Connection) {
        if connection.alpn() != TAKEOVER_ALPN {
            connection.close(1_u32.into(), b"unexpected protocol");

            return;
        }
        let remote = connection.remote_id();
        let phone = self.vouched.borrow().phone(remote, Instant::now()).cloned();
        let Some(phone) = phone else {
            tracing::warn!(%remote, "refused a takeover from a phone the hub does not vouch for");
            connection.close(1_u32.into(), b"not paired");

            return;
        };

        // closing rather than dropping the takeover lets it put the page
        // back as the agent had it
        let cutting = tokio::spawn(close_when_unvouched(
            self.vouched.subscribe(),
            connection.clone(),
            phone.clone(),
        ));
        serve_takeover(connection, phone, self.host.upgrade(), Vec::new()).await;
        cutting.abort();
    }
}

/// Closes `connection` once the hub's vouching no longer lets `phone` in:
/// a newer answer leaves it out, or the last answer lapses
async fn close_when_unvouched(
    mut vouched: watch::Receiver<Vouched>,
    connection: Connection,
    phone: TakeoverPhone,
) {
    loop {
        let until = {
            let current = vouched.borrow_and_update();
            current.phone(phone.id, Instant::now()).and(current.until)
        };
        let Some(until) = until else {
            break;
        };
        tokio::select! {
            changed = vouched.changed() => {
                // the endpoint is going away, which ends the takeover anyway
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep_until(until) => {}
        }
    }

    tracing::warn!(phone = %phone.name, "ended the takeover of a phone the hub no longer vouches for");
    connection.close(1_u32.into(), b"not paired");
}
