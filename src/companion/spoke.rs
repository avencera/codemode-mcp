//! A spoke's own takeover endpoint: the hub's phones dial it to drive this
//! machine's browser sessions
//!
//! A spoke with a `browser` builtin binds an iroh endpoint of its own that
//! takes [`TAKEOVER_ALPN`] only, with an identity kept in
//! `<state_dir>/browser.key`, since a spoke has no Keychain. Every
//! [`REPORT_EVERY`] it reports the endpoint's id and addresses to the hub,
//! which lists it to its phones as a browser machine and answers with its
//! paired phones. Only those are let in, so the hub vouches both ways: a
//! phone dials the endpoint the hub listed, and the spoke admits the phones
//! the hub paired. Until the hub first answers, no phone is

use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, PoisonError, RwLock, Weak},
    time::Duration,
};

use companion_wire::takeover::TAKEOVER_ALPN;
use iroh::{Endpoint, endpoint::Connection};

use super::{
    HANDSHAKE_TIMEOUT, Role, bind_endpoint,
    identity::load_or_create,
    takeover::{TakeoverHost, TakeoverPhone, serve_takeover},
};
use crate::hub::{BrowserEndpoint, client::HubClient};

/// How often a spoke reports its takeover endpoint to the hub, which also
/// brings it the hub's phones
pub const REPORT_EVERY: Duration = Duration::from_secs(30);

/// File in the state directory holding the endpoint's key
pub const IDENTITY_FILE: &str = "browser.key";

/// Most direct addresses reported; a machine with more is dialed through
/// the first ones or its relay
const MAX_ADDRS: usize = 16;

/// The endpoint, the phones it lets in and the browser it serves them
pub struct SpokeTakeovers {
    endpoint: Endpoint,
    /// The hub's paired phones, as of its last answer
    phones: RwLock<Vec<TakeoverPhone>>,
    /// Held weakly, since the browser outlives no gateway
    host: Weak<dyn TakeoverHost>,
}

impl SpokeTakeovers {
    /// Binds the endpoint with the key in `state_dir`, on `listen` or any
    /// free port, with n0's relays and discovery when `discovery` is set,
    /// and serves `host`'s sessions to the phones the hub vouches for
    pub async fn bind(
        state_dir: &Path,
        discovery: bool,
        listen: Option<SocketAddr>,
        host: Weak<dyn TakeoverHost>,
    ) -> Result<Arc<Self>, String> {
        let file = state_dir.join(IDENTITY_FILE);
        let key = load_or_create(Role::Gateway, Some(&file)).map_err(|error| error.to_string())?;
        let endpoint = bind_endpoint(Role::Gateway, key, discovery, listen).await?;
        endpoint.set_alpns(vec![TAKEOVER_ALPN.to_vec()]);
        let takeovers = Arc::new(Self {
            endpoint: endpoint.clone(),
            phones: RwLock::default(),
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

    /// Lets in `phones` from now on, and only them
    pub fn vouch(&self, phones: Vec<TakeoverPhone>) {
        *self.phones.write().unwrap_or_else(PoisonError::into_inner) = phones;
    }

    /// Reports the endpoint to `hub` once it trusts this spoke, and then
    /// every [`REPORT_EVERY`], taking in the phones it answers with, for as
    /// long as this endpoint lives
    pub async fn report_to(self: Arc<Self>, hub: Arc<HubClient>) {
        let takeovers = Arc::downgrade(&self);
        drop(self);
        loop {
            hub.trusted().await;
            let Some(current) = takeovers.upgrade() else {
                return;
            };
            match hub.report_browser(&current.endpoint()).await {
                Ok(vouched) => current.vouch(vouched.phones),
                Err(error) => tracing::debug!(%error, "could not report the browser endpoint"),
            }
            drop(current);
            tokio::time::sleep(REPORT_EVERY).await;
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
        let phone = self
            .phones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|phone| phone.id == remote)
            .cloned();
        let Some(phone) = phone else {
            tracing::warn!(%remote, "refused a takeover from a phone the hub does not vouch for");
            connection.close(1_u32.into(), b"not paired");

            return;
        };

        serve_takeover(connection, phone, self.host.upgrade(), Vec::new()).await;
    }
}
