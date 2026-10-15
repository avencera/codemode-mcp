//! The new companion's side of an invite: registering with the gateway,
//! then asking it to read one reference through this Mac once the agent
//! runs

use std::{net::SocketAddr, time::Duration};

use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use super::{
    ASK_TIMEOUT, Hangup, InviteTicket, PAIR_ALPN, PairCheck, PairRequest, PairResponse, Registered,
    Registration, Role, ask, bind_endpoint,
};

/// How long to look for the gateway
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the check may take: the gateway keeps dialing the new agent for
/// up to a minute, then the owner answers Touch ID
const CHECK_TIMEOUT: Duration = ASK_TIMEOUT.saturating_add(Duration::from_secs(90));

/// Why registering or checking failed
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    /// The gateway could not be reached
    #[error("cannot reach the gateway: {0}")]
    Unreachable(String),
    /// The exchange broke off or the answer was unreadable
    #[error("the gateway sent no usable answer: {0}")]
    Exchange(String),
    /// The gateway refused
    #[error("the gateway refused: {0}")]
    Refused(String),
}

/// What registering needs
#[derive(Debug)]
pub struct Joining<'a> {
    /// The invite
    pub ticket: &'a InviteTicket,
    /// The endpoint id this Mac's companion agent answers on
    pub id: EndpointId,
    /// This Mac's short host name
    pub name: String,
    /// Where the agent listens, for a gateway with discovery off; empty
    /// means this Mac's IPv4 addresses at `port`
    pub addrs: Vec<SocketAddr>,
    /// The agent's fixed port, usually [`super::DIRECT_PORT`]
    pub port: u16,
}

/// A registration the gateway accepted, with the connection kept open for
/// the check
pub struct Joined {
    endpoint: Endpoint,
    connection: Hangup,
    registered: Registered,
}

impl Joined {
    /// What the companion's config needs
    pub fn registered(&self) -> &Registered {
        &self.registered
    }

    /// Hangs up without a check
    pub async fn close(self) {
        drop(self.connection);
        self.endpoint.close().await;
    }

    /// Asks the gateway to read one reference through this Mac, which shows
    /// a Touch ID prompt here; the answer never holds the value
    pub async fn check(self) -> Result<PairCheck, JoinError> {
        let response = tokio::time::timeout(
            CHECK_TIMEOUT,
            ask::<PairResponse>(&self.connection.0, &PairRequest::Check),
        )
        .await
        .unwrap_or_else(|_| Err(format!("no answer within {CHECK_TIMEOUT:?}")));
        drop(self.connection);
        self.endpoint.close().await;

        match response.map_err(JoinError::Exchange)? {
            PairResponse::Checked(check) => Ok(check),
            PairResponse::Refused { message } => Err(JoinError::Refused(message)),
            PairResponse::Registered(_) => Err(JoinError::Exchange("unexpected answer".into())),
        }
    }
}

/// Registers this Mac with the gateway of `joining.ticket`
///
/// The connection comes from a throwaway key, not the companion's: that key
/// belongs to the agent, which starts before the check, and two endpoints
/// with one id would take each other's relay traffic. The invite's secret is
/// what authorizes the registration; the id is not proven then, but every
/// read the gateway makes dials it, which only the holder of its key answers
pub async fn join(joining: Joining<'_>) -> Result<Joined, JoinError> {
    let ticket = joining.ticket;
    let discovery = ticket.addrs.is_empty();
    let endpoint = bind_endpoint(Role::Gateway, SecretKey::generate(), discovery, None)
        .await
        .map_err(JoinError::Unreachable)?;
    let addrs = if discovery || !joining.addrs.is_empty() {
        joining.addrs
    } else {
        // IPv4 only: the agent's `listen` fixes the port of its IPv4 socket,
        // while its IPv6 socket keeps a random one
        endpoint
            .addr()
            .ip_addrs()
            .filter(|addr| addr.is_ipv4())
            .map(|addr| SocketAddr::new(addr.ip(), joining.port))
            .collect()
    };

    let address = EndpointAddr::from_parts(
        ticket.gateway,
        ticket.addrs.iter().copied().map(TransportAddr::Ip),
    );
    let connected = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(address, PAIR_ALPN))
        .await
        .map_err(|_| JoinError::Unreachable(format!("no answer within {CONNECT_TIMEOUT:?}")))
        .and_then(|connected| connected.map_err(|error| JoinError::Unreachable(error.to_string())));
    let connection = match connected {
        Ok(connection) => Hangup(connection),
        Err(error) => {
            endpoint.close().await;

            return Err(error);
        }
    };

    let registration = PairRequest::Register(Registration {
        secret: ticket.secret.to_hex(),
        id: joining.id,
        name: joining.name,
        addrs,
    });
    let response = ask::<PairResponse>(&connection.0, &registration).await;
    let registered = match response {
        Ok(PairResponse::Registered(registered)) => Ok(registered),
        Ok(PairResponse::Refused { message }) => Err(JoinError::Refused(message)),
        Ok(PairResponse::Checked(_)) => Err(JoinError::Exchange("unexpected answer".into())),
        Err(detail) => Err(JoinError::Exchange(detail)),
    };
    match registered {
        Ok(registered) => Ok(Joined {
            endpoint,
            connection,
            registered,
        }),
        Err(error) => {
            drop(connection);
            endpoint.close().await;

            Err(error)
        }
    }
}
