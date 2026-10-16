//! Pairing with a scanned invite: a new iroh key and Secure Enclave key,
//! a registration over the pairing protocol, then the gateway's check
//!
//! It runs as one spawned task that reports to the app actor; nothing else
//! happens on the pairing connection, so an actor would only add mailboxes

use std::{sync::Arc, time::Duration};

use companion_wire::{
    ASK_TIMEOUT, PAIR_ALPN,
    mobile::{PhoneRegistration, PushToken, SealKey},
    ticket::{INVITE_PREFIX, InviteTicket},
    wire::{PairCheck, PairRequest, PairResponse, Registration},
};
use iroh::{EndpointAddr, TransportAddr};
use ractor::ActorRef;

use crate::{
    app::AppMsg,
    ffi::Platform,
    net,
    record::{GatewayRecord, create_key},
};

/// How long the gateway's check may take: its read waits up to
/// [`ASK_TIMEOUT`] for the owner, plus the dial back
const CHECK_TIMEOUT: Duration = ASK_TIMEOUT.saturating_add(Duration::from_secs(30));

/// The invite ticket in scanned text: the ticket alone, or the install
/// command `companion invite` prints and shows as a QR code
pub fn find_ticket(scanned: &str) -> Result<InviteTicket, String> {
    let ticket = scanned
        .split(|character: char| character.is_whitespace() || "\"'`".contains(character))
        .find(|word| word.starts_with(INVITE_PREFIX))
        .ok_or("this QR code holds no codemode-mcp invite")?;

    InviteTicket::decode(ticket).map_err(|error| error.to_string())
}

/// Registers with the gateway in `ticket`, then waits for its check
pub async fn run(
    platform: Arc<dyn Platform>,
    ticket: InviteTicket,
    push: Option<PushToken>,
    app: ActorRef<AppMsg>,
) {
    let (endpoint, connection, record) = match register(Arc::clone(&platform), &ticket, push).await
    {
        Ok(registered) => registered,
        Err(message) => {
            let _ = app.cast(AppMsg::Registered(Err(message)));

            return;
        }
    };
    let _ = app.cast(AppMsg::Registered(Ok(record)));

    // the gateway reads one reference through this phone, which arrives as
    // an ordinary read once the connection actor is up
    let checked = tokio::time::timeout(
        CHECK_TIMEOUT,
        net::ask::<PairResponse>(&connection, &PairRequest::Check),
    )
    .await;
    let checked = match checked {
        Ok(Ok(PairResponse::Checked(check))) => Ok(check),
        Ok(Ok(PairResponse::Refused { message })) => Err(message),
        Ok(Ok(other)) => Err(format!("unexpected answer: {other:?}")),
        Ok(Err(error)) => Err(error),
        Err(_) => Err("the gateway's check did not finish in time".to_owned()),
    };
    let _ = app.cast(AppMsg::Checked(checked));

    connection.close(0_u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await;
}

async fn register(
    platform: Arc<dyn Platform>,
    ticket: &InviteTicket,
    push: Option<PushToken>,
) -> Result<(iroh::Endpoint, iroh::endpoint::Connection, GatewayRecord), String> {
    // fresh keys for every pairing, so a phone paired before has a dead id
    let keys = {
        let platform = Arc::clone(&platform);
        tokio::task::spawn_blocking(move || {
            GatewayRecord::forget(platform.as_ref());
            let key = create_key(platform.as_ref())?;
            let seal_key = platform.create_seal_key()?;

            Ok::<_, crate::ffi::PlatformError>((key, seal_key, platform.device_name()))
        })
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?
    };
    let (key, seal_key, device_name) = keys;
    let seal_key = SealKey::from_bytes(&seal_key)
        .ok_or("the Secure Enclave key is not an uncompressed P-256 point")?;

    let id = key.public();
    let endpoint = net::bind(key, ticket.addrs.is_empty()).await?;
    let address = EndpointAddr::from_parts(
        ticket.gateway,
        ticket.addrs.iter().copied().map(TransportAddr::Ip),
    );
    let connection = tokio::time::timeout(net::DIAL_TIMEOUT, endpoint.connect(address, PAIR_ALPN))
        .await
        .map_err(|_| "the gateway did not answer; is its invite still open?".to_owned())?
        .map_err(|error| format!("cannot reach the gateway: {error}"))?;

    let registration = PairRequest::Register(Box::new(Registration {
        secret: ticket.secret.to_hex(),
        id,
        name: device_name,
        addrs: Vec::new(),
        phone: Some(PhoneRegistration { seal_key, push }),
    }));
    let registered = match net::ask::<PairResponse>(&connection, &registration).await? {
        PairResponse::Registered(registered) => registered,
        PairResponse::Refused { message } => return Err(message),
        other => return Err(format!("unexpected answer: {other:?}")),
    };

    let record = GatewayRecord {
        id: ticket.gateway,
        name: registered.gateway_name,
        phone_name: registered.name,
        allow: registered.references,
        addrs: ticket.addrs.clone(),
    };
    let saved = {
        let platform = Arc::clone(&platform);
        let record = record.clone();
        tokio::task::spawn_blocking(move || record.save(platform.as_ref()))
            .await
            .map_err(|error| error.to_string())?
    };
    saved.map_err(|error| format!("cannot keep the pairing: {error}"))?;

    Ok((endpoint, connection, record))
}

/// What the check found, for the pairing screen
pub fn describe(check: &PairCheck) -> String {
    match check {
        PairCheck::Read { reference, bytes } => {
            format!("Paired. The gateway read {reference} ({bytes} bytes) through this phone.")
        }
        PairCheck::Failed { reference, message } => {
            format!("Paired, but reading {reference} through this phone failed: {message}")
        }
        PairCheck::Skipped => "Paired. The gateway uses no op:// reference yet.".to_owned(),
        PairCheck::NothingSealed => "Paired. This phone can answer a reference once the gateway \
             or a companion Mac has read it."
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use companion_wire::ticket::{InviteSecret, InviteTicket};

    use super::find_ticket;

    #[test]
    fn the_ticket_is_found_in_the_install_command() -> Result<(), String> {
        let ticket = InviteTicket {
            gateway: iroh::SecretKey::generate().public(),
            secret: InviteSecret::generate(),
            addrs: Vec::new(),
        };
        let encoded = ticket.encode();
        let command = format!(
            "curl -LSfs https://github.com/x/y/releases/latest/download/install.sh | sh -s -- --pair {encoded}"
        );

        assert_eq!(find_ticket(&command)?, ticket);
        assert_eq!(find_ticket(&encoded)?, ticket);
        assert!(find_ticket("https://example.com").is_err());

        Ok(())
    }
}
