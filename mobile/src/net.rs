//! iroh plumbing shared by pairing and the connection actor

use std::time::Duration;

use companion_wire::MAX_BODY_BYTES;
use iroh::{
    Endpoint, SecretKey,
    endpoint::{Connection, presets},
};
use serde::{Serialize, de::DeserializeOwned};

/// How long one dial may take before it counts as failed
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// An endpoint as `key` that only dials: the phone accepts nothing
///
/// With `discovery` it uses n0's relays and DNS, so it finds the gateway by
/// id alone, also off the home network; without, it reaches only the
/// addresses the invite carried
pub async fn bind(key: SecretKey, discovery: bool) -> Result<Endpoint, String> {
    let builder = if discovery {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::Minimal)
    };

    builder
        .secret_key(key)
        .bind()
        .await
        .map_err(|error| format!("cannot start iroh: {error}"))
}

/// Sends `request` on a new stream and reads the one answer
pub async fn ask<R: DeserializeOwned>(
    connection: &Connection,
    request: &impl Serialize,
) -> Result<R, String> {
    let request = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(&request)
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    let body = receive
        .read_to_end(MAX_BODY_BYTES)
        .await
        .map_err(|error| error.to_string())?;

    serde_json::from_slice(&body).map_err(|error| format!("malformed answer: {error}"))
}
