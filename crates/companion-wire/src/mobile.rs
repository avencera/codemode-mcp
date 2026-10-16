//! What a phone and the gateway send each other on [`crate::MOBILE_ALPN`]
//!
//! A suspended iOS app cannot accept connections, so the roles of the Mac
//! companion are turned around: the gateway wakes the phone with a push
//! naming the request, and the phone dials the gateway. The gateway then
//! opens one stream per pending read on that connection, carrying a
//! [`PhoneRead`], and the phone answers each with a
//! [`CompanionResponse`](crate::wire::CompanionResponse). The gateway stops
//! a stream whose read it no longer wants (another source answered first, or
//! it expired), which takes the phone's prompt down. Requests of the phone's
//! own ([`PhoneRequest`]) go on streams the phone opens
//!
//! The phone holds no values: the gateway seals each value it reads to the
//! phone's Secure Enclave key and keeps only the ciphertext, which it sends
//! with the read. The seal's `info` binds the gateway and the reference (see
//! [`seal_info`]), so a gateway cannot show one reference in the prompt and
//! have the phone open another's value. A read the gateway holds no copy of
//! comes without one, and the owner enters the value on the phone

use base64::{Engine, engine::general_purpose::STANDARD};
use iroh_base::EndpointId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Bytes of a request id
const REQUEST_ID_BYTES: usize = 16;

/// Bytes of an uncompressed SEC1 P-256 public key: the `0x04` tag and two
/// 32-byte coordinates, CryptoKit's `x963Representation`
pub const SEAL_KEY_BYTES: usize = 65;

/// Start of every seal's `info`; the digit is the format version
const SEAL_INFO_PREFIX: &str = "codemode-mcp/seal/1";

/// Names one read the gateway waits on; the push that wakes the phone and the
/// stream that carries the read hold the same id
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RequestId(String);

impl RequestId {
    /// A fresh random id
    pub fn generate() -> Self {
        Self(hex::encode(rand::random::<[u8; REQUEST_ID_BYTES]>()))
    }

    /// The id as lowercase hex
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RequestId {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let well_formed = text.len() == REQUEST_ID_BYTES * 2
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));

        if well_formed {
            Ok(Self(text))
        } else {
            Err("a request id is 32 lowercase hex digits")
        }
    }
}

impl From<RequestId> for String {
    fn from(id: RequestId) -> Self {
        id.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "RequestId({})", self.0)
    }
}

/// A phone's public P-256 key, which the gateway seals values to; the private
/// half never leaves the phone's Secure Enclave
#[derive(Clone, PartialEq, Eq)]
pub struct SealKey([u8; SEAL_KEY_BYTES]);

impl SealKey {
    /// Reads an uncompressed SEC1 point; `None` for any other length or tag.
    /// Whether the point is on the curve is checked when sealing
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; SEAL_KEY_BYTES] = bytes.try_into().ok()?;

        (bytes[0] == 0x04).then_some(Self(bytes))
    }

    /// The uncompressed SEC1 point
    pub fn as_bytes(&self) -> &[u8; SEAL_KEY_BYTES] {
        &self.0
    }

    /// The key as standard base64, as configs and the wire carry it
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Reads [`SealKey::to_base64`]
    pub fn from_base64(text: &str) -> Option<Self> {
        Self::from_bytes(&STANDARD.decode(text.trim()).ok()?)
    }
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SealKey({})", hex::encode(&self.0[1..9]))
    }
}

impl Serialize for SealKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for SealKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        Self::from_base64(&text)
            .ok_or_else(|| D::Error::custom("a seal key is a base64 uncompressed P-256 point"))
    }
}

/// A value sealed to a phone's [`SealKey`] with HPKE base mode,
/// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// The encapsulated key
    #[serde(with = "base64_bytes")]
    pub enc: Vec<u8>,
    /// The value, encrypted, with its tag
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for Sealed {
    // even the ciphertext stays out of logs; its length says enough
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Sealed({} bytes)", self.ciphertext.len())
    }
}

/// The `info` every seal of `reference` for `gateway` is made with; the
/// phone builds it from the reference it shows, so a ciphertext sent under
/// another reference does not open
pub fn seal_info(gateway: &EndpointId, reference: &str) -> Vec<u8> {
    format!(
        "{SEAL_INFO_PREFIX}\n{}\n{reference}",
        hex::encode(gateway.as_bytes())
    )
    .into_bytes()
}

/// One read the gateway asks a phone to approve, on a stream the gateway
/// opens over the phone's connection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneRead {
    /// The id the push named
    pub id: RequestId,
    /// The `op://` reference, shown in the prompt and matched exactly
    /// against the phone's allow list
    pub reference: String,
    /// The value, sealed to this phone; `None` when the gateway has no copy
    /// yet, so the owner pastes or fills it in
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<Sealed>,
    /// Milliseconds until the gateway gives up on this read
    pub expires_in_ms: u64,
}

/// Which APNs environment a push token belongs to: a build installed from
/// Xcode registers with the sandbox, a TestFlight or App Store build with
/// production
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushEnvironment {
    /// `api.sandbox.push.apple.com`
    Development,
    /// `api.push.apple.com`
    Production,
}

/// Where the gateway sends the pushes that wake a phone
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken {
    /// The APNs device token, as lowercase hex
    pub token: String,
    /// Which APNs environment issued it
    pub environment: PushEnvironment,
}

impl std::fmt::Debug for PushToken {
    // a token lets anyone holding the APNs key push to the phone
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushToken")
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// What a phone adds to its [`Registration`](crate::wire::Registration)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneRegistration {
    /// The Secure Enclave key values are sealed to
    pub seal_key: SealKey,
    /// Where to push; `None` when the owner turned notifications off, so the
    /// phone answers only while its app is open
    #[serde(default)]
    pub push: Option<PushToken>,
}

/// What a phone asks the gateway, on a stream the phone opens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneRequest {
    /// Push to this token from now on; `None` stops pushes
    PushToken(Option<PushToken>),
    /// Stop asking this phone and drop the values sealed to it
    Unpair,
}

/// The gateway's answer to a [`PhoneRequest`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneResponse {
    /// Done
    Done,
    /// Nothing was done
    Refused {
        /// Why
        message: String,
    },
}

/// Keys of the custom data in the push that wakes a phone; the push carries
/// the request id, the reference and the gateway's name, never a value
pub mod push_keys {
    /// The [`RequestId`](super::RequestId), as hex
    pub const REQUEST: &str = "request";
    /// The `op://` reference
    pub const REFERENCE: &str = "reference";
    /// The gateway Mac's short name
    pub const GATEWAY: &str = "gateway";
    /// When the gateway stops waiting for the answer, in Unix milliseconds;
    /// a push tapped later names a read that is already gone
    pub const EXPIRES: &str = "expires";
}

mod base64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;

        STANDARD.decode(text).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestId, SealKey};

    #[test]
    fn request_ids_and_seal_keys_refuse_malformed_text() {
        let id = RequestId::generate();
        assert_eq!(RequestId::try_from(id.to_string()), Ok(id.clone()));
        assert!(RequestId::try_from(id.to_string().to_uppercase()).is_err());
        assert!(RequestId::try_from("00".to_owned()).is_err());

        let mut point = [7_u8; 65];
        assert!(
            SealKey::from_bytes(&point).is_none(),
            "compressed or odd tags are refused"
        );
        point[0] = 0x04;
        let key = SealKey::from_bytes(&point);
        assert_eq!(
            key.as_ref()
                .and_then(|key| SealKey::from_base64(&key.to_base64())),
            key
        );
        assert!(SealKey::from_bytes(&point[..64]).is_none());
    }
}
