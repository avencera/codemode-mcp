//! RFC 6238 one-time codes, computed in the daemon from the seed 1Password
//! keeps for a login, so neither the seed nor the code reaches an agent
//!
//! 1Password answers a one-time-password field either as an
//! `otpauth://totp/...` URI or as the bare base32 secret; both are read
//! here. No error text carries any part of the seed

use std::time::{SystemTime, UNIX_EPOCH};

use totp_hmac::{Hmac, Mac, digest::KeyInit};
use totp_sha1::Sha1;
use totp_sha2::{Sha256, Sha512};

/// The hash the code is computed with
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A time-based one-time password generator
#[derive(Clone)]
pub struct Totp {
    secret: Vec<u8>,
    /// The secret as base32 text, without spaces or padding, for the
    /// redactor
    encoded: String,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

/// Why a seed could not be read; the text never quotes it
#[derive(Debug, Clone, thiserror::Error)]
#[error("the one-time password in 1Password {0}")]
pub struct TotpError(&'static str);

impl std::fmt::Debug for Totp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl Totp {
    /// Reads an `otpauth://totp/...` URI or a bare base32 secret
    pub fn parse(text: &str) -> Result<Self, TotpError> {
        let text = text.trim();
        if !text.to_ascii_lowercase().starts_with("otpauth:") {
            return Self::new(text, Algorithm::Sha1, 6, 30);
        }

        let url = reqwest::Url::parse(text)
            .map_err(|_| TotpError("is not a valid otpauth:// address"))?;
        if url.host_str().map(str::to_ascii_lowercase).as_deref() != Some("totp") {
            return Err(TotpError(
                "is not time-based (otpauth://totp/), so no code can be computed from it",
            ));
        }
        let mut secret = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        for (key, value) in url.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value.into_owned()),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => {
                            return Err(TotpError(
                                "names an algorithm other than SHA1, SHA256 or SHA512",
                            ));
                        }
                    };
                }
                "digits" => {
                    digits = match value.as_ref() {
                        "6" => 6,
                        "8" => 8,
                        _ => return Err(TotpError("asks for a code that is not 6 or 8 digits")),
                    };
                }
                "period" => {
                    period = value
                        .parse::<u64>()
                        .ok()
                        .filter(|period| (1..=3600).contains(period))
                        .ok_or(TotpError("has a period that is not 1 to 3600 seconds"))?;
                }
                _ => {}
            }
        }
        let secret = secret.ok_or(TotpError("has no secret"))?;

        Self::new(&secret, algorithm, digits, period)
    }

    fn new(
        secret: &str,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self, TotpError> {
        // 1Password and many sites show the secret in groups of four
        let encoded: String = secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let secret = base32(&encoded).ok_or(TotpError("is not a base32 secret"))?;
        if secret.is_empty() {
            return Err(TotpError("has an empty secret"));
        }

        Ok(Self {
            secret,
            encoded,
            algorithm,
            digits,
            period,
        })
    }

    /// The secret as base32 text, which other servers' results must not
    /// show either
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// The code for the current time
    pub fn now(&self) -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());

        self.at(seconds)
    }

    /// The code for `seconds` since the Unix epoch
    pub fn at(&self, seconds: u64) -> String {
        let counter = (seconds / self.period).to_be_bytes();
        let digest = match self.algorithm {
            Algorithm::Sha1 => hmac::<Hmac<Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.secret, &counter),
        };
        // RFC 4226 dynamic truncation: the low nibble of the last byte picks
        // four bytes, read without their top bit
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let word = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let code = word % 10_u32.pow(self.digits);

        format!("{code:0width$}", width = self.digits as usize)
    }
}

fn hmac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length, so this never fails
    let mut mac = <M as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(message);

    mac.finalize().into_bytes().to_vec()
}

/// Decodes RFC 4648 base32 without padding; trailing bits that do not
/// fill a byte are dropped, as authenticator apps do
fn base32(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Totp, TotpError};

    /// The RFC 6238 appendix B seeds: the ASCII digits repeated to the
    /// hash's block-friendly length, in base32
    const SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn codes_match_the_rfc_6238_vectors() -> Result<(), TotpError> {
        let uri = |secret: &str, algorithm: &str| {
            format!("otpauth://totp/RFC:test?secret={secret}&algorithm={algorithm}&digits=8")
        };
        let vectors = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let sha1 = Totp::parse(&uri(SHA1, "SHA1"))?;
        let sha256 = Totp::parse(&uri(SHA256, "SHA256"))?;
        let sha512 = Totp::parse(&uri(SHA512, "SHA512"))?;
        for (time, one, two_five_six, five_twelve) in vectors {
            assert_eq!(sha1.at(time), one, "SHA1 at {time}");
            assert_eq!(sha256.at(time), two_five_six, "SHA256 at {time}");
            assert_eq!(sha512.at(time), five_twelve, "SHA512 at {time}");
        }

        Ok(())
    }

    #[test]
    fn a_bare_secret_gives_six_digits_every_thirty_seconds() -> Result<(), TotpError> {
        // the SHA1 vector at 59 s, cut to its last six digits
        let bare = Totp::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")?;
        assert_eq!(bare.at(59), "287082");
        assert_eq!(bare.at(30), bare.at(59));
        assert_eq!(bare.encoded(), SHA1);

        for refused in [
            "otpauth://hotp/x?secret=GEZDGNBV&counter=1",
            "otpauth://totp/x?secret=GEZDGNBV&digits=7",
            "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
            "otpauth://totp/x?secret=GEZDGNBV&period=0",
            "otpauth://totp/x?issuer=GitHub",
            "not base32!",
            "",
        ] {
            let Err(error) = Totp::parse(refused) else {
                panic!("{refused} was read as a seed");
            };
            assert!(!error.to_string().contains("GEZDGNBV"), "{error}");
        }

        Ok(())
    }
}
