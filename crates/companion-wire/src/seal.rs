//! Sealing values to a phone's P-256 key, and opening them with a software
//! key where there is no Secure Enclave (the tests' fake phones)
//!
//! The suite is HPKE base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256
//! and AES-256-GCM, which CryptoKit calls `P256_SHA256_AES_GCM_256` and
//! supports for Secure Enclave keys

use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    kem::DhP256HkdfSha256,
};
use iroh_base::EndpointId;

use crate::mobile::{SealKey, Sealed, seal_info};

type Kem = DhP256HkdfSha256;

/// Why a value could not be sealed or opened; never holds the value
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The key is not a point on P-256
    #[error("the seal key is not a valid P-256 public key")]
    Key,
    /// HPKE failed: a wrong key, a tampered ciphertext or another `info`
    #[error("the value could not be sealed or opened")]
    Hpke,
}

/// Seals `value` to `key`, bound to `gateway` and `reference`
pub fn seal(
    key: &SealKey,
    gateway: &EndpointId,
    reference: &str,
    value: &[u8],
) -> Result<Sealed, SealError> {
    let recipient =
        <Kem as hpke::Kem>::PublicKey::from_bytes(key.as_bytes()).map_err(|_| SealError::Key)?;
    let (enc, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient,
        &seal_info(gateway, reference),
        value,
        &[],
    )
    .map_err(|_| SealError::Hpke)?;

    Ok(Sealed {
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    })
}

/// A P-256 private key held in memory, standing in for a Secure Enclave key
pub struct SoftwareKey(<Kem as hpke::Kem>::PrivateKey, SealKey);

impl SoftwareKey {
    /// A fresh random key
    pub fn generate() -> Result<Self, SealError> {
        let (private, public) = Kem::gen_keypair();
        let public = SealKey::from_bytes(&public.to_bytes()).ok_or(SealError::Key)?;

        Ok(Self(private, public))
    }

    /// The public half, as a phone registers it
    pub fn public(&self) -> &SealKey {
        &self.1
    }

    /// Opens what [`seal`] sealed to this key for `gateway` and `reference`
    pub fn open(
        &self,
        gateway: &EndpointId,
        reference: &str,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, SealError> {
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc)
            .map_err(|_| SealError::Hpke)?;

        hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &self.0,
            &enc,
            &seal_info(gateway, reference),
            &sealed.ciphertext,
            &[],
        )
        .map_err(|_| SealError::Hpke)
    }
}

impl std::fmt::Debug for SoftwareKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("SoftwareKey").field(&self.1).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{SealError, SoftwareKey, seal};

    #[test]
    fn a_seal_opens_only_for_its_gateway_and_reference() -> Result<(), SealError> {
        let gateway = iroh_base::SecretKey::from_bytes(&[1; 32]).public();
        let other_gateway = iroh_base::SecretKey::from_bytes(&[2; 32]).public();
        let key = SoftwareKey::generate()?;
        let sealed = seal(key.public(), &gateway, "op://Dev/a/credential", b"hunter22")?;

        assert_eq!(
            key.open(&gateway, "op://Dev/a/credential", &sealed)?,
            b"hunter22"
        );
        assert!(key.open(&gateway, "op://Dev/b/credential", &sealed).is_err());
        assert!(
            key.open(&other_gateway, "op://Dev/a/credential", &sealed)
                .is_err()
        );
        assert!(
            SoftwareKey::generate()?
                .open(&gateway, "op://Dev/a/credential", &sealed)
                .is_err()
        );

        Ok(())
    }
}
