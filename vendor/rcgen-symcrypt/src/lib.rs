//! A SymCrypt-backed cryptography provider for [`rcgen`].
//!
//! [`default_provider`] supplies key generation and loading, SHA-2 hashing, signing, and
//! certificate signing request verification without enabling rcgen's Ring or AWS-LC backends.
//! SymCrypt is the only cryptographic implementation used by this crate; the RustCrypto format
//! crates are used only to parse and encode standard DER key and signature containers.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::Display;

use der::Decode;
use rcgen::crypto::{CryptoProvider, HashAlgorithm, HashOutput};
use rcgen::{
    Error, KeyPair, RsaKeySize, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
    PKCS_ECDSA_P521_SHA256, PKCS_ECDSA_P521_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_RSA_SHA256,
    PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use rustls_pki_types::PrivateKeyDer;
use symcrypt::hash::{self, HashAlgorithm as SymCryptHashAlgorithm};

mod ec;
mod rsa;

static SYMCRYPT_PROVIDER: SymCryptProvider = SymCryptProvider;

/// Return an rcgen [`CryptoProvider`] backed entirely by SymCrypt.
pub fn default_provider() -> &'static dyn CryptoProvider {
    &SYMCRYPT_PROVIDER
}

/// Implements rcgen's cryptographic provider operations with SymCrypt.
///
/// Most users should obtain a complete provider with [`default_provider`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SymCryptProvider;

impl CryptoProvider for SymCryptProvider {
    fn hash(&self, algorithm: HashAlgorithm, input: &[u8]) -> HashOutput {
        match algorithm {
            HashAlgorithm::Sha256 => HashOutput::new(&hash::sha256(input)),
            HashAlgorithm::Sha384 => HashOutput::new(&hash::sha384(input)),
            HashAlgorithm::Sha512 => HashOutput::new(&hash::sha512(input)),
            _ => panic!("unsupported hash algorithm"),
        }
    }

    fn generate(
        &self,
        algorithm: &'static SignatureAlgorithm,
        key_size: Option<RsaKeySize>,
    ) -> Result<KeyPair, Error> {
        if ec::Curve::for_algorithm(algorithm).is_some() {
            if key_size.is_some() {
                return Err(Error::KeyGenerationUnavailable);
            }
            ec::generate(algorithm)
        } else if rsa::is_algorithm(algorithm) {
            let bits = match key_size.unwrap_or(RsaKeySize::_2048) {
                RsaKeySize::_2048 => 2048,
                RsaKeySize::_3072 => 3072,
                RsaKeySize::_4096 => 4096,
                _ => return Err(Error::KeyGenerationUnavailable),
            };
            rsa::generate(algorithm, bits)
        } else {
            Err(Error::KeyGenerationUnavailable)
        }
    }

    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
        algorithm: Option<&'static SignatureAlgorithm>,
    ) -> Result<KeyPair, Error> {
        if let Some(algorithm) = algorithm {
            if ec::Curve::for_algorithm(algorithm).is_some() {
                return ec::load(&key_der, Some(algorithm));
            }
            if rsa::is_algorithm(algorithm) {
                return rsa::load(&key_der, Some(algorithm));
            }
            return Err(Error::UnsupportedSignatureAlgorithm);
        }

        match &key_der {
            PrivateKeyDer::Sec1(_) => ec::load(&key_der, None),
            PrivateKeyDer::Pkcs1(_) => rsa::load(&key_der, None),
            PrivateKeyDer::Pkcs8(key) => {
                let info = pkcs8::PrivateKeyInfo::from_der(key.secret_pkcs8_der())
                    .map_err(|_| Error::CouldNotParseKeyPair)?;
                if info.algorithm.oid == ec::ALGORITHM_OID {
                    ec::load(&key_der, None)
                } else if info.algorithm.oid == pkcs1::ALGORITHM_OID {
                    rsa::load(&key_der, None)
                } else {
                    Err(Error::CouldNotParseKeyPair)
                }
            }
            _ => Err(Error::CouldNotParseKeyPair),
        }
    }
    fn verify(
        &self,
        algorithm: &'static SignatureAlgorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        if ec::Curve::for_algorithm(algorithm).is_some() {
            ec::verify(algorithm, public_key, message, signature)
        } else if rsa::is_algorithm(algorithm) {
            rsa::verify(algorithm, public_key, message, signature)
        } else {
            Err(Error::UnsupportedSignatureAlgorithm)
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SignatureHash {
    Sha256,
    Sha384,
    Sha512,
}

impl SignatureHash {
    pub(crate) fn for_algorithm(algorithm: &SignatureAlgorithm) -> Option<Self> {
        if algorithm == &PKCS_ECDSA_P256_SHA256
            || algorithm == &PKCS_ECDSA_P521_SHA256
            || algorithm == &PKCS_RSA_SHA256
        {
            Some(Self::Sha256)
        } else if algorithm == &PKCS_ECDSA_P384_SHA384
            || algorithm == &PKCS_ECDSA_P521_SHA384
            || algorithm == &PKCS_RSA_SHA384
        {
            Some(Self::Sha384)
        } else if algorithm == &PKCS_ECDSA_P521_SHA512 || algorithm == &PKCS_RSA_SHA512 {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    pub(crate) fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => hash::sha256(message).to_vec(),
            Self::Sha384 => hash::sha384(message).to_vec(),
            Self::Sha512 => hash::sha512(message).to_vec(),
        }
    }

    pub(crate) fn symcrypt(self) -> SymCryptHashAlgorithm {
        match self {
            Self::Sha256 => SymCryptHashAlgorithm::Sha256,
            Self::Sha384 => SymCryptHashAlgorithm::Sha384,
            Self::Sha512 => SymCryptHashAlgorithm::Sha512,
        }
    }
}

pub(crate) fn provider_error(operation: &str, error: impl Display) -> Error {
    Error::CryptoProviderError(format!("SymCrypt {operation} failed: {error}"))
}
