use der::asn1::UintRef;
use der::{Decode, Document, SecretDocument};
use pkcs1::{RsaPrivateKey, RsaPublicKey};
use pkcs8::PrivateKeyInfo;
use rcgen::{
    Error, KeyPair, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_RSA_SHA256,
    PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use rustls_pki_types::PrivateKeyDer;
use symcrypt::rsa::{RsaKey, RsaKeyPairExportBlob, RsaKeyUsage};

use crate::{provider_error, SignatureHash};

pub(crate) fn is_algorithm(algorithm: &SignatureAlgorithm) -> bool {
    algorithm == &PKCS_RSA_SHA256 || algorithm == &PKCS_RSA_SHA384 || algorithm == &PKCS_RSA_SHA512
}

pub(crate) fn generate(
    algorithm: &'static SignatureAlgorithm,
    bits: u32,
) -> Result<KeyPair, Error> {
    if !is_algorithm(algorithm) {
        return Err(Error::KeyGenerationUnavailable);
    }
    let key = RsaKey::generate_key_pair(bits, None, RsaKeyUsage::Sign)
        .map_err(|error| provider_error("RSA key generation", error))?;
    into_key_pair(key, algorithm)
}

pub(crate) fn load(
    key_der: &PrivateKeyDer<'_>,
    requested_algorithm: Option<&'static SignatureAlgorithm>,
) -> Result<KeyPair, Error> {
    let pkcs1_der = match key_der {
        PrivateKeyDer::Pkcs1(key) => key.secret_pkcs1_der(),
        PrivateKeyDer::Pkcs8(key) => {
            let info = PrivateKeyInfo::from_der(key.secret_pkcs8_der())
                .map_err(|_| Error::CouldNotParseKeyPair)?;
            if info.algorithm.oid != pkcs1::ALGORITHM_OID {
                return Err(Error::CouldNotParseKeyPair);
            }
            info.private_key
        }
        _ => return Err(Error::CouldNotParseKeyPair),
    };
    let parsed = RsaPrivateKey::from_der(pkcs1_der).map_err(|_| Error::CouldNotParseKeyPair)?;
    if parsed.other_prime_infos.is_some() {
        return Err(Error::CouldNotParseKeyPair);
    }
    let algorithm = requested_algorithm.unwrap_or(&PKCS_RSA_SHA256);
    if !is_algorithm(algorithm) {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    let key = RsaKey::set_key_pair(
        parsed.modulus.as_bytes(),
        parsed.public_exponent.as_bytes(),
        parsed.prime1.as_bytes(),
        parsed.prime2.as_bytes(),
        RsaKeyUsage::Sign,
    )
    .map_err(|_| Error::CouldNotParseKeyPair)?;
    let blob = key
        .export_key_pair_blob()
        .map_err(|_| Error::CouldNotParseKeyPair)?;
    if !private_components_match(&parsed, &blob) {
        return Err(Error::CouldNotParseKeyPair);
    }
    into_key_pair_with_blob(key, algorithm, blob)
}

pub(crate) fn verify(
    algorithm: &'static SignatureAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if !is_algorithm(algorithm) {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    let public_key =
        RsaPublicKey::from_der(public_key).map_err(|_| Error::SignatureVerificationFailed)?;
    let key = RsaKey::set_public_key(
        public_key.modulus.as_bytes(),
        public_key.public_exponent.as_bytes(),
        RsaKeyUsage::Sign,
    )
    .map_err(|_| Error::SignatureVerificationFailed)?;
    let hash =
        SignatureHash::for_algorithm(algorithm).ok_or(Error::UnsupportedSignatureAlgorithm)?;
    let digest = hash.digest(message);
    key.pkcs1_verify(&digest, signature, hash.symcrypt())
        .map_err(|_| Error::SignatureVerificationFailed)
}

struct RsaSigningKey {
    key: RsaKey,
    algorithm: &'static SignatureAlgorithm,
    public_key: Vec<u8>,
}

impl PublicKeyData for RsaSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl SigningKey for RsaSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hash = SignatureHash::for_algorithm(self.algorithm)
            .ok_or(Error::UnsupportedSignatureAlgorithm)?;
        let digest = hash.digest(message);
        self.key
            .pkcs1_sign(&digest, hash.symcrypt())
            .map_err(|error| provider_error("RSA signing", error))
    }
}

fn into_key_pair(key: RsaKey, algorithm: &'static SignatureAlgorithm) -> Result<KeyPair, Error> {
    let blob = key
        .export_key_pair_blob()
        .map_err(|error| provider_error("RSA private-key export", error))?;
    into_key_pair_with_blob(key, algorithm, blob)
}

fn into_key_pair_with_blob(
    key: RsaKey,
    algorithm: &'static SignatureAlgorithm,
    blob: RsaKeyPairExportBlob,
) -> Result<KeyPair, Error> {
    let public_key = encode_public_key(&blob)?;
    let serialized_der = encode_pkcs8(&blob)?;
    Ok(KeyPair::from_signing_key(
        Box::new(RsaSigningKey {
            key,
            algorithm,
            public_key,
        }),
        serialized_der,
    ))
}

fn private_components_match(parsed: &RsaPrivateKey<'_>, blob: &RsaKeyPairExportBlob) -> bool {
    // SymCrypt may choose an equivalent private exponent and recomputes the CRT coefficient.
    let public_components_match = integer_eq(parsed.modulus.as_bytes(), &blob.modulus)
        && integer_eq(parsed.public_exponent.as_bytes(), &blob.pub_exp);
    let primes_match = integer_eq(parsed.prime1.as_bytes(), &blob.p)
        && integer_eq(parsed.prime2.as_bytes(), &blob.q)
        && integer_eq(parsed.exponent1.as_bytes(), &blob.d_p)
        && integer_eq(parsed.exponent2.as_bytes(), &blob.d_q);
    let swapped_primes_match = integer_eq(parsed.prime1.as_bytes(), &blob.q)
        && integer_eq(parsed.prime2.as_bytes(), &blob.p)
        && integer_eq(parsed.exponent1.as_bytes(), &blob.d_q)
        && integer_eq(parsed.exponent2.as_bytes(), &blob.d_p);

    public_components_match && (primes_match || swapped_primes_match)
}

fn integer_eq(left: &[u8], right: &[u8]) -> bool {
    trim_leading_zeroes(left) == trim_leading_zeroes(right)
}

fn trim_leading_zeroes(value: &[u8]) -> &[u8] {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    &value[first_nonzero..]
}

fn encode_public_key(blob: &RsaKeyPairExportBlob) -> Result<Vec<u8>, Error> {
    let key = RsaPublicKey {
        modulus: uint(&blob.modulus)?,
        public_exponent: uint(&blob.pub_exp)?,
    };
    let document = Document::try_from(&key)
        .map_err(|error| provider_error("RSA public-key encoding", error))?;
    Ok(document.as_bytes().to_vec())
}

fn encode_pkcs8(blob: &RsaKeyPairExportBlob) -> Result<Vec<u8>, Error> {
    let key = RsaPrivateKey {
        modulus: uint(&blob.modulus)?,
        public_exponent: uint(&blob.pub_exp)?,
        private_exponent: uint(&blob.private_exp)?,
        prime1: uint(&blob.p)?,
        prime2: uint(&blob.q)?,
        exponent1: uint(&blob.d_p)?,
        exponent2: uint(&blob.d_q)?,
        coefficient: uint(&blob.crt_coefficient)?,
        other_prime_infos: None,
    };
    let pkcs1_der =
        SecretDocument::try_from(&key).map_err(|error| provider_error("PKCS#1 encoding", error))?;
    let private_key_info = PrivateKeyInfo::new(pkcs1::ALGORITHM_ID, pkcs1_der.as_bytes());
    let pkcs8_der = SecretDocument::try_from(&private_key_info)
        .map_err(|error| provider_error("PKCS#8 encoding", error))?;
    Ok(pkcs8_der.as_bytes().to_vec())
}

fn uint(bytes: &[u8]) -> Result<UintRef<'_>, Error> {
    UintRef::new(bytes).map_err(|error| provider_error("RSA integer encoding", error))
}
