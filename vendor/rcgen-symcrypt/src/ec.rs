use der::asn1::{ObjectIdentifier, UintRef};
use der::{Decode, Encode, Sequence};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo, SecretDocument};
use rcgen::{
    Error, KeyPair, PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA256, PKCS_ECDSA_P521_SHA384, PKCS_ECDSA_P521_SHA512,
};
use rustls_pki_types::PrivateKeyDer;
use sec1::EcPrivateKey;
use symcrypt::ecc::{CurveType, EcKey, EcKeyUsage};

use crate::{provider_error, SignatureHash};

pub(crate) const ALGORITHM_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    pub(crate) fn for_algorithm(algorithm: &SignatureAlgorithm) -> Option<Self> {
        if algorithm == &PKCS_ECDSA_P256_SHA256 {
            Some(Self::P256)
        } else if algorithm == &PKCS_ECDSA_P384_SHA384 {
            Some(Self::P384)
        } else if algorithm == &PKCS_ECDSA_P521_SHA256
            || algorithm == &PKCS_ECDSA_P521_SHA384
            || algorithm == &PKCS_ECDSA_P521_SHA512
        {
            Some(Self::P521)
        } else {
            None
        }
    }

    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            P256_OID => Some(Self::P256),
            P384_OID => Some(Self::P384),
            P521_OID => Some(Self::P521),
            _ => None,
        }
    }

    fn from_scalar_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::P256),
            48 => Some(Self::P384),
            66 => Some(Self::P521),
            _ => None,
        }
    }

    fn oid(self) -> ObjectIdentifier {
        match self {
            Self::P256 => P256_OID,
            Self::P384 => P384_OID,
            Self::P521 => P521_OID,
        }
    }

    fn size(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    fn symcrypt(self) -> CurveType {
        match self {
            Self::P256 => CurveType::NistP256,
            Self::P384 => CurveType::NistP384,
            Self::P521 => CurveType::NistP521,
        }
    }

    fn default_algorithm(self) -> &'static SignatureAlgorithm {
        match self {
            Self::P256 => &PKCS_ECDSA_P256_SHA256,
            Self::P384 => &PKCS_ECDSA_P384_SHA384,
            Self::P521 => &PKCS_ECDSA_P521_SHA512,
        }
    }
}

pub(crate) fn generate(algorithm: &'static SignatureAlgorithm) -> Result<KeyPair, Error> {
    let curve = Curve::for_algorithm(algorithm).ok_or(Error::KeyGenerationUnavailable)?;
    let key = EcKey::generate_key_pair(curve.symcrypt(), EcKeyUsage::EcDsa)
        .map_err(|error| provider_error("ECDSA key generation", error))?;
    into_key_pair(key, algorithm, curve)
}

pub(crate) fn load(
    key_der: &PrivateKeyDer<'_>,
    requested_algorithm: Option<&'static SignatureAlgorithm>,
) -> Result<KeyPair, Error> {
    let parsed = parse_private_key(key_der)?;
    let requested_curve = requested_algorithm.and_then(Curve::for_algorithm);
    let curve = match (requested_curve, parsed.curve) {
        (Some(requested), Some(encoded)) if requested != encoded => {
            return Err(Error::CouldNotParseKeyPair)
        }
        (Some(requested), _) => requested,
        (None, Some(encoded)) => encoded,
        (None, None) => {
            Curve::from_scalar_len(parsed.scalar.len()).ok_or(Error::CouldNotParseKeyPair)?
        }
    };
    let algorithm = requested_algorithm.unwrap_or_else(|| curve.default_algorithm());
    let scalar = left_pad(&parsed.scalar, curve.size()).ok_or(Error::CouldNotParseKeyPair)?;
    let public_key = parsed
        .public_key
        .as_deref()
        .map(|public_key| decode_public_key(public_key, curve))
        .transpose()?;
    let key = EcKey::set_key_pair(
        curve.symcrypt(),
        &scalar,
        public_key.as_deref(),
        EcKeyUsage::EcDsa,
    )
    .map_err(|_| Error::CouldNotParseKeyPair)?;
    into_key_pair(key, algorithm, curve)
}

pub(crate) fn verify(
    algorithm: &'static SignatureAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let curve = Curve::for_algorithm(algorithm).ok_or(Error::UnsupportedSignatureAlgorithm)?;
    if public_key.len() != curve.size() * 2 + 1 || public_key.first() != Some(&0x04) {
        return Err(Error::SignatureVerificationFailed);
    }
    let key = EcKey::set_public_key(curve.symcrypt(), &public_key[1..], EcKeyUsage::EcDsa)
        .map_err(|_| Error::SignatureVerificationFailed)?;
    let raw_signature =
        decode_signature(signature, curve.size()).ok_or(Error::SignatureVerificationFailed)?;
    let digest = SignatureHash::for_algorithm(algorithm)
        .ok_or(Error::UnsupportedSignatureAlgorithm)?
        .digest(message);
    key.ecdsa_verify(&raw_signature, &digest)
        .map_err(|_| Error::SignatureVerificationFailed)
}

struct EcSigningKey {
    key: EcKey,
    algorithm: &'static SignatureAlgorithm,
    public_key: Vec<u8>,
    curve: Curve,
}

impl PublicKeyData for EcSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl SigningKey for EcSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = SignatureHash::for_algorithm(self.algorithm)
            .ok_or(Error::UnsupportedSignatureAlgorithm)?
            .digest(message);
        let signature = self
            .key
            .ecdsa_sign(&digest)
            .map_err(|error| provider_error("ECDSA signing", error))?;
        encode_signature(&signature, self.curve.size())
    }
}

fn into_key_pair(
    key: EcKey,
    algorithm: &'static SignatureAlgorithm,
    curve: Curve,
) -> Result<KeyPair, Error> {
    let raw_public_key = key
        .export_public_key()
        .map_err(|error| provider_error("ECDSA public-key export", error))?;
    if raw_public_key.len() != curve.size() * 2 {
        return Err(Error::CryptoProviderError(
            "SymCrypt returned an invalid ECDSA public-key length".into(),
        ));
    }
    let mut public_key = Vec::with_capacity(raw_public_key.len() + 1);
    public_key.push(0x04);
    public_key.extend_from_slice(&raw_public_key);
    let private_key = key
        .export_private_key()
        .map_err(|error| provider_error("ECDSA private-key export", error))?;
    let serialized_der = encode_pkcs8(curve, &private_key, &public_key)?;
    let signing_key = EcSigningKey {
        key,
        algorithm,
        public_key,
        curve,
    };
    Ok(KeyPair::from_signing_key(
        Box::new(signing_key),
        serialized_der,
    ))
}

fn encode_pkcs8(curve: Curve, scalar: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Error> {
    let ec_private_key = EcPrivateKey {
        private_key: scalar,
        parameters: Some(sec1::EcParameters::NamedCurve(curve.oid())),
        public_key: Some(public_key),
    };
    let sec1_der = SecretDocument::try_from(&ec_private_key)
        .map_err(|error| provider_error("SEC1 encoding", error))?;
    let curve_oid = curve.oid();
    let algorithm = AlgorithmIdentifierRef {
        oid: ALGORITHM_OID,
        parameters: Some((&curve_oid).into()),
    };
    let private_key_info = PrivateKeyInfo::new(algorithm, sec1_der.as_bytes());
    let pkcs8_der = SecretDocument::try_from(&private_key_info)
        .map_err(|error| provider_error("PKCS#8 encoding", error))?;
    Ok(pkcs8_der.as_bytes().to_vec())
}

struct ParsedPrivateKey {
    scalar: Vec<u8>,
    curve: Option<Curve>,
    public_key: Option<Vec<u8>>,
}

fn parse_private_key(key_der: &PrivateKeyDer<'_>) -> Result<ParsedPrivateKey, Error> {
    match key_der {
        PrivateKeyDer::Sec1(key) => parse_sec1(key.secret_sec1_der(), None),
        PrivateKeyDer::Pkcs8(key) => {
            let info = PrivateKeyInfo::from_der(key.secret_pkcs8_der())
                .map_err(|_| Error::CouldNotParseKeyPair)?;
            if info.algorithm.oid != ALGORITHM_OID {
                return Err(Error::CouldNotParseKeyPair);
            }
            let outer_curve = info
                .algorithm
                .parameters_oid()
                .ok()
                .and_then(Curve::from_oid)
                .ok_or(Error::CouldNotParseKeyPair)?;
            parse_sec1(info.private_key, Some(outer_curve))
        }
        _ => Err(Error::CouldNotParseKeyPair),
    }
}

fn parse_sec1(der: &[u8], outer_curve: Option<Curve>) -> Result<ParsedPrivateKey, Error> {
    let key = EcPrivateKey::from_der(der).map_err(|_| Error::CouldNotParseKeyPair)?;
    let inner_curve = match key
        .parameters
        .and_then(|parameters| parameters.named_curve())
    {
        Some(oid) => Some(Curve::from_oid(oid).ok_or(Error::CouldNotParseKeyPair)?),
        None => None,
    };
    if outer_curve.is_some() && inner_curve.is_some() && outer_curve != inner_curve {
        return Err(Error::CouldNotParseKeyPair);
    }
    Ok(ParsedPrivateKey {
        scalar: key.private_key.to_vec(),
        curve: outer_curve.or(inner_curve),
        public_key: key.public_key.map(ToOwned::to_owned),
    })
}

fn decode_public_key(public_key: &[u8], curve: Curve) -> Result<Vec<u8>, Error> {
    if public_key.len() != curve.size() * 2 + 1 || public_key.first() != Some(&0x04) {
        return Err(Error::CouldNotParseKeyPair);
    }
    Ok(public_key[1..].to_vec())
}

fn left_pad(value: &[u8], len: usize) -> Option<Vec<u8>> {
    if value.len() > len {
        return None;
    }
    let mut padded = vec![0; len];
    padded[len - value.len()..].copy_from_slice(value);
    Some(padded)
}

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fn encode_signature(raw: &[u8], component_len: usize) -> Result<Vec<u8>, Error> {
    if raw.len() != component_len * 2 {
        return Err(Error::CryptoProviderError(
            "SymCrypt returned an invalid ECDSA signature length".into(),
        ));
    }
    let (r, s) = raw.split_at(component_len);
    EcdsaSignature {
        r: UintRef::new(r).map_err(|error| provider_error("ECDSA signature encoding", error))?,
        s: UintRef::new(s).map_err(|error| provider_error("ECDSA signature encoding", error))?,
    }
    .to_der()
    .map_err(|error| provider_error("ECDSA signature encoding", error))
}

fn decode_signature(signature: &[u8], component_len: usize) -> Option<Vec<u8>> {
    let signature = EcdsaSignature::from_der(signature).ok()?;
    let r = left_pad(signature.r.as_bytes(), component_len)?;
    let s = left_pad(signature.s.as_bytes(), component_len)?;
    let mut raw = Vec::with_capacity(component_len * 2);
    raw.extend_from_slice(&r);
    raw.extend_from_slice(&s);
    Some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_components_with_high_bits_round_trip() {
        let mut raw = vec![0; 64];
        raw[0] = 0x80;
        raw[32] = 0xff;
        let encoded = encode_signature(&raw, 32).unwrap();
        assert_eq!(decode_signature(&encoded, 32).unwrap(), raw);
    }
}
