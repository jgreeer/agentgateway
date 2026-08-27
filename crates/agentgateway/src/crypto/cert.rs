//! Selection of the rcgen crypto backend for certificate and CSR generation.
//!
//! This is the certificate-issuance analog of [`crate::crypto::tls`]: the single
//! place that picks the rcgen [`CryptoProvider`] and key-pair type for the
//! compiled-in backend. All certificate/CSR generation should obtain its provider
//! and key pairs from here rather than referencing an rcgen backend directly.

pub use imp::{GatewayKeyPair, generate_key, key_from_pem, provider};

#[cfg(feature = "crypto-aws-lc")]
mod imp {
	use rcgen::{CryptoProvider, Error, PKCS_ECDSA_P256_SHA256};

	/// Concrete rcgen signing key; implements `SigningKey` + `PublicKeyData` and
	/// exposes `serialize_der` / `serialize_pem`, so call sites stay backend-agnostic.
	pub type GatewayKeyPair = rcgen::KeyPair;

	/// rcgen [`CryptoProvider`] to pass to the `*_with_provider` issuance methods.
	pub fn provider() -> &'static dyn CryptoProvider {
		&rcgen::DefaultCryptoProvider
	}

	/// Generates a new ECDSA P-256 key pair.
	pub fn generate_key() -> Result<GatewayKeyPair, Error> {
		rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
	}

	/// Loads a key pair from a PEM-encoded private key.
	pub fn key_from_pem(pem: &str) -> Result<GatewayKeyPair, Error> {
		rcgen::KeyPair::from_pem(pem)
	}
}

#[cfg(feature = "crypto-symcrypt")]
mod imp {
	use rcgen::{CryptoProvider, Error, PKCS_ECDSA_P256_SHA256};

	pub type GatewayKeyPair = rcgen_symcrypt::SymCryptKeyPair;

	pub fn provider() -> &'static dyn CryptoProvider {
		&rcgen_symcrypt::SymCryptProvider
	}

	pub fn generate_key() -> Result<GatewayKeyPair, Error> {
		rcgen_symcrypt::SymCryptKeyPair::generate(&PKCS_ECDSA_P256_SHA256)
	}

	pub fn key_from_pem(pem: &str) -> Result<GatewayKeyPair, Error> {
		use rustls::pki_types::PrivateKeyDer;
		use rustls::pki_types::pem::PemObject;

		// SymCrypt needs the curve up front, so parse to DER and try P-256 then P-384.
		let der =
			PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| Error::CouldNotParseKeyPair)?;
		rcgen_symcrypt::SymCryptKeyPair::from_der(&der, &PKCS_ECDSA_P256_SHA256)
			.or_else(|_| rcgen_symcrypt::SymCryptKeyPair::from_der(&der, &rcgen::PKCS_ECDSA_P384_SHA384))
	}
}
