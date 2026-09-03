//! Selection of rcgen's cryptography provider.

/// Returns the rcgen provider for the compiled-in agentgateway crypto backend.
#[cfg(feature = "crypto-aws-lc")]
pub fn provider() -> &'static dyn ::rcgen::crypto::CryptoProvider {
	::rcgen::crypto::aws_lc_rs::default_provider()
}

/// Returns the rcgen provider for the compiled-in agentgateway crypto backend.
#[cfg(feature = "crypto-symcrypt")]
pub fn provider() -> &'static dyn ::rcgen::crypto::CryptoProvider {
	rcgen_symcrypt::default_provider()
}
