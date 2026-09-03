use rcgen::{generate_simple_self_signed, CertifiedKey};
use rcgen_symcrypt::default_provider;

#[test]
fn explicit_provider_enables_rcgen_convenience_api() {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["localhost".to_string()], default_provider()).unwrap();
    assert!(!cert.der().is_empty());
    assert!(!signing_key.serialize_der().is_empty());
}
