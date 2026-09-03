use der::Decode;
use rcgen::crypto::HashAlgorithm;
use rcgen::{
    CertificateParams, Error, KeyPair, PublicKeyData, RsaKeySize, SigningKey,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA256, PKCS_ECDSA_P521_SHA384,
    PKCS_ECDSA_P521_SHA512, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use rcgen_symcrypt::default_provider;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

#[test]
fn digests_are_computed_by_symcrypt() {
    let provider = default_provider();
    assert_eq!(
        provider.hash(HashAlgorithm::Sha256, b"abc").as_ref(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn ecdsa_generation_loading_signing_and_csrs_round_trip() {
    let provider = default_provider();
    for algorithm in [
        &PKCS_ECDSA_P256_SHA256,
        &PKCS_ECDSA_P384_SHA384,
        &PKCS_ECDSA_P521_SHA256,
        &PKCS_ECDSA_P521_SHA384,
        &PKCS_ECDSA_P521_SHA512,
    ] {
        let generated = KeyPair::generate_for(algorithm, provider).unwrap();
        let private_key = PrivatePkcs8KeyDer::from(generated.serialize_der());
        let loaded =
            KeyPair::from_pkcs8_der_and_sign_algo(&private_key, algorithm, provider).unwrap();
        assert_eq!(generated.der_bytes(), loaded.der_bytes());

        let message = b"rcgen SymCrypt ECDSA provider";
        let signature = loaded.sign(message).unwrap();
        provider
            .verify(algorithm, loaded.der_bytes(), message, &signature)
            .unwrap();
        let mut invalid_signature = signature;
        *invalid_signature.last_mut().unwrap() ^= 1;
        assert_eq!(
            provider
                .verify(algorithm, loaded.der_bytes(), message, &invalid_signature)
                .unwrap_err(),
            Error::SignatureVerificationFailed
        );

        let request = CertificateParams::default()
            .serialize_request(&loaded)
            .unwrap();
        let parsed =
            rcgen::CertificateSigningRequestParams::from_der(request.der(), provider).unwrap();
        assert_eq!(parsed.public_key.algorithm(), algorithm);

        let certificate = CertificateParams::default()
            .self_signed(&loaded, provider)
            .unwrap();
        assert!(!certificate.der().is_empty());
    }
}

#[test]
fn rsa_generation_loading_and_signing_round_trip() {
    let provider = default_provider();
    let generated =
        KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048, provider).unwrap();
    let private_key = generated.serialize_der();

    for algorithm in [&PKCS_RSA_SHA256, &PKCS_RSA_SHA384, &PKCS_RSA_SHA512] {
        let loaded = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(private_key.clone()),
            algorithm,
            provider,
        )
        .unwrap();
        assert_eq!(generated.der_bytes(), loaded.der_bytes());

        let message = b"rcgen SymCrypt RSA provider";
        let signature = loaded.sign(message).unwrap();
        assert_eq!(signature.len(), 256);
        provider
            .verify(algorithm, loaded.der_bytes(), message, &signature)
            .unwrap();

        let certificate = CertificateParams::default()
            .self_signed(&loaded, provider)
            .unwrap();
        assert!(!certificate.der().is_empty());
    }

    let detected = KeyPair::from_der(
        &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
        provider,
    )
    .unwrap();
    assert_eq!(detected.algorithm(), &PKCS_RSA_SHA256);
}

#[test]
fn openssl_rsa_private_key_is_loaded() {
    let provider = default_provider();
    let key = KeyPair::from_pem(include_str!("data/openssl-rsa-2048.pem"), provider).unwrap();
    let message = b"OpenSSL RSA private key";
    let signature = key.sign(message).unwrap();

    provider
        .verify(&PKCS_RSA_SHA256, key.der_bytes(), message, &signature)
        .unwrap();
}

#[test]
fn sec1_and_pkcs1_private_keys_are_loaded() {
    let provider = default_provider();

    let ec = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256, provider).unwrap();
    let ec_der = ec.serialize_der();
    let ec_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&ec_der).unwrap();
    let ec_sec1 = PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(ec_pkcs8.private_key.to_vec()));
    let loaded_ec =
        KeyPair::from_der_and_sign_algo(&ec_sec1, &PKCS_ECDSA_P256_SHA256, provider).unwrap();
    assert_eq!(loaded_ec.der_bytes(), ec.der_bytes());

    let rsa = KeyPair::generate_for(&PKCS_RSA_SHA256, provider).unwrap();
    let rsa_der = rsa.serialize_der();
    let rsa_pkcs8 = pkcs8::PrivateKeyInfo::from_der(&rsa_der).unwrap();
    let rsa_pkcs1 = PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(rsa_pkcs8.private_key.to_vec()));
    let loaded_rsa =
        KeyPair::from_der_and_sign_algo(&rsa_pkcs1, &PKCS_RSA_SHA256, provider).unwrap();
    assert_eq!(loaded_rsa.der_bytes(), rsa.der_bytes());
}

#[test]
fn automatic_ec_detection_uses_the_curve_default() {
    let provider = default_provider();
    for (generated_algorithm, detected_algorithm) in [
        (&PKCS_ECDSA_P256_SHA256, &PKCS_ECDSA_P256_SHA256),
        (&PKCS_ECDSA_P384_SHA384, &PKCS_ECDSA_P384_SHA384),
        (&PKCS_ECDSA_P521_SHA256, &PKCS_ECDSA_P521_SHA512),
    ] {
        let generated = KeyPair::generate_for(generated_algorithm, provider).unwrap();
        let detected = KeyPair::from_der(
            &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.serialize_der())),
            provider,
        )
        .unwrap();
        assert_eq!(detected.algorithm(), detected_algorithm);
        assert_eq!(detected.der_bytes(), generated.der_bytes());
    }
}

#[test]
fn all_rsa_key_sizes_are_generated() {
    let provider = default_provider();
    for (key_size, signature_len) in [
        (RsaKeySize::_2048, 256),
        (RsaKeySize::_3072, 384),
        (RsaKeySize::_4096, 512),
    ] {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, key_size, provider).unwrap();
        assert_eq!(key.sign(b"RSA key size").unwrap().len(), signature_len);
    }
}

#[test]
fn unsupported_algorithms_return_errors() {
    let provider = default_provider();
    assert_eq!(
        provider.generate(&PKCS_ED25519, None).unwrap_err(),
        Error::KeyGenerationUnavailable
    );
    assert_eq!(
        provider
            .verify(&PKCS_ED25519, &[], b"message", &[])
            .unwrap_err(),
        Error::UnsupportedSignatureAlgorithm
    );
}

#[test]
fn signatures_from_another_key_are_rejected() {
    let provider = default_provider();
    for algorithm in [&PKCS_ECDSA_P256_SHA256, &PKCS_RSA_SHA256] {
        let signer = KeyPair::generate_for(algorithm, provider).unwrap();
        let other_key = KeyPair::generate_for(algorithm, provider).unwrap();
        let message = b"wrong key";
        let signature = signer.sign(message).unwrap();
        assert_eq!(
            provider
                .verify(algorithm, other_key.der_bytes(), message, &signature)
                .unwrap_err(),
            Error::SignatureVerificationFailed
        );
    }
}

#[test]
fn malformed_private_keys_are_rejected() {
    let provider = default_provider();
    for key in [
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x30, 0x00])),
        PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(vec![0x30, 0x00])),
        PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(vec![0x30, 0x00])),
    ] {
        assert_eq!(
            KeyPair::from_der(&key, provider).unwrap_err(),
            Error::CouldNotParseKeyPair
        );
    }
}
