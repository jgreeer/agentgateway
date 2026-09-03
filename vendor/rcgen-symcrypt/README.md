# rcgen-symcrypt

A [SymCrypt]-backed [`CryptoProvider`] for [rcgen]. It provides key generation and loading,
SHA-2 hashing, signing, and CSR verification without enabling rcgen's Ring or AWS-LC backends.

## Usage

```toml
[dependencies]
rcgen = { git = "https://github.com/jgreeer/rcgen.git", rev = "19aece99fc60c11f93ea16207d124169fdff39cf", default-features = false, features = ["crypto", "pem"] }
rcgen-symcrypt = { git = "https://github.com/jgreeer/rcgen-symcrypt.git" }
```

Pass the SymCrypt provider to each rcgen API that performs cryptographic work:

```rust,no_run
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rcgen_symcrypt::default_provider;

let CertifiedKey { cert, signing_key } = generate_simple_self_signed(
    ["localhost".to_string()],
    default_provider(),
)?;
println!("{}", cert.pem());
println!("{}", signing_key.serialize_pem());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Supported algorithms

- ECDSA P-256 with SHA-256
- ECDSA P-384 with SHA-384
- ECDSA P-521 with SHA-256, SHA-384, or SHA-512
- RSA PKCS#1 v1.5 with SHA-256, SHA-384, or SHA-512
- RSA key generation at 2048, 3072, and 4096 bits

Ed25519 and ML-DSA are not supported by the current `symcrypt` Rust API.

## Requirements

The `symcrypt` crate dynamically links the system `libsymcrypt`, which must be available at build
and run time. See the [rust-symcrypt installation guide].

This repository currently pins the rcgen provider branch. The Git dependency can be replaced with
a crates.io version after the provider API is released.

[rcgen]: https://github.com/rustls/rcgen
[SymCrypt]: https://github.com/microsoft/SymCrypt
[`CryptoProvider`]: https://docs.rs/rcgen/latest/rcgen/crypto/trait.CryptoProvider.html
[rust-symcrypt installation guide]: https://github.com/microsoft/rust-symcrypt/blob/main/symcrypt/INSTALL.md
