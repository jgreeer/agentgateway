use rcgen::{generate_simple_self_signed, CertifiedKey};
use rcgen_symcrypt::default_provider;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(["localhost".to_string()], default_provider())?;
    println!("{}", cert.pem());
    println!("{}", signing_key.serialize_pem());
    Ok(())
}
