//! Built-in test credentials, embedded at compile time so installed binaries
//! never need the source checkout. These are public test keys, not secrets.
//!
//! plzn consumes the bytes directly. External shims need filenames, so callers
//! write the PEMs into an owned temporary directory that outlives the shim.

use std::io;
use std::path::{Path, PathBuf};

macro_rules! fixtures {
    ($($name:literal),+ $(,)?) => {
        pub(crate) fn read(name: &str) -> io::Result<&'static [u8]> {
            match name {
                $($name => Ok(include_bytes!(concat!("../shims/testdata/", $name))),)+
                _ => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown built-in fixture: {name}"),
                )),
            }
        }
    };
}

fixtures!(
    "server_ecdsa_p521_cert.pem",
    "server_ecdsa_p521_key.pem",
    "server_rsa_2048_cert.pem",
    "server_rsa_2048_key.pem",
    "server_rsa_pss_cert.pem",
    "server_rsa_pss_key.pem",
    "client_ee_ca.pem",
    "client_chain_root.pem",
    "client_cert.pem",
    "client_key.pem",
    "expired_client_cert.pem",
    "expired_client_key.pem",
    "untrusted_client_cert.pem",
    "untrusted_client_key.pem",
    "untrusted_client_cert.der",
    "untrusted_client_key.pkcs8.der",
    "client_ee_cert.pem",
    "client_ee_key.pem",
    "client_ee_cert.der",
    "client_ee_key.pkcs8.der",
    "client_ee_rsa_cert.pem",
    "client_ee_rsa_key.pem",
    "client_ee_rsa_cert.der",
    "client_ee_rsa_key.pkcs8.der",
    "client_ee_rsa_pss_cert.pem",
    "client_ee_rsa_pss_key.pem",
    "client_ee_rsa_pss_cert.der",
    "client_ee_rsa_pss_key.pkcs8.der",
    "client_ee_ecdsa_p384_cert.pem",
    "client_ee_ecdsa_p384_key.pem",
    "client_ee_ecdsa_p384_cert.der",
    "client_ee_ecdsa_p384_key.pkcs8.der",
    "client_ee_ecdsa_p521_cert.pem",
    "client_ee_ecdsa_p521_key.pem",
    "client_ee_ecdsa_p521_cert.der",
    "client_ee_ecdsa_p521_key.pkcs8.der",
    "client_ee_ed25519_cert.pem",
    "client_ee_ed25519_key.pem",
    "client_ee_ed25519_cert.der",
    "client_ee_ed25519_key.pkcs8.der",
);

pub(crate) fn pem(name: &str) -> io::Result<String> {
    std::str::from_utf8(read(name)?)
        .map(str::to_owned)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// `dir` must be owned by the caller and retained while any shim uses the file.
pub(crate) fn write(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let bytes = read(name)?;
    std::fs::create_dir_all(dir)?;
    let path = dir.join(name);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_embedded_bytes_and_rejects_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "client_ee_ca.pem").unwrap();
        assert_eq!(
            std::fs::read(path).unwrap(),
            read("client_ee_ca.pem").unwrap()
        );
        assert!(write(dir.path(), "../client_ee_ca.pem").is_err());
        let not_a_directory = dir.path().join("client_ee_ca.pem");
        assert!(write(&not_a_directory, "client_cert.pem").is_err());
    }
}
