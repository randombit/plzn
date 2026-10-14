// Centralised cert + key generation for test runs.
//
// Uses ring (via rcgen) for ECDSA P-256 and the `rsa` crate for
// RSA-2048. No external process, no openssl CLI, no PATH
// dependency. Both DER and PEM forms are produced because plzn's protocol
// engine consumes DER while external shims consume PEM files.
//
// Why both key types:
//
//   * ECDSA P-256 — instant keygen (<1ms). The default test chain.
//     TLS 1.2 negotiates ECDHE-ECDSA suites,
//     TLS 1.3 uses ecdsa_secp256r1_sha256 for CertificateVerify.
//
//   * RSA-2048 — ~2s keygen. Required for ECDHE-RSA kex paths,
//     RSA-PSS signatures in TLS 1.3, and future PKCS#1 v1.5
//     padding oracle attack tests. The openssl backend defaults
//     to RSA since many real-world servers use RSA certs.
//
// Both produce a self-signed cert for "localhost" valid for 1 day.
// CertBundle carries cert-chain DER and private-key PKCS#8 DER for plzn, plus
// PEM strings written into each external shim's per-test configuration.

use std::io;
use std::path::{Path, PathBuf};

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    EcdsaP256,
    EcdsaP384,
    /// Loaded from `shims/testdata/server_ecdsa_p521_*` (rcgen's ring backend
    /// cannot generate P-521 keys).
    EcdsaP521,
    Ed25519,
    Rsa2048,
    /// An RSA-2048 key whose SPKI / PKCS#8 say id-RSASSA-PSS, loaded from
    /// `shims/testdata/server_rsa_pss_*`: signs rsa_pss_pss_* only.
    RsaPss,
}

impl KeyType {
    pub fn name(self) -> &'static str {
        match self {
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::EcdsaP384 => "ecdsa-p384",
            KeyType::EcdsaP521 => "ecdsa-p521",
            KeyType::Ed25519 => "ed25519",
            KeyType::Rsa2048 => "rsa-2048",
            KeyType::RsaPss => "rsa-pss",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "ecdsa" | "ecdsa-p256" => Some(KeyType::EcdsaP256),
            "ecdsa-p384" | "p384" => Some(KeyType::EcdsaP384),
            "ecdsa-p521" | "p521" => Some(KeyType::EcdsaP521),
            "ed25519" => Some(KeyType::Ed25519),
            "rsa" | "rsa-2048" => Some(KeyType::Rsa2048),
            "rsa-pss" => Some(KeyType::RsaPss),
            _ => None,
        }
    }
}
// NOTE: ECDSA P-521 cert generation is intentionally absent -- rcgen can only
// produce P-521 keys with the aws_lc_rs backend (a heavy C dependency); the
// default `ring` backend cannot. plzn's verifier DOES support P-521
// (SignatureScheme::EcdsaSecp521r1Sha512), so a P-521 server cert loaded from a
// file works; only runtime generation is unavailable.

/// A self-signed cert + private key in both DER and PEM forms.
pub struct CertBundle {
    pub key_type: KeyType,
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertBundle {
    /// Generate a fresh self-signed cert for "localhost".
    ///
    /// ECDSA and Ed25519: instant. RSA: the checked-in
    /// `shims/testdata/server_rsa_2048` bundle (an RSA keygen costs a few
    /// hundred milliseconds and was ~8% of a short run's CPU); the
    /// bundle is embedded, so it is available without the source checkout.
    pub fn generate(key_type: KeyType) -> io::Result<Self> {
        match key_type {
            KeyType::EcdsaP256 => generate_ecdsa(),
            KeyType::EcdsaP384 => generate_ecdsa_p384(),
            KeyType::EcdsaP521 => load_testdata(KeyType::EcdsaP521, "server_ecdsa_p521"),
            KeyType::Ed25519 => generate_rcgen(KeyType::Ed25519, &rcgen::PKCS_ED25519),
            KeyType::Rsa2048 => {
                load_testdata(KeyType::Rsa2048, "server_rsa_2048").or_else(|_| generate_rsa())
            }
            KeyType::RsaPss => load_testdata(KeyType::RsaPss, "server_rsa_pss"),
        }
    }

    /// Write cert.pem and key.pem into `dir`. Creates the
    /// directory if it doesn't exist. Returns the two paths.
    pub fn write_pem_files(&self, dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &self.cert_pem)?;
        std::fs::write(&key_path, &self.key_pem)?;
        Ok((cert_path, key_path))
    }
}

// ---- generators ----

/// A bundle from `shims/testdata/<base>_{cert,key}.pem` (made by
/// `gen_client_ee.sh`), for the key types the runtime cannot generate.
fn load_testdata(key_type: KeyType, base: &str) -> io::Result<CertBundle> {
    let cert_pem = crate::fixtures::pem(&format!("{base}_cert.pem"))?;
    let key_pem = crate::fixtures::pem(&format!("{base}_key.pem"))?;
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| io::Error::other(format!("{}_cert.pem holds no certificate", base)))?
        .map_err(io::Error::other)?
        .as_ref()
        .to_vec();
    let key_pkcs8_der =
        match rustls_pemfile::private_key(&mut key_pem.as_bytes()).map_err(io::Error::other)? {
            Some(PrivateKeyDer::Pkcs8(k)) => k.secret_pkcs8_der().to_vec(),
            Some(_) => return Err(io::Error::other(format!("{}_key.pem is not PKCS#8", base))),
            None => {
                return Err(io::Error::other(format!(
                    "{}_key.pem holds no private key",
                    base
                )));
            }
        };
    Ok(CertBundle {
        key_type,
        cert_der,
        key_pkcs8_der,
        cert_pem,
        key_pem,
    })
}

fn generate_ecdsa() -> io::Result<CertBundle> {
    let key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;
    let cert_der = cert.der().to_vec();
    let key_pkcs8_der = key_pair.serialize_der();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    Ok(CertBundle {
        key_type: KeyType::EcdsaP256,
        cert_der,
        key_pkcs8_der,
        cert_pem,
        key_pem,
    })
}

fn generate_ecdsa_p384() -> io::Result<CertBundle> {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).map_err(io::Error::other)?;
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;
    let cert_der = cert.der().to_vec();
    let key_pkcs8_der = key_pair.serialize_der();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    Ok(CertBundle {
        key_type: KeyType::EcdsaP384,
        cert_der,
        key_pkcs8_der,
        cert_pem,
        key_pem,
    })
}

/// Generate a self-signed "localhost" cert for any rcgen signature algorithm
/// (used for P-521 and Ed25519, which need no special key handling).
fn generate_rcgen(
    key_type: KeyType,
    algo: &'static rcgen::SignatureAlgorithm,
) -> io::Result<CertBundle> {
    let key_pair = rcgen::KeyPair::generate_for(algo).map_err(io::Error::other)?;
    // ring writes an Ed25519 key as PKCS#8 v2 (OneAsymmetricKey with the public
    // key), which Botan's PKCS8::load_key refuses (it decodes v0/v1 only), so
    // the shim could not even load `--cert ed25519`. Re-encode as v1; rcgen
    // keeps the given DER verbatim for serialize_der / serialize_pem.
    let key_pair = if key_type == KeyType::Ed25519 {
        let v1 = ed25519_pkcs8_v1(&key_pair.serialize_der())
            .ok_or_else(|| io::Error::other("Ed25519 PKCS#8 re-encoding: seed not found"))?;
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(v1), algo)
            .map_err(io::Error::other)?
    } else {
        key_pair
    };
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;
    Ok(CertBundle {
        key_type,
        cert_der: cert.der().to_vec(),
        key_pkcs8_der: key_pair.serialize_der(),
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

/// Re-encode an Ed25519 PKCS#8 key as version 1 (RFC 5958 PrivateKeyInfo
/// without the optional public key). The seed is the inner OCTET STRING of
/// the CurvePrivateKey (RFC 8410 7), `04 22 04 20 <32 bytes>` in either
/// version; the v1 envelope around it is fixed: SEQUENCE { INTEGER 0,
/// AlgorithmIdentifier { id-Ed25519 }, OCTET STRING { OCTET STRING seed } }.
fn ed25519_pkcs8_v1(der: &[u8]) -> Option<Vec<u8>> {
    let pos = der.windows(4).position(|w| w == [0x04, 0x22, 0x04, 0x20])?;
    let seed = der.get(pos + 4..pos + 36)?;
    let mut out = vec![
        0x30, 0x2e, // PrivateKeyInfo
        0x02, 0x01, 0x00, // version 0 (v1)
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier { 1.3.101.112 }
        0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING (32) }
    ];
    out.extend_from_slice(seed);
    Some(out)
}

fn generate_rsa() -> io::Result<CertBundle> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;

    // Deterministic RNG so the key is stable across runs. If
    // you want different keys per invocation, seed with the
    // wall clock or a random source.
    let mut rng = ChaCha20Rng::from_seed([0xa5; 32]);
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048).map_err(io::Error::other)?;
    let pkcs8 = rsa_key.to_pkcs8_der().map_err(io::Error::other)?;
    let pkcs8_bytes = pkcs8.as_bytes().to_vec();

    // Hand the PKCS#8 to rcgen to wrap in a self-signed cert.
    let pkcs8_key_der = PrivatePkcs8KeyDer::from(pkcs8_bytes.clone());
    let key_pair =
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key_der, &rcgen::PKCS_RSA_SHA256)
            .map_err(io::Error::other)?;
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(io::Error::other)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "plzn test server");
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;

    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok(CertBundle {
        key_type: KeyType::Rsa2048,
        cert_der,
        key_pkcs8_der: pkcs8_bytes,
        cert_pem,
        key_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_bundle_round_trips() {
        let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
        assert!(!bundle.cert_der.is_empty());
        assert!(!bundle.key_pkcs8_der.is_empty());
        assert!(bundle.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(bundle.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn ecdsa_p384_bundle_round_trips() {
        let bundle = CertBundle::generate(KeyType::EcdsaP384).unwrap();
        assert!(!bundle.cert_der.is_empty());
        assert!(!bundle.key_pkcs8_der.is_empty());
        assert!(bundle.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(bundle.key_pem.contains("PRIVATE KEY"));
        // The plzn client verifier must parse the P-384 SPKI (it dispatches on the
        // secp384r1 curve OID carried in the SPKI algorithm parameters).
        crate::tls::crypto::PublicKey::from_certificate_der(&bundle.cert_der)
            .expect("P-384 certificate SPKI must parse");
    }

    #[test]
    fn ed25519_bundle_key_is_pkcs8_v1() {
        let bundle = CertBundle::generate(KeyType::Ed25519).unwrap();
        // 48 bytes: the fixed v1 envelope plus the 32-byte seed, version 0.
        assert_eq!(
            bundle.key_pkcs8_der.len(),
            48,
            "{:02x?}",
            bundle.key_pkcs8_der
        );
        assert!(
            bundle
                .key_pkcs8_der
                .starts_with(&[0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05])
        );
        // The PEM carries the same v1 encoding.
        assert!(bundle.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let pem_der = rustls_pemfile::private_key(&mut bundle.key_pem.as_bytes())
            .unwrap()
            .expect("a private key block");
        assert_eq!(pem_der.secret_der(), bundle.key_pkcs8_der.as_slice());
        // plzn's own signer loads it, and the certificate's public key matches
        // the private key (the v1 re-encoding kept the seed).
        let sk = crate::tls::crypto::PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        let pk = crate::tls::crypto::PublicKey::from_certificate_der(&bundle.cert_der).unwrap();
        let sig = sk
            .sign(crate::tls::crypto::SignatureScheme::Ed25519, b"v1")
            .unwrap();
        pk.verify(crate::tls::crypto::SignatureScheme::Ed25519, b"v1", &sig)
            .unwrap();
        // A v2 encoding (with the public-key attribute) re-encodes to the same v1.
        let v2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .unwrap()
            .serialize_der();
        assert!(v2.len() > 48);
        let v1 = ed25519_pkcs8_v1(&v2).unwrap();
        assert_eq!(v1.len(), 48);
        assert_eq!(
            &v1[16..],
            &v2[v2
                .windows(4)
                .position(|w| w == [0x04, 0x22, 0x04, 0x20])
                .unwrap()
                + 4..][..32]
        );
    }

    #[test]
    fn rsa_bundle_round_trips() {
        let bundle = CertBundle::generate(KeyType::Rsa2048).unwrap();
        assert!(!bundle.cert_der.is_empty());
        assert!(!bundle.key_pkcs8_der.is_empty());
        assert!(bundle.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(bundle.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn write_pem_files_creates_both() {
        let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
        let dir = std::env::temp_dir().join("plzn-certs-test");
        let _ = std::fs::remove_dir_all(&dir);
        let (cert_path, key_path) = bundle.write_pem_files(&dir).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
