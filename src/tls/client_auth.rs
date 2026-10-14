//! Chain verification for the certificate a CLIENT presents in client
//! authentication, shared by plzn's servers (TLS 1.2 `server12.rs`, TLS 1.3
//! `server13.rs`, DTLS `dtls_server.rs`). A verified CertificateVerify only
//! proves the client holds the key; whether anyone vouches for that key is the
//! path validation done here (RFC 8446 4.4.2.4, RFC 5246 7.4.6).
//!
//! The X.509 work itself (`verify_certificate_chain`) lives in `crypto.rs`
//! next to the certificate parsing; this module carries the trust store plzn's
//! servers use and the mapping of a rejection to a `TlsError::Rejected` that
//! names the alert a conformant server answers with.

use crate::tls::crypto::verify_certificate_chain;
use crate::tls::driver::TlsError;

/// Apply client Certificate assertions before accepting an empty response or
/// validating a non-empty chain. All server protocols share these matchers.
pub(crate) fn match_client_certificate(
    entries: &[&[u8]],
    certificate_type: u8,
    matchers: &[crate::ir::MessageOverrides],
) -> Result<(), TlsError> {
    use crate::ir::{FieldValue, MessageKind};
    use crate::tls::driver::{collect_overrides, match_certificate_type, match_leaf_key};

    for matcher in collect_overrides(matchers, MessageKind::Certificate) {
        match (matcher.field.as_str(), &matcher.value) {
            ("entries", FieldValue::U16(want)) => {
                if entries.len() != *want as usize {
                    return Err(TlsError::MatcherFailed {
                        message: "Certificate",
                        field: "entries".into(),
                        expected: want.to_string(),
                        observed: entries.len().to_string(),
                    });
                }
            }
            ("leaf_key", FieldValue::Ident(want)) => {
                match_leaf_key(entries.first().copied(), want)?;
            }
            ("certificate_type", FieldValue::Ident(want)) => {
                match_certificate_type(certificate_type, want)?;
            }
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Certificate",
                    field: matcher.field.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The client-authentication trust anchors plzn's servers verify against, as
/// DER: every `shims/testdata` root a shim client's credential can chain to.
///
/// - `client_ee_ca.pem` issued the credential plzn's own clients present
///   (`client_ee_cert.der`);
/// - `client_chain_root.pem` is the root of the two-level test chain
///   (`client_chain_{intermediate,leaf}_cert.der`);
/// - `client_cert.pem` is the shim clients' default self-signed credential,
///   trusted as its own anchor (`uut client { client_cert: valid }`);
/// - `expired_client_cert.pem` is trusted as its own anchor but expired
///   (`uut client { client_cert: expired }`), so only the validity check fails.
///
/// `untrusted_client_cert.pem` (`uut client { client_cert: untrusted }`) chains to
/// none of them.
pub fn default_trust_anchors() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for name in [
        "client_ee_ca.pem",
        "client_chain_root.pem",
        "client_cert.pem",
        "expired_client_cert.pem",
    ] {
        let bytes = crate::fixtures::read(name).expect("built-in client trust anchor");
        out.extend(pem_certificates(bytes));
    }
    out
}

/// Every `CERTIFICATE` block of a PEM file, as DER.
pub fn pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem);
    rustls_pemfile::certs(&mut reader)
        .filter_map(|c| c.ok())
        .map(|c| c.as_ref().to_vec())
        .collect()
}

/// Verify the chain a client presented (leaf first, then any intermediates)
/// against `anchors`, at the current time. A rejection becomes
/// `TlsError::Rejected` with the alert a conformant server answers with:
/// unknown_ca for a chain that reaches no anchor, certificate_expired outside
/// a validity period, bad_certificate for a broken signature or encoding.
pub fn verify_client_chain(chain: &[&[u8]], anchors: &[Vec<u8>]) -> Result<(), TlsError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let anchor_refs: Vec<&[u8]> = anchors.iter().map(|a| a.as_slice()).collect();
    verify_certificate_chain(chain, &anchor_refs, now).map_err(|e| TlsError::Rejected {
        alert: e.alert_code(),
        reason: format!("client certificate rejected: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_anchors_load_and_cover_the_test_credentials() {
        let anchors = default_trust_anchors();
        assert!(
            anchors.len() >= 4,
            "expected the four testdata anchors, got {}",
            anchors.len()
        );
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("shims")
            .join("testdata");
        // plzn's own client credential chains to client_ee_ca.
        let ee = std::fs::read(root.join("client_ee_cert.der")).unwrap();
        verify_client_chain(&[&ee], &anchors).expect("client_ee_cert must verify");
        // The two-level chain reaches client_chain_root through its intermediate.
        let leaf = std::fs::read(root.join("client_chain_leaf_cert.der")).unwrap();
        let inter = std::fs::read(root.join("client_chain_intermediate_cert.der")).unwrap();
        verify_client_chain(&[&leaf, &inter], &anchors).expect("client chain must verify");
        // Without the intermediate the leaf's issuer is unknown.
        match verify_client_chain(&[&leaf], &anchors) {
            Err(TlsError::Rejected { alert: 48, .. }) => {}
            other => panic!("expected unknown_ca, got {:?}", other),
        }
        // The shim clients' default self-signed credential is its own anchor.
        let valid = pem_certificates(&std::fs::read(root.join("client_cert.pem")).unwrap());
        verify_client_chain(&[&valid[0]], &anchors).expect("client_cert.pem must verify");
        // The untrusted one reaches nothing: unknown_ca.
        let untrusted = std::fs::read(root.join("untrusted_client_cert.der")).unwrap();
        match verify_client_chain(&[&untrusted], &anchors) {
            Err(TlsError::Rejected { alert: 48, .. }) => {}
            other => panic!("expected unknown_ca, got {:?}", other),
        }
        // The expired one is trusted but out of date: certificate_expired.
        let expired =
            pem_certificates(&std::fs::read(root.join("expired_client_cert.pem")).unwrap());
        match verify_client_chain(&[&expired[0]], &anchors) {
            Err(TlsError::Rejected { alert: 45, .. }) => {}
            other => panic!("expected certificate_expired, got {:?}", other),
        }
    }

    #[test]
    fn typed_client_credentials_chain_to_the_client_ca() {
        // T3: every `credential: <type>` file issued by gen_client_ee.sh.
        let anchors = default_trust_anchors();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("shims")
            .join("testdata");
        for name in [
            "client_ee",
            "client_ee_rsa",
            "client_ee_rsa_pss",
            "client_ee_ecdsa_p384",
            "client_ee_ecdsa_p521",
            "client_ee_ed25519",
        ] {
            let cert = std::fs::read(root.join(format!("{}_cert.der", name))).unwrap();
            verify_client_chain(&[&cert], &anchors)
                .unwrap_or_else(|e| panic!("{} must verify: {:?}", name, e));
            let key = std::fs::read(root.join(format!("{}_key.pkcs8.der", name))).unwrap();
            crate::tls::crypto::PrivateKey::from_pkcs8_der(&key)
                .unwrap_or_else(|e| panic!("{} key: {:?}", name, e));
        }
    }
}
