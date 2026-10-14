//! A: certificate-chain selection for plzn's own endpoints.
//!
//! A server configured with several chains (`chain: [rsa_2048, ecdsa_p256]`)
//! picks one per handshake from what the client can take; a client configured
//! with several client-auth credentials (`client_chain: [...]`) picks one from
//! the CertificateRequest. The rules are the RFCs' minimum: the suite family a
//! key can authenticate (RFC 5246 7.4.2 / RFC 8422 5.1.3), a signature scheme
//! in common (RFC 5246 7.4.1.4.1, RFC 8446 4.4.2.2), and for a client the
//! ClientCertificateType the request lists (RFC 5246 7.4.4 / 7.4.6). Chains
//! are tried in configured order, so the list is a preference order.

use crate::ir::{Chain, KexType};
use crate::tls::crypto::PrivateKey;
use crate::tls::driver::TlsError;
use crate::tls::kex12::{client_cert_type_for, select_signature_scheme};

/// A selected client credential: the certificate list to send and the key
/// its CertificateVerify signs with (None = no CertificateVerify).
pub type SelectedCredential = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// `send Certificate { credential: valid }` names the first `client_chain:`
/// entry when the test configured any (the P-256 client_ee credential
/// otherwise); this resolves the selector against `credentials`.
pub fn valid_credential_from(
    overrides: &[crate::ir::FieldOverride],
    credentials: &[Chain],
) -> Option<SelectedCredential> {
    let names_valid = overrides.iter().any(|ov| {
        ov.field == "credential"
            && matches!(&ov.value, crate::ir::FieldValue::Ident(n) if n == "valid")
    });
    if !names_valid {
        return None;
    }
    credentials
        .first()
        .map(|c| (vec![c.cert_der.clone()], Some(c.key_der.clone())))
}

/// Clone the keys parsed once by the run's chain store.
pub fn parse_chain_keys(chains: &[Chain]) -> Result<Vec<PrivateKey>, TlsError> {
    Ok(chains
        .iter()
        .map(|chain| chain.parsed_key.clone())
        .collect())
}

/// Whether `key` can authenticate a TLS 1.2 suite family: an rsaEncryption key
/// the RSA families (static RSA included), an id-RSASSA-PSS key the signing
/// RSA families only, an ECDSA or EdDSA key the ECDHE_ECDSA family (RFC 8422
/// 5.1.3), a configured PSK the PSK families.
pub fn key_serves_kex(key: &PrivateKey, kex: KexType, psk: bool) -> bool {
    let rsa_kex = key.is_rsa();
    let rsa = rsa_kex || key.is_rsa_pss();
    match kex {
        KexType::EcdheRsa | KexType::DheRsa => rsa,
        KexType::Rsa => rsa_kex,
        KexType::EcdheEcdsa => !rsa,
        KexType::Psk | KexType::EcdhePsk => psk,
    }
}

/// TLS 1.2 server: the first chain that can serve `kex` and, when the suite's
/// ServerKeyExchange is signed, has a scheme in common with the client's
/// signature_algorithms (`allowed` narrows the server's schemes; a client that
/// listed none gets the key's default, as `select_signature_scheme` does).
pub fn select_server_chain_12(
    keys: &[PrivateKey],
    kex: KexType,
    psk: bool,
    client_sigalgs: &[u16],
    allowed: &[u16],
) -> Option<usize> {
    keys.iter().position(|k| {
        key_serves_kex(k, kex, psk)
            && (matches!(kex, KexType::Rsa | KexType::Psk | KexType::EcdhePsk)
                || select_signature_scheme(k, client_sigalgs, allowed).is_some())
    })
}

/// TLS 1.3 server: the first chain with a CertificateVerify scheme the client
/// listed (RFC 8446 4.4.2.2).
pub fn select_server_chain_13(keys: &[PrivateKey], client_sigalgs: &[u16]) -> Option<usize> {
    keys.iter().position(|k| {
        k.tls13_signing_schemes()
            .iter()
            .any(|s| client_sigalgs.contains(&s.wire_value()))
    })
}

/// TLS 1.2 client: the first credential whose ClientCertificateType the
/// CertificateRequest lists and that can sign with one of its schemes (an
/// empty scheme list accepts any).
pub fn select_client_credential_12(
    keys: &[PrivateKey],
    cert_types: &[u8],
    sigalgs: &[u16],
) -> Option<usize> {
    keys.iter().position(|k| {
        cert_types.contains(&client_cert_type_for(k))
            && (sigalgs.is_empty() || select_signature_scheme(k, sigalgs, &[]).is_some())
    })
}

/// TLS 1.3 client: the first credential with a CertificateVerify scheme the
/// CertificateRequest listed (RFC 8446 4.4.2).
pub fn select_client_credential_13(keys: &[PrivateKey], sigalgs: &[u16]) -> Option<usize> {
    select_server_chain_13(keys, sigalgs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::codec::{CLIENT_CERT_TYPE_ECDSA_SIGN, CLIENT_CERT_TYPE_RSA_SIGN};

    fn key(base: &str) -> PrivateKey {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("shims")
            .join("testdata");
        let der =
            std::fs::read(root.join(format!("{}_key.pkcs8.der", base))).expect("testdata key");
        PrivateKey::from_pkcs8_der(&der).expect("pkcs8")
    }

    const ECDSA_P256_SHA256: u16 = 0x0403;
    const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    const RSA_PKCS1_SHA256: u16 = 0x0401;
    const ED25519: u16 = 0x0807;

    #[test]
    fn server_picks_the_chain_the_suite_family_and_sigalgs_allow() {
        let keys = vec![key("client_ee"), key("client_ee_rsa")]; // P-256, then RSA
        assert_eq!(
            select_server_chain_12(&keys, KexType::EcdheRsa, false, &[RSA_PSS_RSAE_SHA256], &[]),
            Some(1)
        );
        assert_eq!(
            select_server_chain_12(&keys, KexType::EcdheEcdsa, false, &[ECDSA_P256_SHA256], &[]),
            Some(0)
        );
        // Static RSA needs no signature scheme at all.
        assert_eq!(
            select_server_chain_12(&keys, KexType::Rsa, false, &[ECDSA_P256_SHA256], &[]),
            Some(1)
        );
        // The family fits but the client accepts no RSA scheme.
        assert_eq!(
            select_server_chain_12(&keys, KexType::EcdheRsa, false, &[ECDSA_P256_SHA256], &[]),
            None
        );
        // A client that lists nothing gets the key's default (RFC 5246 7.4.1.4.1).
        assert_eq!(
            select_server_chain_12(&keys, KexType::EcdheEcdsa, false, &[], &[]),
            Some(0)
        );
        // PSK families need a PSK, not a chain.
        assert_eq!(
            select_server_chain_12(&keys, KexType::Psk, false, &[], &[]),
            None
        );
        assert_eq!(
            select_server_chain_12(&keys, KexType::Psk, true, &[], &[]),
            Some(0)
        );
    }

    #[test]
    fn tls13_server_picks_by_certificate_verify_scheme() {
        let keys = vec![
            key("client_ee_rsa"),
            key("client_ee"),
            key("client_ee_ed25519"),
        ];
        assert_eq!(select_server_chain_13(&keys, &[ECDSA_P256_SHA256]), Some(1));
        assert_eq!(
            select_server_chain_13(&keys, &[RSA_PSS_RSAE_SHA256]),
            Some(0)
        );
        assert_eq!(select_server_chain_13(&keys, &[ED25519]), Some(2));
        // Preference order: the first chain the client can take wins.
        assert_eq!(
            select_server_chain_13(&keys, &[ED25519, RSA_PSS_RSAE_SHA256]),
            Some(0)
        );
        // PKCS#1 v1.5 is not a TLS 1.3 signing scheme (RFC 8446 4.2.3).
        assert_eq!(select_server_chain_13(&keys, &[RSA_PKCS1_SHA256]), None);
    }

    #[test]
    fn client_picks_by_certificate_type_and_scheme() {
        let keys = vec![key("client_ee"), key("client_ee_rsa")];
        assert_eq!(
            select_client_credential_12(&keys, &[CLIENT_CERT_TYPE_RSA_SIGN], &[RSA_PKCS1_SHA256]),
            Some(1)
        );
        assert_eq!(
            select_client_credential_12(&keys, &[CLIENT_CERT_TYPE_ECDSA_SIGN], &[]),
            Some(0)
        );
        assert_eq!(
            select_client_credential_12(&keys, &[CLIENT_CERT_TYPE_RSA_SIGN], &[ECDSA_P256_SHA256]),
            None
        );
        assert_eq!(
            select_client_credential_12(
                &keys,
                &[CLIENT_CERT_TYPE_RSA_SIGN, CLIENT_CERT_TYPE_ECDSA_SIGN],
                &[ECDSA_P256_SHA256, RSA_PKCS1_SHA256]
            ),
            Some(0)
        );
        let keys13 = vec![
            key("client_ee"),
            key("client_ee_rsa"),
            key("client_ee_ed25519"),
        ];
        assert_eq!(select_client_credential_13(&keys13, &[ED25519]), Some(2));
        assert_eq!(
            select_client_credential_13(&keys13, &[RSA_PSS_RSAE_SHA256, ECDSA_P256_SHA256]),
            Some(0)
        );
    }
}
