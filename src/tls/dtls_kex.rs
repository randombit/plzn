//! Helpers shared by plzn's two DTLS 1.2 drivers that the TLS 1.2 drivers
//! keep private or do not have: the TLS 1.2 CertificateRequest codec (RFC 5246
//! 7.4.4), signature-scheme selection against a key, the DTLS ClientHello and
//! ClientKeyExchange field overrides, the RFC 4279 premaster, and the default
//! client credential a `uut server` client-auth flow presents.

use crate::ir::{FieldOverride, FieldValue};
use crate::tls::codec::{ByteCursor, ByteWriter, CodecError};
use crate::tls::crypto::{PrivateKey, SignatureScheme};
use crate::tls::driver::TlsError;
use crate::tls::dtls_handshake::DtlsClientHello;

/// RFC 5246 7.4.4 ClientCertificateType values plzn's servers request.
pub const CERT_TYPE_RSA_SIGN: u8 = 1;
pub const CERT_TYPE_ECDSA_SIGN: u8 = 64;

/// The signature schemes plzn's DTLS peers advertise and verify (every scheme
/// `PublicKey::verify` implements), in preference order.
pub const VERIFY_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::EcdsaSecp256r1Sha256,
    SignatureScheme::EcdsaSecp384r1Sha384,
    SignatureScheme::EcdsaSecp521r1Sha512,
    SignatureScheme::Ed25519,
    SignatureScheme::RsaPssRsaeSha256,
    SignatureScheme::RsaPssRsaeSha384,
    SignatureScheme::RsaPssRsaeSha512,
    SignatureScheme::RsaPkcs1Sha256,
    SignatureScheme::RsaPkcs1Sha384,
    SignatureScheme::RsaPkcs1Sha512,
];

pub fn verify_scheme_wires() -> Vec<u16> {
    VERIFY_SCHEMES.iter().map(|s| s.wire_value()).collect()
}

/// A parsed TLS 1.2 / DTLS 1.2 CertificateRequest.
pub struct CertificateRequest12 {
    pub certificate_types: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    /// DER DistinguishedNames (may be empty: any CA).
    pub authorities: Vec<Vec<u8>>,
}

/// Encode a CertificateRequest body (RFC 5246 7.4.4):
/// `certificate_types<1..2^8-1> supported_signature_algorithms<2..2^16-2>
/// certificate_authorities<0..2^16-1>`.
pub fn encode_certificate_request_12(
    types: &[u8],
    sigalgs: &[u16],
    authorities: &[&[u8]],
) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u8_vec(types);
    let mut algs = ByteWriter::new();
    for a in sigalgs {
        algs.u16(*a);
    }
    w.u16_vec(&algs.into_vec());
    let mut cas = ByteWriter::new();
    for ca in authorities {
        cas.u16_vec(ca);
    }
    w.u16_vec(&cas.into_vec());
    w.into_vec()
}

pub fn parse_certificate_request_12(body: &[u8]) -> Result<CertificateRequest12, CodecError> {
    let mut c = ByteCursor::new(body);
    let certificate_types = c.u8_vec()?.to_vec();
    let alg_bytes = c.u16_vec()?.to_vec();
    if alg_bytes.len() % 2 != 0 {
        return Err(CodecError::UnexpectedEof);
    }
    let signature_algorithms = alg_bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect();
    let ca_bytes = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    let mut authorities = Vec::new();
    let mut cc = ByteCursor::new(&ca_bytes);
    while !cc.is_empty() {
        authorities.push(cc.u16_vec()?.to_vec());
    }
    Ok(CertificateRequest12 {
        certificate_types,
        signature_algorithms,
        authorities,
    })
}

/// The first scheme the peer listed that `key` can sign with; the key's own
/// first preference when the peer listed none it can use (RFC 5246 7.4.1.4.1
/// defaults to SHA-1; plzn's floor is SHA-256, which every peer in the corpus
/// accepts) or sent no signature_algorithms at all.
pub fn select_signature_scheme(key: &PrivateKey, offered: &[u16]) -> SignatureScheme {
    let mine = key.signature_schemes();
    offered
        .iter()
        .find_map(|w| mine.iter().copied().find(|s| s.wire_value() == *w))
        .unwrap_or(mine[0])
}

/// RFC 4279 2: for a pure-PSK ciphersuite the premaster secret is
/// `uint16(len(psk)) || zeros[len(psk)] || uint16(len(psk)) || psk`.
pub fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let n = psk.len();
    let mut out = Vec::with_capacity(4 + 2 * n);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, n));
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(psk);
    out
}

/// The client credential plzn's DTLS client presents when a server requests one
/// and the program carries none: the same end-entity certificate the shim
/// clients get (`shims/testdata/client_ee_cert.der`, chained to
/// `client_ee_ca.pem`, which `ShimConfig::for_program` hands a shim server to
/// trust). `(cert_der, key_pkcs8_der)`.
pub fn default_client_credential() -> Option<(Vec<u8>, Vec<u8>)> {
    named_client_credential("valid")
}

/// A `send Certificate { credential: NAME }` selector: the testdata credential
/// plzn's OWN client presents (TLS 1.2 and DTLS client roles). `valid` is the
/// CA-issued end-entity a server accepts (`client_ee_*`, the default), `untrusted`
/// a self-signed chain a server rejects with unknown_ca. `Some((cert, key))` names
/// a credential; `None` (for `none`, or an absent/unknown name) means the client
/// sends an empty certificate_list with no key.
pub fn named_client_credential(name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (cert, key) = match name {
        "valid" | "ecdsa_p256" => ("client_ee_cert.der", "client_ee_key.pkcs8.der"),
        "rsa" => ("client_ee_rsa_cert.der", "client_ee_rsa_key.pkcs8.der"),
        "rsa_pss" => (
            "client_ee_rsa_pss_cert.der",
            "client_ee_rsa_pss_key.pkcs8.der",
        ),
        "ecdsa_p384" => (
            "client_ee_ecdsa_p384_cert.der",
            "client_ee_ecdsa_p384_key.pkcs8.der",
        ),
        "ecdsa_p521" => (
            "client_ee_ecdsa_p521_cert.der",
            "client_ee_ecdsa_p521_key.pkcs8.der",
        ),
        "ed25519" => (
            "client_ee_ed25519_cert.der",
            "client_ee_ed25519_key.pkcs8.der",
        ),
        "untrusted" => (
            "untrusted_client_cert.der",
            "untrusted_client_key.pkcs8.der",
        ),
        _ => return None, // "none"
    };
    Some((
        crate::fixtures::read(cert).ok()?.to_vec(),
        crate::fixtures::read(key).ok()?.to_vec(),
    ))
}

/// A resolved `credential` selector: the certificate_list entries and the key
/// the CertificateVerify signs with (`None` = no key, no CertificateVerify).
pub type SelectedCredential = (Vec<Vec<u8>>, Option<Vec<u8>>);

/// Resolve a `send Certificate { credential: ... }` override on plzn's client to
/// `(cert_list, key_der)`: an empty list and no key for `none` (or a load
/// failure); a single-entry list and its key otherwise. `None` when the flow
/// declares no `credential` override (the driver keeps its configured default).
pub fn client_credential_override(overrides: &[FieldOverride]) -> Option<SelectedCredential> {
    for ov in overrides {
        if ov.field == "credential" {
            if let FieldValue::Ident(name) = &ov.value {
                return Some(match named_client_credential(name) {
                    Some((cert, key)) => (vec![cert], Some(key)),
                    None => (Vec::new(), None),
                });
            }
        }
    }
    None
}

/// Apply one `send ClientHello { field: value }` override to a DTLS ClientHello
/// under construction. Same vocabulary as the TLS client's (`legacy_version`,
/// `random`, `legacy_session_id`, `cipher_suites` / `ciphers`,
/// `compression_methods`, `extensions`), plus the DTLS `cookie`.
pub fn apply_dtls_client_hello_override(
    ch: &mut DtlsClientHello,
    ov: &FieldOverride,
) -> Result<(), TlsError> {
    match (ov.field.as_str(), &ov.value) {
        ("legacy_version", FieldValue::U16(v)) => ch.client_version = *v,
        ("cipher_suites", FieldValue::U16List(v)) | ("ciphers", FieldValue::U16List(v)) => {
            ch.cipher_suites = v.clone()
        }
        ("legacy_compression_methods", FieldValue::U8List(v))
        | ("compression_methods", FieldValue::U8List(v)) => ch.compression_methods = v.clone(),
        ("legacy_session_id", FieldValue::Bytes(v)) => ch.session_id = v.clone(),
        ("cookie", FieldValue::Bytes(v)) => ch.cookie = v.clone(),
        ("random", FieldValue::Bytes(v)) => {
            if v.len() != 32 {
                return Err(TlsError::Internal(
                    "ClientHello.random override must be exactly 32 bytes",
                ));
            }
            ch.random.copy_from_slice(v);
        }
        // Raw extension entries (no outer length); the encoder re-adds it.
        ("extensions", FieldValue::Bytes(v)) => ch.extensions = v.clone(),
        // Consumed by the key-exchange builder.
        ("key_share_point", _) => {}
        _ => {
            return Err(TlsError::UnknownFieldOverride {
                message: "ClientHello",
                field: ov.field.clone(),
            });
        }
    }
    Ok(())
}

/// A `send Certificate { certificate_list: ... }` override: empty bytes = an
/// empty certificate_list (the "no certificate" answer, RFC 5246 7.4.6), any
/// other bytes = one DER certificate entry.
pub fn certificate_list_override(
    overrides: &[FieldOverride],
) -> Result<Option<Vec<Vec<u8>>>, TlsError> {
    for ov in overrides {
        match (ov.field.as_str(), &ov.value) {
            ("certificate_list", FieldValue::Bytes(v)) => {
                return Ok(Some(if v.is_empty() {
                    Vec::new()
                } else {
                    vec![v.clone()]
                }));
            }
            // Handled by `client_credential_override` at the call site.
            ("credential", _) => {}
            ("certificate_request_context", _) => {}
            // Handled by the DTLS server's Certificate sender: repeat its
            // configured leaf to build deliberately large certificate lists.
            ("entries", _) => {}
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Certificate",
                    field: ov.field.clone(),
                });
            }
        }
    }
    Ok(None)
}

/// `send Finished { verify_data: BYTES }` on either DTLS driver: the override
/// replaces the computed verify_data outright (the TLS 1.2 drivers' rule).
/// Anything else named on Finished is an unknown override.
pub(crate) fn finished_verify_data_override(
    overrides: &[crate::ir::FieldOverride],
    computed: Vec<u8>,
) -> Result<Vec<u8>, TlsError> {
    let mut vd = computed;
    for ov in overrides {
        match (ov.field.as_str(), &ov.value) {
            ("verify_data", crate::ir::FieldValue::Bytes(v)) => vd = v.clone(),
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Finished",
                    field: ov.field.clone(),
                });
            }
        }
    }
    Ok(vd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_request_12_round_trips() {
        let body = encode_certificate_request_12(
            &[CERT_TYPE_ECDSA_SIGN, CERT_TYPE_RSA_SIGN],
            &[0x0403, 0x0804],
            &[&[0x30, 0x03, 0x02, 0x01, 0x01]],
        );
        let cr = parse_certificate_request_12(&body).unwrap();
        assert_eq!(cr.certificate_types, vec![64, 1]);
        assert_eq!(cr.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(cr.authorities.len(), 1);
        // No authorities: the CA vector is an empty u16-length list.
        let body = encode_certificate_request_12(&[1], &[0x0401], &[]);
        assert_eq!(&body[body.len() - 2..], &[0, 0]);
        assert!(parse_certificate_request_12(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn psk_premaster_layout() {
        let pms = psk_premaster(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(pms, vec![0, 3, 0, 0, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn scheme_selection_follows_the_peer_list_then_the_key() {
        let key = PrivateKey::from_pkcs8_der(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/shims/testdata/client_ee_key.pkcs8.der"
            ))
            .unwrap(),
        )
        .unwrap();
        // An ECDSA P-256 key signs only ecdsa_secp256r1_sha256, whatever else is offered.
        assert_eq!(
            select_signature_scheme(&key, &[0x0804, 0x0403]),
            SignatureScheme::EcdsaSecp256r1Sha256
        );
        assert_eq!(
            select_signature_scheme(&key, &[0x0804]),
            SignatureScheme::EcdsaSecp256r1Sha256
        );
        assert_eq!(
            select_signature_scheme(&key, &[]),
            SignatureScheme::EcdsaSecp256r1Sha256
        );
    }
}
