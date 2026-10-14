//! A minimal OCSP responder for the shim servers' stapling (RFC 6960): a
//! signed `good` response for the server certificate `plzn run` generates,
//! issued by that certificate's own key (the test certificates are
//! self-signed, so the issuer and the responder are the certificate itself).
//! `uut server { ocsp_stapling: true }` makes `ShimConfig::for_program` write one
//! next to the certificate the shim loads (`credentials.ocsp_file`); the shim
//! staples it and plzn's client checks the CertificateStatus / TLS 1.3 leaf
//! status_request it gets back.
//!
//! DER is written by hand (tag, length, content); the certificate is parsed
//! with x509-cert for the issuer Name, serial and public key.

use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use crate::tls::crypto::{HashAlg, PrivateKey, SignatureScheme, hash};

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n < 0x1_0000 {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// `GeneralizedTime` for a Unix timestamp (UTC, whole seconds).
fn generalized_time(secs: u64) -> Vec<u8> {
    // Civil-from-days (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
    tlv(0x18, s.as_bytes())
}

/// The X.509 signature AlgorithmIdentifier and the TLS scheme plzn signs
/// with, for the certificate key's type.
fn signature_algorithm(pk: &PrivateKey) -> (Vec<u8>, SignatureScheme) {
    match pk.default_signature_scheme() {
        SignatureScheme::EcdsaSecp256r1Sha256 => (
            // ecdsa-with-SHA256, no parameters
            seq(&[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]),
            SignatureScheme::EcdsaSecp256r1Sha256,
        ),
        SignatureScheme::EcdsaSecp384r1Sha384 => (
            seq(&[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03])]),
            SignatureScheme::EcdsaSecp384r1Sha384,
        ),
        SignatureScheme::EcdsaSecp521r1Sha512 => (
            seq(&[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04])]),
            SignatureScheme::EcdsaSecp521r1Sha512,
        ),
        SignatureScheme::Ed25519 => (
            // id-Ed25519, no parameters
            seq(&[tlv(0x06, &[0x2b, 0x65, 0x70])]),
            SignatureScheme::Ed25519,
        ),
        _ => (
            // sha256WithRSAEncryption, NULL parameters
            seq(&[
                tlv(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
                ),
                tlv(0x05, &[]),
            ]),
            SignatureScheme::RsaPkcs1Sha256,
        ),
    }
}

/// A DER `OCSPResponse` (RFC 6960 4.2.1) saying `cert_der` is good,
/// signed by `key_pkcs8_der` (the certificate's own key: self-signed test
/// certificates are their own issuer and responder), valid from now for a
/// day, with the responder certificate attached.
pub fn good_response(
    cert_der: &[u8],
    key_pkcs8_der: &[u8],
    now_secs: u64,
) -> Result<Vec<u8>, String> {
    let cert = Certificate::from_der(cert_der).map_err(|e| format!("certificate: {}", e))?;
    let tbs = &cert.tbs_certificate;
    let issuer_der = tbs.issuer.to_der().map_err(|e| format!("issuer: {}", e))?;
    let spk = tbs.subject_public_key_info.subject_public_key.raw_bytes();
    let issuer_name_hash = hash(HashAlg::Sha1, &issuer_der);
    let issuer_key_hash = hash(HashAlg::Sha1, spk);
    let serial = tbs.serial_number.as_bytes();
    let pk = PrivateKey::from_pkcs8_der(key_pkcs8_der).map_err(|e| format!("key: {}", e))?;

    // CertID { hashAlgorithm sha1, issuerNameHash, issuerKeyHash, serialNumber }
    let sha1_alg = seq(&[tlv(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), tlv(0x05, &[])]);
    let cert_id = seq(&[
        sha1_alg,
        tlv(0x04, &issuer_name_hash),
        tlv(0x04, &issuer_key_hash),
        tlv(0x02, serial),
    ]);
    // SingleResponse { certID, certStatus good [0] IMPLICIT NULL, thisUpdate,
    // nextUpdate [0] EXPLICIT }
    let single = seq(&[
        cert_id,
        tlv(0x80, &[]),
        generalized_time(now_secs),
        tlv(0xa0, &generalized_time(now_secs + 86_400)),
    ]);
    // ResponseData { responderID byKey [2] EXPLICIT KeyHash, producedAt, responses }
    let tbs_response = seq(&[
        tlv(0xa2, &tlv(0x04, &issuer_key_hash)),
        generalized_time(now_secs),
        seq(&[single]),
    ]);
    let (sig_alg, scheme) = signature_algorithm(&pk);
    let signature = pk
        .sign(scheme, &tbs_response)
        .map_err(|e| format!("sign: {}", e))?;
    let mut bit_string = vec![0u8];
    bit_string.extend_from_slice(&signature);
    // BasicOCSPResponse { tbsResponseData, signatureAlgorithm, signature, certs [0] EXPLICIT }
    let basic = seq(&[
        tbs_response,
        sig_alg,
        tlv(0x03, &bit_string),
        tlv(0xa0, &seq(&[cert_der.to_vec()])),
    ]);
    // OCSPResponse { responseStatus successful, responseBytes [0] EXPLICIT { id-pkix-ocsp-basic, OCTET STRING } }
    let response_bytes = seq(&[
        tlv(
            0x06,
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
        ),
        tlv(0x04, &basic),
    ]);
    Ok(seq(&[tlv(0x0a, &[0]), tlv(0xa0, &response_bytes)]))
}

/// `good_response` at the current time.
pub fn good_response_now(cert_der: &[u8], key_pkcs8_der: &[u8]) -> Result<Vec<u8>, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    good_response(cert_der, key_pkcs8_der, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_formats_utc() {
        // 2026-09-08 00:00:00Z
        let t = generalized_time(1_788_825_600);
        assert_eq!(&t[2..], b"20260908000000Z");
        assert_eq!(&generalized_time(0)[2..], b"19700101000000Z");
    }

    #[test]
    fn good_response_parses_and_verifies_for_every_key_type() {
        use crate::server::certs::{CertBundle, KeyType};
        use crate::tls::crypto::PublicKey;
        for kt in [
            KeyType::Rsa2048,
            KeyType::EcdsaP256,
            KeyType::EcdsaP384,
            KeyType::Ed25519,
        ] {
            let bundle = CertBundle::generate(kt).unwrap();
            let der =
                good_response(&bundle.cert_der, &bundle.key_pkcs8_der, 1_788_998_400).unwrap();
            assert!(
                crate::tls::codec::ocsp_response_is_successful(&der),
                "{:?}",
                kt
            );
            // PLZN_OCSP_DUMP=<dir>: write the response and certificate out for
            // an external check (`openssl ocsp -respin ... -text`).
            if let Ok(dir) = std::env::var("PLZN_OCSP_DUMP") {
                let name = format!("{:?}", kt).to_lowercase();
                let _ = std::fs::write(format!("{}/{}.ocsp.der", dir, name), &der);
                let _ = std::fs::write(format!("{}/{}.cert.pem", dir, name), &bundle.cert_pem);
                let _ = std::fs::write(format!("{}/{}.key.pem", dir, name), &bundle.key_pem);
            }
            let pk = PublicKey::from_certificate_der(&bundle.cert_der).unwrap();
            let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
            let (_, scheme) = signature_algorithm(&sk);
            // Re-derive the signed input the way good_response built it and check.
            let cert = Certificate::from_der(&bundle.cert_der).unwrap();
            let issuer_der = cert.tbs_certificate.issuer.to_der().unwrap();
            let spk = cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let cert_id = seq(&[
                seq(&[tlv(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]), tlv(0x05, &[])]),
                tlv(0x04, &hash(HashAlg::Sha1, &issuer_der)),
                tlv(0x04, &hash(HashAlg::Sha1, spk)),
                tlv(0x02, cert.tbs_certificate.serial_number.as_bytes()),
            ]);
            let single = seq(&[
                cert_id,
                tlv(0x80, &[]),
                generalized_time(1_788_998_400),
                tlv(0xa0, &generalized_time(1_788_998_400 + 86_400)),
            ]);
            let tbs_response = seq(&[
                tlv(0xa2, &tlv(0x04, &hash(HashAlg::Sha1, spk))),
                generalized_time(1_788_998_400),
                seq(&[single]),
            ]);
            assert!(
                der.windows(tbs_response.len())
                    .any(|w| w == tbs_response.as_slice()),
                "{:?}: tbsResponseData not found in the response",
                kt
            );
            let sig = sk.sign(scheme, &tbs_response).unwrap();
            pk.verify(scheme, &tbs_response, &sig).unwrap();
        }
    }
}
