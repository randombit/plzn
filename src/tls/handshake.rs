// TLS 1.2 key schedule.
//
// This is a thin layer over the PRF helpers in `crypto.rs` that
// names the four derivations the driver needs: master_secret,
// extended-master-secret variant, the key block, and the
// verify_data for Finished.
//
// The actual byte-pumping primitives (P_hash, HMAC, hash) stay
// behind the crypto seam.

use crate::tls::crypto::{
    AeadAlg, AeadKey, CryptoError, HashAlg, TranscriptHash, hash, hkdf_expand_label,
    hkdf_expand_label_with_prefix, hkdf_extract, hmac, tls12_prf,
};
use crate::tls::record::TlsVersion;

fn legacy_prf(
    version: TlsVersion,
    prf_hash: HashAlg,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Vec<u8> {
    if matches!(version, TlsVersion::Tls10 | TlsVersion::Tls11) {
        crate::tls::crypto::tls10_prf(secret, label, seed, length)
    } else {
        tls12_prf(prf_hash, secret, label, seed, length)
    }
}

/// Derived traffic keys for a TLS 1.2 AEAD connection. No MAC keys
/// because AEAD suites don't have one.
#[derive(Clone)]
pub struct Tls12KeyBlock {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: [u8; 4], // GCM implicit nonce / "salt"
    pub server_write_iv: [u8; 4],
}

impl Tls12KeyBlock {
    pub fn build_client_aead_key(&self, alg: AeadAlg) -> Result<AeadKey, CryptoError> {
        AeadKey::new(alg, &self.client_write_key)
    }

    pub fn build_server_aead_key(&self, alg: AeadAlg) -> Result<AeadKey, CryptoError> {
        AeadKey::new(alg, &self.server_write_key)
    }
}

/// Derive the master secret from a pre-master secret + client/server
/// randoms (non-EMS path). RFC 5246 §8.1.
pub fn derive_master_secret(
    prf_hash: HashAlg,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    tls12_prf(prf_hash, pre_master_secret, b"master secret", &seed, 48)
}

pub fn derive_master_secret_for(
    version: TlsVersion,
    prf_hash: HashAlg,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    legacy_prf(
        version,
        prf_hash,
        pre_master_secret,
        b"master secret",
        &seed,
        48,
    )
}

/// Derive the master secret in Extended Master Secret mode
/// (RFC 7627 §4). `session_hash` is `Hash(transcript)` at the point
/// after ClientKeyExchange has been hashed in.
pub fn derive_master_secret_ems(
    prf_hash: HashAlg,
    pre_master_secret: &[u8],
    session_hash: &[u8],
) -> Vec<u8> {
    tls12_prf(
        prf_hash,
        pre_master_secret,
        b"extended master secret",
        session_hash,
        48,
    )
}

pub fn derive_master_secret_ems_for(
    version: TlsVersion,
    prf_hash: HashAlg,
    pre_master_secret: &[u8],
    session_hash: &[u8],
) -> Vec<u8> {
    legacy_prf(
        version,
        prf_hash,
        pre_master_secret,
        b"extended master secret",
        session_hash,
        48,
    )
}

/// Expand the master secret into a key block for an AEAD suite.
/// `key_len` is the per-direction AEAD key length (16 for AES-128-GCM,
/// 32 for AES-256-GCM). `iv_len` is the GCM salt length (fixed at 4
/// for AES-GCM in TLS 1.2).
pub fn derive_key_block_aead(
    prf_hash: HashAlg,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    key_len: usize,
    iv_len: usize,
) -> Tls12KeyBlock {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let total = 2 * key_len + 2 * iv_len;
    let block = tls12_prf(prf_hash, master_secret, b"key expansion", &seed, total);
    // Order (RFC 5246 §6.3): client_write_MAC_key, server_write_MAC_key,
    // client_write_key, server_write_key, client_write_IV, server_write_IV.
    // For AEAD the two MAC keys are zero-length, so we skip straight
    // to the write_keys.
    let client_key = block[..key_len].to_vec();
    let server_key = block[key_len..2 * key_len].to_vec();
    let mut client_iv = [0u8; 4];
    let mut server_iv = [0u8; 4];
    client_iv.copy_from_slice(&block[2 * key_len..2 * key_len + iv_len]);
    server_iv.copy_from_slice(&block[2 * key_len + iv_len..2 * key_len + 2 * iv_len]);
    assert_eq!(iv_len, 4, "wedge only supports GCM IV length");
    Tls12KeyBlock {
        client_write_key: client_key,
        server_write_key: server_key,
        client_write_iv: client_iv,
        server_write_iv: server_iv,
    }
}

/// Key block for a CBC suite. Order per RFC 5246 §6.3:
/// client_write_MAC_key, server_write_MAC_key,
/// client_write_key, server_write_key.
/// No IVs in the key block — CBC uses explicit per-record IVs.
#[derive(Clone)]
pub struct Tls12CbcKeyBlock {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
}

pub fn derive_key_block_cbc(
    prf_hash: HashAlg,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    mac_key_len: usize,
    enc_key_len: usize,
) -> Tls12CbcKeyBlock {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let total = 2 * mac_key_len + 2 * enc_key_len;
    let block = tls12_prf(prf_hash, master_secret, b"key expansion", &seed, total);
    let mut pos = 0;
    let client_mac = block[pos..pos + mac_key_len].to_vec();
    pos += mac_key_len;
    let server_mac = block[pos..pos + mac_key_len].to_vec();
    pos += mac_key_len;
    let client_key = block[pos..pos + enc_key_len].to_vec();
    pos += enc_key_len;
    let server_key = block[pos..pos + enc_key_len].to_vec();
    Tls12CbcKeyBlock {
        client_mac_key: client_mac,
        server_mac_key: server_mac,
        client_write_key: client_key,
        server_write_key: server_key,
    }
}

/// The complete TLS 1.2 key block (RFC 5246 6.3) for any suite: MAC keys
/// (empty for AEAD suites), encryption keys, and the implicit IVs (the 4-byte
/// GCM/CCM salt, the 12-byte ChaCha20-Poly1305 IV, empty for CBC and NULL).
#[derive(Clone)]
pub struct Tls12SuiteKeys {
    pub client_mac_key: Vec<u8>,
    pub server_mac_key: Vec<u8>,
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
}

pub fn derive_key_block(
    prf_hash: HashAlg,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    mac_key_len: usize,
    enc_key_len: usize,
    iv_len: usize,
) -> Tls12SuiteKeys {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let total = 2 * mac_key_len + 2 * enc_key_len + 2 * iv_len;
    let block = tls12_prf(prf_hash, master_secret, b"key expansion", &seed, total);
    let mut pos = 0;
    let mut take = |n: usize| {
        let v = block[pos..pos + n].to_vec();
        pos += n;
        v
    };
    Tls12SuiteKeys {
        client_mac_key: take(mac_key_len),
        server_mac_key: take(mac_key_len),
        client_write_key: take(enc_key_len),
        server_write_key: take(enc_key_len),
        client_write_iv: take(iv_len),
        server_write_iv: take(iv_len),
    }
}

/// Both directions' record keys for a negotiated TLS 1.2 suite, from the
/// master secret and randoms: `(client_writes, server_writes)`. The suite's
/// PRF hash (SHA-384 for *_SHA384 suites) drives the expansion.
pub fn tls12_direction_keys(
    suite: &crate::ir::SuiteInfo,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    etm: bool,
) -> Result<
    (
        crate::tls::record::DirectionKeys,
        crate::tls::record::DirectionKeys,
    ),
    CryptoError,
> {
    use crate::tls::record::DirectionKeys;
    let kb = derive_key_block(
        suite.prf,
        master_secret,
        server_random,
        client_random,
        suite.mac_key_len(),
        suite.cipher.key_len(),
        suite.cipher.implicit_iv_len(),
    );
    let client = DirectionKeys::for_tls12_suite(
        suite,
        kb.client_write_key,
        kb.client_mac_key,
        &kb.client_write_iv,
        etm,
    )?;
    let server = DirectionKeys::for_tls12_suite(
        suite,
        kb.server_write_key,
        kb.server_mac_key,
        &kb.server_write_iv,
        etm,
    )?;
    Ok((client, server))
}

pub fn legacy_direction_keys(
    version: TlsVersion,
    suite: &crate::ir::SuiteInfo,
    master_secret: &[u8],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    etm: bool,
) -> Result<
    (
        crate::tls::record::DirectionKeys,
        crate::tls::record::DirectionKeys,
    ),
    CryptoError,
> {
    if version == TlsVersion::Tls12 {
        return tls12_direction_keys(suite, master_secret, server_random, client_random, etm);
    }
    let iv_len = if version == TlsVersion::Tls10 && suite.cipher.is_cbc() {
        match suite.cipher {
            crate::ir::BulkCipher::TripleDesCbc => 8,
            _ => 16,
        }
    } else {
        suite.cipher.implicit_iv_len()
    };
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let mac_len = suite.mac_key_len();
    let key_len = suite.cipher.key_len();
    let block = legacy_prf(
        version,
        suite.prf,
        master_secret,
        b"key expansion",
        &seed,
        2 * (mac_len + key_len + iv_len),
    );
    let mut pos = 0;
    let mut take = |n: usize| {
        let out = block[pos..pos + n].to_vec();
        pos += n;
        out
    };
    let client_mac = take(mac_len);
    let server_mac = take(mac_len);
    let client_key = take(key_len);
    let server_key = take(key_len);
    let client_iv = take(iv_len);
    let server_iv = take(iv_len);
    Ok((
        crate::tls::record::DirectionKeys::for_legacy_suite(
            version, suite, client_key, client_mac, &client_iv, etm,
        )?,
        crate::tls::record::DirectionKeys::for_legacy_suite(
            version, suite, server_key, server_mac, &server_iv, etm,
        )?,
    ))
}

/// TLS 1.2 Finished `verify_data`.
///
/// `label` is `"client finished"` or `"server finished"`.
/// `transcript_hash` is the current digest of the transcript at
/// the point `verify_data` is needed.
pub fn compute_verify_data(
    prf_hash: HashAlg,
    master_secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    tls12_prf(prf_hash, master_secret, label, transcript_hash, 12)
}

pub fn compute_verify_data_for(
    version: TlsVersion,
    prf_hash: HashAlg,
    master_secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    legacy_prf(version, prf_hash, master_secret, label, transcript_hash, 12)
}

/// RFC 5705 exported keying material. An absent context and a present empty
/// context deliberately produce different seeds.
pub fn export_keying_material_tls12(
    prf_hash: HashAlg,
    master_secret: &[u8],
    label: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    context: Option<&[u8]>,
    length: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(66 + context.map_or(0, <[u8]>::len));
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if let Some(context) = context {
        seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
        seed.extend_from_slice(context);
    }
    tls12_prf(prf_hash, master_secret, label, &seed, length)
}

// Keep the RFC 5705 inputs explicit at call sites; combining the two randoms
// or label/context into an ad-hoc tuple would make their required ordering
// easier to misuse.
#[allow(clippy::too_many_arguments)]
pub fn export_keying_material_legacy(
    version: TlsVersion,
    prf_hash: HashAlg,
    master_secret: &[u8],
    label: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    context: Option<&[u8]>,
    length: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(66 + context.map_or(0, <[u8]>::len));
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if let Some(context) = context {
        seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
        seed.extend_from_slice(context);
    }
    legacy_prf(version, prf_hash, master_secret, label, &seed, length)
}

// ============================================================
//                     TLS 1.3 key schedule
// ============================================================

/// TLS 1.3 key-schedule state machine (RFC 8446 §7.1).
///
/// Stages, each driven by a single advance method:
///
///   * `new` → early_secret from all-zero PSK
///   * `advance_to_handshake` → handshake_secret from ECDHE, then
///     client/server handshake traffic secrets
///   * `advance_to_application` → master_secret, then client/server
///     application traffic secrets
///
/// Traffic-secret → (key, iv) expansion is exposed separately via
/// `traffic_key_iv` so the driver can hand them to the record layer.
pub struct Tls13KeySchedule {
    hash: HashAlg,
    is_dtls: bool,
    early_secret: Vec<u8>,
    handshake_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    exporter_master_secret: Option<Vec<u8>>,
    pub client_hs_traffic_secret: Option<Vec<u8>>,
    pub server_hs_traffic_secret: Option<Vec<u8>>,
    pub client_ap_traffic_secret: Option<Vec<u8>>,
    pub server_ap_traffic_secret: Option<Vec<u8>>,
}

impl Tls13KeySchedule {
    /// Start a new schedule with no PSK. The early secret is
    /// `HKDF-Extract(0, 0^hash_len)`.
    pub fn new(hash: HashAlg) -> Self {
        let zero_psk = vec![0u8; hash.output_len()];
        Self::with_psk(hash, &zero_psk)
    }

    pub fn new_dtls(hash: HashAlg) -> Self {
        let zero_psk = vec![0u8; hash.output_len()];
        Self::with_psk_dtls(hash, &zero_psk)
    }

    /// Start a new schedule with an external PSK. The early secret
    /// is `HKDF-Extract(0, psk)`.
    pub fn with_psk(hash: HashAlg, psk: &[u8]) -> Self {
        Self::with_psk_protocol(hash, psk, false)
    }

    pub fn with_psk_dtls(hash: HashAlg, psk: &[u8]) -> Self {
        Self::with_psk_protocol(hash, psk, true)
    }

    fn with_psk_protocol(hash: HashAlg, psk: &[u8], is_dtls: bool) -> Self {
        let salt = vec![0u8; hash.output_len()];
        let early_secret = hkdf_extract(hash, &salt, psk);
        Self {
            hash,
            is_dtls,
            early_secret,
            handshake_secret: None,
            master_secret: None,
            exporter_master_secret: None,
            client_hs_traffic_secret: None,
            server_hs_traffic_secret: None,
            client_ap_traffic_secret: None,
            server_ap_traffic_secret: None,
        }
    }

    fn expand(&self, secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
        if self.is_dtls {
            hkdf_expand_label_with_prefix(self.hash, secret, "dtls13", label, context, length)
        } else {
            hkdf_expand_label(self.hash, secret, label, context, length)
        }
    }

    fn derive(&self, secret: &[u8], label: &str, transcript: &TranscriptHash) -> Vec<u8> {
        self.expand(secret, label, &transcript.digest(), self.hash.output_len())
    }

    /// Derive the handshake secret + client/server handshake
    /// traffic secrets. `transcript` must be the hash of
    /// `ClientHello || ServerHello` at this point.
    pub fn advance_to_handshake(&mut self, ecdhe_shared: &[u8], transcript: &TranscriptHash) {
        // derived1 = Derive-Secret(early_secret, "derived", "")
        let empty_transcript = TranscriptHash::new(self.hash);
        let derived1 = self.derive(&self.early_secret, "derived", &empty_transcript);
        // handshake_secret = HKDF-Extract(derived1, (EC)DHE)
        let handshake_secret = hkdf_extract(self.hash, &derived1, ecdhe_shared);
        let client_hs_ts = self.derive(&handshake_secret, "c hs traffic", transcript);
        let server_hs_ts = self.derive(&handshake_secret, "s hs traffic", transcript);
        self.handshake_secret = Some(handshake_secret);
        self.client_hs_traffic_secret = Some(client_hs_ts);
        self.server_hs_traffic_secret = Some(server_hs_ts);
    }

    /// Derive the master secret + client/server application
    /// traffic secrets. `transcript` must be the hash of every
    /// handshake message up through the server's Finished.
    pub fn advance_to_application(&mut self, transcript: &TranscriptHash) {
        self.advance_to_application_with_digest(&transcript.digest());
    }

    /// Application key schedule from a precomputed transcript digest (must be the
    /// transcript through the SERVER's Finished, RFC 8446 7.1). In client-auth
    /// the live transcript at the client's Finished already includes the client's
    /// Certificate/CertificateVerify, so the digest must be snapshotted earlier.
    pub fn advance_to_application_with_digest(&mut self, transcript_digest: &[u8]) {
        let handshake_secret = self
            .handshake_secret
            .as_ref()
            .expect("advance_to_handshake must run first");
        let empty_transcript = TranscriptHash::new(self.hash);
        let derived2 = self.derive(handshake_secret, "derived", &empty_transcript);
        let zero_ikm = vec![0u8; self.hash.output_len()];
        let master_secret = hkdf_extract(self.hash, &derived2, &zero_ikm);
        let client_ap_ts = self.expand(
            &master_secret,
            "c ap traffic",
            transcript_digest,
            self.hash.output_len(),
        );
        let server_ap_ts = self.expand(
            &master_secret,
            "s ap traffic",
            transcript_digest,
            self.hash.output_len(),
        );
        let exporter_master_secret = self.expand(
            &master_secret,
            "exp master",
            transcript_digest,
            self.hash.output_len(),
        );
        self.master_secret = Some(master_secret);
        self.exporter_master_secret = Some(exporter_master_secret);
        self.client_ap_traffic_secret = Some(client_ap_ts);
        self.server_ap_traffic_secret = Some(server_ap_ts);
    }

    /// Expand a traffic secret into (key, iv) pair for an AEAD of
    /// the given algorithm.
    pub fn traffic_key_iv(
        &self,
        traffic_secret: &[u8],
        aead: AeadAlg,
    ) -> Result<(AeadKey, [u8; 12]), CryptoError> {
        let key_bytes = self.expand(traffic_secret, "key", &[], aead.key_len());
        let iv_bytes = self.expand(traffic_secret, "iv", &[], 12);
        let key = AeadKey::new(aead, &key_bytes)?;
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        Ok((key, iv))
    }

    /// DTLS 1.3's record-number key, absent for ordinary TLS 1.3.
    pub fn record_number_key(&self, traffic_secret: &[u8], aead: AeadAlg) -> Option<Vec<u8>> {
        self.is_dtls
            .then(|| self.expand(traffic_secret, "sn", &[], aead.key_len()))
    }

    pub fn direction_keys(
        &self,
        traffic_secret: &[u8],
        aead: AeadAlg,
    ) -> Result<crate::tls::record::DirectionKeys, CryptoError> {
        let (key, iv) = self.traffic_key_iv(traffic_secret, aead)?;
        Ok(match self.record_number_key(traffic_secret, aead) {
            Some(rn_key) => crate::tls::record::DirectionKeys::new_dtls13(key, iv, rn_key),
            None => crate::tls::record::DirectionKeys::new_tls13(key, iv),
        })
    }

    pub fn is_dtls(&self) -> bool {
        self.is_dtls
    }

    /// RFC 8446 section 7.5 / RFC 9147: exporter output from the exporter
    /// master secret captured at the server Finished transcript boundary.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Option<Vec<u8>> {
        let secret = self.exporter_master_secret.as_ref()?;
        let label = std::str::from_utf8(label).ok()?;
        if length > 255 * self.hash.output_len() {
            return None;
        }
        let empty_hash = hash(self.hash, &[]);
        let derived = self.expand(secret, label, &empty_hash, self.hash.output_len());
        let context_hash = hash(self.hash, context.unwrap_or_default());
        Some(self.expand(&derived, "exporter", &context_hash, length))
    }

    /// Compute TLS 1.3 Finished verify_data (RFC 8446 §4.4.4):
    ///
    ///   finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", hash_len)
    ///   verify_data  = HMAC(finished_key, transcript_hash)
    pub fn compute_finished(&self, traffic_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let finished_key = self.expand(traffic_secret, "finished", &[], self.hash.output_len());
        hmac(self.hash, &finished_key, transcript_hash)
    }

    pub fn hash_alg(&self) -> HashAlg {
        self.hash
    }

    /// Client early traffic secret (RFC 8446 7.1), derived from the PSK-based
    /// early secret and the transcript containing the final ClientHello.
    pub fn client_early_traffic_secret(&self, transcript: &TranscriptHash) -> Vec<u8> {
        self.derive(&self.early_secret, "c e traffic", transcript)
    }

    /// Derive the resumption master secret (RFC 8446 §7.1):
    ///
    ///   resumption_master_secret =
    ///       Derive-Secret(master_secret, "res master", transcript)
    ///
    /// `transcript` must include all handshake messages through
    /// the client's Finished.
    pub fn derive_resumption_master_secret(&self, transcript: &TranscriptHash) -> Vec<u8> {
        let master_secret = self
            .master_secret
            .as_ref()
            .expect("advance_to_application must run first");
        self.derive(master_secret, "res master", transcript)
    }

    /// Derive a resumption PSK from the resumption_master_secret and
    /// a ticket nonce (RFC 8446 §4.6.1):
    ///
    ///   PSK = HKDF-Expand-Label(resumption_master_secret,
    ///                            "resumption", ticket_nonce, Hash.length)
    pub fn derive_resumption_psk(
        &self,
        resumption_master_secret: &[u8],
        ticket_nonce: &[u8],
    ) -> Vec<u8> {
        self.expand(
            resumption_master_secret,
            "resumption",
            ticket_nonce,
            self.hash.output_len(),
        )
    }

    /// Compute a PSK binder value (RFC 8446 §4.2.11.2):
    ///
    ///   binder_key = Derive-Secret(early_secret, "ext binder" | "res binder", "")
    ///   finished_key = HKDF-Expand-Label(binder_key, "finished", "", hash_len)
    ///   binder = HMAC(finished_key, transcript_hash_truncated)
    pub fn compute_binder(&self, transcript_hash: &[u8], is_external: bool) -> Vec<u8> {
        let label = if is_external {
            "ext binder"
        } else {
            "res binder"
        };
        let empty_transcript = TranscriptHash::new(self.hash);
        let binder_key = self.derive(&self.early_secret, label, &empty_transcript);
        let finished_key = self.expand(&binder_key, "finished", &[], self.hash.output_len());
        hmac(self.hash, &finished_key, transcript_hash)
    }

    /// Rotate an application traffic secret per RFC 8446 §7.2:
    /// `application_traffic_secret_N+1 =
    ///     HKDF-Expand-Label(secret_N, "traffic upd", "", Hash.length)`
    pub fn rotate_traffic_secret(&self, current: &[u8]) -> Vec<u8> {
        self.expand(current, "traffic upd", &[], self.hash.output_len())
    }
}

/// Replace the running transcript with the synthetic message_hash
/// construct for HRR (RFC 8446 §4.4.1):
///
/// ```text
/// transcript = Hash(
///   message_hash(254) || length(hash_len) || Hash(CH1) ||
///   ... HRR bytes ...
/// )
/// ```
///
/// After this, the transcript covers: synthetic(CH1) || HRR.
/// The caller then feeds CH2 + SH + ... as usual.
pub fn replace_transcript_for_hrr(
    transcript: &mut TranscriptHash,
    ch1_hash: &[u8],
    hrr_framed: &[u8],
    hash: HashAlg,
) {
    // Build the synthetic message_hash message:
    //   type=254, length=hash_len, body=Hash(CH1)
    let hash_len = hash.output_len();
    let mut synthetic = Vec::with_capacity(4 + hash_len);
    synthetic.push(crate::tls::codec::HS_MESSAGE_HASH);
    // 3-byte length
    synthetic.push(0);
    synthetic.push(0);
    synthetic.push(hash_len as u8);
    synthetic.extend_from_slice(ch1_hash);

    // Reset the transcript and feed the synthetic + HRR.
    *transcript = TranscriptHash::new(hash);
    transcript.update(&synthetic);
    transcript.update(hrr_framed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_block_splits_as_expected() {
        // Synthetic but deterministic: construct a 40-byte key block
        // and make sure the slicing matches RFC ordering.
        let ms = [0xaau8; 48];
        let cr = [0x01u8; 32];
        let sr = [0x02u8; 32];
        let kb = derive_key_block_aead(HashAlg::Sha256, &ms, &sr, &cr, 16, 4);
        assert_eq!(kb.client_write_key.len(), 16);
        assert_eq!(kb.server_write_key.len(), 16);
        assert_eq!(kb.client_write_iv.len(), 4);
        assert_eq!(kb.server_write_iv.len(), 4);
        // Deterministic: same inputs give the same bytes.
        let kb2 = derive_key_block_aead(HashAlg::Sha256, &ms, &sr, &cr, 16, 4);
        assert_eq!(kb.client_write_key, kb2.client_write_key);
        assert_eq!(kb.server_write_key, kb2.server_write_key);
    }

    #[test]
    fn verify_data_is_twelve_bytes() {
        let ms = [0x00u8; 48];
        let hh = [0x11u8; 32];
        let vd = compute_verify_data(HashAlg::Sha256, &ms, b"client finished", &hh);
        assert_eq!(vd.len(), 12);
    }

    #[test]
    fn tls10_master_secret_matches_gnutls_vector() {
        // The GnuTLS-derived TLS 1.0 key-schedule vector also used by Go's
        // crypto/tls tests. This checks the combined MD5/SHA-1 PRF rather than
        // merely comparing two paths through plzn's implementation.
        let decode = crate::tls::crypto::hex_to_bytes;
        let premaster = decode(
            "0302cac83ad4b1db3b9ab49ad05957de2a504a634a386fc600889321e1a971f57\
             479466830ac3e6f468e87f5385fa0c5",
        );
        let client_random =
            decode("4ae66303755184a3917fcb44880605fcc53baa01912b22ed94473fc69cebd558");
        let server_random =
            decode("4ae663020ec16e6bb5130be918cfcafd4d765979a3136a5d50c593446e4e44db");
        let client_random: [u8; 32] = client_random.try_into().unwrap();
        let server_random: [u8; 32] = server_random.try_into().unwrap();
        assert_eq!(
            derive_master_secret_for(
                TlsVersion::Tls10,
                HashAlg::Sha256,
                &premaster,
                &client_random,
                &server_random,
            ),
            decode(
                "3d851bab6e5556e959a16bc36d66cfae32f672bfa9ecdef6096cbb1b23472df1d\
                 a63dbbd9827606413221d149ed08ceb"
            )
        );
    }

    #[test]
    fn oversized_tls13_exporter_is_rejected_without_panicking() {
        let mut schedule = Tls13KeySchedule::new(HashAlg::Sha256);
        let transcript = TranscriptHash::new(HashAlg::Sha256);
        schedule.advance_to_handshake(&[0x42; 32], &transcript);
        schedule.advance_to_application(&transcript);
        assert!(
            schedule
                .export_keying_material(b"label", None, 255 * 32)
                .is_some()
        );
        assert!(
            schedule
                .export_keying_material(b"label", None, 255 * 32 + 1)
                .is_none()
        );
    }
}
