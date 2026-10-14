// The sole point of contact between plzn and RustCrypto.
//
// Rules:
//
//   * Every import of `aes_gcm`, `hmac`, `hkdf`, `num_bigint`, `p256`, `x25519_dalek`,
//     `rsa`, `sha2`, `rand_chacha`, `rand_core`, `x509_cert` lives in
//     this file. No other file in the crate may name those crates.
//   * Public types are plzn-owned: enum-tagged wrappers that hide
//     generic parameters and trait-heavy APIs. Callers never see a
//     `GenericArray` or a `Hmac<Sha256>`.
//   * Functions are the direct-style primitives the rest of the TLS
//     stack needs: hash_update, hkdf_expand_label, aead_seal/open,
//     ecdhe_generate/agree. No builder patterns.
//
// If a caller outside this file needs a new primitive, add it here
// rather than pulling in the underlying crate.

#![allow(dead_code)] // seam lands before all callers exist

use std::fmt;
use std::sync::Arc;

use aes::cipher::BlockEncrypt;
use aes_gcm::aead::consts::{U8, U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use md5::Md5;
use num_bigint::BigUint;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::VerifyingKey as RsaPkcs1VerifyingKey;
use rsa::pss::VerifyingKey as RsaPssVerifyingKey;
use rsa::signature::Verifier as _;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::asn1::ObjectIdentifier;

// ============================================================
//                            Errors
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    AeadSealFailed,
    AeadOpenFailed,
    BadKeyLength,
    BadNonceLength,
    BadPublicKey,
    BadSignature,
    UnsupportedSuite,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::AeadSealFailed => write!(f, "AEAD seal failed"),
            CryptoError::AeadOpenFailed => write!(f, "AEAD open failed (bad tag or ciphertext)"),
            CryptoError::BadKeyLength => write!(f, "bad symmetric key length"),
            CryptoError::BadNonceLength => write!(f, "bad AEAD nonce length"),
            CryptoError::BadPublicKey => write!(f, "bad public key encoding"),
            CryptoError::BadSignature => write!(f, "signature verification failed"),
            CryptoError::UnsupportedSuite => write!(f, "unsupported cipher suite / group"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ============================================================
//                        Deterministic RNG
// ============================================================

/// Seedable RNG used for every randomised value in a test (client
/// random, ephemeral keys, nonces where we get to pick them). Per
/// `DSL.md §4.1` the seed is derived from `hash(test_id ||
/// global_seed)`; per `§7` each consumer gets its own *sub-seed*
/// so that adding a new random consumer doesn't shift unrelated
/// downstream values.
pub struct Rng {
    inner: ChaCha20Rng,
}

impl Rng {
    /// Seed from a 32-byte value.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: ChaCha20Rng::from_seed(seed),
        }
    }

    /// Derive a sub-seed from the given label.
    ///
    /// `sub_seed(parent, "client_random")` gives a stable 32-byte
    /// value that is independent of any other sub-seed derived from
    /// the same parent.
    pub fn sub_seed(parent: [u8; 32], label: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(parent);
        h.update([0u8]); // delimiter; parents are 32 bytes so unambiguous
        h.update(label);
        let out = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&out);
        seed
    }

    pub fn fill(&mut self, dst: &mut [u8]) {
        self.inner.fill_bytes(dst);
    }

    pub fn random_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.inner.fill_bytes(&mut out);
        out
    }
}

// ============================================================
//                        Hashes (transcript)
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }
}

/// Running hash of the handshake transcript. Clonable mid-handshake
/// because TLS 1.2's Finished and CertificateVerify need snapshots.
#[derive(Clone)]
pub enum TranscriptHash {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHash {
    pub fn new(alg: HashAlg) -> Self {
        match alg {
            HashAlg::Sha256 => TranscriptHash::Sha256(Sha256::new()),
            HashAlg::Sha384 => TranscriptHash::Sha384(Sha384::new()),
            HashAlg::Sha1 => panic!("SHA-1 is not used for transcript hashing"),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            TranscriptHash::Sha256(h) => h.update(bytes),
            TranscriptHash::Sha384(h) => h.update(bytes),
        }
    }

    /// Snapshot the current transcript digest without consuming it.
    pub fn digest(&self) -> Vec<u8> {
        match self {
            TranscriptHash::Sha256(h) => h.clone().finalize().to_vec(),
            TranscriptHash::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }

    pub fn alg(&self) -> HashAlg {
        match self {
            TranscriptHash::Sha256(_) => HashAlg::Sha256,
            TranscriptHash::Sha384(_) => HashAlg::Sha384,
        }
    }
}

/// One-shot hash of a single buffer.
pub fn hash(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => Sha1::digest(data).to_vec(),
        HashAlg::Sha256 => Sha256::digest(data).to_vec(),
        HashAlg::Sha384 => Sha384::digest(data).to_vec(),
    }
}

// ============================================================
//                            HMAC
// ============================================================

pub fn hmac(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha1 => {
            let mut m =
                <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HashAlg::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key)
                .expect("HMAC-SHA256 accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HashAlg::Sha384 => {
            let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key)
                .expect("HMAC-SHA384 accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

// ============================================================
//                 HKDF-Expand-Label (TLS 1.3)
// ============================================================

/// TLS 1.3 `HKDF-Expand-Label` (RFC 8446 §7.1).
///
/// `HkdfLabel = { length, "tls13 " || label, context }`.
pub fn hkdf_expand_label(
    alg: HashAlg,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    hkdf_expand_label_with_prefix(alg, secret, "tls13 ", label, context, length)
}

/// HKDF-Expand-Label with an explicit protocol prefix. DTLS 1.3 uses
/// `"dtls13"` where TLS 1.3 uses `"tls13"` (RFC 9147 section 5.10).
pub fn hkdf_expand_label_with_prefix(
    alg: HashAlg,
    secret: &[u8],
    prefix: &str,
    label: &str,
    context: &[u8],
    length: usize,
) -> Vec<u8> {
    // Serialize the HkdfLabel structure inline.
    let mut info = Vec::with_capacity(4 + label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    let full_label = format!("{}{}", prefix, label);
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; length];
    match alg {
        HashAlg::Sha256 => {
            let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("secret >= hash output len");
            hkdf.expand(&info, &mut out)
                .expect("length fits HKDF-Expand output");
        }
        HashAlg::Sha384 => {
            let hkdf = Hkdf::<Sha384>::from_prk(secret).expect("secret >= hash output len");
            hkdf.expand(&info, &mut out)
                .expect("length fits HKDF-Expand output");
        }
        HashAlg::Sha1 => panic!("HKDF not supported with SHA-1"),
    }
    out
}

/// DTLS 1.3 record-number encryption mask (RFC 9147 section 4.2.3).
/// AES suites encrypt the first 16 ciphertext bytes as one ECB block;
/// ChaCha20 interprets the first four sample bytes as a little-endian block
/// counter and the following twelve as its nonce.
pub fn dtls13_record_number_mask(
    alg: AeadAlg,
    key: &[u8],
    sample: &[u8],
) -> Result<[u8; 2], CryptoError> {
    if sample.len() < 16 {
        return Err(CryptoError::AeadOpenFailed);
    }
    let mut mask = [0u8; 2];
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes128Ccm | AeadAlg::Aes128Ccm8 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
            let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(&sample[..16]);
            cipher.encrypt_block(&mut block);
            mask.copy_from_slice(&block[..2]);
        }
        AeadAlg::Aes256Gcm | AeadAlg::Aes256Ccm | AeadAlg::Aes256Ccm8 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
            let mut block = aes::cipher::Block::<aes::Aes256>::clone_from_slice(&sample[..16]);
            cipher.encrypt_block(&mut block);
            mask.copy_from_slice(&block[..2]);
        }
        AeadAlg::ChaCha20Poly1305 => {
            let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
            mask.copy_from_slice(&chacha20_block_prefix(key, counter, &sample[4..16])?);
        }
        _ => return Err(CryptoError::UnsupportedSuite),
    }
    Ok(mask)
}

/// The first two bytes of the RFC 8439 ChaCha20 block function. Calling the
/// stream-cipher seek API at counter `u32::MAX` is not safe: producing even a
/// partial block makes that API advance its 32-bit block counter and panic.
fn chacha20_block_prefix(key: &[u8], counter: u32, nonce: &[u8]) -> Result<[u8; 2], CryptoError> {
    let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::BadKeyLength)?;
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::BadNonceLength)?;
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (word, bytes) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    state[12] = counter;
    for (word, bytes) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let first = state[0].wrapping_add(initial[0]).to_le_bytes();
    Ok([first[0], first[1]])
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// TLS 1.3 `HKDF-Extract` (RFC 8446 §7.1). Returns a secret whose
/// length equals the hash output.
pub fn hkdf_extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            prk.to_vec()
        }
        HashAlg::Sha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
            prk.to_vec()
        }
        HashAlg::Sha1 => panic!("HKDF not supported with SHA-1"),
    }
}

/// TLS 1.3 `Derive-Secret(secret, label, transcript)`.
pub fn derive_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &str,
    transcript: &TranscriptHash,
) -> Vec<u8> {
    let ctx = transcript.digest();
    hkdf_expand_label(alg, secret, label, &ctx, alg.output_len())
}

/// Like `derive_secret` but with a precomputed transcript digest. Needed when
/// the required transcript point differs from the live transcript (e.g. TLS 1.3
/// application secrets derive from the transcript through the server's Finished,
/// which precedes the client's own Certificate/CertificateVerify in client-auth).
pub fn derive_secret_from_digest(
    alg: HashAlg,
    secret: &[u8],
    label: &str,
    digest: &[u8],
) -> Vec<u8> {
    hkdf_expand_label(alg, secret, label, digest, alg.output_len())
}

// ============================================================
//                    TLS 1.2 P_hash PRF
// ============================================================

/// TLS 1.2 `P_<hash>` function (RFC 5246 §5). Generates `length`
/// bytes from `(secret, seed)`.
pub fn tls12_prf(alg: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    // labeled_seed = label || seed
    let mut labeled_seed = Vec::with_capacity(label.len() + seed.len());
    labeled_seed.extend_from_slice(label);
    labeled_seed.extend_from_slice(seed);

    let mut out = Vec::with_capacity(length);
    // A(0) = seed; A(i) = HMAC(secret, A(i-1))
    let mut a = hmac(alg, secret, &labeled_seed);
    while out.len() < length {
        // output chunk = HMAC(secret, A(i) || labeled_seed)
        let mut input = Vec::with_capacity(a.len() + labeled_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&labeled_seed);
        let chunk = hmac(alg, secret, &input);
        let take = (length - out.len()).min(chunk.len());
        out.extend_from_slice(&chunk[..take]);
        // advance A
        a = hmac(alg, secret, &a);
    }
    out
}

fn p_hash_md5(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mac = |data: &[u8]| {
        let mut m =
            <Hmac<Md5> as Mac>::new_from_slice(secret).expect("HMAC-MD5 accepts any key length");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(length);
    let mut a = mac(seed);
    while out.len() < length {
        let mut input = a.clone();
        input.extend_from_slice(seed);
        let chunk = mac(&input);
        out.extend_from_slice(&chunk[..(length - out.len()).min(chunk.len())]);
        a = mac(&a);
    }
    out
}

/// TLS 1.0/1.1 PRF (RFC 2246 section 5): P_MD5 over the first half of the
/// secret XOR P_SHA-1 over the second half. Odd-length secrets share the
/// middle byte between both halves.
pub fn tls10_prf(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut labeled_seed = Vec::with_capacity(label.len() + seed.len());
    labeled_seed.extend_from_slice(label);
    labeled_seed.extend_from_slice(seed);
    let half = secret.len().div_ceil(2);
    let md5 = p_hash_md5(&secret[..half], &labeled_seed, length);
    let sha1 = tls12_prf(
        HashAlg::Sha1,
        &secret[secret.len() - half..],
        &[],
        &labeled_seed,
        length,
    );
    md5.into_iter().zip(sha1).map(|(a, b)| a ^ b).collect()
}

/// TLS 1.0/1.1 handshake digest: MD5(handshake_messages) || SHA-1(...).
pub fn tls10_transcript_digest(transcript: &[u8]) -> Vec<u8> {
    let mut out = Md5::digest(transcript).to_vec();
    out.extend_from_slice(&Sha1::digest(transcript));
    out
}

// ============================================================
//                            AEADs
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    /// RFC 6655 AES-CCM with a 16-byte tag.
    Aes128Ccm,
    Aes256Ccm,
    /// RFC 6655 AES-CCM_8: an 8-byte tag.
    Aes128Ccm8,
    Aes256Ccm8,
    /// RFC 6209 ARIA-GCM (the GCM construction over the ARIA block cipher).
    Aria128Gcm,
    Aria256Gcm,
    /// RFC 6367 Camellia-GCM.
    Camellia128Gcm,
    Camellia256Gcm,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm
            | AeadAlg::Aes128Ccm
            | AeadAlg::Aes128Ccm8
            | AeadAlg::Aria128Gcm
            | AeadAlg::Camellia128Gcm => 16,
            AeadAlg::Aes256Gcm
            | AeadAlg::Aes256Ccm
            | AeadAlg::Aes256Ccm8
            | AeadAlg::Aria256Gcm
            | AeadAlg::Camellia256Gcm
            | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }
    pub fn nonce_len(self) -> usize {
        12
    }
    pub fn tag_len(self) -> usize {
        match self {
            AeadAlg::Aes128Ccm8 | AeadAlg::Aes256Ccm8 => 8,
            _ => 16,
        }
    }
}

// The generic GCM and CCM constructions from the RustCrypto AEAD crates,
// instantiated over each block cipher TLS names a suite for. All use the
// 12-byte nonce every TLS AEAD suite specifies (RFC 5288 / 6655 / 6209 / 6367).
type Aria128Gcm = AesGcm<aria::Aria128, U12>;
type Aria256Gcm = AesGcm<aria::Aria256, U12>;
type Camellia128Gcm = AesGcm<camellia::Camellia128, U12>;
type Camellia256Gcm = AesGcm<camellia::Camellia256, U12>;
type Aes128Ccm = ccm::Ccm<aes::Aes128, U16, U12>;
type Aes256Ccm = ccm::Ccm<aes::Aes256, U16, U12>;
type Aes128Ccm8 = ccm::Ccm<aes::Aes128, U8, U12>;
type Aes256Ccm8 = ccm::Ccm<aes::Aes256, U8, U12>;

fn aead_seal<A: KeyInit + Aead>(
    key: &[u8],
    nonce: &[u8],
    payload: Payload<'_, '_>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = A::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
    cipher
        .encrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| CryptoError::AeadSealFailed)
}

fn aead_open<A: KeyInit + Aead>(
    key: &[u8],
    nonce: &[u8],
    payload: Payload<'_, '_>,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = A::new_from_slice(key).map_err(|_| CryptoError::BadKeyLength)?;
    cipher
        .decrypt(GenericArray::from_slice(nonce), payload)
        .map_err(|_| CryptoError::AeadOpenFailed)
}

#[derive(Clone)]
pub struct AeadKey {
    alg: AeadAlg,
    key: Vec<u8>,
}

impl AeadKey {
    pub fn new(alg: AeadAlg, key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != alg.key_len() {
            return Err(CryptoError::BadKeyLength);
        }
        Ok(Self {
            alg,
            key: key.to_vec(),
        })
    }

    pub fn alg(&self) -> AeadAlg {
        self.alg
    }

    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != self.alg.nonce_len() {
            return Err(CryptoError::BadNonceLength);
        }
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let k = &self.key;
        match self.alg {
            AeadAlg::Aes128Gcm => aead_seal::<Aes128Gcm>(k, nonce, payload),
            AeadAlg::Aes256Gcm => aead_seal::<Aes256Gcm>(k, nonce, payload),
            AeadAlg::ChaCha20Poly1305 => {
                aead_seal::<chacha20poly1305::ChaCha20Poly1305>(k, nonce, payload)
            }
            AeadAlg::Aes128Ccm => aead_seal::<Aes128Ccm>(k, nonce, payload),
            AeadAlg::Aes256Ccm => aead_seal::<Aes256Ccm>(k, nonce, payload),
            AeadAlg::Aes128Ccm8 => aead_seal::<Aes128Ccm8>(k, nonce, payload),
            AeadAlg::Aes256Ccm8 => aead_seal::<Aes256Ccm8>(k, nonce, payload),
            AeadAlg::Aria128Gcm => aead_seal::<Aria128Gcm>(k, nonce, payload),
            AeadAlg::Aria256Gcm => aead_seal::<Aria256Gcm>(k, nonce, payload),
            AeadAlg::Camellia128Gcm => aead_seal::<Camellia128Gcm>(k, nonce, payload),
            AeadAlg::Camellia256Gcm => aead_seal::<Camellia256Gcm>(k, nonce, payload),
        }
    }

    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != self.alg.nonce_len() {
            return Err(CryptoError::BadNonceLength);
        }
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let k = &self.key;
        match self.alg {
            AeadAlg::Aes128Gcm => aead_open::<Aes128Gcm>(k, nonce, payload),
            AeadAlg::Aes256Gcm => aead_open::<Aes256Gcm>(k, nonce, payload),
            AeadAlg::ChaCha20Poly1305 => {
                aead_open::<chacha20poly1305::ChaCha20Poly1305>(k, nonce, payload)
            }
            AeadAlg::Aes128Ccm => aead_open::<Aes128Ccm>(k, nonce, payload),
            AeadAlg::Aes256Ccm => aead_open::<Aes256Ccm>(k, nonce, payload),
            AeadAlg::Aes128Ccm8 => aead_open::<Aes128Ccm8>(k, nonce, payload),
            AeadAlg::Aes256Ccm8 => aead_open::<Aes256Ccm8>(k, nonce, payload),
            AeadAlg::Aria128Gcm => aead_open::<Aria128Gcm>(k, nonce, payload),
            AeadAlg::Aria256Gcm => aead_open::<Aria256Gcm>(k, nonce, payload),
            AeadAlg::Camellia128Gcm => aead_open::<Camellia128Gcm>(k, nonce, payload),
            AeadAlg::Camellia256Gcm => aead_open::<Camellia256Gcm>(k, nonce, payload),
        }
    }
}

// ============================================================
//                 FFDHE (finite-field DH) key exchange
// ============================================================

/// A finite-field Diffie-Hellman private value for a group (p, g), used by the
/// TLS 1.2 DHE_RSA suites. Values are big-endian byte strings on the wire.
pub struct FfdhePrivate {
    p: num_bigint::BigUint,
    x: num_bigint::BigUint,
    p_len: usize,
}

impl FfdhePrivate {
    /// Generate a private exponent for the group (`p`, `g`) given big-endian
    /// modulus/generator bytes, drawing entropy from `rng`.
    pub fn generate(p_be: &[u8], _g_be: &[u8], rng: &mut Rng) -> Self {
        use num_bigint::BigUint;
        let p = BigUint::from_bytes_be(p_be);
        // A short private exponent, as RFC 7919 5.2 recommends (at least twice
        // the group's security strength: 225 bits for ffdhe2048, 275 for
        // ffdhe3072, 325 / 375 / 400 for the larger groups; 160 for the small
        // RFC 2409 negatives). Exponentiation cost is linear in the exponent
        // length, so this is the difference between a 2048-bit and a 256-bit
        // modpow per key agreement -- it was half of plzn's CPU time.
        let p_bits = p_be.len() * 8;
        let x_bytes = match p_bits {
            b if b >= 8192 => 52,
            b if b >= 6144 => 48,
            b if b >= 4096 => 44,
            b if b >= 3072 => 36,
            b if b >= 2048 => 32,
            _ => 20,
        }
        .min(p_be.len());
        let raw: Vec<u8> = (0..x_bytes).map(|_| rng.random_array::<1>()[0]).collect();
        let x = if p > BigUint::from(4u8) {
            // Keep the private value in 2..p-2. Besides being the conventional
            // range, this makes tiny arbitrary-group fixtures deterministic
            // without occasionally producing the public values 0 or 1.
            (BigUint::from_bytes_be(&raw) % (&p - BigUint::from(3u8))) + BigUint::from(2u8)
        } else {
            BigUint::from(1u8)
        };
        FfdhePrivate {
            p,
            x,
            p_len: p_be.len(),
        }
    }

    /// RFC 8446 4.2.8.1: a peer's public value must be encoded at the prime's
    /// length and satisfy 1 < Y < p-1. Rejects 0, 1 and p-1 (the values whose
    /// shared secret is a known constant) and any other size.
    pub fn peer_in_range(&self, peer_ys_be: &[u8]) -> bool {
        if peer_ys_be.len() != self.p_len {
            return false;
        }
        self.peer_integer_in_range(peer_ys_be)
    }

    /// TLS 1.2's ServerDHParams and ClientDiffieHellmanPublic carry opaque
    /// length-prefixed integers, without TLS 1.3's requirement to pad them to
    /// the prime's width. Validate only the numeric public-value bounds.
    pub fn peer_integer_in_range(&self, peer_ys_be: &[u8]) -> bool {
        use num_bigint::BigUint;
        let y = BigUint::from_bytes_be(peer_ys_be);
        let one = BigUint::from(1u32);
        if self.p <= one {
            return false;
        }
        y > one && y < &self.p - &one
    }

    /// Client public value Yc = g^x mod p, big-endian, left-padded to p's length.
    pub fn public_bytes(&self, g_be: &[u8]) -> Vec<u8> {
        use num_bigint::BigUint;
        let g = BigUint::from_bytes_be(g_be);
        let yc = g.modpow(&self.x, &self.p);
        left_pad(&yc.to_bytes_be(), self.p_len)
    }

    /// Shared secret Ys^x mod p, big-endian, left-padded to p's length (the TLS
    /// 1.2 DHE premaster secret, RFC 5246 8.1.2).
    pub fn agree(&self, peer_ys_be: &[u8]) -> Vec<u8> {
        use num_bigint::BigUint;
        let ys = BigUint::from_bytes_be(peer_ys_be);
        let z = ys.modpow(&self.x, &self.p);
        left_pad(&z.to_bytes_be(), self.p_len)
    }
}

/// Decode a hex string (whitespace ignored) to bytes. Used for embedding fixed
/// groups/vectors (e.g. the ffdhe2048 modulus).
pub(crate) fn hex_to_bytes(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    clean
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn left_pad(bytes: &[u8], len: usize) -> Vec<u8> {
    if bytes.len() >= len {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

/// Every shared secret a peer can derive from the public value `y` without
/// revealing its own exponent: the powers `y^0 .. y^(r-1) mod p` when `y` has
/// multiplicative order `r <= max_order`, each left-padded to p's length.
/// `y = 0 (mod p)` gives the single secret 0. None when `p <= 2`, when `y` is
/// not a unit, or when its order exceeds the bound.
pub fn ffdhe_small_subgroup(p_be: &[u8], y_be: &[u8], max_order: usize) -> Option<Vec<Vec<u8>>> {
    use num_bigint::BigUint;
    let p = BigUint::from_bytes_be(p_be);
    let one = BigUint::from(1u32);
    if p <= BigUint::from(2u32) {
        return None;
    }
    let y = BigUint::from_bytes_be(y_be) % &p;
    if y == BigUint::from(0u32) {
        return Some(vec![vec![0u8; p_be.len()]]);
    }
    let mut powers = vec![one.clone()];
    let mut t = y.clone();
    while t != one {
        if powers.len() >= max_order {
            return None;
        }
        powers.push(t.clone());
        t = (t * &y) % &p;
    }
    Some(
        powers
            .iter()
            .map(|v| left_pad(&v.to_bytes_be(), p_be.len()))
            .collect(),
    )
}

/// An element of the largest odd prime order `r <= bound` dividing `p - 1`:
/// `h^((p-1)/r) mod p` for the first `h >= 2` that is not 1, left-padded to
/// p's length. None when `p - 1` has no such factor (a safe prime has none).
/// The largest, because a peer's secret `y^x` is 1 -- which careful peers
/// refuse -- whenever `r` divides its exponent: one run in `r`.
pub fn ffdhe_small_order_element(p_be: &[u8], bound: u32) -> Option<Vec<u8>> {
    use num_bigint::BigUint;
    let p = BigUint::from_bytes_be(p_be);
    let one = BigUint::from(1u32);
    if p <= BigUint::from(3u32) {
        return None;
    }
    let n = &p - &one;
    let zero = BigUint::from(0u32);
    let is_prime = |r: u32| {
        (3..)
            .step_by(2)
            .take_while(|d| d * d <= r)
            .all(|d| !r.is_multiple_of(d))
    };
    let r = (3..=bound)
        .rev()
        .find(|&r| !r.is_multiple_of(2) && is_prime(r) && &n % r == zero)?;
    let exponent = &n / r;
    (2u32..1000).find_map(|h| {
        let y = BigUint::from(h).modpow(&exponent, &p);
        (y != one).then(|| left_pad(&y.to_bytes_be(), p_be.len()))
    })
}

#[cfg(test)]
mod small_subgroup_tests {
    use super::*;
    use crate::tls::kex12::{DhGroup, RFC5114_2048_256_Q_HEX};
    use num_bigint::BigUint;

    #[test]
    fn rfc5114_2048_256_is_the_published_group() {
        let group = DhGroup::rfc5114_2048_256();
        assert_eq!(group.p.len(), 256);
        assert!(is_probable_prime_be(&group.p));
        let p = BigUint::from_bytes_be(&group.p);
        let q = BigUint::parse_bytes(RFC5114_2048_256_Q_HEX.as_bytes(), 16).unwrap();
        assert!(is_probable_prime_be(&q.to_bytes_be()));
        assert_eq!((&p - 1u32) % &q, BigUint::from(0u32));
        assert_eq!(
            BigUint::from_bytes_be(&group.g).modpow(&q, &p),
            BigUint::from(1u32)
        );
    }

    #[test]
    fn small_subgroups_enumerate_every_power() {
        let p = DhGroup::rfc5114_2048_256().p;
        // p - 1 = 2 * 7 * 13 * 2549 * 142031 * ...: the largest odd prime
        // order up to the bound is 2549, the smallest 7.
        let y = ffdhe_small_order_element(&p, 4096).expect("p - 1 has the factor 2549");
        let powers = ffdhe_small_subgroup(&p, &y, 4096).expect("order 2549");
        assert_eq!(powers.len(), 2549);
        assert_eq!(powers[1], y);
        assert!(powers.iter().all(|v| v.len() == p.len()));
        let distinct: std::collections::BTreeSet<_> = powers.iter().collect();
        assert_eq!(distinct.len(), 2549);
        // Capped below the order: no candidates rather than a partial set.
        assert!(ffdhe_small_subgroup(&p, &y, 2548).is_none());
        let y7 = ffdhe_small_order_element(&p, 12).expect("p - 1 has the factor 7");
        assert_eq!(
            ffdhe_small_subgroup(&p, &y7, 4096).map(|v| v.len()),
            Some(7)
        );

        // A safe prime: no small odd-order element, and 2 has order q.
        let ffdhe = DhGroup::ffdhe2048().p;
        assert!(ffdhe_small_order_element(&ffdhe, 1 << 16).is_none());
        assert!(ffdhe_small_subgroup(&ffdhe, &[2], 4096).is_none());

        // The boundary public values: 0 and p give 0; 1 and p + 1 give 1;
        // p - 1 has order 2.
        let n = BigUint::from_bytes_be(&ffdhe);
        let at_width = |v: BigUint| left_pad(&v.to_bytes_be(), ffdhe.len());
        let zero = at_width(BigUint::from(0u32));
        let one = at_width(BigUint::from(1u32));
        let p_minus_1 = at_width(&n - 1u32);
        for (y, expect) in [
            (vec![0u8], vec![zero.clone()]),
            (ffdhe.clone(), vec![zero]),
            (vec![1u8], vec![one.clone()]),
            ((&n + 1u32).to_bytes_be(), vec![one.clone()]),
            (p_minus_1.clone(), vec![one, p_minus_1]),
        ] {
            assert_eq!(ffdhe_small_subgroup(&ffdhe, &y, 4096), Some(expect));
        }
    }
}

// ============================================================
//                     ECDHE key exchange
// ============================================================

/// Named groups the harness can generate an ephemeral for. Despite the name,
/// the RFC 7919 finite-field groups and the ML-KEM key-encapsulation groups
/// live here too: a TLS 1.3 key_share treats every one of them alike (a
/// public value in, a fixed-size shared secret out), so one type covers every
/// group a hello can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdheGroup {
    X25519,
    X448,
    P256,
    P384,
    P521,
    /// brainpoolP256r1 / brainpoolP384r1 (RFC 7027) under their TLS 1.2
    /// codepoints. The same curves carry different codepoints in TLS 1.3
    /// (RFC 8734), which the `..Tls13` variants name; RFC 8734 forbids using
    /// either set in the other version.
    Bp256,
    Bp384,
    Bp256Tls13,
    Bp384Tls13,
    Ffdhe2048,
    Ffdhe3072,
    Ffdhe4096,
    Ffdhe6144,
    Ffdhe8192,
    /// FIPS 203 ML-KEM as a TLS 1.3 key exchange
    /// (draft-connolly-tls-mlkem-key-agreement): the client's share is the
    /// encapsulation key, the server's the ciphertext.
    MlKem512,
    MlKem768,
    MlKem1024,
    /// ECDH + ML-KEM hybrids: the three draft-ietf-tls-ecdhe-mlkem groups plus
    /// experimental X448MLKEM1024. Shares and shared secrets are plain
    /// concatenations, ML-KEM first for the historically reversed
    /// X25519MLKEM768 name and ECDH first otherwise.
    X25519MlKem768,
    X448MlKem1024,
    Secp256r1MlKem768,
    Secp384r1MlKem1024,
}

/// The ML-KEM parameter set behind a pure or hybrid KEM group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemParam {
    M512,
    M768,
    M1024,
}

impl MlKemParam {
    /// Encapsulation-key length (FIPS 203 table 3).
    pub fn ek_len(self) -> usize {
        match self {
            MlKemParam::M512 => 800,
            MlKemParam::M768 => 1184,
            MlKemParam::M1024 => 1568,
        }
    }

    /// Ciphertext length.
    pub fn ct_len(self) -> usize {
        match self {
            MlKemParam::M512 => 768,
            MlKemParam::M768 => 1088,
            MlKemParam::M1024 => 1568,
        }
    }

    /// The pure-KEM group of this parameter set.
    pub fn group(self) -> EcdheGroup {
        match self {
            MlKemParam::M512 => EcdheGroup::MlKem512,
            MlKemParam::M768 => EcdheGroup::MlKem768,
            MlKemParam::M1024 => EcdheGroup::MlKem1024,
        }
    }
}

impl EcdheGroup {
    /// The group for a TLS NamedGroup wire value, if plzn implements it.
    pub fn from_wire(wire: u16) -> Option<Self> {
        Some(match wire {
            0x001d => EcdheGroup::X25519,
            0x001e => EcdheGroup::X448,
            0x0017 => EcdheGroup::P256,
            0x0018 => EcdheGroup::P384,
            0x0019 => EcdheGroup::P521,
            0x001a => EcdheGroup::Bp256,
            0x001b => EcdheGroup::Bp384,
            0x001f => EcdheGroup::Bp256Tls13,
            0x0020 => EcdheGroup::Bp384Tls13,
            0x0100 => EcdheGroup::Ffdhe2048,
            0x0101 => EcdheGroup::Ffdhe3072,
            0x0102 => EcdheGroup::Ffdhe4096,
            0x0103 => EcdheGroup::Ffdhe6144,
            0x0104 => EcdheGroup::Ffdhe8192,
            0x0200 => EcdheGroup::MlKem512,
            0x0201 => EcdheGroup::MlKem768,
            0x0202 => EcdheGroup::MlKem1024,
            0x11ec => EcdheGroup::X25519MlKem768,
            0x11ee => EcdheGroup::X448MlKem1024,
            0x11eb => EcdheGroup::Secp256r1MlKem768,
            0x11ed => EcdheGroup::Secp384r1MlKem1024,
            _ => return None,
        })
    }

    pub fn wire_value(self) -> u16 {
        match self {
            EcdheGroup::X25519 => 0x001d,
            EcdheGroup::X448 => 0x001e,
            EcdheGroup::P256 => 0x0017,
            EcdheGroup::P384 => 0x0018,
            EcdheGroup::P521 => 0x0019,
            EcdheGroup::Bp256 => 0x001a,
            EcdheGroup::Bp384 => 0x001b,
            EcdheGroup::Bp256Tls13 => 0x001f,
            EcdheGroup::Bp384Tls13 => 0x0020,
            EcdheGroup::Ffdhe2048 => 0x0100,
            EcdheGroup::Ffdhe3072 => 0x0101,
            EcdheGroup::Ffdhe4096 => 0x0102,
            EcdheGroup::Ffdhe6144 => 0x0103,
            EcdheGroup::Ffdhe8192 => 0x0104,
            EcdheGroup::MlKem512 => 0x0200,
            EcdheGroup::MlKem768 => 0x0201,
            EcdheGroup::MlKem1024 => 0x0202,
            EcdheGroup::X25519MlKem768 => 0x11ec,
            EcdheGroup::X448MlKem1024 => 0x11ee,
            EcdheGroup::Secp256r1MlKem768 => 0x11eb,
            EcdheGroup::Secp384r1MlKem1024 => 0x11ed,
        }
    }

    /// Every group plzn implements, in wire order of the families.
    pub const ALL: &'static [EcdheGroup] = &[
        EcdheGroup::X25519,
        EcdheGroup::X448,
        EcdheGroup::P256,
        EcdheGroup::P384,
        EcdheGroup::P521,
        EcdheGroup::Bp256,
        EcdheGroup::Bp384,
        EcdheGroup::Bp256Tls13,
        EcdheGroup::Bp384Tls13,
        EcdheGroup::Ffdhe2048,
        EcdheGroup::Ffdhe3072,
        EcdheGroup::Ffdhe4096,
        EcdheGroup::Ffdhe6144,
        EcdheGroup::Ffdhe8192,
        EcdheGroup::MlKem512,
        EcdheGroup::MlKem768,
        EcdheGroup::MlKem1024,
        EcdheGroup::X25519MlKem768,
        EcdheGroup::X448MlKem1024,
        EcdheGroup::Secp256r1MlKem768,
        EcdheGroup::Secp384r1MlKem1024,
    ];

    /// The IANA name, for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            EcdheGroup::X25519 => "x25519",
            EcdheGroup::X448 => "x448",
            EcdheGroup::P256 => "secp256r1",
            EcdheGroup::P384 => "secp384r1",
            EcdheGroup::P521 => "secp521r1",
            EcdheGroup::Bp256 => "brainpoolP256r1",
            EcdheGroup::Bp384 => "brainpoolP384r1",
            EcdheGroup::Bp256Tls13 => "brainpoolP256r1tls13",
            EcdheGroup::Bp384Tls13 => "brainpoolP384r1tls13",
            EcdheGroup::Ffdhe2048 => "ffdhe2048",
            EcdheGroup::Ffdhe3072 => "ffdhe3072",
            EcdheGroup::Ffdhe4096 => "ffdhe4096",
            EcdheGroup::Ffdhe6144 => "ffdhe6144",
            EcdheGroup::Ffdhe8192 => "ffdhe8192",
            EcdheGroup::MlKem512 => "MLKEM512",
            EcdheGroup::MlKem768 => "MLKEM768",
            EcdheGroup::MlKem1024 => "MLKEM1024",
            EcdheGroup::X25519MlKem768 => "X25519MLKEM768",
            EcdheGroup::X448MlKem1024 => "X448MLKEM1024",
            EcdheGroup::Secp256r1MlKem768 => "SecP256r1MLKEM768",
            EcdheGroup::Secp384r1MlKem1024 => "SecP384r1MLKEM1024",
        }
    }

    pub fn is_ffdhe(self) -> bool {
        matches!(
            self,
            EcdheGroup::Ffdhe2048
                | EcdheGroup::Ffdhe3072
                | EcdheGroup::Ffdhe4096
                | EcdheGroup::Ffdhe6144
                | EcdheGroup::Ffdhe8192
        )
    }

    /// A prime-order Weierstrass curve (NIST or brainpool): SEC1 points.
    pub fn is_weierstrass(self) -> bool {
        matches!(
            self,
            EcdheGroup::P256
                | EcdheGroup::P384
                | EcdheGroup::P521
                | EcdheGroup::Bp256
                | EcdheGroup::Bp384
                | EcdheGroup::Bp256Tls13
                | EcdheGroup::Bp384Tls13
        )
    }

    /// A pure ML-KEM group (no ECDH component).
    pub fn is_pure_kem(self) -> bool {
        matches!(
            self,
            EcdheGroup::MlKem512 | EcdheGroup::MlKem768 | EcdheGroup::MlKem1024
        )
    }

    /// An ECDH + ML-KEM hybrid.
    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            EcdheGroup::X25519MlKem768
                | EcdheGroup::X448MlKem1024
                | EcdheGroup::Secp256r1MlKem768
                | EcdheGroup::Secp384r1MlKem1024
        )
    }

    /// Any group with an ML-KEM component. These are key ENCAPSULATION
    /// groups: the two sides' shares differ (encapsulation key vs ciphertext),
    /// so the responder must use `EcdhePrivate::respond`, not `generate`.
    pub fn is_kem(self) -> bool {
        self.is_pure_kem() || self.is_hybrid()
    }

    /// Groups defined for TLS 1.3 only (RFC 8734 brainpool codepoints, every
    /// KEM group): a TLS 1.2 server never selects them.
    pub fn is_tls13_only(self) -> bool {
        self.is_kem() || matches!(self, EcdheGroup::Bp256Tls13 | EcdheGroup::Bp384Tls13)
    }

    /// The RFC 7027 brainpool codepoints, defined for TLS 1.2 only (RFC 8734 2).
    pub fn is_tls12_only(self) -> bool {
        matches!(self, EcdheGroup::Bp256 | EcdheGroup::Bp384)
    }

    /// The ML-KEM parameter set of a KEM group.
    pub fn kem_param(self) -> Option<MlKemParam> {
        Some(match self {
            EcdheGroup::MlKem512 => MlKemParam::M512,
            EcdheGroup::MlKem768 | EcdheGroup::X25519MlKem768 | EcdheGroup::Secp256r1MlKem768 => {
                MlKemParam::M768
            }
            EcdheGroup::MlKem1024 | EcdheGroup::X448MlKem1024 | EcdheGroup::Secp384r1MlKem1024 => {
                MlKemParam::M1024
            }
            _ => return None,
        })
    }

    /// The ECDH component of a hybrid group.
    pub fn ecdh_component(self) -> Option<EcdheGroup> {
        Some(match self {
            EcdheGroup::X25519MlKem768 => EcdheGroup::X25519,
            EcdheGroup::X448MlKem1024 => EcdheGroup::X448,
            EcdheGroup::Secp256r1MlKem768 => EcdheGroup::P256,
            EcdheGroup::Secp384r1MlKem1024 => EcdheGroup::P384,
            _ => return None,
        })
    }

    /// Whether a hybrid's shares and secret put the ML-KEM half first. Only
    /// X25519MLKEM768 has the historical reverse-of-name ordering.
    pub fn kem_first(self) -> bool {
        self == EcdheGroup::X25519MlKem768
    }

    /// Length of the share the INITIATOR (client) sends for this group.
    pub fn initiator_share_len(self) -> usize {
        match self {
            EcdheGroup::X25519 => 32,
            EcdheGroup::X448 => 56,
            EcdheGroup::P256 | EcdheGroup::Bp256 | EcdheGroup::Bp256Tls13 => 65,
            EcdheGroup::P384 | EcdheGroup::Bp384 | EcdheGroup::Bp384Tls13 => 97,
            EcdheGroup::P521 => 133,
            EcdheGroup::Ffdhe2048 => 256,
            EcdheGroup::Ffdhe3072 => 384,
            EcdheGroup::Ffdhe4096 => 512,
            EcdheGroup::Ffdhe6144 => 768,
            EcdheGroup::Ffdhe8192 => 1024,
            EcdheGroup::MlKem512 | EcdheGroup::MlKem768 | EcdheGroup::MlKem1024 => {
                self.kem_param().expect("kem").ek_len()
            }
            EcdheGroup::X25519MlKem768
            | EcdheGroup::X448MlKem1024
            | EcdheGroup::Secp256r1MlKem768
            | EcdheGroup::Secp384r1MlKem1024 => {
                self.kem_param().expect("kem").ek_len()
                    + self.ecdh_component().expect("hybrid").initiator_share_len()
            }
        }
    }

    /// Length of the share the RESPONDER (server) sends for this group.
    pub fn responder_share_len(self) -> usize {
        match self.kem_param() {
            None => self.initiator_share_len(),
            Some(param) => {
                param.ct_len()
                    + self
                        .ecdh_component()
                        .map(|g| g.initiator_share_len())
                        .unwrap_or(0)
            }
        }
    }

    /// The RFC 7919 prime (big-endian) for a finite-field group; None for a
    /// curve. The generator is 2 for every RFC 7919 group.
    pub fn ffdhe_prime(self) -> Option<Vec<u8>> {
        match self {
            EcdheGroup::Ffdhe2048 => Some(hex_to_bytes(FFDHE2048_P_HEX)),
            EcdheGroup::Ffdhe3072 => Some(hex_to_bytes(FFDHE3072_P_HEX)),
            EcdheGroup::Ffdhe4096 => Some(hex_to_bytes(FFDHE4096_P_HEX)),
            EcdheGroup::Ffdhe6144 => Some(hex_to_bytes(FFDHE6144_P_HEX)),
            EcdheGroup::Ffdhe8192 => Some(crate::tls::kex12::DhGroup::ffdhe8192().p),
            _ => None,
        }
    }
}

/// RFC 7919 Appendix A.1 ffdhe2048 prime: 2^2048 - 2^1984 + {[2^1918 * e] +
/// 560316} * 2^64 - 1. Checked against that construction and for safe-primality.
pub const FFDHE2048_P_HEX: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
     A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
     D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
     984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
     BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
     AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
     9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
     C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF";

/// RFC 7919 Appendix A.2 ffdhe3072 prime: 2^3072 - 2^3008 + {[2^2942 * e] +
/// 2625351} * 2^64 - 1. Checked the same way.
pub const FFDHE3072_P_HEX: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
     A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A\
     D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
     984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A\
     BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4\
     AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
     9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005\
     C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035B\
     BC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
     AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF\
     5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E\
     0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF";

/// RFC 7919 Appendix A.3 ffdhe4096 prime.
pub const FFDHE4096_P_HEX: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
     7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
     984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
     B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
     9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
     886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
     AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D\
     ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
     7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832\
     A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
     8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF";

/// RFC 7919 Appendix A.4 ffdhe6144 prime.
pub const FFDHE6144_P_HEX: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
     7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
     984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
     B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
     9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
     886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91C\
     AEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0D\
     ABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
     7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832\
     A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
     8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A4E677D2C38532A3A23BA4442CAF53EA6\
     3BB454329B7624C8917BDD64B1C0FD4CB38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
     A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E7FB29F8C183023C3587E38DA0077D9B4\
     763E4E4B94B2BBC194C6651E77CAF992EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C\
     D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B91178CCF2DD5CACEF403EC9D1810C6272B04\
     5B3B71F9DC6B80D63FDD4A8E9ADB1E6962A69526D43161C1A41D570D7938DAD4A40E329CD0E40E65FFFFFFFFFFFFFFFF";

/// Generator for every RFC 7919 group.
const FFDHE_G: [u8; 1] = [2];

/// Private half of an (EC)DHE key pair, or of one side of an ML-KEM
/// exchange. Keeps the underlying key type private; callers only see
/// public-key bytes and the shared secret.
pub enum EcdhePrivate {
    X25519(x25519_dalek::StaticSecret),
    X448 {
        scalar: [u8; 56],
        public: [u8; 56],
    },
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
    /// brainpoolP256r1 under either codepoint (the group records which).
    Bp256 {
        sk: bp256::r1::SecretKey,
        group: EcdheGroup,
    },
    Bp384 {
        sk: bp384::r1::SecretKey,
        group: EcdheGroup,
    },
    /// RFC 7919 finite-field group: the exponent bound to its prime.
    Ffdhe {
        key: FfdhePrivate,
        group: EcdheGroup,
    },
    /// ML-KEM initiator: the decapsulation key. Its share is the
    /// encapsulation key; `agree` decapsulates the peer's ciphertext.
    MlKem {
        dk: MlKemDecapsKey,
        group: EcdheGroup,
    },
    /// ML-KEM responder: already encapsulated against the peer's key. Its
    /// share is the ciphertext and `agree` yields the fixed shared secret.
    MlKemResponder {
        ciphertext: Vec<u8>,
        shared: Vec<u8>,
        group: EcdheGroup,
    },
    /// ECDH + ML-KEM hybrid: both halves, concatenated per the group's order.
    Hybrid {
        ecdh: Box<EcdhePrivate>,
        kem: Box<EcdhePrivate>,
        group: EcdheGroup,
    },
}

/// An ML-KEM decapsulation key of one parameter set.
pub enum MlKemDecapsKey {
    M512(ml_kem::DecapsulationKey<ml_kem::MlKem512>),
    M768(ml_kem::DecapsulationKey<ml_kem::MlKem768>),
    M1024(ml_kem::DecapsulationKey<ml_kem::MlKem1024>),
}

/// The ML-KEM operations of one parameter set. The crate's generic bounds
/// are crate-private, so each set gets its own module through this macro.
macro_rules! mlkem_ops {
    ($modname:ident, $P:ty) => {
        mod $modname {
            use super::{CryptoError, Rng};

            /// FIPS 203 keygen from the seed d || z, both drawn from the
            /// test's deterministic rng.
            pub fn from_seed(rng: &mut Rng) -> ml_kem::DecapsulationKey<$P> {
                let seed: [u8; 64] = rng.random_array();
                ml_kem::DecapsulationKey::<$P>::from_seed(ml_kem::Seed::from(seed))
            }

            pub fn ek_bytes(dk: &ml_kem::DecapsulationKey<$P>) -> Vec<u8> {
                use ml_kem::KeyExport;
                dk.encapsulation_key().to_bytes().to_vec()
            }

            pub fn decaps(
                dk: &ml_kem::DecapsulationKey<$P>,
                ct: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                use ml_kem::Decapsulate;
                dk.decapsulate_slice(ct)
                    .map(|k| k.to_vec())
                    .map_err(|_| CryptoError::BadPublicKey)
            }

            /// Encapsulate against a peer's encapsulation key with the
            /// randomness m drawn from the rng: (ciphertext, shared secret).
            pub fn encaps(
                ek_bytes: &[u8],
                rng: &mut Rng,
            ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
                use ml_kem::TryKeyInit;
                let ek = ml_kem::EncapsulationKey::<$P>::new_from_slice(ek_bytes)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let m: [u8; 32] = rng.random_array();
                let (ct, ss) = ek.encapsulate_deterministic(&ml_kem::B32::from(m));
                Ok((ct.to_vec(), ss.to_vec()))
            }
        }
    };
}

mlkem_ops!(mlkem512, ml_kem::MlKem512);
mlkem_ops!(mlkem768, ml_kem::MlKem768);
mlkem_ops!(mlkem1024, ml_kem::MlKem1024);

/// Split a hybrid share into (kem part, ecdh part) following the group's order.
fn split_hybrid(
    group: EcdheGroup,
    share: &[u8],
    kem_len: usize,
) -> Result<(&[u8], &[u8]), CryptoError> {
    let ecdh_len = group
        .ecdh_component()
        .ok_or(CryptoError::BadPublicKey)?
        .initiator_share_len();
    if share.len() != kem_len + ecdh_len {
        return Err(CryptoError::BadPublicKey);
    }
    Ok(if group.kem_first() {
        (&share[..kem_len], &share[kem_len..])
    } else {
        (&share[ecdh_len..], &share[..ecdh_len])
    })
}

fn join_hybrid(group: EcdheGroup, kem: &[u8], ecdh: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(kem.len() + ecdh.len());
    if group.kem_first() {
        out.extend_from_slice(kem);
        out.extend_from_slice(ecdh);
    } else {
        out.extend_from_slice(ecdh);
        out.extend_from_slice(kem);
    }
    out
}

fn bp256_secret(rng: &mut Rng) -> bp256::r1::SecretKey {
    loop {
        let bytes: [u8; 32] = rng.random_array();
        if let Ok(sk) = bp256::r1::SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

fn bp384_secret(rng: &mut Rng) -> bp384::r1::SecretKey {
    loop {
        let bytes: [u8; 48] = rng.random_array();
        if let Ok(sk) = bp384::r1::SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

/// RFC 7748 X448 using ordinary big integers. This is intentionally a small,
/// non-constant-time interoperability implementation for the test harness.
fn x448(scalar: &[u8; 56], u_bytes: &[u8; 56]) -> [u8; 56] {
    let one = BigUint::from(1u8);
    let p = (&one << 448usize) - (&one << 224usize) - &one;
    let a24 = BigUint::from(39081u32);

    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;

    let x1 = BigUint::from_bytes_le(u_bytes) % &p;
    let mut x2 = one.clone();
    let mut z2 = BigUint::from(0u8);
    let mut x3 = x1.clone();
    let mut z3 = one;
    let mut swap = 0u8;

    for bit in (0..448usize).rev() {
        let scalar_bit = (k[bit / 8] >> (bit & 7)) & 1;
        swap ^= scalar_bit;
        if swap != 0 {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = scalar_bit;

        let a = (&x2 + &z2) % &p;
        let aa = (&a * &a) % &p;
        let b = sub_mod(&x2, &z2, &p);
        let bb = (&b * &b) % &p;
        let e = sub_mod(&aa, &bb, &p);
        let c = (&x3 + &z3) % &p;
        let d = sub_mod(&x3, &z3, &p);
        let da = (&d * &a) % &p;
        let cb = (&c * &b) % &p;
        let da_plus_cb = (&da + &cb) % &p;
        let da_minus_cb = sub_mod(&da, &cb, &p);

        x3 = (&da_plus_cb * &da_plus_cb) % &p;
        z3 = (&x1 * &da_minus_cb * &da_minus_cb) % &p;
        x2 = (&aa * &bb) % &p;
        z2 = (&e * ((&aa + (&a24 * &e)) % &p)) % &p;
    }
    if swap != 0 {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    let result = (x2 * z2.modpow(&(&p - BigUint::from(2u8)), &p)) % &p;
    let bytes = result.to_bytes_le();
    let mut out = [0u8; 56];
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

fn sub_mod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a >= b { a - b } else { modulus - (b - a) }
}

impl EcdhePrivate {
    /// Generate a fresh private key drawing entropy from `rng`: the INITIATOR
    /// form. For an ECDH or FFDHE group either side uses it; for a KEM group
    /// it produces the client's (decapsulation) side, and the server must use
    /// `respond` against the client's share instead.
    pub fn generate(group: EcdheGroup, rng: &mut Rng) -> Self {
        match group {
            EcdheGroup::X25519 => {
                let seed: [u8; 32] = rng.random_array();
                EcdhePrivate::X25519(x25519_dalek::StaticSecret::from(seed))
            }
            EcdheGroup::X448 => {
                let scalar: [u8; 56] = rng.random_array();
                let mut base = [0u8; 56];
                base[0] = 5;
                let public = x448(&scalar, &base);
                EcdhePrivate::X448 { scalar, public }
            }
            EcdheGroup::P256 => {
                // p256 needs a RngCore; we hand it our ChaCha20Rng.
                EcdhePrivate::P256(p256::ecdh::EphemeralSecret::random(&mut rng.inner))
            }
            EcdheGroup::P384 => {
                EcdhePrivate::P384(p384::ecdh::EphemeralSecret::random(&mut rng.inner))
            }
            EcdheGroup::P521 => {
                EcdhePrivate::P521(p521::ecdh::EphemeralSecret::random(&mut rng.inner))
            }
            EcdheGroup::Bp256 | EcdheGroup::Bp256Tls13 => EcdhePrivate::Bp256 {
                sk: bp256_secret(rng),
                group,
            },
            EcdheGroup::Bp384 | EcdheGroup::Bp384Tls13 => EcdhePrivate::Bp384 {
                sk: bp384_secret(rng),
                group,
            },
            EcdheGroup::Ffdhe2048
            | EcdheGroup::Ffdhe3072
            | EcdheGroup::Ffdhe4096
            | EcdheGroup::Ffdhe6144
            | EcdheGroup::Ffdhe8192 => {
                let p = group.ffdhe_prime().expect("ffdhe group has a prime");
                EcdhePrivate::Ffdhe {
                    key: FfdhePrivate::generate(&p, &FFDHE_G, rng),
                    group,
                }
            }
            EcdheGroup::MlKem512 => EcdhePrivate::MlKem {
                dk: MlKemDecapsKey::M512(mlkem512::from_seed(rng)),
                group,
            },
            EcdheGroup::MlKem768 => EcdhePrivate::MlKem {
                dk: MlKemDecapsKey::M768(mlkem768::from_seed(rng)),
                group,
            },
            EcdheGroup::MlKem1024 => EcdhePrivate::MlKem {
                dk: MlKemDecapsKey::M1024(mlkem1024::from_seed(rng)),
                group,
            },
            EcdheGroup::X25519MlKem768
            | EcdheGroup::X448MlKem1024
            | EcdheGroup::Secp256r1MlKem768
            | EcdheGroup::Secp384r1MlKem1024 => {
                let ecdh = EcdhePrivate::generate(group.ecdh_component().expect("hybrid"), rng);
                let kem = EcdhePrivate::generate(group.kem_param().expect("hybrid").group(), rng);
                EcdhePrivate::Hybrid {
                    ecdh: Box::new(ecdh),
                    kem: Box::new(kem),
                    group,
                }
            }
        }
    }

    /// The RESPONDER form: the server's half against the client's share.
    /// ECDH / FFDHE groups just generate (the share is not needed yet); a KEM
    /// group encapsulates against the client's encapsulation key here, so the
    /// ciphertext is the share and the shared secret is fixed now.
    pub fn respond(
        group: EcdheGroup,
        peer_share: &[u8],
        rng: &mut Rng,
    ) -> Result<Self, CryptoError> {
        if !group.is_kem() {
            return Ok(EcdhePrivate::generate(group, rng));
        }
        let param = group.kem_param().expect("kem group");
        let ek: &[u8] = if group.is_hybrid() {
            split_hybrid(group, peer_share, param.ek_len())?.0
        } else if peer_share.len() == param.ek_len() {
            peer_share
        } else {
            return Err(CryptoError::BadPublicKey);
        };
        let (ciphertext, shared) = match param {
            MlKemParam::M512 => mlkem512::encaps(ek, rng)?,
            MlKemParam::M768 => mlkem768::encaps(ek, rng)?,
            MlKemParam::M1024 => mlkem1024::encaps(ek, rng)?,
        };
        if !group.is_hybrid() {
            return Ok(EcdhePrivate::MlKemResponder {
                ciphertext,
                shared,
                group,
            });
        }
        let kem = EcdhePrivate::MlKemResponder {
            ciphertext,
            shared,
            group: param.group(),
        };
        let ecdh = EcdhePrivate::generate(group.ecdh_component().expect("hybrid"), rng);
        Ok(EcdhePrivate::Hybrid {
            ecdh: Box::new(ecdh),
            kem: Box::new(kem),
            group,
        })
    }

    pub fn group(&self) -> EcdheGroup {
        match self {
            EcdhePrivate::X25519(_) => EcdheGroup::X25519,
            EcdhePrivate::X448 { .. } => EcdheGroup::X448,
            EcdhePrivate::P256(_) => EcdheGroup::P256,
            EcdhePrivate::P384(_) => EcdheGroup::P384,
            EcdhePrivate::P521(_) => EcdheGroup::P521,
            EcdhePrivate::Bp256 { group, .. }
            | EcdhePrivate::Bp384 { group, .. }
            | EcdhePrivate::Ffdhe { group, .. }
            | EcdhePrivate::MlKem { group, .. }
            | EcdhePrivate::MlKemResponder { group, .. }
            | EcdhePrivate::Hybrid { group, .. } => *group,
        }
    }

    /// Return the public key bytes in the wire format TLS expects.
    ///
    ///   * X25519 / X448: little-endian u-coordinate (RFC 8446).
    ///   * NIST / brainpool curves: uncompressed SEC1 (0x04 || X || Y).
    ///   * FFDHE: Y left-padded to the prime's length.
    ///   * ML-KEM: the encapsulation key (initiator) or ciphertext (responder).
    ///   * Hybrids: the two halves concatenated in the group's order.
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            EcdhePrivate::X25519(sk) => {
                let pk = x25519_dalek::PublicKey::from(sk);
                pk.as_bytes().to_vec()
            }
            EcdhePrivate::X448 { public, .. } => public.to_vec(),
            EcdhePrivate::P256(sk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let pk = sk.public_key();
                pk.to_encoded_point(false).as_bytes().to_vec()
            }
            EcdhePrivate::P384(sk) => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;
                let pk = sk.public_key();
                pk.to_encoded_point(false).as_bytes().to_vec()
            }
            EcdhePrivate::P521(sk) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                let pk = sk.public_key();
                pk.to_encoded_point(false).as_bytes().to_vec()
            }
            EcdhePrivate::Bp256 { sk, .. } => {
                use ec14::sec1::ToSec1Point;
                sk.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
            EcdhePrivate::Bp384 { sk, .. } => {
                use ec14::sec1::ToSec1Point;
                sk.public_key().to_sec1_point(false).as_bytes().to_vec()
            }
            // RFC 8446 4.2.8.1: Y = g^x mod p, left-padded to the prime's length.
            EcdhePrivate::Ffdhe { key, .. } => key.public_bytes(&FFDHE_G),
            EcdhePrivate::MlKem { dk, .. } => match dk {
                MlKemDecapsKey::M512(dk) => mlkem512::ek_bytes(dk),
                MlKemDecapsKey::M768(dk) => mlkem768::ek_bytes(dk),
                MlKemDecapsKey::M1024(dk) => mlkem1024::ek_bytes(dk),
            },
            EcdhePrivate::MlKemResponder { ciphertext, .. } => ciphertext.clone(),
            EcdhePrivate::Hybrid { ecdh, kem, group } => {
                join_hybrid(*group, &kem.public_bytes(), &ecdh.public_bytes())
            }
        }
    }

    /// The public key in SEC1 compressed form (0x02/0x03 || X) for the
    /// prime curves -- an encoding TLS 1.3 forbids in key_share (RFC 8446
    /// 4.2.8.2: uncompressed only), so a test can offer a well-formed but
    /// illegal point. None for X25519 / X448, whose u-coordinates have no
    /// compressed form, and for the finite-field and KEM groups.
    pub fn public_bytes_compressed(&self) -> Option<Vec<u8>> {
        match self {
            EcdhePrivate::P256(sk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                Some(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
            }
            EcdhePrivate::P384(sk) => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;
                Some(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
            }
            EcdhePrivate::P521(sk) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                Some(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
            }
            EcdhePrivate::Bp256 { sk, .. } => {
                use ec14::sec1::ToSec1Point;
                Some(sk.public_key().to_sec1_point(true).as_bytes().to_vec())
            }
            EcdhePrivate::Bp384 { sk, .. } => {
                use ec14::sec1::ToSec1Point;
                Some(sk.public_key().to_sec1_point(true).as_bytes().to_vec())
            }
            // An ECDH + ML-KEM hybrid: re-encode the ECDH half, keep the KEM half.
            EcdhePrivate::Hybrid { ecdh, kem, group } => {
                let c = ecdh.public_bytes_compressed()?;
                Some(join_hybrid(*group, &kem.public_bytes(), &c))
            }
            _ => None,
        }
    }

    /// The public key in the SEC1 "hybrid" form (0x06/0x07 || X || Y: both
    /// coordinates plus the parity tag) for the prime curves (and the ECDH
    /// half of a NIST-curve ML-KEM hybrid); None otherwise.
    pub fn public_bytes_hybrid_sec1(&self) -> Option<Vec<u8>> {
        if let EcdhePrivate::Hybrid { ecdh, kem, group } = self {
            let h = ecdh.public_bytes_hybrid_sec1()?;
            return Some(join_hybrid(*group, &kem.public_bytes(), &h));
        }
        let compressed = self.public_bytes_compressed()?;
        let mut out = self.public_bytes();
        out[0] = compressed[0] + 4; // 0x02 -> 0x06, 0x03 -> 0x07
        Some(out)
    }

    /// The public key as bare X || Y without the SEC1 0x04 prefix, for the
    /// prime curves (and the ECDH half of a NIST-curve hybrid); None otherwise.
    pub fn public_bytes_xy(&self) -> Option<Vec<u8>> {
        match self {
            EcdhePrivate::Hybrid { ecdh, kem, group } => {
                let xy = ecdh.public_bytes_xy()?;
                Some(join_hybrid(*group, &kem.public_bytes(), &xy))
            }
            _ if self.group().is_weierstrass() => Some(self.public_bytes()[1..].to_vec()),
            _ => None,
        }
    }

    /// Compute the shared secret with the peer's public key bytes.
    pub fn agree(self, peer_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            EcdhePrivate::X25519(sk) => {
                if peer_public.len() != 32 {
                    return Err(CryptoError::BadPublicKey);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(peer_public);
                let pk = x25519_dalek::PublicKey::from(arr);
                let shared = sk.diffie_hellman(&pk);
                if shared.as_bytes().iter().all(|&byte| byte == 0) {
                    return Err(CryptoError::BadPublicKey);
                }
                Ok(shared.as_bytes().to_vec())
            }
            EcdhePrivate::X448 { scalar, .. } => {
                let peer: [u8; 56] = peer_public
                    .try_into()
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let shared = x448(&scalar, &peer);
                if shared.iter().all(|&byte| byte == 0) {
                    return Err(CryptoError::BadPublicKey);
                }
                Ok(shared.to_vec())
            }
            EcdhePrivate::P256(sk) => {
                use p256::elliptic_curve::sec1::FromEncodedPoint;
                let pt = p256::EncodedPoint::from_bytes(peer_public)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let pk_opt = p256::PublicKey::from_encoded_point(&pt);
                let pk: p256::PublicKey = Option::from(pk_opt).ok_or(CryptoError::BadPublicKey)?;
                let shared = sk.diffie_hellman(&pk);
                Ok(shared.raw_secret_bytes().to_vec())
            }
            EcdhePrivate::P384(sk) => {
                use p384::elliptic_curve::sec1::FromEncodedPoint;
                let pt = p384::EncodedPoint::from_bytes(peer_public)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let pk_opt = p384::PublicKey::from_encoded_point(&pt);
                let pk: p384::PublicKey = Option::from(pk_opt).ok_or(CryptoError::BadPublicKey)?;
                let shared = sk.diffie_hellman(&pk);
                Ok(shared.raw_secret_bytes().to_vec())
            }
            EcdhePrivate::P521(sk) => {
                use p521::elliptic_curve::sec1::FromEncodedPoint;
                let pt = p521::EncodedPoint::from_bytes(peer_public)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let pk_opt = p521::PublicKey::from_encoded_point(&pt);
                let pk: p521::PublicKey = Option::from(pk_opt).ok_or(CryptoError::BadPublicKey)?;
                let shared = sk.diffie_hellman(&pk);
                Ok(shared.raw_secret_bytes().to_vec())
            }
            EcdhePrivate::Bp256 { sk, .. } => {
                let pk = ec14::PublicKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(peer_public)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let shared = ec14::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            EcdhePrivate::Bp384 { sk, .. } => {
                let pk = ec14::PublicKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(peer_public)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                let shared = ec14::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
                Ok(shared.raw_secret_bytes().to_vec())
            }
            // RFC 8446 4.2.8.1 / 7.4.1: validate 1 < Y < p-1 at the prime's length,
            // then Z = Y^x mod p left-padded to the prime's length.
            EcdhePrivate::Ffdhe { key, .. } => {
                if !key.peer_in_range(peer_public) {
                    return Err(CryptoError::BadPublicKey);
                }
                Ok(key.agree(peer_public))
            }
            EcdhePrivate::MlKem { dk, group } => {
                if peer_public.len() != group.kem_param().expect("kem").ct_len() {
                    return Err(CryptoError::BadPublicKey);
                }
                match dk {
                    MlKemDecapsKey::M512(dk) => mlkem512::decaps(&dk, peer_public),
                    MlKemDecapsKey::M768(dk) => mlkem768::decaps(&dk, peer_public),
                    MlKemDecapsKey::M1024(dk) => mlkem1024::decaps(&dk, peer_public),
                }
            }
            // The responder fixed the secret at encapsulation time; the peer
            // share it is handed back is the one it encapsulated against.
            EcdhePrivate::MlKemResponder { shared, .. } => Ok(shared),
            EcdhePrivate::Hybrid { ecdh, kem, group } => {
                let param = group.kem_param().expect("hybrid");
                // The initiator receives ct || pk, the responder was handed ek || pk.
                let kem_len = if matches!(*kem, EcdhePrivate::MlKemResponder { .. }) {
                    param.ek_len()
                } else {
                    param.ct_len()
                };
                let (kem_part, ecdh_part) = split_hybrid(group, peer_public, kem_len)?;
                let kem_ss = kem.agree(kem_part)?;
                let ecdh_ss = ecdh.agree(ecdh_part)?;
                Ok(join_hybrid(group, &kem_ss, &ecdh_ss))
            }
        }
    }
}

// ============================================================
//              RSA PKCS#1 v1.5 encryption (for RSA kex)
// ============================================================

/// The RSA modulus n of a public key, big-endian (k bytes); None for a
/// non-RSA key. `send ClientKeyExchange { encrypted_premaster: modulus }`
/// sends it as the ciphertext (tlsfuzzer's "modulus as premaster" probe).
pub fn rsa_modulus_bytes(pub_key: &PublicKey) -> Option<Vec<u8>> {
    match &pub_key.inner {
        PublicKeyInner::Rsa(key) => {
            use rsa::traits::PublicKeyParts;
            Some(key.n().to_bytes_be())
        }
        _ => None,
    }
}

/// Textbook RSA: c = m^e mod n over a caller-built encoded message (the
/// PKCS#1 v1.5 EM with a deliberate padding fault, or a raw block), left-
/// padded to k bytes. The `rsa` crate refuses to encrypt without a padding
/// scheme, which is the point here.
pub fn rsa_raw_encrypt(pub_key: &PublicKey, em: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match &pub_key.inner {
        PublicKeyInner::Rsa(key) => {
            use num_bigint::BigUint;
            use rsa::traits::PublicKeyParts;
            let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
            let e = BigUint::from_bytes_be(&key.e().to_bytes_be());
            let k = key.size();
            let m = BigUint::from_bytes_be(em);
            let c = m.modpow(&e, &n).to_bytes_be();
            let mut out = vec![0u8; k.saturating_sub(c.len())];
            out.extend_from_slice(&c);
            Ok(out)
        }
        _ => Err(CryptoError::UnsupportedSuite),
    }
}

/// Encrypt a plaintext under an RSA public key using PKCS#1 v1.5
/// padding. Used by the TLS 1.2 static-RSA key exchange path to
/// encrypt the 48-byte PreMasterSecret.
///
/// The RNG is seeded so the PKCS#1 padding bytes are deterministic
/// in tests. In a real TLS stack you'd want true randomness here;
/// for a test harness determinism is more useful.
pub fn rsa_pkcs1v15_encrypt(pub_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match &pub_key.inner {
        PublicKeyInner::Rsa(key) => {
            use rsa::Pkcs1v15Encrypt;
            let mut rng = ChaCha20Rng::from_seed([0xbb; 32]);
            key.encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
                .map_err(|_| CryptoError::BadPublicKey)
        }
        _ => Err(CryptoError::UnsupportedSuite),
    }
}

/// Decrypt a PKCS#1 v1.5 ciphertext under an RSA private key (the server
/// side of the TLS 1.2 static-RSA key exchange). Fails on bad padding; the
/// RFC 5246 7.4.7.1 random-premaster substitution is the caller's job
/// (`kex12::rsa_server_premaster`), not this primitive's.
pub fn rsa_pkcs1v15_decrypt(key: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.inner.as_ref() {
        PrivateKeyInner::Rsa(sk) => {
            use rsa::Pkcs1v15Encrypt;
            sk.decrypt(Pkcs1v15Encrypt, ciphertext)
                .map_err(|_| CryptoError::BadPublicKey)
        }
        _ => Err(CryptoError::UnsupportedSuite),
    }
}

/// `p - 1` for a big-endian modulus, left-padded to the modulus length: the
/// finite-field public value of order 2 a peer must reject.
pub fn bigint_minus_one_be(p_be: &[u8]) -> Vec<u8> {
    use num_bigint::BigUint;
    let v = BigUint::from_bytes_be(p_be) - BigUint::from(1u32);
    left_pad(&v.to_bytes_be(), p_be.len())
}

/// Miller-Rabin with fixed small bases on a big-endian integer. Used by the
/// tests that pin plzn's built-in DH groups as safe primes, not for anything
/// on the wire.
pub fn is_probable_prime_be(n_be: &[u8]) -> bool {
    use num_bigint::BigUint;
    let n = BigUint::from_bytes_be(n_be);
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    if n < BigUint::from(4u32) {
        return n == two || n == BigUint::from(3u32);
    }
    let n_minus_1 = &n - &one;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while &d % 2u32 == BigUint::from(0u32) {
        d /= 2u32;
        r += 1;
    }
    'witness: for a in [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = BigUint::from(a).modpow(&d, &n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 1..r {
            x = x.modpow(&two, &n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// `p` and `(p - 1) / 2` both probable primes.
pub fn is_probable_safe_prime_be(p_be: &[u8]) -> bool {
    use num_bigint::BigUint;
    let p = BigUint::from_bytes_be(p_be);
    let q = (&p - 1u32) / 2u32;
    is_probable_prime_be(p_be) && is_probable_prime_be(&q.to_bytes_be())
}

// ============================================================
//                  AES-CBC encrypt / decrypt
// ============================================================

/// AES-128-CBC encrypt. Input must be a multiple of 16 bytes
/// (the caller is responsible for PKCS#7 padding). Returns the
/// ciphertext (same length as input, no IV prepended).
pub fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    cbc_encrypt(CbcCipher::Aes128, key, iv, plaintext)
}

/// AES-128-CBC decrypt. Input must be a multiple of 16 bytes.
/// Returns the plaintext (same length as input; the caller strips
/// PKCS#7 padding).
pub fn aes128_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    cbc_decrypt(CbcCipher::Aes128, key, iv, ciphertext)
}

/// The block ciphers TLS 1.2 runs in CBC mode (RFC 5246 6.2.3.2 GenericBlockCipher).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CbcCipher {
    Aes128,
    Aes256,
    /// 3DES-EDE (RFC 5246 A.5): a 24-byte key and 8-byte blocks.
    TripleDes,
}

impl CbcCipher {
    pub fn key_len(self) -> usize {
        match self {
            CbcCipher::Aes128 => 16,
            CbcCipher::Aes256 => 32,
            CbcCipher::TripleDes => 24,
        }
    }
    /// Block length, which is also the explicit per-record IV length.
    pub fn block_len(self) -> usize {
        match self {
            CbcCipher::Aes128 | CbcCipher::Aes256 => 16,
            CbcCipher::TripleDes => 8,
        }
    }
}

fn cbc_encrypt_with<C>(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>
where
    C: cbc::cipher::BlockEncryptMut + cbc::cipher::BlockCipher + cbc::cipher::KeyInit,
{
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    let mut buf = plaintext.to_vec();
    let enc =
        cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| CryptoError::BadKeyLength)?;
    enc.encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, plaintext.len())
        .map_err(|_| CryptoError::AeadSealFailed)?;
    Ok(buf)
}

fn cbc_decrypt_with<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>
where
    C: cbc::cipher::BlockDecryptMut + cbc::cipher::BlockCipher + cbc::cipher::KeyInit,
{
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    let mut buf = ciphertext.to_vec();
    let dec =
        cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| CryptoError::BadKeyLength)?;
    dec.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| CryptoError::AeadOpenFailed)?;
    Ok(buf)
}

/// CBC-encrypt an already block-aligned buffer (the record layer pads).
pub fn cbc_encrypt(
    cipher: CbcCipher,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != cipher.key_len() {
        return Err(CryptoError::BadKeyLength);
    }
    if iv.len() != cipher.block_len() {
        return Err(CryptoError::BadNonceLength);
    }
    if !plaintext.len().is_multiple_of(cipher.block_len()) {
        return Err(CryptoError::BadKeyLength); // reuse; means "bad block alignment"
    }
    match cipher {
        CbcCipher::Aes128 => cbc_encrypt_with::<aes::Aes128>(key, iv, plaintext),
        CbcCipher::Aes256 => cbc_encrypt_with::<aes::Aes256>(key, iv, plaintext),
        CbcCipher::TripleDes => cbc_encrypt_with::<des::TdesEde3>(key, iv, plaintext),
    }
}

/// CBC-decrypt a block-aligned buffer; the caller strips the padding.
pub fn cbc_decrypt(
    cipher: CbcCipher,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != cipher.key_len() {
        return Err(CryptoError::BadKeyLength);
    }
    if iv.len() != cipher.block_len() {
        return Err(CryptoError::BadNonceLength);
    }
    if !ciphertext.len().is_multiple_of(cipher.block_len()) {
        return Err(CryptoError::BadKeyLength);
    }
    match cipher {
        CbcCipher::Aes128 => cbc_decrypt_with::<aes::Aes128>(key, iv, ciphertext),
        CbcCipher::Aes256 => cbc_decrypt_with::<aes::Aes256>(key, iv, ciphertext),
        CbcCipher::TripleDes => cbc_decrypt_with::<des::TdesEde3>(key, iv, ciphertext),
    }
}

// ============================================================
//                  Signature schemes + verify
// ============================================================

/// TLS SignatureScheme values we support (wedge scope: happy-path
/// variants across RSA and P-256). The numeric codes match RFC 8446
/// §4.2.3 wire values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureScheme {
    RsaPkcs1Sha256,       // 0x0401 — TLS 1.2 default RSA
    RsaPkcs1Sha384,       // 0x0501
    RsaPkcs1Sha512,       // 0x0601
    RsaPssRsaeSha256,     // 0x0804 — TLS 1.3 default RSA
    RsaPssRsaeSha384,     // 0x0805
    RsaPssRsaeSha512,     // 0x0806
    EcdsaSecp256r1Sha256, // 0x0403 — TLS 1.2 + 1.3 with P-256
    EcdsaSecp384r1Sha384, // 0x0503 - TLS 1.2 + 1.3 with P-384
    EcdsaSecp521r1Sha512, // 0x0603 - TLS 1.2 + 1.3 with P-521
    Ed25519,              // 0x0807 - EdDSA
    // The legacy RFC 5246 7.4.1.4.1 hash/signature pairs (TLS 1.2 only; RFC 8446
    // 4.2.3 forbids every one of them in a TLS 1.3 CertificateVerify). plzn signs
    // and verifies them so the SLOTH / signature-flexibility negatives can be
    // driven from its own client.
    RsaPkcs1Md5,    // 0x0101
    RsaPkcs1Sha1,   // 0x0201
    RsaPkcs1Sha224, // 0x0301
    EcdsaMd5,       // 0x0103
    EcdsaSha1,      // 0x0203
    EcdsaSha224,    // 0x0303
    // RSASSA-PSS under an id-RSASSA-PSS key (RFC 8446 4.2.3: rsa_pss_pss_*).
    RsaPssPssSha256, // 0x0809
    RsaPssPssSha384, // 0x080a
    RsaPssPssSha512, // 0x080b
}

impl SignatureScheme {
    pub fn wire_value(self) -> u16 {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => 0x0401,
            SignatureScheme::RsaPkcs1Sha384 => 0x0501,
            SignatureScheme::RsaPkcs1Sha512 => 0x0601,
            SignatureScheme::RsaPssRsaeSha256 => 0x0804,
            SignatureScheme::RsaPssRsaeSha384 => 0x0805,
            SignatureScheme::RsaPssRsaeSha512 => 0x0806,
            SignatureScheme::EcdsaSecp256r1Sha256 => 0x0403,
            SignatureScheme::EcdsaSecp384r1Sha384 => 0x0503,
            SignatureScheme::EcdsaSecp521r1Sha512 => 0x0603,
            SignatureScheme::Ed25519 => 0x0807,
            SignatureScheme::RsaPkcs1Md5 => 0x0101,
            SignatureScheme::RsaPkcs1Sha1 => 0x0201,
            SignatureScheme::RsaPkcs1Sha224 => 0x0301,
            SignatureScheme::EcdsaMd5 => 0x0103,
            SignatureScheme::EcdsaSha1 => 0x0203,
            SignatureScheme::EcdsaSha224 => 0x0303,
            SignatureScheme::RsaPssPssSha256 => 0x0809,
            SignatureScheme::RsaPssPssSha384 => 0x080a,
            SignatureScheme::RsaPssPssSha512 => 0x080b,
        }
    }

    pub fn from_wire_value(v: u16) -> Option<Self> {
        Some(match v {
            0x0401 => SignatureScheme::RsaPkcs1Sha256,
            0x0501 => SignatureScheme::RsaPkcs1Sha384,
            0x0601 => SignatureScheme::RsaPkcs1Sha512,
            0x0804 => SignatureScheme::RsaPssRsaeSha256,
            0x0805 => SignatureScheme::RsaPssRsaeSha384,
            0x0806 => SignatureScheme::RsaPssRsaeSha512,
            0x0403 => SignatureScheme::EcdsaSecp256r1Sha256,
            0x0503 => SignatureScheme::EcdsaSecp384r1Sha384,
            0x0603 => SignatureScheme::EcdsaSecp521r1Sha512,
            0x0807 => SignatureScheme::Ed25519,
            0x0101 => SignatureScheme::RsaPkcs1Md5,
            0x0201 => SignatureScheme::RsaPkcs1Sha1,
            0x0301 => SignatureScheme::RsaPkcs1Sha224,
            0x0103 => SignatureScheme::EcdsaMd5,
            0x0203 => SignatureScheme::EcdsaSha1,
            0x0303 => SignatureScheme::EcdsaSha224,
            0x0809 => SignatureScheme::RsaPssPssSha256,
            0x080a => SignatureScheme::RsaPssPssSha384,
            0x080b => SignatureScheme::RsaPssPssSha512,
            _ => return None,
        })
    }

    /// The hash the scheme names (None for Ed25519, which hashes internally).
    pub fn hash(self) -> Option<SigHash> {
        Some(match self {
            SignatureScheme::RsaPkcs1Md5 | SignatureScheme::EcdsaMd5 => SigHash::Md5,
            SignatureScheme::RsaPkcs1Sha1 | SignatureScheme::EcdsaSha1 => SigHash::Sha1,
            SignatureScheme::RsaPkcs1Sha224 | SignatureScheme::EcdsaSha224 => SigHash::Sha224,
            SignatureScheme::RsaPkcs1Sha256
            | SignatureScheme::RsaPssRsaeSha256
            | SignatureScheme::RsaPssPssSha256
            | SignatureScheme::EcdsaSecp256r1Sha256 => SigHash::Sha256,
            SignatureScheme::RsaPkcs1Sha384
            | SignatureScheme::RsaPssRsaeSha384
            | SignatureScheme::RsaPssPssSha384
            | SignatureScheme::EcdsaSecp384r1Sha384 => SigHash::Sha384,
            SignatureScheme::RsaPkcs1Sha512
            | SignatureScheme::RsaPssRsaeSha512
            | SignatureScheme::RsaPssPssSha512
            | SignatureScheme::EcdsaSecp521r1Sha512 => SigHash::Sha512,
            SignatureScheme::Ed25519 => return None,
        })
    }

    /// RSASSA-PKCS1-v1_5 (any hash).
    pub fn is_rsa_pkcs1(self) -> bool {
        matches!(
            self,
            SignatureScheme::RsaPkcs1Md5
                | SignatureScheme::RsaPkcs1Sha1
                | SignatureScheme::RsaPkcs1Sha224
                | SignatureScheme::RsaPkcs1Sha256
                | SignatureScheme::RsaPkcs1Sha384
                | SignatureScheme::RsaPkcs1Sha512
        )
    }

    /// RSASSA-PSS, whichever key type the codepoint names.
    pub fn is_rsa_pss(self) -> bool {
        self.is_rsa_pss_rsae() || self.is_rsa_pss_pss()
    }

    pub fn is_rsa_pss_rsae(self) -> bool {
        matches!(
            self,
            SignatureScheme::RsaPssRsaeSha256
                | SignatureScheme::RsaPssRsaeSha384
                | SignatureScheme::RsaPssRsaeSha512
        )
    }

    pub fn is_rsa_pss_pss(self) -> bool {
        matches!(
            self,
            SignatureScheme::RsaPssPssSha256
                | SignatureScheme::RsaPssPssSha384
                | SignatureScheme::RsaPssPssSha512
        )
    }

    pub fn is_rsa(self) -> bool {
        self.is_rsa_pkcs1() || self.is_rsa_pss()
    }

    pub fn is_ecdsa(self) -> bool {
        matches!(
            self,
            SignatureScheme::EcdsaMd5
                | SignatureScheme::EcdsaSha1
                | SignatureScheme::EcdsaSha224
                | SignatureScheme::EcdsaSecp256r1Sha256
                | SignatureScheme::EcdsaSecp384r1Sha384
                | SignatureScheme::EcdsaSecp521r1Sha512
        )
    }
}

/// The hash half of a signature scheme, for signing and for the raw
/// RSASSA encodings plzn builds itself (legacy pairs, chosen PSS salt / MGF1
/// hash, TLS 1.1-style signatures, pre-encryption padding edits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigHash {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl SigHash {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "md5" => SigHash::Md5,
            "sha1" => SigHash::Sha1,
            "sha224" => SigHash::Sha224,
            "sha256" => SigHash::Sha256,
            "sha384" => SigHash::Sha384,
            "sha512" => SigHash::Sha512,
            _ => return None,
        })
    }

    pub fn output_len(self) -> usize {
        match self {
            SigHash::Md5 => 16,
            SigHash::Sha1 => 20,
            SigHash::Sha224 => 28,
            SigHash::Sha256 => 32,
            SigHash::Sha384 => 48,
            SigHash::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            SigHash::Md5 => <md5::Md5 as Digest>::digest(data).to_vec(),
            SigHash::Sha1 => <Sha1 as Digest>::digest(data).to_vec(),
            SigHash::Sha224 => <sha2::Sha224 as Digest>::digest(data).to_vec(),
            SigHash::Sha256 => <Sha256 as Digest>::digest(data).to_vec(),
            SigHash::Sha384 => <Sha384 as Digest>::digest(data).to_vec(),
            SigHash::Sha512 => <Sha512 as Digest>::digest(data).to_vec(),
        }
    }

    /// The DER DigestInfo prefix RFC 8017 9.2 note 1 lists for the hash
    /// (EMSA-PKCS1-v1_5's `T` is this prefix followed by the digest).
    pub fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            SigHash::Md5 => &[
                0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                0x05, 0x00, 0x04, 0x10,
            ],
            SigHash::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            SigHash::Sha224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00, 0x04, 0x1c,
            ],
            SigHash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            SigHash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            SigHash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

// ---- RSASSA encodings built by hand (RFC 8017), so a test can choose the
// salt length, the MGF1 hash, the TLS 1.1 no-DigestInfo form, or corrupt the
// encoded message before the private-key operation. ----

/// EMSA-PKCS1-v1_5-ENCODE (RFC 8017 9.2): `00 01 FF..FF 00 T`, k bytes.
fn emsa_pkcs1_v15_encode(t: &[u8], k: usize) -> Result<Vec<u8>, CryptoError> {
    if k < t.len() + 11 {
        return Err(CryptoError::BadSignature);
    }
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat_n(0xff, k - t.len() - 3));
    em.push(0x00);
    em.extend_from_slice(t);
    Ok(em)
}

/// MGF1 (RFC 8017 B.2.1) with the given hash.
fn mgf1(hash: SigHash, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend(hash.digest(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-ENCODE (RFC 8017 9.1.1) over `m_hash` = Hash(M), with `salt` of
/// any length and `mgf1_hash` for the mask (the standard TLS form uses the
/// scheme's hash for both and a salt as long as the digest).
fn emsa_pss_encode(
    hash: SigHash,
    mgf1_hash: SigHash,
    salt: &[u8],
    m_hash: &[u8],
    em_bits: usize,
) -> Result<Vec<u8>, CryptoError> {
    let h_len = hash.output_len();
    let em_len = em_bits.div_ceil(8);
    let s_len = salt.len();
    if em_len < h_len + s_len + 2 {
        return Err(CryptoError::BadSignature);
    }
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash);
    m_prime.extend_from_slice(salt);
    let h = hash.digest(&m_prime);
    let mut db = vec![0u8; em_len - s_len - h_len - 2];
    db.push(0x01);
    db.extend_from_slice(salt);
    let db_mask = mgf1(mgf1_hash, &h, em_len - h_len - 1);
    let mut em: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 {
        em[0] &= 0xffu8 >> unused_bits;
    }
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

/// The RSA private-key operation on an already-encoded message: `em^d mod n`,
/// left-padded to the modulus length. Test code: no blinding.
fn rsa_private_raw(key: &rsa::RsaPrivateKey, em: &[u8]) -> Vec<u8> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let k = key.size();
    let m = rsa::BigUint::from_bytes_be(em);
    // The crate's private operation runs the CRT over the precomputed primes
    // (two half-size exponentiations instead of one full `d mod n`, about four
    // times cheaper) and skips blinding when no RNG is given, which keeps the
    // signature deterministic per test. `m >= n` (a deliberately oversized
    // encoded message) is the one input it refuses: fall back to the plain
    // exponentiation so the caller still gets its bytes.
    let s = rsa::hazmat::rsa_decrypt(None::<&mut ChaCha20Rng>, key, &m)
        .unwrap_or_else(|_| m.modpow(key.d(), key.n()));
    let mut out = s.to_bytes_be();
    while out.len() < k {
        out.insert(0, 0);
    }
    out
}

/// The RSA public-key operation: `s^e mod n`, left-padded to the modulus length.
fn rsa_public_raw(key: &RsaPublicKey, sig: &[u8]) -> Vec<u8> {
    use rsa::traits::PublicKeyParts;
    let k = key.size();
    let s = rsa::BigUint::from_bytes_be(sig);
    let m = s.modpow(key.e(), key.n());
    let mut out = m.to_bytes_be();
    while out.len() < k {
        out.insert(0, 0);
    }
    out
}

/// Verify an RSASSA-PKCS1-v1_5 signature under any of the hashes (the
/// rsa crate's verifier only covers SHA-2), by re-encoding and comparing.
fn rsa_pkcs1_verify_raw(
    key: &RsaPublicKey,
    hash: SigHash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use rsa::traits::PublicKeyParts;
    if signature.len() != key.size() {
        return Err(CryptoError::BadSignature);
    }
    let mut t = hash.digest_info_prefix().to_vec();
    t.extend(hash.digest(message));
    let expected = emsa_pkcs1_v15_encode(&t, key.size())?;
    if rsa_public_raw(key, signature) == expected {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

/// A pre-encryption edit to the RSASSA encoded message (`@ xor[signature.em,
/// i] = v` / `set`): index counts from the end when negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmEdit {
    pub index: i64,
    pub value: u8,
    pub xor: bool,
}

/// How a signature is to be produced beyond the scheme itself: the knobs
/// `send CertificateVerify { salt_length, mgf1_hash, format: tls11 }` and the
/// `signature.em` mutations expose.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SigningOptions {
    /// RSASSA-PSS salt length in bytes (default: the hash length).
    pub salt_len: Option<usize>,
    /// RSASSA-PSS MGF1 hash (default: the scheme's hash).
    pub mgf1_hash: Option<SigHash>,
    /// The TLS 1.0 / 1.1 signature form (RFC 4346 7.4.8): RSA over
    /// MD5(m) || SHA-1(m) with no DigestInfo, ECDSA over SHA-1(m).
    pub tls11: bool,
    /// Edits to the RSA encoded message before the private-key operation.
    pub em_edits: Vec<EmEdit>,
}

impl SigningOptions {
    pub fn is_default(&self) -> bool {
        *self == SigningOptions::default()
    }
}

/// A peer's public key, extracted from their X.509 certificate.
///
/// Only what we need: RSA (for PKCS#1 v1.5 + PSS), and P-256 ECDSA.
/// Everything else rejects at `from_certificate_der` time with
/// `UnsupportedSuite`. The wrapped inner types are RustCrypto-native;
/// callers never see them — they only use the plzn-owned `verify`
/// method.
pub struct PublicKey {
    inner: PublicKeyInner,
}

enum PublicKeyInner {
    Rsa(RsaPublicKey),
    /// An id-RSASSA-PSS key (RFC 4055): verifies rsa_pss_pss_* only.
    RsaPss(RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
    EcdsaP521(p521::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    /// Verify the TLS 1.0/1.1 digitally-signed form. RSA uses the historical
    /// MD5(message) || SHA-1(message) PKCS#1 v1.5 block without DigestInfo;
    /// ECDSA uses SHA-1 and is otherwise the normal DER signature.
    pub fn verify_tls11(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        match &self.inner {
            PublicKeyInner::Rsa(key) => {
                use rsa::traits::PublicKeyParts;
                let mut digest = Md5::digest(message).to_vec();
                digest.extend_from_slice(&Sha1::digest(message));
                let expected = emsa_pkcs1_v15_encode(&digest, key.size())?;
                if rsa_public_raw(key, signature) == expected {
                    Ok(())
                } else {
                    Err(CryptoError::BadSignature)
                }
            }
            PublicKeyInner::EcdsaP256(_)
            | PublicKeyInner::EcdsaP384(_)
            | PublicKeyInner::EcdsaP521(_) => {
                self.verify(SignatureScheme::EcdsaSha1, message, signature)
            }
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    /// RFC 8446 4.2.3: CertificateVerify has a narrower scheme/key policy
    /// than TLS 1.2 and certificate signatures.
    pub fn verify_tls13(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        use SignatureScheme as S;
        let permitted = matches!(
            (&self.inner, scheme),
            (
                PublicKeyInner::Rsa(_),
                S::RsaPssRsaeSha256 | S::RsaPssRsaeSha384 | S::RsaPssRsaeSha512
            ) | (
                PublicKeyInner::RsaPss(_),
                S::RsaPssPssSha256 | S::RsaPssPssSha384 | S::RsaPssPssSha512
            ) | (PublicKeyInner::EcdsaP256(_), S::EcdsaSecp256r1Sha256)
                | (PublicKeyInner::EcdsaP384(_), S::EcdsaSecp384r1Sha384)
                | (PublicKeyInner::EcdsaP521(_), S::EcdsaSecp521r1Sha512)
                | (PublicKeyInner::Ed25519(_), S::Ed25519)
        );
        if !permitted {
            return Err(CryptoError::BadSignature);
        }
        self.verify(scheme, message, signature)
    }
    /// Parse a DER-encoded X.509 certificate and extract the subject
    /// public key. We do **not** validate the certificate chain,
    /// validity period, or any extension — we trust the oracle and
    /// only need the SPKI for signature verification downstream.
    pub fn from_certificate_der(der: &[u8]) -> Result<Self, CryptoError> {
        let cert = Certificate::from_der(der).map_err(|_| CryptoError::BadPublicKey)?;
        Self::from_spki(&cert.tbs_certificate.subject_public_key_info)
    }

    /// The key's type (the `chain:` / `leaf_key` vocabulary).
    pub fn kind(&self) -> KeyKind {
        match &self.inner {
            PublicKeyInner::Rsa(_) => KeyKind::Rsa,
            PublicKeyInner::RsaPss(_) => KeyKind::RsaPss,
            PublicKeyInner::EcdsaP256(_) => KeyKind::EcdsaP256,
            PublicKeyInner::EcdsaP384(_) => KeyKind::EcdsaP384,
            PublicKeyInner::EcdsaP521(_) => KeyKind::EcdsaP521,
            PublicKeyInner::Ed25519(_) => KeyKind::Ed25519,
        }
    }

    /// Parse a public key from a raw SubjectPublicKeyInfo (DER). This is exactly the
    /// content of a RawPublicKey Certificate entry (RFC 7250 §3: "the Certificate ...
    /// contains ... the SubjectPublicKeyInfo structure"), an SPKI with no X.509 wrapping.
    /// Reuses the same algorithm dispatch as `from_certificate_der`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(der)
            .map_err(|_| CryptoError::BadPublicKey)?;
        Self::from_spki(&spki)
    }

    /// Extract the leaf public key from a TLS 1.3 CertificateEntry's `cert_data`, choosing
    /// the encoding by the negotiated certificate type (RFC 7250): RawPublicKey (2) means
    /// the bytes are a bare SubjectPublicKeyInfo; anything else (X.509 = 0, the default) is
    /// a DER certificate. This is the decode branch the handshake takes once
    /// server_certificate_type negotiation lands.
    pub fn from_certificate_entry(cert_data: &[u8], cert_type: u8) -> Result<Self, CryptoError> {
        use crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY;
        if cert_type == CERT_TYPE_RAW_PUBLIC_KEY {
            Self::from_spki_der(cert_data)
        } else {
            Self::from_certificate_der(cert_data)
        }
    }

    fn from_spki(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self, CryptoError> {
        let oid_str = spki.algorithm.oid.to_string();
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CryptoError::BadPublicKey)?;
        match oid_str.as_str() {
            // rsaEncryption (PKCS#1). SPKI body is a DER-encoded
            // RSAPublicKey SEQUENCE { modulus, publicExponent }.
            "1.2.840.113549.1.1.1" => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                let key =
                    RsaPublicKey::from_pkcs1_der(bits).map_err(|_| CryptoError::BadPublicKey)?;
                Ok(PublicKey {
                    inner: PublicKeyInner::Rsa(key),
                })
            }
            // id-RSASSA-PSS (RFC 4055 3.1): the same RSAPublicKey body, but the
            // key may only make (and verify) RSASSA-PSS signatures.
            "1.2.840.113549.1.1.10" => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                let key =
                    RsaPublicKey::from_pkcs1_der(bits).map_err(|_| CryptoError::BadPublicKey)?;
                Ok(PublicKey {
                    inner: PublicKeyInner::RsaPss(key),
                })
            }
            // id-ecPublicKey. The curve is named by the OID in
            // `spki.algorithm.parameters`; dispatch on it. secp384r1
            // (1.3.132.0.34) and secp521r1 (1.3.132.0.35) use the p384/p521
            // crates; everything else (prime256v1 / unspecified) defaults to P-256.
            "1.2.840.10045.2.1" => {
                let curve_oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                    .map(|o| o.to_string());
                match curve_oid.as_deref() {
                    Some("1.3.132.0.34") => {
                        let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(bits)
                            .map_err(|_| CryptoError::BadPublicKey)?;
                        Ok(PublicKey {
                            inner: PublicKeyInner::EcdsaP384(key),
                        })
                    }
                    Some("1.3.132.0.35") => {
                        let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(bits)
                            .map_err(|_| CryptoError::BadPublicKey)?;
                        Ok(PublicKey {
                            inner: PublicKeyInner::EcdsaP521(key),
                        })
                    }
                    _ => {
                        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(bits)
                            .map_err(|_| CryptoError::BadPublicKey)?;
                        Ok(PublicKey {
                            inner: PublicKeyInner::EcdsaP256(key),
                        })
                    }
                }
            }
            // id-Ed25519 (RFC 8410). The SPKI subjectPublicKey is the raw
            // 32-byte Ed25519 public key.
            "1.3.101.112" => {
                let arr: [u8; 32] = bits.try_into().map_err(|_| CryptoError::BadPublicKey)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                    .map_err(|_| CryptoError::BadPublicKey)?;
                Ok(PublicKey {
                    inner: PublicKeyInner::Ed25519(key),
                })
            }
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    /// Construct directly from an RSA public key. Test-only path —
    /// real code goes through `from_certificate_der`.
    #[cfg(test)]
    fn from_rsa(key: RsaPublicKey) -> Self {
        Self {
            inner: PublicKeyInner::Rsa(key),
        }
    }

    /// Construct directly from a P-256 verifying key. Test-only path.
    #[cfg(test)]
    fn from_ecdsa_p256(key: p256::ecdsa::VerifyingKey) -> Self {
        Self {
            inner: PublicKeyInner::EcdsaP256(key),
        }
    }

    /// Construct directly from a P-521 verifying key. Test-only path.
    #[cfg(test)]
    fn from_ecdsa_p521(key: p521::ecdsa::VerifyingKey) -> Self {
        Self {
            inner: PublicKeyInner::EcdsaP521(key),
        }
    }

    /// Construct directly from an Ed25519 verifying key. Test-only path.
    #[cfg(test)]
    fn from_ed25519(key: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            inner: PublicKeyInner::Ed25519(key),
        }
    }

    /// Verify `signature` over `message` under `scheme`. Returns
    /// `BadSignature` on any failure (bad encoding, wrong key type,
    /// authentication mismatch).
    ///
    /// ECDSA schemes are read the RFC 5246 7.4.1.4.1 way -- a hash and
    /// "ECDSA on whatever curve the key is on" -- so a P-256 key verifies an
    /// ecdsa_secp384r1_sha384 signature (Botan's TLS 1.2 client signs that way)
    /// and the legacy SHA-1 / SHA-224 / MD5 pairs; whether a TLS 1.3 peer may
    /// use a curve-mismatched scheme is the handshake's rule (RFC 8446 4.2.3),
    /// checked by the caller.
    pub fn verify(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match (&self.inner, scheme) {
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPkcs1Sha256) => {
                let vk = RsaPkcs1VerifyingKey::<Sha256>::new(key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPkcs1Sha384) => {
                let vk = RsaPkcs1VerifyingKey::<Sha384>::new(key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPkcs1Sha512) => {
                let vk = RsaPkcs1VerifyingKey::<Sha512>::new(key.clone());
                let sig = rsa::pkcs1v15::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            // The legacy PKCS#1 v1.5 pairs: the rsa crate's verifier covers SHA-2
            // only, so re-encode and compare.
            (
                PublicKeyInner::Rsa(key),
                SignatureScheme::RsaPkcs1Md5
                | SignatureScheme::RsaPkcs1Sha1
                | SignatureScheme::RsaPkcs1Sha224,
            ) => rsa_pkcs1_verify_raw(
                key,
                scheme.hash().expect("PKCS#1 scheme names a hash"),
                message,
                signature,
            ),
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPssRsaeSha256)
            | (PublicKeyInner::RsaPss(key), SignatureScheme::RsaPssPssSha256) => {
                let vk = RsaPssVerifyingKey::<Sha256>::new(key.clone());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPssRsaeSha384)
            | (PublicKeyInner::RsaPss(key), SignatureScheme::RsaPssPssSha384) => {
                let vk = RsaPssVerifyingKey::<Sha384>::new(key.clone());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::Rsa(key), SignatureScheme::RsaPssRsaeSha512)
            | (PublicKeyInner::RsaPss(key), SignatureScheme::RsaPssPssSha512) => {
                let vk = RsaPssVerifyingKey::<Sha512>::new(key.clone());
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                vk.verify(message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::EcdsaP256(key), s) if s.is_ecdsa() => {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                key.verify_prehash(
                    &ecdsa_prehash_for_field(&ecdsa_scheme_prehash(scheme, message), 32),
                    &sig,
                )
                .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::EcdsaP384(key), s) if s.is_ecdsa() => {
                use p384::ecdsa::signature::hazmat::PrehashVerifier;
                let sig = p384::ecdsa::Signature::from_der(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                key.verify_prehash(
                    &ecdsa_prehash_for_field(&ecdsa_scheme_prehash(scheme, message), 48),
                    &sig,
                )
                .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::EcdsaP521(key), s) if s.is_ecdsa() => {
                use p521::ecdsa::signature::hazmat::PrehashVerifier;
                let sig = p521::ecdsa::Signature::from_der(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                key.verify_prehash(
                    &ecdsa_prehash_for_field(&ecdsa_scheme_prehash(scheme, message), 66),
                    &sig,
                )
                .map_err(|_| CryptoError::BadSignature)
            }
            (PublicKeyInner::Ed25519(key), SignatureScheme::Ed25519) => {
                // Ed25519's TLS wire signature is the raw 64-byte value.
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| CryptoError::BadSignature)?;
                ed25519_dalek::Verifier::verify(key, message, &sig)
                    .map_err(|_| CryptoError::BadSignature)
            }
            // Any (key-type, scheme) combination we didn't enumerate
            // above is either unsupported or a type mismatch (e.g.
            // verifying an RSA signature under an ECDSA key, or an
            // rsa_pss_pss label on an rsaEncryption key).
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }

    /// Verify under TLS 1.2 / DTLS 1.2 semantics (RFC 5246 7.4.1.4.1): a
    /// SignatureAndHashAlgorithm names a hash and a signature ALGORITHM, so an
    /// ECDSA scheme applies to whatever curve the key is on -- Botan signs a
    /// P-256 key's ServerKeyExchange with `ecdsa_secp521r1_sha512` when the
    /// client lists it, meaning ECDSA over SHA-512. `verify` reads ECDSA that
    /// way for every scheme now, so this is the same check under its
    /// historical name.
    pub fn verify_tls12(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.verify(scheme, message, signature)
    }

    /// True for an id-RSASSA-PSS key (RFC 8446 4.2.3: only rsa_pss_pss_*
    /// signatures are valid under it).
    pub fn is_rsa_pss(&self) -> bool {
        matches!(self.inner, PublicKeyInner::RsaPss(_))
    }

    /// The RSA modulus, big-endian, for an RSA or RSA-PSS key (None otherwise):
    /// `send ClientKeyExchange { encrypted_premaster: modulus }`-style probes.
    pub fn rsa_modulus_be(&self) -> Option<Vec<u8>> {
        use rsa::traits::PublicKeyParts;
        match &self.inner {
            PublicKeyInner::Rsa(k) | PublicKeyInner::RsaPss(k) => Some(k.n().to_bytes_be()),
            _ => None,
        }
    }
}

/// Extract the DER SubjectPublicKeyInfo from an X.509 certificate for an RFC
/// 7250 RawPublicKey Certificate entry.
pub fn certificate_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use x509_cert::der::Encode;
    let cert = Certificate::from_der(cert_der).map_err(|_| CryptoError::BadPublicKey)?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| CryptoError::BadPublicKey)
}

// ============================================================
//                  Private key + signing
// ============================================================

/// A private key for signing, the mirror of `PublicKey` for
/// verification. Used by the server-side harness to sign
/// ServerKeyExchange (TLS 1.2) and CertificateVerify (TLS 1.3).
///
/// Constructed from the PKCS#8 DER that `CertBundle` produces.
/// The key type (RSA vs ECDSA) is detected from the PKCS#8 OID.
#[derive(Clone)]
pub struct PrivateKey {
    inner: Arc<PrivateKeyInner>,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKey")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// The digest an ECDSA signature scheme names (TLS 1.2 semantics: the hash
/// half of the SignatureAndHashAlgorithm), over `message`.
fn ecdsa_scheme_prehash(scheme: SignatureScheme, message: &[u8]) -> Vec<u8> {
    scheme.hash().unwrap_or(SigHash::Sha256).digest(message)
}

/// A prehash shorter than half the field size is refused by the ecdsa crate's
/// `bits2field`; left-padding with zeros keeps the integer value RFC 6979 /
/// SEC 1 would take, so MD5 / SHA-1 / SHA-224 digests sign on P-384 / P-521.
fn ecdsa_prehash_for_field(digest: &[u8], field_bytes: usize) -> Vec<u8> {
    let min = field_bytes / 2;
    if digest.len() >= min {
        return digest.to_vec();
    }
    let mut out = vec![0u8; min - digest.len()];
    out.extend_from_slice(digest);
    out
}

// Parsed keys are cached per run and cheaply cloned into each endpoint. The
// ~240-byte size difference between RSA and ECDSA isn't worth another Box.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
enum PrivateKeyInner {
    Rsa(rsa::RsaPrivateKey),
    /// An RSA key whose PKCS#8 wrapper says id-RSASSA-PSS: it signs only
    /// RSASSA-PSS (rsa_pss_pss_* in TLS 1.3).
    RsaPss(rsa::RsaPrivateKey),
    EcdsaP256(p256::ecdsa::SigningKey),
    EcdsaP384(p384::ecdsa::SigningKey),
    EcdsaP521(p521::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

/// The algorithm family of a [`PrivateKey`], for choosing signature schemes
/// and TLS 1.2 ClientCertificateType values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    RsaPss,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

impl KeyKind {
    /// The DSL's name for the kind (`chain:` entries, `leaf_key` matchers).
    pub fn dsl_name(self) -> &'static str {
        match self {
            KeyKind::Rsa => "rsa_2048",
            KeyKind::RsaPss => "rsa_pss",
            KeyKind::EcdsaP256 => "ecdsa_p256",
            KeyKind::EcdsaP384 => "ecdsa_p384",
            KeyKind::EcdsaP521 => "ecdsa_p521",
            KeyKind::Ed25519 => "ed25519",
        }
    }

    /// Parse a DSL name (`rsa` is an alias of `rsa_2048`).
    pub fn from_dsl_name(name: &str) -> Option<KeyKind> {
        Some(match name {
            "rsa" | "rsa_2048" => KeyKind::Rsa,
            "rsa_pss" => KeyKind::RsaPss,
            "ecdsa_p256" => KeyKind::EcdsaP256,
            "ecdsa_p384" => KeyKind::EcdsaP384,
            "ecdsa_p521" => KeyKind::EcdsaP521,
            "ed25519" => KeyKind::Ed25519,
            _ => return None,
        })
    }
}

impl PrivateKey {
    /// Parse a PKCS#8 DER-encoded private key. The algorithm OID inside the
    /// PKCS#8 wrapper picks the type: rsaEncryption, id-RSASSA-PSS,
    /// id-ecPublicKey (with the curve in its parameters: P-256 / P-384 /
    /// P-521) or id-Ed25519.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        use rsa::pkcs8::PrivateKeyInfo;
        if let Ok(pki) = PrivateKeyInfo::try_from(der) {
            match pki.algorithm.oid.to_string().as_str() {
                // id-RSASSA-PSS: the private key is a PKCS#1 RSAPrivateKey.
                "1.2.840.113549.1.1.10" => {
                    use rsa::pkcs1::DecodeRsaPrivateKey;
                    let key = rsa::RsaPrivateKey::from_pkcs1_der(pki.private_key)
                        .map_err(|_| CryptoError::BadPublicKey)?;
                    return Ok(PrivateKey {
                        inner: Arc::new(PrivateKeyInner::RsaPss(key)),
                    });
                }
                "1.2.840.10045.2.1" => {
                    let curve = pki
                        .algorithm
                        .parameters
                        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                        .map(|o| o.to_string());
                    match curve.as_deref() {
                        Some("1.3.132.0.34") => {
                            use p384::pkcs8::DecodePrivateKey;
                            let key = p384::ecdsa::SigningKey::from_pkcs8_der(der)
                                .map_err(|_| CryptoError::BadPublicKey)?;
                            return Ok(PrivateKey {
                                inner: Arc::new(PrivateKeyInner::EcdsaP384(key)),
                            });
                        }
                        Some("1.3.132.0.35") => {
                            let key = p521_signing_key_from_pkcs8(der)?;
                            return Ok(PrivateKey {
                                inner: Arc::new(PrivateKeyInner::EcdsaP521(key)),
                            });
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        // Try RSA first.
        {
            use rsa::pkcs8::DecodePrivateKey;
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                return Ok(PrivateKey {
                    inner: Arc::new(PrivateKeyInner::Rsa(key)),
                });
            }
        }
        // Try ECDSA P-256.
        {
            use p256::pkcs8::DecodePrivateKey;
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(PrivateKey {
                    inner: Arc::new(PrivateKeyInner::EcdsaP256(key)),
                });
            }
        }
        // ECDSA P-384 (the `--cert ecdsa-p384` bundle).
        {
            use p384::pkcs8::DecodePrivateKey;
            if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(PrivateKey {
                    inner: Arc::new(PrivateKeyInner::EcdsaP384(key)),
                });
            }
        }
        // ECDSA P-521 (the `--cert ecdsa-p521` bundle).
        if let Ok(key) = p521_signing_key_from_pkcs8(der) {
            return Ok(PrivateKey {
                inner: Arc::new(PrivateKeyInner::EcdsaP521(key)),
            });
        }
        // Ed25519 (the `--cert ed25519` bundle).
        {
            use ed25519_dalek::pkcs8::DecodePrivateKey;
            if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
                return Ok(PrivateKey {
                    inner: Arc::new(PrivateKeyInner::Ed25519(key)),
                });
            }
        }
        Err(CryptoError::BadPublicKey) // reuse; means "can't parse key"
    }

    /// True when this key can produce a signature under `scheme` (the TLS 1.3
    /// CertificateVerify rule, RFC 8446 4.2.3: the server picks a scheme the
    /// client listed AND its key can use; RSA keys sign only RSA-PSS there, an
    /// id-RSASSA-PSS key only rsa_pss_pss_*, an ECDSA key only its own curve's
    /// scheme).
    pub fn supports_scheme(&self, scheme: SignatureScheme) -> bool {
        matches!(
            (self.inner.as_ref(), scheme),
            (PrivateKeyInner::Rsa(_), SignatureScheme::RsaPssRsaeSha256)
                | (PrivateKeyInner::Rsa(_), SignatureScheme::RsaPssRsaeSha384)
                | (PrivateKeyInner::Rsa(_), SignatureScheme::RsaPssRsaeSha512)
                | (PrivateKeyInner::Rsa(_), SignatureScheme::RsaPkcs1Sha256)
                | (PrivateKeyInner::Rsa(_), SignatureScheme::RsaPkcs1Sha384)
                | (PrivateKeyInner::RsaPss(_), SignatureScheme::RsaPssPssSha256)
                | (PrivateKeyInner::RsaPss(_), SignatureScheme::RsaPssPssSha384)
                | (PrivateKeyInner::RsaPss(_), SignatureScheme::RsaPssPssSha512)
                | (
                    PrivateKeyInner::EcdsaP256(_),
                    SignatureScheme::EcdsaSecp256r1Sha256
                )
                | (
                    PrivateKeyInner::EcdsaP384(_),
                    SignatureScheme::EcdsaSecp384r1Sha384
                )
                | (
                    PrivateKeyInner::EcdsaP521(_),
                    SignatureScheme::EcdsaSecp521r1Sha512
                )
                | (PrivateKeyInner::Ed25519(_), SignatureScheme::Ed25519)
        )
    }

    /// The TLS 1.3 CertificateVerify schemes this key can use, in the order the
    /// server prefers them (RSA-PSS only for RSA keys: RFC 8446 4.2.3 forbids
    /// PKCS#1 v1.5 in CertificateVerify).
    pub fn tls13_signing_schemes(&self) -> &'static [SignatureScheme] {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(_) => &[
                SignatureScheme::RsaPssRsaeSha256,
                SignatureScheme::RsaPssRsaeSha384,
                SignatureScheme::RsaPssRsaeSha512,
            ],
            PrivateKeyInner::RsaPss(_) => &[
                SignatureScheme::RsaPssPssSha256,
                SignatureScheme::RsaPssPssSha384,
                SignatureScheme::RsaPssPssSha512,
            ],
            PrivateKeyInner::EcdsaP256(_) => &[SignatureScheme::EcdsaSecp256r1Sha256],
            PrivateKeyInner::EcdsaP384(_) => &[SignatureScheme::EcdsaSecp384r1Sha384],
            PrivateKeyInner::EcdsaP521(_) => &[SignatureScheme::EcdsaSecp521r1Sha512],
            PrivateKeyInner::Ed25519(_) => &[SignatureScheme::Ed25519],
        }
    }

    pub fn is_ed25519(&self) -> bool {
        matches!(self.inner.as_ref(), PrivateKeyInner::Ed25519(_))
    }

    pub fn kind(&self) -> KeyKind {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(_) => KeyKind::Rsa,
            PrivateKeyInner::RsaPss(_) => KeyKind::RsaPss,
            PrivateKeyInner::EcdsaP256(_) => KeyKind::EcdsaP256,
            PrivateKeyInner::EcdsaP384(_) => KeyKind::EcdsaP384,
            PrivateKeyInner::EcdsaP521(_) => KeyKind::EcdsaP521,
            PrivateKeyInner::Ed25519(_) => KeyKind::Ed25519,
        }
    }

    /// Every signature scheme this key can sign with, most preferred first
    /// (RSA: the PSS schemes before PKCS#1 v1.5, SHA-256 before the longer
    /// hashes). TLS 1.2 servers intersect this with the client's
    /// signature_algorithms; TLS 1.2 clients with the CertificateRequest's.
    /// The legacy SHA-1 / SHA-224 / MD5 pairs are deliberately absent: plzn
    /// signs them only on request (`send CertificateVerify { sign_with }`).
    pub fn signature_schemes(&self) -> Vec<SignatureScheme> {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(_) => vec![
                SignatureScheme::RsaPssRsaeSha256,
                SignatureScheme::RsaPssRsaeSha384,
                SignatureScheme::RsaPssRsaeSha512,
                SignatureScheme::RsaPkcs1Sha256,
                SignatureScheme::RsaPkcs1Sha384,
                SignatureScheme::RsaPkcs1Sha512,
            ],
            PrivateKeyInner::RsaPss(_) => vec![
                SignatureScheme::RsaPssPssSha256,
                SignatureScheme::RsaPssPssSha384,
                SignatureScheme::RsaPssPssSha512,
            ],
            PrivateKeyInner::EcdsaP256(_) => vec![SignatureScheme::EcdsaSecp256r1Sha256],
            PrivateKeyInner::EcdsaP384(_) => vec![SignatureScheme::EcdsaSecp384r1Sha384],
            PrivateKeyInner::EcdsaP521(_) => vec![SignatureScheme::EcdsaSecp521r1Sha512],
            PrivateKeyInner::Ed25519(_) => vec![SignatureScheme::Ed25519],
        }
    }

    /// An rsaEncryption key (static RSA key exchange, PKCS#1 v1.5 and
    /// rsa_pss_rsae signatures). False for an id-RSASSA-PSS key.
    pub fn is_rsa(&self) -> bool {
        matches!(self.inner.as_ref(), PrivateKeyInner::Rsa(_))
    }

    /// An id-RSASSA-PSS key: RSA signatures only, and only PSS.
    pub fn is_rsa_pss(&self) -> bool {
        matches!(self.inner.as_ref(), PrivateKeyInner::RsaPss(_))
    }

    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self.inner.as_ref(),
            PrivateKeyInner::EcdsaP256(_)
                | PrivateKeyInner::EcdsaP384(_)
                | PrivateKeyInner::EcdsaP521(_)
        )
    }

    /// Default TLS 1.3 signature scheme for this key type.
    pub fn default_signature_scheme(&self) -> SignatureScheme {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(_) => SignatureScheme::RsaPssRsaeSha256,
            PrivateKeyInner::RsaPss(_) => SignatureScheme::RsaPssPssSha256,
            PrivateKeyInner::EcdsaP256(_) => SignatureScheme::EcdsaSecp256r1Sha256,
            PrivateKeyInner::EcdsaP384(_) => SignatureScheme::EcdsaSecp384r1Sha384,
            PrivateKeyInner::EcdsaP521(_) => SignatureScheme::EcdsaSecp521r1Sha512,
            PrivateKeyInner::Ed25519(_) => SignatureScheme::Ed25519,
        }
    }

    /// Extract the corresponding `PublicKey` for verification.
    pub fn public_key(&self) -> PublicKey {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(sk) => PublicKey {
                inner: PublicKeyInner::Rsa(rsa::RsaPublicKey::from(sk)),
            },
            PrivateKeyInner::RsaPss(sk) => PublicKey {
                inner: PublicKeyInner::RsaPss(rsa::RsaPublicKey::from(sk)),
            },
            PrivateKeyInner::EcdsaP256(sk) => PublicKey {
                inner: PublicKeyInner::EcdsaP256(*sk.verifying_key()),
            },
            PrivateKeyInner::EcdsaP384(sk) => PublicKey {
                inner: PublicKeyInner::EcdsaP384(*sk.verifying_key()),
            },
            PrivateKeyInner::EcdsaP521(sk) => PublicKey {
                inner: PublicKeyInner::EcdsaP521(p521::ecdsa::VerifyingKey::from(sk)),
            },
            PrivateKeyInner::Ed25519(sk) => PublicKey {
                inner: PublicKeyInner::Ed25519(sk.verifying_key()),
            },
        }
    }

    /// Sign `message` under `scheme`. The caller is responsible
    /// for constructing the correct input (e.g. the RFC 8446
    /// CertificateVerify signed blob, or the TLS 1.2 SKE
    /// client_random || server_random || params).
    ///
    /// Returns the signature bytes in the wire format TLS expects:
    ///   * RSA PKCS#1 v1.5 / PSS: raw signature bytes
    ///   * ECDSA: DER-encoded (SEQUENCE { r, s })
    ///   * Ed25519: the raw 64-byte signature
    pub fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_with_options(scheme, message, &SigningOptions::default())
    }

    /// `sign` with the knobs a CertificateVerify probe needs: a chosen PSS salt
    /// length or MGF1 hash, the TLS 1.1 signature form, edits to the RSA
    /// encoded message before the private-key operation. ECDSA schemes are
    /// read the TLS 1.2 way (a hash on the key's own curve), so a P-256 key
    /// signs ecdsa_secp384r1_sha384 as "ECDSA over SHA-384"; an RSA key of
    /// either kind signs any RSA scheme (the peer, not the signer, is what a
    /// key/scheme mismatch tests).
    pub fn sign_with_options(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        opts: &SigningOptions,
    ) -> Result<Vec<u8>, CryptoError> {
        match self.inner.as_ref() {
            PrivateKeyInner::Rsa(key) | PrivateKeyInner::RsaPss(key) => {
                if !scheme.is_rsa() {
                    return Err(CryptoError::UnsupportedSuite);
                }
                rsa_sign_em(key, scheme, message, opts)
            }
            PrivateKeyInner::EcdsaP256(_)
            | PrivateKeyInner::EcdsaP384(_)
            | PrivateKeyInner::EcdsaP521(_) => {
                if !opts.tls11 && !scheme.is_ecdsa() {
                    return Err(CryptoError::UnsupportedSuite);
                }
                // RFC 4492 5.10: TLS 1.1 ECDSA signatures are over SHA-1.
                let digest = if opts.tls11 {
                    SigHash::Sha1.digest(message)
                } else {
                    ecdsa_scheme_prehash(scheme, message)
                };
                self.ecdsa_sign_prehash(&digest)
            }
            PrivateKeyInner::Ed25519(key) => {
                if scheme != SignatureScheme::Ed25519 || opts.tls11 {
                    return Err(CryptoError::UnsupportedSuite);
                }
                use ed25519_dalek::Signer;
                // RFC 8446 4.2.3 / RFC 8032: the wire form is the raw 64-byte
                // signature; pure Ed25519 hashes internally.
                Ok(key.sign(message).to_bytes().to_vec())
            }
        }
    }

    /// ECDSA over an already-computed digest, DER-encoded (SEQUENCE { r, s }).
    fn ecdsa_sign_prehash(&self, digest: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self.inner.as_ref() {
            PrivateKeyInner::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&ecdsa_prehash_for_field(digest, 32))
                    .map_err(|_| CryptoError::BadSignature)?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            PrivateKeyInner::EcdsaP384(key) => {
                use p384::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(&ecdsa_prehash_for_field(digest, 48))
                    .map_err(|_| CryptoError::BadSignature)?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            PrivateKeyInner::EcdsaP521(key) => {
                use p521::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p521::ecdsa::Signature = key
                    .sign_prehash(&ecdsa_prehash_for_field(digest, 66))
                    .map_err(|_| CryptoError::BadSignature)?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            _ => Err(CryptoError::UnsupportedSuite),
        }
    }
}

/// The p521 crate's ECDSA signing key has no PKCS#8 decoder of its own: go
/// through the curve's `SecretKey`.
fn p521_signing_key_from_pkcs8(der: &[u8]) -> Result<p521::ecdsa::SigningKey, CryptoError> {
    use p521::pkcs8::DecodePrivateKey;
    let secret = p521::SecretKey::from_pkcs8_der(der).map_err(|_| CryptoError::BadPublicKey)?;
    p521::ecdsa::SigningKey::from_bytes(&secret.to_bytes()).map_err(|_| CryptoError::BadPublicKey)
}

/// RSASSA signing on an RSA key of either kind: encode (PKCS#1 v1.5 with the
/// scheme's DigestInfo, PSS with the chosen salt / MGF1 hash, or the TLS 1.1
/// MD5 || SHA-1 form), apply the encoded-message edits, run the private-key
/// operation.
fn rsa_sign_em(
    key: &rsa::RsaPrivateKey,
    scheme: SignatureScheme,
    message: &[u8],
    opts: &SigningOptions,
) -> Result<Vec<u8>, CryptoError> {
    use rsa::traits::PublicKeyParts;
    let k = key.size();
    let mut em = if opts.tls11 {
        // RFC 4346 7.4.8 / 4.7: the RSA signature covers MD5(m) || SHA-1(m)
        // with PKCS#1 block type 1 and no DigestInfo.
        let mut t = SigHash::Md5.digest(message);
        t.extend(SigHash::Sha1.digest(message));
        emsa_pkcs1_v15_encode(&t, k)?
    } else if scheme.is_rsa_pkcs1() {
        let h = scheme.hash().ok_or(CryptoError::UnsupportedSuite)?;
        let mut t = h.digest_info_prefix().to_vec();
        t.extend(h.digest(message));
        emsa_pkcs1_v15_encode(&t, k)?
    } else if scheme.is_rsa_pss() {
        let h = scheme.hash().ok_or(CryptoError::UnsupportedSuite)?;
        let salt_len = opts.salt_len.unwrap_or(h.output_len());
        let mgf = opts.mgf1_hash.unwrap_or(h);
        // A seeded RNG keeps the salt (and so the signature) deterministic
        // per test, like every other random plzn draws.
        let mut rng = ChaCha20Rng::from_seed([0xcc; 32]);
        let mut salt = vec![0u8; salt_len];
        rng.fill_bytes(&mut salt);
        let mod_bits = key.n().bits();
        emsa_pss_encode(h, mgf, &salt, &h.digest(message), mod_bits - 1)?
    } else {
        return Err(CryptoError::UnsupportedSuite);
    };
    for edit in &opts.em_edits {
        let len = em.len() as i64;
        let idx = if edit.index < 0 {
            len + edit.index
        } else {
            edit.index
        };
        if idx < 0 || idx >= len {
            return Err(CryptoError::BadSignature);
        }
        let idx = idx as usize;
        if edit.xor {
            em[idx] ^= edit.value;
        } else {
            em[idx] = edit.value;
        }
    }
    Ok(rsa_private_raw(key, &em))
}

// ============================================================
//                              tests
// ============================================================

// ============================================================
//              X.509 path validation (peer certificates)
// ============================================================

/// Why a presented certificate chain was rejected. `alert_code` is the TLS
/// alert a conformant endpoint answers with (RFC 5246 7.2.2 / RFC 8446 6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A presented certificate did not parse (bad_certificate).
    Malformed(String),
    /// The clock is past a certificate's notAfter (certificate_expired).
    Expired { subject: String },
    /// The clock is before a certificate's notBefore (certificate_expired).
    NotYetValid { subject: String },
    /// A signature did not verify under its issuer's key (bad_certificate).
    BadSignature { subject: String },
    /// A signature algorithm plzn cannot verify (unsupported_certificate).
    UnsupportedAlgorithm { subject: String, oid: String },
    /// An issuing certificate in the chain is not a CA (unknown_ca).
    NotACa { subject: String },
    /// Nothing presented or trusted issued the top of the path (unknown_ca).
    UnknownIssuer { subject: String, issuer: String },
}

impl ChainError {
    pub fn alert_code(&self) -> u8 {
        match self {
            ChainError::Malformed(_) | ChainError::BadSignature { .. } => 42,
            ChainError::UnsupportedAlgorithm { .. } => 43,
            ChainError::Expired { .. } | ChainError::NotYetValid { .. } => 45,
            ChainError::NotACa { .. } | ChainError::UnknownIssuer { .. } => 48,
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Malformed(why) => write!(f, "malformed certificate: {}", why),
            ChainError::Expired { subject } => write!(f, "certificate `{}` has expired", subject),
            ChainError::NotYetValid { subject } => {
                write!(f, "certificate `{}` is not yet valid", subject)
            }
            ChainError::BadSignature { subject } => {
                write!(
                    f,
                    "signature on certificate `{}` does not verify under its issuer's key",
                    subject
                )
            }
            ChainError::UnsupportedAlgorithm { subject, oid } => {
                write!(
                    f,
                    "certificate `{}` is signed with an unsupported algorithm ({})",
                    subject, oid
                )
            }
            ChainError::NotACa { subject } => {
                write!(f, "issuing certificate `{}` is not a CA", subject)
            }
            ChainError::UnknownIssuer { subject, issuer } => write!(
                f,
                "certificate `{}` was issued by `{}`, which is neither presented nor trusted",
                subject, issuer
            ),
        }
    }
}

impl std::error::Error for ChainError {}

struct ParsedCert {
    cert: Certificate,
    der: Vec<u8>,
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
    subject: String,
}

fn parse_chain_cert(der: &[u8]) -> Result<ParsedCert, ChainError> {
    use x509_cert::der::Encode;
    let cert = Certificate::from_der(der).map_err(|e| ChainError::Malformed(e.to_string()))?;
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(ChainError::Malformed(
            "inner and outer signatureAlgorithm differ".into(),
        ));
    }
    let subject_der = cert
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| ChainError::Malformed(e.to_string()))?;
    let issuer_der = cert
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| ChainError::Malformed(e.to_string()))?;
    let subject = cert.tbs_certificate.subject.to_string();
    Ok(ParsedCert {
        cert,
        der: der.to_vec(),
        subject_der,
        issuer_der,
        subject,
    })
}

/// The scheme a certificate's `signatureAlgorithm` maps to, for verifying its
/// TBSCertificate under the issuer's key (RFC 5280 4.1.1.2 / RFC 8410 3).
fn certificate_signature_scheme(oid: &str) -> Option<SignatureScheme> {
    Some(match oid {
        "1.2.840.113549.1.1.11" => SignatureScheme::RsaPkcs1Sha256, // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => SignatureScheme::RsaPkcs1Sha384, // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => SignatureScheme::RsaPkcs1Sha512, // sha512WithRSAEncryption
        "1.2.840.10045.4.3.2" => SignatureScheme::EcdsaSecp256r1Sha256, // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => SignatureScheme::EcdsaSecp384r1Sha384, // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => SignatureScheme::EcdsaSecp521r1Sha512, // ecdsa-with-SHA512
        "1.3.101.112" => SignatureScheme::Ed25519,                  // id-Ed25519
        "1.2.840.113549.1.1.4" => SignatureScheme::RsaPkcs1Md5,     // md5WithRSAEncryption
        "1.2.840.113549.1.1.5" => SignatureScheme::RsaPkcs1Sha1,    // sha1WithRSAEncryption
        "1.2.840.113549.1.1.14" => SignatureScheme::RsaPkcs1Sha224, // sha224WithRSAEncryption
        "1.2.840.10045.4.1" => SignatureScheme::EcdsaSha1,          // ecdsa-with-SHA1
        "1.2.840.10045.4.3.1" => SignatureScheme::EcdsaSha224,      // ecdsa-with-SHA224
        _ => return None,
    })
}

/// The scheme an RSASSA-PSS `signatureAlgorithm` (RFC 4055 3.1) maps to: the
/// hash from its parameters, rsa_pss_pss_* under an
/// id-RSASSA-PSS issuer key and rsa_pss_rsae_* under an rsaEncryption one.
fn certificate_pss_scheme(
    params: Option<&x509_cert::der::Any>,
    issuer_is_pss: bool,
) -> Result<SignatureScheme, ChainError> {
    let params = params
        .ok_or_else(|| {
            ChainError::Malformed("RSASSA-PSS signature parameters are required".into())
        })?
        .decode_as::<rsa::pkcs1::RsaPssParams>()
        .map_err(|e| ChainError::Malformed(format!("RSASSA-PSS parameters: {e}")))?;
    let oid = params.hash.oid.to_string();
    let (rsae, pss, length) = match oid.as_str() {
        "2.16.840.1.101.3.4.2.1" => (
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssPssSha256,
            32,
        ),
        "2.16.840.1.101.3.4.2.2" => (
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssPssSha384,
            48,
        ),
        "2.16.840.1.101.3.4.2.3" => (
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPssPssSha512,
            64,
        ),
        _ => {
            return Err(ChainError::Malformed(format!(
                "unsupported RSASSA-PSS certificate hash {oid}"
            )));
        }
    };
    let valid_hash_params = |p: Option<x509_cert::der::asn1::AnyRef<'_>>| {
        p.is_none_or(|v| v == x509_cert::der::asn1::AnyRef::NULL)
    };
    if !valid_hash_params(params.hash.parameters)
        || params.mask_gen.oid.to_string() != "1.2.840.113549.1.1.8"
        || !params
            .mask_gen
            .parameters
            .is_some_and(|mgf| mgf.oid == params.hash.oid && valid_hash_params(mgf.parameters))
        || params.salt_len != length
    {
        return Err(ChainError::Malformed("unsupported RSASSA-PSS certificate parameters (requires matching MGF1 hash and digest-length salt)".into()));
    }
    Ok(if issuer_is_pss { pss } else { rsae })
}

/// Return the TLS SignatureScheme corresponding to an X.509 certificate's
/// signatureAlgorithm, plus whether the certificate is self-issued. TLS 1.3's
/// signature_algorithms_cert check applies to certificates in the transmitted
/// chain, but a self-issued trust anchor may be omitted from that check.
pub fn certificate_signature_metadata(der: &[u8]) -> Result<(SignatureScheme, bool), ChainError> {
    let parsed = parse_chain_cert(der)?;
    let self_issued = parsed.subject_der == parsed.issuer_der;
    let oid = parsed.cert.signature_algorithm.oid.to_string();
    let scheme = if oid == "1.2.840.113549.1.1.10" {
        // For a self-issued PSS certificate the issuer key is this
        // certificate's SPKI. For a non-self-issued leaf without its issuer in
        // hand, rsae is the conservative/default form; callers that validate a
        // full chain still determine the precise form in verify_issued_by.
        let issuer_is_pss = self_issued
            && parsed
                .cert
                .tbs_certificate
                .subject_public_key_info
                .algorithm
                .oid
                .to_string()
                == "1.2.840.113549.1.1.10";
        certificate_pss_scheme(
            parsed.cert.signature_algorithm.parameters.as_ref(),
            issuer_is_pss,
        )?
    } else {
        certificate_signature_scheme(&oid).ok_or(ChainError::UnsupportedAlgorithm {
            subject: parsed.subject,
            oid,
        })?
    };
    Ok((scheme, self_issued))
}

/// Verify `subject`'s signature under `issuer_key`.
fn verify_issued_by(issuer_key: &PublicKey, subject: &ParsedCert) -> Result<(), ChainError> {
    use x509_cert::der::Encode;
    let oid = subject.cert.signature_algorithm.oid.to_string();
    let scheme = if oid == "1.2.840.113549.1.1.10" {
        certificate_pss_scheme(
            subject.cert.signature_algorithm.parameters.as_ref(),
            issuer_key.is_rsa_pss(),
        )?
    } else {
        certificate_signature_scheme(&oid).ok_or_else(|| ChainError::UnsupportedAlgorithm {
            subject: subject.subject.clone(),
            oid: oid.clone(),
        })?
    };
    let tbs = subject
        .cert
        .tbs_certificate
        .to_der()
        .map_err(|e| ChainError::Malformed(e.to_string()))?;
    let sig = subject.cert.signature.as_bytes().ok_or_else(|| {
        ChainError::Malformed("certificate signature is not octet-aligned".into())
    })?;
    issuer_key
        .verify(scheme, &tbs, sig)
        .map_err(|_| ChainError::BadSignature {
            subject: subject.subject.clone(),
        })
}

/// basicConstraints.cA (RFC 5280 4.2.1.9); a certificate without the
/// extension is not a CA.
fn validate_certificate_profile(cert: &ParsedCert, leaf: bool) -> Result<(), ChainError> {
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let mut seen = std::collections::HashSet::new();
    for extension in cert.cert.tbs_certificate.extensions.iter().flatten() {
        let oid = extension.extn_id.to_string();
        if !seen.insert(oid.clone()) {
            return Err(ChainError::Malformed(format!("duplicate extension {oid}")));
        }
        let data = extension.extn_value.as_bytes();
        let malformed = |e| ChainError::Malformed(format!("extension {oid}: {e}"));
        match oid.as_str() {
            "2.5.29.19" => {
                BasicConstraints::from_der(data).map_err(malformed)?;
            }
            "2.5.29.15" => {
                let usage = KeyUsage::from_der(data).map_err(malformed)?;
                if (leaf && !usage.digital_signature()) || (!leaf && !usage.key_cert_sign()) {
                    return Err(ChainError::Malformed(
                        "certificate keyUsage forbids its client-auth path role".into(),
                    ));
                }
            }
            "2.5.29.37" => {
                let eku = ExtendedKeyUsage::from_der(data).map_err(malformed)?;
                if !eku.0.iter().any(|oid| {
                    matches!(
                        oid.to_string().as_str(),
                        "1.3.6.1.5.5.7.3.2" | "2.5.29.37.0"
                    )
                }) {
                    return Err(ChainError::Malformed(
                        "certificate EKU does not permit client authentication".into(),
                    ));
                }
            }
            "2.5.29.17" => {
                x509_cert::ext::pkix::SubjectAltName::from_der(data).map_err(malformed)?;
            }
            // Unsupported restrictions must never silently disappear.
            "2.5.29.30" | "2.5.29.36" | "2.5.29.54" | "2.5.29.33" => {
                return Err(ChainError::Malformed(format!(
                    "unsupported certificate constraint {oid}"
                )));
            }
            _ if extension.critical => {
                return Err(ChainError::Malformed(format!(
                    "unsupported critical extension {oid}"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_issuer_profile(cert: &ParsedCert, ca_below: usize) -> Result<(), ChainError> {
    validate_certificate_profile(cert, false)?;
    if !is_ca(cert) {
        return Err(ChainError::NotACa {
            subject: cert.subject.clone(),
        });
    }
    for extension in cert.cert.tbs_certificate.extensions.iter().flatten() {
        if extension.extn_id.to_string() == "2.5.29.19" {
            let constraints =
                x509_cert::ext::pkix::BasicConstraints::from_der(extension.extn_value.as_bytes())
                    .map_err(|e| ChainError::Malformed(e.to_string()))?;
            if constraints
                .path_len_constraint
                .is_some_and(|limit| ca_below > usize::from(limit))
            {
                return Err(ChainError::Malformed(
                    "certificate pathLenConstraint exceeded".into(),
                ));
            }
        }
    }
    Ok(())
}

fn is_ca(cert: &ParsedCert) -> bool {
    let Some(exts) = &cert.cert.tbs_certificate.extensions else {
        return false;
    };
    exts.iter()
        .find(|e| e.extn_id.to_string() == "2.5.29.19")
        .and_then(|e| {
            x509_cert::ext::pkix::BasicConstraints::from_der(e.extn_value.as_bytes()).ok()
        })
        .map(|bc| bc.ca)
        .unwrap_or(false)
}

/// Validate the path from `chain[0]` (the leaf) to one of `anchors` (DER
/// certificates), through the other presented certificates, at Unix time
/// `now`: every presented certificate must be within its validity period, each
/// link's signature must verify under the issuer's key, every issuing
/// certificate in the chain must be a CA, and the top of the path must be an
/// anchor itself or signed by one. A self-signed certificate verifies only when
/// it is an anchor. Anchors that do not parse are ignored.
pub fn verify_certificate_chain(
    chain: &[&[u8]],
    anchors: &[&[u8]],
    now: u64,
) -> Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::Malformed("empty certificate list".into()));
    }
    let presented = chain
        .iter()
        .map(|der| parse_chain_cert(der))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors: Vec<ParsedCert> = anchors
        .iter()
        .filter_map(|der| parse_chain_cert(der).ok())
        .collect();
    for c in &presented {
        let validity = &c.cert.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        if now < not_before {
            return Err(ChainError::NotYetValid {
                subject: c.subject.clone(),
            });
        }
        if now > not_after {
            return Err(ChainError::Expired {
                subject: c.subject.clone(),
            });
        }
    }
    validate_certificate_profile(&presented[0], true)?;
    let mut used = vec![false; presented.len()];
    used[0] = true;
    walk_chain(&presented[0], &presented, &anchors, &mut used, 0, 0)
}

fn walk_chain(
    current: &ParsedCert,
    presented: &[ParsedCert],
    anchors: &[ParsedCert],
    used: &mut [bool],
    depth: usize,
    ca_below: usize,
) -> Result<(), ChainError> {
    if depth >= 8 {
        return Err(ChainError::Malformed(
            "certificate path exceeds eight links".into(),
        ));
    }
    if anchors.iter().any(|anchor| anchor.der == current.der) {
        return Ok(());
    }
    let below_issuer =
        ca_below + usize::from(depth > 0 && current.subject_der != current.issuer_der);
    let mut failure = ChainError::UnknownIssuer {
        subject: current.subject.clone(),
        issuer: current.cert.tbs_certificate.issuer.to_string(),
    };
    for anchor in anchors
        .iter()
        .filter(|a| a.subject_der == current.issuer_der)
    {
        let result = (|| {
            validate_issuer_profile(anchor, below_issuer)?;
            let key = PublicKey::from_certificate_der(&anchor.der)
                .map_err(|_| ChainError::Malformed("anchor public key".into()))?;
            verify_issued_by(&key, current)
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => failure = error,
        }
    }
    for (index, issuer) in presented.iter().enumerate() {
        if used[index] || issuer.subject_der != current.issuer_der {
            continue;
        }
        let result = (|| {
            validate_issuer_profile(issuer, below_issuer)?;
            let key = PublicKey::from_certificate_der(&issuer.der)
                .map_err(|_| ChainError::Malformed("issuer public key".into()))?;
            verify_issued_by(&key, current)?;
            used[index] = true;
            let result = walk_chain(issuer, presented, anchors, used, depth + 1, below_issuer);
            used[index] = false;
            result
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

#[cfg(test)]
mod chain_tests {
    use super::{ChainError, verify_certificate_chain};

    fn params(name: &str, ca: bool) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, name);
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(2099, 1, 1);
        if ca {
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        }
        p
    }

    const NOW: u64 = 1_800_000_000; // 2027-01-15

    #[test]
    fn self_signed_verifies_only_as_its_own_anchor() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params("self", false).self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        verify_certificate_chain(&[&der], &[&der], NOW).expect("own anchor");
        let other = params("other", true)
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        assert!(matches!(
            verify_certificate_chain(&[&der], &[other.der()], NOW),
            Err(ChainError::UnknownIssuer { .. })
        ));
        assert!(matches!(
            verify_certificate_chain(&[&der], &[], NOW),
            Err(ChainError::UnknownIssuer { .. })
        ));
    }

    #[test]
    fn issued_leaf_chains_to_the_root_directly_or_via_an_intermediate() {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let root = params("root", true).self_signed(&root_key).unwrap();
        let inter_key = rcgen::KeyPair::generate().unwrap();
        let inter = params("inter", true)
            .signed_by(&inter_key, &root, &root_key)
            .unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params("leaf", false)
            .signed_by(&leaf_key, &inter, &inter_key)
            .unwrap();
        let direct = params("direct", false)
            .signed_by(&leaf_key, &root, &root_key)
            .unwrap();

        verify_certificate_chain(&[direct.der()], &[root.der()], NOW).expect("root-issued leaf");
        verify_certificate_chain(&[leaf.der(), inter.der()], &[root.der()], NOW)
            .expect("via intermediate");
        // The intermediate itself is an acceptable anchor.
        verify_certificate_chain(&[leaf.der()], &[inter.der()], NOW).expect("intermediate anchor");
        // Without the intermediate the leaf's issuer is unknown.
        assert!(matches!(
            verify_certificate_chain(&[leaf.der()], &[root.der()], NOW),
            Err(ChainError::UnknownIssuer { .. })
        ));
        // A non-CA "intermediate" is refused as an issuer.
        let fake_key = rcgen::KeyPair::generate().unwrap();
        let fake_inter = params("inter", false)
            .signed_by(&fake_key, &root, &root_key)
            .unwrap();
        let leaf2 = params("leaf2", false)
            .signed_by(&leaf_key, &fake_inter, &fake_key)
            .unwrap();
        assert!(matches!(
            verify_certificate_chain(&[leaf2.der(), fake_inter.der()], &[root.der()], NOW),
            Err(ChainError::NotACa { .. })
        ));
        // A leaf whose issuer name matches the root but whose signature does not.
        let rogue_key = rcgen::KeyPair::generate().unwrap();
        let rogue_root = params("root", true).self_signed(&rogue_key).unwrap();
        let rogue_leaf = params("rogue", false)
            .signed_by(&leaf_key, &rogue_root, &rogue_key)
            .unwrap();
        assert!(matches!(
            verify_certificate_chain(&[rogue_leaf.der()], &[root.der()], NOW),
            Err(ChainError::BadSignature { .. })
        ));
    }

    #[test]
    fn validity_window_is_enforced() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params("self", false).self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        // Before notBefore (2020-01-01) and after notAfter (2099-01-01).
        assert!(matches!(
            verify_certificate_chain(&[&der], &[&der], 1_500_000_000),
            Err(ChainError::NotYetValid { .. })
        ));
        assert!(matches!(
            verify_certificate_chain(&[&der], &[&der], 4_200_000_000),
            Err(ChainError::Expired { .. })
        ));
        assert!(matches!(
            verify_certificate_chain(&[], &[&der], NOW),
            Err(ChainError::Malformed(_))
        ));
        assert!(matches!(
            verify_certificate_chain(&[&der[..der.len() / 2]], &[&der], NOW),
            Err(ChainError::Malformed(_))
        ));
    }

    #[test]
    fn alert_codes_follow_the_rfc() {
        assert_eq!(
            ChainError::UnknownIssuer {
                subject: "a".into(),
                issuer: "b".into()
            }
            .alert_code(),
            48
        );
        assert_eq!(
            ChainError::Expired {
                subject: "a".into()
            }
            .alert_code(),
            45
        );
        assert_eq!(
            ChainError::BadSignature {
                subject: "a".into()
            }
            .alert_code(),
            42
        );
        assert_eq!(
            ChainError::UnsupportedAlgorithm {
                subject: "a".into(),
                oid: "1".into()
            }
            .alert_code(),
            43
        );
    }

    #[test]
    fn client_auth_constraints_and_unknown_critical_extensions_are_enforced() {
        let key = rcgen::KeyPair::generate().unwrap();
        for kind in 0..4 {
            let mut p = params("constrained", false);
            match kind {
                0 => p.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment],
                1 => p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
                _ => {
                    let oid: &[u64] = if kind == 2 {
                        &[1, 2, 3, 4]
                    } else {
                        &[2, 5, 29, 30]
                    };
                    let mut ext = rcgen::CustomExtension::from_oid_content(oid, vec![0x30, 0]);
                    ext.set_criticality(kind == 2);
                    p.custom_extensions.push(ext);
                }
            }
            let cert = p.self_signed(&key).unwrap();
            assert!(
                verify_certificate_chain(&[cert.der()], &[cert.der()], NOW).is_err(),
                "accepted constraint {kind}"
            );
        }
        let mut p = params("client", false);
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.self_signed(&key).unwrap();
        verify_certificate_chain(&[cert.der()], &[cert.der()], NOW).unwrap();
    }

    #[test]
    fn path_length_and_ca_key_usage_are_enforced() {
        for wrong_usage in [false, true] {
            let mut root_params = params("root", true);
            if wrong_usage {
                root_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            } else {
                root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
            }
            let root_key = rcgen::KeyPair::generate().unwrap();
            let root = root_params.self_signed(&root_key).unwrap();
            let inter_key = rcgen::KeyPair::generate().unwrap();
            let inter = params("inter", true)
                .signed_by(&inter_key, &root, &root_key)
                .unwrap();
            let leaf = params("leaf", false)
                .signed_by(&rcgen::KeyPair::generate().unwrap(), &inter, &inter_key)
                .unwrap();
            assert!(
                verify_certificate_chain(&[leaf.der(), inter.der()], &[root.der()], NOW).is_err()
            );
        }
    }

    #[test]
    fn chain_builder_tries_alternate_same_subject_issuers() {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let root = params("root", true).self_signed(&root_key).unwrap();
        let wrong = params("inter", true)
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &root, &root_key)
            .unwrap();
        let inter_key = rcgen::KeyPair::generate().unwrap();
        let inter = params("inter", true)
            .signed_by(&inter_key, &root, &root_key)
            .unwrap();
        let leaf = params("leaf", false)
            .signed_by(&rcgen::KeyPair::generate().unwrap(), &inter, &inter_key)
            .unwrap();
        verify_certificate_chain(&[leaf.der(), wrong.der(), inter.der()], &[root.der()], NOW)
            .unwrap();
    }

    #[test]
    fn certificate_pss_parameters_are_not_guessed() {
        use super::certificate_pss_scheme;
        use x509_cert::der::{Any, Decode};
        assert!(certificate_pss_scheme(None, false).is_err());
        // Empty parameters mean SHA-1 defaults, not SHA-256.
        assert!(certificate_pss_scheme(Some(&Any::from_der(&[0x30, 0]).unwrap()), false).is_err());
        assert!(certificate_pss_scheme(Some(&Any::from_der(&[0x05, 0]).unwrap()), false).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_label_matches_rfc8448_sample() {
        // RFC 8448 §3 "Simple 1-RTT Handshake" — after deriving the
        // early_secret from an all-zero PSK, Derive-Secret(early_secret,
        // "derived", "") should give a well-known value. We reproduce
        // the first step to guard against signature changes in the
        // HKDF crate.
        let zero_ikm = [0u8; 32];
        let zero_salt = [0u8; 32];
        let early_secret = hkdf_extract(HashAlg::Sha256, &zero_salt, &zero_ikm);
        assert_eq!(early_secret.len(), 32);
        // Expand with "derived" over empty-transcript hash.
        let empty_hash = hash(HashAlg::Sha256, b"");
        let derived = hkdf_expand_label(HashAlg::Sha256, &early_secret, "derived", &empty_hash, 32);
        // Value from RFC 8448 §3:
        //   6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97
        //   16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
        let expected = [
            0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba,
            0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57,
            0x6c, 0x36, 0x11, 0xba,
        ];
        assert_eq!(derived, expected);
    }

    #[test]
    fn dtls13_chacha_record_mask_handles_last_counter() {
        let key: Vec<u8> = (0u8..32).collect();
        let mut sample = vec![0xff; 16];
        sample[4..].copy_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        assert!(dtls13_record_number_mask(AeadAlg::ChaCha20Poly1305, &key, &sample).is_ok());

        // RFC 8439 section 2.3.2's block-function vector begins 10 f1 at
        // counter 1 for this key and nonce.
        sample[..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            dtls13_record_number_mask(AeadAlg::ChaCha20Poly1305, &key, &sample).unwrap(),
            [0x10, 0xf1]
        );
    }

    #[test]
    fn dtls13_ccm_record_masks_use_the_aes_block_function() {
        let sample: Vec<u8> = (0u8..16).collect();
        let key128 = [0x42; 16];
        let aes128 = dtls13_record_number_mask(AeadAlg::Aes128Gcm, &key128, &sample).unwrap();
        assert_eq!(
            dtls13_record_number_mask(AeadAlg::Aes128Ccm, &key128, &sample).unwrap(),
            aes128
        );
        assert_eq!(
            dtls13_record_number_mask(AeadAlg::Aes128Ccm8, &key128, &sample).unwrap(),
            aes128
        );

        let key256 = [0x24; 32];
        let aes256 = dtls13_record_number_mask(AeadAlg::Aes256Gcm, &key256, &sample).unwrap();
        assert_eq!(
            dtls13_record_number_mask(AeadAlg::Aes256Ccm, &key256, &sample).unwrap(),
            aes256
        );
        assert_eq!(
            dtls13_record_number_mask(AeadAlg::Aes256Ccm8, &key256, &sample).unwrap(),
            aes256
        );
    }

    #[test]
    fn tls12_prf_known_answer_vectors() {
        // draft-ietf-tls-tls12-prf-01 sections 2 and 3, the published
        // P_SHA256 and P_SHA384 100-byte test vectors used for TLS 1.2.
        let sha256_secret = hex_to_bytes("9bbe436ba940f017b17652849a71db35");
        let sha256_seed = hex_to_bytes("a0ba9f936cda311827a6f796ffd5198c");
        let sha256_expected = hex_to_bytes(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a
             6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab
             4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701
             87347b66",
        );
        assert_eq!(
            tls12_prf(
                HashAlg::Sha256,
                &sha256_secret,
                b"test label",
                &sha256_seed,
                100,
            ),
            sha256_expected
        );

        let sha384_secret = hex_to_bytes("b80b733d6ceefcdc71566ea48e5567df");
        let sha384_seed = hex_to_bytes("cd665cf6a8447dd6ff8b27555edb7465");
        let sha384_expected = hex_to_bytes(
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd
             e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd
             8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425
             9b5bf8cd",
        );
        assert_eq!(
            tls12_prf(
                HashAlg::Sha384,
                &sha384_secret,
                b"test label",
                &sha384_seed,
                100,
            ),
            sha384_expected
        );
    }

    #[test]
    fn aes_128_gcm_round_trip() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad = b"associated";
        let plaintext = b"hello world";
        let k = AeadKey::new(AeadAlg::Aes128Gcm, &key).unwrap();
        let ct = k.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
        let pt = k.open(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        // Tampering the ciphertext should fail authentication.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(k.open(&nonce, aad, &bad).is_err());
    }

    #[test]
    fn chacha20_poly1305_round_trip() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad = b"associated";
        let plaintext = b"hello world";
        let k = AeadKey::new(AeadAlg::ChaCha20Poly1305, &key).unwrap();
        let ct = k.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
        let pt = k.open(&nonce, aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        // Tampering the ciphertext should fail authentication.
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(k.open(&nonce, aad, &bad).is_err());
        // Wrong AAD should also fail.
        assert!(k.open(&nonce, b"other", &ct).is_err());
    }

    #[test]
    fn compressed_public_bytes_are_sec1_compressed_or_none() {
        let mut rng = Rng::from_seed([9u8; 32]);
        // NIST curves: 0x02/0x03 || X, half the uncompressed length (minus the tag).
        for (group, coord) in [(EcdheGroup::P256, 32usize), (EcdheGroup::P384, 48)] {
            let k = EcdhePrivate::generate(group, &mut rng);
            let c = k.public_bytes_compressed().expect("NIST curves compress");
            assert_eq!(c.len(), 1 + coord);
            assert!(c[0] == 0x02 || c[0] == 0x03, "tag {:#04x}", c[0]);
            let u = k.public_bytes();
            assert_eq!(u[0], 0x04);
            // Same X coordinate in both encodings.
            assert_eq!(&c[1..], &u[1..1 + coord]);
        }
        // Montgomery u-coordinates have no compressed form.
        let x = EcdhePrivate::generate(EcdheGroup::X25519, &mut rng);
        assert!(x.public_bytes_compressed().is_none());
        let x = EcdhePrivate::generate(EcdheGroup::X448, &mut rng);
        assert!(x.public_bytes_compressed().is_none());
    }

    #[test]
    fn ecdhe_p521_agrees() {
        let mut ra = Rng::from_seed([21u8; 32]);
        let mut rb = Rng::from_seed([22u8; 32]);
        let a = EcdhePrivate::generate(EcdheGroup::P521, &mut ra);
        let b = EcdhePrivate::generate(EcdheGroup::P521, &mut rb);
        assert_eq!(a.group(), EcdheGroup::P521);
        let pa = a.public_bytes();
        let pb = b.public_bytes();
        assert_eq!(pa.len(), 133, "uncompressed P-521 point: 0x04 || 66 || 66");
        assert_eq!(pa[0], 0x04);
        assert_eq!(a.public_bytes_compressed().unwrap().len(), 67);
        let sa = a.agree(&pb).unwrap();
        let sb = b.agree(&pa).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 66);
    }

    #[test]
    fn ffdhe_groups_agree_and_validate_the_peer() {
        for (group, len) in [
            (EcdheGroup::Ffdhe2048, 256usize),
            (EcdheGroup::Ffdhe3072, 384),
            (EcdheGroup::Ffdhe4096, 512),
            (EcdheGroup::Ffdhe6144, 768),
            (EcdheGroup::Ffdhe8192, 1024),
        ] {
            assert!(group.is_ffdhe());
            assert_eq!(group.ffdhe_prime().unwrap().len(), len);
            let mut ra = Rng::from_seed([31u8; 32]);
            let mut rb = Rng::from_seed([32u8; 32]);
            let a = EcdhePrivate::generate(group, &mut ra);
            let b = EcdhePrivate::generate(group, &mut rb);
            assert_eq!(a.group(), group);
            let pa = a.public_bytes();
            let pb = b.public_bytes();
            // RFC 8446 4.2.8.1: the public value is padded to the prime's length.
            assert_eq!(pa.len(), len);
            assert!(a.public_bytes_compressed().is_none());
            let sa = EcdhePrivate::generate(group, &mut Rng::from_seed([31u8; 32]))
                .agree(&pb)
                .unwrap();
            let sb = b.agree(&pa).unwrap();
            assert_eq!(sa, sb);
            assert_eq!(
                sa.len(),
                len,
                "shared secret padded to the prime's length (RFC 8446 7.4.1)"
            );

            // RFC 8446 4.2.8.1: 1 < Y < p-1 at the prime's length; 0, 1, p-1 and a
            // short or long encoding are rejected.
            let p = group.ffdhe_prime().unwrap();
            let mut p_minus_1 = p.clone();
            *p_minus_1.last_mut().unwrap() -= 1; // p is odd, so no borrow
            let mut one = vec![0u8; len];
            one[len - 1] = 1;
            for bad in [
                vec![0u8; len],
                one,
                p_minus_1,
                vec![2u8; len - 1],
                vec![2u8; len + 1],
            ] {
                assert!(
                    EcdhePrivate::generate(group, &mut Rng::from_seed([33u8; 32]))
                        .agree(&bad)
                        .is_err(),
                    "must reject a {}-byte value starting {:02x}",
                    bad.len(),
                    bad[0]
                );
            }
        }
    }

    #[test]
    fn ecdhe_p384_agrees() {
        let mut rng_a = Rng::from_seed([5u8; 32]);
        let mut rng_b = Rng::from_seed([6u8; 32]);
        let sk_a = EcdhePrivate::generate(EcdheGroup::P384, &mut rng_a);
        let sk_b = EcdhePrivate::generate(EcdheGroup::P384, &mut rng_b);
        let pk_a = sk_a.public_bytes();
        let pk_b = sk_b.public_bytes();
        // Uncompressed SEC1 point for P-384: 0x04 || X(48) || Y(48).
        assert_eq!(pk_a.len(), 97);
        assert_eq!(pk_a[0], 0x04);
        let shared_a = sk_a.agree(&pk_b).unwrap();
        let shared_b = sk_b.agree(&pk_a).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 48);
    }

    #[test]
    fn ecdhe_x25519_agrees() {
        let mut rng_a = Rng::from_seed([1u8; 32]);
        let mut rng_b = Rng::from_seed([2u8; 32]);
        let sk_a = EcdhePrivate::generate(EcdheGroup::X25519, &mut rng_a);
        let sk_b = EcdhePrivate::generate(EcdheGroup::X25519, &mut rng_b);
        let pk_a = sk_a.public_bytes();
        let pk_b = sk_b.public_bytes();
        let shared_a = sk_a.agree(&pk_b).unwrap();
        let shared_b = sk_b.agree(&pk_a).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    #[test]
    fn x25519_rejects_an_all_zero_shared_secret() {
        let private = EcdhePrivate::generate(EcdheGroup::X25519, &mut Rng::from_seed([7; 32]));
        assert!(private.agree(&[0; 32]).is_err());
    }

    #[test]
    fn x448_matches_rfc7748_vectors() {
        fn bytes56(hex: &str) -> [u8; 56] {
            hex_to_bytes(hex).try_into().expect("56-byte vector")
        }

        let scalar = bytes56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779\
             c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = bytes56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031\
             ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let expected = bytes56(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaad\
             eb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        );
        assert_eq!(x448(&scalar, &u), expected);

        let alice_private = bytes56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5\
             74a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let alice_public = bytes56(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bb\
             c836647241d953d40c5b12da88120d53177f80e532c41fa0",
        );
        let bob_private = bytes56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120\
             bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        );
        let bob_public = bytes56(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972\
             fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        );
        let shared = bytes56(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56\
             fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        let mut base = [0u8; 56];
        base[0] = 5;
        assert_eq!(x448(&alice_private, &base), alice_public);
        assert_eq!(x448(&bob_private, &base), bob_public);
        assert_eq!(x448(&alice_private, &bob_public), shared);
        assert_eq!(x448(&bob_private, &alice_public), shared);

        // RFC 7748 requires non-canonical u-coordinates to be reduced mod p.
        let one = BigUint::from(1u8);
        let p = (&one << 448usize) - (&one << 224usize) - &one;
        let noncanonical = (&p + BigUint::from(5u8)).to_bytes_le();
        let mut noncanonical_base = [0u8; 56];
        noncanonical_base[..noncanonical.len()].copy_from_slice(&noncanonical);
        assert_eq!(
            x448(&alice_private, &noncanonical_base),
            x448(&alice_private, &base)
        );

        let private = EcdhePrivate::generate(EcdheGroup::X448, &mut Rng::from_seed([90u8; 32]));
        assert_eq!(private.agree(&[0u8; 56]), Err(CryptoError::BadPublicKey));
    }

    #[test]
    fn ecdhe_p256_agrees() {
        let mut rng_a = Rng::from_seed([3u8; 32]);
        let mut rng_b = Rng::from_seed([4u8; 32]);
        let sk_a = EcdhePrivate::generate(EcdheGroup::P256, &mut rng_a);
        let sk_b = EcdhePrivate::generate(EcdheGroup::P256, &mut rng_b);
        let pk_a = sk_a.public_bytes();
        let pk_b = sk_b.public_bytes();
        assert_eq!(pk_a.len(), 65);
        assert_eq!(pk_a[0], 0x04);
        let shared_a = sk_a.agree(&pk_b).unwrap();
        let shared_b = sk_b.agree(&pk_a).unwrap();
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }

    /// Every implemented group agrees from both sides through the same two
    /// calls a TLS 1.3 handshake makes: the client `generate`s, the server
    /// `respond`s against the client's share, and both `agree` on the other
    /// side's share. Checks the wire sizes of each group's shares too.
    #[test]
    fn every_group_agrees_initiator_to_responder() {
        for &group in EcdheGroup::ALL {
            let mut rng_c = Rng::from_seed([21u8; 32]);
            let mut rng_s = Rng::from_seed([22u8; 32]);
            let client = EcdhePrivate::generate(group, &mut rng_c);
            let client_share = client.public_bytes();
            assert_eq!(
                client_share.len(),
                group.initiator_share_len(),
                "{}",
                group.name()
            );
            let server = EcdhePrivate::respond(group, &client_share, &mut rng_s)
                .expect("valid client share");
            let server_share = server.public_bytes();
            assert_eq!(
                server_share.len(),
                group.responder_share_len(),
                "{}",
                group.name()
            );
            let ss_s = server.agree(&client_share).expect("server agrees");
            let ss_c = client.agree(&server_share).expect("client agrees");
            assert_eq!(ss_s, ss_c, "{}", group.name());
            let expect_len = match group {
                EcdheGroup::X25519 => 32,
                EcdheGroup::X448 => 56,
                EcdheGroup::P256 | EcdheGroup::Bp256 | EcdheGroup::Bp256Tls13 => 32,
                EcdheGroup::P384 | EcdheGroup::Bp384 | EcdheGroup::Bp384Tls13 => 48,
                EcdheGroup::P521 => 66,
                EcdheGroup::Ffdhe2048 => 256,
                EcdheGroup::Ffdhe3072 => 384,
                EcdheGroup::Ffdhe4096 => 512,
                EcdheGroup::Ffdhe6144 => 768,
                EcdheGroup::Ffdhe8192 => 1024,
                EcdheGroup::MlKem512 | EcdheGroup::MlKem768 | EcdheGroup::MlKem1024 => 32,
                EcdheGroup::X25519MlKem768 | EcdheGroup::Secp256r1MlKem768 => 64,
                EcdheGroup::X448MlKem1024 => 88,
                EcdheGroup::Secp384r1MlKem1024 => 80,
            };
            assert_eq!(ss_c.len(), expect_len, "{}", group.name());
            assert_eq!(EcdheGroup::from_wire(group.wire_value()), Some(group));
        }
    }

    /// X25519MLKEM768 puts the ML-KEM half first in both shares and in the
    /// secret; all other hybrids follow their names and put ECDH first.
    #[test]
    fn hybrid_shares_follow_their_defined_order() {
        let mut rng_c = Rng::from_seed([31u8; 32]);
        let mut rng_s = Rng::from_seed([32u8; 32]);
        // X25519MLKEM768: ek(1184) || x25519(32); server: ct(1088) || x25519(32).
        let client = EcdhePrivate::generate(EcdheGroup::X25519MlKem768, &mut rng_c);
        let share = client.public_bytes();
        assert_eq!(share.len(), 1216);
        let (ecdh, kem) = match &client {
            EcdhePrivate::Hybrid { ecdh, kem, .. } => (ecdh.public_bytes(), kem.public_bytes()),
            _ => panic!("hybrid"),
        };
        assert_eq!(&share[..1184], &kem[..]);
        assert_eq!(&share[1184..], &ecdh[..]);
        let server = EcdhePrivate::respond(EcdheGroup::X25519MlKem768, &share, &mut rng_s).unwrap();
        assert_eq!(server.public_bytes().len(), 1120);

        // X448MLKEM1024 follows the normal name order: x448(56) || ek(1568).
        let client = EcdhePrivate::generate(EcdheGroup::X448MlKem1024, &mut rng_c);
        let share = client.public_bytes();
        assert_eq!(share.len(), 1624);
        let (ecdh, kem) = match &client {
            EcdhePrivate::Hybrid { ecdh, kem, .. } => (ecdh.public_bytes(), kem.public_bytes()),
            _ => panic!("hybrid"),
        };
        assert_eq!(&share[..56], &ecdh[..]);
        assert_eq!(&share[56..], &kem[..]);
        let server = EcdhePrivate::respond(EcdheGroup::X448MlKem1024, &share, &mut rng_s).unwrap();
        assert_eq!(server.public_bytes().len(), 1624);

        // The hybrid fails if its classical component has a low-order point.
        let client = EcdhePrivate::generate(EcdheGroup::X448MlKem1024, &mut rng_c);
        let mut client_share = client.public_bytes();
        client_share[..56].fill(0);
        let server =
            EcdhePrivate::respond(EcdheGroup::X448MlKem1024, &client_share, &mut rng_s).unwrap();
        assert_eq!(server.agree(&client_share), Err(CryptoError::BadPublicKey));

        // SecP256r1MLKEM768: p256(65) || ek(1184); server p256(65) || ct(1088).
        let client = EcdhePrivate::generate(EcdheGroup::Secp256r1MlKem768, &mut rng_c);
        let share = client.public_bytes();
        assert_eq!(share.len(), 1249);
        assert_eq!(share[0], 0x04, "uncompressed P-256 point comes first");
        let server =
            EcdhePrivate::respond(EcdheGroup::Secp256r1MlKem768, &share, &mut rng_s).unwrap();
        let sshare = server.public_bytes();
        assert_eq!(sshare.len(), 1153);
        assert_eq!(sshare[0], 0x04);
        // A responder given a share of the wrong length refuses it.
        assert!(EcdhePrivate::respond(EcdheGroup::X25519MlKem768, &share, &mut rng_s).is_err());
        assert!(EcdhePrivate::respond(EcdheGroup::MlKem768, &[0u8; 1183], &mut rng_s).is_err());
    }

    /// Brainpool points are SEC1 on the RFC 7027 curves; the compressed and
    /// hybrid encodings exist for the negatives, and a point off the curve is
    /// rejected.
    #[test]
    fn brainpool_points_encode_and_validate() {
        let mut rng = Rng::from_seed([41u8; 32]);
        let a = EcdhePrivate::generate(EcdheGroup::Bp256Tls13, &mut rng);
        let pk = a.public_bytes();
        assert_eq!(pk.len(), 65);
        assert_eq!(a.public_bytes_compressed().unwrap().len(), 33);
        let hybrid = a.public_bytes_hybrid_sec1().unwrap();
        assert!(hybrid[0] == 0x06 || hybrid[0] == 0x07);
        assert_eq!(&hybrid[1..], &pk[1..]);
        let mut bad = pk.clone();
        bad[64] ^= 1;
        let b = EcdhePrivate::generate(EcdheGroup::Bp256, &mut rng);
        assert!(
            b.agree(&bad).is_err(),
            "off-curve brainpool point must be rejected"
        );
        let c = EcdhePrivate::generate(EcdheGroup::Bp384, &mut rng);
        assert_eq!(c.public_bytes().len(), 97);
    }

    #[test]
    fn ffdhe_agrees() {
        // ffdhe2048 modulus (RFC 7919), generator g = 2.
        let p_hex = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1\
                     D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF9\
                     7D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD6561\
                     2433F51F5F066ED0856365553DED1AF3B557135E7F57C935\
                     984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE735\
                     30ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FB\
                     B96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB19\
                     0B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61\
                     9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD73\
                     3BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA\
                     886B423861285C97FFFFFFFFFFFFFFFF";
        let p = crate::tls::crypto::hex_to_bytes(p_hex);
        let g = vec![0x02];
        let mut rng_a = Rng::from_seed([9u8; 32]);
        let mut rng_b = Rng::from_seed([10u8; 32]);
        let a = FfdhePrivate::generate(&p, &g, &mut rng_a);
        let b = FfdhePrivate::generate(&p, &g, &mut rng_b);
        let ya = a.public_bytes(&g);
        let yb = b.public_bytes(&g);
        assert_eq!(ya.len(), p.len());
        let sa = a.agree(&yb);
        let sb = b.agree(&ya);
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), p.len());
    }

    #[test]
    fn rng_sub_seed_is_stable_and_independent() {
        let parent = [7u8; 32];
        let a = Rng::sub_seed(parent, b"client_random");
        let b = Rng::sub_seed(parent, b"ecdh_private");
        let a2 = Rng::sub_seed(parent, b"client_random");
        assert_eq!(a, a2); // stable
        assert_ne!(a, b); // independent per label
    }

    // ---------- signature verification ----------
    //
    // Trait imports scoped to this sub-module so they don't leak
    // into the rest of `tests` and stay close to the sig code.
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::signature::SignatureEncoding as _;

    fn seeded_cryptorng() -> ChaCha20Rng {
        // Deterministic RNG for key-gen paths, so these tests are
        // reproducible (and the slow RSA-2048 generation only
        // happens once per `cargo test` invocation anyway).
        ChaCha20Rng::from_seed([0x42; 32])
    }

    #[test]
    fn certificate_signature_metadata_distinguishes_leaf_and_anchor() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("shims/testdata/client_ee_rsa_cert.der");
        let issued = std::fs::read(fixture).expect("read CA-issued RSA fixture");
        assert_eq!(
            certificate_signature_metadata(&issued).unwrap(),
            (SignatureScheme::EcdsaSecp256r1Sha256, false)
        );

        let self_signed =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::Rsa2048)
                .unwrap();
        assert_eq!(
            certificate_signature_metadata(&self_signed.cert_der).unwrap(),
            (SignatureScheme::RsaPkcs1Sha256, true)
        );
    }

    #[test]
    fn rsa_pkcs1_sha256_round_trip() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::RandomizedSigner;

        let mut rng = seeded_cryptorng();
        // 2048 is slow but this is a one-time cost.
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk_rsa = RsaPublicKey::from(&sk);
        let signing_key = SigningKey::<Sha256>::new(sk);

        let message = b"TLS 1.2 ServerKeyExchange signed blob";
        let sig = signing_key.sign_with_rng(&mut rng, message);

        let pk = PublicKey::from_rsa(pk_rsa);
        pk.verify(
            SignatureScheme::RsaPkcs1Sha256,
            message,
            sig.to_bytes().as_ref(),
        )
        .expect("signature must verify");

        // Tamper the signature.
        let mut bad = sig.to_bytes().to_vec();
        bad[5] ^= 0x01;
        assert_eq!(
            pk.verify(SignatureScheme::RsaPkcs1Sha256, message, &bad),
            Err(CryptoError::BadSignature)
        );

        // Tamper the message.
        assert_eq!(
            pk.verify(
                SignatureScheme::RsaPkcs1Sha256,
                b"different message",
                sig.to_bytes().as_ref(),
            ),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn rsa_pss_sha256_round_trip() {
        use rsa::RsaPrivateKey;
        use rsa::pss::SigningKey;
        use rsa::signature::RandomizedSigner;

        let mut rng = seeded_cryptorng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk_rsa = RsaPublicKey::from(&sk);
        let signing_key = SigningKey::<Sha256>::new(sk);

        let message = b"TLS 1.3 CertificateVerify content";
        let sig = signing_key.sign_with_rng(&mut rng, message);

        let pk = PublicKey::from_rsa(pk_rsa);
        pk.verify(
            SignatureScheme::RsaPssRsaeSha256,
            message,
            sig.to_bytes().as_ref(),
        )
        .expect("PSS signature must verify");

        // Under the wrong scheme (PKCS#1 instead of PSS) it must fail.
        assert!(
            pk.verify(
                SignatureScheme::RsaPkcs1Sha256,
                message,
                sig.to_bytes().as_ref()
            )
            .is_err()
        );
    }

    #[test]
    fn rsa_pss_sha512_round_trip() {
        use rsa::RsaPrivateKey;
        use rsa::pss::SigningKey;
        use rsa::signature::RandomizedSigner;

        let mut rng = seeded_cryptorng();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pk_rsa = RsaPublicKey::from(&sk);
        let signing_key = SigningKey::<Sha512>::new(sk);

        let message = b"TLS 1.3 CertificateVerify content";
        let sig = signing_key.sign_with_rng(&mut rng, message);

        let pk = PublicKey::from_rsa(pk_rsa);
        pk.verify(
            SignatureScheme::RsaPssRsaeSha512,
            message,
            sig.to_bytes().as_ref(),
        )
        .expect("PSS-SHA512 signature must verify");

        // A SHA-256-PSS verifier must reject a SHA-512-PSS signature.
        assert!(
            pk.verify(
                SignatureScheme::RsaPssRsaeSha256,
                message,
                sig.to_bytes().as_ref()
            )
            .is_err()
        );
    }

    #[test]
    fn ecdsa_p256_sha256_round_trip() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

        let mut rng = seeded_cryptorng();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key: VerifyingKey = *signing_key.verifying_key();

        let message = b"ECDSA over P-256 test vector";
        let sig: Signature = signing_key.sign(message);
        // TLS wire format: DER-encoded.
        let sig_der = sig.to_der().as_bytes().to_vec();

        let pk = PublicKey::from_ecdsa_p256(verifying_key);
        pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, message, &sig_der)
            .expect("ECDSA signature must verify");

        // Tamper the DER signature — the outermost SEQUENCE byte
        // stays valid, but the inner integers break.
        let mut bad = sig_der.clone();
        if bad.len() > 4 {
            bad[4] ^= 0x01;
        }
        assert!(
            pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, message, &bad)
                .is_err()
        );

        // Verifying an ECDSA signature under a non-ECDSA scheme fails.
        assert_eq!(
            pk.verify(SignatureScheme::RsaPkcs1Sha256, message, &sig_der),
            Err(CryptoError::UnsupportedSuite)
        );
    }

    #[test]
    fn ecdsa_p521_sha512_round_trip() {
        use p521::ecdsa::signature::Signer;
        use p521::ecdsa::{Signature, SigningKey, VerifyingKey};

        let mut rng = seeded_cryptorng();
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"ECDSA over P-521 test vector";
        let sig: Signature = signing_key.sign(message);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let pk = PublicKey::from_ecdsa_p521(verifying_key);
        pk.verify(SignatureScheme::EcdsaSecp521r1Sha512, message, &sig_der)
            .expect("P-521 signature must verify");

        // Wrong message must fail.
        assert!(
            pk.verify(
                SignatureScheme::EcdsaSecp521r1Sha512,
                b"other message",
                &sig_der
            )
            .is_err()
        );
    }

    #[test]
    fn ed25519_round_trip() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut seed = [0u8; 32];
        seed[0] = 7;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let message = b"Ed25519 CertificateVerify content";
        let sig = signing_key.sign(message);
        // TLS wire format for Ed25519 is the raw 64-byte signature.
        let sig_bytes = sig.to_bytes().to_vec();

        let pk = PublicKey::from_ed25519(verifying_key);
        pk.verify(SignatureScheme::Ed25519, message, &sig_bytes)
            .expect("Ed25519 signature must verify");

        // Wrong message must fail.
        assert!(
            pk.verify(SignatureScheme::Ed25519, b"other message", &sig_bytes)
                .is_err()
        );
    }

    #[test]
    fn public_key_from_rcgen_cert_roundtrip() {
        // End-to-end SPKI parse: ask rcgen for a self-signed ECDSA
        // P-256 cert, parse its DER via PublicKey::from_certificate_der,
        // verify a signature produced by the matching private key.
        //
        // Not using RSA here because rcgen doesn't generate RSA keys
        // internally (rsa key-gen is slow and not part of rcgen's
        // scope without a specific backend feature). The RSA SPKI
        // parsing path is exercised implicitly when we land the
        // rustls oracle with its generated RSA cert.

        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should succeed");
        let cert_der = cert.cert.der().to_vec();
        let pk = PublicKey::from_certificate_der(&cert_der).expect("SPKI parse should succeed");

        // Extract the matching signing key from rcgen's serialized
        // PKCS#8 DER so we can produce a signature to verify.
        // Note rcgen 0.13 names the field `key_pair`.
        let key_der = cert.key_pair.serialize_der();
        let signing_key = SigningKey::from_pkcs8_der(&key_der).expect("PKCS#8 decode of P-256 key");
        let message = b"round-trip via rcgen";
        let sig: Signature = signing_key.sign(message);
        let sig_der = sig.to_der().as_bytes().to_vec();

        pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, message, &sig_der)
            .expect("signature must verify against SPKI-parsed key");
    }

    #[test]
    fn public_key_from_spki_der_roundtrip() {
        // RFC 7250 RawPublicKey: the Certificate entry is a bare SubjectPublicKeyInfo
        // (no X.509 wrapper). Take an rcgen P-256 cert, extract just its SPKI DER, parse
        // it via `from_spki_der`, and verify a signature -- the same working key that
        // `from_certificate_der` yields from the full cert.
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use x509_cert::der::Encode;

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should succeed");
        let cert_der = cert.cert.der().to_vec();

        // Extract the raw SubjectPublicKeyInfo DER from the X.509 cert.
        let parsed = Certificate::from_der(&cert_der).expect("parse cert");
        let spki_der = parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("encode SPKI");

        // The raw SPKI DER must parse to the same working key.
        let pk = PublicKey::from_spki_der(&spki_der).expect("SPKI-der parse should succeed");

        let key_der = cert.key_pair.serialize_der();
        let signing_key = SigningKey::from_pkcs8_der(&key_der).expect("PKCS#8 decode");
        let message = b"raw public key round-trip";
        let sig: Signature = signing_key.sign(message);
        let sig_der = sig.to_der().as_bytes().to_vec();

        pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, message, &sig_der)
            .expect("signature must verify against SPKI-der-parsed key");

        // A truncated SPKI must be rejected, not silently accepted.
        assert!(PublicKey::from_spki_der(&spki_der[..spki_der.len() / 2]).is_err());
    }

    #[test]
    fn from_certificate_entry_dispatches_on_cert_type() {
        // Same rcgen P-256 cert: the X.509 DER decodes under cert_type X509 (0), and its
        // bare SPKI DER decodes under cert_type RawPublicKey (2). Each must be rejected
        // under the WRONG cert_type (X.509 is not a valid SPKI and vice versa).
        use crate::tls::codec::{CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509};
        use x509_cert::der::Encode;

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should succeed");
        let cert_der = cert.cert.der().to_vec();
        let parsed = Certificate::from_der(&cert_der).expect("parse cert");
        let spki_der = parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("encode SPKI");

        assert!(PublicKey::from_certificate_entry(&cert_der, CERT_TYPE_X509).is_ok());
        assert!(PublicKey::from_certificate_entry(&spki_der, CERT_TYPE_RAW_PUBLIC_KEY).is_ok());
        // Wrong encoding for the declared type must fail.
        assert!(PublicKey::from_certificate_entry(&cert_der, CERT_TYPE_RAW_PUBLIC_KEY).is_err());
        assert!(PublicKey::from_certificate_entry(&spki_der, CERT_TYPE_X509).is_err());
    }

    // ---------- PrivateKey sign-then-verify ----------

    #[test]
    fn private_key_rsa_pkcs1_sign_then_verify() {
        // Generate an RSA CertBundle, extract PrivateKey, sign,
        // verify against the matching PublicKey.
        let bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::Rsa2048)
                .unwrap();
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        assert!(sk.is_rsa());
        let pk = sk.public_key();
        let message = b"TLS 1.2 ServerKeyExchange signed blob";
        let sig = sk.sign(SignatureScheme::RsaPkcs1Sha256, message).unwrap();
        pk.verify(SignatureScheme::RsaPkcs1Sha256, message, &sig)
            .expect("RSA PKCS#1 sign-then-verify");
        // Wrong message must fail.
        assert!(
            pk.verify(SignatureScheme::RsaPkcs1Sha256, b"wrong", &sig)
                .is_err()
        );
    }

    #[test]
    fn private_key_rsa_pss_sign_then_verify() {
        let bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::Rsa2048)
                .unwrap();
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        let pk = sk.public_key();
        let message = b"TLS 1.3 CertificateVerify content";
        let sig = sk.sign(SignatureScheme::RsaPssRsaeSha256, message).unwrap();
        pk.verify(SignatureScheme::RsaPssRsaeSha256, message, &sig)
            .expect("RSA-PSS sign-then-verify");
        // Cross-scheme: PSS sig under PKCS#1 must fail.
        assert!(
            pk.verify(SignatureScheme::RsaPkcs1Sha256, message, &sig)
                .is_err()
        );
    }

    #[test]
    fn private_key_ecdsa_sign_then_verify() {
        let bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::EcdsaP256)
                .unwrap();
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        assert!(sk.is_ecdsa());
        let pk = sk.public_key();
        let message = b"ECDSA P-256 round trip";
        let sig = sk
            .sign(SignatureScheme::EcdsaSecp256r1Sha256, message)
            .unwrap();
        pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, message, &sig)
            .expect("ECDSA sign-then-verify");
        // Wrong scheme for this key type.
        assert_eq!(
            sk.sign(SignatureScheme::RsaPkcs1Sha256, message),
            Err(CryptoError::UnsupportedSuite)
        );
    }

    #[test]
    fn private_key_from_pkcs8_detects_key_type() {
        let rsa_bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::Rsa2048)
                .unwrap();
        let ecdsa_bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::EcdsaP256)
                .unwrap();
        let rsa_sk = PrivateKey::from_pkcs8_der(&rsa_bundle.key_pkcs8_der).unwrap();
        let ecdsa_sk = PrivateKey::from_pkcs8_der(&ecdsa_bundle.key_pkcs8_der).unwrap();
        assert!(rsa_sk.is_rsa());
        assert!(!rsa_sk.is_ecdsa());
        assert!(ecdsa_sk.is_ecdsa());
        assert!(!ecdsa_sk.is_rsa());
        // Garbage DER fails.
        assert!(PrivateKey::from_pkcs8_der(b"not a key").is_err());
    }

    #[test]
    fn ed25519_pkcs8_parse_sign_verify() {
        let bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::Ed25519)
                .unwrap();
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        assert!(sk.is_ed25519());
        // RFC 8446 4.2.3: an Ed25519 key advertises exactly ed25519 (0x0807).
        assert_eq!(sk.tls13_signing_schemes(), &[SignatureScheme::Ed25519]);
        assert!(sk.supports_scheme(SignatureScheme::Ed25519));
        assert!(!sk.supports_scheme(SignatureScheme::RsaPssRsaeSha256));
        let pk = sk.public_key();
        let message = b"TLS 1.3 CertificateVerify transcript";
        let sig = sk.sign(SignatureScheme::Ed25519, message).unwrap();
        // Ed25519's TLS wire signature is the raw 64-byte value.
        assert_eq!(sig.len(), 64);
        pk.verify(SignatureScheme::Ed25519, message, &sig)
            .expect("Ed25519 sign-then-verify");
        assert!(pk.verify(SignatureScheme::Ed25519, b"wrong", &sig).is_err());
    }

    #[test]
    fn ecdsa_p384_pkcs8_parse_sign_verify() {
        let bundle =
            crate::server::certs::CertBundle::generate(crate::server::certs::KeyType::EcdsaP384)
                .unwrap();
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();
        // is_ecdsa() is P-256-specific; the scheme list identifies the curve.
        assert_eq!(
            sk.tls13_signing_schemes(),
            &[SignatureScheme::EcdsaSecp384r1Sha384]
        );
        assert!(sk.supports_scheme(SignatureScheme::EcdsaSecp384r1Sha384));
        let pk = sk.public_key();
        let message = b"TLS 1.3 CertificateVerify transcript (P-384)";
        let sig = sk
            .sign(SignatureScheme::EcdsaSecp384r1Sha384, message)
            .unwrap();
        pk.verify(SignatureScheme::EcdsaSecp384r1Sha384, message, &sig)
            .expect("P-384 ECDSA sign-then-verify");
        assert!(
            pk.verify(SignatureScheme::EcdsaSecp384r1Sha384, b"wrong", &sig)
                .is_err()
        );
    }
}

#[cfg(test)]
mod tls12_key_kind_tests {
    use super::*;
    use crate::server::certs::{CertBundle, KeyType};

    fn key_of(kt: KeyType) -> (PrivateKey, PublicKey) {
        let bundle = CertBundle::generate(kt).expect("bundle");
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).expect("pkcs8");
        let pk = PublicKey::from_certificate_der(&bundle.cert_der).expect("cert");
        (sk, pk)
    }

    #[test]
    fn p384_and_ed25519_keys_parse_and_sign_with_their_own_scheme() {
        for (kt, kind, scheme) in [
            (
                KeyType::EcdsaP384,
                KeyKind::EcdsaP384,
                SignatureScheme::EcdsaSecp384r1Sha384,
            ),
            (KeyType::Ed25519, KeyKind::Ed25519, SignatureScheme::Ed25519),
            (
                KeyType::EcdsaP256,
                KeyKind::EcdsaP256,
                SignatureScheme::EcdsaSecp256r1Sha256,
            ),
        ] {
            let (sk, pk) = key_of(kt);
            assert_eq!(sk.kind(), kind);
            assert_eq!(sk.signature_schemes(), vec![scheme]);
            assert_eq!(sk.default_signature_scheme(), scheme);
            let sig = sk.sign(scheme, b"server params").expect("sign");
            pk.verify(scheme, b"server params", &sig).expect("verify");
            assert!(pk.verify(scheme, b"other params", &sig).is_err());
            // The wrong family is refused outright.
            assert!(sk.sign(SignatureScheme::RsaPssRsaeSha256, b"x").is_err());
        }
        let (rsa, _) = key_of(KeyType::Rsa2048);
        assert_eq!(rsa.kind(), KeyKind::Rsa);
        assert_eq!(rsa.signature_schemes().len(), 6);
        let sig = rsa.sign(SignatureScheme::RsaPkcs1Sha512, b"m").unwrap();
        rsa.public_key()
            .verify(SignatureScheme::RsaPkcs1Sha512, b"m", &sig)
            .unwrap();
    }

    #[test]
    fn tls12_ecdsa_codepoints_name_the_hash_not_the_curve() {
        // A P-256 key signing under SHA-384 (what Botan's client does for its
        // TLS 1.2 CertificateVerify when the server lists ecdsa_secp384r1_sha384).
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
        let pk = PublicKey::from_certificate_der(&bundle.cert_der).unwrap();
        let sk = {
            use p256::pkcs8::DecodePrivateKey;
            p256::ecdsa::SigningKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap()
        };
        let msg = b"handshake messages";
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&Sha384::digest(msg)).unwrap();
        let der = sig.to_der().as_bytes().to_vec();
        pk.verify(SignatureScheme::EcdsaSecp384r1Sha384, msg, &der)
            .expect("SHA-384 prehash on P-256");
        assert!(
            pk.verify_tls13(SignatureScheme::EcdsaSecp384r1Sha384, msg, &der)
                .is_err(),
            "TLS 1.3 must bind ECDSA schemes to the curve"
        );
        assert!(
            pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, msg, &der)
                .is_err()
        );
        assert!(
            pk.verify(SignatureScheme::EcdsaSecp521r1Sha512, msg, &der)
                .is_err()
        );
    }
}

// T3: the CertificateVerify signing controls (legacy pairs, PSS salt / MGF1,
// the TLS 1.1 form, encoded-message edits) and the new key kinds.
#[cfg(test)]
mod t3_signing_tests {
    use super::*;
    use std::path::PathBuf;

    fn testdata(name: &str) -> Vec<u8> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("shims")
            .join("testdata");
        std::fs::read(root.join(name)).unwrap_or_else(|e| panic!("{}: {}", name, e))
    }

    fn rsa_key() -> PrivateKey {
        PrivateKey::from_pkcs8_der(&testdata("client_ee_rsa_key.pkcs8.der")).expect("rsa key")
    }

    #[test]
    fn legacy_pkcs1_pairs_sign_and_verify() {
        let sk = rsa_key();
        let pk = sk.public_key();
        let msg = b"legacy hash pairs";
        for scheme in [
            SignatureScheme::RsaPkcs1Md5,
            SignatureScheme::RsaPkcs1Sha1,
            SignatureScheme::RsaPkcs1Sha224,
        ] {
            let sig = sk.sign(scheme, msg).expect("sign");
            assert_eq!(sig.len(), 256);
            pk.verify(scheme, msg, &sig)
                .expect("verifies under its own scheme");
            // Another hash's DigestInfo does not match.
            assert!(
                pk.verify(SignatureScheme::RsaPkcs1Sha256, msg, &sig)
                    .is_err()
            );
            let mut bad = sig.clone();
            bad[100] ^= 1;
            assert!(pk.verify(scheme, msg, &bad).is_err());
        }
    }

    #[test]
    fn hand_built_encodings_match_the_rsa_crate() {
        // sign() builds EMSA-PKCS1-v1_5 / EMSA-PSS by hand; verify() for
        // SHA-2 goes through the rsa crate, so a roundtrip cross-checks them.
        let sk = rsa_key();
        let pk = sk.public_key();
        let msg = b"cross-check";
        for scheme in [
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
        ] {
            let sig = sk.sign(scheme, msg).expect("sign");
            pk.verify(scheme, msg, &sig)
                .unwrap_or_else(|e| panic!("{:?}: {:?}", scheme, e));
        }
    }

    #[test]
    fn pss_salt_and_mgf1_options_break_the_standard_verifier() {
        let sk = rsa_key();
        let pk = sk.public_key();
        let msg = b"salt";
        let s = SignatureScheme::RsaPssRsaeSha256;
        let ok = sk
            .sign_with_options(s, msg, &SigningOptions::default())
            .unwrap();
        pk.verify(s, msg, &ok).expect("default salt verifies");
        let short_salt = sk
            .sign_with_options(
                s,
                msg,
                &SigningOptions {
                    salt_len: Some(20),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            pk.verify(s, msg, &short_salt).is_err(),
            "a 20-byte salt is not the RFC 8446 form"
        );
        let other_mgf = sk
            .sign_with_options(
                s,
                msg,
                &SigningOptions {
                    mgf1_hash: Some(SigHash::Sha384),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            pk.verify(s, msg, &other_mgf).is_err(),
            "MGF1 with SHA-384 does not verify"
        );
        // The em_len - h_len - 2 bound: a salt that cannot fit is refused.
        assert!(
            sk.sign_with_options(
                s,
                msg,
                &SigningOptions {
                    salt_len: Some(300),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn tls11_form_is_md5_sha1_without_digestinfo() {
        let sk = rsa_key();
        let pk = sk.public_key();
        let msg = b"tls 1.1 transcript";
        let sig = sk
            .sign_with_options(
                SignatureScheme::RsaPkcs1Sha256,
                msg,
                &SigningOptions {
                    tls11: true,
                    ..Default::default()
                },
            )
            .unwrap();
        // Recover the encoded message and check its shape.
        let PublicKeyInner::Rsa(key) = &pk.inner else {
            panic!("rsa")
        };
        let em = rsa_public_raw(key, &sig);
        assert_eq!(&em[..2], &[0x00, 0x01]);
        let sep = em.iter().skip(2).position(|b| *b == 0x00).unwrap() + 2;
        let t = &em[sep + 1..];
        let mut expected = SigHash::Md5.digest(msg);
        expected.extend(SigHash::Sha1.digest(msg));
        assert_eq!(t, expected.as_slice(), "MD5 || SHA-1, no DigestInfo");
        assert!(
            pk.verify(SignatureScheme::RsaPkcs1Sha256, msg, &sig)
                .is_err()
        );
    }

    #[test]
    fn em_edits_corrupt_the_signature_deterministically() {
        let sk = rsa_key();
        let pk = sk.public_key();
        let msg = b"edit";
        let s = SignatureScheme::RsaPkcs1Sha256;
        let edit = SigningOptions {
            em_edits: vec![EmEdit {
                index: -1,
                value: 0x01,
                xor: true,
            }],
            ..Default::default()
        };
        let sig = sk.sign_with_options(s, msg, &edit).unwrap();
        assert!(pk.verify(s, msg, &sig).is_err());
        // Index -1 is the last byte of the encoded message, and the operation
        // is reproducible.
        assert_eq!(sig, sk.sign_with_options(s, msg, &edit).unwrap());
        // A set on byte 1 (the block type) is refused by the verifier too.
        let set = SigningOptions {
            em_edits: vec![EmEdit {
                index: 1,
                value: 0x02,
                xor: false,
            }],
            ..Default::default()
        };
        assert!(
            pk.verify(s, msg, &sk.sign_with_options(s, msg, &set).unwrap())
                .is_err()
        );
        // Out of range is an error, not a panic.
        let oob = SigningOptions {
            em_edits: vec![EmEdit {
                index: 1000,
                value: 1,
                xor: true,
            }],
            ..Default::default()
        };
        assert!(sk.sign_with_options(s, msg, &oob).is_err());
    }

    #[test]
    fn rsa_pss_key_and_certificate() {
        let sk = PrivateKey::from_pkcs8_der(&testdata("client_ee_rsa_pss_key.pkcs8.der"))
            .expect("pss key");
        assert_eq!(sk.kind(), KeyKind::RsaPss);
        assert!(sk.is_rsa_pss() && !sk.is_rsa());
        assert_eq!(
            sk.default_signature_scheme(),
            SignatureScheme::RsaPssPssSha256
        );
        assert_eq!(
            sk.tls13_signing_schemes()[0],
            SignatureScheme::RsaPssPssSha256
        );
        let pk = PublicKey::from_certificate_der(&testdata("client_ee_rsa_pss_cert.der"))
            .expect("pss cert");
        assert!(pk.is_rsa_pss());
        let msg = b"pss key";
        for s in [
            SignatureScheme::RsaPssPssSha256,
            SignatureScheme::RsaPssPssSha384,
            SignatureScheme::RsaPssPssSha512,
        ] {
            let sig = sk.sign(s, msg).unwrap();
            pk.verify(s, msg, &sig)
                .expect("rsa_pss_pss verifies under the PSS SPKI");
        }
        // The rsae label is a key-type mismatch to the verifier (the signer
        // still produces it: that is what the negative probes send).
        let sig = sk.sign(SignatureScheme::RsaPssRsaeSha256, msg).unwrap();
        assert!(
            pk.verify(SignatureScheme::RsaPssRsaeSha256, msg, &sig)
                .is_err()
        );
        // And an rsaEncryption key does not verify rsa_pss_pss.
        let plain = rsa_key().public_key();
        let sig = rsa_key()
            .sign(SignatureScheme::RsaPssPssSha256, msg)
            .unwrap();
        assert!(
            plain
                .verify(SignatureScheme::RsaPssPssSha256, msg, &sig)
                .is_err()
        );
        // The server-side bundle loads the same way.
        let (cert, key) = (
            testdata("server_rsa_pss_cert.pem"),
            testdata("server_rsa_pss_key.pem"),
        );
        assert!(!cert.is_empty() && !key.is_empty());
    }

    #[test]
    fn p521_key_signs_and_verifies_any_hash() {
        let sk = PrivateKey::from_pkcs8_der(&testdata("client_ee_ecdsa_p521_key.pkcs8.der"))
            .expect("p521 key");
        assert_eq!(sk.kind(), KeyKind::EcdsaP521);
        let pk = PublicKey::from_certificate_der(&testdata("client_ee_ecdsa_p521_cert.der"))
            .expect("p521 cert");
        let msg = b"p521";
        let sig = sk.sign(SignatureScheme::EcdsaSecp521r1Sha512, msg).unwrap();
        pk.verify(SignatureScheme::EcdsaSecp521r1Sha512, msg, &sig)
            .expect("own scheme");
        assert!(
            pk.verify(SignatureScheme::EcdsaSecp384r1Sha384, msg, &sig)
                .is_err()
        );
        // Short digests are left-padded for the field, and round-trip.
        for s in [
            SignatureScheme::EcdsaMd5,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::EcdsaSha224,
        ] {
            let sig = sk.sign(s, msg).unwrap();
            pk.verify(s, msg, &sig)
                .unwrap_or_else(|e| panic!("{:?}: {:?}", s, e));
        }
    }

    #[test]
    fn ecdsa_p256_signs_other_hashes_tls12_style() {
        let sk =
            PrivateKey::from_pkcs8_der(&testdata("client_ee_key.pkcs8.der")).expect("p256 key");
        let pk = sk.public_key();
        let msg = b"p256 cross hash";
        for s in [
            SignatureScheme::EcdsaSha1,
            SignatureScheme::EcdsaSha224,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
        ] {
            let sig = sk.sign(s, msg).unwrap();
            pk.verify(s, msg, &sig)
                .unwrap_or_else(|e| panic!("{:?}: {:?}", s, e));
            assert!(
                pk.verify(SignatureScheme::EcdsaSecp256r1Sha256, msg, &sig)
                    .is_err()
            );
        }
        // TLS 1.1 form: SHA-1.
        let sig = sk
            .sign_with_options(
                SignatureScheme::EcdsaSecp256r1Sha256,
                msg,
                &SigningOptions {
                    tls11: true,
                    ..Default::default()
                },
            )
            .unwrap();
        pk.verify(SignatureScheme::EcdsaSha1, msg, &sig)
            .expect("tls11 ECDSA is over SHA-1");
        // An Ed25519 key refuses everything but ed25519.
        let ed = PrivateKey::from_pkcs8_der(&testdata("client_ee_ed25519_key.pkcs8.der"))
            .expect("ed25519 key");
        assert_eq!(ed.kind(), KeyKind::Ed25519);
        assert!(ed.sign(SignatureScheme::EcdsaSecp256r1Sha256, msg).is_err());
        let sig = ed.sign(SignatureScheme::Ed25519, msg).unwrap();
        ed.public_key()
            .verify(SignatureScheme::Ed25519, msg, &sig)
            .unwrap();
    }

    #[test]
    fn scheme_table_roundtrips_and_names_hashes() {
        for w in [
            0x0101u16, 0x0201, 0x0301, 0x0103, 0x0203, 0x0303, 0x0809, 0x080a, 0x080b, 0x0401,
            0x0804, 0x0403, 0x0807,
        ] {
            let s = SignatureScheme::from_wire_value(w).unwrap();
            assert_eq!(s.wire_value(), w);
        }
        assert_eq!(SignatureScheme::RsaPkcs1Md5.hash(), Some(SigHash::Md5));
        assert_eq!(SignatureScheme::EcdsaSha224.hash(), Some(SigHash::Sha224));
        assert_eq!(SignatureScheme::Ed25519.hash(), None);
        assert!(
            SignatureScheme::RsaPssPssSha384.is_rsa_pss_pss()
                && SignatureScheme::RsaPssPssSha384.is_rsa()
        );
        assert_eq!(SigHash::from_name("sha384"), Some(SigHash::Sha384));
        assert_eq!(SigHash::Sha224.digest(b"").len(), 28);
        // The DigestInfo prefixes end in the digest length.
        for h in [
            SigHash::Md5,
            SigHash::Sha1,
            SigHash::Sha224,
            SigHash::Sha256,
            SigHash::Sha384,
            SigHash::Sha512,
        ] {
            assert_eq!(
                *h.digest_info_prefix().last().unwrap() as usize,
                h.output_len()
            );
        }
    }
}
