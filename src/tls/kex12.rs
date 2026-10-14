//! TLS 1.2 / DTLS 1.2 key exchange shared by every 1.2 driver: static RSA
//! (RFC 5246 7.4.7.1) and ephemeral finite-field DHE (RFC 5246 7.4.3 /
//! 7.4.7.2). The TLS 1.2 client, the TLS 1.2 server and both DTLS drivers
//! call these; none of them carries its own copy of the arithmetic.
//!
//! Static RSA: the client encrypts `client_version || 46 random bytes` under
//! the server's RSA public key; the server decrypts and, per RFC 5246
//! 7.4.7.1, MUST NOT let a bad padding, a wrong length or a wrong version
//! show -- it substitutes a random premaster and lets the Finished check fail
//! instead (the Bleichenbacher / ROBOT countermeasure the corpus probes).
//!
//! DHE: the server sends explicit `ServerDHParams { p, g, Ys }` signed with
//! its certificate key; the client answers with `Yc`. Both sides check the
//! peer's public value is in `(1, p-1)` and strip the leading zero bytes of
//! the shared secret (RFC 5246 8.1.2).

use crate::tls::crypto::{
    EcdheGroup, FfdhePrivate, PrivateKey, PublicKey, Rng, hex_to_bytes, rsa_pkcs1v15_decrypt,
    rsa_pkcs1v15_encrypt,
};
use crate::tls::driver::TlsError;

/// A finite-field group for `ServerDHParams`: big-endian modulus and
/// generator bytes as they appear on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhGroup {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
}

impl DhGroup {
    /// RFC 7919 ffdhe2048, the group plzn's servers use by default (2048 bits
    /// is exactly Botan's `minimum_dh_group_size` and OpenSSL's security
    /// level 1 floor, so every client accepts it).
    pub fn ffdhe2048() -> Self {
        DhGroup {
            p: EcdheGroup::Ffdhe2048
                .ffdhe_prime()
                .expect("ffdhe2048 prime is built in"),
            g: vec![2],
        }
    }

    /// RFC 7919 ffdhe3072, selectable with the `ffdhe3072` peer capability.
    pub fn ffdhe3072() -> Self {
        DhGroup {
            p: EcdheGroup::Ffdhe3072
                .ffdhe_prime()
                .expect("ffdhe3072 prime is built in"),
            g: vec![2],
        }
    }

    pub fn ffdhe4096() -> Self {
        DhGroup {
            p: EcdheGroup::Ffdhe4096
                .ffdhe_prime()
                .expect("ffdhe4096 prime is built in"),
            g: vec![2],
        }
    }

    pub fn ffdhe6144() -> Self {
        DhGroup {
            p: EcdheGroup::Ffdhe6144
                .ffdhe_prime()
                .expect("ffdhe6144 prime is built in"),
            g: vec![2],
        }
    }

    /// RFC 7919 ffdhe8192, used as the large valid-parameter boundary case.
    pub fn ffdhe8192() -> Self {
        DhGroup {
            p: hex_to_bytes(FFDHE8192_P_HEX),
            g: vec![2],
        }
    }

    /// The RFC 7919 group named by a TLS NamedGroup wire value, if plzn has it.
    pub fn by_named_group(wire: u16) -> Option<Self> {
        match wire {
            0x0100 => Some(Self::ffdhe2048()),
            0x0101 => Some(Self::ffdhe3072()),
            0x0102 => Some(Self::ffdhe4096()),
            0x0103 => Some(Self::ffdhe6144()),
            0x0104 => Some(Self::ffdhe8192()),
            _ => None,
        }
    }

    /// RFC 2409 6.2 "Second Oakley Group": a 1024-bit safe prime. Below what
    /// current clients accept (Botan: insufficient_security, "DH group
    /// validation failed"; OpenSSL: "dh key too small"), which is the point of
    /// `send ServerKeyExchange { dh_p_bits: 1024 }`.
    pub fn modp1024() -> Self {
        DhGroup {
            p: hex_to_bytes(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404dd\
                 ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
                 ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff",
            ),
            g: vec![2],
        }
    }

    /// RFC 2409 6.1 "First Oakley Group": a 768-bit safe prime.
    pub fn modp768() -> Self {
        DhGroup {
            p: hex_to_bytes(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404dd\
                 ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a63a3620ffffffffffffffff",
            ),
            g: vec![2],
        }
    }

    /// RFC 5114 2.3 "2048-bit MODP Group with 256-bit Prime Order Subgroup".
    /// Not a safe prime: p - 1 = 2 * 7 * 13 * 2549 * 142031 * c * q (c a
    /// 1757-bit cofactor), so the group has small subgroups (order 7 first)
    /// that ServerDHParams, carrying no q, gives a client no way to test for.
    pub fn rfc5114_2048_256() -> Self {
        DhGroup {
            p: hex_to_bytes(RFC5114_2048_256_P_HEX),
            g: hex_to_bytes(RFC5114_2048_256_G_HEX),
        }
    }

    /// The group a `dh_p_bits` override names.
    pub fn by_bits(bits: u16) -> Option<Self> {
        match bits {
            8192 => Some(Self::ffdhe8192()),
            6144 => Some(Self::ffdhe6144()),
            4096 => Some(Self::ffdhe4096()),
            3072 => Some(Self::ffdhe3072()),
            2048 => Some(Self::ffdhe2048()),
            1024 => Some(Self::modp1024()),
            768 => Some(Self::modp768()),
            _ => None,
        }
    }

    pub fn bits(&self) -> usize {
        self.p.len() * 8
    }
}

/// RFC 7919 Appendix A.5 ffdhe8192 prime.
const FFDHE8192_P_HEX: &str = "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695\
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
     0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB\
     7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A\
     7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038\
     092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF\
     8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E0DD9020BFD64B645036C7A\
     4E677D2C38532A3A23BA4442CAF53EA63BB454329B7624C8917BDD64B1C0FD4C\
     B38E8C334C701C3ACDAD0657FCCFEC719B1F5C3E4E46041F388147FB4CFDB477\
     A52471F7A9A96910B855322EDB6340D8A00EF092350511E30ABEC1FFF9E3A26E\
     7FB29F8C183023C3587E38DA0077D9B4763E4E4B94B2BBC194C6651E77CAF992\
     EEAAC0232A281BF6B3A739C1226116820AE8DB5847A67CBEF9C9091B462D538C\
     D72B03746AE77F5E62292C311562A846505DC82DB854338AE49F5235C95B9117\
     8CCF2DD5CACEF403EC9D1810C6272B045B3B71F9DC6B80D63FDD4A8E9ADB1E69\
     62A69526D43161C1A41D570D7938DAD4A40E329CCFF46AAA36AD004CF600C838\
     1E425A31D951AE64FDB23FCEC9509D43687FEB69EDD1CC5E0B8CC3BDF64B10EF\
     86B63142A3AB8829555B2F747C932665CB2C0F1CC01BD70229388839D2AF05E4\
     54504AC78B7582822846C0BA35C35F5C59160CC046FD8251541FC68C9C86B022\
     BB7099876A460E7451A8A93109703FEE1C217E6C3826E52C51AA691E0E423CFC\
     99E9E31650C1217B624816CDAD9A95F9D5B8019488D9C0A0A1FE3075A577E231\
     83F81D4A3F2FA4571EFC8CE0BA8A4FE8B6855DFE72B0A66EDED2FBABFBE58A30\
     FAFABE1C5D71A87E2F741EF8C1FE86FEA6BBFDE530677F0D97D11D49F7A8443D\
     0822E506A9F4614E011E2A94838FF88CD68C8BB7C5C6424CFFFFFFFFFFFFFFFF";

/// RFC 5114 2.3 prime.
const RFC5114_2048_256_P_HEX: &str = "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00\
     E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C\
     209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B\
     6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76\
     B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E\
     F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026\
     C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103\
     A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";

/// RFC 5114 2.3 generator (of the 256-bit prime-order subgroup).
const RFC5114_2048_256_G_HEX: &str = "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125\
     10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62\
     901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B\
     777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193\
     B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A\
     DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915\
     B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3\
     2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";

/// RFC 5114 2.3 subgroup order q, which ServerDHParams cannot carry.
#[cfg(test)]
pub(crate) const RFC5114_2048_256_Q_HEX: &str =
    "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3";

/// `client_random || server_random || params`: the bytes a ServerKeyExchange
/// signature covers (RFC 5246 7.4.3), for the DHE and ECDHE forms alike.
pub fn ske_signed_input(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    params: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + params.len());
    out.extend_from_slice(client_random);
    out.extend_from_slice(server_random);
    out.extend_from_slice(params);
    out
}

/// RFC 5246 8.1.2: "Leading bytes of Z that contain all zero bits are
/// stripped before it is used as the pre_master_secret." (TLS 1.3 keeps
/// them, RFC 8446 7.4.1.)
pub fn strip_leading_zeros(z: &[u8]) -> Vec<u8> {
    let first = z.iter().position(|b| *b != 0).unwrap_or(z.len());
    z[first..].to_vec()
}

/// The server half of a DHE exchange: a private value for `group` and the
/// public `Ys` that goes into `ServerDHParams`.
pub struct DheServer {
    group: DhGroup,
    private: Option<FfdhePrivate>,
    ys: Vec<u8>,
}

impl DheServer {
    /// Deterministic for a seed (plzn's usual sub-seed discipline).
    pub fn generate(group: DhGroup, seed: [u8; 32]) -> Self {
        Self::generate_with_public(group, seed, None)
    }

    /// Generate the server half while optionally replacing Ys with exact wire
    /// bytes. An explicit Ys deliberately has no corresponding private value:
    /// it is intended for rejection tests, and accepting it must fail the case
    /// instead of letting plzn manufacture an unrelated premaster secret --
    /// unless Ys has small order, see `premaster_candidates`.
    pub fn generate_with_public(group: DhGroup, seed: [u8; 32], ys: Option<Vec<u8>>) -> Self {
        if let Some(ys) = ys {
            return DheServer {
                group,
                private: None,
                ys,
            };
        }
        if !modulus_supports_modpow(&group.p) {
            return DheServer {
                group,
                private: None,
                ys: vec![2],
            };
        }
        let mut rng = Rng::from_seed(Rng::sub_seed(seed, b"dhe_server_private"));
        let private = FfdhePrivate::generate(&group.p, &group.g, &mut rng);
        let ys = private.public_bytes(&group.g);
        DheServer {
            group,
            private: Some(private),
            ys,
        }
    }

    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    pub fn ys(&self) -> &[u8] {
        &self.ys
    }

    /// The `ServerDHParams` encoding (RFC 5246 7.4.3): `dh_p`, `dh_g`, `dh_Ys`,
    /// each with a u16 length prefix. This is what gets signed.
    pub fn params(&self) -> Vec<u8> {
        encode_server_dh_params(&self.group.p, &self.group.g, &self.ys)
    }

    /// The premaster secret from the client's `Yc`: rejects a value outside
    /// `(1, p-1)` (the values whose shared secret is a known constant), then
    /// strips the leading zero bytes of `Yc^x mod p`.
    pub fn premaster(&self, yc: &[u8]) -> Result<Vec<u8>, TlsError> {
        let private = self.private.as_ref().ok_or(TlsError::Internal(
            "DHE ClientKeyExchange followed explicit invalid dh_Ys/dh_p parameters",
        ))?;
        if !private.peer_integer_in_range(yc) {
            return Err(TlsError::Internal(
                "DHE ClientKeyExchange: dh_Yc is not in (1, p-1)",
            ));
        }
        Ok(strip_leading_zeros(&private.agree(yc)))
    }

    /// Every premaster secret the client can hold after `Yc`. With plzn's own
    /// Ys that is exactly `premaster`. An explicit Ys has no private value, but
    /// when it has small order the client's `Z = Ys^xc` is one of its powers
    /// whatever `xc` is: each is returned, and the caller keeps the one the
    /// client's first protected record authenticates. `Yc` is not consulted
    /// then -- Z does not depend on it, and a degenerate generator (the case
    /// these parameters exist for) makes a degenerate `Yc` the expected answer.
    pub fn premaster_candidates(&self, yc: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
        if self.private.is_some() {
            return self.premaster(yc).map(|pms| vec![pms]);
        }
        crate::tls::crypto::ffdhe_small_subgroup(&self.group.p, &self.ys, DHE_SMALL_SUBGROUP_LIMIT)
            .map(|secrets| secrets.iter().map(|z| strip_leading_zeros(z)).collect())
            .ok_or(TlsError::Internal(
                "DHE ClientKeyExchange followed an explicit dh_Ys without small order (or dh_p <= 2): plzn cannot know the client's shared secret",
            ))
    }
}

fn modulus_supports_modpow(p: &[u8]) -> bool {
    let mut significant = p.iter().copied().skip_while(|&b| b == 0);
    match significant.next() {
        None => false,
        Some(1 | 2) => significant.next().is_some(),
        Some(_) => true,
    }
}

/// The largest small subgroup whose every element plzn will try as the
/// client's shared secret when an explicit `dh_Ys` leaves it no private value.
pub const DHE_SMALL_SUBGROUP_LIMIT: usize = 4096;

/// The `dh_p` names: `rfc5114_2048_256` (RFC 5114 2.3's prime, generator
/// unchanged).
pub fn dh_prime_recipe(name: &str) -> Option<Vec<u8>> {
    match name {
        "rfc5114_2048_256" => Some(DhGroup::rfc5114_2048_256().p),
        _ => None,
    }
}

/// Resolve compact boundary recipes against p. Values are encoded at p's
/// width so a rejection isolates the integer value rather than its length.
/// `small_order` is an element of the largest odd prime order dividing p - 1
/// that plzn will enumerate (2549 for `rfc5114_2048_256`; none exists for a
/// safe prime).
pub fn dh_parameter_recipe(p: &[u8], recipe: &str) -> Option<Vec<u8>> {
    let width = p.len().max(1);
    let small = |value: u8| {
        let mut out = vec![0u8; width];
        *out.last_mut().expect("nonempty") = value;
        out
    };
    Some(match recipe {
        "zero" => small(0),
        "one" => small(1),
        "two" => small(2),
        "p_minus_1" if modulus_supports_modpow(p) => crate::tls::crypto::bigint_minus_one_be(p),
        "p_minus_1" => vec![0u8; width],
        "p" => p.to_vec(),
        "p_plus_1" => bigint_plus_one_be(p),
        "small_order" => {
            crate::tls::crypto::ffdhe_small_order_element(p, DHE_SMALL_SUBGROUP_LIMIT as u32)?
        }
        _ => return None,
    })
}

fn bigint_plus_one_be(value: &[u8]) -> Vec<u8> {
    let mut out = value.to_vec();
    for byte in out.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return out;
        }
    }
    out.insert(0, 1);
    out
}

pub fn encode_server_dh_params(p: &[u8], g: &[u8], ys: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + p.len() + g.len() + ys.len());
    for part in [p, g, ys] {
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The client half of a DHE exchange: given the server's `(p, g, Ys)`, a
/// deterministic private value; returns `(Yc, premaster)`. A `Ys` outside
/// `(1, p-1)` is refused before any arithmetic.
pub fn dhe_client_premaster(
    p: &[u8],
    g: &[u8],
    ys: &[u8],
    seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    if !modulus_supports_modpow(p) {
        return Err(TlsError::Internal(
            "DHE ServerKeyExchange: dh_p must encode an integer greater than 2",
        ));
    }
    let mut rng = Rng::from_seed(Rng::sub_seed(seed, b"ffdhe_private"));
    let private = FfdhePrivate::generate(p, g, &mut rng);
    if !private.peer_integer_in_range(ys) {
        return Err(TlsError::Internal(
            "DHE ServerKeyExchange: dh_Ys is not in (1, p-1)",
        ));
    }
    let yc = private.public_bytes(g);
    let pms = strip_leading_zeros(&private.agree(ys));
    Ok((yc, pms))
}

/// Like `dhe_client_premaster`, but the private value is searched (over
/// per-attempt sub-seeds) until the UNSTRIPPED shared secret Z starts with
/// `leading_zeros` zero bytes -- tlsfuzzer's "no shared secret padding"
/// probe, which checks the server strips them too (RFC 5246 8.1.2). The
/// premaster returned is stripped like the plain path's. Bounded at 2^20
/// attempts (one zero byte takes about 256, two about 65536).
pub fn dhe_client_premaster_leading_zeros(
    p: &[u8],
    g: &[u8],
    ys: &[u8],
    seed: [u8; 32],
    leading_zeros: usize,
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    for attempt in 0u32..(1 << 20) {
        let label = format!("ffdhe_private:lz:{}", attempt);
        let mut rng = Rng::from_seed(Rng::sub_seed(seed, label.as_bytes()));
        let private = FfdhePrivate::generate(p, g, &mut rng);
        if !private.peer_integer_in_range(ys) {
            return Err(TlsError::Internal(
                "DHE ServerKeyExchange: dh_Ys is not in (1, p-1)",
            ));
        }
        let yc = private.public_bytes(g);
        let z = private.agree(ys);
        if z.iter().take(leading_zeros).all(|b| *b == 0) {
            return Ok((yc, strip_leading_zeros(&z)));
        }
    }
    Err(TlsError::Internal(
        "shared_secret_leading_zeros: no private value found within 2^20 attempts",
    ))
}

/// A deliberately invalid `Yc` / `Ys` for the negatives: the RFC 8446
/// 4.2.8.1 bounds a peer MUST reject, encoded at the prime's length.
pub fn dh_public_recipe(p: &[u8], recipe: DhPublicRecipe) -> Vec<u8> {
    let mut out = vec![0u8; p.len()];
    match recipe {
        DhPublicRecipe::Zero => {}
        DhPublicRecipe::One => {
            if let Some(last) = out.last_mut() {
                *last = 1;
            }
        }
        DhPublicRecipe::PMinusOne => out = crate::tls::crypto::bigint_minus_one_be(p),
        DhPublicRecipe::P => out.copy_from_slice(p),
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhPublicRecipe {
    Zero,
    One,
    PMinusOne,
    /// Y = p itself, just past the RFC 8446 4.2.8.1 upper bound.
    P,
}

/// Static RSA, client side: the 48-byte premaster `client_version || 46
/// random bytes` and its PKCS#1 v1.5 encryption under the server's key.
pub fn rsa_client_premaster(
    server_key: &PublicKey,
    client_version: u16,
    seed: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let mut pms = Vec::with_capacity(48);
    pms.extend_from_slice(&client_version.to_be_bytes());
    let mut rng = Rng::from_seed(Rng::sub_seed(seed, b"pms_random"));
    let random: [u8; 46] = rng.random_array();
    pms.extend_from_slice(&random);
    let encrypted = rsa_pkcs1v15_encrypt(server_key, &pms)?;
    Ok((pms, encrypted))
}

/// The RSA public key's length k in bytes (the EM / ciphertext size).
pub fn rsa_key_len(server_key: &PublicKey) -> Option<usize> {
    crate::tls::crypto::rsa_modulus_bytes(server_key).map(|n| n.len())
}

/// Byte ranges of a PKCS#1 v1.5 type-2 EM `00 || 02 || PS || 00 || M` of k
/// bytes around a 48-byte premaster, for the `pkcs1.*` mutation paths.
pub fn pkcs1_em_layout(k: usize, m_len: usize) -> Vec<(&'static str, std::ops::Range<usize>)> {
    let ps_end = k - m_len - 1;
    vec![
        ("em", 0..k),
        ("block_type", 1..2),
        ("padding", 2..ps_end),
        ("separator", ps_end..ps_end + 1),
        ("premaster", ps_end + 1..k),
    ]
}

/// Build the PKCS#1 v1.5 type-2 EM for `m`: PS is k - 3 - |m| bytes, each
/// non-zero -- random from the test's seed, or every byte `padding_byte`
/// when given (a zero `padding_byte` makes the deliberate "PS contains a
/// zero" fault). This is the input to `rsa_raw_encrypt` when a test shapes
/// the padding; the plain path uses the `rsa` crate's own encoder.
pub fn pkcs1_type2_em(
    k: usize,
    m: &[u8],
    padding_byte: Option<u8>,
    seed: [u8; 32],
) -> Result<Vec<u8>, TlsError> {
    if k < m.len() + 11 {
        return Err(TlsError::Internal(
            "premaster too long for the RSA modulus (PKCS#1 v1.5 needs 11 bytes of overhead)",
        ));
    }
    let ps_len = k - 3 - m.len();
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    match padding_byte {
        Some(b) => em.extend(std::iter::repeat_n(b, ps_len)),
        None => {
            let mut rng = Rng::from_seed(Rng::sub_seed(seed, b"pkcs1_ps"));
            while em.len() < 2 + ps_len {
                let b: [u8; 1] = rng.random_array();
                if b[0] != 0 {
                    em.push(b[0]);
                }
            }
        }
    }
    em.push(0x00);
    em.extend_from_slice(m);
    Ok(em)
}

/// Static RSA, server side (RFC 5246 7.4.7.1). Never fails and never reveals
/// why a ciphertext was bad: a padding error or a plaintext that is not
/// exactly 48 bytes yields `client_version || R` for a random `R`; a wrong
/// version inside a well-formed plaintext yields `client_version || M[2..]`.
/// Either way the handshake continues and fails at Finished, which is the
/// countermeasure the ROBOT probes check for. `client_version` is the
/// ClientHello's version field (0x0303 for TLS 1.2, 0xfefd for DTLS 1.2).
pub fn rsa_server_premaster(
    server_key: &PrivateKey,
    encrypted: &[u8],
    client_version: u16,
    seed: [u8; 32],
) -> Vec<u8> {
    let mut rng = Rng::from_seed(Rng::sub_seed(seed, b"rsa_pms_fallback"));
    let r: [u8; 46] = rng.random_array();
    let version = client_version.to_be_bytes();
    let mut pms = Vec::with_capacity(48);
    pms.extend_from_slice(&version);
    match rsa_pkcs1v15_decrypt(server_key, encrypted) {
        Ok(m) if m.len() == 48 => {
            // The version bytes are replaced by the ones the client claimed,
            // so a mismatch poisons the master secret without an alert.
            pms.extend_from_slice(&m[2..]);
        }
        _ => pms.extend_from_slice(&r),
    }
    pms
}

// ============================================================
//                  pre-shared keys (RFC 4279 / RFC 5489)
// ============================================================

/// RFC 4279 2: the premaster secret of a plain PSK suite,
/// `uint16(N) || N zero bytes || uint16(N) || psk` (the "other_secret" is N
/// zeros for a suite with no key exchange of its own).
pub fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let zeros = vec![0u8; psk.len()];
    psk_premaster_with(&zeros, psk)
}

/// RFC 4279 3 / RFC 5489 2: the premaster secret of a DHE_PSK / ECDHE_PSK
/// suite, `uint16(len(Z)) || Z || uint16(len(psk)) || psk` where Z is the
/// (EC)DH shared secret (leading zeros kept: RFC 5489 references RFC 4492,
/// whose ECDH Z is the fixed-length x coordinate).
pub fn psk_premaster_with(other_secret: &[u8], psk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + other_secret.len() + psk.len());
    out.extend_from_slice(&(other_secret.len() as u16).to_be_bytes());
    out.extend_from_slice(other_secret);
    out.extend_from_slice(&(psk.len() as u16).to_be_bytes());
    out.extend_from_slice(psk);
    out
}

/// Plain-PSK ServerKeyExchange (RFC 4279 2): `opaque psk_identity_hint<0..2^16-1>`.
pub fn encode_psk_hint_ske(hint: &[u8]) -> Vec<u8> {
    encode_psk_hint_ske_mapped(hint).bytes
}

pub fn encode_psk_hint_ske_mapped(hint: &[u8]) -> crate::tls::codec::EncodedBody {
    let mut w = crate::tls::codec::ByteWriter::new();
    w.mark("psk_identity_hint");
    w.mark("psk_identity_hint_length");
    w.u16(hint.len() as u16);
    w.mark_end("psk_identity_hint_length");
    w.bytes(hint);
    w.mark_end("psk_identity_hint");
    w.into_encoded_body()
}

pub fn decode_psk_hint_ske(body: &[u8]) -> Result<Vec<u8>, crate::tls::codec::CodecError> {
    let mut c = crate::tls::codec::ByteCursor::new(body);
    let hint = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(hint)
}

/// ECDHE_PSK ServerKeyExchange (RFC 5489 3.2): the hint, then the
/// (unsigned) `ServerECDHParams`: `ECParameters { named_curve, group }` and
/// the public point. Mapped so `send ServerKeyExchange @ ...` mutations can
/// target the point.
pub fn encode_ecdhe_psk_ske_mapped(
    hint: &[u8],
    named_group: u16,
    point: &[u8],
) -> crate::tls::codec::EncodedBody {
    let mut w = crate::tls::codec::ByteWriter::new();
    w.mark("psk_identity_hint");
    w.mark("psk_identity_hint_length");
    w.u16(hint.len() as u16);
    w.mark_end("psk_identity_hint_length");
    w.bytes(hint);
    w.mark_end("psk_identity_hint");
    w.u8(3); // curve_type = named_curve
    w.mark("named_group");
    w.u16(named_group);
    w.mark_end("named_group");
    w.mark("ecdh_point");
    w.mark("ecdh_point_length");
    w.u8(point.len() as u8);
    w.mark_end("ecdh_point_length");
    w.bytes(point);
    w.mark_end("ecdh_point");
    w.into_encoded_body()
}

/// Parsed ECDHE_PSK ServerKeyExchange: `(hint, named_group, point)`.
pub fn decode_ecdhe_psk_ske(
    body: &[u8],
) -> Result<(Vec<u8>, u16, Vec<u8>), crate::tls::codec::CodecError> {
    let mut c = crate::tls::codec::ByteCursor::new(body);
    let hint = c.u16_vec()?.to_vec();
    let curve_type = c.u8()?;
    if curve_type != 3 {
        return Err(crate::tls::codec::CodecError::MalformedExtension(
            curve_type as u16,
        ));
    }
    let named_group = c.u16()?;
    let point = c.u8_vec()?.to_vec();
    c.expect_empty()?;
    Ok((hint, named_group, point))
}

/// PSK-family ClientKeyExchange: `opaque psk_identity<0..2^16-1>` followed,
/// for ECDHE_PSK, by the client's `ECPoint` (RFC 5489 3.3). Mapped so
/// mutations can target `psk_identity` / `ecdh_point`.
pub fn encode_psk_cke_mapped(
    identity: &[u8],
    ecdh_point: Option<&[u8]>,
) -> crate::tls::codec::EncodedBody {
    let mut w = crate::tls::codec::ByteWriter::new();
    w.mark("psk_identity");
    w.mark("psk_identity_length");
    w.u16(identity.len() as u16);
    w.mark_end("psk_identity_length");
    w.bytes(identity);
    w.mark_end("psk_identity");
    if let Some(point) = ecdh_point {
        w.mark("ecdh_point");
        w.mark("ecdh_point_length");
        w.u8(point.len() as u8);
        w.mark_end("ecdh_point_length");
        w.bytes(point);
        w.mark_end("ecdh_point");
    }
    w.into_encoded_body()
}

/// Parsed PSK-family ClientKeyExchange: `(identity, ecdh_point)`; the point
/// is present for ECDHE_PSK only (`with_point`).
pub fn decode_psk_cke(
    body: &[u8],
    with_point: bool,
) -> Result<(Vec<u8>, Option<Vec<u8>>), crate::tls::codec::CodecError> {
    let mut c = crate::tls::codec::ByteCursor::new(body);
    let identity = c.u16_vec()?.to_vec();
    let point = if with_point {
        Some(c.u8_vec()?.to_vec())
    } else {
        None
    };
    c.expect_empty()?;
    Ok((identity, point))
}

// ============================================================
//                  server-side negotiation helpers
// ============================================================

/// The ECDHE groups plzn's TLS 1.2 server selects from when the test pins
/// none: the same order the shims' clients tend to prefer.
pub const DEFAULT_SERVER_ECDHE_GROUPS: &[u16] = &[0x001d, 0x0017, 0x0018, 0x0019];

/// Pick the ECDHE group for the ServerKeyExchange: the first of the server's
/// capability list (or the default) that the client offered in
/// supported_groups. A client that sent no supported_groups (RFC 8422 5.1
/// lets the server assume any curve) gets the server's first group.
pub fn select_ecdhe_group(server_groups: &[u16], client_groups: &[u16]) -> Option<u16> {
    let candidates: Vec<u16> = server_groups
        .iter()
        .copied()
        .filter(|g| matches!(EcdheGroup::from_wire(*g), Some(gr) if !gr.is_ffdhe() && !gr.is_tls13_only()))
        .collect();
    let candidates = if candidates.is_empty() {
        DEFAULT_SERVER_ECDHE_GROUPS.to_vec()
    } else {
        candidates
    };
    if client_groups.is_empty() {
        return candidates.first().copied();
    }
    candidates.into_iter().find(|g| client_groups.contains(g))
}

/// Pick the signature scheme for the ServerKeyExchange (or the client's
/// CertificateVerify): of the schemes `key` can sign with, restricted to
/// `allowed` when that is non-empty, the first the peer listed -- in the
/// PEER's preference order (RFC 5246 7.4.1.4.1: the list is "in descending
/// order of preference"). A peer that listed nothing gets the key's default.
/// `None` means no common scheme (the server MUST fail the handshake).
pub fn select_signature_scheme(
    key: &PrivateKey,
    peer_offered: &[u16],
    allowed: &[u16],
) -> Option<crate::tls::crypto::SignatureScheme> {
    let can: Vec<crate::tls::crypto::SignatureScheme> = key
        .signature_schemes()
        .into_iter()
        .filter(|s| allowed.is_empty() || allowed.contains(&s.wire_value()))
        .collect();
    if peer_offered.is_empty() {
        // RFC 5246 7.4.1.4.1's default pairs are SHA-1 based, which plzn does
        // not sign; the key's first scheme is the closest modern equivalent.
        return can.first().copied();
    }
    peer_offered
        .iter()
        .find_map(|w| can.iter().copied().find(|s| s.wire_value() == *w))
}

/// The RFC 5246 7.4.4 ClientCertificateType a key can satisfy.
pub fn client_cert_type_for(key: &PrivateKey) -> u8 {
    match key.kind() {
        crate::tls::crypto::KeyKind::Rsa => crate::tls::codec::CLIENT_CERT_TYPE_RSA_SIGN,
        _ => crate::tls::codec::CLIENT_CERT_TYPE_ECDSA_SIGN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::certs::{CertBundle, KeyType};
    use crate::tls::crypto::PrivateKey;

    fn rsa_key() -> (PrivateKey, PublicKey) {
        let bundle = CertBundle::generate(KeyType::Rsa2048).expect("rsa bundle");
        let sk = PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).expect("pkcs8");
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn rsa_premaster_round_trips_and_bad_inputs_fall_back_silently() {
        let (sk, pk) = rsa_key();
        let (pms, ct) = rsa_client_premaster(&pk, 0x0303, [7; 32]).unwrap();
        assert_eq!(pms.len(), 48);
        assert_eq!(&pms[..2], &[0x03, 0x03]);
        assert_eq!(rsa_server_premaster(&sk, &ct, 0x0303, [9; 32]), pms);

        // A wrong version inside a valid ciphertext: the server keeps the
        // random half but stamps the claimed version, so the secrets differ.
        let (pms_bad, ct_bad) = rsa_client_premaster(&pk, 0x0301, [7; 32]).unwrap();
        let got = rsa_server_premaster(&sk, &ct_bad, 0x0303, [9; 32]);
        assert_eq!(&got[..2], &[0x03, 0x03]);
        assert_eq!(&got[2..], &pms_bad[2..]);
        assert_ne!(got, pms_bad);

        // Garbage ciphertext / bad padding: a random 48-byte premaster with
        // the claimed version, deterministic for the seed, never an error.
        let mut garbage = ct.clone();
        garbage[10] ^= 0x55;
        let a = rsa_server_premaster(&sk, &garbage, 0x0303, [9; 32]);
        let b = rsa_server_premaster(&sk, &garbage, 0x0303, [9; 32]);
        assert_eq!(a.len(), 48);
        assert_eq!(&a[..2], &[0x03, 0x03]);
        assert_eq!(a, b);
        assert_ne!(a, pms);
        // A ciphertext of the wrong length is handled the same way.
        assert_eq!(
            rsa_server_premaster(&sk, &ct[..100], 0x0303, [9; 32]).len(),
            48
        );
        // DTLS stamps its own version.
        assert_eq!(
            &rsa_server_premaster(&sk, &garbage, 0xfefd, [9; 32])[..2],
            &[0xfe, 0xfd]
        );
    }

    #[test]
    fn dhe_server_and_client_agree_and_sign_round_trips() {
        let (sk, pk) = rsa_key();
        let server = DheServer::generate(DhGroup::ffdhe2048(), [1; 32]);
        assert_eq!(server.group().bits(), 2048);
        let params = server.params();
        // p, g, Ys each u16-length-prefixed.
        assert_eq!(params.len(), 6 + 256 + 1 + 256);
        let (yc, pms_client) =
            dhe_client_premaster(&server.group().p, &server.group().g, server.ys(), [2; 32])
                .unwrap();
        let pms_server = server.premaster(&yc).unwrap();
        assert_eq!(pms_client, pms_server);
        assert!(
            !pms_client.is_empty() && pms_client[0] != 0,
            "leading zeros stripped"
        );

        let cr = [0x11; 32];
        let sr = [0x22; 32];
        let signed = ske_signed_input(&cr, &sr, &params);
        let sig = sk
            .sign(crate::tls::crypto::SignatureScheme::RsaPkcs1Sha256, &signed)
            .unwrap();
        pk.verify(
            crate::tls::crypto::SignatureScheme::RsaPkcs1Sha256,
            &signed,
            &sig,
        )
        .unwrap();
        let mut tampered = signed.clone();
        tampered[70] ^= 1;
        assert!(
            pk.verify(
                crate::tls::crypto::SignatureScheme::RsaPkcs1Sha256,
                &tampered,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn arbitrary_dh_group_and_wire_recipes_work() {
        let group = DhGroup {
            p: vec![23],
            g: vec![5],
        };
        let server = DheServer::generate(group.clone(), [41; 32]);
        let (yc, client_secret) =
            dhe_client_premaster(&group.p, &group.g, server.ys(), [42; 32]).unwrap();
        assert_eq!(server.premaster(&yc).unwrap(), client_secret);

        assert_eq!(dh_parameter_recipe(&group.p, "zero"), Some(vec![0]));
        assert_eq!(dh_parameter_recipe(&group.p, "one"), Some(vec![1]));
        assert_eq!(dh_parameter_recipe(&group.p, "two"), Some(vec![2]));
        assert_eq!(dh_parameter_recipe(&group.p, "p_minus_1"), Some(vec![22]));
        assert_eq!(dh_parameter_recipe(&group.p, "p"), Some(vec![23]));
        assert_eq!(dh_parameter_recipe(&group.p, "p_plus_1"), Some(vec![24]));
        assert!(dh_parameter_recipe(&group.p, "no_such_recipe").is_none());

        let explicit = DheServer::generate_with_public(group, [43; 32], Some(vec![7]));
        assert_eq!(explicit.ys(), &[7]);
        assert!(explicit.premaster(&[8]).is_err());
    }

    #[test]
    fn dhe_public_values_out_of_range_are_rejected_on_both_sides() {
        let group = DhGroup::ffdhe2048();
        let server = DheServer::generate(group.clone(), [1; 32]);
        for recipe in [
            DhPublicRecipe::Zero,
            DhPublicRecipe::One,
            DhPublicRecipe::PMinusOne,
        ] {
            let bad = dh_public_recipe(&group.p, recipe);
            assert_eq!(bad.len(), group.p.len());
            assert!(server.premaster(&bad).is_err(), "{:?}", recipe);
            assert!(
                dhe_client_premaster(&group.p, &group.g, &bad, [2; 32]).is_err(),
                "{:?}",
                recipe
            );
        }
        // p-1 really is p-1.
        let pm1 = dh_public_recipe(&group.p, DhPublicRecipe::PMinusOne);
        assert_eq!(pm1[..255], group.p[..255]);
        assert_eq!(pm1[255], group.p[255] - 1);
    }

    #[test]
    fn tls12_accepts_unpadded_dh_public_integers() {
        let group = DhGroup {
            p: vec![0, 23],
            g: vec![5],
        };
        let server = DheServer::generate(group.clone(), [44; 32]);
        let (yc, client_secret) =
            dhe_client_premaster(&group.p, &group.g, server.ys(), [45; 32]).unwrap();
        assert_eq!(yc[0], 0);
        assert_eq!(server.premaster(&yc[1..]).unwrap(), client_secret);
    }

    #[test]
    fn built_in_dh_groups_are_safe_primes() {
        assert_eq!(DhGroup::modp1024().bits(), 1024);
        assert_eq!(DhGroup::modp768().bits(), 768);
        assert_eq!(DhGroup::by_bits(2048), Some(DhGroup::ffdhe2048()));
        assert_eq!(DhGroup::by_bits(8192), Some(DhGroup::ffdhe8192()));
        assert!(DhGroup::by_bits(512).is_none());
        // Each is a safe prime: (p-1)/2 is prime as well.
        for g in [
            DhGroup::modp1024(),
            DhGroup::modp768(),
            DhGroup::ffdhe2048(),
            DhGroup::ffdhe8192(),
        ] {
            assert!(
                crate::tls::crypto::is_probable_safe_prime_be(&g.p),
                "{} bits",
                g.bits()
            );
        }
    }

    #[test]
    fn psk_premaster_formats_follow_rfc_4279() {
        // Plain PSK: len || zeros || len || psk.
        let pm = psk_premaster(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(pm, vec![0, 3, 0, 0, 0, 0, 3, 0xAA, 0xBB, 0xCC]);
        // ECDHE_PSK: len(Z) || Z || len(psk) || psk, Z kept verbatim.
        let pm = psk_premaster_with(&[0x00, 0x11], &[0xAA]);
        assert_eq!(pm, vec![0, 2, 0x00, 0x11, 0, 1, 0xAA]);
    }

    #[test]
    fn psk_messages_round_trip() {
        let ske = encode_psk_hint_ske(b"hint");
        assert_eq!(decode_psk_hint_ske(&ske).unwrap(), b"hint");
        let ske = encode_ecdhe_psk_ske_mapped(b"h", 0x001d, &[0x11; 32]);
        assert!(ske.fields.contains_key("ecdh_point"));
        let (hint, group, point) = decode_ecdhe_psk_ske(&ske.bytes).unwrap();
        assert_eq!(
            (hint.as_slice(), group, point.len()),
            (b"h".as_slice(), 0x001d, 32)
        );
        let cke = encode_psk_cke_mapped(b"id", Some(&[0x22; 65]));
        let (id, point) = decode_psk_cke(&cke.bytes, true).unwrap();
        assert_eq!(
            (id.as_slice(), point.map(|p| p.len())),
            (b"id".as_slice(), Some(65))
        );
        let cke = encode_psk_cke_mapped(b"id", None);
        assert_eq!(
            decode_psk_cke(&cke.bytes, false).unwrap(),
            (b"id".to_vec(), None)
        );
        assert!(decode_psk_cke(&cke.bytes, true).is_err());
    }

    #[test]
    fn group_and_scheme_selection_follow_the_peer_within_the_server_set() {
        // Server prefers x25519; client offered P-256 and P-384 only -> P-256.
        assert_eq!(
            select_ecdhe_group(&[0x001d, 0x0017], &[0x0018, 0x0017]),
            Some(0x0017)
        );
        // No group capabilities: the default set; client offering only P-521 -> P-521.
        assert_eq!(select_ecdhe_group(&[], &[0x0019]), Some(0x0019));
        // ffdhe groups are not ECDHE candidates; nothing in common -> None.
        assert_eq!(
            select_ecdhe_group(&[0x0100], &[0x0100, 0x001d]),
            Some(0x001d)
        );
        assert_eq!(select_ecdhe_group(&[0x0017], &[0x001d]), None);
        // No supported_groups from the client -> the server's first group.
        assert_eq!(select_ecdhe_group(&[0x0018], &[]), Some(0x0018));

        let (sk, _) = rsa_key();
        // The client's order wins: PKCS#1 listed first is selected over PSS.
        let s = select_signature_scheme(&sk, &[0x0401, 0x0804], &[]).unwrap();
        assert_eq!(s.wire_value(), 0x0401);
        // `allowed` restricts the key's schemes: only PSS-SHA384 permitted.
        let s = select_signature_scheme(&sk, &[0x0401, 0x0805], &[0x0805]).unwrap();
        assert_eq!(s.wire_value(), 0x0805);
        // ECDSA-only client with an RSA key: no common scheme.
        assert!(select_signature_scheme(&sk, &[0x0403], &[]).is_none());
        // Nothing offered: the key's default.
        assert_eq!(
            select_signature_scheme(&sk, &[], &[]).unwrap().wire_value(),
            0x0804
        );
        assert_eq!(
            client_cert_type_for(&sk),
            crate::tls::codec::CLIENT_CERT_TYPE_RSA_SIGN
        );
    }

    #[test]
    fn small_order_explicit_ys_yields_every_premaster_the_client_can_hold() {
        // g = 1: every client answers Yc = 1, yet its secret is Ys^xc.
        let group = DhGroup {
            g: vec![1],
            ..DhGroup::rfc5114_2048_256()
        };
        let ys = dh_parameter_recipe(&group.p, "small_order").expect("p - 1 has the factor 2549");
        let server = DheServer::generate_with_public(group.clone(), [3; 32], Some(ys.clone()));
        for seed in 0u8..16 {
            let (yc, pms) = dhe_client_premaster(&group.p, &group.g, &ys, [seed; 32]).unwrap();
            assert_eq!(strip_leading_zeros(&yc), [1]);
            let candidates = server.premaster_candidates(&yc).unwrap();
            assert_eq!(candidates.len(), 2549);
            assert!(candidates.contains(&pms), "seed {seed}");
        }

        // An explicit Ys of large order (2 generates ffdhe2048's q-subgroup)
        // leaves plzn no way to know the secret.
        let server = DheServer::generate_with_public(DhGroup::ffdhe2048(), [3; 32], Some(vec![2]));
        assert!(server.premaster_candidates(&[2]).is_err());
        // A safe prime has no small_order element at all.
        assert!(dh_parameter_recipe(&DhGroup::ffdhe2048().p, "small_order").is_none());

        // plzn's own Ys: exactly the one premaster.
        let server = DheServer::generate(DhGroup::ffdhe2048(), [3; 32]);
        let (yc, pms) =
            dhe_client_premaster(&server.group().p, &[2], server.ys(), [5; 32]).unwrap();
        assert_eq!(server.premaster_candidates(&yc).unwrap(), vec![pms]);
    }
}
