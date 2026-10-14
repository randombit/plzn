// Certificate generation for the config-file shims. The shims (botan / openssl /
// rustls) are the test backends; there are no in-process server backends anymore.

pub mod certs;
// T6: OCSP responses for the shims' stapling.
pub mod ocsp;
