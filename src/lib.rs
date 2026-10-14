pub mod app_data;
pub mod ast;
pub mod check;
pub mod diag;
pub mod discovery;
mod fixtures;
pub mod format;
pub mod ir;
pub mod lex;
pub mod lower;
pub mod parse;
pub mod pcap;
pub mod runtime;
pub mod schema;
pub mod server;
pub mod shim;
pub mod tls;
pub mod transport;

use diag::Diag;

pub fn lint(source_name: &str, source: &str) -> Vec<Diag> {
    let mut diags = Vec::new();
    let tokens = match lex::lex(source) {
        Ok(t) => t,
        Err(errs) => {
            diags.extend(errs.into_iter().map(|e| e.into_diag(source_name, source)));
            return diags;
        }
    };
    let file = match parse::parse(&tokens) {
        Ok(f) => f,
        Err(errs) => {
            diags.extend(errs.into_iter().map(|e| e.into_diag(source_name, source)));
            return diags;
        }
    };
    let errs = check::check(&file);
    diags.extend(errs.into_iter().map(|e| e.into_diag(source_name, source)));
    if !diags.is_empty() {
        return diags;
    }
    // Run lowering to catch semantic errors (expect-ok without AppData
    // exchange, unsupported constructs, etc.). DTLS lowers like TLS now.
    for test in &file.tests {
        if let Err(errs) = lower::lower(test) {
            diags.extend(errs.into_iter().map(|e| e.into_diag(source_name, source)));
        }
    }
    diags
}
