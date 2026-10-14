// Recursive-descent parser for the brace-delimited plzn DSL.
//
// Grammar highlights:
//   * Blocks are `{ ... }`. Statements inside a block are terminated by
//     newlines.
//   * Newlines are consumed greedily everywhere newlines don't carry
//     meaning (between tests, inside `( )`, `[ ]`, and field-override
//     `{ }` blocks).
//   * Errors collect but recovery is crude: on a parse error inside a
//     test we skip to the next `plzn tls` declaration.

use crate::ast::*;
use crate::lex::{Tok, Token};

#[derive(Clone, Debug)]
pub struct ParseError {
    pub span: Span,
    pub message: String,
}

impl ParseError {
    pub fn into_diag(self, source_name: &str, source: &str) -> crate::diag::Diag {
        crate::diag::Diag::from_simple(source_name, source, self.span, "parse error", self.message)
    }
}

fn check_unique_field(
    seen: &mut std::collections::HashSet<String>,
    field: &Ident,
    block: &str,
) -> Result<(), ParseError> {
    if seen.insert(field.name.clone()) {
        Ok(())
    } else {
        Err(ParseError {
            span: field.span,
            message: format!("duplicate `{}` field in `{block}` block", field.name),
        })
    }
}

pub fn parse(tokens: &[Token]) -> Result<File, Vec<ParseError>> {
    let mut p = Parser::new(tokens);
    let mut file = File { tests: Vec::new() };
    let mut errors = Vec::new();
    p.skip_newlines();
    while !p.eof() {
        match p.parse_test() {
            Ok(t) => file.tests.push(t),
            Err(e) => {
                errors.push(e);
                p.recover_to_next_test();
            }
        }
        p.skip_newlines();
    }
    if errors.is_empty() {
        Ok(file)
    } else {
        Err(errors)
    }
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    // ----- cursor helpers -----

    fn eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_at(&self, off: usize) -> Option<&Token> {
        self.tokens.get(self.pos + off)
    }

    fn prev_span(&self) -> Span {
        if self.pos > 0 {
            self.tokens[self.pos - 1].span
        } else {
            Span::dummy()
        }
    }

    fn bump(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn at(&self, t: &Tok) -> bool {
        matches!(self.peek(), Some(Token { tok, .. }) if tok == t)
    }

    fn at_ident(&self, name: &str) -> bool {
        matches!(self.peek(), Some(Token { tok: Tok::Ident(s), .. }) if s == name)
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.at(t) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn eat_ident(&mut self, name: &str) -> bool {
        if self.at_ident(name) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn skip_newlines(&mut self) {
        while self.at(&Tok::Newline) {
            self.bump();
        }
    }

    fn expect(&mut self, t: &Tok, what: &str) -> Result<Span, ParseError> {
        match self.peek() {
            Some(tok) if &tok.tok == t => {
                let span = tok.span;
                self.bump();
                Ok(span)
            }
            Some(tok) => Err(ParseError {
                span: tok.span,
                message: format!("expected {}, found {}", what, describe_tok(&tok.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: format!("expected {}, found end of file", what),
            }),
        }
    }

    fn expect_newline_or_rbrace(&mut self) -> Result<(), ParseError> {
        // Accept newline (consumed) or peek at `}` (left for caller).
        if self.eat(&Tok::Newline) {
            return Ok(());
        }
        if self.at(&Tok::RBrace) {
            return Ok(());
        }
        match self.peek() {
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!(
                    "expected newline or `}}` to end statement, found {}",
                    describe_tok(&t.tok)
                ),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected newline or `}`, found end of file".into(),
            }),
        }
    }

    fn expect_ident(&mut self) -> Result<Ident, ParseError> {
        match self.peek() {
            Some(Token {
                tok: Tok::Ident(s),
                span,
            }) => {
                let id = Ident {
                    name: s.clone(),
                    span: *span,
                };
                self.bump();
                Ok(id)
            }
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!("expected identifier, found {}", describe_tok(&t.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected identifier, found end of file".into(),
            }),
        }
    }

    fn expect_str(&mut self) -> Result<StrLit, ParseError> {
        match self.peek() {
            Some(Token {
                tok: Tok::Str(s),
                span,
            }) => {
                let v = StrLit {
                    value: s.clone(),
                    span: *span,
                };
                self.bump();
                Ok(v)
            }
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!("expected string, found {}", describe_tok(&t.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected string, found end of file".into(),
            }),
        }
    }

    fn expect_int(&mut self) -> Result<IntLit, ParseError> {
        let (neg, lead_span) = if let Some(t) = self.peek() {
            if t.tok == Tok::Minus {
                let s = t.span;
                self.bump();
                (true, Some(s))
            } else {
                (false, None)
            }
        } else {
            (false, None)
        };
        match self.peek() {
            Some(Token {
                tok: Tok::Int(n) | Tok::Hex(n),
                span,
            }) => {
                let value = if neg { -*n } else { *n };
                let span = match lead_span {
                    Some(s) => s.join(*span),
                    None => *span,
                };
                self.bump();
                Ok(IntLit { value, span })
            }
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!("expected integer, found {}", describe_tok(&t.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected integer, found end of file".into(),
            }),
        }
    }

    fn recover_to_next_test(&mut self) {
        while let Some(t) = self.peek() {
            match &t.tok {
                Tok::Ident(s)
                    if s == "plzn"
                        && matches!(self.peek_at(1), Some(Token { tok: Tok::Ident(protocol), .. }) if protocol == "tls") =>
                {
                    break;
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    // ================= grammar =================

    fn parse_test(&mut self) -> Result<Test, ParseError> {
        let start = self.peek().map(|t| t.span).unwrap_or(Span::dummy());
        if !self.eat_ident("plzn") || !self.eat_ident("tls") {
            return Err(ParseError {
                span: start,
                message: "expected `plzn tls`".into(),
            });
        }
        let name = self.expect_str()?;
        self.expect(&Tok::LBrace, "`{`")?;
        self.skip_newlines();

        let mut header = Vec::new();
        let mut matrix = None;
        let mut psk = None;
        let mut uut = None;
        let mut peer = None;
        let mut sessions = Vec::new();
        let mut flow = None;
        let mut expect: Option<Expect> = None;
        let mut asserts = Vec::new();
        let mut repeat: Option<IntLit> = None;

        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            // T1: `repeat N` -- run the test N times (fresh connection each).
            if self.at_ident("repeat") {
                if repeat.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "duplicate test-level `repeat` declaration".into(),
                    });
                }
                self.bump();
                let n = self.expect_int()?;
                if !(1..=4096).contains(&n.value) {
                    return Err(ParseError {
                        span: n.span,
                        message: format!("repeat count {} out of range (1..4096)", n.value),
                    });
                }
                self.expect_newline_or_rbrace()?;
                repeat = Some(n);
                continue;
            }
            if self.at_ident("rfc") {
                header.push(self.parse_rfc_line()?);
                continue;
            }
            if self.at_ident("testing") {
                let span = self.peek().unwrap().span;
                return Err(ParseError {
                    span,
                    message: "`testing client|server` was merged into the mandatory UUT block; use `uut client { ... }` or `uut server { ... }`".into(),
                });
            }
            if self.at_ident("cfg") {
                let span = self.peek().unwrap().span;
                return Err(ParseError {
                    span,
                    message: "`cfg` lines were replaced by `uut client|server { versions: [...] }` plus `peer { capabilities: [...] }`".into(),
                });
            }
            if self.at_ident("skip") {
                header.push(self.parse_backend_annotation(false)?);
                continue;
            }
            if self.at_ident("xfail") {
                header.push(self.parse_backend_annotation(true)?);
                continue;
            }
            // A: `chain: [...]` / `client_chain: [...]`.
            if self.at_ident("chain") || self.at_ident("client_chain") {
                header.push(self.parse_chain_line()?);
                continue;
            }
            if self.at_ident("matrix") {
                if matrix.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "test has more than one `matrix` block".into(),
                    });
                }
                matrix = Some(self.parse_matrix()?);
                continue;
            }
            if (self.at(&Tok::Plus) || self.at(&Tok::Minus))
                && matches!(self.peek_at(1), Some(Token { tok: Tok::Ident(s), .. }) if s == "ext")
            {
                let span = self.peek().unwrap().span;
                return Err(ParseError {
                    span,
                    message: "+ext/-ext at test level not supported; \
                              use inside `send X { ... }` body instead"
                        .into(),
                });
            }
            if self.at_ident("psk") {
                if psk.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "test has more than one `psk` block".into(),
                    });
                }
                psk = Some(self.parse_psk_block()?);
                continue;
            }
            if self.at_ident("uut") {
                if uut.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "test has more than one `uut` block".into(),
                    });
                }
                uut = Some(self.parse_uut_block()?);
                continue;
            }
            if self.at_ident("peer") {
                if peer.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "test has more than one `peer` block".into(),
                    });
                }
                peer = Some(self.parse_peer_block()?);
                continue;
            }
            if self.at_ident("session") {
                sessions.push(self.parse_session_block()?);
                continue;
            }
            if self.at_ident("flow") {
                if flow.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "more than one `flow` block in the same scope".into(),
                    });
                }
                flow = Some(self.parse_flow()?);
                continue;
            }
            if self.at_ident("expect") {
                if let Some(e) = &mut expect {
                    // Already have a primary expect — this must be an override.
                    let ov = self.parse_expect_override()?;
                    e.overrides.push(ov);
                } else {
                    expect = Some(self.parse_expect()?);
                }
                continue;
            }
            if self.at_ident("assert") {
                asserts.push(self.parse_assert()?);
                continue;
            }
            let t = self.peek().unwrap();
            return Err(ParseError {
                span: t.span,
                message: format!("unexpected {} in test body", describe_tok(&t.tok)),
            });
        }
        let end = self.expect(&Tok::RBrace, "`}`")?;

        Ok(Test {
            name,
            header,
            matrix,
            psk,
            uut,
            peer,
            sessions,
            flow,
            expect,
            asserts,
            repeat,
            span: start.join(end),
        })
    }

    fn parse_rfc_line(&mut self) -> Result<HeaderLine, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // rfc
        let number = self.expect_int()?;
        if number.value < 0 || number.value > u32::MAX as i64 {
            return Err(ParseError {
                span: number.span,
                message: "rfc number out of range".into(),
            });
        }
        // `rfc 8446 section 4.1.2`. The section is written bare, the way the
        // RFC itself numbers it -- no `§`, no quotes.
        let section = if self.at_ident("section") {
            self.bump();
            Some(self.parse_section_ref()?)
        } else if let Some(Token {
            tok: Tok::Str(s),
            span,
        }) = self.peek()
        {
            // The retired quoted form: name the replacement rather than just
            // complaining about an unexpected string.
            return Err(ParseError {
                span: *span,
                message: format!(
                    "quoted rfc section is no longer supported; write `section {}`",
                    s.trim_start_matches('\u{a7}')
                ),
            });
        } else {
            None
        };
        self.expect_newline_or_rbrace()?;
        let end = section.as_ref().map(|s| s.span).unwrap_or(number.span);
        Ok(HeaderLine::Rfc {
            number: number.value as u32,
            section,
            span: start.join(end),
        })
    }

    /// A section path: `4.1.2`, `7.4.1.4.1`, or an appendix like `B.4`. The
    /// lexer hands us the pieces as separate tokens, so adjacent spans are
    /// what make `4.1.2` one path and `4 .1` a mistake.
    fn parse_section_ref(&mut self) -> Result<SectionRef, ParseError> {
        let (mut text, mut span) = self.section_segment()?;
        while self.at(&Tok::Dot) {
            let dot = self.peek().unwrap().span;
            if dot.start != span.end {
                break;
            }
            self.bump();
            let (seg, seg_span) = self.section_segment()?;
            if seg_span.start != dot.end {
                return Err(ParseError {
                    span: dot.join(seg_span),
                    message: "rfc section must not contain spaces; write `4.1.2`".into(),
                });
            }
            text.push('.');
            text.push_str(&seg);
            span = span.join(seg_span);
        }
        Ok(SectionRef { text, span })
    }

    /// One component of a section path: a number, or the letter naming an
    /// appendix (`B` in `B.4`).
    fn section_segment(&mut self) -> Result<(String, Span), ParseError> {
        let (seg, span) = match self.peek() {
            Some(Token {
                tok: Tok::Int(n),
                span,
            }) => (n.to_string(), *span),
            Some(Token {
                tok: Tok::Ident(s),
                span,
            }) if s.len() <= 2 && s.chars().all(|c| c.is_ascii_alphabetic()) => (s.clone(), *span),
            Some(t) => {
                return Err(ParseError {
                    span: t.span,
                    message: format!(
                        "expected a section number after `section`, found {}",
                        describe_tok(&t.tok)
                    ),
                });
            }
            None => {
                return Err(ParseError {
                    span: self.prev_span(),
                    message: "expected a section number after `section`".into(),
                });
            }
        };
        self.bump();
        Ok((seg, span))
    }

    /// A: `chain: [rsa_2048, ecdsa_p256]`, `client_chain: []`.
    fn parse_chain_line(&mut self) -> Result<HeaderLine, ParseError> {
        let start = self.peek().unwrap().span;
        let kw = self.expect_ident()?;
        let client = kw.name == "client_chain";
        self.expect(&Tok::Colon, "`:` after `chain`")?;
        self.expect(
            &Tok::LBracket,
            "`[` opening the chain list (`chain: [default]`)",
        )?;
        let mut names = Vec::new();
        while !self.at(&Tok::RBracket) && !self.eof() {
            if self.eat(&Tok::Comma) {
                continue;
            }
            names.push(self.expect_ident()?);
        }
        let end = self.expect(&Tok::RBracket, "`]` closing the chain list")?;
        self.expect_newline_or_rbrace()?;
        Ok(HeaderLine::Chain {
            client,
            names,
            span: start.join(end),
        })
    }

    fn parse_backend_annotation(&mut self, xfail: bool) -> Result<HeaderLine, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // skip / xfail
        let mut backends = Vec::new();
        backends.push(self.expect_ident()?);
        while self.eat(&Tok::Comma) {
            backends.push(self.expect_ident()?);
        }
        // Optional reason: `xfail rustls "does not enforce the record limit"`.
        let reason = if matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Str(_),
                ..
            })
        ) {
            Some(self.expect_str()?)
        } else {
            None
        };
        let end = reason
            .as_ref()
            .map(|r| r.span)
            .unwrap_or(backends.last().unwrap().span);
        self.expect_newline_or_rbrace()?;
        if xfail {
            Ok(HeaderLine::Xfail {
                backends,
                reason,
                span: start.join(end),
            })
        } else {
            Ok(HeaderLine::Skip {
                backends,
                reason,
                span: start.join(end),
            })
        }
    }

    fn parse_matrix(&mut self) -> Result<Matrix, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // matrix
        self.expect(&Tok::LBrace, "`{` after `matrix`")?;
        self.skip_newlines();
        let mut axes = Vec::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            axes.push(self.parse_matrix_axis()?);
        }
        let end = self.expect(&Tok::RBrace, "`}` closing matrix")?;
        Ok(Matrix {
            axes,
            span: start.join(end),
        })
    }

    fn parse_matrix_axis(&mut self) -> Result<MatrixAxis, ParseError> {
        let var = self.expect_ident()?;
        let start = var.span;
        if !self.eat_ident("in") {
            let t = self.peek().cloned();
            return Err(ParseError {
                span: t.as_ref().map(|t| t.span).unwrap_or(start),
                message: "expected `in` after matrix variable".into(),
            });
        }
        let values = if self.at(&Tok::LBracket) {
            let lb = self.peek().unwrap().span;
            self.bump();
            self.skip_newlines();
            let mut items = Vec::new();
            if !self.at(&Tok::RBracket) {
                items.push(self.parse_matrix_item()?);
                while self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    items.push(self.parse_matrix_item()?);
                }
            }
            self.skip_newlines();
            let rb = self.expect(&Tok::RBracket, "`]`")?;
            MatrixValues::List {
                items,
                span: lb.join(rb),
            }
        } else if matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Int(_) | Tok::Hex(_) | Tok::Minus,
                ..
            })
        ) {
            let lo = self.expect_int()?;
            self.expect(&Tok::DotDot, "`..`")?;
            let hi = self.expect_int()?;
            // T1: `lo..hi step N`.
            let step = if self.at_ident("step") {
                self.bump();
                let st = self.expect_int()?;
                if st.value < 1 {
                    return Err(ParseError {
                        span: st.span,
                        message: "matrix range step must be >= 1".into(),
                    });
                }
                Some(st)
            } else {
                None
            };
            MatrixValues::Range {
                lo,
                hi,
                step,
                span: lo.span.join(hi.span),
            }
        } else {
            let name = self.expect_ident()?;
            let (arg, end) = if self.eat(&Tok::LParen) {
                let a = if self.at(&Tok::RParen) {
                    None
                } else {
                    Some(self.expect_ident()?)
                };
                let rp = self.expect(&Tok::RParen, "`)`")?;
                (a, rp)
            } else {
                (None, name.span)
            };
            MatrixValues::Named {
                name: name.clone(),
                arg,
                span: name.span.join(end),
            }
        };
        self.expect_newline_or_rbrace()?;
        Ok(MatrixAxis {
            var: var.clone(),
            values,
            span: var.span.join(start),
        })
    }

    // T1: one matrix list entry: `N` or `lo..hi` (inclusive); D: or a name
    // from the suite / group / scheme / extension tables, resolved at lowering.
    fn parse_matrix_item(&mut self) -> Result<MatrixItem, ParseError> {
        if matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Ident(_),
                ..
            })
        ) {
            let id = self.expect_ident()?;
            return Ok(MatrixItem::Name(id));
        }
        let lo = self.expect_int()?;
        if self.eat(&Tok::DotDot) {
            let hi = self.expect_int()?;
            if lo.value > hi.value {
                return Err(ParseError {
                    span: lo.span.join(hi.span),
                    message: format!(
                        "range `{}..{}` is empty; lo must be <= hi",
                        lo.value, hi.value
                    ),
                });
            }
            return Ok(MatrixItem::Range { lo, hi });
        }
        Ok(MatrixItem::Int(lo))
    }

    /// Parse `+ext NAME = VALUE` or `+ext 0xNNNN = raw "HEX"` or
    /// `-ext NAME` / `-ext 0xNNNN`; T1: `+ext each lo..hi [= VALUE]` and
    /// `+ext $id [= VALUE]`.
    fn parse_ext_delta(&mut self) -> Result<ExtDelta, ParseError> {
        let sign_tok = self.peek().unwrap().clone();
        let is_add = matches!(sign_tok.tok, Tok::Plus);
        self.bump(); // + or -
        let ext_id = self.expect_ident()?;
        if ext_id.name != "ext" {
            return Err(ParseError {
                span: ext_id.span,
                message: format!("expected `ext`, found `{}`", ext_id.name),
            });
        }
        // Optional `dup` modifier: `+ext dup TYPE = ...` appends even when an
        // extension of this type is already present (DuplicateExtension tests).
        let dup = is_add && self.at_ident("dup") && {
            self.bump();
            true
        };
        // T1: `+ext each <types> [= value]` -- one extension per listed type
        // (`90..100`, `[90..13171, 13173..16473]`, `[$a, $b]`).
        if is_add && self.at_ident("each") {
            if dup {
                return Err(ParseError {
                    span: self.peek().unwrap().span,
                    message: "`+ext each` already appends each entry; do not combine it with `dup`"
                        .into(),
                });
            }
            self.bump();
            let types = self.parse_field_value()?;
            let value = if self.eat(&Tok::Eq) {
                self.parse_ext_value()?
            } else {
                ExtValue::Empty(self.prev_span())
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(ExtDelta::AddEach {
                types,
                value,
                span: sign_tok.span.join(end),
            });
        }
        // Target: either an ident (`server_name`) or an integer literal
        // for an unknown extension type (`0x0a0a`), or (T1) a matrix variable.
        let target = match self.peek().cloned() {
            Some(Token {
                tok: Tok::Dollar,
                span,
            }) => {
                self.bump();
                let id = self.expect_ident()?;
                ExtTarget::Var(Ident {
                    name: id.name,
                    span: span.join(id.span),
                })
            }
            Some(Token {
                tok: Tok::Hex(n) | Tok::Int(n),
                span,
            }) => {
                self.bump();
                if !(0..=0xffff).contains(&n) {
                    return Err(ParseError {
                        span,
                        message: format!("extension type {} out of range (0..0xffff)", n),
                    });
                }
                ExtTarget::Wire(n as u16, span)
            }
            _ => {
                let name = self.expect_ident()?;
                ExtTarget::Named(name)
            }
        };
        if !is_add {
            self.expect_newline_or_rbrace()?;
            let end = match &target {
                ExtTarget::Named(n) => n.span,
                ExtTarget::Wire(_, s) => *s,
                ExtTarget::Var(v) => v.span,
            };
            return Ok(ExtDelta::Remove {
                target,
                span: sign_tok.span.join(end),
            });
        }
        // `+ext NAME` with no value: an empty extension body.
        if self.at(&Tok::Newline) || self.at(&Tok::RBrace) || self.eof() {
            let end = match &target {
                ExtTarget::Named(n) => n.span,
                ExtTarget::Wire(_, s) => *s,
                ExtTarget::Var(v) => v.span,
            };
            self.expect_newline_or_rbrace()?;
            return Ok(ExtDelta::Add {
                target,
                value: ExtValue::Empty(end),
                dup,
                span: sign_tok.span.join(end),
            });
        }
        self.expect(&Tok::Eq, "`=` after extension name")?;
        let value = self.parse_ext_value()?;
        let end_span = self.prev_span();
        self.expect_newline_or_rbrace()?;
        Ok(ExtDelta::Add {
            target,
            value,
            dup,
            span: sign_tok.span.join(end_span),
        })
    }

    /// Parse the right-hand side of `+ext NAME = ...`:
    ///   `raw "HEX"` | `"string"` | `[ident, ident]` | `["s", "t"]` | `INT` | `ident`
    fn parse_ext_value(&mut self) -> Result<ExtValue, ParseError> {
        // raw "HEX"
        if self.at_ident("raw") {
            let start = self.peek().unwrap().span;
            self.bump();
            let (s, span) = match self.peek().cloned() {
                Some(Token {
                    tok: Tok::Str(s),
                    span,
                }) => {
                    self.bump();
                    (s, span)
                }
                _ => {
                    return Err(ParseError {
                        span: start,
                        message: "expected hex string after `raw`".into(),
                    });
                }
            };
            let hex_str: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if !hex_str.len().is_multiple_of(2) {
                return Err(ParseError {
                    span,
                    message: "raw hex must have even number of digits".into(),
                });
            }
            let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                .collect();
            let bytes = bytes.map_err(|_| ParseError {
                span,
                message: "invalid hex digit".into(),
            })?;
            return Ok(ExtValue::Raw(bytes, start.join(span)));
        }
        // T1: every other form is the shared value grammar: `[...]` lists (names,
        // numbers, strings, ranges, repeats, `key : bytes` entries), a string, a
        // number, a bare name (`ocsp`, `tls13`, `secp256r1`) or a matrix variable.
        let v = self.parse_field_value()?;
        let span = self.prev_span();
        Ok(match v {
            FieldValue::List(items) => ExtValue::List(items, span),
            FieldValue::Empty => ExtValue::List(Vec::new(), span),
            FieldValue::Str(lit) => ExtValue::Str(lit),
            FieldValue::Int(n) => ExtValue::Int(n),
            FieldValue::Ident(id) => ExtValue::Ident(id),
            FieldValue::MatrixVar(id) => ExtValue::Var(id),
            other => ExtValue::List(vec![other], span),
        })
    }

    /// Parse `session <name> [resumes: <other>, version: tls13, force_resume: true] { ... }`.
    fn parse_session_block(&mut self) -> Result<SessionBlock, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // session
        let name = self.expect_ident()?;
        let mut resumes = None;
        let mut version = None;
        let mut force_resume = None;
        if self.eat(&Tok::LBracket) {
            loop {
                let key = self.expect_ident()?;
                self.expect(&Tok::Colon, "`:` in session qualifier")?;
                match key.name.as_str() {
                    "resumes" if resumes.is_none() => resumes = Some(self.expect_ident()?),
                    "version" if version.is_none() => version = Some(self.expect_ident()?),
                    "force_resume" if force_resume.is_none() => {
                        let value = self.expect_ident()?;
                        match value.name.as_str() {
                            "true" => force_resume = Some(true),
                            "false" => force_resume = Some(false),
                            _ => {
                                return Err(ParseError {
                                    span: value.span,
                                    message: "`force_resume` must be `true` or `false`".into(),
                                });
                            }
                        }
                    }
                    "resumes" | "version" | "force_resume" => {
                        return Err(ParseError {
                            span: key.span,
                            message: format!("duplicate `{}` session qualifier", key.name),
                        });
                    }
                    _ => {
                        return Err(ParseError {
                            span: key.span,
                            message: "session qualifier must be `resumes:`, `version:`, or `force_resume:`".into(),
                        });
                    }
                }
                if self.eat(&Tok::RBracket) {
                    break;
                }
                self.expect(&Tok::Comma, "`,` between session qualifiers")?;
            }
        }
        self.expect(&Tok::LBrace, "`{` after session name")?;
        self.skip_newlines();
        let mut flow: Option<Flow> = None;
        let mut expect: Option<Expect> = None;
        let mut asserts = Vec::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            if self.at_ident("flow") {
                if flow.is_some() {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "more than one `flow` block in the same scope".into(),
                    });
                }
                flow = Some(self.parse_flow()?);
                continue;
            }
            if self.at_ident("expect") {
                if let Some(e) = &mut expect {
                    // A second `expect` in the session is a per-backend override
                    // (`expect <kind> if <uut>`), same as at test scope.
                    let ov = self.parse_expect_override()?;
                    e.overrides.push(ov);
                } else {
                    expect = Some(self.parse_expect()?);
                }
                continue;
            }
            if self.at_ident("assert") {
                asserts.push(self.parse_assert()?);
                continue;
            }
            let t = self.peek().unwrap();
            return Err(ParseError {
                span: t.span,
                message: format!("unexpected {} in session body", describe_tok(&t.tok)),
            });
        }
        let end = self.expect(&Tok::RBrace, "`}` closing session")?;
        let flow = flow.ok_or_else(|| ParseError {
            span: start,
            message: "session block missing `flow`".into(),
        })?;
        let expect = expect.ok_or_else(|| ParseError {
            span: start,
            message: "session block missing `expect`".into(),
        })?;
        Ok(SessionBlock {
            name,
            resumes,
            version,
            force_resume: force_resume.unwrap_or(false),
            flow,
            expect,
            asserts,
            span: start.join(end),
        })
    }

    /// Parse `psk { identity: "...", secret: "hex...", offer { ... }, ... }`.
    fn parse_psk_block(&mut self) -> Result<PskBlock, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // psk
        self.expect(&Tok::LBrace, "`{` after `psk`")?;
        self.skip_newlines();
        let mut identity: Option<StrLit> = None;
        let mut secret: Option<Vec<u8>> = None;
        let mut offers = Vec::new();
        let mut seen_fields = std::collections::HashSet::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            let field = self.expect_ident()?;
            if field.name == "offer" {
                offers.push(self.parse_psk_offer(field.span)?);
                self.expect_newline_or_rbrace()?;
                continue;
            }
            check_unique_field(&mut seen_fields, &field, "psk")?;
            self.expect(&Tok::Colon, "`:` after field name")?;
            match field.name.as_str() {
                "identity" => {
                    let s = match self.peek().cloned() {
                        Some(Token {
                            tok: Tok::Str(s),
                            span,
                        }) => {
                            self.bump();
                            StrLit { value: s, span }
                        }
                        _ => {
                            return Err(ParseError {
                                span: field.span,
                                message: "psk identity must be a quoted string".into(),
                            });
                        }
                    };
                    identity = Some(s);
                }
                "secret" => {
                    secret = Some(self.parse_psk_secret("psk secret")?);
                }
                other => {
                    return Err(ParseError {
                        span: field.span,
                        message: format!(
                            "unknown psk field `{}`; expected `identity`, `secret`, or `offer {{ ... }}`",
                            other
                        ),
                    });
                }
            }
            self.expect_newline_or_rbrace()?;
        }
        let end = self.expect(&Tok::RBrace, "`}` closing psk")?;
        let identity = identity.ok_or_else(|| ParseError {
            span: start,
            message: "psk block missing `identity` field".into(),
        })?;
        let secret = secret.ok_or_else(|| ParseError {
            span: start,
            message: "psk block missing `secret` field".into(),
        })?;
        Ok(PskBlock {
            identity,
            secret,
            offers,
            span: start.join(end),
        })
    }

    fn parse_psk_offer(&mut self, start: Span) -> Result<crate::ast::PskOffer, ParseError> {
        self.expect(&Tok::LBrace, "`{` after `offer`")?;
        self.skip_newlines();
        let mut identity = None;
        let mut secret = None;
        let mut hash = None;
        let mut seen_fields = std::collections::HashSet::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            let field = self.expect_ident()?;
            self.expect(&Tok::Colon, "`:` after PSK offer field name")?;
            check_unique_field(&mut seen_fields, &field, "PSK offer")?;
            match field.name.as_str() {
                "identity" => identity = Some(self.expect_str()?),
                "secret" => secret = Some(self.parse_psk_secret("PSK offer secret")?),
                "hash" => {
                    let value = self.expect_ident()?;
                    if value.name != "sha256" && value.name != "sha384" {
                        return Err(ParseError {
                            span: value.span,
                            message: "PSK offer hash must be `sha256` or `sha384`".into(),
                        });
                    }
                    hash = Some(value);
                }
                other => {
                    return Err(ParseError {
                        span: field.span,
                        message: format!(
                            "unknown PSK offer field `{}`; expected `identity`, `secret`, or `hash`",
                            other
                        ),
                    });
                }
            }
            self.expect_newline_or_rbrace()?;
        }
        let end = self.expect(&Tok::RBrace, "`}` closing PSK offer")?;
        Ok(crate::ast::PskOffer {
            identity: identity.ok_or_else(|| ParseError {
                span: start,
                message: "PSK offer missing `identity` field".into(),
            })?,
            secret: secret.ok_or_else(|| ParseError {
                span: start,
                message: "PSK offer missing `secret` field".into(),
            })?,
            hash: hash.unwrap_or(Ident {
                name: "sha256".into(),
                span: start,
            }),
            span: start.join(end),
        })
    }

    fn parse_psk_secret(&mut self, description: &str) -> Result<Vec<u8>, ParseError> {
        let value = self.expect_str().map_err(|mut error| {
            error.message = format!("{} must be a quoted hex string", description);
            error
        })?;
        let hex: String = value.value.chars().filter(|c| !c.is_whitespace()).collect();
        if hex.is_empty() || !hex.len().is_multiple_of(2) {
            return Err(ParseError {
                span: value.span,
                message: format!(
                    "{} hex string must contain a non-empty even number of digits",
                    description
                ),
            });
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ParseError {
                span: value.span,
                message: format!("{} contains an invalid hex digit", description),
            })
    }

    /// Parse `uut server { versions: [tls12], cipher_suites: [0x1301], ... }` — the
    /// unit-under-test's policy. See ast::UutBlock.
    fn parse_uut_block(&mut self) -> Result<crate::ast::UutBlock, ParseError> {
        use crate::ast::{UutBlock, UutRole};
        let start = self.peek().unwrap().span;
        self.bump(); // uut
        let role_ident = self.expect_ident().map_err(|_| ParseError {
            span: self.peek().map_or(start, |token| token.span),
            message: "expected `client` or `server` after `uut`".into(),
        })?;
        let role = match role_ident.name.as_str() {
            "client" => UutRole::Client,
            "server" => UutRole::Server,
            other => {
                return Err(ParseError {
                    span: role_ident.span,
                    message: format!(
                        "expected `client` or `server` after `uut`, found `{}`",
                        other
                    ),
                });
            }
        };
        self.expect(&Tok::LBrace, "`{` after `uut client|server`")?;
        self.skip_newlines();
        let mut block = UutBlock {
            role,
            versions: Vec::new(),
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            require_client_cert: false,
            request_client_cert: false,
            verify_peer: false,
            alpn_advertise: Vec::new(),
            alpn_select: None,
            alpn_select_from: Vec::new(),
            expect_alpn: None,
            alpn_decline: false,
            srtp_profiles: Vec::new(),
            expect_srtp_profile: None,
            signing_prefs: Vec::new(),
            verify_prefs: Vec::new(),
            server_preference: None,
            renegotiation: None,
            session_tickets: None,
            max_early_data: None,
            max_cert_list: None,
            record_size_limit: None,
            records_per_traffic_key: None,
            key_update: false,
            extended_master_secret: None,
            encrypt_then_mac: None,
            middlebox_compat: None,
            compress_certificate: false,
            raw_public_key: false,
            server_certificate_types: Vec::new(),
            client_certificate_types: Vec::new(),
            mtu: None,
            initial_timeout_ms: None,
            dtls_max_retransmissions: None,
            dtls_max_timeout_ms: None,
            dtls_require_cookie: None,
            dtls_epoch0_restart: None,
            dtls_max_hello_verify_requests: None,
            numeric_literals: Vec::new(),
            min_key_update_interval_ms: None,
            psk_secret: None,
            psk_identity: None,
            client_cert: None,
            renegotiate_after_handshake: false,
            hello_request_after_app_data: false,
            require_client_cert_on_renegotiation: false,
            half_rtt_data: Vec::new(),
            ocsp_stapling: false,
            post_handshake_auth: None,
            span: start,
        };
        let mut seen_fields = std::collections::HashSet::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            let field = self.expect_ident()?;
            self.expect(&Tok::Colon, "`:` after uut field name")?;
            check_unique_field(&mut seen_fields, &field, "uut")?;
            match field.name.as_str() {
                "versions" => block.versions = self.parse_uut_version_list()?,
                "capabilities" => {
                    return Err(ParseError {
                        span: field.span,
                        message: "`capabilities` shapes plzn's endpoint; move it to `peer { capabilities: [...] }`".into(),
                    });
                }
                "cipher_suites" => {
                    block.cipher_suites = self.parse_uut_suite_list(&mut block.numeric_literals)?
                }
                "curves" => {
                    block.curves = self.parse_uut_group_list(&mut block.numeric_literals)?
                }
                "require_client_cert" => block.require_client_cert = self.parse_bool()?,
                "request_client_cert" => block.request_client_cert = self.parse_bool()?,
                "verify_peer" => block.verify_peer = self.parse_bool()?,
                "alpn_advertise" => {
                    block.alpn_advertise = self.parse_uut_str_list("alpn_advertise")?
                }
                "alpn_decline" => block.alpn_decline = self.parse_bool()?,
                "alpn_select" => block.alpn_select = Some(self.expect_str()?.value),
                "alpn_select_from" => {
                    block.alpn_select_from = self.parse_uut_str_list("alpn_select_from")?
                }
                "expect_alpn" => block.expect_alpn = Some(self.expect_str()?.value),
                "srtp_profiles" => block.srtp_profiles = self.parse_uut_srtp_list()?,
                "expect_srtp_profile" => {
                    block.expect_srtp_profile = Some(self.parse_uut_srtp_profile()?)
                }
                "signing_prefs" => {
                    block.signing_prefs = self.parse_uut_sigalg_list(&mut block.numeric_literals)?
                }
                "verify_prefs" => {
                    block.verify_prefs = self.parse_uut_sigalg_list(&mut block.numeric_literals)?
                }
                "server_preference" => block.server_preference = Some(self.parse_bool()?),
                "encrypt_then_mac" => block.encrypt_then_mac = Some(self.parse_bool()?),
                "middlebox_compat" => block.middlebox_compat = Some(self.parse_bool()?),
                "compress_certificate" => block.compress_certificate = self.parse_bool()?,
                "raw_public_key" => block.raw_public_key = self.parse_bool()?,
                "server_certificate_types" => {
                    block.server_certificate_types =
                        self.parse_uut_ident_list("server_certificate_types")?
                }
                "client_certificate_types" => {
                    block.client_certificate_types =
                        self.parse_uut_ident_list("client_certificate_types")?
                }
                "renegotiation" => {
                    block.renegotiation =
                        Some(self.parse_uut_choice(
                            "renegotiation",
                            &["none", "client", "server", "both"],
                        )?)
                }
                "extended_master_secret" => {
                    block.extended_master_secret =
                        Some(self.parse_uut_choice(
                            "extended_master_secret",
                            &["require", "allow", "off"],
                        )?)
                }
                "session_tickets" => {
                    block.session_tickets = Some(self.parse_uut_u32("session_tickets")?)
                }
                "max_early_data" => {
                    block.max_early_data = Some(self.parse_uut_u32("max_early_data")?)
                }
                "max_cert_list" => block.max_cert_list = Some(self.parse_uut_u32("max_cert_list")?),
                "record_size_limit" => {
                    let limit = self.parse_uut_u32("record_size_limit")?;
                    if !(64..=16385).contains(&limit) {
                        return Err(ParseError {
                            span: field.span,
                            message: format!(
                                "uut.record_size_limit must be between 64 and 16385, not {}",
                                limit
                            ),
                        });
                    }
                    block.record_size_limit = Some(limit)
                }
                "records_per_traffic_key" => {
                    block.records_per_traffic_key =
                        Some(self.parse_uut_u32("records_per_traffic_key")?)
                }
                "key_update" => block.key_update = self.parse_bool()?,
                "mtu" => block.mtu = Some(self.parse_uut_u32("mtu")?),
                "initial_timeout_ms" => {
                    block.initial_timeout_ms = Some(self.parse_uut_u32("initial_timeout_ms")?)
                }
                "dtls_max_retransmissions" => {
                    block.dtls_max_retransmissions =
                        Some(self.parse_uut_u32("dtls_max_retransmissions")?)
                }
                "dtls_max_timeout_ms" => {
                    block.dtls_max_timeout_ms = Some(self.parse_uut_u32("dtls_max_timeout_ms")?)
                }
                "dtls_require_cookie" => block.dtls_require_cookie = Some(self.parse_bool()?),
                "dtls_epoch0_restart" => block.dtls_epoch0_restart = Some(self.parse_bool()?),
                "dtls_max_hello_verify_requests" => {
                    block.dtls_max_hello_verify_requests =
                        Some(self.parse_uut_u32("dtls_max_hello_verify_requests")?)
                }
                "min_key_update_interval_ms" => {
                    block.min_key_update_interval_ms =
                        Some(self.parse_uut_u32("min_key_update_interval_ms")?)
                }
                "psk_secret" => block.psk_secret = Some(self.parse_uut_hex_str("psk_secret")?),
                "psk_identity" => block.psk_identity = Some(self.expect_str()?.value),
                "client_cert" => {
                    block.client_cert = Some(self.parse_uut_choice(
                        "client_cert",
                        &["valid", "untrusted", "none", "expired"],
                    )?)
                }
                "renegotiate_after_handshake" => {
                    block.renegotiate_after_handshake = self.parse_bool()?
                }
                "hello_request_after_app_data" => {
                    block.hello_request_after_app_data = self.parse_bool()?
                }
                "require_client_cert_on_renegotiation" => {
                    block.require_client_cert_on_renegotiation = self.parse_bool()?
                }
                "half_rtt_data" => {
                    block.half_rtt_data = self.parse_uut_str_list("half_rtt_data")?
                }
                // T6:
                "ocsp_stapling" => block.ocsp_stapling = self.parse_bool()?,
                "post_handshake_auth" => {
                    block.post_handshake_auth =
                        Some(self.parse_uut_choice("post_handshake_auth", &["request", "require"])?)
                }
                other => {
                    return Err(ParseError {
                        span: field.span,
                        message: format!(
                            "unknown uut field `{}`; expected versions, \
                             cipher_suites, curves, signing_prefs, verify_prefs, \
                             require_client_cert, request_client_cert, verify_peer, \
                             alpn_advertise, alpn_select, alpn_select_from, expect_alpn, alpn_decline, \
                             srtp_profiles, expect_srtp_profile, server_preference, renegotiation, \
                             session_tickets, max_early_data, max_cert_list, record_size_limit, records_per_traffic_key, key_update, extended_master_secret, encrypt_then_mac, \
                             middlebox_compat, compress_certificate, raw_public_key, server_certificate_types, client_certificate_types, mtu, initial_timeout_ms, dtls_max_retransmissions, \
                             dtls_max_timeout_ms, dtls_require_cookie, dtls_epoch0_restart, \
                             dtls_max_hello_verify_requests, \
                             min_key_update_interval_ms, \
                             psk_secret, psk_identity, client_cert, renegotiate_after_handshake, \
                             half_rtt_data, ocsp_stapling, post_handshake_auth, \
                             hello_request_after_app_data, require_client_cert_on_renegotiation",
                            other
                        ),
                    });
                }
            }
            // Accept either newline- or comma-separated fields.
            self.eat(&Tok::Comma);
            self.skip_newlines();
        }
        let end = self.expect(&Tok::RBrace, "`}` closing uut")?;
        block.span = start.join(end);
        Ok(block)
    }

    /// Configuration owned by plzn's endpoint rather than by the UUT.
    fn parse_peer_block(&mut self) -> Result<crate::ast::PeerBlock, ParseError> {
        use crate::ast::PeerBlock;
        let start = self.peek().unwrap().span;
        self.bump(); // peer
        self.expect(&Tok::LBrace, "`{` after `peer`")?;
        self.skip_newlines();
        let mut block = PeerBlock {
            capabilities: Vec::new(),
            request_client_cert: false,
            span: start,
        };
        let mut seen_fields = std::collections::HashSet::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            let field = self.expect_ident()?;
            self.expect(&Tok::Colon, "`:` after peer field name")?;
            check_unique_field(&mut seen_fields, &field, "peer")?;
            match field.name.as_str() {
                "capabilities" => block.capabilities = self.parse_uut_ident_list("capabilities")?,
                "request_client_cert" => block.request_client_cert = self.parse_bool()?,
                other => {
                    return Err(ParseError {
                        span: field.span,
                        message: format!(
                            "unknown peer field `{}`; expected capabilities, request_client_cert",
                            other
                        ),
                    });
                }
            }
            self.eat(&Tok::Comma);
            self.skip_newlines();
        }
        let end = self.expect(&Tok::RBrace, "`}` closing peer")?;
        block.span = start.join(end);
        Ok(block)
    }

    /// A quoted hex string (`psk_secret: "0a0b"`), returned normalised
    /// (lower-case, no whitespace); it must decode to at least one byte.
    fn parse_uut_hex_str(&mut self, field: &str) -> Result<String, ParseError> {
        let s = self.expect_str()?;
        let hex: String = s
            .value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase();
        let valid = !hex.is_empty()
            && hex.len().is_multiple_of(2)
            && hex.chars().all(|c| c.is_ascii_hexdigit());
        if !valid {
            return Err(ParseError {
                span: s.span,
                message: format!(
                    "uut.{} must be a quoted hex string with an even number of digits",
                    field
                ),
            });
        }
        Ok(hex)
    }

    /// A bracketed list of quoted strings (`half_rtt_data: ["h", "r"]`).
    fn parse_uut_str_list(&mut self, field: &str) -> Result<Vec<String>, ParseError> {
        self.expect(&Tok::LBracket, &format!("`[` after `{}:`", field))?;
        let mut out = Vec::new();
        loop {
            self.skip_newlines();
            if self.eat(&Tok::RBracket) {
                break;
            }
            out.push(self.expect_str()?.value);
            self.skip_newlines();
            if !self.eat(&Tok::Comma) {
                self.expect(&Tok::RBracket, &format!("`]` closing `{}`", field))?;
                break;
            }
        }
        Ok(out)
    }

    /// One of a fixed set of bare names (`renegotiation: none`).
    fn parse_uut_choice(&mut self, field: &str, allowed: &[&str]) -> Result<String, ParseError> {
        let id = self.expect_ident()?;
        if allowed.contains(&id.name.as_str()) {
            Ok(id.name)
        } else {
            Err(ParseError {
                span: id.span,
                message: format!(
                    "`{}` takes one of {}, not `{}`",
                    field,
                    allowed
                        .iter()
                        .map(|a| format!("`{}`", a))
                        .collect::<Vec<_>>()
                        .join(", "),
                    id.name
                ),
            })
        }
    }

    /// A non-negative integer that fits in u32.
    fn parse_uut_u32(&mut self, field: &str) -> Result<u32, ParseError> {
        let n = self.expect_int()?;
        if (0..=u32::MAX as i64).contains(&n.value) {
            Ok(n.value as u32)
        } else {
            Err(ParseError {
                span: n.span,
                message: format!("`{}` must be 0..=4294967295, not {}", field, n.value),
            })
        }
    }

    /// `[rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256]` or raw wire values.
    fn parse_uut_sigalg_list(
        &mut self,
        literals: &mut Vec<(crate::schema::NameDomain, IntLit)>,
    ) -> Result<Vec<u16>, ParseError> {
        self.expect(&Tok::LBracket, "`[`")?;
        self.skip_newlines();
        let mut out = Vec::new();
        while !self.at(&Tok::RBracket) {
            match self.peek().cloned() {
                Some(Token {
                    tok: Tok::Ident(name),
                    span,
                }) => {
                    self.bump();
                    match crate::schema::sigalg_wire_value(&name) {
                        Some(w) => out.push(w),
                        None => {
                            return Err(ParseError {
                                span,
                                message: format!(
                                    "unknown signature scheme `{}`; try rsa_pss_rsae_sha256, \
                                     ecdsa_secp256r1_sha256, rsa_pkcs1_sha256",
                                    name
                                ),
                            });
                        }
                    }
                }
                _ => {
                    let n = self.expect_int()?;
                    if !(0..=0xffff).contains(&n.value) {
                        return Err(ParseError {
                            span: n.span,
                            message: format!(
                                "signature scheme {} out of range (0..0xffff)",
                                n.value
                            ),
                        });
                    }
                    literals.push((crate::schema::NameDomain::Sigalg, n));
                    out.push(n.value as u16);
                }
            }
            self.skip_newlines();
            if !self.eat(&Tok::Comma) {
                break;
            }
            self.skip_newlines();
        }
        self.expect(&Tok::RBracket, "`]`")?;
        Ok(out)
    }

    fn parse_uut_srtp_profile(&mut self) -> Result<u16, ParseError> {
        if let Some(Token {
            tok: Tok::Ident(name),
            span,
        }) = self.peek().cloned()
        {
            self.bump();
            return crate::schema::srtp_profile_value(&name).ok_or_else(|| ParseError {
                span,
                message: format!("unknown SRTP protection profile `{}`", name),
            });
        }
        let n = self.expect_int()?;
        if !(0..=0xffff).contains(&n.value) {
            return Err(ParseError {
                span: n.span,
                message: format!(
                    "SRTP protection profile {} out of range (0..0xffff)",
                    n.value
                ),
            });
        }
        Ok(n.value as u16)
    }

    fn parse_uut_srtp_list(&mut self) -> Result<Vec<u16>, ParseError> {
        self.expect(&Tok::LBracket, "`[` starting SRTP profile list")?;
        self.skip_newlines();
        let mut out = Vec::new();
        while !self.at(&Tok::RBracket) {
            out.push(self.parse_uut_srtp_profile()?);
            self.skip_newlines();
            if !self.eat(&Tok::Comma) {
                break;
            }
            self.skip_newlines();
        }
        self.expect(&Tok::RBracket, "`]` closing SRTP profile list")?;
        Ok(out)
    }

    /// Parse a list of symbolic identifiers. Semantic validation belongs to
    /// the checker so misspellings receive the usual suggestions.
    fn parse_uut_ident_list(&mut self, field: &str) -> Result<Vec<Ident>, ParseError> {
        self.expect(&Tok::LBracket, &format!("`[` starting {} list", field))?;
        self.skip_newlines();
        let mut out = Vec::new();
        if !self.at(&Tok::RBracket) {
            loop {
                out.push(self.expect_ident()?);
                self.skip_newlines();
                if self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    continue;
                }
                break;
            }
        }
        self.expect(&Tok::RBracket, &format!("`]` closing {} list", field))?;
        Ok(out)
    }

    /// Parse `[tls12, $version]`. Matrix variables are resolved after matrix
    /// expansion, just like the numeric UUT selector fields.
    fn parse_uut_version_list(&mut self) -> Result<Vec<crate::ast::VersionRef>, ParseError> {
        use crate::ast::VersionRef;
        self.expect(&Tok::LBracket, "`[` starting versions list")?;
        self.skip_newlines();
        let mut out = Vec::new();
        if !self.at(&Tok::RBracket) {
            loop {
                let is_var = self.eat(&Tok::Dollar);
                let id = self.expect_ident()?;
                out.push(if is_var {
                    VersionRef::Var(id)
                } else {
                    VersionRef::Name(id)
                });
                self.skip_newlines();
                if self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    continue;
                }
                break;
            }
        }
        self.expect(&Tok::RBracket, "`]` closing versions list")?;
        Ok(out)
    }

    /// Parse `true` / `false`.
    fn parse_bool(&mut self) -> Result<bool, ParseError> {
        let id = self.expect_ident()?;
        match id.name.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(ParseError {
                span: id.span,
                message: format!("expected `true` or `false`, got `{}`", other),
            }),
        }
    }

    /// Parse `[0xc02b, $suite, ...]`: integers or matrix variables, resolved
    /// per matrix point at lowering.
    /// D: `uut client|server { cipher_suites: [AES_128_GCM_SHA256, 0x0a0a, $suite] }` --
    /// suite names (resolved here), numbers (recorded for the named-constant
    /// lint) or matrix variables.
    fn parse_uut_suite_list(
        &mut self,
        literals: &mut Vec<(crate::schema::NameDomain, IntLit)>,
    ) -> Result<Vec<IntOrVar>, ParseError> {
        self.expect(&Tok::LBracket, "`[` starting list")?;
        let mut out = Vec::new();
        self.skip_newlines();
        if !self.at(&Tok::RBracket) {
            loop {
                if let Some(Token {
                    tok: Tok::Ident(name),
                    span,
                }) = self.peek().cloned()
                {
                    match crate::schema::suite_wire_value(&name) {
                        Some(w) => {
                            self.bump();
                            out.push(IntOrVar::Int(IntLit {
                                value: i64::from(w),
                                span,
                            }));
                        }
                        None => {
                            return Err(ParseError {
                                span,
                                message: format!(
                                    "unknown cipher suite `{}` (see `plzn names`)",
                                    name
                                ),
                            });
                        }
                    }
                } else {
                    let v = self.parse_int_or_var()?;
                    if let IntOrVar::Int(lit) = &v {
                        literals.push((crate::schema::NameDomain::Suite, *lit));
                    }
                    out.push(v);
                }
                self.skip_newlines();
                if self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    continue;
                }
                break;
            }
        }
        self.expect(&Tok::RBracket, "`]` closing list")?;
        Ok(out)
    }

    /// Parse a curve list: `[secp256r1, 0x001d, $group, ...]` — named groups,
    /// raw wire codes, or matrix variables resolved per point at lowering.
    fn parse_uut_group_list(
        &mut self,
        literals: &mut Vec<(crate::schema::NameDomain, IntLit)>,
    ) -> Result<Vec<IntOrVar>, ParseError> {
        self.expect(&Tok::LBracket, "`[` starting curve list")?;
        let mut out = Vec::new();
        self.skip_newlines();
        if !self.at(&Tok::RBracket) {
            loop {
                if let Some(Token {
                    tok: Tok::Ident(name),
                    span,
                }) = self.peek().cloned()
                {
                    match crate::schema::group_wire_value(&name) {
                        Some(code) => {
                            self.bump();
                            out.push(IntOrVar::Int(IntLit {
                                value: i64::from(code),
                                span,
                            }));
                        }
                        None => {
                            return Err(ParseError {
                                span,
                                message: format!("unknown group `{}`", name),
                            });
                        }
                    }
                } else {
                    let value = self.parse_int_or_var()?;
                    if let IntOrVar::Int(lit) = &value {
                        literals.push((crate::schema::NameDomain::Group, *lit));
                    }
                    out.push(value);
                }
                self.skip_newlines();
                if self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    continue;
                }
                break;
            }
        }
        self.expect(&Tok::RBracket, "`]` closing curve list")?;
        Ok(out)
    }

    fn parse_flow(&mut self) -> Result<Flow, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // flow
        let preset = if self.at_ident("handshake") {
            let base = self.expect_ident()?;
            let mut anchor = None;
            let mut end = base.span;
            if self.at_ident("until") || self.at_ident("after") {
                let when_id = self.expect_ident()?;
                let when = match when_id.name.as_str() {
                    "until" => AnchorWhen::Until,
                    "after" => AnchorWhen::After,
                    _ => unreachable!(),
                };
                let verb_id = self.expect_ident()?;
                let verb = match verb_id.name.as_str() {
                    "send" => AnchorVerb::Send,
                    "recv" => AnchorVerb::Recv,
                    other => {
                        return Err(ParseError {
                            span: verb_id.span,
                            message: format!("expected `send` or `recv`, found `{}`", other),
                        });
                    }
                };
                let msg = self.expect_ident()?;
                end = msg.span;
                anchor = Some(FlowAnchor {
                    when,
                    verb,
                    msg,
                    span: when_id.span.join(end),
                });
            }
            Some(FlowPreset {
                base: base.clone(),
                anchor,
                span: base.span.join(end),
            })
        } else {
            None
        };
        self.expect(&Tok::LBrace, "`{` to open flow body")?;
        self.skip_newlines();

        let mut steps = Vec::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            if self.at_ident("coalesce") || self.at_ident("atomic") {
                self.parse_coalesce_block(&mut steps)?;
                continue;
            }
            steps.push(self.parse_step()?);
        }
        let end = self.expect(&Tok::RBrace, "`}` closing flow")?;
        let steps = expand_repeats(steps);
        Ok(Flow {
            preset,
            steps,
            span: start.join(end),
        })
    }

    /// `coalesce [hold_keys] { step* }` / `atomic { step* }`: the block's steps
    /// are emitted flat between a Begin and an End marker. Blocks do not nest.
    fn parse_coalesce_block(&mut self, steps: &mut Vec<Step>) -> Result<(), ParseError> {
        let start = self.peek().unwrap().span;
        let kw = self.expect_ident()?; // coalesce | atomic
        let atomic = kw.name == "atomic";
        let mode = if !atomic && self.at_ident("hold_keys") {
            self.bump();
            crate::ir::CoalesceMode::HoldKeys
        } else if !atomic && self.at_ident("old_keys") {
            self.bump();
            crate::ir::CoalesceMode::OldKeys
        } else {
            crate::ir::CoalesceMode::Flush
        };
        self.expect(&Tok::LBrace, &format!("`{{` to open {} block", kw.name))?;
        if atomic {
            steps.push(Step::AtomicBegin { span: start });
        } else {
            steps.push(Step::CoalesceBegin { mode, span: start });
        }
        self.skip_newlines();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Newline) {
                continue;
            }
            if self.at_ident("coalesce") || self.at_ident("atomic") {
                return Err(ParseError {
                    span: self.peek().unwrap().span,
                    message: "`coalesce` blocks do not nest (nor `atomic` ones)".into(),
                });
            }
            steps.push(self.parse_step()?);
        }
        let end = self.expect(&Tok::RBrace, &format!("`}}` closing {} block", kw.name))?;
        self.expect_newline_or_rbrace()?;
        if atomic {
            steps.push(Step::AtomicEnd {
                span: start.join(end),
            });
        } else {
            steps.push(Step::CoalesceEnd {
                span: start.join(end),
            });
        }
        Ok(())
    }

    fn parse_step(&mut self) -> Result<Step, ParseError> {
        if self.at_ident("repeat") {
            return self.parse_repeat_block();
        }
        if self.at_ident("flush_fragment") {
            let span = self.peek().unwrap().span;
            self.bump();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::FlushFragment { span });
        }
        if self.at_ident("send") {
            return self.parse_send_step();
        }
        if self.at_ident("recv") {
            return self.parse_recv_step();
        }
        if self.at_ident("close") {
            return self.parse_close_step();
        }
        if self.at_ident("wait") {
            return self.parse_wait_step();
        }
        if self.at_ident("advance_clock") {
            return self.parse_advance_clock_step();
        }
        if self.at_ident("expect") {
            return self.parse_dtls_timeout_expect_step();
        }
        if self.at_ident("set_timeout") {
            return self.parse_set_timeout_step();
        }
        if self.at_ident("rotate_cookie_secret") {
            let span = self.peek().unwrap().span;
            self.bump();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::RotateCookieSecret { span });
        }
        if self.at_ident("expect_retransmit") {
            let span = self.peek().unwrap().span;
            self.bump();
            // `expect_retransmit no_ccs`: the resent flight must carry no
            // ChangeCipherSpec (a renegotiation ClientHello retransmit).
            if self.at_ident("no_ccs") {
                let flag = self.expect_ident()?;
                self.expect_newline_or_rbrace()?;
                return Ok(Step::Dtls {
                    op: crate::ir::DtlsOp::ExpectRetransmitNoCcs,
                    span: span.join(flag.span),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::ExpectRetransmit { span });
        }
        if self.at_ident("resend_flight") {
            let span = self.peek().unwrap().span;
            self.bump();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::ResendFlight { span });
        }
        if self.at_ident("renegotiate") {
            // T5: `renegotiate [resumed] [insecure] [{ ClientHello overrides + ext deltas }]`.
            let start = self.peek().unwrap().span;
            self.bump();
            let mut resumed = false;
            let mut insecure = false;
            loop {
                if self.at_ident("resumed") && !resumed {
                    resumed = true;
                    self.bump();
                } else if self.at_ident("insecure") && !insecure {
                    insecure = true;
                    self.bump();
                } else {
                    break;
                }
            }
            let (overrides, ext_deltas) = if self.at(&Tok::LBrace) {
                self.parse_send_body()?
            } else {
                (Vec::new(), Vec::new())
            };
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Renegotiate {
                resumed,
                insecure,
                overrides,
                ext_deltas,
                span: start,
            });
        }
        // DTLS flight control (see ir::DtlsOp).
        for (kw, op) in [
            ("discard_flight", crate::ir::DtlsOp::DiscardFlight),
            ("hold_flight", crate::ir::DtlsOp::HoldFlight),
            ("hold_retransmit", crate::ir::DtlsOp::HoldRetransmit),
            ("begin_renegotiation", crate::ir::DtlsOp::BeginRenegotiation),
            ("restart", crate::ir::DtlsOp::Restart),
            ("future_seq_first", crate::ir::DtlsOp::FutureSeqFirst),
        ] {
            if self.at_ident(kw) {
                let span = self.peek().unwrap().span;
                self.bump();
                self.expect_newline_or_rbrace()?;
                return Ok(Step::Dtls { op, span });
            }
        }
        if self.at_ident("interleave_flight") {
            let start = self.peek().unwrap().span;
            self.bump();
            let split = if self.at_ident("split") {
                self.bump();
                true
            } else {
                false
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::InterleaveFlight { split },
                span: start.join(end),
            });
        }
        if self.at_ident("retransmit_flight") {
            let start = self.peek().unwrap().span;
            self.bump();
            let order = if self.at_ident("split") {
                self.bump();
                Some(self.parse_record_index_list()?)
            } else {
                None
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::RetransmitFlight { order },
                span: start.join(end),
            });
        }
        if self.at_ident("release_flight") {
            let start = self.peek().unwrap().span;
            self.bump();
            let records = if self.at(&Tok::LBracket) {
                Some(self.parse_record_index_list()?)
            } else {
                None
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::ReleaseFlight { records },
                span: start.join(end),
            });
        }
        if self.at_ident("replay_flight") {
            let start = self.peek().unwrap().span;
            self.bump();
            let n = self.expect_int()?;
            if n.value < 1 {
                return Err(ParseError {
                    span: n.span,
                    message: "replay_flight takes a 1-based flight number".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::ReplayFlight(n.value as usize),
                span: start.join(n.span),
            });
        }
        if self.at_ident("map_record_sequences") {
            let start = self.peek().unwrap().span;
            self.bump();
            let mode = self.expect_ident()?;
            let map = match mode.name.as_str() {
                "identity" => crate::ir::DtlsSequenceMap::Identity,
                "multiply" | "xor" => {
                    let n = self.expect_int()?;
                    if n.value < 0 {
                        return Err(ParseError {
                            span: n.span,
                            message: "record sequence mappings require a non-negative operand"
                                .into(),
                        });
                    }
                    if mode.name == "multiply" {
                        crate::ir::DtlsSequenceMap::Multiply(n.value as u64)
                    } else {
                        crate::ir::DtlsSequenceMap::Xor(n.value as u64)
                    }
                }
                other => {
                    return Err(ParseError {
                        span: mode.span,
                        message: format!(
                            "expected `identity`, `multiply N`, or `xor N` after `map_record_sequences`, found `{}`",
                            other
                        ),
                    });
                }
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::MapRecordSequences(map),
                span: start.join(end),
            });
        }
        if self.at_ident("set_mtu") {
            let start = self.peek().unwrap().span;
            self.bump();
            let mtu = self.expect_int()?;
            if !(1..=u32::MAX as i64).contains(&mtu.value) {
                return Err(ParseError {
                    span: mtu.span,
                    message: "set_mtu requires a value in 1..=4294967295".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::SetMtu(mtu.value as u32),
                span: start.join(mtu.span),
            });
        }
        if self.at_ident("suppress_ack") {
            let span = self.peek().unwrap().span;
            self.bump();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::SuppressAck,
                span,
            });
        }
        if self.at_ident("expect_ack") {
            let span = self.peek().unwrap().span;
            self.bump();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::ExpectAck,
                span,
            });
        }
        if self.at_ident("send_previous_epoch") {
            let start = self.peek().unwrap().span;
            self.bump();
            let message = self.expect_ident()?;
            if message.name != "Finished" {
                return Err(ParseError {
                    span: message.span,
                    message: "send_previous_epoch currently supports only Finished".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::SendPreviousEpochFinished,
                span: start.join(message.span),
            });
        }
        if self.at_ident("retransmit_previous_epoch") {
            let start = self.peek().unwrap().span;
            self.bump();
            let message = self.expect_ident()?;
            if message.name != "Finished" {
                return Err(ParseError {
                    span: message.span,
                    message: "retransmit_previous_epoch currently supports only Finished".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::RetransmitPreviousEpochFinished,
                span: start.join(message.span),
            });
        }
        if self.at_ident("send_ack") {
            let start = self.peek().unwrap().span;
            self.bump();
            let selection = self.expect_ident()?;
            let selection = match selection.name.as_str() {
                "all" => crate::ir::DtlsAckSelection::All,
                "first" => crate::ir::DtlsAckSelection::First,
                "last" => crate::ir::DtlsAckSelection::Last,
                "even" => crate::ir::DtlsAckSelection::Even,
                "odd" => crate::ir::DtlsAckSelection::Odd,
                other => {
                    return Err(ParseError {
                        span: selection.span,
                        message: format!(
                            "send_ack selection must be all, first, last, even, or odd, found `{}`",
                            other
                        ),
                    });
                }
            };
            let outer_epoch = if self.at_ident("outer_epoch") {
                self.bump();
                let epoch = self.expect_int()?;
                if !(0..=u16::MAX as i64).contains(&epoch.value) {
                    return Err(ParseError {
                        span: epoch.span,
                        message: "ACK outer_epoch must fit in u16".into(),
                    });
                }
                Some(epoch.value as u16)
            } else {
                None
            };
            let overflow_epoch = if self.at_ident("overflow_epoch") {
                self.bump();
                true
            } else {
                false
            };
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::SendAck {
                    selection,
                    outer_epoch,
                    overflow_epoch,
                },
                span: start.join(end),
            });
        }
        if self.at_ident("header_only_flood") {
            let start = self.peek().unwrap().span;
            self.bump();
            let n = self.expect_int()?;
            if n.value < 1 {
                return Err(ParseError {
                    span: n.span,
                    message: "header_only_flood takes a count >= 1".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::HeaderOnlyFlood {
                    count: n.value as usize,
                },
                span: start.join(n.span),
            });
        }
        if self.at_ident("large_length_fragment") {
            let start = self.peek().unwrap().span;
            self.bump();
            let n = self.expect_int()?;
            if n.value < 1 || n.value > 0xff_ffff {
                return Err(ParseError {
                    span: n.span,
                    message: "large_length_fragment takes a 24-bit length in 1..=16777215".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::LargeLengthFragment {
                    length: n.value as u32,
                },
                span: start.join(n.span),
            });
        }
        if self.at_ident("hvr_flood") {
            let start = self.peek().unwrap().span;
            self.bump();
            let count = self.expect_int()?;
            let kw = self.expect_ident()?;
            if kw.name != "max_answers" {
                return Err(ParseError {
                    span: kw.span,
                    message: format!(
                        "expected `max_answers` after the hvr_flood count, found `{}`",
                        kw.name
                    ),
                });
            }
            let max = self.expect_int()?;
            if count.value < 1 || max.value < 0 {
                return Err(ParseError {
                    span: start.join(max.span),
                    message: "hvr_flood N max_answers M needs N >= 1, M >= 0".into(),
                });
            }
            self.expect_newline_or_rbrace()?;
            return Ok(Step::Dtls {
                op: crate::ir::DtlsOp::HvrFlood {
                    count: count.value as usize,
                    max_answers: max.value as usize,
                },
                span: start.join(max.span),
            });
        }
        let t = self.peek().cloned();
        Err(ParseError {
            span: t.as_ref().map(|t| t.span).unwrap_or(Span::dummy()),
            message: format!(
                "expected `send`, `recv`, `close`, `wait`, `repeat N {{ ... }}`, `advance_clock`, `expect next_timeout`, `expect no_timeout`, `set_timeout`, `expect_retransmit`, `resend_flight`, `rotate_cookie_secret`, `renegotiate`, `coalesce {{ ... }}`, `atomic {{ ... }}`, `flush_fragment`, a DTLS flight step (`discard_flight`, `retransmit_flight`, `hold_flight`, `hold_retransmit`, `release_flight`, `replay_flight N`, `interleave_flight [split]`, `begin_renegotiation`, `restart`, `hvr_flood`), found {}",
                t.as_ref()
                    .map(|t| describe_tok(&t.tok))
                    .unwrap_or_else(|| "end of file".into())
            ),
        })
    }

    /// `[0, 2, 1]`: record indices of a DTLS flight.
    fn parse_record_index_list(&mut self) -> Result<Vec<usize>, ParseError> {
        self.expect(&Tok::LBracket, "`[` opening the record index list")?;
        let mut idx = Vec::new();
        while !self.at(&Tok::RBracket) {
            let n = self.expect_int()?;
            if n.value < 0 {
                return Err(ParseError {
                    span: n.span,
                    message: "record index must be non-negative".into(),
                });
            }
            idx.push(n.value as usize);
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        self.expect(&Tok::RBracket, "`]` closing the record index list")?;
        Ok(idx)
    }

    fn parse_advance_clock_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // "advance_clock"
        let (nanos, end) = self.parse_dtls_duration("advance_clock")?;
        self.expect_newline_or_rbrace()?;
        Ok(Step::AdvanceClock {
            nanos,
            span: start.join(end),
        })
    }

    fn parse_dtls_timeout_expect_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // "expect"
        let kind = self.expect_ident()?;
        match kind.name.as_str() {
            "next_timeout" => {
                let (nanos, end) = self.parse_dtls_duration("expect next_timeout")?;
                self.expect_newline_or_rbrace()?;
                Ok(Step::ExpectNextTimeout {
                    nanos,
                    span: start.join(end),
                })
            }
            "no_timeout" => {
                self.expect_newline_or_rbrace()?;
                Ok(Step::ExpectNoTimeout {
                    span: start.join(kind.span),
                })
            }
            other => Err(ParseError {
                span: kind.span,
                message: format!(
                    "inside a flow, `expect` must be followed by `next_timeout` or `no_timeout`, found `{}`",
                    other
                ),
            }),
        }
    }

    fn parse_set_timeout_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // "set_timeout"
        let (nanos, end) = self.parse_dtls_duration("set_timeout")?;
        if nanos % 1_000_000 != 0 || nanos / 1_000_000 > u64::from(u32::MAX) {
            return Err(ParseError {
                span: start.join(end),
                message: "set_timeout must be a whole number of milliseconds in the u32 range"
                    .into(),
            });
        }
        self.expect_newline_or_rbrace()?;
        Ok(Step::SetTimeout {
            millis: (nanos / 1_000_000) as u32,
            span: start.join(end),
        })
    }

    /// Parse an integer duration used by DTLS timer controls. The wire protocol
    /// is nanoseconds; live timeout updates are narrowed to milliseconds by the
    /// caller because that is the library API shared by the shims.
    fn parse_dtls_duration(&mut self, context: &str) -> Result<(u64, Span), ParseError> {
        let n = self.expect_int()?;
        if n.value < 0 {
            return Err(ParseError {
                span: n.span,
                message: format!("{} duration must be non-negative", context),
            });
        }
        let unit = self.expect_ident()?;
        let nanos = match unit.name.as_str() {
            "ns" => n.value as u64,
            "us" => (n.value as u64).saturating_mul(1_000),
            "ms" => (n.value as u64).saturating_mul(1_000_000),
            "s" => (n.value as u64).saturating_mul(1_000_000_000),
            other => {
                return Err(ParseError {
                    span: unit.span,
                    message: format!(
                        "expected `ns`, `us`, `ms`, or `s` unit after {} duration, found `{}`",
                        context, other
                    ),
                });
            }
        };
        Ok((nanos, unit.span))
    }

    fn parse_wait_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // "wait"
        let n = self.expect_int()?;
        // Expect a unit suffix: "ms" is the only one for now.
        let unit = self.expect_ident()?;
        if unit.name != "ms" {
            return Err(ParseError {
                span: unit.span,
                message: format!(
                    "expected `ms` unit after wait duration, found `{}`",
                    unit.name
                ),
            });
        }
        if n.value < 0 {
            return Err(ParseError {
                span: n.span,
                message: "wait duration must be non-negative".into(),
            });
        }
        self.expect_newline_or_rbrace()?;
        Ok(Step::Wait {
            millis: n.value as u64,
            span: start.join(unit.span),
        })
    }

    /// Parse one segment of a `send raw` expression:
    ///   - `"ff0303..."` → hex string
    ///   - `0xDEAD` → short hex integer (up to 8 bytes)
    ///   - `0xff * 256` → byte repeat
    fn parse_raw_segment(&mut self) -> Result<Vec<u8>, ParseError> {
        if let Some(tok) = self.peek() {
            if let Tok::Str(ref s) = tok.tok {
                let s = s.clone();
                let span = tok.span;
                self.bump();
                let hex_str: String = s.chars().filter(|c| !c.is_whitespace()).collect();
                if !hex_str.len().is_multiple_of(2) {
                    return Err(ParseError {
                        span,
                        message: "hex string must have even number of hex digits".into(),
                    });
                }
                let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                    .collect();
                return bytes.map_err(|_| ParseError {
                    span,
                    message: "invalid hex digit in raw string".into(),
                });
            }
        }
        // Integer, possibly with `* count` repeat.
        let n = self.expect_int()?;
        if self.eat(&Tok::Star) {
            let count = self.expect_int()?;
            let c = count.value;
            if !(0..=65536).contains(&c) {
                return Err(ParseError {
                    span: count.span,
                    message: format!("repeat count {} out of range (0..65536)", c),
                });
            }
            return Ok(vec![n.value as u8; c as usize]);
        }
        // Single hex integer → big-endian bytes.
        let mut bytes = Vec::new();
        let mut v = n.value as u64;
        if v == 0 {
            bytes.push(0);
        } else {
            while v > 0 {
                bytes.push((v & 0xff) as u8);
                v >>= 8;
            }
            bytes.reverse();
        }
        Ok(bytes)
    }

    /// Record/alert sends can use byte modifiers, but have no handshake
    /// message to which a dedicated DTLS fragmentation plan could apply.
    fn parse_record_send_suffix(&mut self) -> Result<Vec<Mutation>, ParseError> {
        if !self.at(&Tok::At) {
            return Ok(Vec::new());
        }
        let span = self.peek().unwrap().span;
        let (mutations, fragmentation) = self.parse_send_at_suffix()?;
        if fragmentation.is_some() {
            return Err(ParseError {
                span,
                message: "DTLS handshake fragmentation plans are not supported on `send alert`, `send empty_record`, or `send record`".into(),
            });
        }
        Ok(mutations)
    }

    fn parse_send_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // send
        if self.at_ident("raw") {
            self.bump();
            // Parse one or more segments joined by `+`:
            //   send raw "160303..." + 0xff * 256 + "cafe"
            let mut bytes = self.parse_raw_segment()?;
            while self.eat(&Tok::Plus) {
                bytes.extend(self.parse_raw_segment()?);
            }
            let end_span = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(Step::SendRaw {
                hex: bytes,
                span: start.join(end_span),
            });
        }
        if self.at_ident("alert") {
            // `send alert warning/no_renegotiation`: an alert record, no close.
            self.bump();
            let level = self.expect_ident()?;
            let code = if self.eat(&Tok::Slash) {
                Some(self.expect_ident()?)
            } else {
                None
            };
            let span = match &code {
                Some(c) => level.span.join(c.span),
                None => level.span,
            };
            // T2: `send alert warning/close_notify @ plaintext` (record mutations).
            let mutations = self.parse_record_send_suffix()?;
            self.expect_newline_or_rbrace()?;
            return Ok(Step::SendAlert {
                alert: AlertSpec { level, code, span },
                mutations,
                span: start.join(span),
            });
        }
        if self.at_ident("empty_record") {
            // `send empty_record handshake` / `send empty_record 0x00`: a
            // zero-length record of that (named or numeric) content type.
            self.bump();
            let content_type = match self.peek().cloned() {
                Some(Token {
                    tok: Tok::Int(_) | Tok::Hex(_),
                    ..
                }) => crate::ast::ContentTypeSpec::Numeric(self.expect_int()?),
                _ => crate::ast::ContentTypeSpec::Named(self.expect_ident()?),
            };
            let span = start.join(content_type.span());
            let mutations = self.parse_record_send_suffix()?;
            self.expect_newline_or_rbrace()?;
            return Ok(Step::SendEmptyRecord {
                content_type,
                mutations,
                span,
            });
        }
        if self.at_ident("record")
            && matches!(
                self.peek_at(1),
                Some(Token {
                    tok: Tok::Int(_) | Tok::Hex(_),
                    ..
                })
            )
        {
            // `send record 24 "hello"` / `send record 24 raw "HEX" + 0x00 * 8`: a
            // record of that content type under the current write keys.
            self.bump();
            let content_type = self.expect_int()?;
            let data = if self.at_ident("raw") {
                self.bump();
                let mut bytes = self.parse_raw_segment()?;
                while self.eat(&Tok::Plus) {
                    bytes.extend(self.parse_raw_segment()?);
                }
                bytes
            } else {
                match self.peek().cloned() {
                    Some(Token {
                        tok: Tok::Str(text),
                        ..
                    }) => {
                        self.bump();
                        text.into_bytes()
                    }
                    Some(t) => {
                        return Err(ParseError {
                            span: t.span,
                            message: format!(
                                "`send record N` takes a \"text\" payload or `raw \"HEX\"`, found {}",
                                describe_tok(&t.tok)
                            ),
                        });
                    }
                    None => {
                        return Err(ParseError {
                            span: content_type.span,
                            message: "`send record N` needs a payload".into(),
                        });
                    }
                }
            };
            let end = self.prev_span();
            let mutations = self.parse_record_send_suffix()?;
            self.expect_newline_or_rbrace()?;
            return Ok(Step::SendRecord {
                content_type,
                data,
                mutations,
                span: start.join(end),
            });
        }
        let msgs = self.parse_message_list()?;
        // T6: `send ClientHello raw "HEX" [+ ...]`: the literal body of the
        // hello as sent (a fingerprint replay); it becomes the `raw_body`
        // override, so the rest of the step grammar is unchanged.
        let raw_body: Option<FieldOverride> = if msgs.len() == 1 && self.at_ident("raw") {
            let raw_span = self.peek().unwrap().span;
            self.bump();
            let mut bytes = self.parse_raw_segment()?;
            while self.eat(&Tok::Plus) {
                bytes.extend(self.parse_raw_segment()?);
            }
            let span = raw_span.join(self.prev_span());
            Some(FieldOverride {
                field: Ident {
                    name: "raw_body".into(),
                    span,
                },
                value: FieldValue::List(
                    bytes
                        .iter()
                        .map(|b| {
                            FieldValue::Int(IntLit {
                                value: *b as i64,
                                span,
                            })
                        })
                        .collect(),
                ),
                span,
            })
        } else {
            None
        };
        let (mut overrides, ext_deltas) = if self.at(&Tok::LBrace) {
            self.parse_send_body()?
        } else {
            (Vec::new(), Vec::new())
        };
        if let Some(rb) = raw_body {
            overrides.push(rb);
        }
        let (mutations, dtls_frag) = if self.at(&Tok::At) {
            self.parse_send_at_suffix()?
        } else {
            (Vec::new(), None)
        };
        self.expect_newline_or_rbrace()?;
        let end = msgs.last().map(|m| m.name.span).unwrap_or(start);
        Ok(Step::Send {
            msgs,
            overrides,
            mutations,
            ext_deltas,
            dtls_frag,
            span: start.join(end),
        })
    }

    fn parse_recv_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // recv
        // T6: `recv alert warning/close_notify`: the next record must be that
        // alert (tlsfuzzer's ExpectAlert after a close_notify, for instance).
        if self.at_ident("alert") {
            self.bump();
            let level = self.expect_ident()?;
            let code = if self.eat(&Tok::Slash) {
                Some(self.expect_ident()?)
            } else {
                None
            };
            let span = match &code {
                Some(c) => level.span.join(c.span),
                None => level.span,
            };
            self.expect_newline_or_rbrace()?;
            return Ok(Step::RecvAlert {
                alert: AlertSpec { level, code, span },
                span: start.join(span),
            });
        }
        let msgs = self.parse_message_list()?;
        let (matchers, ext_matchers) = if self.at(&Tok::LBrace) {
            self.parse_recv_body()?
        } else {
            (Vec::new(), Vec::new())
        };
        self.expect_newline_or_rbrace()?;
        let end = msgs.last().map(|m| m.name.span).unwrap_or(start);
        Ok(Step::Recv {
            msgs,
            matchers,
            ext_matchers,
            span: start.join(end),
        })
    }

    /// T6: `repeat N { steps }`. The block nests (a `repeat` inside a
    /// `repeat`, or `coalesce` inside it); `expand_repeats` flattens it.
    fn parse_repeat_block(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // repeat
        let count = self.parse_int_or_var()?;
        if let IntOrVar::Int(n) = &count {
            if n.value < 1 || n.value > 100_000 {
                return Err(ParseError {
                    span: n.span,
                    message: "`repeat N` takes a count from 1 to 100000".into(),
                });
            }
        }
        self.expect(&Tok::LBrace, "`{` after `repeat N`")?;
        let mut steps = Vec::new();
        loop {
            self.skip_newlines();
            if self.at(&Tok::RBrace) {
                break;
            }
            if self.at_ident("coalesce") {
                self.parse_coalesce_block(&mut steps)?;
                continue;
            }
            steps.push(self.parse_step()?);
        }
        let end = self.expect(&Tok::RBrace, "`}` closing repeat block")?;
        self.expect_newline_or_rbrace()?;
        Ok(Step::Repeat {
            count,
            steps,
            span: start.join(end),
        })
    }

    /// The `{ ... }` body of a `recv X` step: field matchers (`field: value`)
    /// and extension-body matchers (`ext NAME == value`, `ext NAME: value`,
    /// `ext 0xNNNN == raw "HEX"`).
    fn parse_recv_body(
        &mut self,
    ) -> Result<(Vec<FieldOverride>, Vec<crate::ast::ExtMatcher>), ParseError> {
        self.expect(&Tok::LBrace, "`{`")?;
        self.skip_newlines();
        let mut matchers = Vec::new();
        let mut ext_matchers = Vec::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Comma) || self.eat(&Tok::Newline) {
                continue;
            }
            if self.at_ident("ext")
                && matches!(
                    self.peek_at(1),
                    Some(Token {
                        tok: Tok::Ident(_) | Tok::Hex(_) | Tok::Int(_),
                        ..
                    })
                )
            {
                let start = self.peek().unwrap().span;
                self.bump(); // ext
                let target = match self.peek().cloned() {
                    Some(Token {
                        tok: Tok::Hex(n) | Tok::Int(n),
                        span,
                    }) => {
                        self.bump();
                        if !(0..=0xffff).contains(&n) {
                            return Err(ParseError {
                                span,
                                message: format!("extension type {} out of range (0..0xffff)", n),
                            });
                        }
                        ExtTarget::Wire(n as u16, span)
                    }
                    _ => ExtTarget::Named(self.expect_ident()?),
                };
                if !self.eat(&Tok::EqEq) && !self.eat(&Tok::Colon) {
                    let t = self.peek().cloned();
                    return Err(ParseError {
                        span: t.as_ref().map(|t| t.span).unwrap_or(start),
                        message:
                            "expected `==` or `:` after the extension name in an `ext` matcher"
                                .into(),
                    });
                }
                let value = self.parse_ext_value()?;
                let end = self.prev_span();
                ext_matchers.push(crate::ast::ExtMatcher {
                    target,
                    value,
                    span: start.join(end),
                });
                continue;
            }
            matchers.push(self.parse_field_override()?);
        }
        self.expect(&Tok::RBrace, "`}`")?;
        Ok((matchers, ext_matchers))
    }

    fn parse_close_step(&mut self) -> Result<Step, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // close
        // `close reset`: abortive close (TCP RST), no alert.
        let reset = if self.at_ident("reset") {
            self.bump();
            true
        } else {
            false
        };
        let alert = if self.at_ident("alert") {
            self.bump();
            let level = self.expect_ident()?;
            let code = if self.eat(&Tok::Slash) {
                Some(self.expect_ident()?)
            } else {
                None
            };
            let span = match &code {
                Some(c) => level.span.join(c.span),
                None => level.span,
            };
            Some(AlertSpec { level, code, span })
        } else {
            None
        };
        self.expect_newline_or_rbrace()?;
        let end = alert.as_ref().map(|a| a.span).unwrap_or(start);
        Ok(Step::Close {
            alert,
            reset,
            span: start.join(end),
        })
    }

    fn parse_message_list(&mut self) -> Result<Vec<MessageRef>, ParseError> {
        let mut out = Vec::new();
        out.push(self.parse_message_ref()?);
        while self.eat(&Tok::Comma) {
            out.push(self.parse_message_ref()?);
        }
        Ok(out)
    }

    fn parse_message_ref(&mut self) -> Result<MessageRef, ParseError> {
        let name = self.expect_ident()?;
        // Retain legacy message payload parsing so lowering can name the new
        // AppData `{ size, reply }` syntax in its migration diagnostic.
        let has_payload = matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Str(_) | Tok::LBracket | Tok::Dollar,
                ..
            })
        ) || self.at_ident("zeros");
        let payload = if has_payload {
            Some(self.parse_field_value()?)
        } else {
            None
        };
        Ok(MessageRef { name, payload })
    }

    /// Parse the `{ ... }` body of a `send X` step, which may
    /// contain field overrides (`field: value`) and/or extension
    /// deltas (`+ext name = value` / `-ext name`).
    fn parse_send_body(&mut self) -> Result<(Vec<FieldOverride>, Vec<ExtDelta>), ParseError> {
        self.expect(&Tok::LBrace, "`{`")?;
        self.skip_newlines();
        let mut overrides = Vec::new();
        let mut ext_deltas = Vec::new();
        while !self.at(&Tok::RBrace) && !self.eof() {
            if self.eat(&Tok::Comma) || self.eat(&Tok::Newline) {
                continue;
            }
            if (self.at(&Tok::Plus) || self.at(&Tok::Minus))
                && matches!(self.peek_at(1), Some(Token { tok: Tok::Ident(s), .. }) if s == "ext")
            {
                ext_deltas.push(self.parse_ext_delta()?);
                continue;
            }
            if self.at_ident("reverse_extensions") {
                let sp = self.peek().unwrap().span;
                self.bump();
                self.expect_newline_or_rbrace()?;
                ext_deltas.push(ExtDelta::Reverse { span: sp });
                continue;
            }
            overrides.push(self.parse_field_override()?);
        }
        self.expect(&Tok::RBrace, "`}`")?;
        Ok((overrides, ext_deltas))
    }

    fn parse_field_override(&mut self) -> Result<FieldOverride, ParseError> {
        let field = self.expect_ident()?;
        let start = field.span;
        self.expect(&Tok::Colon, "`:` after field name")?;
        let value = self.parse_field_value()?;
        Ok(FieldOverride {
            field,
            value,
            span: start,
        })
    }

    /// T1: the shared value grammar (field overrides, matchers, extension
    /// values, message payloads):
    ///   atom   := INT | "str" | NAME | $var | [ item, ... ] | zeros N | capture $name
    ///   item   := value [ : value ]          (`key : value` = an entry)
    ///   value  := atom [ .. int-or-var ] { * int-or-var }
    /// `lo..hi` expands inclusively inside a list; `x * N` repeats x N times
    /// (a number, string, name, list or range); nested lists flatten.
    fn parse_field_value(&mut self) -> Result<FieldValue, ParseError> {
        let atom = self.parse_field_atom()?;
        let start = self.prev_span();
        let mut v = atom;
        if self.at(&Tok::DotDot) {
            let lo = match &v {
                FieldValue::Int(i) => IntOrVar::Int(*i),
                FieldValue::MatrixVar(id) => IntOrVar::Var(id.clone()),
                _ => {
                    return Err(ParseError {
                        span: self.peek().unwrap().span,
                        message: "a `lo..hi` range needs a number or matrix variable on its left"
                            .into(),
                    });
                }
            };
            self.bump();
            let hi = self.parse_int_or_var()?;
            v = FieldValue::Range {
                lo,
                hi,
                span: start.join(self.prev_span()),
            };
        }
        while self.at(&Tok::Star) {
            self.bump();
            let count = self.parse_int_or_var()?;
            if let IntOrVar::Int(n) = &count {
                if !(0..=1 << 20).contains(&n.value) {
                    return Err(ParseError {
                        span: n.span,
                        message: format!("repeat count {} out of range (0..1048576)", n.value),
                    });
                }
            }
            v = FieldValue::Repeat {
                item: Box::new(v),
                count,
                span: start.join(self.prev_span()),
            };
        }
        Ok(v)
    }

    fn parse_field_atom(&mut self) -> Result<FieldValue, ParseError> {
        match self.peek().cloned() {
            Some(Token {
                tok: Tok::Int(_) | Tok::Hex(_) | Tok::Minus,
                ..
            }) => {
                let i = self.expect_int()?;
                Ok(FieldValue::Int(i))
            }
            Some(Token {
                tok: Tok::Str(s),
                span,
            }) => {
                self.bump();
                Ok(FieldValue::Str(StrLit { value: s, span }))
            }
            // T4: `file "path"` -- the file's bytes as a byte-field value.
            Some(Token {
                tok: Tok::Ident(ref name),
                span,
            }) if name == "file"
                && matches!(
                    self.peek_at(1),
                    Some(Token {
                        tok: Tok::Str(_),
                        ..
                    })
                ) =>
            {
                self.bump();
                let Some(Token {
                    tok: Tok::Str(path),
                    span: pspan,
                }) = self.peek().cloned()
                else {
                    unreachable!("checked above");
                };
                self.bump();
                let _ = span;
                Ok(FieldValue::File(StrLit {
                    value: path,
                    span: pspan,
                }))
            }
            Some(Token {
                tok: Tok::LBracket, ..
            }) => {
                self.bump();
                self.skip_newlines();
                if self.at(&Tok::RBracket) {
                    self.bump();
                    return Ok(FieldValue::Empty);
                }
                let mut items = Vec::new();
                items.push(self.parse_list_item()?);
                while self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    if self.at(&Tok::RBracket) {
                        break; // trailing comma
                    }
                    items.push(self.parse_list_item()?);
                }
                self.skip_newlines();
                self.expect(&Tok::RBracket, "`]`")?;
                Ok(FieldValue::List(items))
            }
            Some(Token {
                tok: Tok::Dollar,
                span,
            }) => {
                self.bump();
                let id = self.expect_ident()?;
                Ok(FieldValue::MatrixVar(Ident {
                    name: id.name,
                    span: span.join(id.span),
                }))
            }
            Some(Token {
                tok: Tok::Ident(ref name),
                span,
            }) if name == "zeros" => {
                self.bump();
                let count = self.parse_int_or_var()?;
                Ok(FieldValue::Repeat {
                    item: Box::new(FieldValue::Int(IntLit { value: 0, span })),
                    count,
                    span: span.join(self.prev_span()),
                })
            }
            Some(Token {
                tok: Tok::Ident(ref name),
                ..
            }) if name == "capture" => {
                self.bump();
                let dollar = self.expect(&Tok::Dollar, "`$name` after `capture`")?;
                let id = self.expect_ident()?;
                Ok(FieldValue::Capture(Ident {
                    name: id.name,
                    span: dollar.join(id.span),
                }))
            }
            Some(Token {
                tok: Tok::Ident(_), ..
            }) => {
                let id = self.expect_ident()?;
                Ok(FieldValue::Ident(id))
            }
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!("unexpected {} in field value", describe_tok(&t.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected field value, found end of file".into(),
            }),
        }
    }

    /// One list item: a value, or `key : value` (a key_share entry).
    fn parse_list_item(&mut self) -> Result<FieldValue, ParseError> {
        let v = self.parse_field_value()?;
        if self.at(&Tok::Colon) {
            self.bump();
            let start = self.prev_span();
            let value = self.parse_field_value()?;
            return Ok(FieldValue::Entry {
                key: Box::new(v),
                value: Box::new(value),
                span: start.join(self.prev_span()),
            });
        }
        Ok(v)
    }

    /// The `@ ...` suffix on a `send` step: a comma-separated list where each item
    /// is either a byte mutation (`@ xor[..]=..`) or a DTLS fragmentation scheme
    /// (`@ fragment N`). The frag scheme is DTLS-specific and lowers separately
    /// from mutations, so it is collected on its own. At most one is allowed.
    fn parse_send_at_suffix(
        &mut self,
    ) -> Result<(Vec<Mutation>, Option<crate::ast::DtlsFrag>), ParseError> {
        let mut muts = Vec::new();
        let mut frag: Option<crate::ast::DtlsFrag> = None;
        loop {
            if self.at_dtls_frag_suffix() {
                let f = self.parse_dtls_frag()?;
                if frag.is_some() {
                    return Err(ParseError {
                        span: self.prev_span(),
                        message: "a send step may carry only one DTLS fragmentation scheme".into(),
                    });
                }
                frag = Some(f);
            } else {
                muts.push(self.parse_mutation()?);
            }
            if !self.eat(&Tok::Comma) {
                break;
            }
        }
        Ok((muts, frag))
    }

    /// True if the next tokens are `@ <dtls-frag-keyword>`.
    fn at_dtls_frag_suffix(&self) -> bool {
        // After a comma the `@` is optional: `@ fragment 8, duplicate_fragment 8`.
        let kw = if self.at(&Tok::At) {
            self.peek_at(1)
        } else {
            self.peek()
        };
        matches!(
            kw,
            Some(Token { tok: Tok::Ident(name), .. })
                if matches!(
                    name.as_str(),
                    "duplicate_fragment"
                        | "reorder_overlap"
                        | "complete_and_fragments"
                        | "empty_fragments"
                        | "split_fragment_record"
                        | "overlap_mismatch"
                        | "type_mismatch"
                        | "length_mismatch"
                        | "fragment_length_mismatch"
                        | "future_sequence"
                        | "future_sequence_packed"
                        | "offset_overflow"
                )
        )
    }

    /// The `@` that opens a mutation; optional after a comma in an `@` list.
    fn eat_at(&mut self) -> Span {
        if self.at(&Tok::At) {
            let sp = self.peek().unwrap().span;
            self.bump();
            sp
        } else {
            self.peek().map(|t| t.span).unwrap_or(Span::dummy())
        }
    }

    fn parse_dtls_frag(&mut self) -> Result<crate::ast::DtlsFrag, ParseError> {
        use crate::ast::DtlsFrag;
        let at = self.eat_at();
        let kw = self.expect_ident()?;
        let f = match kw.name.as_str() {
            "duplicate_fragment" => DtlsFrag::DuplicateFragment {
                n: self.expect_int()?,
            },
            "reorder_overlap" => DtlsFrag::ReorderOverlap {
                n: self.expect_int()?,
            },
            "complete_and_fragments" => DtlsFrag::CompleteAndFragments {
                n: self.expect_int()?,
            },
            "empty_fragments" => DtlsFrag::EmptyFragments {
                span: at.join(kw.span),
            },
            "split_fragment_record" => DtlsFrag::SplitFragmentRecord {
                n: self.expect_int()?,
            },
            "overlap_mismatch" => DtlsFrag::OverlapMismatch {
                n: self.expect_int()?,
            },
            "type_mismatch" => DtlsFrag::TypeMismatch {
                n: self.expect_int()?,
            },
            "length_mismatch" => DtlsFrag::LengthMismatch {
                n: self.expect_int()?,
            },
            "fragment_length_mismatch" => DtlsFrag::FragmentLengthMismatch {
                n: self.expect_int()?,
            },
            "future_sequence" => DtlsFrag::FutureSequence {
                n: self.expect_int()?,
            },
            "future_sequence_packed" => DtlsFrag::FutureSequencePacked {
                n: self.expect_int()?,
            },
            "offset_overflow" => DtlsFrag::OffsetOverflow {
                span: at.join(kw.span),
            },
            other => {
                return Err(ParseError {
                    span: kw.span,
                    message: format!("unknown DTLS fragmentation scheme `{}`", other),
                });
            }
        };
        Ok(f)
    }

    fn parse_mutation(&mut self) -> Result<Mutation, ParseError> {
        let at = self.eat_at();
        let op_id = self.expect_ident()?;
        let start = at.join(op_id.span);
        let op = match op_id.name.as_str() {
            "xor" | "set" => {
                self.expect(&Tok::LBracket, "`[`")?;
                let target = self.parse_byte_target()?;
                self.expect(&Tok::RBracket, "`]`")?;
                self.expect(&Tok::Eq, "`=`")?;
                let value = self.parse_mut_value()?;
                if op_id.name == "xor" {
                    MutationOp::Xor { target, value }
                } else {
                    MutationOp::Set { target, value }
                }
            }
            "add" | "sub" => {
                self.expect(&Tok::LBracket, "`[`")?;
                let target = self.parse_field_path()?;
                self.expect(&Tok::RBracket, "`]`")?;
                self.expect(&Tok::Eq, "`=`")?;
                let value = self.parse_mut_value()?;
                if op_id.name == "add" {
                    MutationOp::Add { target, value }
                } else {
                    MutationOp::Sub { target, value }
                }
            }
            "pad" => {
                if self.eat(&Tok::Plus) {
                    let n = self.parse_mut_value()?;
                    // `pad +N 0xfa`: the pad byte (default zero).
                    let byte = match self.peek().cloned() {
                        Some(Token {
                            tok: Tok::Int(_) | Tok::Hex(_),
                            ..
                        }) => Some(self.expect_int()?),
                        _ => None,
                    };
                    MutationOp::PadPlus { n, byte }
                } else if self.eat(&Tok::Minus) {
                    let n = self.parse_mut_value()?;
                    MutationOp::PadMinus { n }
                } else if matches!(
                    self.peek(),
                    Some(Token {
                        tok: Tok::Str(_),
                        ..
                    })
                ) {
                    // `pad "ff01000100"`: append exactly these bytes.
                    let span = self.peek().unwrap().span;
                    let bytes = self.parse_raw_segment()?;
                    MutationOp::PadBytes { bytes, span }
                } else {
                    return Err(ParseError {
                        span: op_id.span,
                        message: "`pad` requires `+N [0xNN]`, `-N` or `\"HEX\"`".into(),
                    });
                }
            }
            "record_version" => {
                let v = self.expect_int()?;
                MutationOp::RecordVersion { v }
            }
            "record_pad" => {
                if self.at_ident("fill") {
                    let f = self.expect_ident()?;
                    MutationOp::RecordPad {
                        n: None,
                        span: op_id.span.join(f.span),
                    }
                } else {
                    let n = self.expect_int()?;
                    MutationOp::RecordPad {
                        n: Some(n),
                        span: op_id.span.join(n.span),
                    }
                }
            }
            "dtls13_short_sequence" => MutationOp::Dtls13ShortSequence,
            "dtls13_omit_length" => MutationOp::Dtls13OmitLength,
            "dtls13_set_cid_bit" => MutationOp::Dtls13SetCidBit,
            "dtls13_legacy_header" => MutationOp::Dtls13LegacyHeader,
            "plaintext" => {
                let replace = if self.eat(&Tok::Eq) {
                    let mut bytes = self.parse_raw_segment()?;
                    while self.eat(&Tok::Plus) {
                        bytes.extend(self.parse_raw_segment()?);
                    }
                    Some(bytes)
                } else {
                    None
                };
                MutationOp::Plaintext {
                    replace,
                    span: op_id.span.join(self.prev_span()),
                }
            }
            "cbc_pad" => {
                let n = self.expect_int()?;
                MutationOp::CbcPad { n }
            }
            "truncate" => {
                let n = self.parse_mut_value()?;
                MutationOp::Truncate { n }
            }
            "trailing" => {
                let span = self.peek().map_or(op_id.span, |token| token.span);
                let bytes = self.parse_raw_segment()?;
                MutationOp::TrailingBytes { bytes, span }
            }
            "omit_prefix" => {
                let n = self.parse_mut_value()?;
                MutationOp::OmitPrefix { n }
            }
            "reorder" => {
                let n = self.expect_int()?;
                MutationOp::Reorder { n }
            }
            "fragment" => {
                let n = self.parse_mut_value()?;
                let hold = if self.at_ident("hold") {
                    self.bump();
                    crate::ir::FragHold::Last
                } else if self.at_ident("hold_all") {
                    self.bump();
                    crate::ir::FragHold::All
                } else if self.at_ident("hold_old_keys") {
                    self.bump();
                    crate::ir::FragHold::LastOldKeys
                } else {
                    crate::ir::FragHold::None
                };
                MutationOp::Fragment { n, hold }
            }
            other => {
                return Err(ParseError {
                    span: op_id.span,
                    message: format!("unknown mutation op `{}`", other),
                });
            }
        };
        let end = self.peek().map(|t| t.span).unwrap_or(start);
        Ok(Mutation {
            op,
            span: start.join(end),
        })
    }

    fn parse_byte_target(&mut self) -> Result<ByteTarget, ParseError> {
        let start = self.peek().map(|t| t.span).unwrap_or(Span::dummy());

        let path = if matches!(
            self.peek(),
            Some(Token {
                tok: Tok::Ident(_),
                ..
            })
        ) && matches!(self.peek_at(1), Some(Token { tok: Tok::Dot, .. }))
        {
            let mut parts = Vec::new();
            parts.push(self.expect_ident()?);
            while self.eat(&Tok::Dot) {
                parts.push(self.expect_ident()?);
            }
            if self.at(&Tok::Comma) {
                self.bump();
            }
            let span = parts.first().unwrap().span.join(parts.last().unwrap().span);
            Some(FieldPath { parts, span })
        } else {
            None
        };

        // T2: a bare path (`set[record.inner_type] = 0`) means byte 0.
        let index = if path.is_some() && self.at(&Tok::RBracket) {
            ByteIndex::Single(IntOrVar::Int(IntLit {
                value: 0,
                span: self.prev_span(),
            }))
        } else {
            self.parse_byte_index()?
        };
        let end = self.peek().map(|t| t.span).unwrap_or(start);
        Ok(ByteTarget {
            path,
            index,
            span: start.join(end),
        })
    }

    fn parse_field_path(&mut self) -> Result<FieldPath, ParseError> {
        let mut parts = vec![self.expect_ident()?];
        while self.eat(&Tok::Dot) {
            parts.push(self.expect_ident()?);
        }
        if parts.len() < 2 {
            return Err(ParseError {
                span: parts[0].span,
                message: "a length adjustment target must be a named field path such as `handshake.length`".into(),
            });
        }
        let span = parts.first().unwrap().span.join(parts.last().unwrap().span);
        Ok(FieldPath { parts, span })
    }

    fn parse_byte_index(&mut self) -> Result<ByteIndex, ParseError> {
        let lo = self.parse_int_or_var()?;
        if self.eat(&Tok::DotDot) {
            let hi = self.parse_int_or_var()?;
            Ok(ByteIndex::Range { lo, hi })
        } else {
            Ok(ByteIndex::Single(lo))
        }
    }

    fn parse_int_or_var(&mut self) -> Result<IntOrVar, ParseError> {
        if self.eat(&Tok::Dollar) {
            let id = self.expect_ident()?;
            // T1: `$var + N` / `$var - N`.
            if self.at(&Tok::Plus) || self.at(&Tok::Minus) {
                let neg = self.at(&Tok::Minus);
                self.bump();
                let n = self.expect_int()?;
                let offset = if neg { -n.value } else { n.value };
                return Ok(IntOrVar::VarOffset { var: id, offset });
            }
            return Ok(IntOrVar::Var(id));
        }
        let i = self.expect_int()?;
        Ok(IntOrVar::Int(i))
    }

    fn parse_mut_value(&mut self) -> Result<MutValue, ParseError> {
        if self.eat(&Tok::Dollar) {
            let id = self.expect_ident()?;
            return Ok(MutValue::Var(id));
        }
        match self.peek().cloned() {
            Some(Token {
                tok: Tok::Int(_) | Tok::Hex(_) | Tok::Minus,
                ..
            }) => {
                let i = self.expect_int()?;
                Ok(MutValue::Int(i))
            }
            Some(t) => Err(ParseError {
                span: t.span,
                message: format!("expected integer or $var, found {}", describe_tok(&t.tok)),
            }),
            None => Err(ParseError {
                span: Span::dummy(),
                message: "expected mutation value, found end of file".into(),
            }),
        }
    }

    fn parse_expect(&mut self) -> Result<Expect, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // expect
        let kind = self.parse_expect_kind()?;
        self.expect_newline_or_rbrace()?;
        Ok(Expect {
            kind,
            overrides: Vec::new(),
            span: start.join(self.prev_span()),
        })
    }

    /// Parse `expect <kind> if <uut>` — an override for a specific UUT.
    /// Returns None if the current `expect` has no `if` clause (it's
    /// a primary expect, not an override).
    fn parse_expect_override(&mut self) -> Result<ExpectOverride, ParseError> {
        self.bump(); // expect
        let kind = self.parse_expect_kind()?;
        if !self.eat_ident("if") {
            return Err(ParseError {
                span: self.prev_span(),
                message: "expected `if <uut>` after override expect".into(),
            });
        }
        let uut = self.expect_ident()?;
        self.expect_newline_or_rbrace()?;
        Ok(ExpectOverride { kind, uut })
    }

    fn parse_expect_kind(&mut self) -> Result<ExpectKind, ParseError> {
        let id = self.expect_ident()?;
        match id.name.as_str() {
            "ok" => Ok(ExpectKind::Ok),
            "close" => Ok(ExpectKind::Close),
            "reset" => Ok(ExpectKind::Reset),
            "timeout" => Ok(ExpectKind::Timeout),
            "handshake-fails" => Ok(ExpectKind::HandshakeFails),
            "any" => {
                self.expect(&Tok::LBrace, "`{`")?;
                self.skip_newlines();
                let mut alternatives = vec![self.parse_expect_kind()?];
                while self.eat(&Tok::Comma) {
                    self.skip_newlines();
                    alternatives.push(self.parse_expect_kind()?);
                }
                self.skip_newlines();
                self.expect(&Tok::RBrace, "`}`")?;
                if alternatives.len() < 2 {
                    return Err(ParseError {
                        span: id.span.join(self.prev_span()),
                        message: "`expect any` needs at least two alternatives".into(),
                    });
                }
                Ok(ExpectKind::Any(alternatives))
            }
            "alert" | "reject" => {
                let reject = id.name == "reject";
                let level = self.expect_ident()?;
                let codes = if self.eat(&Tok::Slash) {
                    if self.eat(&Tok::LBrace) {
                        self.skip_newlines();
                        let mut v = Vec::new();
                        v.push(self.expect_ident()?);
                        while self.eat(&Tok::Comma) {
                            self.skip_newlines();
                            v.push(self.expect_ident()?);
                        }
                        self.skip_newlines();
                        self.expect(&Tok::RBrace, "`}`")?;
                        v
                    } else {
                        vec![self.expect_ident()?]
                    }
                } else {
                    Vec::new()
                };
                Ok(if reject {
                    ExpectKind::Reject { level, codes }
                } else {
                    ExpectKind::Alert { level, codes }
                })
            }
            other => Err(ParseError {
                span: id.span,
                message: format!("unknown expect outcome `{}`", other),
            }),
        }
    }

    fn parse_assert(&mut self) -> Result<AssertLine, ParseError> {
        let start = self.peek().unwrap().span;
        self.bump(); // assert
        let first = self.expect_ident()?;
        // T1: `assert unique $a, $b`.
        if first.name == "unique" && self.at(&Tok::Dollar) {
            let mut vars = Vec::new();
            loop {
                let d = self.expect(&Tok::Dollar, "`$name`")?;
                let id = self.expect_ident()?;
                vars.push(Ident {
                    name: id.name,
                    span: d.join(id.span),
                });
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
            let end = self.prev_span();
            self.expect_newline_or_rbrace()?;
            return Ok(AssertLine {
                kind: AssertKind::Unique(vars),
                span: start.join(end),
            });
        }
        if first.name == "max_datagram_size" {
            let n = self.expect_int()?;
            if n.value <= 0 || n.value > u32::MAX as i64 {
                return Err(ParseError {
                    span: n.span,
                    message: "max_datagram_size must be between 1 and 4294967295".into(),
                });
            }
            let end = n.span;
            self.expect_newline_or_rbrace()?;
            return Ok(AssertLine {
                kind: AssertKind::MaxDatagramSize(n),
                span: start.join(end),
            });
        }
        if !self.at(&Tok::Dot) && !self.at(&Tok::EqEq) {
            self.expect_newline_or_rbrace()?;
            return Ok(AssertLine {
                kind: AssertKind::Named(first.clone()),
                span: start.join(first.span),
            });
        }
        let mut parts = vec![first];
        while self.eat(&Tok::Dot) {
            parts.push(self.expect_ident()?);
        }
        let path_span = parts.first().unwrap().span.join(parts.last().unwrap().span);
        let path = FieldPath {
            parts,
            span: path_span,
        };
        self.expect(&Tok::EqEq, "`==`")?;
        let value = self.parse_field_value()?;
        self.expect_newline_or_rbrace()?;
        Ok(AssertLine {
            kind: AssertKind::Eq { path, value },
            span: start.join(path_span),
        })
    }
}

fn describe_tok(t: &Tok) -> String {
    match t {
        Tok::Newline => "newline".into(),
        Tok::Comma => "`,`".into(),
        Tok::Colon => "`:`".into(),
        Tok::LBrace => "`{`".into(),
        Tok::RBrace => "`}`".into(),
        Tok::LBracket => "`[`".into(),
        Tok::RBracket => "`]`".into(),
        Tok::LParen => "`(`".into(),
        Tok::RParen => "`)`".into(),
        Tok::Plus => "`+`".into(),
        Tok::Minus => "`-`".into(),
        Tok::Star => "`*`".into(),
        Tok::Slash => "`/`".into(),
        Tok::Dot => "`.`".into(),
        Tok::DotDot => "`..`".into(),
        Tok::Eq => "`=`".into(),
        Tok::EqEq => "`==`".into(),
        Tok::At => "`@`".into(),
        Tok::Dollar => "`$`".into(),
        Tok::Int(n) => format!("integer `{}`", n),
        Tok::Hex(n) => format!("hex `0x{:x}`", n),
        Tok::Str(s) => format!("string `{:?}`", s),
        Tok::Ident(s) => format!("`{}`", s),
    }
}

/// T6: flatten `repeat N { ... }` blocks (recursively) into N copies of their
/// steps, so lowering and the runtime only ever see plain step lists.
fn expand_repeats(steps: Vec<Step>) -> Vec<Step> {
    let mut out = Vec::with_capacity(steps.len());
    for st in steps {
        match st {
            Step::Repeat {
                count,
                steps: inner,
                span,
            } => {
                let inner = expand_repeats(inner);
                match count {
                    IntOrVar::Int(n) => {
                        for _ in 0..n.value {
                            out.extend(inner.iter().cloned());
                        }
                    }
                    // A matrix-variable count is unrolled by lowering.
                    other => out.push(Step::Repeat {
                        count: other,
                        steps: inner,
                        span,
                    }),
                }
            }
            other => out.push(other),
        }
    }
    out
}
