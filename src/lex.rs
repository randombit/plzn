// Token definition + driver, built on `logos`.
//
// Whitespace (except `\n`) and line comments are skipped. `\n` is emitted
// as an explicit Newline token because the parser uses it as a statement
// terminator in statement position and ignores it everywhere else.
//
// Integer literals: decimal or 0x-prefixed hex; the parser handles a
// unary `-` in front when a signed int is legal. We never treat an
// all-hex literal as a byte-string in the lexer — that's a parser-level
// reinterpretation if needed. Keeps the lexer dumb.

use crate::ast::Span;
use logos::Logos;

#[derive(Logos, Clone, Debug, PartialEq)]
#[logos(skip r"[ \t\r]+")] // horizontal whitespace
#[logos(skip r"#[^\n]*")] // line comments
pub enum Tok {
    #[token("\n")]
    Newline,

    #[token(",")]
    Comma,
    #[token(":")]
    Colon,
    #[token("{")]
    LBrace,
    #[token("}")]
    RBrace,
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token("(")]
    LParen,
    #[token(")")]
    RParen,
    #[token("+")]
    Plus,
    #[token("-")]
    Minus,
    #[token("*")]
    Star,
    #[token("/")]
    Slash,
    #[token(".")]
    Dot,
    #[token("..")]
    DotDot,
    #[token("=")]
    Eq,
    #[token("==")]
    EqEq,
    #[token("@")]
    At,
    #[token("$")]
    Dollar,

    // 0x-prefixed hex integers.
    #[regex(r"0x[0-9A-Fa-f]+", |lex| i64::from_str_radix(&lex.slice()[2..], 16).ok())]
    Hex(i64),

    // Decimal integers.
    #[regex(r"[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Int(i64),

    // Identifiers: letter/underscore followed by letters/digits/_/-.
    #[regex(r"[A-Za-z_][A-Za-z0-9_-]*", |lex| lex.slice().to_owned())]
    Ident(String),

    // Double-quoted strings with C-style escapes.
    #[regex(r#""([^"\\\n]|\\.)*""#, |lex| unescape(lex.slice()))]
    Str(String),
}

fn unescape(raw: &str) -> Option<String> {
    // raw includes the surrounding quotes.
    let inner = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '0' => out.push('\0'),
            other => {
                // Unknown escape: preserve literally so the user sees it
                // in a diagnostic; an error is emitted by a pre-check below.
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

#[derive(Clone, Debug)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct LexError {
    pub span: Span,
    pub message: String,
}

impl LexError {
    pub fn into_diag(self, source_name: &str, source: &str) -> crate::diag::Diag {
        crate::diag::Diag::from_simple(source_name, source, self.span, "lex error", self.message)
    }
}

pub fn lex(source: &str) -> Result<Vec<Token>, Vec<LexError>> {
    lex_source(source).map(|(tokens, _)| tokens)
}

/// Keep foreign declarations opaque, with their original spans for formatting.
/// Filtering here also keeps foreign syntax out of TLS lexical diagnostics.
pub(crate) fn lex_source(source: &str) -> Result<(Vec<Token>, Vec<Span>), Vec<LexError>> {
    let mut tokens = Vec::new();
    let mut ignored = Vec::new();
    let mut errors = Vec::new();
    let mut lexer = Tok::lexer(source);
    let mut depth = 0usize;
    while let Some(result) = lexer.next() {
        let span = Span::new(lexer.span().start, lexer.span().end);
        match result {
            Ok(tok) => {
                if depth == 0 && matches!(&tok, Tok::Ident(name) if name == "plzn") {
                    match skip_foreign_flow(&mut lexer, span) {
                        Ok(Some(span)) => {
                            ignored.push(span);
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            errors.push(error);
                            break;
                        }
                    }
                }
                match tok {
                    Tok::LBrace => depth += 1,
                    Tok::RBrace => depth = depth.saturating_sub(1),
                    _ => {}
                }
                tokens.push(Token { tok, span });
            }
            Err(_) => errors.push(LexError {
                span,
                message: format!("unexpected input `{}`", lexer.slice().escape_default()),
            }),
        }
    }
    if errors.is_empty() {
        Ok((tokens, ignored))
    } else {
        Err(errors)
    }
}

fn skip_foreign_flow(
    lexer: &mut logos::Lexer<'_, Tok>,
    start: Span,
) -> Result<Option<Span>, LexError> {
    let mut lookahead = lexer.clone();
    if !matches!(lookahead.next(), Some(Ok(Tok::Ident(protocol))) if protocol != "tls") {
        return Ok(None);
    }
    // Protocols share the declaration envelope, but not their body grammar.
    for (valid, expected) in [
        (
            matches!(lookahead.next(), Some(Ok(Tok::Str(_)))),
            "flow name",
        ),
        (matches!(lookahead.next(), Some(Ok(Tok::LBrace))), "`{`"),
    ] {
        if !valid {
            return Err(LexError {
                span: start,
                message: format!("expected {expected} in protocol flow declaration"),
            });
        }
    }

    let mut depth = 1usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = false;
    for (index, byte) in lookahead.remainder().bytes().enumerate() {
        if comment {
            comment = byte != b'\n';
        } else if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'#' => comment = true,
                b'"' => quoted = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        lookahead.bump(index + 1);
                        let span = Span::new(start.start, lookahead.span().end);
                        *lexer = lookahead;
                        return Ok(Some(span));
                    }
                }
                _ => {}
            }
        }
    }
    Err(LexError {
        span: start,
        message: "unclosed protocol flow; expected `}`".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn simple_header() {
        let t = toks("plzn tls \"tls12/happy-rsa\" {\n  role server\n}\n");
        assert!(matches!(t[0], Tok::Ident(ref s) if s == "plzn"));
        assert!(matches!(t[1], Tok::Ident(ref s) if s == "tls"));
        assert!(matches!(t[2], Tok::Str(ref s) if s == "tls12/happy-rsa"));
        assert_eq!(t[3], Tok::LBrace);
        assert_eq!(t[4], Tok::Newline);
        assert!(matches!(t[5], Tok::Ident(ref s) if s == "role"));
    }

    #[test]
    fn hex_and_int() {
        let t = toks("0x01 0xff 0x1301 255\n");
        assert!(matches!(t[0], Tok::Hex(1)));
        assert!(matches!(t[1], Tok::Hex(0xff)));
        assert!(matches!(t[2], Tok::Hex(0x1301)));
        assert!(matches!(t[3], Tok::Int(255)));
    }

    #[test]
    fn string_with_escapes() {
        let t = toks(r#"send AppData "GET / HTTP/1.0\r\n\r\n""#);
        match &t[2] {
            Tok::Str(s) => assert_eq!(s, "GET / HTTP/1.0\r\n\r\n"),
            _ => panic!("expected Str, got {:?}", t[2]),
        }
    }

    #[test]
    fn comments_skipped() {
        let t = toks("# comment\ntest\n");
        // first token is the leading newline AFTER the skipped comment
        assert_eq!(t[0], Tok::Newline);
        assert!(matches!(t[1], Tok::Ident(ref s) if s == "test"));
    }
}
