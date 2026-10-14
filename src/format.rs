//! Canonical whitespace formatting for `.plzn` sources.
//!
//! Formatting deliberately leaves tokens and line breaks alone. Newlines are
//! statement terminators in the DSL, so reflowing would be a semantic change.
//! The formatter normalizes block/continuation indentation, trailing
//! whitespace, line endings, and the final newline after first verifying that
//! the source parses.

use crate::ast::Span;
use crate::diag::Diag;
use crate::lex::{Tok, Token};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delimiter {
    Brace,
    Bracket,
    Paren,
}

#[derive(Clone, Copy, Debug)]
struct Frame {
    delimiter: Delimiter,
    content_indent: usize,
    close_indent: usize,
}

struct SourceLine<'a> {
    text: &'a str,
    start: usize,
    full_end: usize,
}

/// Format one syntactically valid `.plzn` source file.
pub fn format_source(source_name: &str, source: &str) -> Result<String, Vec<Diag>> {
    let (tokens, ignored) = match crate::lex::lex_source(source) {
        Ok(tokens) => tokens,
        Err(errors) => {
            return Err(errors
                .into_iter()
                .map(|error| error.into_diag(source_name, source))
                .collect());
        }
    };

    if let Err(errors) = crate::parse::parse(&tokens) {
        return Err(errors
            .into_iter()
            .map(|error| error.into_diag(source_name, source))
            .collect());
    }

    if !ignored.is_empty() && tokens.iter().all(|token| token.tok == Tok::Newline) {
        return Ok(source.to_owned());
    }
    Ok(format_tokens(source, &tokens, &ignored))
}

fn format_tokens(source: &str, tokens: &[Token], ignored: &[Span]) -> String {
    let lines = source_lines(source);
    let Some(last_nonblank) = lines.iter().rposition(|line| !line.text.trim().is_empty()) else {
        return String::new();
    };

    let mut output = String::with_capacity(source.len());
    let mut token_index = 0usize;
    let mut frames: Vec<Frame> = Vec::new();

    for line in lines.into_iter().take(last_nonblank + 1) {
        // A shared line stays intact too: changing even its whitespace could
        // affect another protocol's syntax. TLS tokens still update our frames.
        let preserve = ignored
            .iter()
            .any(|span| span.start < line.full_end && span.end > line.start);
        while token_index < tokens.len() && tokens[token_index].span.end <= line.start {
            token_index += 1;
        }
        let first_token = token_index;
        while token_index < tokens.len() && tokens[token_index].span.start < line.full_end {
            token_index += 1;
        }
        let line_tokens: Vec<&Token> = tokens[first_token..token_index]
            .iter()
            .filter(|token| !matches!(token.tok, Tok::Newline))
            .collect();

        let content = line.text.trim_start_matches([' ', '\t']).trim_end();
        if content.is_empty() && !preserve {
            output.push('\n');
            continue;
        }

        let original_content_start =
            line.text.len() - line.text.trim_start_matches([' ', '\t']).len();
        let indent = if preserve {
            original_content_start
        } else {
            match line_tokens.first().and_then(|token| closing(&token.tok)) {
                Some(delimiter) => frames
                    .iter()
                    .rev()
                    .find(|frame| frame.delimiter == delimiter)
                    .map_or(0, |frame| frame.close_indent),
                None => frames.last().map_or(0, |frame| frame.content_indent),
            }
        };

        if preserve {
            output.push_str(&source[line.start..line.full_end]);
        } else {
            output.extend(std::iter::repeat_n(' ', indent));
            output.push_str(content);
            output.push('\n');
        }

        for (index, token) in line_tokens.iter().enumerate() {
            if let Some(delimiter) = opening(&token.tok) {
                let has_following_token = line_tokens.get(index + 1).is_some();
                let (content_indent, close_indent) = match delimiter {
                    Delimiter::Brace => (indent + 2, indent),
                    Delimiter::Bracket | Delimiter::Paren if has_following_token => {
                        let column =
                            indent + token.span.start - line.start - original_content_start;
                        (column + 1, indent)
                    }
                    Delimiter::Bracket | Delimiter::Paren => (indent + 2, indent),
                };
                frames.push(Frame {
                    delimiter,
                    content_indent,
                    close_indent,
                });
            } else if let Some(delimiter) = closing(&token.tok) {
                debug_assert_eq!(frames.last().map(|frame| frame.delimiter), Some(delimiter));
                frames.pop();
            }
        }
    }

    output
}

fn source_lines(source: &str) -> Vec<SourceLine<'_>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for segment in source.split_inclusive('\n') {
        let text = segment.strip_suffix('\n').unwrap_or(segment);
        let text = text.strip_suffix('\r').unwrap_or(text);
        let full_end = start + segment.len();
        lines.push(SourceLine {
            text,
            start,
            full_end,
        });
        start = full_end;
    }
    if start < source.len() {
        lines.push(SourceLine {
            text: &source[start..],
            start,
            full_end: source.len(),
        });
    }
    lines
}

fn opening(token: &Tok) -> Option<Delimiter> {
    match token {
        Tok::LBrace => Some(Delimiter::Brace),
        Tok::LBracket => Some(Delimiter::Bracket),
        Tok::LParen => Some(Delimiter::Paren),
        _ => None,
    }
}

fn closing(token: &Tok) -> Option<Delimiter> {
    match token {
        Tok::RBrace => Some(Delimiter::Brace),
        Tok::RBracket => Some(Delimiter::Bracket),
        Tok::RParen => Some(Delimiter::Paren),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::format_source;

    #[test]
    fn canonicalizes_blocks_and_multiline_lists() {
        let source = concat!(
            "plzn tls \"format/me\" {  \r\n",
            "      chain: [default]\r\n",
            " uut client {\r\n",
            "          versions: [\r\n",
            " tls12,\r\n",
            "             tls13\r\n",
            "       ]\r\n",
            " }\r\n",
            "    flow handshake {\r\n",
            "          send AppData\r\n",
            " }\r\n",
            "     expect ok\r\n",
            "}\r\n\r\n",
        );
        let expected = concat!(
            "plzn tls \"format/me\" {\n",
            "  chain: [default]\n",
            "  uut client {\n",
            "    versions: [\n",
            "      tls12,\n",
            "      tls13\n",
            "    ]\n",
            "  }\n",
            "  flow handshake {\n",
            "    send AppData\n",
            "  }\n",
            "  expect ok\n",
            "}\n",
        );
        assert_eq!(format_source("case.plzn", source).unwrap(), expected);
    }

    #[test]
    fn preserves_hanging_list_alignment_and_ignores_delimiters_in_comments_and_strings() {
        let source = concat!(
            "plzn tls \"format/}[hanging\" {\n",
            " matrix {\n",
            "       value in [one, two,\n",
            " three, four]\n",
            " }\n",
            " flow {\n",
            "       # } does not close the flow\n",
            "       send raw \"00\"\n",
            " }\n",
            " expect close\n",
            "}",
        );
        let expected = concat!(
            "plzn tls \"format/}[hanging\" {\n",
            "  matrix {\n",
            "    value in [one, two,\n",
            "              three, four]\n",
            "  }\n",
            "  flow {\n",
            "    # } does not close the flow\n",
            "    send raw \"00\"\n",
            "  }\n",
            "  expect close\n",
            "}\n",
        );
        let formatted = format_source("case.plzn", source).unwrap();
        assert_eq!(formatted, expected);
        assert_eq!(format_source("case.plzn", &formatted).unwrap(), formatted);
    }

    #[test]
    fn refuses_syntactically_invalid_input() {
        let errors = format_source("bad.plzn", "plzn tls \"bad\" {\n").unwrap_err();
        assert!(!errors.is_empty());
    }
}
