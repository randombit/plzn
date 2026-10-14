// Human-readable diagnostics with file:line:col and a visual caret.
//
// Design goal (DSL.md §3.11): every error is self-explanatory without
// needing to read plzn source. That means: where in the file, what we
// expected, what we saw, and — when relevant — the closest valid name.

use crate::ast::Span;
use std::fmt;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Diag {
    pub source_name: String,
    pub line: usize,
    pub col: usize,
    pub excerpt: String,
    pub caret: String,
    pub category: String,
    pub message: String,
    pub suggestions: Vec<String>,
}

impl Diag {
    pub fn from_simple(
        source_name: &str,
        source: &str,
        span: Span,
        category: &str,
        message: String,
    ) -> Self {
        Self::new(source_name, source, span, category, message, vec![])
    }

    pub fn new(
        source_name: &str,
        source: &str,
        span: Span,
        category: &str,
        message: String,
        suggestions: Vec<String>,
    ) -> Self {
        let (line, col, excerpt, caret) = locate(source, span);
        Self {
            source_name: source_name.to_string(),
            line,
            col,
            excerpt,
            caret,
            category: category.to_string(),
            message,
            suggestions,
        }
    }
}

impl fmt::Display for Diag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}:{}:{}: {}: {}",
            self.source_name, self.line, self.col, self.category, self.message
        )?;
        if !self.excerpt.is_empty() {
            writeln!(f, "    {}", self.excerpt)?;
            writeln!(f, "    {}", self.caret)?;
        }
        for s in &self.suggestions {
            writeln!(f, "    help: {}", s)?;
        }
        Ok(())
    }
}

fn locate(source: &str, span: Span) -> (usize, usize, String, String) {
    let start = span.start.min(source.len());
    let end = span.end.min(source.len());
    let bytes = source.as_bytes();

    // Line number + line start offset.
    let mut line = 1usize;
    let mut line_start = 0usize;
    for i in 0..start {
        if bytes.get(i) == Some(&b'\n') {
            line += 1;
            line_start = i + 1;
        }
    }
    let col = start - line_start + 1;

    // Extract the line (up to the next newline or EOF).
    let mut line_end = line_start;
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    let excerpt = String::from_utf8_lossy(&bytes[line_start..line_end]).into_owned();

    // Caret underline aligned to col, width = span length (min 1).
    let width = end.saturating_sub(start).max(1);
    let pad = " ".repeat(col.saturating_sub(1));
    let bar = "^".repeat(width);
    let caret = format!("{}{}", pad, bar);

    (line, col, excerpt, caret)
}

/// Return up to 3 identifiers from `candidates` closest to `input`.
/// Uses Levenshtein with early-out; candidate list is small (<500).
pub fn suggestions(input: &str, candidates: &[&str]) -> Vec<String> {
    let mut scored: Vec<(usize, &str)> = candidates
        .iter()
        .filter_map(|c| {
            let d = levenshtein(input, c);
            if d <= (input.len().max(c.len())) / 2 + 1 {
                Some((d, *c))
            } else {
                None
            }
        })
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored
        .into_iter()
        .take(3)
        .map(|(_, c)| format!("did you mean `{}`?", c))
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggest_near_miss() {
        let s = suggestions("tls13", &["tls12", "tls13", "dtls12", "dtls13"]);
        assert!(s.iter().any(|x| x.contains("tls13")));
    }

    #[test]
    fn locate_finds_line_col() {
        let src = "line one\nline two\nline three\n";
        let span = Span::new(9, 13); // "line" on line 2
        let (l, c, excerpt, _) = locate(src, span);
        assert_eq!(l, 2);
        assert_eq!(c, 1);
        assert_eq!(excerpt, "line two");
    }
}
