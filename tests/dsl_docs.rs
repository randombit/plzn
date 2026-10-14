//! Keep the language reference's complete examples on the public lint pipeline.

#[test]
fn dsl_reference_examples_lint_clean() {
    let markdown = include_str!("../docs/DSL.md");
    let mut example = None;
    let mut count = 0;

    for (index, line) in markdown.lines().enumerate() {
        if line == "```plzn" {
            assert!(example.is_none(), "nested example at line {}", index + 1);
            example = Some((index + 2, String::new()));
        } else if line == "```" && example.is_some() {
            let (start, source) = example.take().unwrap();
            assert!(!source.trim().is_empty(), "empty example at line {start}");
            let name = format!("docs/DSL.md:{start}");
            let diags = plzn::lint(&name, &source);
            assert!(
                diags.is_empty(),
                "{name} failed to lint:\n{}",
                diags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            count += 1;
        } else if let Some((_, source)) = example.as_mut() {
            source.push_str(line);
            source.push('\n');
        }
    }

    assert!(example.is_none(), "unclosed plzn example");
    assert!(
        count > 0,
        "no complete plzn examples in the language reference"
    );
}
