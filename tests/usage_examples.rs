use std::path::PathBuf;

fn usage_blocks() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("USAGE.md");
    let source = std::fs::read_to_string(&path).expect("read docs/USAGE.md");
    let mut blocks = Vec::new();
    let mut current = None::<String>;

    for line in source.lines() {
        if line.starts_with("```") {
            if let Some(block) = current.take() {
                if block.contains("plzn tls \"usage/") {
                    blocks.push(block);
                }
            } else {
                current = Some(String::new());
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    blocks
}

#[test]
fn every_usage_example_lints_clean() {
    let blocks = usage_blocks();
    assert!(
        blocks.len() >= 15,
        "expected at least 15 executable usage blocks, found {}",
        blocks.len()
    );
    let mut failures = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let name = format!("docs/USAGE.md block {}", index + 1);
        let diagnostics = plzn::lint(&name, block);
        if !diagnostics.is_empty() {
            let rendered = diagnostics
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            failures.push(format!(
                "{name} does not lint clean:\n{rendered}\n\n{block}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n---\n\n"));
}
