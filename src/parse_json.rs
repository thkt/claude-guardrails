use serde::de::DeserializeOwned;

/// Linters may prefix JSON with non-JSON lines (version info, config warnings)
/// and emit either single-line or pretty-printed (multi-line) JSON. Tries full
/// stdout first, then locates the first line that starts with `{` and lets
/// `serde_json`'s streaming parser consume one balanced JSON value from there.
pub fn parse_linter_json<T: DeserializeOwned>(stdout: &str, stderr: &str, tool: &str) -> Option<T> {
    if let Ok(parsed) = serde_json::from_str::<T>(stdout) {
        return Some(parsed);
    }

    let Some(start) = first_json_object_offset(stdout) else {
        if !stdout.is_empty() || !stderr.is_empty() {
            eprintln!("guardrails: {tool}: no JSON in output (may have config issues)");
        }
        if !stderr.is_empty() {
            eprintln!(
                "guardrails: {} stderr: {}",
                tool,
                stderr.lines().next().unwrap_or("")
            );
        }
        return None;
    };

    let mut stream = serde_json::Deserializer::from_str(&stdout[start..]).into_iter::<T>();
    match stream.next() {
        Some(Ok(parsed)) => Some(parsed),
        Some(Err(e)) => {
            eprintln!(
                "guardrails: {tool}: JSON parse error at line {}: {e}",
                e.line()
            );
            None
        }
        None => None,
    }
}

/// Returns the byte offset of the first line whose non-whitespace content begins with `{`.
fn first_json_object_offset(s: &str) -> Option<usize> {
    let mut offset = 0;
    for line in s.split_inclusive('\n') {
        let leading = line.len() - line.trim_start().len();
        if line[leading..].starts_with('{') {
            return Some(offset + leading);
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestOutput {
        value: i32,
    }

    #[test]
    fn parses_clean_json() {
        let result = parse_linter_json::<TestOutput>(r#"{"value": 42}"#, "", "test");
        assert_eq!(result, Some(TestOutput { value: 42 }));
    }

    #[test]
    fn parses_json_with_prefix_lines() {
        let stdout = "Warning: unstable option\n{\"value\": 99}";
        let result = parse_linter_json::<TestOutput>(stdout, "", "test");
        assert_eq!(result, Some(TestOutput { value: 99 }));
    }

    #[test]
    fn returns_none_on_empty_output() {
        let result = parse_linter_json::<TestOutput>("", "", "test");
        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_on_no_json() {
        let result = parse_linter_json::<TestOutput>("just text\nno json", "err", "test");
        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_on_invalid_json_line() {
        let result = parse_linter_json::<TestOutput>("{invalid json}", "", "test");
        assert_eq!(result, None);
    }

    #[test]
    fn parses_pretty_printed_json_after_warnings() {
        let stdout = "Warning: unstable option\n{\n  \"value\": 99\n}\n";
        let result = parse_linter_json::<TestOutput>(stdout, "", "test");
        assert_eq!(result, Some(TestOutput { value: 99 }));
    }

    #[test]
    fn parses_pretty_printed_json_with_nested_object() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Nested {
            inner: TestOutput,
        }
        let stdout = "Warning: foo\n{\n  \"inner\": {\n    \"value\": 7\n  }\n}\n";
        let result = parse_linter_json::<Nested>(stdout, "", "test");
        assert_eq!(
            result,
            Some(Nested {
                inner: TestOutput { value: 7 }
            })
        );
    }
}
