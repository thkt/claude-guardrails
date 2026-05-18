use serde::de::DeserializeOwned;

/// Linters may prefix JSON with non-JSON lines (version info, config warnings).
/// Tries full stdout first, then falls back to the first `{`-prefixed line.
pub fn parse_linter_json<T: DeserializeOwned>(stdout: &str, stderr: &str, tool: &str) -> Option<T> {
    if let Ok(parsed) = serde_json::from_str::<T>(stdout) {
        return Some(parsed);
    }

    let json_str = stdout
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or("");

    if json_str.is_empty() {
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
    }

    match serde_json::from_str::<T>(json_str) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            eprintln!("guardrails: {tool}: JSON parse error: {e}");
            None
        }
    }
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
}
