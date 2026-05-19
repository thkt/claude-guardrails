use regex::Regex;

/// Compiles a `Regex` from a build-time literal, panicking with a symbol-tagged
/// diagnostic on failure. The `name` argument should match the `static` symbol
/// (or other call-site identifier) so a panic trace pinpoints the culprit.
pub(crate) fn regex_or_die(name: &str, pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("{name}: invalid regex: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_valid_pattern() {
        let re = regex_or_die("TEST", r"^foo");
        assert!(re.is_match("foobar"));
    }

    #[test]
    #[should_panic(expected = "TEST: invalid regex")]
    fn panics_with_symbol_tag_on_invalid_pattern() {
        let _ = regex_or_die("TEST", r"(unclosed");
    }
}
