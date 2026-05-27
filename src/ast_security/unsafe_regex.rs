use super::SecurityVisitor;
use crate::rules::{rule_id, Severity};
use oxc_ast::ast::RegExpLiteral;

impl SecurityVisitor<'_> {
    pub(super) fn check_unsafe_regex(&mut self, re: &RegExpLiteral) {
        let pattern = re.regex.pattern.text.as_str();
        if has_nested_quantifiers(pattern) {
            self.push_violation(
                rule_id::UNSAFE_REGEX,
                Severity::Medium,
                "Regex has nested quantifiers vulnerable to ReDoS. Simplify or use atomic groups.",
                re.span,
            );
        }
    }
}

/// Skip past `[...]` in a regex pattern. `start` is the byte after `[`.
fn skip_char_class(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == b']' {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

// Group-depth bookkeeping uses a fixed 16-slot stack. Patterns nested
// deeper than 16 groups silently skip the inner-quantifier check (false
// negative); real-world ReDoS patterns rarely exceed that depth, and
// growing to a `Vec` only matters once a concrete pattern shows up.
fn has_nested_quantifiers(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut group_has_quantifier = [false; 16];
    let mut depth: usize = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => {
                let Some(close) = skip_char_class(bytes, i + 1) else {
                    break;
                };
                i = close;
            }
            b'(' => {
                if depth < group_has_quantifier.len() {
                    group_has_quantifier[depth] = false;
                    depth += 1;
                }
                // Skip non-capturing/lookaround modifiers (?:, ?=, ?!, ?<)
                if i + 2 < bytes.len()
                    && bytes[i + 1] == b'?'
                    && matches!(bytes[i + 2], b':' | b'=' | b'!' | b'<')
                {
                    i += 2;
                }
            }
            b')' if depth > 0 => {
                depth -= 1;
                if group_has_quantifier[depth]
                    && i + 1 < bytes.len()
                    && matches!(bytes[i + 1], b'+' | b'*' | b'?' | b'{')
                {
                    return true;
                }
            }
            b'+' | b'*' | b'?' | b'{' if depth > 0 => {
                group_has_quantifier[depth - 1] = true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests;
