//! JS/TS string and comment scanner.
//!
//! # Limitations
//!
//! **Regex literals are not supported.** `/` triggers comment detection when
//! followed by `/` or `*` (e.g., `/\d+/g` is misidentified as line comment).
//! Disambiguating regex from division requires context-aware parsing beyond
//! this scanner's scope.

pub struct StringScanner<'a> {
    bytes: &'a [u8],
    pub(crate) pos: usize,
    pub(crate) in_single_quote: bool,
    pub(crate) in_double_quote: bool,
    pub(crate) in_template: bool,
    pub(crate) in_block_comment: bool,
    pub(crate) in_line_comment: bool,
    pub(crate) template_interp_depth: Vec<i32>,
}

impl<'a> StringScanner<'a> {
    pub fn new(bytes: &'a [u8], start: usize) -> Self {
        Self {
            bytes,
            pos: start,
            in_single_quote: false,
            in_double_quote: false,
            in_template: false,
            in_block_comment: false,
            in_line_comment: false,
            template_interp_depth: Vec::new(),
        }
    }

    /// Template interpolation (`${...}`) returns false because it contains executable code.
    pub fn in_string_or_comment(&self) -> bool {
        self.in_single_quote
            || self.in_double_quote
            || self.in_template
            || self.in_block_comment
            || self.in_line_comment
    }

    /// Also skips interpolation-closing braces (depth 1 + `}`).
    pub fn skip_for_bracket_matching(&self) -> bool {
        if self.in_string_or_comment() {
            return true;
        }
        if let Some(&depth) = self.template_interp_depth.last() {
            if depth == 1 && self.current() == Some(b'}') {
                return true;
            }
        }
        false
    }

    pub fn current(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos + 1).copied()
    }

    /// Advance scanner, handling strings/comments. Returns true if advanced.
    pub fn advance(&mut self) -> bool {
        if self.pos >= self.bytes.len() {
            return false;
        }

        let byte = self.bytes[self.pos];
        let next = self.peek();

        if self.in_line_comment {
            if byte == b'\n' {
                self.in_line_comment = false;
            }
            self.pos += 1;
            return true;
        }

        if self.in_block_comment {
            if byte == b'*' && next == Some(b'/') {
                self.in_block_comment = false;
                self.pos += 2;
            } else {
                self.pos += 1;
            }
            return true;
        }

        if !self.template_interp_depth.is_empty() {
            if (self.in_single_quote || self.in_double_quote)
                && byte == b'\\'
                && self.pos + 1 < self.bytes.len()
            {
                self.pos += 2;
                return true;
            }
            if self.in_single_quote {
                if byte == b'\'' {
                    self.in_single_quote = false;
                }
                self.pos += 1;
                return true;
            }
            if self.in_double_quote {
                if byte == b'"' {
                    self.in_double_quote = false;
                }
                self.pos += 1;
                return true;
            }
            match byte {
                b'{' => {
                    // SAFETY: outer `if !self.template_interp_depth.is_empty()`
                    // guards entry; the stack stays non-empty until the matching
                    // `}` pops it.
                    *self.template_interp_depth.last_mut().expect(
                        "scanner: template_interp_depth non-empty in interpolation branch",
                    ) += 1;
                }
                b'}' => {
                    // SAFETY: same invariant as the `{` arm — interpolation
                    // depth stack is non-empty within this branch.
                    let depth = self
                        .template_interp_depth
                        .last_mut()
                        .expect("scanner: template_interp_depth non-empty in interpolation branch");
                    *depth -= 1;
                    if *depth == 0 {
                        self.template_interp_depth.pop();
                        self.in_template = true;
                    }
                }
                b'\'' => self.in_single_quote = true,
                b'"' => self.in_double_quote = true,
                b'`' => self.in_template = true,
                _ => {}
            }
            self.pos += 1;
            return true;
        }

        if self.in_single_quote || self.in_double_quote || self.in_template {
            if byte == b'\\' {
                self.pos += if self.pos + 1 < self.bytes.len() {
                    2
                } else {
                    1
                };
                return true;
            }
            if self.in_single_quote && byte == b'\'' {
                self.in_single_quote = false;
            } else if self.in_double_quote && byte == b'"' {
                self.in_double_quote = false;
            } else if self.in_template {
                if byte == b'`' {
                    self.in_template = false;
                } else if byte == b'$' && next == Some(b'{') {
                    self.in_template = false;
                    self.template_interp_depth.push(1);
                    self.pos += 2;
                    return true;
                }
            }
            self.pos += 1;
            return true;
        }

        match byte {
            b'\'' => self.in_single_quote = true,
            b'"' => self.in_double_quote = true,
            b'`' => self.in_template = true,
            b'/' if next == Some(b'/') => {
                self.in_line_comment = true;
                self.pos += 2;
                return true;
            }
            b'/' if next == Some(b'*') => {
                self.in_block_comment = true;
                self.pos += 2;
                return true;
            }
            _ => {}
        }

        self.pos += 1;
        true
    }
}

pub fn extract_delimited_range(
    content: &str,
    start: usize,
    open: u8,
    close: u8,
) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    let mut scanner = StringScanner::new(bytes, start);
    let mut depth = 1;

    while scanner.pos < bytes.len() && depth > 0 {
        let skip = scanner.skip_for_bracket_matching();
        let byte = scanner.current();
        scanner.advance();

        if !skip {
            match byte {
                Some(b) if b == open => depth += 1,
                Some(b) if b == close => depth -= 1,
                _ => {}
            }
        }
    }

    if depth == 0 {
        Some((start, scanner.pos - 1))
    } else {
        None
    }
}

pub fn extract_delimited_content(content: &str, start: usize, open: u8, close: u8) -> Option<&str> {
    extract_delimited_range(content, start, open, close).map(|(s, e)| &content[s..e])
}

/// Pre-compute line offsets for O(log n) line number lookup.
pub fn build_line_offsets(content: &str) -> Vec<usize> {
    content
        .as_bytes()
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| if b == b'\n' { Some(i) } else { None })
        .collect()
}

/// Per-byte classification of source. Built in a single pass so callers can
/// replace per-position rescans (O(n) each) with O(1) lookups.
///
/// - `comment[i]` is true when byte `i` is inside a `//` or `/* */` comment.
/// - `code_visible[i]` keeps the original byte when `i` is code, otherwise
///   ASCII space (`0x20`). Template interpolation (`${...}`) content stays
///   code. Multi-byte string/comment content is preserved at byte level by
///   replacing each byte individually; UTF-8 validity is maintained because
///   ASCII space is a single-byte ASCII codepoint.
pub struct SourceMasks {
    pub comment: Vec<bool>,
    pub code_visible: Vec<u8>,
}

pub fn build_source_masks(content: &str) -> SourceMasks {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut comment = vec![false; len];
    let mut code_visible = bytes.to_vec();
    let mut scanner = StringScanner::new(bytes, 0);

    while scanner.pos < len {
        let start = scanner.pos;
        let in_interp = !scanner.template_interp_depth.is_empty()
            && !scanner.in_single_quote
            && !scanner.in_double_quote;
        let in_comment_now = scanner.in_block_comment || scanner.in_line_comment;
        let in_string_now =
            scanner.in_single_quote || scanner.in_double_quote || scanner.in_template;
        let hide = (in_string_now || in_comment_now) && !in_interp;

        scanner.advance();
        let end = scanner.pos.min(len);

        for i in start..end {
            comment[i] = in_comment_now;
            if hide {
                code_visible[i] = b' ';
            }
        }
    }

    SourceMasks {
        comment,
        code_visible,
    }
}

/// Offsets on newline characters belong to the line ending at that position.
pub fn offset_to_line(offsets: &[usize], offset: usize) -> usize {
    match offsets.binary_search(&offset) {
        Ok(idx) | Err(idx) => idx + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn scanner_handles_simple_string() {
        let content = b"'hello'";
        let mut scanner = StringScanner::new(content, 0);

        assert!(!scanner.in_string_or_comment());
        scanner.advance(); // '
        assert!(scanner.in_single_quote);
        while scanner.pos < content.len() {
            scanner.advance();
        }
        assert!(!scanner.in_single_quote);
    }

    #[test]
    fn scanner_handles_block_comment() {
        let content = b"/* comment */code";
        let mut scanner = StringScanner::new(content, 0);

        scanner.advance(); // /* (advances by 2)
        assert!(scanner.in_block_comment);
        while scanner.in_block_comment && scanner.pos < content.len() {
            scanner.advance();
        }
        assert!(!scanner.in_block_comment);
        assert_eq!(scanner.pos, 13); // After */ (pointing to 'c' in code)
    }

    #[test]
    fn scanner_handles_template_interpolation() {
        let content = b"`${x}`";
        let mut scanner = StringScanner::new(content, 0);

        scanner.advance(); // ` (pos=1)
        assert!(scanner.in_template);
        scanner.advance(); // ${ (advances by 2, pos=3, enters interpolation)
        assert!(!scanner.template_interp_depth.is_empty());
        assert!(!scanner.in_template); // Template paused during interpolation
        scanner.advance(); // x (pos=4)
        scanner.advance(); // } (pos=5, exits interpolation, resumes template)
        assert!(scanner.in_template);
        scanner.advance(); // ` (pos=6, exits template)
        assert!(!scanner.in_template);
    }

    #[test]
    fn scanner_handles_line_comment() {
        let content = b"// comment\ncode";
        let mut scanner = StringScanner::new(content, 0);

        scanner.advance(); // // (advances by 2)
        assert!(scanner.in_line_comment);
        while scanner.in_line_comment && scanner.pos < content.len() {
            scanner.advance();
        }
        assert!(!scanner.in_line_comment);
        assert_eq!(scanner.pos, 11); // After \n (pointing to 'c' in code)
    }

    #[test]
    fn line_offsets_work() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        assert_eq!(offset_to_line(&offsets, 0), 1);
        assert_eq!(offset_to_line(&offsets, 6), 2);
        assert_eq!(offset_to_line(&offsets, 12), 3);
    }

    #[test]
    fn escape_at_end_of_input() {
        let content = b"'\\";
        let mut scanner = StringScanner::new(content, 0);
        scanner.advance(); // '
        scanner.advance(); // \ (should not panic)
        assert!(scanner.pos <= content.len());
    }

    #[test]
    fn extract_delimited_balanced_braces() {
        let content = "{ a + b }";
        assert_eq!(
            extract_delimited_content(content, 1, b'{', b'}'),
            Some(" a + b ")
        );
    }

    #[test]
    fn extract_delimited_nested() {
        let content = "{ if (x) { y } }";
        assert_eq!(
            extract_delimited_content(content, 1, b'{', b'}'),
            Some(" if (x) { y } ")
        );
    }

    #[test]
    fn extract_delimited_unmatched_returns_none() {
        let content = "{ unclosed";
        assert_eq!(extract_delimited_content(content, 1, b'{', b'}'), None);
    }

    #[test]
    fn extract_delimited_parens() {
        let content = "(a, b, c)";
        assert_eq!(
            extract_delimited_content(content, 1, b'(', b')'),
            Some("a, b, c")
        );
    }

    #[test]
    fn extract_delimited_skips_string_braces() {
        let content = r#"{ "}" + x }"#;
        let result = extract_delimited_content(content, 1, b'{', b'}');
        assert_eq!(result, Some(r#" "}" + x "#));
    }

    #[test]
    fn source_masks_flag_line_comment_bytes() {
        let masks = build_source_masks("code\n// hidden\nmore");
        // bytes: 0..4 = "code", 4 = '\n', 5..7 = "//", 7..14 = " hidden",
        // 14 = '\n' (still inside line comment until consumed), 15..19 = "more".
        assert!(!masks.comment[0]);
        assert!(!masks.comment[4]);
        assert!(masks.comment[7], "byte inside // comment must be flagged");
        assert!(!masks.comment[15], "first byte after the newline is code");
    }

    #[test]
    fn source_masks_hide_string_content() {
        let masks = build_source_masks("let x = 'secret';");
        let visible = str::from_utf8(&masks.code_visible).expect("valid utf8");
        // Quote delimiters remain code (the scanner flips state on the byte
        // following the quote), only the body and the closing quote — which
        // is observed while still inside the string — are blanked.
        assert_eq!(visible, "let x = '       ;");
    }

    #[test]
    fn source_masks_preserve_template_interpolation_as_code() {
        let masks = build_source_masks("`${name}`");
        let visible = str::from_utf8(&masks.code_visible).expect("valid utf8");
        // backticks and template literal frame are hidden; ${name} body is code.
        assert!(visible.contains("name"));
    }

    #[test]
    fn source_masks_flag_block_comment_bytes() {
        let masks = build_source_masks("a /* hidden */ b");
        assert!(masks.comment[5], "block comment body must be flagged");
        assert!(!masks.comment[0]);
        assert!(
            !masks.comment[15],
            "byte after block comment returns to code"
        );
    }
}
