//! Shared JavaScript/TypeScript string and comment scanner.
//!
//! Provides unified parsing for:
//! - String literals (single, double, template)
//! - Comments (line `//` and block `/* */`)
//! - Template interpolations `${...}`
//!
//! # Limitations
//!
//! **Regex literals are not supported.** A forward slash `/` triggers comment
//! detection when followed by `/` or `*`. This affects patterns like:
//! - `const pattern = /\d+/g;` — misidentified as line comment
//! - Division followed by `/` or `*` may trigger false detection
//!
//! Fully disambiguating regex from division requires context-aware parsing
//! beyond the scope of this scanner.
//!
//! Note: Tracks ASCII delimiters only. UTF-8 content is handled correctly
//! since multi-byte sequences never contain ASCII delimiter bytes.

pub struct StringScanner<'a> {
    bytes: &'a [u8],
    pub pos: usize,
    pub in_single_quote: bool,
    pub in_double_quote: bool,
    pub in_template: bool,
    pub in_block_comment: bool,
    pub in_line_comment: bool,
    pub template_interp_depth: Vec<i32>,
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

    /// Returns true if currently inside a string literal, comment, or template interpolation.
    /// Note: Template interpolation content IS code, but we track it separately for depth.
    pub fn in_non_code_context(&self) -> bool {
        self.in_single_quote
            || self.in_double_quote
            || self.in_template
            || self.in_block_comment
            || self.in_line_comment
            || !self.template_interp_depth.is_empty()
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
                    *self
                        .template_interp_depth
                        .last_mut()
                        .expect("in interpolation branch") += 1
                }
                b'}' => {
                    let depth = self
                        .template_interp_depth
                        .last_mut()
                        .expect("in interpolation branch");
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

/// Pre-compute line offsets for O(log n) line number lookup.
pub fn build_line_offsets(content: &str) -> Vec<usize> {
    content
        .char_indices()
        .filter_map(|(i, c)| if c == '\n' { Some(i) } else { None })
        .collect()
}

/// Convert byte offset to 1-based line number using binary search.
/// Offsets pointing to newline characters belong to the line ending at that position.
pub fn offset_to_line(offsets: &[usize], offset: usize) -> usize {
    match offsets.binary_search(&offset) {
        Ok(idx) | Err(idx) => idx + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_handles_simple_string() {
        let content = b"'hello'";
        let mut scanner = StringScanner::new(content, 0);

        assert!(!scanner.in_non_code_context());
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
}
