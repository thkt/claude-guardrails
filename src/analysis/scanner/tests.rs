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
    assert!(masks.comment[5], "the // opener delimiter must be flagged");
    assert!(masks.comment[6], "the // opener delimiter must be flagged");
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
    // bytes: 0 = 'a', 1 = ' ', 2..4 = "/*", 5..11 = "hidden", 11 = ' ',
    // 12..14 = "*/", 14 = ' ', 15 = 'b'.
    assert!(masks.comment[2], "the /* opener delimiter must be flagged");
    assert!(masks.comment[3], "the /* opener delimiter must be flagged");
    assert!(masks.comment[5], "block comment body must be flagged");
    assert!(masks.comment[13], "the */ closer delimiter must be flagged");
    assert!(!masks.comment[0]);
    assert!(
        !masks.comment[15],
        "byte after block comment returns to code"
    );
}
