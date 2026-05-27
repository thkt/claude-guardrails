use super::*;
use std::time::Instant;

#[test]
fn fail_open_on_invalid_or_unsupported_input() {
    assert!(check_js("function { invalid syntax !!!").is_empty());
    assert!(check_js("").is_empty());
    assert!(check("body { color: red; }", "/src/styles.css").is_empty());
}

#[test]
fn bidi_rlo_in_code_blocked() {
    let v = check_js("let x = '\u{202E}' + y;");
    assert_eq!(v.len(), 1, "should detect bidi char");
    assert_eq!(v[0].severity, Severity::High);
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn bidi_rli_in_comment_blocked() {
    let v = check_js("// comment with \u{2067} bidi\nlet x = 1;");
    assert_eq!(v.len(), 1, "should detect bidi in comments");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn bidi_rlm_in_string_blocked() {
    let v = check_js("const s = \"hello\u{200F}world\";");
    assert_eq!(v.len(), 1, "should detect bidi in strings");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
}

#[test]
fn no_bidi_safe() {
    assert!(check_js("const x = 1;\nconst y = 2;").is_empty());
}

#[test]
fn multiple_bidi_reports_first() {
    let v = check_js("let a = '\u{202E}';\nlet b = '\u{202D}';");
    assert_eq!(v.len(), 1, "should report only first bidi occurrence");
    assert_eq!(v[0].rule, rule_id::BIDI_CHARACTERS);
    assert_eq!(v[0].line, Some(1), "should report first line");
}

#[test]
fn p1_and_p2_violations_coexist() {
    let code = concat!(
        "exec(userInput);\n",
        "const m = require(variable);\n",
        "const re = /^(a+)+$/;\n",
        "res.json({ stack: err.stack });\n",
        "fs.readFile(userInput, cb);\n",
    );
    let v = check_js(code);
    let rules: Vec<&str> = v.iter().map(|v| v.rule.as_str()).collect();
    assert!(rules.contains(&rule_id::CHILD_PROCESS_INJECTION));
    assert!(rules.contains(&rule_id::NON_LITERAL_REQUIRE));
    assert!(rules.contains(&rule_id::UNSAFE_REGEX));
    assert!(rules.contains(&rule_id::ERR_STACK_EXPOSURE));
    assert!(rules.contains(&rule_id::NON_LITERAL_FS_PATH));
    assert!(v.len() >= 5, "expected at least 5, got {}", v.len());
}

// T-018: nfr001_performance_under_10ms
#[test]
fn nfr001_performance_under_10ms() {
    let content = concat!(
        "const m = require('./ok');\n",
        "const n = require(variable);\n",
        "const re1 = /^(a+)+$/;\n",
        "const re2 = /^\\d+$/;\n",
        "exec('ls -la');\n",
        "exec(userInput);\n",
        "fs.readFile('./config.json', cb);\n",
        "fs.readFile(userInput, cb);\n",
        "res.json({ error: 'oops' });\n",
        "res.json({ stack: err.stack });\n",
        "const s = process.env.JWT_SECRET ?? 'fallback';\n",
        "const id = Math.random().toString(36).substring(2);\n",
        "el.innerHTML = userInput;\n",
        "el.outerHTML = `<span>${x}</span>`;\n",
        "document.write(userInput);\n",
        // TC-006: deeply-nested BinaryExpression to stress is_safe_html_value
        // recursive descent on the safe-static path (all string literals).
        "el.innerHTML = 'a' + 'b' + 'c' + 'd' + 'e' + 'f' + 'g' + 'h' + 'i' + 'j' + 'k' + 'l' + 'm' + 'n' + 'o' + 'p';\n",
        "obj[\"__proto__\"] = userInput;\n",
        "Object.assign(target, JSON.parse(input));\n",
        "_.merge(target, JSON.parse(input));\n",
        "const lookup = styleMap[variant];\n",
        "const token = Math.random();\n",
        "function generateSessionToken() { return Math.random(); }\n",
        "const fixed = Math.random().toFixed(8);\n",
    );
    let start = Instant::now();
    let iterations = 100;
    for _ in 0..iterations {
        let _ = check(content, "/src/app/api/handler/route.ts");
    }
    let elapsed = start.elapsed();
    let per_file_us = elapsed.as_micros() / iterations;
    eprintln!("NFR-001: {per_file_us}us/file ({iterations} iterations)");
    assert!(
        per_file_us < 10_000,
        "AST check exceeded 10ms/file: {per_file_us}us"
    );
}
