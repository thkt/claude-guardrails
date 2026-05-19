use super::{Rule, Severity, Violation, RE_JS_FILE};
use regex::Regex;
use std::sync::LazyLock;

static RE_JWT_DECODE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(jwtDecode|jwt_decode)\s*(?:<[^>]*>)?\s*\(")
        .expect("RE_JWT_DECODE_CALL: invalid regex")
});

static RE_ATOB_SPLIT_DOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\batob\s*\(\s*\w+\s*\.\s*split\s*\(\s*['"]\.['"]"#)
        .expect("RE_ATOB_SPLIT_DOT: invalid regex")
});

static RE_ATOB_TOKEN_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\batob\s*\(\s*\w*(?i:jwt|token)\w*\s*\)")
        .expect("RE_ATOB_TOKEN_VAR: invalid regex")
});

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        let patterns: &[&Regex] = &[&RE_JWT_DECODE_CALL, &RE_ATOB_SPLIT_DOT, &RE_ATOB_TOKEN_VAR];
        let mut violations = Vec::new();
        for &(line_num, line) in lines {
            if patterns.iter().any(|p| p.is_match(line)) {
                violations.push(Violation {
                    rule: super::rule_id::JWT_CLIENT_DECODE.to_owned(),
                    severity: Severity::Medium,
                    fix: "Verify JWT server-side. Client-side decode can be tampered with; use jwtVerify with a signature check.".to_owned(),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                });
            }
        }
        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        if !RULE.file_pattern.is_match(path) {
            return Vec::new();
        }
        RULE.check(content, path, &super::super::non_comment_lines(content))
    }

    #[test]
    fn detects_jwtdecode_camel_call() {
        let v = check("const decoded = jwtDecode(token);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_jwt_decode_snake_call() {
        let v = check("const payload = jwt_decode(accessToken);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_jwtdecode_with_generic_type() {
        let v = check(
            "const decoded = jwtDecode<MyClaims>(token);",
            "/src/auth.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_jwt_verify() {
        assert!(check(
            "const { payload } = await jwtVerify(token, secret);",
            "/src/auth.ts",
        )
        .is_empty());
    }

    #[test]
    fn allows_plain_code() {
        assert!(check("export function main() {}", "/src/auth.ts").is_empty());
    }

    #[test]
    fn detects_atob_split_token_dot() {
        let v = check(
            "const payload = JSON.parse(atob(jwt.split('.')[1]));",
            "/src/auth.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_atob_plain_string() {
        assert!(check("const decoded = atob('SGVsbG8gV29ybGQ=');", "/src/auth.ts",).is_empty());
    }

    #[test]
    fn detects_atob_jwt_variable() {
        let v = check("const data = atob(jwtPayload);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_atob_token_variable() {
        let v = check("const data = atob(tokenString);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_atob_random_variable() {
        assert!(check("const data = atob(imageBase64);", "/src/auth.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check("// jwtDecode(token);", "/src/auth.ts").is_empty());
    }

    #[test]
    fn reports_multiple_violations_on_different_lines() {
        let content = "const a = jwtDecode(t1);\nconst b = jwt_decode(t2);";
        let v = check(content, "/src/auth.ts");
        assert_eq!(v.len(), 2);
    }
}
