use super::{Rule, Severity, Violation};
use regex::Regex;
use std::sync::LazyLock;

static FILE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\.github/workflows/[^/]+\.ya?ml|(?:^|/)action\.ya?ml)$")
        .expect("FILE_PATTERN: invalid regex")
});

static EXPRESSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{\{([^}]*)\}\}").expect("EXPRESSION: invalid regex"));

static KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:-\s+)?(run|script):\s*(.*)$").expect("KEY: invalid regex"));

/// Per actionlint's `untrusted-inputs` check
/// (https://github.com/rhysd/actionlint/blob/main/docs/checks.md#untrusted-inputs).
/// Substring match catches direct access, `toJSON(...)`, and object filter
/// (`github.event.*.body`) at the cost of false positives via `contains(...)`.
const UNTRUSTED_PATTERNS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
];

const DOCS_URL: &str = "https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks";

pub fn rule() -> Rule {
    Rule {
        file_pattern: FILE_PATTERN.clone(),
        checker: Box::new(|content: &str, file_path: &str, _lines: &[(u32, &str)]| {
            scan(content, file_path)
        }),
    }
}

fn scan(content: &str, file_path: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut block_indent: Option<usize> = None;

    for (idx, line) in content.lines().enumerate() {
        let line_num = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();

        if let Some(key_indent) = block_indent {
            let inside_block =
                trimmed.is_empty() || trimmed.starts_with('#') || indent > key_indent;
            if inside_block {
                check_expressions(line, line_num, file_path, &mut violations);
                continue;
            }
            block_indent = None;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(caps) = KEY.captures(trimmed) else {
            continue;
        };
        let value = caps.get(2).map_or("", |m| m.as_str()).trim();
        if is_block_scalar_indicator(value) {
            block_indent = Some(indent);
        } else if !value.is_empty() {
            check_expressions(value, line_num, file_path, &mut violations);
        }
    }

    violations
}

fn is_block_scalar_indicator(value: &str) -> bool {
    value.starts_with('|') || value.starts_with('>')
}

fn check_expressions(text: &str, line_num: u32, file_path: &str, violations: &mut Vec<Violation>) {
    for cap in EXPRESSION.captures_iter(text) {
        let Some(inner) = cap.get(1) else { continue };
        let body = inner.as_str();
        for pattern in UNTRUSTED_PATTERNS {
            if body.contains(pattern) {
                violations.push(Violation {
                    rule: super::rule_id::EXPRESSION_INJECTION.to_owned(),
                    severity: Severity::Critical,
                    fix: format!(
                        "Untrusted GitHub context '{}' used in run:/script:. Pass via env: variable instead. {}",
                        pattern, DOCS_URL
                    ),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                });
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path, &super::super::non_comment_lines(content))
    }

    const WF: &str = ".github/workflows/test.yml";

    // T-001: inline run: with untrusted context
    #[test]
    fn detects_inline_run_with_untrusted() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
        assert_eq!(v[0].rule, "expression-injection");
        assert_eq!(v[0].line, Some(4));
        assert!(v[0].fix.contains("github.event.pull_request.title"));
    }

    // T-002: literal block scalar `run: |` with untrusted inside
    #[test]
    fn detects_block_scalar_pipe() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.body }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(5));
    }

    // T-003: folded block scalar `run: >` with untrusted inside
    #[test]
    fn detects_block_scalar_folded() {
        let yaml =
            "jobs:\n  t:\n    steps:\n      - run: >\n          echo \"${{ github.head_ref }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(5));
    }

    // T-004: env: with untrusted is not flagged (env is the safe pattern)
    #[test]
    fn ignores_env_assignment() {
        let yaml = "jobs:\n  t:\n    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n";
        let v = check(yaml, WF);
        assert!(
            v.is_empty(),
            "env: assignment is the safe pattern; should not flag: {:?}",
            v
        );
    }

    // T-005: secrets context inside run: is safe
    #[test]
    fn ignores_secrets_in_run() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: gh auth login --with-token ${{ secrets.GITHUB_TOKEN }}\n";
        assert!(check(yaml, WF).is_empty());
    }

    // T-006: matrix / steps / needs / env contexts in run: are safe
    #[test]
    fn ignores_safe_contexts_in_run() {
        let cases = [
            "      - run: echo ${{ matrix.os }}",
            "      - run: echo ${{ steps.x.outputs.y }}",
            "      - run: echo ${{ needs.build.outputs.version }}",
            "      - run: echo ${{ env.FOO }}",
            "      - run: echo ${{ inputs.name }}",
            "      - run: echo ${{ github.ref_name }}",
            "      - run: echo ${{ github.sha }}",
        ];
        for line in cases {
            let yaml = format!("jobs:\n  t:\n    steps:\n{}\n", line);
            assert!(
                check(&yaml, WF).is_empty(),
                "safe context must not flag: {}",
                line
            );
        }
    }

    // T-007: if: key with untrusted context is not flagged (run only)
    #[test]
    fn ignores_if_key() {
        let yaml = "jobs:\n  t:\n    steps:\n      - if: ${{ github.event.pull_request.title == 'release' }}\n        run: cargo build\n";
        let v = check(yaml, WF);
        assert!(v.is_empty(), "if: key must not flag: {:?}", v);
    }

    // T-008: files outside .github/workflows/ and not action.yml are out of scope
    #[test]
    fn ignores_files_outside_scope() {
        let yaml = "- run: echo ${{ github.event.issue.title }}\n";
        for path in [
            "/src/app.ts",
            "/docs/readme.md",
            "/scripts/build.yml",
            "/config/app.yaml",
            "/.github/dependabot.yml",
            "/.github/ISSUE_TEMPLATE/bug.yml",
        ] {
            assert!(
                check(yaml, path).is_empty(),
                "out of scope path must not flag: {}",
                path
            );
        }
    }

    // T-009: block scalar ends when indent dedents
    #[test]
    fn block_scalar_ends_at_dedent() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: |\n          echo safe\n      - name: next\n        run: echo \"${{ github.event.issue.title }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1, "only the second step should flag");
        assert_eq!(v[0].line, Some(7));
    }

    // T-010: multiple violations across steps are all reported with correct line numbers
    #[test]
    fn reports_multiple_violations_with_line_numbers() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n      - run: |\n          echo \"${{ github.head_ref }}\"\n          echo \"${{ github.event.comment.body }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].line, Some(4));
        assert_eq!(v[1].line, Some(6));
        assert_eq!(v[2].line, Some(7));
    }

    // T-011: composite action.yml is in scope (runs.steps[].run)
    #[test]
    fn detects_in_composite_action_yml() {
        let yaml = "runs:\n  using: composite\n  steps:\n    - run: echo \"${{ github.event.pull_request.body }}\"\n      shell: bash\n";
        for path in ["/repo/action.yml", "/repo/path/to/action.yaml"] {
            let v = check(yaml, path);
            assert_eq!(v.len(), 1, "composite action.yml must flag: {}", path);
        }
    }

    // T-012: actions/github-script with: script: is in scope
    #[test]
    fn detects_in_github_script_with_script_key() {
        let yaml = "jobs:\n  t:\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log('${{ github.head_ref }}')\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(7));
    }

    // T-013: object filter `github.event.*.body` is caught by substring match
    #[test]
    fn detects_object_filter_via_substring() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: echo \"${{ toJSON(github.event.comment.body) }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1, "toJSON(...) wrapping untrusted must still flag");
    }

    // T-014: contains(...) with untrusted is also flagged (known limitation: actionlint treats this as safe)
    #[test]
    fn known_limitation_contains_is_flagged() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: if [ \"${{ contains(github.event.pull_request.title, '[skip]') }}\" = \"true\" ]; then exit 0; fi\n";
        let v = check(yaml, WF);
        assert_eq!(
            v.len(),
            1,
            "guardrails errs on the safe side: contains() wrapping is still flagged"
        );
    }

    // T-015: .yaml extension is also covered
    #[test]
    fn covers_yaml_extension() {
        let yaml =
            "jobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n";
        let v = check(yaml, ".github/workflows/ci.yaml");
        assert_eq!(v.len(), 1);
    }

    // T-016: YAML comment line inside block scalar is still scanned for safety
    #[test]
    fn comment_inside_block_scalar_does_not_break_state() {
        let yaml = "jobs:\n  t:\n    steps:\n      - run: |\n          # benign comment\n          echo \"${{ github.event.issue.title }}\"\n";
        let v = check(yaml, WF);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(6));
    }
}
