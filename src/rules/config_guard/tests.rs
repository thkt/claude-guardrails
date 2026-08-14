use super::*;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from("/repo")
}

fn check_path(file_path: &str) -> Vec<Violation> {
    let root = root();
    check(file_path, Some(&root))
}

// T-479: git root 直下の `.guardrails.json` への編集は Critical の violation になる
#[test]
fn git_root_直下の_guardrails_json_への編集は_critical_の_violation_になる() {
    let v = check_path("/repo/.guardrails.json");

    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[0].rule, rule_id::CONFIG_GUARD);
}

// T-480: `.claude/tools.json` と `.claude-guardrails.json` への編集も Critical の violation になる
#[test]
fn tools_json_と_legacy_config_への編集も_critical_の_violation_になる() {
    for path in ["/repo/.claude/tools.json", "/repo/.claude-guardrails.json"] {
        let v = check_path(path);

        assert_eq!(v.len(), 1, "{path}: {v:?}");
        assert_eq!(v[0].severity, Severity::Critical, "{path}");
    }
}

// T-481: `packages/foo/.guardrails.json` では発火しない
#[test]
fn git_root_の外にある同名ファイルでは発火しない() {
    assert!(check_path("/repo/packages/foo/.guardrails.json").is_empty());
}

// T-482: `my.guardrails.json` では発火しない
#[test]
fn 末尾が一致するだけの別名ファイルでは発火しない() {
    assert!(check_path("/repo/my.guardrails.json").is_empty());
}

// git root が分からないときは発火しない
#[test]
fn git_root_が無いときは発火しない() {
    assert!(check(".guardrails.json", None).is_empty());
}
