use super::{rule_id, Severity, Violation, RE_REACT_FILE};
use crate::analysis::ast;
use oxc_ast::ast::{CallExpression, Expression, Program, Span};
use oxc_ast_visit::{walk, Visit};

const FIX_MESSAGE: &str = "Avoid useEffect. Consider: \
    (1) derived state with useMemo/computation in render, \
    (2) data-fetching library (TanStack Query, SWR), \
    (3) event handler, \
    (4) useMountEffect for one-time setup, \
    (5) key prop to reset component state.";

#[cfg(test)]
fn check(content: &str, file_path: &str) -> Vec<Violation> {
    super::test_check_program(content, file_path, check_program)
}

#[cfg(test)]
fn check_fail_open(content: &str, file_path: &str) -> Vec<Violation> {
    super::test_check_program_fail_open(content, file_path, check_program)
}

pub fn check_program(
    program: &Program<'_>,
    line_offsets: &[usize],
    file_path: &str,
) -> Vec<Violation> {
    if !RE_REACT_FILE.is_match(file_path) {
        return Vec::new();
    }

    let mut visitor = UseEffectVisitor {
        violation: None,
        file_path,
        line_offsets,
    };
    visitor.visit_program(program);
    visitor.violation.into_iter().collect()
}

struct UseEffectVisitor<'s> {
    violation: Option<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
}

impl UseEffectVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        ast::span_to_line(self.line_offsets, span)
    }
}

impl<'a> Visit<'a> for UseEffectVisitor<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.violation.is_none() && is_use_effect_callee(&call.callee) {
            self.violation = Some(Violation {
                rule: rule_id::NO_USE_EFFECT.to_owned(),
                severity: Severity::Medium,
                fix: FIX_MESSAGE.to_owned(),
                file: self.file_path.to_owned(),
                line: Some(self.span_to_line(call.span)),
            });
            return;
        }
        walk::walk_call_expression(self, call);
    }
}

fn is_use_effect_callee(callee: &Expression) -> bool {
    match callee {
        Expression::Identifier(id) => id.name == "useEffect",
        Expression::StaticMemberExpression(sme) => sme.property.name == "useEffect",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_use_effect_call() {
        let v = check("useEffect(() => { fetchData(); }, []);", "/src/App.tsx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, "no-use-effect");
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_jsx_file() {
        let v = check("useEffect(() => {}, []);", "/src/App.jsx");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_react_dot_use_effect() {
        let v = check("React.useEffect(() => {}, []);", "/src/App.tsx");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_use_mount_effect() {
        assert!(check("useMountEffect(() => { init(); });", "/src/App.tsx").is_empty());
    }

    #[test]
    fn allows_use_layout_effect() {
        assert!(check("useLayoutEffect(() => { measure(); }, []);", "/src/App.tsx").is_empty());
    }

    #[test]
    fn allows_non_react_files() {
        assert!(check("useEffect(() => {}, []);", "/src/hooks/utils.ts").is_empty());
        assert!(check("useEffect(() => {}, []);", "/src/lib/helper.js").is_empty());
    }

    #[test]
    fn ignores_comments() {
        assert!(check("// useEffect(() => {}, []);\nconst x = 1;", "/src/App.tsx").is_empty());
    }

    #[test]
    fn ignores_block_comments() {
        assert!(check(
            "/*\nuseEffect(() => {}, []);\n*/\nconst x = 1;",
            "/src/App.tsx"
        )
        .is_empty());
    }

    #[test]
    fn ignores_string_literal() {
        assert!(check(r#"const s = "useEffect(() => {})";"#, "/src/App.tsx").is_empty());
    }

    #[test]
    fn reports_first_occurrence_only() {
        let v = check(
            "useEffect(() => {}, []);\nuseEffect(() => {}, [id]);",
            "/src/App.tsx",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(1));
    }

    #[test]
    fn invalid_syntax_fail_open() {
        assert!(check_fail_open("function { invalid !!!", "/src/App.tsx").is_empty());
    }

    #[test]
    fn empty_file() {
        assert!(check("", "/src/App.tsx").is_empty());
    }
}
