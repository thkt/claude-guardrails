use crate::analysis::scanner;
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, Program};
use oxc_parser::Parser;
use oxc_span::{SourceType, Span};

/// Returns None on unsupported file type or parser panic (fail-open).
pub fn with_parsed_program<R>(
    content: &str,
    file_path: &str,
    f: impl FnOnce(&Program<'_>, &[usize]) -> R,
) -> Option<R> {
    let source_type = SourceType::from_path(file_path).ok()?;
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, content, source_type).parse();
    if ret.panicked {
        eprintln!("guardrails: ast: parser panicked on {file_path}");
        return None;
    }
    let line_offsets = scanner::build_line_offsets(content);
    Some(f(&ret.program, &line_offsets))
}

// MAX_INPUT_SIZE caps stdin and on-disk reads at 10 MB (see main.rs), so
// line numbers stay well under u32::MAX. `as u32` cannot truncate within
// that bound.
#[allow(clippy::cast_possible_truncation)]
pub fn span_to_line(offsets: &[usize], span: Span) -> u32 {
    scanner::offset_to_line(offsets, span.start as usize) as u32
}

pub fn is_ident(expr: &Expression, name: &str) -> bool {
    matches!(expr, Expression::Identifier(id) if id.name == name)
}

pub fn is_static_template_literal(expr: &Expression) -> bool {
    matches!(expr, Expression::TemplateLiteral(tl) if tl.expressions.is_empty())
}

/// Unwraps `obj.prop` and `obj["prop"]` (string-literal key only) to `(object, name)`.
pub fn member_name<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    match expr {
        Expression::StaticMemberExpression(sme) => Some((&sme.object, sme.property.name.as_str())),
        Expression::ComputedMemberExpression(cme) => match &cme.expression {
            Expression::StringLiteral(s) => Some((&cme.object, s.value.as_str())),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_js() {
        let result = with_parsed_program("const x = 1;", "/test.ts", |_, _| 42);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn returns_none_for_unsupported_type() {
        assert_eq!(
            with_parsed_program("body{}", "/styles.css", |_, _| 42),
            None,
        );
    }

    #[test]
    fn span_to_line_basic() {
        let offsets = scanner::build_line_offsets("line1\nline2\nline3");
        assert_eq!(span_to_line(&offsets, Span::new(0, 5)), 1);
        assert_eq!(span_to_line(&offsets, Span::new(6, 11)), 2);
        assert_eq!(span_to_line(&offsets, Span::new(12, 17)), 3);
    }
}
