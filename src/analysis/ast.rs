use crate::analysis::scanner;
use oxc_allocator::Allocator;
use oxc_ast::ast::{ArrowFunctionExpression, Expression, FormalParameters, FunctionBody, Program};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};

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

/// The statically known property key of a computed member access (`obj[key]`):
/// a string literal's value, or a substitution-free template literal's cooked
/// text. Returns `None` for dynamic keys and for an absent cooked value (a
/// template literal with an invalid escape) — a `None` key matches no forbidden
/// token, keeping `obj[expr]` from firing on an unresolvable key (#383).
pub fn static_key<'a>(key: &'a Expression<'a>) -> Option<&'a str> {
    match key {
        Expression::StringLiteral(s) => Some(s.value.as_str()),
        Expression::TemplateLiteral(tl) if tl.expressions.is_empty() => {
            tl.quasis.first()?.value.cooked.as_deref()
        }
        _ => None,
    }
}

/// Unwraps `obj.prop` and `obj[key]` to `(object, name)`. The computed key
/// resolves through `static_key`, so a string literal or a substitution-free
/// template literal key both unwrap; a dynamic key yields `None`.
pub fn member_name<'a>(expr: &'a Expression<'a>) -> Option<(&'a Expression<'a>, &'a str)> {
    match expr {
        Expression::StaticMemberExpression(sme) => Some((&sme.object, sme.property.name.as_str())),
        Expression::ComputedMemberExpression(cme) => {
            static_key(&cme.expression).map(|name| (&cme.object, name))
        }
        _ => None,
    }
}

/// A callback body in both of its arrow forms: the block `(e) => { ... }` and
/// the concise `(e) => expr`. A caller that reads only `FunctionBody` stops
/// seeing concise callbacks; going through this type keeps both inspected.
#[derive(Clone, Copy)]
pub enum CallbackBody<'a, 'b> {
    Block(&'b FunctionBody<'a>),
    Concise(&'b Expression<'a>),
}

impl<'a, 'b> CallbackBody<'a, 'b> {
    /// `None` when the arrow body is neither form, which a parsed arrow function
    /// never is — the caller propagates it rather than panicking.
    pub fn from_arrow(arrow: &'b ArrowFunctionExpression<'a>) -> Option<Self> {
        match arrow.body.as_function_body() {
            Some(body) => Some(Self::Block(body)),
            None => arrow.body.as_expression().map(Self::Concise),
        }
    }

    pub fn span(self) -> Span {
        match self {
            Self::Block(body) => body.span,
            Self::Concise(expr) => expr.span(),
        }
    }

    /// A concise body always evaluates its expression, so it is never empty.
    /// A directive-only block (`() => { 'use strict'; }`) counts as non-empty,
    /// unlike `FunctionBody::is_empty` — it is not the placeholder form callers
    /// exempt.
    pub fn is_empty(self) -> bool {
        matches!(self, Self::Block(body) if body.statements.is_empty())
    }

    pub fn visit_with<V: Visit<'a>>(self, visitor: &mut V) {
        match self {
            Self::Block(body) => visitor.visit_function_body(body),
            Self::Concise(expr) => visitor.visit_expression(expr),
        }
    }
}

/// The parameter list and body of an inline callback, whether written as an
/// arrow or a `function` expression. Returns `None` for any other expression,
/// and for a body-less `function` form such as a TypeScript ambient declaration.
pub fn callable_signature<'a, 'b>(
    expr: &'b Expression<'a>,
) -> Option<(&'b FormalParameters<'a>, CallbackBody<'a, 'b>)> {
    match expr {
        Expression::ArrowFunctionExpression(arrow) => {
            Some((&arrow.params, CallbackBody::from_arrow(arrow)?))
        }
        Expression::FunctionExpression(func) => {
            Some((&func.params, CallbackBody::Block(func.body.as_deref()?)))
        }
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

    // T-383-1 (#383): a string-literal key and a substitution-free template
    // key both resolve to the same text; a substituted template and a dynamic
    // identifier key resolve to None. (cooked=None is not exercised here: an
    // untagged template with an invalid escape is a parse error, not a node.)
    #[test]
    fn static_key_resolves_string_and_static_template_keys() {
        use oxc_ast::ast::Statement;
        fn key_of<'a>(program: &'a Program<'a>) -> &'a Expression<'a> {
            let Statement::ExpressionStatement(stmt) = &program.body[0] else {
                panic!("expected expression statement");
            };
            let Expression::ComputedMemberExpression(cme) = &stmt.expression else {
                panic!("expected computed member expression");
            };
            &cme.expression
        }
        for (src, expected) in [
            (r#"o["x"];"#, Some("x")),
            ("o[`x`];", Some("x")),
            ("o[`${e}`];", None),
            ("o[prop];", None),
        ] {
            with_parsed_program(src, "/t.ts", |p, _| {
                assert_eq!(static_key(key_of(p)), expected, "failed for: {src}");
            });
        }
    }
}
