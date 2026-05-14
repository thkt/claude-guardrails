use super::{count_matches_in_lines, find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use regex::Regex;
use std::sync::LazyLock;

static RE_TARGET_DIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"/(usecases?|use-cases?|application|services?|domain|handlers?|app|server)/|(^|/)(app|pages)/api/|(^|/)app/.*/route\.[jt]sx?$",
    )
    .expect("RE_TARGET_DIR: invalid regex")
});

static RE_WRITE_OPS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.(save|create|update|delete|insert|persist)\s*\(")
        .expect("RE_WRITE_OPS: invalid regex")
});

static RE_TX_BOUNDARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(@Transactional|\btransaction\b|\$transaction|\bunitOfWork\b|\brunInTransaction\b|\bwithTransaction\b|\bbeginTransaction\b|\bQueryRunner\b|\bgetManager\b|knex\.transaction|sequelize\.transaction|db\.transaction)",
    )
    .expect("RE_TX_BOUNDARY: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
            if !RE_TARGET_DIR.is_match(file_path) {
                return Vec::new();
            }

            let write_count = count_matches_in_lines(lines, &RE_WRITE_OPS);
            if write_count < 2 {
                return Vec::new();
            }

            if find_match_in_lines(lines, &RE_TX_BOUNDARY).is_some() {
                return Vec::new();
            }

            vec![Violation {
                rule: super::rule_id::TRANSACTION_BOUNDARY.to_owned(),
                severity: Severity::Medium,
                fix: format!(
                    "Add transaction boundary (UnitOfWork, @Transactional, or explicit tx) - {} write ops detected",
                    write_count
                ),
                file: file_path.to_owned(),
                line: find_match_in_lines(lines, &RE_WRITE_OPS),
            }]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        rule().check(content, path, &super::super::non_comment_lines(content))
    }

    #[test]
    fn detects_multiple_writes_without_transaction() {
        let content = r#"
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("2 write ops"));
    }

    #[test]
    fn allows_with_transaction_boundaries() {
        let cases = [
            "@Transactional()\nasync function handle() { await user.save(); await order.create(); }",
            "await unitOfWork.execute(async () => { await user.save(); await order.create(); });",
            "await prisma.$transaction(async (tx) => { await tx.user.create(); await tx.order.create(); });",
            "await db.transaction(async (tx) => { await tx.insert(users); await tx.insert(orders); });",
        ];
        for content in cases {
            let violations = check(content, "/src/usecases/handler.ts");
            assert!(
                violations.is_empty(),
                "Should allow: {}",
                &content[..50.min(content.len())]
            );
        }
    }

    #[test]
    fn skips_non_target_directories() {
        let content = r#"
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/utils/helper.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn skips_single_write() {
        let content = r#"
            async function handle() {
                await user.save();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn no_false_positive_for_set_add() {
        let content = r#"
            function process() {
                mySet.add(item);
                myMap.set(key, value);
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn detects_in_domain_directory() {
        let content = r#"
            async function handle() {
                await entity.save();
                await aggregate.persist();
            }
        "#;
        let violations = check(content, "/src/domain/order/handler.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_in_app_api_route() {
        let content = r#"
            export async function POST() {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/app/api/orders/route.ts").len(), 1);
    }

    #[test]
    fn detects_in_pages_api() {
        let content = r#"
            export default async function handler() {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/pages/api/orders.ts").len(), 1);
    }

    #[test]
    fn detects_in_server_directory() {
        let content = r#"
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/server/orders/handler.ts").len(), 1);
    }

    #[test]
    fn detects_in_app_route_segment() {
        let content = r#"
            export async function POST() {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/app/orders/[id]/route.tsx").len(), 1);
    }

    #[test]
    fn detects_when_keyword_in_variable_name() {
        let content = r#"
            async function handle(transactionId: string) {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/src/usecases/handler.ts").len(), 1);
    }

    #[test]
    fn detects_when_keyword_in_comment() {
        let content = r#"
            // TODO: wrap in unitOfWork later
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        assert_eq!(check(content, "/src/usecases/handler.ts").len(), 1);
    }
}
