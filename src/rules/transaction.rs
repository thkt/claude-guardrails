use super::{
    count_non_comment_matches, find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE,
};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_TARGET_DIR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/(usecases?|use-cases?|application|services?|domain|handlers?|app)/")
        .expect("RE_TARGET_DIR: invalid regex")
});

static RE_WRITE_OPS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\.(save|create|update|delete|insert|persist)\s*\(")
        .expect("RE_WRITE_OPS: invalid regex")
});

static RE_TX_BOUNDARY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(@Transactional|\btransaction\b|\$transaction|\bunitOfWork\b|\brunInTransaction\b|\bwithTransaction\b|\bbeginTransaction\b|\bQueryRunner\b|\bgetManager\b|knex\.transaction|sequelize\.transaction|db\.transaction)",
    )
    .expect("RE_TX_BOUNDARY: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            if !RE_TARGET_DIR.is_match(file_path) {
                return Vec::new();
            }

            let write_count = count_non_comment_matches(content, &RE_WRITE_OPS);
            if write_count < 2 {
                return Vec::new();
            }

            if find_non_comment_match(content, &RE_TX_BOUNDARY).is_some() {
                return Vec::new();
            }

            vec![Violation {
                rule: "transaction-boundary".to_string(),
                severity: Severity::Medium,
                failure: format!(
                    "Add transaction boundary (UnitOfWork, @Transactional, or explicit tx) - {} write ops detected",
                    write_count
                ),
                file: file_path.to_string(),
                line: find_non_comment_match(content, &RE_WRITE_OPS),
            }]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        rule().check(content, path)
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
        assert!(violations[0].failure.contains("2 write ops"));
    }

    #[test]
    fn allows_with_transactional_decorator() {
        let content = r#"
            @Transactional()
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn allows_with_unit_of_work() {
        let content = r#"
            async function handle() {
                await unitOfWork.execute(async () => {
                    await user.save();
                    await order.create();
                });
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn allows_with_prisma_transaction() {
        let content = r#"
            async function handle() {
                await prisma.$transaction(async (tx) => {
                    await tx.user.create();
                    await tx.order.create();
                });
            }
        "#;
        let violations = check(content, "/src/services/handler.ts");
        assert!(violations.is_empty());
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
    fn allows_with_drizzle_transaction() {
        let content = r#"
            async function handle() {
                await db.transaction(async (tx) => {
                    await tx.insert(users).values(user);
                    await tx.insert(orders).values(order);
                });
            }
        "#;
        let violations = check(content, "/src/services/handler.ts");
        assert!(violations.is_empty());
    }

    #[test]
    fn detects_when_transaction_keyword_only_in_variable_name() {
        let content = r#"
            async function handle(transactionId: string) {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_when_transaction_keyword_only_in_comment() {
        let content = r#"
            // TODO: wrap in unitOfWork later
            async function handle() {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_when_unitofwork_only_in_variable_name() {
        let content = r#"
            async function handle(unitOfWorkId: string) {
                await user.save();
                await order.create();
            }
        "#;
        let violations = check(content, "/src/usecases/handler.ts");
        assert_eq!(violations.len(), 1);
    }
}
