use crate::rules::Violation;

fn format_rule_name(rule: &str) -> (String, &'static str) {
    if rule.starts_with("biome/") {
        let short = rule.strip_prefix("biome/lint/").unwrap_or(rule);
        let name = short.rsplit('/').next().unwrap_or(short);
        (name.to_string(), "biome")
    } else {
        (rule.to_string(), "guardrails")
    }
}

pub fn format_violations(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![
        format!("GUARDRAILS: {} issues blocked this operation", violations.len()),
        String::new(),
    ];

    for (i, v) in violations.iter().enumerate() {
        let (rule_name, source) = format_rule_name(&v.rule);
        let location = match v.line {
            Some(l) => format!("{}:{}", v.file, l),
            None => v.file.clone(),
        };

        lines.push(format!("[{}] {} ({})", i + 1, rule_name, source));
        lines.push(format!("    location: {}", location));
        lines.push(format!("    fix: {}", v.failure));
        lines.push(String::new());
    }

    lines.push("Fix the issues above and retry.".to_string());

    lines.join("\n")
}

pub fn format_warnings(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![format!("GUARDRAILS: {} warnings", violations.len())];

    for v in violations {
        let (rule_name, source) = format_rule_name(&v.rule);
        let location = match v.line {
            Some(l) => format!("{}:{}", v.file, l),
            None => v.file.clone(),
        };
        lines.push(format!("  - {} ({}) at {}", rule_name, source, location));
    }

    lines.push(String::new());

    lines.join("\n")
}
