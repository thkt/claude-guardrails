mod biome;
mod config;
mod reporter;
mod rules;
mod scanner;

use config::Config;
use reporter::{format_violations, format_warnings};
use rules::Violation;
use std::io::{self, Read};

const MAX_INPUT_SIZE: u64 = 10_000_000; // 10MB limit

fn is_js_ts_file(path: &str) -> bool {
    path.ends_with(".ts")
        || path.ends_with(".tsx")
        || path.ends_with(".js")
        || path.ends_with(".jsx")
}

#[derive(serde::Deserialize)]
struct ToolInput {
    tool_name: String,
    tool_input: ToolInputData,
}

#[derive(serde::Deserialize)]
struct ToolInputData {
    file_path: Option<String>,
    content: Option<String>,
    new_string: Option<String>,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize)]
struct EditItem {
    new_string: Option<String>,
}

fn get_file_and_content(input: &ToolInput) -> Option<(String, String)> {
    let file_path = input.tool_input.file_path.clone()?;

    let content = match input.tool_name.as_str() {
        "Write" => input.tool_input.content.clone()?,
        "Edit" => input.tool_input.new_string.clone()?,
        "MultiEdit" => {
            let edits = input.tool_input.edits.as_ref()?;
            edits
                .iter()
                .filter_map(|e| e.new_string.clone())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => return None,
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some((file_path, content))
}

fn main() {
    let config = Config::load();

    if !config.enabled {
        std::process::exit(0);
    }

    let mut input_str = String::new();
    let bytes_read = match io::stdin()
        .take(MAX_INPUT_SIZE)
        .read_to_string(&mut input_str)
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("guardrails: failed to read stdin: {}", e);
            std::process::exit(1);
        }
    };

    // Fail fast on truncation - truncated JSON would produce misleading parse errors.
    if bytes_read as u64 == MAX_INPUT_SIZE {
        eprintln!(
            "guardrails: error: input too large (>={} bytes), aborting",
            MAX_INPUT_SIZE
        );
        std::process::exit(1);
    }

    let input: ToolInput = match serde_json::from_str(&input_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("guardrails: invalid JSON input: {}", e);
            std::process::exit(1);
        }
    };

    let Some((file_path, content)) = get_file_and_content(&input) else {
        eprintln!(
            "guardrails: skipping {} (unsupported or empty)",
            input.tool_name
        );
        std::process::exit(0);
    };

    let mut violations: Vec<Violation> = Vec::new();

    if config.rules.biome && is_js_ts_file(&file_path) {
        if biome::is_available() {
            violations.extend(biome::check(&content, &file_path));
        } else {
            eprintln!("guardrails: biome not found in PATH, skipping biome checks");
        }
    }

    let rules = rules::load_rules(&config);
    for rule in &rules {
        if !rule.file_pattern.is_match(&file_path) {
            continue;
        }
        violations.extend(rule.check(&content, &file_path));
    }

    let blocking: Vec<&Violation> = violations
        .iter()
        .filter(|v| config.severity.block_on.contains(&v.severity))
        .collect();

    let warnings: Vec<&Violation> = violations
        .iter()
        .filter(|v| !config.severity.block_on.contains(&v.severity))
        .collect();

    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(&warnings));
    }

    if !blocking.is_empty() {
        eprintln!("{}", format_violations(&blocking));
        std::process::exit(2);
    }

    std::process::exit(0);
}
