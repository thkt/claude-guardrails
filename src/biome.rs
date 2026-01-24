use crate::rules::{Severity, Violation};
use serde::Deserialize;
use std::io::Write;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct BiomeOutput {
    diagnostics: Vec<BiomeDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct BiomeDiagnostic {
    category: String,
    severity: String,
    description: String,
    advices: BiomeAdvices,
    location: BiomeLocation,
}

#[derive(Debug, Deserialize)]
struct BiomeAdvices {
    advices: Vec<BiomeAdvice>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BiomeAdvice {
    Log { log: (String, Vec<BiomeMessagePart>) },
    #[allow(dead_code)]
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct BiomeMessagePart {
    content: String,
}

#[derive(Debug, Deserialize)]
struct BiomeLocation {
    span: Option<Vec<u32>>,
    #[serde(rename = "sourceCode")]
    source_code: Option<String>,
}

pub fn is_available() -> bool {
    Command::new("biome")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Creates temp file in same directory as file_path to inherit project's biome.json
pub fn check(content: &str, file_path: &str) -> Vec<Violation> {
    use std::path::Path;

    let path = Path::new(file_path);
    let dir = path.parent().unwrap_or(Path::new("/tmp/claude"));
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");
    let temp_name = format!(".guardrails-check-{}.{}", std::process::id(), extension);
    let temp_path = dir.join(&temp_name);
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("guardrails: biome: failed to create directory {:?}: {}", dir, e);
    }

    let mut file = match std::fs::File::create(&temp_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("guardrails: biome: failed to create temp file: {}", e);
            return vec![];
        }
    };

    if let Err(e) = file.write_all(content.as_bytes()) {
        eprintln!("guardrails: biome: failed to write temp file: {}", e);
        cleanup_temp_file(&temp_path);
        return vec![];
    }

    let temp_path_str = match temp_path.to_str() {
        Some(s) => s,
        None => {
            eprintln!("guardrails: biome: temp path contains non-UTF8 characters");
            cleanup_temp_file(&temp_path);
            return vec![];
        }
    };

    let output = match Command::new("biome")
        .args(["lint", "--reporter=json", temp_path_str])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("guardrails: biome: failed to execute: {}", e);
            cleanup_temp_file(&temp_path);
            return vec![];
        }
    };

    cleanup_temp_file(&temp_path);

    // biome outputs to stdout even on errors
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Find JSON in output (skip warning line about unstable option)
    let json_str = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or("");

    if json_str.is_empty() {
        if !stdout.is_empty() || !stderr.is_empty() {
            eprintln!("guardrails: biome: no JSON output (may have config issues)");
            if !stderr.is_empty() {
                eprintln!("guardrails: biome stderr: {}", stderr.lines().next().unwrap_or(""));
            }
        }
        return vec![];
    }

    let biome_output: BiomeOutput = match serde_json::from_str(json_str) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("guardrails: biome: failed to parse output: {}", e);
            return vec![];
        }
    };

    biome_output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = match d.severity.as_str() {
                "error" => Severity::High,
                "warning" => Severity::Medium,
                _ => Severity::Low,
            };

            let line = d.location.span.as_ref().map(|span| {
                let offset = span.first().copied().unwrap_or(0) as usize;
                let source = d.location.source_code.as_deref().unwrap_or("");
                let line_num = source.chars().take(offset).filter(|&c| c == '\n').count() + 1;
                line_num as u32
            });

            let fix = get_fix_for_rule(&d.category)
                .map(String::from)
                .unwrap_or_else(|| extract_fix_from_advices(&d.advices, &d.description));

            Violation {
                rule: format!("biome/{}", d.category),
                severity,
                failure: fix,
                file: file_path.to_string(),
                line,
            }
        })
        .collect()
}

fn cleanup_temp_file(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("guardrails: biome: failed to cleanup temp file: {}", e);
        }
    }
}

fn get_fix_for_rule(category: &str) -> Option<&'static str> {
    match category {
        // security
        "lint/security/noGlobalEval" => Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution"),
        // suspicious
        "lint/suspicious/noExplicitAny" => Some("Use `unknown` with type guards, or define a specific type/interface"),
        "lint/suspicious/noDebugger" => Some("Remove debugger statement"),
        "lint/suspicious/noConsole" => Some("Remove console.log or use a proper logger"),
        // correctness
        "lint/correctness/noUnusedVariables" => Some("Remove the variable, or prefix with _ if intentional"),
        "lint/correctness/noUnusedImports" => Some("Remove the unused import"),
        // a11y
        "lint/a11y/useAltText" => Some("Add alt attribute to img element"),
        "lint/a11y/useButtonType" => Some("Add type attribute to button element"),
        "lint/a11y/noBlankTarget" => Some("Add rel=\"noopener noreferrer\" to links with target=\"_blank\""),
        _ => None,
    }
}

fn extract_fix_from_advices(advices: &BiomeAdvices, fallback: &str) -> String {
    let texts: Vec<String> = advices
        .advices
        .iter()
        .filter_map(|advice| {
            if let BiomeAdvice::Log { log: (_, parts) } = advice {
                let text: String = parts.iter().map(|p| p.content.as_str()).collect();
                if !text.is_empty() {
                    return Some(text);
                }
            }
            None
        })
        .collect();

    if texts.is_empty() {
        fallback.to_string()
    } else {
        texts.join(" ")
    }
}
