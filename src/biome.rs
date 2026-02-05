use crate::rules::{Severity, Violation};
use crate::scanner::{build_line_offsets, offset_to_line};
use serde::Deserialize;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

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
    Log {
        log: (String, Vec<BiomeMessagePart>),
    },
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

/// Creates temp file in same directory as file_path to inherit project's biome.json.
pub fn check(content: &str, file_path: &str) -> Vec<Violation> {
    let path = Path::new(file_path);
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");

    let temp_dir = std::env::temp_dir();
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(&temp_dir);

    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!(
            "guardrails: biome: failed to create directory {:?}: {}",
            dir, e
        );
        return vec![];
    }

    let temp_file = match NamedTempFile::with_suffix_in(format!(".{}", extension), dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("guardrails: biome: failed to create temp file: {}", e);
            return vec![];
        }
    };

    if let Err(e) = temp_file.as_file().write_all(content.as_bytes()) {
        eprintln!("guardrails: biome: failed to write temp file: {}", e);
        return vec![];
    }

    if let Err(e) = temp_file.as_file().flush() {
        eprintln!(
            "guardrails: biome: failed to flush temp file before lint: {}",
            e
        );
        return vec![];
    }

    let temp_path_str = match temp_file.path().to_str() {
        Some(s) => s,
        None => {
            eprintln!("guardrails: biome: temp path contains non-UTF8 characters");
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
            return vec![];
        }
    };

    // biome outputs to stdout even on errors
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Try parsing full stdout as JSON first, then fall back to finding JSON line.
    // Biome may prefix output with warning lines about unstable options.
    let biome_output: BiomeOutput = match serde_json::from_str(&stdout) {
        Ok(o) => o,
        Err(_) => {
            let json_str = stdout
                .lines()
                .find(|line| line.trim_start().starts_with('{'))
                .unwrap_or("");

            if json_str.is_empty() {
                if !stdout.is_empty() || !stderr.is_empty() {
                    eprintln!("guardrails: biome: no JSON in output (may have config issues)");
                    if !stderr.is_empty() {
                        eprintln!(
                            "guardrails: biome stderr: {}",
                            stderr.lines().next().unwrap_or("")
                        );
                    }
                }
                return vec![];
            }

            match serde_json::from_str(json_str) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("guardrails: biome: JSON parse error: {}", e);
                    return vec![];
                }
            }
        }
    };

    // Note: Uses first diagnostic's source_code for all diagnostics.
    // This is valid for single-file lint runs (our use case).
    let source_code = biome_output
        .diagnostics
        .first()
        .and_then(|d| d.location.source_code.as_deref())
        .unwrap_or("");
    let line_offsets = build_line_offsets(source_code);

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
                offset_to_line(&line_offsets, offset) as u32
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

fn get_fix_for_rule(category: &str) -> Option<&'static str> {
    match category {
        "lint/security/noGlobalEval" => {
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        }
        "lint/suspicious/noExplicitAny" => {
            Some("Use `unknown` with type guards, or define a specific type/interface")
        }
        "lint/suspicious/noDebugger" => Some("Remove debugger statement"),
        "lint/suspicious/noConsole" => Some("Remove console.log or use a proper logger"),
        "lint/correctness/noUnusedVariables" => {
            Some("Remove the variable, or prefix with _ if intentional")
        }
        "lint/correctness/noUnusedImports" => Some("Remove the unused import"),
        "lint/a11y/useAltText" => Some("Add alt attribute to img element"),
        "lint/a11y/useButtonType" => Some("Add type attribute to button element"),
        "lint/a11y/noBlankTarget" => {
            Some("Add rel=\"noopener noreferrer\" to links with target=\"_blank\"")
        }
        _ => None,
    }
}

fn extract_fix_from_advices(advices: &BiomeAdvices, fallback: &str) -> String {
    let texts: Vec<String> = advices
        .advices
        .iter()
        .filter_map(|advice| match advice {
            BiomeAdvice::Log { log: (_, parts) } => {
                let text: String = parts.iter().map(|p| p.content.as_str()).collect();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            }
            BiomeAdvice::Other(_) => None,
        })
        .collect();

    if texts.is_empty() {
        fallback.to_string()
    } else {
        texts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_line_offsets_empty() {
        let offsets = build_line_offsets("");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_build_line_offsets_single_line() {
        let offsets = build_line_offsets("hello world");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_build_line_offsets_multiple_lines() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        assert_eq!(offsets, vec![5, 11]); // positions of \n characters
    }

    #[test]
    fn test_offset_to_line() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        for (offset, expected) in [(0, 1), (4, 1), (6, 2), (10, 2), (12, 3)] {
            assert_eq!(offset_to_line(&offsets, offset), expected);
        }
    }

    #[test]
    fn test_get_fix_for_known_rule() {
        assert!(get_fix_for_rule("lint/security/noGlobalEval").is_some());
        assert!(get_fix_for_rule("lint/suspicious/noExplicitAny").is_some());
        assert!(get_fix_for_rule("lint/a11y/useAltText").is_some());
    }

    #[test]
    fn test_get_fix_for_unknown_rule() {
        assert!(get_fix_for_rule("unknown/rule").is_none());
    }

    #[test]
    fn test_extract_fix_from_empty_advices() {
        let advices = BiomeAdvices { advices: vec![] };
        let result = extract_fix_from_advices(&advices, "fallback message");
        assert_eq!(result, "fallback message");
    }

    #[test]
    fn test_extract_fix_from_log_advice() {
        let advices = BiomeAdvices {
            advices: vec![BiomeAdvice::Log {
                log: (
                    "info".to_string(),
                    vec![BiomeMessagePart {
                        content: "Fix suggestion".to_string(),
                    }],
                ),
            }],
        };
        let result = extract_fix_from_advices(&advices, "fallback");
        assert_eq!(result, "Fix suggestion");
    }

    // Note: Integration tests for is_available() and check() require the actual biome binary.
    // Mocking Command execution in Rust adds significant complexity for limited benefit.
}
