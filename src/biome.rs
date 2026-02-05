use crate::rules::{Severity, Violation};
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

    // Use parent directory if available, otherwise system temp dir
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

    // Find JSON in output (skip warning line about unstable option)
    let json_str = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or("");

    if json_str.is_empty() {
        if !stdout.is_empty() || !stderr.is_empty() {
            eprintln!("guardrails: biome: no JSON output (may have config issues)");
            if !stderr.is_empty() {
                eprintln!(
                    "guardrails: biome stderr: {}",
                    stderr.lines().next().unwrap_or("")
                );
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
                offset_to_line(&line_offsets, offset)
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

/// Returns byte offsets of newline characters for O(log n) line lookup.
fn build_line_offsets(source: &str) -> Vec<usize> {
    source
        .char_indices()
        .filter_map(|(i, c)| if c == '\n' { Some(i) } else { None })
        .collect()
}

/// Convert byte offset to 1-based line number.
fn offset_to_line(line_offsets: &[usize], offset: usize) -> u32 {
    match line_offsets.binary_search(&offset) {
        Ok(idx) | Err(idx) => (idx + 1) as u32,
    }
}

fn get_fix_for_rule(category: &str) -> Option<&'static str> {
    match category {
        // security
        "lint/security/noGlobalEval" => {
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        }
        // suspicious
        "lint/suspicious/noExplicitAny" => {
            Some("Use `unknown` with type guards, or define a specific type/interface")
        }
        "lint/suspicious/noDebugger" => Some("Remove debugger statement"),
        "lint/suspicious/noConsole" => Some("Remove console.log or use a proper logger"),
        // correctness
        "lint/correctness/noUnusedVariables" => {
            Some("Remove the variable, or prefix with _ if intentional")
        }
        "lint/correctness/noUnusedImports" => Some("Remove the unused import"),
        // a11y
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
        .filter_map(|advice| {
            match advice {
                BiomeAdvice::Log { log: (_, parts) } => {
                    let text: String = parts.iter().map(|p| p.content.as_str()).collect();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
                BiomeAdvice::Other(_) => {}
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
    fn test_offset_to_line_first_line() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        assert_eq!(offset_to_line(&offsets, 0), 1);
        assert_eq!(offset_to_line(&offsets, 4), 1);
    }

    #[test]
    fn test_offset_to_line_second_line() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        assert_eq!(offset_to_line(&offsets, 6), 2);
        assert_eq!(offset_to_line(&offsets, 10), 2);
    }

    #[test]
    fn test_offset_to_line_third_line() {
        let offsets = build_line_offsets("line1\nline2\nline3");
        assert_eq!(offset_to_line(&offsets, 12), 3);
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

    #[test]
    fn test_biome_output_parsing() {
        let json = r#"{"diagnostics":[]}"#;
        let output: BiomeOutput = serde_json::from_str(json).unwrap();
        assert!(output.diagnostics.is_empty());
    }

    #[test]
    fn test_biome_diagnostic_parsing() {
        let json = r#"{
            "diagnostics": [{
                "category": "lint/test",
                "severity": "error",
                "description": "Test error",
                "advices": {"advices": []},
                "location": {"span": [10, 20], "sourceCode": "test"}
            }]
        }"#;
        let output: BiomeOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.diagnostics.len(), 1);
        assert_eq!(output.diagnostics[0].category, "lint/test");
        assert_eq!(output.diagnostics[0].severity, "error");
    }

    // TODO: Integration tests for is_available() and check() require mocking biome command
}
