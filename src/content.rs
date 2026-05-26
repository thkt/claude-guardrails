//! Tool-input deserialization and post-edit content resolution.
//!
//! `ToolInput` / `EditItem` deserialize the `PreToolUse` payload; the resolve and
//! apply functions reconstruct the post-edit file content (or a degraded
//! snippet) that the linters audit.

use crate::rules::RE_JS_FILE;
use crate::MAX_INPUT_SIZE;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug)]
pub(crate) enum ToolName {
    Write,
    Edit,
    MultiEdit,
    Other(String),
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Write => "Write",
            Self::Edit => "Edit",
            Self::MultiEdit => "MultiEdit",
            Self::Other(name) => name.as_str(),
        })
    }
}

// Deserialize from the raw JSON string, preserving the original name in
// `Other` so diagnostics can report which unsupported tool carried content.
// `#[serde(other)]` cannot capture the payload, so this is hand-written.
impl<'de> serde::Deserialize<'de> for ToolName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "Write" => Self::Write,
            "Edit" => Self::Edit,
            "MultiEdit" => Self::MultiEdit,
            _ => Self::Other(s),
        })
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct ToolInput {
    pub(crate) tool_name: ToolName,
    pub(crate) tool_input: ToolInputData,
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct ToolInputData {
    pub(crate) file_path: Option<String>,
    pub(crate) content: Option<String>,
    new_string: Option<String>,
    old_string: Option<String>,
    #[serde(default)]
    replace_all: bool,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize, Default)]
struct EditItem {
    new_string: Option<String>,
    old_string: Option<String>,
    #[serde(default)]
    replace_all: bool,
}

/// Reason analysis fell back to the Edit/MultiEdit snippet instead of
/// post-edit full file content. Distinct from `NotApplicable` (intentional
/// snippet mode, e.g., non-JS file) — every variant here means the caller
/// wanted full context but could not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DegradedReason {
    OversizedFile,
    NonUtf8Content,
    FileNotFound,
    PermissionDenied,
    IoError,
    OldStringNotFound,
    MultiEditMidFailure(usize),
    PathOutsideProject,
}

impl DegradedReason {
    pub(crate) fn note(self) -> String {
        match self {
            Self::OversizedFile => format!(
                "Target file exceeds {MAX_INPUT_SIZE}-byte limit; analyzed Edit snippet only."
            ),
            Self::NonUtf8Content => {
                "Target file is not valid UTF-8; analyzed Edit snippet only.".to_owned()
            }
            Self::FileNotFound => "Target file not on disk; analyzed Edit snippet only.".to_owned(),
            Self::PermissionDenied => {
                "Permission denied reading target file; analyzed Edit snippet only.".to_owned()
            }
            Self::IoError => {
                "I/O error reading target file; analyzed Edit snippet only.".to_owned()
            }
            Self::OldStringNotFound => {
                "Edit pattern not found in target file; analyzed Edit snippet only.".to_owned()
            }
            Self::MultiEditMidFailure(idx) => format!(
                "MultiEdit edit {idx} did not match post-edit content; analyzed Edit snippet only."
            ),
            Self::PathOutsideProject => {
                "Target file resolves outside the project root (symlink or path traversal); analyzed Edit snippet only.".to_owned()
            }
        }
    }
}

/// Result of resolving full post-edit content for a hook invocation.
/// - `Full`: full file content reconstructed (post-write semantic intact).
/// - `Degraded`: caller wanted full context, failed for a documented reason.
/// - `NotApplicable`: full-file analysis not attempted (non-JS file, missing
///   `old_string`, etc.). Silent fallback to snippet is correct here.
enum ContentResolution {
    Full(String),
    Degraded(DegradedReason),
    NotApplicable,
}

pub(crate) struct ResolvedTarget {
    pub(crate) file_path: String,
    pub(crate) content: String,
    pub(crate) is_js: bool,
    pub(crate) degraded: Option<DegradedReason>,
}

pub(crate) fn get_file_and_content(
    input: &ToolInput,
    project_root: Option<&Path>,
) -> Option<ResolvedTarget> {
    let file_path = input.tool_input.file_path.clone()?;
    let is_js = RE_JS_FILE.is_match(&file_path);

    let (content, degraded) = match &input.tool_name {
        ToolName::Write => (input.tool_input.content.clone()?, None),
        ToolName::Edit => {
            let new_string = input.tool_input.new_string.clone()?;
            match resolve_edit_content(
                &file_path,
                input.tool_input.old_string.as_deref(),
                &new_string,
                input.tool_input.replace_all,
                project_root,
                is_js,
            ) {
                ContentResolution::Full(c) => (c, None),
                ContentResolution::Degraded(reason) => (new_string, Some(reason)),
                ContentResolution::NotApplicable => (new_string, None),
            }
        }
        ToolName::MultiEdit => {
            let edits = input.tool_input.edits.as_ref()?;
            match resolve_multi_edit_content(&file_path, edits, project_root, is_js) {
                ContentResolution::Full(c) => (c, None),
                ContentResolution::Degraded(reason) => (join_new_strings(edits), Some(reason)),
                ContentResolution::NotApplicable => (join_new_strings(edits), None),
            }
        }
        ToolName::Other(name) => {
            if input.tool_input.content.is_some() || input.tool_input.new_string.is_some() {
                eprintln!(
                    "guardrails: unknown tool '{name}' has content fields — add to get_file_and_content if it writes files"
                );
            }
            return None;
        }
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some(ResolvedTarget {
        file_path,
        content,
        is_js,
        degraded,
    })
}

fn join_new_strings(edits: &[EditItem]) -> String {
    edits
        .iter()
        .filter_map(|e| e.new_string.as_deref())
        .collect::<Vec<_>>()
        .join("\n")
}

fn apply_edit(
    file_content: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> Option<String> {
    if old_string.is_empty() {
        return None;
    }
    if replace_all {
        let mut matched = false;
        let mut result = String::with_capacity(file_content.len());
        let mut cursor = 0;
        for (idx, _) in file_content.match_indices(old_string) {
            matched = true;
            result.push_str(&file_content[cursor..idx]);
            result.push_str(new_string);
            cursor = idx + old_string.len();
        }
        if !matched {
            return None;
        }
        result.push_str(&file_content[cursor..]);
        Some(result)
    } else {
        let idx = file_content.find(old_string)?;
        let mut result =
            String::with_capacity(file_content.len() + new_string.len() - old_string.len());
        result.push_str(&file_content[..idx]);
        result.push_str(new_string);
        result.push_str(&file_content[idx + old_string.len()..]);
        Some(result)
    }
}

/// Bound on-disk file read at `MAX_INPUT_SIZE` to mirror the stdin cap.
/// Canonicalizes the path; when `project_root` is `Some`, rejects targets
/// resolving outside that root (defense against symlink / `..` path
/// traversal). Production callers pass canonical cwd; `None` disables the
/// boundary (used by tests over tempdirs).
///
/// `is_js` is taken as input to avoid re-running `RE_JS_FILE.is_match` on
/// an already-classified path. Pass `RE_JS_FILE.is_match(file_path)` when
/// no classification has been done yet.
fn read_file_capped(
    file_path: &str,
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    if !is_js {
        return ContentResolution::NotApplicable;
    }
    let canonical = match fs::canonicalize(file_path) {
        Ok(p) => p,
        Err(e) => return ContentResolution::Degraded(io_error_to_reason(&e)),
    };
    if let Some(root) = project_root {
        if !canonical.starts_with(root) {
            return ContentResolution::Degraded(DegradedReason::PathOutsideProject);
        }
    }
    let file = match fs::File::open(&canonical) {
        Ok(f) => f,
        Err(e) => return ContentResolution::Degraded(io_error_to_reason(&e)),
    };
    let mut buf = String::new();
    if let Err(e) = file.take(MAX_INPUT_SIZE + 1).read_to_string(&mut buf) {
        return ContentResolution::Degraded(io_error_to_reason(&e));
    }
    if !content_within_cap(&buf, MAX_INPUT_SIZE) {
        return ContentResolution::Degraded(DegradedReason::OversizedFile);
    }
    ContentResolution::Full(buf)
}

/// Pure size-cap predicate. Cap is parameterized so the boundary is
/// testable with small fixtures (no 10MB allocation required).
pub(crate) fn content_within_cap(content: &str, cap: u64) -> bool {
    u64::try_from(content.len()).is_ok_and(|n| n <= cap)
}

fn io_error_to_reason(e: &io::Error) -> DegradedReason {
    match e.kind() {
        io::ErrorKind::NotFound => DegradedReason::FileNotFound,
        io::ErrorKind::PermissionDenied => DegradedReason::PermissionDenied,
        io::ErrorKind::InvalidData => DegradedReason::NonUtf8Content,
        _ => DegradedReason::IoError,
    }
}

fn resolve_edit_content(
    file_path: &str,
    old_string: Option<&str>,
    new_string: &str,
    replace_all: bool,
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    let Some(old) = old_string else {
        return ContentResolution::NotApplicable;
    };
    let content = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return other,
    };
    match apply_edit(&content, old, new_string, replace_all) {
        Some(applied) => ContentResolution::Full(applied),
        None => ContentResolution::Degraded(DegradedReason::OldStringNotFound),
    }
}

fn resolve_multi_edit_content(
    file_path: &str,
    edits: &[EditItem],
    project_root: Option<&Path>,
    is_js: bool,
) -> ContentResolution {
    let mut current = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return other,
    };
    for (idx, edit) in edits.iter().enumerate() {
        let Some(old) = edit.old_string.as_deref() else {
            return ContentResolution::NotApplicable;
        };
        let Some(new) = edit.new_string.as_deref() else {
            return ContentResolution::NotApplicable;
        };
        match apply_edit(&current, old, new, edit.replace_all) {
            Some(applied) => current = applied,
            None => return ContentResolution::Degraded(DegradedReason::MultiEditMidFailure(idx)),
        }
    }
    ContentResolution::Full(current)
}

#[cfg(test)]
mod tests;
