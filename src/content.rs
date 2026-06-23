//! Tool-input deserialization and post-edit content resolution.
//!
//! `ToolInput` / `EditItem` deserialize the `PreToolUse` payload; the resolve and
//! apply functions reconstruct the post-edit file content (or a degraded
//! snippet) that the linters audit.

use crate::invariant::is_structured_config;
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
    pub(crate) new_string: Option<String>,
    pub(crate) old_string: Option<String>,
    #[serde(default)]
    pub(crate) replace_all: bool,
    pub(crate) edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct EditItem {
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
pub(crate) enum ContentResolution {
    Full(String),
    Degraded(DegradedReason),
    NotApplicable,
}

impl ContentResolution {
    /// The reconstructed full content, or `None` when the resolution degraded or
    /// did not apply. The invariant gate compares against full content only; a
    /// degraded resolution is surfaced as a note elsewhere, not silently fed in.
    pub(crate) fn as_full_str(&self) -> Option<&str> {
        match self {
            Self::Full(content) => Some(content),
            _ => None,
        }
    }
}

/// Where the before-edit content for the diff-aware pass comes from.
/// - `Retained`: Edit/MultiEdit resolution already read the file; reuse it.
/// - `OnDisk`: Write never reads the target; read lazily only when needed.
/// - `Unavailable`: resolution was degraded or snippet-mode, so no
///   trustworthy before content exists.
#[derive(Debug, PartialEq)]
pub(crate) enum BeforeSource {
    Retained(String),
    OnDisk,
    Unavailable,
}

pub(crate) struct ResolvedTarget {
    pub(crate) file_path: String,
    pub(crate) content: String,
    pub(crate) is_js: bool,
    pub(crate) degraded: Option<DegradedReason>,
    pub(crate) before: BeforeSource,
    /// Full post-edit content for the invariant gate, resolved only for
    /// `.json` (`is_structured_config`) targets. `content` stays the snippet for
    /// non-JS Edits so existing content-scan rules are unaffected; the invariant
    /// pass reads `Full` content from here. A `Degraded` resolution carries the
    /// reason so the gate can surface a note instead of silently skipping a
    /// pinned file; `NotApplicable` is non-`.json` or a tool that writes no body.
    pub(crate) structured_full: ContentResolution,
}

pub(crate) fn get_file_and_content(
    input: &ToolInput,
    project_root: Option<&Path>,
) -> Option<ResolvedTarget> {
    let file_path = input.tool_input.file_path.clone()?;
    let is_js = RE_JS_FILE.is_match(&file_path);

    let (content, degraded, before) = match &input.tool_name {
        ToolName::Write => (
            input.tool_input.content.clone()?,
            None,
            BeforeSource::OnDisk,
        ),
        ToolName::Edit => {
            let new_string = input.tool_input.new_string.clone()?;
            let (resolution, before) = resolve_edit_content(
                &file_path,
                input.tool_input.old_string.as_deref(),
                &new_string,
                input.tool_input.replace_all,
                project_root,
                is_js,
            );
            match resolution {
                ContentResolution::Full(c) => (c, None, before),
                ContentResolution::Degraded(reason) => (new_string, Some(reason), before),
                ContentResolution::NotApplicable => (new_string, None, before),
            }
        }
        ToolName::MultiEdit => {
            let edits = input.tool_input.edits.as_ref()?;
            let (resolution, before) =
                resolve_multi_edit_content(&file_path, edits, project_root, is_js);
            match resolution {
                ContentResolution::Full(c) => (c, None, before),
                ContentResolution::Degraded(reason) => {
                    (join_new_strings(edits), Some(reason), before)
                }
                ContentResolution::NotApplicable => (join_new_strings(edits), None, before),
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

    let structured_full = reconstruct_structured_full(input, &file_path, project_root);

    Some(ResolvedTarget {
        file_path,
        content,
        is_js,
        degraded,
        before,
        structured_full,
    })
}

/// Full post-edit content for the invariant gate, computed only for `.json`
/// targets. Non-`.json` paths return `NotApplicable` before any disk read
/// (NFR-001). Reuses the Edit/MultiEdit resolution with the read gate forced
/// open so a `.json` Edit (which `is_js=false` would otherwise leave as a
/// snippet) is reconstructed in full. A degraded resolution is returned as
/// `Degraded(reason)` rather than collapsed to `NotApplicable`, so the gate can
/// note a skipped pin instead of silently passing it. `content` on the target is
/// untouched, so existing rules keep seeing the snippet.
fn reconstruct_structured_full(
    input: &ToolInput,
    file_path: &str,
    project_root: Option<&Path>,
) -> ContentResolution {
    if !is_structured_config(file_path) {
        return ContentResolution::NotApplicable;
    }
    match &input.tool_name {
        ToolName::Write => match input.tool_input.content.clone() {
            Some(content) => ContentResolution::Full(content),
            None => ContentResolution::NotApplicable,
        },
        ToolName::Edit => {
            let Some(new_string) = input.tool_input.new_string.as_deref() else {
                return ContentResolution::NotApplicable;
            };
            resolve_edit_content(
                file_path,
                input.tool_input.old_string.as_deref(),
                new_string,
                input.tool_input.replace_all,
                project_root,
                true,
            )
            .0
        }
        ToolName::MultiEdit => {
            let Some(edits) = input.tool_input.edits.as_ref() else {
                return ContentResolution::NotApplicable;
            };
            resolve_multi_edit_content(file_path, edits, project_root, true).0
        }
        ToolName::Other(_) => ContentResolution::NotApplicable,
    }
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
pub(crate) fn read_file_capped(
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
    // Read bytes first so a cap-boundary split of a multibyte codepoint is
    // reported as OversizedFile, not as a UTF-8 decode failure (#302).
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_INPUT_SIZE + 1).read_to_end(&mut bytes) {
        return ContentResolution::Degraded(io_error_to_reason(&e));
    }
    if !length_within_cap(bytes.len(), MAX_INPUT_SIZE) {
        return ContentResolution::Degraded(DegradedReason::OversizedFile);
    }
    match String::from_utf8(bytes) {
        Ok(buf) => ContentResolution::Full(buf),
        Err(_) => ContentResolution::Degraded(DegradedReason::NonUtf8Content),
    }
}

/// Pure size-cap predicate over a byte length. Cap is parameterized so the
/// boundary is testable with small fixtures (no 10MB allocation required).
pub(crate) fn length_within_cap(len: usize, cap: u64) -> bool {
    u64::try_from(len).is_ok_and(|n| n <= cap)
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
) -> (ContentResolution, BeforeSource) {
    let Some(old) = old_string else {
        return (ContentResolution::NotApplicable, BeforeSource::Unavailable);
    };
    let content = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return (other, BeforeSource::Unavailable),
    };
    match apply_edit(&content, old, new_string, replace_all) {
        Some(applied) => (
            ContentResolution::Full(applied),
            BeforeSource::Retained(content),
        ),
        None => (
            ContentResolution::Degraded(DegradedReason::OldStringNotFound),
            BeforeSource::Unavailable,
        ),
    }
}

fn resolve_multi_edit_content(
    file_path: &str,
    edits: &[EditItem],
    project_root: Option<&Path>,
    is_js: bool,
) -> (ContentResolution, BeforeSource) {
    let before = match read_file_capped(file_path, project_root, is_js) {
        ContentResolution::Full(c) => c,
        other => return (other, BeforeSource::Unavailable),
    };
    let mut current = before.clone();
    for (idx, edit) in edits.iter().enumerate() {
        let Some(old) = edit.old_string.as_deref() else {
            return (ContentResolution::NotApplicable, BeforeSource::Unavailable);
        };
        let Some(new) = edit.new_string.as_deref() else {
            return (ContentResolution::NotApplicable, BeforeSource::Unavailable);
        };
        match apply_edit(&current, old, new, edit.replace_all) {
            Some(applied) => current = applied,
            None => {
                return (
                    ContentResolution::Degraded(DegradedReason::MultiEditMidFailure(idx)),
                    BeforeSource::Unavailable,
                )
            }
        }
    }
    (
        ContentResolution::Full(current),
        BeforeSource::Retained(before),
    )
}

#[cfg(test)]
mod tests;
