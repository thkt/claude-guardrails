//! Resolves a hook-supplied `file_path` into a repository-root-relative path.
//!
//! `fs::canonicalize` cannot carry this on its own: a `PreToolUse` hook sees a
//! file about to be created, and canonicalize requires the path to exist.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A `file_path` placed under the repository root.
pub(crate) struct Resolved {
    pub(crate) relative: PathBuf,
    /// True when resolution landed somewhere other than the spelling the
    /// caller was given, so the spelling and `relative` match different
    /// patterns.
    pub(crate) moved: bool,
}

/// Resolves `file_path` against `root`, or `None` when it lands outside
/// `root`. A relative `file_path` is taken as relative to `root`.
///
/// The `..` fold runs before any symlink resolution, so a path climbing out of
/// the repository is rejected whether or not it exists on disk.
pub(crate) fn resolve_under_root(file_path: &Path, root: &Path) -> Option<Resolved> {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let absolute = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        root.join(file_path)
    };

    let lexical = fold_parent_dirs(&absolute);
    let resolved = follow_symlinks(&lexical);
    let relative = resolved.strip_prefix(&root).ok()?.to_path_buf();

    Some(Resolved {
        relative,
        moved: resolved != lexical,
    })
}

/// Mirrors what `canonicalize` would do for the path-syntax part alone.
fn fold_parent_dirs(absolute: &Path) -> PathBuf {
    let mut folded: Vec<Component> = Vec::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                if matches!(folded.last(), Some(Component::Normal(_))) {
                    folded.pop();
                } else {
                    folded.push(component);
                }
            }
            other => folded.push(other),
        }
    }
    folded.into_iter().collect()
}

/// Collapses symlinked ancestors of `lexical` into the same space as `root`.
///
/// The components below the nearest existing ancestor are rejoined unresolved:
/// they are about to be created, so none of them can be a symlink today.
///
/// The walk is not confined to `root`: a spelling outside it can still resolve
/// inside it. What lands outside is rejected by `strip_prefix` afterwards.
fn follow_symlinks(lexical: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(lexical) {
        return canonical;
    }

    let mut below: Vec<OsString> = Vec::new();
    let mut current = lexical;
    while let (Some(parent), Some(name)) = (current.parent(), current.file_name()) {
        below.push(name.to_os_string());
        if let Ok(canonical_parent) = fs::canonicalize(parent) {
            let mut resolved = canonical_parent;
            resolved.extend(below.iter().rev());
            return resolved;
        }
        current = parent;
    }
    lexical.to_path_buf()
}

#[cfg(test)]
mod tests;
