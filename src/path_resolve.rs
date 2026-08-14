//! Resolves a hook-supplied `file_path` into a repository-root-relative path.
//!
//! The path may not exist yet (a `PreToolUse` hook sees a file about to be
//! created), so `fs::canonicalize` cannot be applied to it wholesale. What is
//! resolvable still gets resolved: symlinks collapse for the part that exists
//! on disk, and `..` is folded lexically for the rest.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A `file_path` placed under the repository root.
pub(crate) struct Resolved {
    /// The path relative to the root, for glob matching.
    pub(crate) relative: PathBuf,
    /// True when symlink resolution landed somewhere other than the spelling
    /// the caller was given. Callers surface this: the same spelling matches
    /// different patterns before and after resolution.
    pub(crate) moved: bool,
}

/// Resolves `file_path` against `root`, or `None` when it lands outside `root`.
///
/// A relative `file_path` is taken as relative to `root`. `..` is folded
/// lexically first, so a path that climbs out of the repository is rejected
/// whether or not any of it exists on disk.
pub(crate) fn resolve_under_root(file_path: &Path, root: &Path) -> Option<Resolved> {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let absolute = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        root.join(file_path)
    };

    let lexical = fold_parent_dirs(&absolute);
    let resolved = follow_symlinks(&lexical, &root);
    let relative = resolved.strip_prefix(&root).ok()?.to_path_buf();

    Some(Resolved {
        relative,
        moved: resolved != lexical,
    })
}

/// Folds `..` by popping the last pushed `Normal` component, mirroring what
/// `canonicalize` would do for the path-syntax part alone.
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
/// A path that exists is canonicalized whole, which covers a symlink in the
/// final component. Otherwise the nearest existing ancestor is canonicalized
/// and the components below it are rejoined. Those components are about to be
/// created, so none of them can be a symlink today.
///
/// The walk stops at `root`. A path outside the repository is rejected by
/// `strip_prefix` regardless, and canonicalizing it would stat directories the
/// repository does not own.
fn follow_symlinks(lexical: &Path, root: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(lexical) {
        return canonical;
    }

    let mut below: Vec<OsString> = Vec::new();
    let mut current = lexical;
    while let (Some(parent), Some(name)) = (current.parent(), current.file_name()) {
        if !parent.starts_with(root) {
            break;
        }
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
