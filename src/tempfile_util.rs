use std::env;
use std::io::Write;
use std::path::Path;
use tempfile::{Builder, NamedTempFile};

/// Create a temp file in the same directory as `file_path` so linters inherit project config.
/// Falls back to the system temp directory when the parent directory does not exist.
pub fn write_temp(content: &str, file_path: &str, tool: &str) -> Option<NamedTempFile> {
    write_temp_in(content, file_path, tool, &env::temp_dir())
}

pub(crate) fn write_temp_in(
    content: &str,
    file_path: &str,
    tool: &str,
    fallback_dir: &Path,
) -> Option<NamedTempFile> {
    let path = Path::new(file_path);
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("ts");

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && p.is_dir())
        .unwrap_or(fallback_dir);

    let temp_file = match Builder::new()
        .suffix(&format!(".{}", extension))
        .tempfile_in(dir)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("guardrails: {}: failed to create temp file: {}", tool, e);
            return None;
        }
    };

    if let Err(e) = temp_file.as_file().write_all(content.as_bytes()) {
        eprintln!("guardrails: {}: failed to write temp file: {}", tool, e);
        return None;
    }

    if let Err(e) = temp_file.as_file().flush() {
        eprintln!("guardrails: {}: failed to flush temp file: {}", tool, e);
        return None;
    }

    Some(temp_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn creates_temp_file_with_correct_extension() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("src/app.tsx");
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();

        let tf = write_temp("content", file_path.to_str().unwrap(), "test").unwrap();
        assert!(
            tf.path().to_str().unwrap().ends_with(".tsx"),
            "expected .tsx suffix, got {:?}",
            tf.path()
        );
    }

    #[test]
    fn writes_content_to_temp_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("app.ts");

        let mut tf = write_temp("hello world", file_path.to_str().unwrap(), "test").unwrap();
        let mut buf = String::new();
        tf.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        tf.as_file_mut().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");
    }

    #[test]
    fn falls_back_to_temp_dir_when_parent_missing() {
        let tf = write_temp("content", "/nonexistent/dir/app.ts", "test").unwrap();
        assert!(tf.path().to_str().unwrap().ends_with(".ts"));
    }

    #[test]
    fn fallback_dir_injection_lands_in_supplied_directory() {
        let injected = tempfile::TempDir::new().unwrap();
        let injected_canon = fs::canonicalize(injected.path()).unwrap();
        let tf = write_temp_in(
            "content",
            "/nonexistent/dir/app.ts",
            "test",
            injected.path(),
        )
        .unwrap();
        let tf_canon = fs::canonicalize(tf.path()).unwrap();
        assert!(
            tf_canon.starts_with(&injected_canon),
            "expected {tf_canon:?} under {injected_canon:?}"
        );
    }

    #[test]
    fn defaults_to_ts_extension_when_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let file_path = tmp.path().join("Makefile");

        let tf = write_temp("content", file_path.to_str().unwrap(), "test").unwrap();
        assert!(
            tf.path().to_str().unwrap().ends_with(".ts"),
            "expected .ts fallback, got {:?}",
            tf.path()
        );
    }
}
