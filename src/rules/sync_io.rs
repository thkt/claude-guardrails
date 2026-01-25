use super::{find_non_comment_match, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_EXCLUDED_FILE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\.config\.[jt]s$|/scripts?/|/cli/|/bin/|\.mjs$)")
        .expect("RE_EXCLUDED_FILE: invalid regex")
});

struct SyncIo {
    pattern: &'static Lazy<Regex>,
    method: &'static str,
    async_alternative: &'static str,
}

static RE_READ_FILE_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"readFileSync\s*\(").expect("RE_READ_FILE_SYNC: invalid regex"));

static RE_WRITE_FILE_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"writeFileSync\s*\(").expect("RE_WRITE_FILE_SYNC: invalid regex"));

static RE_EXISTS_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"existsSync\s*\(").expect("RE_EXISTS_SYNC: invalid regex"));

static RE_MKDIR_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"mkdirSync\s*\(").expect("RE_MKDIR_SYNC: invalid regex"));

static RE_RMDIR_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"rm(dir)?Sync\s*\(").expect("RE_RMDIR_SYNC: invalid regex"));

static RE_STAT_SYNC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(l)?statSync\s*\(").expect("RE_STAT_SYNC: invalid regex"));

static SYNC_IO: Lazy<[SyncIo; 6]> = Lazy::new(|| {
    [
        SyncIo {
            pattern: &RE_READ_FILE_SYNC,
            method: "readFileSync",
            async_alternative: "readFile (fs/promises)",
        },
        SyncIo {
            pattern: &RE_WRITE_FILE_SYNC,
            method: "writeFileSync",
            async_alternative: "writeFile (fs/promises)",
        },
        SyncIo {
            pattern: &RE_EXISTS_SYNC,
            method: "existsSync",
            async_alternative: "access (fs/promises)",
        },
        SyncIo {
            pattern: &RE_MKDIR_SYNC,
            method: "mkdirSync",
            async_alternative: "mkdir (fs/promises)",
        },
        SyncIo {
            pattern: &RE_RMDIR_SYNC,
            method: "rmSync/rmdirSync",
            async_alternative: "rm (fs/promises)",
        },
        SyncIo {
            pattern: &RE_STAT_SYNC,
            method: "statSync",
            async_alternative: "stat (fs/promises)",
        },
    ]
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            // Allow sync I/O in config files and CLI scripts
            if RE_EXCLUDED_FILE.is_match(file_path) {
                return Vec::new();
            }

            let mut violations = Vec::new();

            for io in SYNC_IO.iter() {
                if let Some(line_num) = find_non_comment_match(content, io.pattern) {
                    violations.push(Violation {
                        rule: "sync-io".to_string(),
                        severity: Severity::Medium,
                        failure: format!(
                            "{} blocks the event loop. Use {} instead.",
                            io.method, io.async_alternative
                        ),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
                }
            }

            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        rule().check(content, path)
    }

    #[test]
    fn detects_read_file_sync() {
        let content = r#"const data = fs.readFileSync('file.txt', 'utf8');"#;
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].failure.contains("readFileSync"));
    }

    #[test]
    fn detects_write_file_sync() {
        let content = r#"fs.writeFileSync('file.txt', data);"#;
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_exists_sync() {
        let content = r#"if (fs.existsSync(path)) { }"#;
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn allows_in_config_files() {
        let content = r#"const data = fs.readFileSync('config.json', 'utf8');"#;
        assert!(check(content, "/webpack.config.js").is_empty());
        assert!(check(content, "/vite.config.ts").is_empty());
    }

    #[test]
    fn allows_in_scripts() {
        let content = r#"const data = fs.readFileSync('data.json', 'utf8');"#;
        assert!(check(content, "/scripts/build.ts").is_empty());
        assert!(check(content, "/cli/index.ts").is_empty());
    }

    #[test]
    fn allows_async_versions() {
        let content = r#"
            const data = await fs.readFile('file.txt', 'utf8');
            await fs.writeFile('file.txt', data);
        "#;
        assert!(check(content, "/src/utils/file.ts").is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r#"
            // Don't use readFileSync
            const data = await fs.readFile('file.txt', 'utf8');
        "#;
        assert!(check(content, "/src/utils/file.ts").is_empty());
    }
}
