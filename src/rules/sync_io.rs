use super::{find_match_in_lines, Rule, Severity, Violation, RE_JS_FILE};
use crate::regex_util::regex_or_die;
use regex::Regex;
use std::sync::LazyLock;

static RE_EXCLUDED_FILE: LazyLock<Regex> = LazyLock::new(|| {
    regex_or_die(
        "RE_EXCLUDED_FILE",
        r"(\.config\.[jt]s$|/scripts?/|/cli/|/bin/|\.mjs$)",
    )
});

struct SyncIo {
    pattern: &'static LazyLock<Regex>,
    method: &'static str,
    async_alternative: &'static str,
}

static RE_READ_FILE_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_READ_FILE_SYNC", r"readFileSync\s*\("));

static RE_WRITE_FILE_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_WRITE_FILE_SYNC", r"writeFileSync\s*\("));

static RE_EXISTS_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_EXISTS_SYNC", r"existsSync\s*\("));

static RE_MKDIR_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_MKDIR_SYNC", r"mkdirSync\s*\("));

static RE_RMDIR_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_RMDIR_SYNC", r"rm(dir)?Sync\s*\("));

static RE_STAT_SYNC: LazyLock<Regex> =
    LazyLock::new(|| regex_or_die("RE_STAT_SYNC", r"(l)?statSync\s*\("));

static SYNC_IO: LazyLock<[SyncIo; 6]> = LazyLock::new(|| {
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

pub static RULE: LazyLock<Rule> = LazyLock::new(|| Rule {
    file_pattern: RE_JS_FILE.clone(),
    checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
        // Allow sync I/O in config files and CLI scripts
        if RE_EXCLUDED_FILE.is_match(file_path) {
            return Vec::new();
        }

        let mut violations = Vec::new();

        for io in SYNC_IO.iter() {
            if let Some(line_num) = find_match_in_lines(lines, io.pattern) {
                violations.push(Violation {
                    rule: super::rule_id::SYNC_IO.to_owned(),
                    severity: Severity::Medium,
                    fix: format!(
                        "{} blocks the event loop. Use {} instead.",
                        io.method, io.async_alternative
                    ),
                    file: file_path.to_owned(),
                    line: Some(line_num),
                });
            }
        }

        violations
    }),
});

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        super::super::check_rule(&RULE, content, path)
    }

    #[test]
    fn detects_read_file_sync() {
        let content = r"const data = fs.readFileSync('file.txt', 'utf8');";
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
        assert!(violations[0].fix.contains("readFileSync"));
    }

    #[test]
    fn detects_write_file_sync() {
        let content = r"fs.writeFileSync('file.txt', data);";
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn detects_exists_sync() {
        let content = r"if (fs.existsSync(path)) { }";
        let violations = check(content, "/src/utils/file.ts");
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn allows_in_config_files() {
        let content = r"const data = fs.readFileSync('config.json', 'utf8');";
        assert!(check(content, "/webpack.config.js").is_empty());
        assert!(check(content, "/vite.config.ts").is_empty());
    }

    #[test]
    fn allows_in_next_config() {
        let content = r"const data = fs.readFileSync('config.json', 'utf8');";
        assert!(check(content, "/next.config.ts").is_empty());
        assert!(check(content, "/next.config.js").is_empty());
    }

    #[test]
    fn allows_in_scripts() {
        let content = r"const data = fs.readFileSync('data.json', 'utf8');";
        assert!(check(content, "/scripts/build.ts").is_empty());
        assert!(check(content, "/cli/index.ts").is_empty());
    }

    #[test]
    fn allows_async_versions() {
        let content = r"
            const data = await fs.readFile('file.txt', 'utf8');
            await fs.writeFile('file.txt', data);
        ";
        assert!(check(content, "/src/utils/file.ts").is_empty());
    }

    #[test]
    fn ignores_comments() {
        let content = r"
            // Don't use readFileSync
            const data = await fs.readFile('file.txt', 'utf8');
        ";
        assert!(check(content, "/src/utils/file.ts").is_empty());
    }
}
