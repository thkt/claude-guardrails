//! Process exit codes for hook mode per Group 3 (Hook tool) convention.
//!
//! | Exit | Source       | Meaning                                   |
//! |------|--------------|-------------------------------------------|
//! | 0    | EX_OK        | allow (lint pass)                         |
//! | 1    | convention   | advisory failure (severity=warn)          |
//! | 2    | convention   | blocking failure (severity=error)         |
//! | 64   | EX_USAGE     | hook input JSON malformed                 |
//! | 70   | EX_SOFTWARE  | internal panic / invariant violation      |
//!
//! `ErrorCode` (in `envelope.rs`) covers the JSON `error.code` field for
//! human/agent-readable diagnostics; this enum maps to the process exit code
//! Claude Code reads to decide between *allow / advisory / blocking*.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookExitCode {
    Pass,
    Advisory,
    Blocking,
    InputError,
    Internal,
}

impl HookExitCode {
    pub const fn code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Advisory => 1,
            Self::Blocking => 2,
            Self::InputError => 64,
            Self::Internal => 70,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HookExitCode;

    // T-001: pass_is_zero
    #[test]
    fn pass_is_zero() {
        assert_eq!(HookExitCode::Pass.code(), 0);
    }

    // T-002: advisory_is_one
    #[test]
    fn advisory_is_one() {
        assert_eq!(HookExitCode::Advisory.code(), 1);
    }

    // T-003: blocking_is_two
    #[test]
    fn blocking_is_two() {
        assert_eq!(HookExitCode::Blocking.code(), 2);
    }

    // T-004: input_error_is_sysexits_usage
    #[test]
    fn input_error_is_sysexits_usage() {
        assert_eq!(HookExitCode::InputError.code(), 64);
    }

    // T-005: internal_is_sysexits_software
    #[test]
    fn internal_is_sysexits_software() {
        assert_eq!(HookExitCode::Internal.code(), 70);
    }
}
