//! Stdin parsing for the `PreToolUse` payload: reads bytes, enforces the size
//! cap, and deserializes into `ToolInput`. Failures map to typed
//! `ParseStdinError` variants. `Oversized` is fail-closed (exit 2, blocks the
//! tool call); `InvalidJson` / `Io` are fail-open (exit 64, non-blocking). See
//! `hook_exit_code` and ADR-0004.

use crate::content::{length_within_cap, ToolInput};
use crate::hook_exit::HookExitCode;
use crate::io::envelope::{ErrorCode, ErrorPayload};
use crate::io::output::build_payload;
use crate::MAX_INPUT_SIZE;
use std::io::{self, Read};

// Typed parse failures. The cause is carried as a variant; `hook_exit_code`
// selects the process exit and `into_payload` the rendered envelope.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseStdinError {
    #[error("failed to read stdin: {0}")]
    Io(#[from] io::Error),
    #[error("input too large (>{cap} bytes), blocking as precaution")]
    Oversized { cap: u64 },
    #[error("invalid JSON input: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

impl ParseStdinError {
    /// Selects the hook exit code for this failure. Only `Oversized` is
    /// fail-closed via `Blocking` (exit 2): exit 2 is the sole `PreToolUse` code
    /// that halts the tool call, so routing oversized payloads there closes the
    /// bypass the resource-boundary axis targets (ADR-0004). `InvalidJson` / `Io`
    /// stay non-blocking (`InputError`, exit 64): Claude Code builds the
    /// envelope, so a malformed or unreadable payload signals its bug or schema
    /// drift, not an agent-controllable lever — blocking them would halt every
    /// edit the day the envelope schema drifts past the serde model.
    pub(crate) fn hook_exit_code(&self) -> HookExitCode {
        match self {
            Self::Oversized { .. } => HookExitCode::Blocking,
            Self::Io(_) | Self::InvalidJson(_) => HookExitCode::InputError,
        }
    }

    pub(crate) fn into_payload(self) -> ErrorPayload {
        let (code, next_step) = match &self {
            Self::Io(_) => (
                ErrorCode::IoError,
                "Pass valid Claude Code hook JSON via stdin",
            ),
            Self::Oversized { .. } => (
                ErrorCode::DataError,
                "Reduce input size or split into smaller hook calls",
            ),
            Self::InvalidJson(_) => (
                ErrorCode::DataError,
                "Pass valid Claude Code hook JSON with tool_name and tool_input fields",
            ),
        };
        build_payload(code, self.to_string(), next_step)
    }
}

pub(crate) fn parse_stdin() -> Result<ToolInput, ParseStdinError> {
    parse_stdin_from(&mut io::stdin().lock())
}

fn parse_stdin_from(reader: &mut dyn Read) -> Result<ToolInput, ParseStdinError> {
    // Read bytes first so a cap-boundary split of a multibyte codepoint is
    // reported as Oversized, not as a UTF-8 decode failure (#302).
    let mut bytes = Vec::new();
    reader.take(MAX_INPUT_SIZE + 1).read_to_end(&mut bytes)?;

    if !length_within_cap(bytes.len(), MAX_INPUT_SIZE) {
        return Err(ParseStdinError::Oversized {
            cap: MAX_INPUT_SIZE,
        });
    }

    // No Utf8 variant on ParseStdinError: route a decode failure through the
    // existing `Io` mapping (InvalidData) to keep the IO_ERROR next_step.
    let input_str =
        String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(serde_json::from_str(&input_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ToolName;

    #[test]
    fn parse_stdin_from_accepts_valid_write_payload() {
        let json =
            r#"{"tool_name":"Write","tool_input":{"file_path":"/x.ts","content":"const x=1;"}}"#;
        let mut cursor = io::Cursor::new(json.as_bytes());
        match parse_stdin_from(&mut cursor) {
            Ok(parsed) => {
                assert!(matches!(parsed.tool_name, ToolName::Write));
                assert_eq!(parsed.tool_input.file_path.as_deref(), Some("/x.ts"));
                assert_eq!(parsed.tool_input.content.as_deref(), Some("const x=1;"));
            }
            Err(e) => panic!("expected Ok, got Err({e:?})"),
        }
    }

    #[test]
    fn parse_stdin_from_rejects_invalid_json() {
        let mut cursor = io::Cursor::new(&b"not json"[..]);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::InvalidJson(_)), "got {e:?}"),
            Ok(_) => panic!("expected Err for invalid JSON"),
        }
    }

    #[test]
    fn parse_stdin_from_rejects_oversized_input() {
        let size = usize::try_from(MAX_INPUT_SIZE + 1).unwrap();
        let payload = vec![b'a'; size];
        let mut cursor = io::Cursor::new(payload);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::Oversized { .. }), "got {e:?}"),
            Ok(_) => panic!("expected Err for oversized input"),
        }
    }

    #[test]
    fn parse_stdin_from_oversized_multibyte_split_maps_oversized() {
        // The cap boundary (byte N+1) splits a 4-byte codepoint: take(N+1)
        // captures only 3 of its 4 bytes, so decode-first sees invalid UTF-8.
        // Byte-first ordering must report Oversized, not Io.
        let n = usize::try_from(MAX_INPUT_SIZE).unwrap();
        let mut payload = vec![b'a'; n - 2];
        payload.extend_from_slice("𝄞".as_bytes()); // 4 bytes -> total n + 2
        let mut cursor = io::Cursor::new(payload);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::Oversized { .. }), "got {e:?}"),
            Ok(_) => panic!("expected Err for oversized input"),
        }
    }

    #[test]
    fn parse_stdin_from_invalid_utf8_within_cap_maps_io() {
        // Invalid UTF-8 that fits under the cap stays an Io error (IO_ERROR
        // next_step), locking the decode-failure mapping unchanged.
        let mut cursor = io::Cursor::new(vec![0xff, 0xfe, 0xfd]);
        match parse_stdin_from(&mut cursor) {
            Err(e) => assert!(matches!(e, ParseStdinError::Io(_)), "got {e:?}"),
            Ok(_) => panic!("expected Err for invalid UTF-8 input"),
        }
    }

    #[test]
    fn oversized_is_fail_closed_blocking_exit() {
        // #375: only Oversized blocks (exit 2). Exit 2 is the sole PreToolUse
        // code that halts the tool call, so the resource-boundary bypass closes.
        assert_eq!(
            ParseStdinError::Oversized {
                cap: MAX_INPUT_SIZE
            }
            .hook_exit_code(),
            HookExitCode::Blocking
        );
    }

    #[test]
    fn invalid_json_and_io_are_fail_open_input_error_exit() {
        // InvalidJson / Io stay non-blocking (exit 64): Claude Code owns the
        // envelope, so these are its bug or schema drift, not an agent bypass.
        assert_eq!(
            ParseStdinError::InvalidJson(
                serde_json::from_str::<serde_json::Value>("nope").unwrap_err()
            )
            .hook_exit_code(),
            HookExitCode::InputError
        );
        assert_eq!(
            ParseStdinError::Io(io::Error::other("x")).hook_exit_code(),
            HookExitCode::InputError
        );
    }

    #[test]
    fn parse_stdin_error_into_payload_maps_error_codes() {
        assert_eq!(
            ParseStdinError::Io(io::Error::other("x"))
                .into_payload()
                .code,
            ErrorCode::IoError
        );
        assert_eq!(
            ParseStdinError::Oversized {
                cap: MAX_INPUT_SIZE
            }
            .into_payload()
            .code,
            ErrorCode::DataError
        );
        let json_err = serde_json::from_str::<serde_json::Value>("nope").unwrap_err();
        assert_eq!(
            ParseStdinError::InvalidJson(json_err).into_payload().code,
            ErrorCode::DataError
        );
    }
}
