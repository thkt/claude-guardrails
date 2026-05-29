//! Fail-closed stdin parsing: reads the `PreToolUse` payload, enforces the
//! size cap, and deserializes into `ToolInput`. Failures map to typed
//! `ParseStdinError` variants the caller renders.

use crate::content::{content_within_cap, ToolInput};
use crate::io::envelope::{ErrorCode, ErrorPayload};
use crate::io::output::build_payload;
use crate::MAX_INPUT_SIZE;
use std::io::{self, Read};

// Fail-closed input parsing. Errors carry the cause as a typed variant; the
// exit code (always 64, hook input contract per ADR-0005) and rendering are
// the caller's responsibility.
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
    let mut input_str = String::new();
    reader
        .take(MAX_INPUT_SIZE + 1)
        .read_to_string(&mut input_str)?;

    if !content_within_cap(&input_str, MAX_INPUT_SIZE) {
        return Err(ParseStdinError::Oversized {
            cap: MAX_INPUT_SIZE,
        });
    }

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
