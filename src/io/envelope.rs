//! JSON output envelopes for agent-friendly output across guardrails.
//! `SuccessEnvelope<T>` wraps command-specific data with a degradation
//! signal; `ErrorEnvelope` wraps a structured error with a next-step hint
//! and recovery candidates. Shape and exit code mapping are fixed in
//! ADR-0005 (`docs/decisions/0005-json-envelope-and-sysexits-adoption.md`).

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SuccessEnvelope<T: Serialize> {
    pub data: T,
    pub degraded: bool,
    pub notes: Vec<String>,
}

impl<T: Serialize> SuccessEnvelope<T> {
    pub fn ok(data: T) -> Self {
        Self {
            data,
            degraded: false,
            notes: Vec::new(),
        }
    }

    /// Only degradation notes drive the `degraded` flag; `info` notes ride
    /// along at the tail of `notes` without flagging the envelope.
    pub fn with_notes_and_info(data: T, degradations: Vec<String>, info: Vec<String>) -> Self {
        // `degraded` is the union of environmental notes (project root / config /
        // linter) and `ContentResolution::Degraded` notes. See ADR-0007 §Degraded
        // derivation semantics for the per-source aggregation order.
        let degraded = !degradations.is_empty();
        let mut notes = degradations;
        notes.extend(info);
        Self {
            data,
            degraded,
            notes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names)]
pub enum ErrorCode {
    // ADR-0005 lists USAGE_ERROR as a valid error.code for exit 64 and the
    // serialization / exit_code tests pin it, but no runtime path constructs it:
    // hook input errors map to Data/IoError and clap usage errors exit 64
    // without a JSON envelope. Kept for contract and test completeness.
    #[allow(dead_code)]
    UsageError,
    DataError,
    IoError,
}

impl ErrorCode {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::UsageError => 64,
            Self::DataError => 65,
            Self::IoError => 74,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub error: ErrorPayload,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    pub retryable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_payload_omits_optional_next_step() {
        let payload = ErrorPayload {
            code: ErrorCode::UsageError,
            message: String::from("Missing input"),
            next_step: None,
            candidates: vec![],
            retryable: false,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            !json.contains("next_step"),
            "next_step should be omitted when None, got: {json}"
        );
    }

    #[test]
    fn error_payload_omits_empty_candidates() {
        let payload = ErrorPayload {
            code: ErrorCode::UsageError,
            message: String::from("invalid"),
            next_step: None,
            candidates: vec![],
            retryable: false,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            !json.contains("candidates"),
            "candidates should be omitted when empty, got: {json}"
        );
    }

    #[test]
    fn error_payload_includes_present_optional_fields() {
        let payload = ErrorPayload {
            code: ErrorCode::UsageError,
            message: String::from("did you mean"),
            next_step: Some(String::from("Pass valid hook JSON via stdin")),
            candidates: vec![String::from("write"), String::from("edit")],
            retryable: false,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(
            json.contains(r#""next_step":"Pass valid hook JSON via stdin""#),
            "got: {json}"
        );
        assert!(
            json.contains(r#""candidates":["write","edit"]"#),
            "got: {json}"
        );
    }

    #[test]
    fn error_envelope_wraps_payload_under_error_key() {
        let env = ErrorEnvelope {
            error: ErrorPayload {
                code: ErrorCode::UsageError,
                message: String::from("Missing input"),
                next_step: None,
                candidates: vec![],
                retryable: false,
            },
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            json.starts_with(r#"{"error":"#),
            "envelope should start with `{{\"error\":`, got: {json}"
        );
        assert!(
            json.contains(r#""code":"USAGE_ERROR""#),
            "payload should contain code, got: {json}"
        );
    }

    #[test]
    fn success_envelope_ok_is_not_degraded() {
        let env = SuccessEnvelope::ok(serde_json::json!({"a": 1}));
        assert!(!env.degraded);
        assert!(env.notes.is_empty());
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""degraded":false"#), "got: {json}");
        assert!(json.contains(r#""notes":[]"#), "got: {json}");
    }

    #[test]
    fn success_envelope_with_notes_sets_degraded() {
        let env = SuccessEnvelope::with_notes_and_info(
            serde_json::json!(null),
            vec![String::from("oxlint not found")],
            Vec::new(),
        );
        assert!(env.degraded);
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains(r#""degraded":true"#), "got: {json}");
        assert!(
            json.contains(r#""notes":["oxlint not found"]"#),
            "got: {json}"
        );
    }

    #[test]
    fn success_envelope_with_empty_notes_is_not_degraded() {
        let env =
            SuccessEnvelope::with_notes_and_info(serde_json::json!(null), Vec::new(), Vec::new());
        assert!(!env.degraded);
    }

    // T-294 / T-295 (envelope layer): info-only notes appear in `notes`
    // without setting the degraded flag.
    #[test]
    fn success_envelope_with_info_only_is_not_degraded() {
        let env = SuccessEnvelope::with_notes_and_info(
            serde_json::json!(null),
            Vec::new(),
            vec![String::from("2 demoted")],
        );
        assert!(!env.degraded);
        assert_eq!(env.notes, vec![String::from("2 demoted")]);
    }

    // T-294 / T-295 (envelope layer): degradations alone decide the flag and
    // precede info notes in the merged `notes` order.
    #[test]
    fn success_envelope_orders_degradations_before_info() {
        let env = SuccessEnvelope::with_notes_and_info(
            serde_json::json!(null),
            vec![String::from("oxlint not found")],
            vec![String::from("2 demoted")],
        );
        assert!(env.degraded);
        assert_eq!(
            env.notes,
            vec![String::from("oxlint not found"), String::from("2 demoted")]
        );
    }

    #[test]
    fn error_code_serializes_screaming_snake_case() {
        let pairs = [
            (ErrorCode::UsageError, r#""USAGE_ERROR""#),
            (ErrorCode::DataError, r#""DATA_ERROR""#),
            (ErrorCode::IoError, r#""IO_ERROR""#),
        ];
        for (code, expected) in pairs {
            let actual = serde_json::to_string(&code).unwrap();
            assert_eq!(
                actual, expected,
                "code {code:?} should serialize as {expected}"
            );
        }
    }

    #[test]
    fn error_code_exit_code_matches_sysexits_h() {
        assert_eq!(ErrorCode::UsageError.exit_code(), 64);
        assert_eq!(ErrorCode::DataError.exit_code(), 65);
        assert_eq!(ErrorCode::IoError.exit_code(), 74);
    }
}
