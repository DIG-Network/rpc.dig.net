//! Minimal JSON-RPC 2.0 envelope reading — just enough to name every method a request invokes.
//!
//! The gateway does not interpret params, ids, or results; the node does that. All this module
//! answers is: *which methods does this body call?* — because that is the only question the tier
//! gate needs, and keeping it to that keeps the security boundary small enough to test
//! exhaustively.

use serde_json::Value;

/// Largest number of calls accepted in one batch.
///
/// A batch is a request amplifier: one HTTP request, N node calls. Left unbounded, a single POST
/// could fan out to an arbitrary number of capsule reads. 32 is comfortably above any real client
/// (the browser SDK batches a handful of manifest reads at most) and far below an amplification
/// worth mounting.
pub const MAX_BATCH_CALLS: usize = 32;

/// Why a body could not be read as a set of JSON-RPC calls.
///
/// Every variant is a refusal. There is no "parsed but odd" state that still reaches the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Body is neither a JSON object nor an array — not a JSON-RPC request at all.
    NotAnEnvelope,
    /// An empty batch (`[]`). Invalid per JSON-RPC 2.0 §6.
    EmptyBatch,
    /// A batch with more than [`MAX_BATCH_CALLS`] members.
    BatchTooLarge,
    /// A batch member that is not an object.
    NonObjectBatchMember,
    /// A call with no `method`, or a `method` that is not a string.
    ///
    /// This is the shape the node's DHT and PEX frame families use — they are dispatched on the
    /// body's *shape*, not on a `method` name. Refusing a method-less body is what stops a frame
    /// intended for the peer transport from being posted to the public read tier.
    MissingMethod,
}

impl EnvelopeError {
    /// The JSON-RPC error code to answer with. Malformed envelopes are `-32600` invalid-request;
    /// a method-less body is also an invalid request rather than a missing method, because no
    /// method was ever named.
    pub const fn code(self) -> i32 {
        -32600
    }

    /// A short, non-revealing message. It says the request was malformed and nothing about the
    /// node behind the gateway.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotAnEnvelope => "not a JSON-RPC 2.0 request",
            Self::EmptyBatch => "empty batch",
            Self::BatchTooLarge => "batch too large",
            Self::NonObjectBatchMember => "batch member is not an object",
            Self::MissingMethod => "request has no method",
        }
    }
}

/// Every method named by `body`, in order, or the reason the body is not a usable envelope.
///
/// Accepts the two legal JSON-RPC 2.0 shapes — a single call object, or a batch array of them —
/// and nothing else.
pub fn methods_of(body: &Value) -> Result<Vec<&str>, EnvelopeError> {
    match body {
        Value::Object(_) => Ok(vec![method_name(body)?]),
        Value::Array(calls) => read_batch(calls),
        _ => Err(EnvelopeError::NotAnEnvelope),
    }
}

/// Read a batch array, rejecting the empty, the oversized, and the non-object member.
fn read_batch(calls: &[Value]) -> Result<Vec<&str>, EnvelopeError> {
    if calls.is_empty() {
        return Err(EnvelopeError::EmptyBatch);
    }
    if calls.len() > MAX_BATCH_CALLS {
        return Err(EnvelopeError::BatchTooLarge);
    }
    calls
        .iter()
        .map(|call| {
            if !call.is_object() {
                return Err(EnvelopeError::NonObjectBatchMember);
            }
            method_name(call)
        })
        .collect()
}

/// The `method` of one call object, which must be present and a string.
fn method_name(call: &Value) -> Result<&str, EnvelopeError> {
    call.get("method")
        .and_then(Value::as_str)
        .ok_or(EnvelopeError::MissingMethod)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn single_call_yields_its_method() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "dig.getContent", "params": {}});
        assert_eq!(methods_of(&body).unwrap(), vec!["dig.getContent"]);
    }

    #[test]
    fn batch_yields_every_method_in_order() {
        let body = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "dig.getContent"},
            {"jsonrpc": "2.0", "id": 2, "method": "dig.getManifest"},
        ]);
        assert_eq!(
            methods_of(&body).unwrap(),
            vec!["dig.getContent", "dig.getManifest"]
        );
    }

    #[test]
    fn scalar_and_null_bodies_are_not_envelopes() {
        for body in [json!(null), json!(1), json!("dig.getContent"), json!(true)] {
            assert_eq!(methods_of(&body), Err(EnvelopeError::NotAnEnvelope));
        }
    }

    #[test]
    fn empty_batch_is_rejected() {
        assert_eq!(methods_of(&json!([])), Err(EnvelopeError::EmptyBatch));
    }

    #[test]
    fn oversized_batch_is_rejected() {
        let ok: Vec<_> = (0..MAX_BATCH_CALLS)
            .map(|_| json!({"method": "dig.getContent"}))
            .collect();
        assert!(methods_of(&Value::Array(ok)).is_ok());

        let too_big: Vec<_> = (0..MAX_BATCH_CALLS + 1)
            .map(|_| json!({"method": "dig.getContent"}))
            .collect();
        assert_eq!(
            methods_of(&Value::Array(too_big)),
            Err(EnvelopeError::BatchTooLarge)
        );
    }

    #[test]
    fn nested_array_member_is_rejected() {
        let body = json!([[{"method": "dig.getContent"}]]);
        assert_eq!(methods_of(&body), Err(EnvelopeError::NonObjectBatchMember));
    }

    /// A method-less body is the DHT/PEX shape-dispatched frame. It must never pass.
    #[test]
    fn method_less_body_is_rejected() {
        for body in [
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"find_node": {"target": "ab"}}),
            json!({"pex_handshake": {}}),
        ] {
            assert_eq!(methods_of(&body), Err(EnvelopeError::MissingMethod));
        }
    }

    #[test]
    fn non_string_method_is_rejected() {
        for m in [json!(1), json!(null), json!(["dig.getContent"]), json!({})] {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": m});
            assert_eq!(methods_of(&body), Err(EnvelopeError::MissingMethod));
        }
    }

    /// One malformed member spoils the batch — the reader never returns a partial list that a
    /// caller could mistake for "the methods that will run".
    #[test]
    fn one_bad_member_fails_the_whole_batch() {
        let body = json!([
            {"method": "dig.getContent"},
            {"no_method_here": true},
        ]);
        assert_eq!(methods_of(&body), Err(EnvelopeError::MissingMethod));
    }

    #[test]
    fn every_error_uses_the_invalid_request_code() {
        for e in [
            EnvelopeError::NotAnEnvelope,
            EnvelopeError::EmptyBatch,
            EnvelopeError::BatchTooLarge,
            EnvelopeError::NonObjectBatchMember,
            EnvelopeError::MissingMethod,
        ] {
            assert_eq!(e.code(), -32600);
            assert!(!e.message().is_empty());
        }
    }
}
