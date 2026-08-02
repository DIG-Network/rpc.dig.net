//! The tier gate: the single decision that keeps the node's non-public surface unreachable.
//!
//! [`screen`] is a pure function of the request body. It is the whole boundary — if it returns
//! [`Verdict::Allow`], the body is forwarded to the node verbatim; if it returns
//! [`Verdict::Deny`], the body never leaves the gateway. There is no other path to the node.

use crate::jsonrpc::{methods_of, EnvelopeError};
use crate::tier::{tier_of, Tier};
use serde_json::Value;

/// Reported when a method is refused.
///
/// The gateway answers `-32601 method not found` for a restricted method rather than a
/// "forbidden" code, so an anonymous caller cannot tell a method that exists-but-is-privileged
/// from one that does not exist. This matches how the node answers management methods on its own
/// peer surface (`dig-node SPEC` §11) — one consistent, uninformative answer.
pub const METHOD_NOT_FOUND: i32 = -32601;

/// The gate's decision about one request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every call in the body is on the public-read allowlist. Forward it unchanged.
    Allow,
    /// Refuse. Answer with this JSON-RPC error and do not contact the node.
    Deny {
        /// JSON-RPC error code to return.
        code: i32,
        /// Short, non-revealing message.
        message: &'static str,
    },
}

impl Verdict {
    /// Whether this verdict permits forwarding. Reads better than matching at call sites.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// Decide whether `body` may reach the node.
///
/// A body is allowed only when it is a well-formed JSON-RPC 2.0 envelope **and every call in it**
/// names a public-read method. A batch is all-or-nothing on purpose: forwarding the permitted
/// members of a mixed batch would let a caller smuggle a restricted call alongside a legitimate
/// one and learn, from the shape of the reply, that it was stripped.
pub fn screen(body: &Value) -> Verdict {
    let methods = match methods_of(body) {
        Ok(methods) => methods,
        Err(e) => return deny_envelope(e),
    };

    match methods.iter().find(|m| tier_of(m) != Tier::PublicRead) {
        Some(_) => Verdict::Deny {
            code: METHOD_NOT_FOUND,
            message: "method not found",
        },
        None => Verdict::Allow,
    }
}

/// Turn a malformed-envelope error into a denial.
fn deny_envelope(e: EnvelopeError) -> Verdict {
    Verdict::Deny {
        code: e.code(),
        message: e.message(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn denied(body: &Value) -> bool {
        !screen(body).is_allowed()
    }

    #[test]
    fn a_public_read_call_is_allowed() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "dig.getContent", "params": {}});
        assert_eq!(screen(&body), Verdict::Allow);
    }

    #[test]
    fn an_all_public_batch_is_allowed() {
        let body = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "dig.getManifest"},
            {"jsonrpc": "2.0", "id": 2, "method": "dig.getContent"},
            {"jsonrpc": "2.0", "id": 3, "method": "dig.health"},
        ]);
        assert_eq!(screen(&body), Verdict::Allow);
    }

    #[test]
    fn a_restricted_call_is_denied_as_method_not_found() {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "control.status"});
        assert_eq!(
            screen(&body),
            Verdict::Deny {
                code: METHOD_NOT_FOUND,
                message: "method not found",
            }
        );
    }

    /// The batch-smuggling case. A single restricted member denies the entire batch — this is
    /// the bypass an element-by-element gate exists to close.
    #[test]
    fn one_restricted_member_denies_the_whole_batch() {
        for smuggled in [
            "control.status",
            "cache.clear",
            "dig.listInventory",
            "dig.getPeers",
            "sign",
        ] {
            let body = json!([
                {"jsonrpc": "2.0", "id": 1, "method": "dig.getContent"},
                {"jsonrpc": "2.0", "id": 2, "method": smuggled},
                {"jsonrpc": "2.0", "id": 3, "method": "dig.getManifest"},
            ]);
            assert!(denied(&body), "{smuggled} smuggled through a batch");
        }
    }

    /// Position must not matter: first, middle and last are screened identically.
    #[test]
    fn a_restricted_member_is_caught_in_any_position() {
        let bad = json!({"method": "cache.setCapBytes"});
        let good = json!({"method": "dig.getContent"});
        for batch in [
            json!([bad, good, good]),
            json!([good, bad, good]),
            json!([good, good, bad]),
        ] {
            assert!(denied(&batch));
        }
    }

    #[test]
    fn every_peer_and_control_method_is_denied() {
        for m in [
            "dig.getPeers",
            "dig.announce",
            "dig.getNetworkInfo",
            "dig.getAvailability",
            "dig.listInventory",
            "dig.fetchRange",
            "cache.getConfig",
            "cache.setCapBytes",
            "cache.clear",
            "cache.listCached",
            "cache.removeCached",
            "cache.fetchAndCache",
            "control.status",
            "control.peerStatus",
            "control.sync.trigger",
            "control.hostedStores.pin",
            "rpc.discover",
        ] {
            assert!(denied(&json!({"method": m})), "{m} reached the node");
        }
    }

    #[test]
    fn shape_dispatched_peer_frames_are_denied() {
        for body in [
            json!({"find_node": {"target": "ab"}}),
            json!({"find_providers": {"key": "ab"}}),
            json!({"add_provider": {"key": "ab"}}),
            json!({"ping": {}}),
            json!({"pex_handshake": {}}),
            json!({"pex_snapshot": {}}),
        ] {
            assert!(denied(&body), "{body} reached the node");
        }
    }

    #[test]
    fn malformed_envelopes_are_denied_as_invalid_request() {
        for body in [json!(null), json!([]), json!("dig.getContent"), json!(7)] {
            match screen(&body) {
                Verdict::Deny { code, .. } => assert_eq!(code, -32600),
                Verdict::Allow => panic!("{body} was allowed"),
            }
        }
    }

    #[test]
    fn an_oversized_batch_is_denied_even_when_every_member_is_public() {
        let calls: Vec<_> = (0..crate::jsonrpc::MAX_BATCH_CALLS + 1)
            .map(|_| json!({"method": "dig.getContent"}))
            .collect();
        assert!(denied(&Value::Array(calls)));
    }

    /// Deny-by-default: a method the gateway has never heard of is refused, not forwarded. A node
    /// upgrade cannot widen the public surface without an explicit allowlist entry here.
    #[test]
    fn an_unknown_method_is_denied() {
        assert!(denied(&json!({"method": "dig.brandNewThing"})));
        assert!(denied(&json!({"method": "dig.getContentButEvil"})));
    }

    /// Every allowlisted method really does pass — otherwise the gate would be a silent outage.
    #[test]
    fn every_allowlisted_method_is_allowed() {
        for m in crate::tier::PUBLIC_READ_METHODS {
            assert_eq!(
                screen(&json!({"jsonrpc": "2.0", "id": 1, "method": m})),
                Verdict::Allow,
                "{m} is on the allowlist but the gate denied it"
            );
        }
    }
}
