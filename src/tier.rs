//! The method→tier table: which JSON-RPC methods the anonymous read tier may reach.
//!
//! Tiers come from the ecosystem RPC contract (`DESIGN_DIG_RPC.md` §1, dig-node `SPEC.md` §11).
//! The gateway serves the PUBLIC-READ tier and *only* that tier; PEER and CONTROL methods are
//! reachable on the node's own transports (mTLS peer port, loopback control), never through here.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The access tier a JSON-RPC method belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Anonymous, browser-reachable, CORS-enabled. The only tier this gateway forwards.
    PublicRead,
    /// Anything not on the public-read allowlist: PEER, CONTROL, wallet, or simply unknown.
    ///
    /// Unknown methods land here deliberately. A node upgrade that adds a method must add it to
    /// [`PUBLIC_READ_METHODS`] to expose it publicly — the gateway never widens itself by
    /// accident, and a method it has never heard of is refused rather than forwarded.
    Restricted,
}

/// Every method the anonymous public read tier may call, verbatim.
///
/// Sourced from the read-tier catalogue in `DESIGN_DIG_RPC.md` §1 plus the tier ruling in §2.5
/// (the chain-anchored reads are canonically PUBLIC-READ: they are facts a browser resolves
/// anonymously). Matching is **exact and case-sensitive** — see [`tier_of`].
///
/// Deliberately absent, and the reason each must stay absent:
///
/// | excluded | why |
/// |---|---|
/// | `dig.getPeers`, `dig.announce`, `dig.getNetworkInfo` | peer-exchange: lets an anonymous caller enumerate and inject into the peer graph |
/// | `dig.getAvailability`, `dig.listInventory`, `dig.fetchRange` | PEER tier; `listInventory` is a free map of everything this node holds |
/// | `cache.*` | control of what the node stores — the disk/cost-exhaustion surface |
/// | `control.*` | node lifecycle, upstream config, pin registry |
/// | `rpc.discover` | self-describes the *whole* surface including control; the gateway serves its own filtered discovery instead |
/// | anything wallet-shaped | the node's `9778` answers wallet RPC on bare method names; none may ever be reachable |
pub const PUBLIC_READ_METHODS: &[&str] = &[
    // --- content + proof reads ---
    "dig.getContent",
    "dig.getCapsule",
    "dig.getModule", // historical alias of dig.getCapsule
    "dig.getProof",
    "dig.getProofStatus",
    // --- manifest / metadata / listing ---
    "dig.getManifest",
    "dig.getMetadata",
    "dig.getPublicManifest",
    "dig.listCapsules",
    // --- chain-anchored reads (DESIGN_DIG_RPC.md §2.5: canonical tier is PUBLIC-READ) ---
    "dig.getAnchoredRoot",
    "dig.getCollection",
    "dig.listCollectionItems",
    // --- discovery ---
    "dig.health",
    "dig.methods",
];

/// The allowlist as a set, built once. `PUBLIC_READ_METHODS` stays a slice because it is the
/// human-readable source of truth; this is the lookup structure.
fn allowlist() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| PUBLIC_READ_METHODS.iter().copied().collect())
}

/// Classify a method name.
///
/// Matching is exact: no case folding, no trimming, no prefix matching. A caller that sends
/// `"DIG.getContent"`, `"dig.getContent "` or `"dig.getContentX"` is denied. Normalising here
/// would mean the gateway and the node could disagree about which method was called, which is
/// precisely how an allowlist gets walked past.
pub fn tier_of(method: &str) -> Tier {
    if allowlist().contains(method) {
        Tier::PublicRead
    } else {
        Tier::Restricted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_read_is_public() {
        assert_eq!(tier_of("dig.getContent"), Tier::PublicRead);
        assert_eq!(tier_of("dig.getCapsule"), Tier::PublicRead);
        assert_eq!(tier_of("dig.health"), Tier::PublicRead);
    }

    #[test]
    fn peer_tier_methods_are_restricted() {
        for m in [
            "dig.getPeers",
            "dig.announce",
            "dig.getNetworkInfo",
            "dig.getAvailability",
            "dig.listInventory",
            "dig.fetchRange",
        ] {
            assert_eq!(tier_of(m), Tier::Restricted, "{m} must not be public");
        }
    }

    #[test]
    fn control_and_cache_methods_are_restricted() {
        for m in [
            "control.status",
            "control.peerStatus",
            "control.config.setUpstream",
            "control.hostedStores.pin",
            "cache.getConfig",
            "cache.setCapBytes",
            "cache.clear",
            "cache.fetchAndCache",
            "rpc.discover",
        ] {
            assert_eq!(tier_of(m), Tier::Restricted, "{m} must not be public");
        }
    }

    /// The node's `9778` router answers `POST /:method` as WALLET rpc on bare method names.
    /// None of those shapes may classify as public.
    #[test]
    fn wallet_shaped_methods_are_restricted() {
        for m in [
            "sign",
            "getPublicKeys",
            "sendTransaction",
            "signMessage",
            "getBalance",
            "walletUnlock",
        ] {
            assert_eq!(tier_of(m), Tier::Restricted, "{m} must not be public");
        }
    }

    #[test]
    fn unknown_methods_default_to_restricted() {
        assert_eq!(tier_of("dig.somethingNew"), Tier::Restricted);
        assert_eq!(tier_of(""), Tier::Restricted);
    }

    /// Exact matching: no case folding, no trimming, no prefix acceptance. Each of these is a
    /// real bypass shape if the comparison is ever loosened.
    #[test]
    fn matching_is_exact() {
        for m in [
            "DIG.getContent",
            "dig.GetContent",
            "dig.getcontent",
            " dig.getContent",
            "dig.getContent ",
            "dig.getContent\n",
            "dig.getContentX",
            "dig.getContent\u{0}",
        ] {
            assert_eq!(tier_of(m), Tier::Restricted, "{m:?} must not be public");
        }
    }

    /// Guards against a duplicate or a stray entry creeping into the hand-maintained slice.
    #[test]
    fn allowlist_has_no_duplicates() {
        assert_eq!(allowlist().len(), PUBLIC_READ_METHODS.len());
    }

    /// A blunt tripwire: nothing on the allowlist may carry a control/cache/peer-ish prefix.
    /// If someone adds one, this fails before the gate ever ships.
    #[test]
    fn allowlist_contains_only_dig_read_namespace() {
        for m in PUBLIC_READ_METHODS {
            assert!(m.starts_with("dig."), "{m} is outside the dig. namespace");
            for banned in [
                "announce",
                "Peers",
                "Inventory",
                "fetchRange",
                "NetworkInfo",
            ] {
                assert!(!m.contains(banned), "{m} looks peer-tier");
            }
        }
    }
}
