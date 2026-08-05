//! `.github/verify-node.sh` — the post-deploy acceptance check, asserted as source properties.
//!
//! This script runs on the host over SSM and is the gate every deploy passes. Its two load-bearing
//! properties for dig_ecosystem#2034 are checkable by reading the file:
//!
//! 1. The gateway port is DERIVED from the running unit, not hardcoded — a second literal is exactly
//!    what drifted (probing 8080 while the gateway bound 443) and reported every healthy deploy RED.
//! 2. The health probe and the routable-listener boundary assertion are still present and still
//!    fail the deploy when the gateway is down — the fix corrects the port, it does not weaken the
//!    control.
//!
//! A behavioural harness for this script would need a whole fake host (ss, systemctl, journalctl,
//! mountpoint, a peer journal); these source assertions pin the exact regressions the ticket
//! describes without that machinery, and the real behavioural proof is the on-host run every deploy
//! performs.

use std::path::{Path, PathBuf};

fn script_source() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    std::fs::read_to_string(root.join(".github/verify-node.sh")).expect("read .github/verify-node.sh")
}

fn _repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// `bash` rejects a function header ending in `\r`, and SSM runs this file with no cloud-init in the
/// path to normalise it. `.gitattributes` pins `*.sh` to LF; this asserts it.
#[test]
fn the_verify_script_is_stored_with_unix_line_endings() {
    assert!(
        !script_source().contains('\r'),
        ".github/verify-node.sh contains CR; it must be stored LF-only (.gitattributes)"
    );
}

/// The port MUST come from the running unit's `GATEWAY_LISTEN`, never a literal. This is the
/// dig_ecosystem#2034 regression: a hardcoded second copy drifted from what the gateway binds.
#[test]
fn the_gateway_port_is_derived_from_the_running_unit() {
    let src = script_source();
    assert!(
        src.contains("systemctl show rpc-gateway.service --property=Environment"),
        "the port must be read from the unit's GATEWAY_LISTEN, not hardcoded"
    );
    assert!(
        src.contains("GATEWAY_PORT=\"${GATEWAY_LISTEN##*:}\""),
        "the port must be taken from GATEWAY_LISTEN"
    );
}

/// No probe or boundary assertion may name a bare gateway-port literal. `443`/`8080` appearing only
/// inside `$GATEWAY_PORT`-derived expressions is fine; a standalone `:443$`/`:8080$` in a grep or a
/// `node-rpc.dig.net:443` in `--resolve` would be the exact drift this ticket removes.
#[test]
fn no_hardcoded_gateway_port_literal_remains_in_a_probe_or_assertion() {
    let src = script_source();
    for needle in [
        "node-rpc.dig.net:443:",
        "node-rpc.dig.net:8080:",
        ":(9444|9445|443)",
        ":(9444|9445|8080)",
        "localhost:8080",
    ] {
        assert!(
            !src.contains(needle),
            "verify-node.sh still hardcodes the gateway port via `{needle}`; derive it from \
             GATEWAY_LISTEN instead (dig_ecosystem#2034)"
        );
    }
}

/// The fix must not weaken the check: the /health probe (fatal `curl -fsS` under `set -e`) and the
/// routable-listener boundary assertion both survive, so a genuinely down gateway still fails the
/// deploy.
#[test]
fn the_health_probe_and_listener_boundary_are_intact() {
    let src = script_source();
    assert!(src.contains("set -euo pipefail"), "the script must run under set -e");
    assert!(
        src.contains("\"${RESOLVE[@]}\" \"$GATEWAY/health\""),
        "the fatal /health probe against the derived port must remain"
    );
    assert!(
        src.contains("FAIL: unexpected listener(s) on a routable address"),
        "the routable-listener boundary assertion must remain"
    );
    // The boundary allowlist must be built from the derived port, not a literal.
    assert!(
        src.contains(":(9444|9445|$GATEWAY_PORT)"),
        "the listener allowlist must use the derived $GATEWAY_PORT"
    );
}
