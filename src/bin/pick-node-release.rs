//! `pick-node-release` — which `dig-node` release should the rpc.dig.net host install?
//!
//! Reads the GitHub releases JSON on **stdin** and writes `GITHUB_OUTPUT` lines on **stdout**:
//!
//! ```text
//! gh api repos/DIG-Network/dig-node/releases --paginate \
//!   | pick-node-release --current v0.84.0 >>"$GITHUB_OUTPUT"
//! ```
//!
//! Reading stdin rather than calling the API keeps this binary I/O-free apart from its own pipes,
//! which is what lets [`rpc_dig_net::release`] hold the entire decision under unit test. Every
//! rule it applies, and why each one exists, is documented there.
//!
//! Exits non-zero with a message on stderr when no release can be chosen — a release set with no
//! installable artifact is a condition the deploy must see, not one to paper over.

use std::io::Read;
use std::process::ExitCode;

use rpc_dig_net::release::{github_output, plan};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let current = match flag(&args, "--current") {
        Some(tag) => tag,
        None => {
            eprintln!("usage: pick-node-release --current <tag> [--require <tag>] <releases.json");
            return ExitCode::FAILURE;
        }
    };
    let require = flag(&args, "--require");

    let mut releases_json = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut releases_json) {
        eprintln!("could not read the releases JSON from stdin: {e}");
        return ExitCode::FAILURE;
    }

    match plan(&releases_json, &current, require.as_deref()) {
        Ok(chosen) => {
            print!("{}", github_output(&chosen));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("cannot choose a dig-node release: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The value following `name`, if it was given.
fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}
