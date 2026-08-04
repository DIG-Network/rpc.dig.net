//! `.github/update-node.sh` — the in-place node update, tested as behaviour.
//!
//! This script runs as root, unattended, at 07:17 UTC, on the machine that serves the public read
//! tier. Everything that makes it safe is an ORDERING claim — "the checksum is verified before
//! anything is installed", "a failed start puts the old binary back" — and an ordering claim about
//! shell inside a workflow is unfalsifiable unless something drives it. dig_ecosystem#2037 is the
//! precedent: the certificate defect that cost ~21 hours was six lines of shell in a Terraform
//! template, unreachable from `cargo test`, so nothing could assert the property it broke.
//!
//! # How the harness works
//!
//! The script's paths are parameterised (`DIG_NODE_UPDATE_*`), so a test can point it at a sandbox
//! holding a fake `/usr/local/bin` and `/var/lib/dig-node`. Fakes for `curl`, `systemctl` and
//! `journalctl` go first on `PATH`, and the "node binary" is a shell script that prints a version.
//!
//! The coupling that makes the tests mean anything is in the fake `systemctl`: a restart reads the
//! version out of whichever binary is currently installed and records it as the version being
//! served. So "the node comes up on what was installed" is modelled rather than assumed, and a
//! rollback genuinely changes what the health probe sees — which is what lets
//! [`behaviour::a_node_that_does_not_come_up_is_rolled_back`] fail on a script that forgets to
//! restore.
//!
//! `sha256sum` and `install` are deliberately NOT faked. The checksum gate is the security
//! property under test, so it runs for real.

use std::path::{Path, PathBuf};

/// The repository root, from this test binary's own location.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn script_source() -> String {
    std::fs::read_to_string(repo_root().join(".github/update-node.sh"))
        .expect("read .github/update-node.sh")
}

// ---------------------------------------------------------------------------------------------
// Static assertions — properties readable from the file, checkable on any platform.
// ---------------------------------------------------------------------------------------------

/// `bash` rejects `restart_stack() {\r` outright, and this file is executed by SSM with no
/// cloud-init in the path to normalise it. `.gitattributes` pins `*.sh` to LF; this asserts it.
#[test]
fn the_update_script_is_stored_with_unix_line_endings() {
    assert!(
        !script_source().contains('\r'),
        ".github/update-node.sh contains CR; it must be stored LF-only (.gitattributes)"
    );
}

/// The verify-then-install ordering, asserted on the source itself.
///
/// The behavioural tests below prove the effect; this proves the *shape*, so a future edit that
/// reorders the file is caught even if a fake happens to make the effect look right.
#[test]
fn the_checksum_is_verified_before_anything_is_installed() {
    let src = script_source();
    let verify = src.find("sha256sum -c -").expect("a checksum check");
    let install = src.find("install -m 0755").expect("an install step");
    let swap = src.find("mv -f \"$CANDIDATE\" \"$BIN\"").expect("the swap");

    assert!(
        verify < install && install < swap,
        "the order must be verify -> stage -> swap; got verify@{verify} install@{install} swap@{swap}"
    );
}

/// The recorded version must not move until the new binary is proven to serve.
///
/// This one is about the INTERRUPTED path, which no fake can stage: if the stamp is written
/// straight after the swap, a kill between there and the health wait — an SSM execution timeout, a
/// SIGTERM, a reboot — leaves a stamp naming a release nothing verified, while the workflow never
/// reached the step that moves the repository variables. That is the pin/reality divergence
/// SPEC §7.2 forbids. Written after the health gate, the same interruption leaves the stamp naming
/// the OLD release, which the next run simply installs again.
#[test]
fn the_recorded_version_moves_only_after_the_node_is_proven_healthy() {
    let src = script_source();
    let swap = src.find(r#"mv -f "$CANDIDATE" "$BIN""#).expect("the swap");
    let health = src
        .find(r#"if await_healthy "${NEW_VERSION#v}""#)
        .expect("the health gate");
    // The rollback writes `"$CURRENT"`, so this find is unambiguously the success-path stamp.
    let stamp = src
        .find(r#"echo "$NEW_VERSION" >"$STAMP""#)
        .expect("the stamp write");

    assert!(
        swap < health && health < stamp,
        "the stamp must be written AFTER the health gate; got swap@{swap} health@{health} stamp@{stamp}"
    );
}

/// A `.deb` URL bricks this node. Selection is what prevents it (see `src/release.rs`), and
/// nothing in the script may reconstruct an artifact name of its own.
#[test]
fn the_script_never_builds_an_artifact_url_of_its_own() {
    let src = script_source();
    assert!(
        !src.contains("releases/download"),
        "the artifact URL is chosen and validated by src/release.rs and passed in; the script \
         must not assemble one"
    );
}

#[cfg(unix)]
mod behaviour {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Output};

    /// A sandboxed host: a fake bin directory, a fake state directory, and fakes for every
    /// external program the script can reach except the ones under test.
    struct Sandbox {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    /// What one run of the script did.
    struct Run {
        output: Output,
    }

    impl Run {
        fn succeeded(&self) -> bool {
            self.output.status.success()
        }
        fn log(&self) -> String {
            format!(
                "{}{}",
                String::from_utf8_lossy(&self.output.stdout),
                String::from_utf8_lossy(&self.output.stderr)
            )
        }
    }

    impl Sandbox {
        /// A host currently running `installed`, with `available` published for download.
        fn new(installed: &str, available: &str) -> Sandbox {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_path_buf();
            for sub in ["bin", "usrbin", "state", "artifacts"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }

            let sandbox = Sandbox { _dir: dir, root };
            sandbox.write_node_binary(&sandbox.path("usrbin").join("dig-node"), installed);
            // With a trailing newline, exactly as `echo > DIG_NODE_VERSION` writes it in user_data.
            fs::write(
                sandbox.path("state").join("DIG_NODE_VERSION"),
                format!("{installed}\n"),
            )
            .unwrap();
            // Nothing is being served until something starts; a restart sets this.
            fs::write(sandbox.path("serving"), installed.trim_start_matches('v')).unwrap();
            fs::write(sandbox.path("gateway_ok"), "1").unwrap();

            sandbox.publish_artifact(available);
            sandbox.install_fake_curl();
            sandbox.install_fake_systemctl();
            sandbox.install_fake_journalctl();
            sandbox
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        fn write_executable(&self, path: &Path, body: &str) {
            fs::write(path, body).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        /// A stand-in for the node binary: it answers `--version` and nothing else, which is all
        /// the update path ever asks of it.
        fn write_node_binary(&self, at: &Path, version: &str) {
            let bare = version.trim_start_matches('v');
            self.write_executable(
                at,
                &format!("#!/usr/bin/env bash\necho 'dig-node {bare}'\n"),
            );
        }

        /// Publish a downloadable release artifact. Returns its real sha256.
        fn publish_artifact(&self, version: &str) -> String {
            let at = self.path("artifacts").join(format!("dig-node-{version}"));
            self.write_node_binary(&at, version);
            sha256_of(&at)
        }

        /// A release artifact that is not an executable this machine can run — a wrong-arch build,
        /// or a `.deb` that slipped through. It still has a perfectly good checksum.
        fn publish_unrunnable_artifact(&self, version: &str) -> String {
            let at = self.path("artifacts").join(format!("dig-node-{version}"));
            fs::write(&at, b"\x7fELF-for-some-other-machine").unwrap();
            sha256_of(&at)
        }

        /// The version the node reports once it is up. A restart overwrites this from whichever
        /// binary is installed, so tests set it only to model a node that comes up WRONG.
        fn make_node_come_up_broken(&self) {
            self.write_executable(
                self.path("bin").join("systemctl").as_path(),
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/systemctl.log"
# The node starts, but never becomes healthy — a crash loop, or a build that exits at once.
printf '' >"$SANDBOX/serving"
exit 0
"#,
            );
        }

        fn stop_the_gateway_answering(&self) {
            fs::write(self.path("gateway_ok"), "0").unwrap();
        }

        /// `curl` reduced to the three calls the script makes.
        ///
        /// Download copies from the sandbox's artifact directory, so the bytes the checksum runs
        /// over are real bytes on disk. The health probe reports whatever the fake `systemctl`
        /// last recorded, which is what ties "is it healthy" to "what is installed".
        fn install_fake_curl(&self) {
            self.write_executable(
                self.path("bin").join("curl").as_path(),
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/curl.log"

# Download: `-o <dest> <url>`. The URL's basename names a file in the artifact directory.
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    --resolve|--max-time|-H|-d) shift 2 ;;
    http*|localhost*) url="$1"; shift ;;
    *) shift ;;
  esac
done

if [ -n "$dest" ]; then
  src="$SANDBOX/artifacts/$(basename "$url")"
  [ -f "$src" ] || { echo "404 $url" >&2; exit 22; }
  cp "$src" "$dest"
  exit 0
fi

case "$url" in
  localhost:9778)
    v="$(cat "$SANDBOX/serving" 2>/dev/null || true)"
    [ -n "$v" ] || exit 7           # nothing is listening
    printf '{"jsonrpc":"2.0","id":1,"result":{"status":"ok","version":"%s"}}' "$v"
    ;;
  https://*/health)
    [ "$(cat "$SANDBOX/gateway_ok")" = "1" ] || exit 7
    echo ok
    ;;
  *) echo "unexpected curl target: $url" >&2; exit 99 ;;
esac
"#,
            );
        }

        /// A restart brings the node up ON THE INSTALLED BINARY. That single line is what makes a
        /// rollback observable: restore the old binary and the health probe starts reporting the
        /// old version again, exactly as it would on the real host.
        fn install_fake_systemctl(&self) {
            self.write_executable(
                self.path("bin").join("systemctl").as_path(),
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/systemctl.log"
if [ "$1" = "restart" ] && [ "$2" = "dig-node.service" ]; then
  "$SANDBOX/usrbin/dig-node" --version | awk '{print $2}' >"$SANDBOX/serving"
fi
exit 0
"#,
            );
        }

        fn install_fake_journalctl(&self) {
            self.write_executable(
                self.path("bin").join("journalctl").as_path(),
                "#!/usr/bin/env bash\necho 'fake journal'\nexit 0\n",
            );
        }

        fn read(&self, relative: &str) -> String {
            fs::read_to_string(self.path(relative)).unwrap_or_default()
        }

        fn installed_version(&self) -> String {
            let out = Command::new(self.path("usrbin").join("dig-node"))
                .arg("--version")
                .output()
                .expect("query the installed binary");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        /// The recorded installed version, trimmed — it is written with `echo` on the host and
        /// with `fs::write` here, and the newline is not the property under test.
        fn stamp(&self) -> String {
            self.read("state/DIG_NODE_VERSION").trim().to_string()
        }

        fn systemctl_log(&self) -> String {
            self.read("systemctl.log")
        }

        fn run(&self, version: &str, sha: &str, allow_downgrade: bool) -> Run {
            let script = repo_root().join(".github/update-node.sh");
            let path = format!(
                "{}:{}",
                self.path("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let output = Command::new("bash")
                .arg(&script)
                .env("PATH", path)
                .env("SANDBOX", &self.root)
                .env(
                    "NEW_URL",
                    format!("https://example.invalid/dig-node-{version}"),
                )
                .env("NEW_SHA", sha)
                .env("NEW_VERSION", version)
                .env("ALLOW_DOWNGRADE", if allow_downgrade { "1" } else { "0" })
                .env("DIG_NODE_UPDATE_BIN_DIR", self.path("usrbin"))
                .env("DIG_NODE_UPDATE_STATE_DIR", self.path("state"))
                .env("DIG_NODE_UPDATE_CERT_ENV", self.path("no-such-env-file"))
                .env("DIG_NODE_UPDATE_OWNER", current_owner())
                .env("DIG_NODE_UPDATE_HEALTH_TIMEOUT", "6")
                .output()
                .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
            Run { output }
        }
    }

    fn sha256_of(path: &Path) -> String {
        let out = Command::new("sha256sum")
            .arg(path)
            .output()
            .expect("sha256sum");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .expect("a digest")
            .to_string()
    }

    /// `user:group` for the current process — the tests are not root and cannot chown to it.
    fn current_owner() -> String {
        let name = |flag: &str| {
            let out = Command::new("id").arg(flag).output().expect("id");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        format!("{}:{}", name("-un"), name("-gn"))
    }

    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_good_release_is_installed_and_served() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");

        let run = host.run("v0.93.9", &sha, false);

        assert!(run.succeeded(), "update failed:\n{}", run.log());
        assert_eq!(host.installed_version(), "dig-node 0.93.9");
        assert_eq!(host.stamp(), "v0.93.9");
        assert_eq!(host.read("serving").trim(), "0.93.9");
        assert!(run.log().contains("UPDATED v0.84.0 -> v0.93.9"));
    }

    /// The public read tier is in front of this node, and `rpc-gateway` declares
    /// `Requires=dig-node.service` — so systemd may stop it alongside the node. An update that
    /// restarts only the node can leave rpc.dig.net down while reporting success.
    #[test]
    fn the_gateway_is_brought_back_up_too() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");

        assert!(host.run("v0.93.9", &sha, false).succeeded());

        assert!(
            host.systemctl_log().contains("start rpc-gateway.service"),
            "the gateway was never started; log was:\n{}",
            host.systemctl_log()
        );
    }

    /// The security property, run against real `sha256sum` over real bytes.
    #[test]
    fn a_checksum_mismatch_installs_nothing_and_never_touches_the_service() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        host.publish_artifact("v0.93.9");
        let wrong = "0".repeat(64);

        let run = host.run("v0.93.9", &wrong, false);

        assert!(!run.succeeded(), "a bad checksum must fail the update");
        assert_eq!(
            host.installed_version(),
            "dig-node 0.84.0",
            "the running binary was replaced despite a failed checksum"
        );
        assert_eq!(host.stamp(), "v0.84.0", "the recorded version moved");
        assert_eq!(
            host.systemctl_log(),
            "",
            "the service was touched before the bytes were proven"
        );
    }

    /// A checksum proves provenance, not that the file runs here. This host is Graviton; an amd64
    /// build has a perfectly valid digest and cannot execute.
    #[test]
    fn an_artifact_that_cannot_execute_here_installs_nothing() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_unrunnable_artifact("v0.93.9");

        let run = host.run("v0.93.9", &sha, false);

        assert!(!run.succeeded(), "an unrunnable artifact must fail");
        assert_eq!(host.installed_version(), "dig-node 0.84.0");
        assert_eq!(host.stamp(), "v0.84.0");
        assert_eq!(
            host.systemctl_log(),
            "",
            "the service was restarted for a binary that cannot run"
        );
    }

    /// The whole point of doing this unattended: a bad release must not leave the tier down.
    #[test]
    fn a_node_that_does_not_come_up_is_rolled_back() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");
        host.make_node_come_up_broken();

        let run = host.run("v0.93.9", &sha, false);

        assert!(
            !run.succeeded(),
            "a node that never serves must fail loudly"
        );
        assert!(
            run.log().contains("ROLLED BACK") || run.log().contains("CRITICAL"),
            "the failure was silent:\n{}",
            run.log()
        );
        assert_eq!(
            host.installed_version(),
            "dig-node 0.84.0",
            "the new binary was left in place after it failed to serve"
        );
        assert_eq!(
            host.stamp(),
            "v0.84.0",
            "the recorded version still claims the release that failed"
        );
    }

    /// The node is fine but the tier it exists to serve is not. Both are failures.
    #[test]
    fn a_healthy_node_behind_a_dead_gateway_is_still_a_failure() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");
        host.stop_the_gateway_answering();

        let run = host.run("v0.93.9", &sha, false);

        assert!(
            !run.succeeded(),
            "an update that leaves the read tier dead must not report success:\n{}",
            run.log()
        );
        assert_eq!(host.installed_version(), "dig-node 0.84.0");
    }

    #[test]
    fn a_downgrade_is_refused_unless_it_was_asked_for() {
        let host = Sandbox::new("v0.93.9", "v0.84.0");
        let sha = host.publish_artifact("v0.84.0");

        let refused = host.run("v0.84.0", &sha, false);
        assert!(!refused.succeeded());
        assert!(refused.log().contains("REFUSING"), "{}", refused.log());
        assert_eq!(host.installed_version(), "dig-node 0.93.9");
        assert_eq!(host.systemctl_log(), "");

        let deliberate = host.run("v0.84.0", &sha, true);
        assert!(
            deliberate.succeeded(),
            "a deliberate rollback must work:\n{}",
            deliberate.log()
        );
        assert_eq!(host.installed_version(), "dig-node 0.84.0");
        assert_eq!(host.stamp(), "v0.84.0");
    }

    /// `v0.9.0` sorts above `v0.84.0` as a string. The guard has to order numerically or it lets
    /// exactly the regression it exists to stop straight through.
    #[test]
    fn the_downgrade_guard_orders_numerically() {
        let host = Sandbox::new("v0.84.0", "v0.9.0");
        let sha = host.publish_artifact("v0.9.0");

        let run = host.run("v0.9.0", &sha, false);

        assert!(
            !run.succeeded() && run.log().contains("REFUSING"),
            "v0.9.0 is older than v0.84.0 and must be refused:\n{}",
            run.log()
        );
    }

    #[test]
    fn re_running_on_the_installed_version_does_nothing() {
        let host = Sandbox::new("v0.93.9", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");

        let run = host.run("v0.93.9", &sha, false);

        assert!(run.succeeded());
        assert_eq!(host.systemctl_log(), "", "a no-op restarted the service");
        assert!(
            !host.read("curl.log").contains("-o"),
            "a no-op downloaded the artifact anyway"
        );
    }

    /// A successful update leaves the binary it replaced beside the new one, so recovering from a
    /// release that is healthy but wrong is a rename rather than a download.
    #[test]
    fn the_previous_binary_is_kept_for_a_manual_rollback() {
        let host = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = host.publish_artifact("v0.93.9");

        assert!(host.run("v0.93.9", &sha, false).succeeded());

        let previous = host.path("usrbin").join("dig-node.rollback");
        assert!(previous.is_file(), "no dig-node.rollback was left behind");
        let out = Command::new(&previous).arg("--version").output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "dig-node 0.84.0"
        );
    }

    /// Nothing half-installed may be left lying in the binary directory on any path.
    #[test]
    fn no_candidate_file_survives_any_outcome() {
        let candidate_left =
            |host: &Sandbox| host.path("usrbin").join("dig-node.candidate").exists();

        let good = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = good.publish_artifact("v0.93.9");
        good.run("v0.93.9", &sha, false);
        assert!(!candidate_left(&good), "a candidate survived a good update");

        let bad_sum = Sandbox::new("v0.84.0", "v0.93.9");
        bad_sum.publish_artifact("v0.93.9");
        bad_sum.run("v0.93.9", &"0".repeat(64), false);
        assert!(
            !candidate_left(&bad_sum),
            "a candidate survived a checksum failure"
        );

        let broken = Sandbox::new("v0.84.0", "v0.93.9");
        let sha = broken.publish_artifact("v0.93.9");
        broken.make_node_come_up_broken();
        broken.run("v0.93.9", &sha, false);
        assert!(!candidate_left(&broken), "a candidate survived a rollback");
    }
}
