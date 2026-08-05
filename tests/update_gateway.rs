//! `.github/update-gateway.sh` — the in-place gateway update, tested as behaviour.
//!
//! This script runs as root, on a deploy, on the machine that serves the public read tier. It
//! exists so that a routine deploy stops replacing the instance (dig_ecosystem#2034): terraform
//! leaves the box still and this swaps one checksum-verified binary instead. Everything that makes
//! it safe is an ORDERING claim — "the checksum is verified before anything is installed", "a
//! gateway that does not serve is rolled back" — and an ordering claim about shell inside a workflow
//! is unfalsifiable unless something drives it.
//!
//! # How the harness works
//!
//! The script's paths and its `file`/`curl`/`systemctl` calls are parameterised or shadowed on
//! `PATH`, so a test can point it at a sandbox holding a fake `/usr/local/bin`. The coupling that
//! makes the tests mean anything is in the fake `systemctl`: a restart reads the installed binary
//! and records whether it "serves", so a rollback genuinely changes what the health probe sees.
//!
//! `sha256sum` and `install` are deliberately NOT faked — the checksum gate is the security property
//! under test, so it runs for real. `file` IS faked: the runner is x86 and cannot make a real
//! aarch64 ELF, so the arch branch is modelled by a marker in the artifact bytes.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn script_source() -> String {
    std::fs::read_to_string(repo_root().join(".github/update-gateway.sh"))
        .expect("read .github/update-gateway.sh")
}

// -------------------------------------------------------------------------------------------------
// Static assertions — properties readable from the file, checkable on any platform.
// -------------------------------------------------------------------------------------------------

#[test]
fn the_update_script_is_stored_with_unix_line_endings() {
    assert!(
        !script_source().contains('\r'),
        ".github/update-gateway.sh contains CR; it must be stored LF-only (.gitattributes)"
    );
}

/// verify -> stage -> swap. A future edit that reorders the file is caught even if a fake happens to
/// make the effect look right.
#[test]
fn the_checksum_is_verified_before_anything_is_installed() {
    let src = script_source();
    let verify = src.find("sha256sum -c -").expect("a checksum check");
    let install = src.find("install -m 0755").expect("an install step");
    let swap = src.find(r#"mv -f "$CANDIDATE" "$BIN""#).expect("the swap");
    assert!(
        verify < install && install < swap,
        "order must be verify -> stage -> swap; got verify@{verify} install@{install} swap@{swap}"
    );
}

/// The gateway is judged on what it SERVES, before the run is allowed to report success — the swap
/// must come before the health gate, and the health gate before the success exit.
#[test]
fn success_is_judged_on_serving_not_on_installing() {
    let src = script_source();
    let swap = src.find(r#"mv -f "$CANDIDATE" "$BIN""#).expect("the swap");
    let gate = src.find("if await_serving; then").expect("the health gate");
    let ok = src
        .find("INSTALLED gateway $NEW_SHA")
        .expect("the success message");
    assert!(
        swap < gate && gate < ok,
        "success must follow a health gate; got swap@{swap} gate@{gate} ok@{ok}"
    );
}

/// The port the health probe uses is derived from the unit, never a literal (same root cause as
/// dig_ecosystem#2034 on the verify script).
#[test]
fn the_health_probe_port_is_derived_from_the_unit() {
    let src = script_source();
    assert!(
        src.contains("systemctl show \"$UNIT\" --property=Environment"),
        "the gateway port must be read from the unit's GATEWAY_LISTEN"
    );
    assert!(
        !src.contains("node-rpc.dig.net:443:"),
        "the health probe must not hardcode :443"
    );
}

#[cfg(unix)]
mod behaviour {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Output};

    struct Sandbox {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

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

    /// Artifact bytes carry two independent markers: `ELFAARCH64` (the fake `file` reports an
    /// aarch64 ELF) and `GOOD`/`BROKEN` (the fake `systemctl` restart records whether it serves).
    const GOOD: &str = "ELFAARCH64\nGOOD gateway\n";
    const BROKEN_SERVING: &str = "ELFAARCH64\nBROKEN gateway\n";
    const NOT_AN_EXECUTABLE: &str = "just some bytes, no ELF marker\n";

    impl Sandbox {
        /// A host currently serving on `installed` bytes.
        fn new(installed: &str) -> Sandbox {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_path_buf();
            for sub in ["bin", "usrbin", "artifacts"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            let sandbox = Sandbox { _dir: dir, root };
            fs::write(sandbox.path("usrbin").join("rpc-gateway"), installed).unwrap();
            // Something is serving to begin with; a restart recomputes it from the installed bytes.
            fs::write(sandbox.path("serving"), "1").unwrap();
            sandbox.install_fake_curl();
            sandbox.install_fake_systemctl();
            sandbox.install_fake_file();
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

        /// Publish downloadable artifact bytes under `name`; returns their real sha256.
        fn publish(&self, name: &str, bytes: &str) -> String {
            let at = self.path("artifacts").join(name);
            fs::write(&at, bytes).unwrap();
            sha256_of(&at)
        }

        /// `curl` reduced to the two calls the script makes: a download, and the TLS health probe.
        fn install_fake_curl(&self) {
            self.write_executable(
                self.path("bin").join("curl").as_path(),
                r#"#!/usr/bin/env bash
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    --resolve|--max-time|-H|-d) shift 2 ;;
    http*) url="$1"; shift ;;
    *) shift ;;
  esac
done
if [ -n "$dest" ]; then
  src="$SANDBOX/artifacts/$(basename "$url")"
  [ -f "$src" ] || { echo "404 $url" >&2; exit 22; }
  cp "$src" "$dest"; exit 0
fi
case "$url" in
  https://*/health) [ "$(cat "$SANDBOX/serving")" = "1" ] || exit 7; echo ok ;;
  *) echo "unexpected curl target: $url" >&2; exit 99 ;;
esac
"#,
            );
        }

        /// A restart brings the gateway up ON THE INSTALLED BINARY: it serves iff those bytes carry
        /// the `GOOD` marker. That single coupling is what makes a rollback observable.
        fn install_fake_systemctl(&self) {
            self.write_executable(
                self.path("bin").join("systemctl").as_path(),
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/systemctl.log"
case "$1" in
  is-active) exit 0 ;;
  show) echo 'GATEWAY_LISTEN=0.0.0.0:8080 DIG_NODE_URL=http://127.0.0.1:9778' ;;
  restart)
    if grep -q GOOD "$SANDBOX/usrbin/rpc-gateway" 2>/dev/null; then
      echo 1 >"$SANDBOX/serving"
    else
      echo 0 >"$SANDBOX/serving"
    fi ;;
esac
exit 0
"#,
            );
        }

        /// The arch classifier: an `ELFAARCH64` marker makes it an aarch64 ELF, anything else is data.
        fn install_fake_file(&self) {
            self.write_executable(
                self.path("bin").join("file").as_path(),
                r#"#!/usr/bin/env bash
target="${!#}"
if grep -q ELFAARCH64 "$target" 2>/dev/null; then
  echo "ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked"
else
  echo "data"
fi
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

        fn installed_bytes(&self) -> String {
            self.read("usrbin/rpc-gateway")
        }

        fn systemctl_log(&self) -> String {
            self.read("systemctl.log")
        }

        fn run(&self, url_name: &str, sha: &str) -> Run {
            let script = repo_root().join(".github/update-gateway.sh");
            let path = format!(
                "{}:{}",
                self.path("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let output = Command::new("bash")
                .arg(&script)
                .env("PATH", path)
                .env("SANDBOX", &self.root)
                .env("NEW_URL", format!("https://example.invalid/{url_name}"))
                .env("NEW_SHA", sha)
                .env("GATEWAY_UPDATE_BIN_DIR", self.path("usrbin"))
                .env("GATEWAY_UPDATE_CERT_ENV", self.path("no-such-env-file"))
                .env("GATEWAY_UPDATE_OWNER", current_owner())
                .env("GATEWAY_UPDATE_UNIT_TIMEOUT", "6")
                .env("GATEWAY_UPDATE_HEALTH_TIMEOUT", "6")
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

    fn current_owner() -> String {
        let name = |flag: &str| {
            let out = Command::new("id").arg(flag).output().expect("id");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        format!("{}:{}", name("-un"), name("-gn"))
    }

    // ---------------------------------------------------------------------------------------------

    #[test]
    fn a_good_gateway_is_installed_and_served() {
        let host = Sandbox::new("ELFAARCH64\nGOOD old\n");
        let sha = host.publish("rpc-gateway-aarch64", GOOD);

        let run = host.run("rpc-gateway-aarch64", &sha);

        assert!(run.succeeded(), "update failed:\n{}", run.log());
        assert_eq!(
            host.installed_bytes(),
            GOOD,
            "the new binary was not installed"
        );
        assert_eq!(host.read("serving").trim(), "1");
        assert!(run.log().contains("INSTALLED gateway"), "{}", run.log());
    }

    /// The security property, run against real `sha256sum` over real bytes.
    #[test]
    fn a_checksum_mismatch_installs_nothing_and_never_touches_the_service() {
        let old = "ELFAARCH64\nGOOD old\n";
        let host = Sandbox::new(old);
        host.publish("rpc-gateway-aarch64", GOOD);
        let wrong = "0".repeat(64);

        let run = host.run("rpc-gateway-aarch64", &wrong);

        assert!(!run.succeeded(), "a bad checksum must fail the update");
        assert_eq!(
            host.installed_bytes(),
            old,
            "the binary was replaced despite a bad checksum"
        );
        assert_eq!(
            host.systemctl_log().matches("restart").count(),
            0,
            "the service was restarted"
        );
    }

    /// A checksum proves provenance, not that the file runs here. This host is Graviton; a non-ELF
    /// or wrong-arch artifact has a perfectly valid digest and cannot execute.
    #[test]
    fn an_artifact_that_cannot_execute_here_installs_nothing() {
        let old = "ELFAARCH64\nGOOD old\n";
        let host = Sandbox::new(old);
        let sha = host.publish("rpc-gateway-aarch64", NOT_AN_EXECUTABLE);

        let run = host.run("rpc-gateway-aarch64", &sha);

        assert!(!run.succeeded(), "an unrunnable artifact must fail");
        assert_eq!(host.installed_bytes(), old);
        assert_eq!(host.systemctl_log().matches("restart").count(), 0);
    }

    /// The whole point of doing this on a live box: a gateway that does not come back up must be
    /// rolled back to the one that was serving, not left broken in front of the public.
    #[test]
    fn a_gateway_that_does_not_serve_is_rolled_back() {
        let old = "ELFAARCH64\nGOOD old\n";
        let host = Sandbox::new(old);
        let sha = host.publish("rpc-gateway-aarch64", BROKEN_SERVING);

        let run = host.run("rpc-gateway-aarch64", &sha);

        assert!(
            !run.succeeded(),
            "a gateway that never serves must fail loudly"
        );
        assert!(
            run.log().contains("ROLLED BACK") || run.log().contains("CRITICAL"),
            "the failure was silent:\n{}",
            run.log()
        );
        assert_eq!(
            host.installed_bytes(),
            old,
            "the broken binary was left in place"
        );
        assert_eq!(host.read("serving").trim(), "1", "the tier was left down");
    }

    /// A fresh instance already has exactly these bytes from user_data; the deploy's in-place step
    /// must be a no-op there rather than bouncing a healthy gateway.
    #[test]
    fn re_installing_the_same_bytes_does_nothing() {
        let host = Sandbox::new(GOOD);
        let sha = host.publish("rpc-gateway-aarch64", GOOD);

        let run = host.run("rpc-gateway-aarch64", &sha);

        assert!(run.succeeded(), "{}", run.log());
        assert_eq!(
            host.systemctl_log().matches("restart").count(),
            0,
            "a no-op restarted the gateway"
        );
        assert!(run.log().contains("nothing to do"), "{}", run.log());
    }

    /// A successful update leaves the binary it replaced beside the new one, so recovering from a
    /// bad-but-serving build is a rename rather than a download.
    #[test]
    fn the_previous_binary_is_kept_for_a_manual_rollback() {
        let old = "ELFAARCH64\nGOOD old\n";
        let host = Sandbox::new(old);
        let sha = host.publish("rpc-gateway-aarch64", GOOD);

        assert!(host.run("rpc-gateway-aarch64", &sha).succeeded());

        assert_eq!(
            host.read("usrbin/rpc-gateway.rollback"),
            old,
            "no rollback copy was kept"
        );
    }

    /// Nothing half-installed may be left lying in the binary directory on any path.
    #[test]
    fn no_candidate_file_survives_any_outcome() {
        let candidate_left = |h: &Sandbox| h.path("usrbin").join("rpc-gateway.candidate").exists();

        let good = Sandbox::new("ELFAARCH64\nGOOD old\n");
        let sha = good.publish("rpc-gateway-aarch64", GOOD);
        good.run("rpc-gateway-aarch64", &sha);
        assert!(!candidate_left(&good), "a candidate survived a good update");

        let bad = Sandbox::new("ELFAARCH64\nGOOD old\n");
        bad.publish("rpc-gateway-aarch64", BROKEN_SERVING);
        let sha = sha256_of(&bad.path("artifacts").join("rpc-gateway-aarch64"));
        bad.run("rpc-gateway-aarch64", &sha);
        assert!(!candidate_left(&bad), "a candidate survived a rollback");
    }
}
