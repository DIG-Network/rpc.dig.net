//! The origin certificate's lifecycle, tested as behaviour rather than as prose.
//!
//! # Why this file exists
//!
//! On 2026-08-03 the read tier was down for ~21 hours (dig_ecosystem#2037). Nothing was wrong
//! with the gateway, the node, or the capsules. The certificate lived only on instance-local
//! disk, Terraform replaces the instance on every deploy, and so every deploy *bought a new
//! certificate* instead of reusing one. The sixth replacement in a day hit Let's Encrypt's
//! five-per-week limit for that exact identifier set, and the gateway — which exits when the
//! cert file is missing — crash-looped 47 times with no way to self-recover.
//!
//! The defect was never visible in a unit test because the certificate logic was six lines of
//! shell inside a Terraform template: unreachable from `cargo test`, so nothing could assert
//! that a replacement is cheap. These tests make that assertion.
//!
//! The one that matters most is
//! [`a_restored_certificate_means_lets_encrypt_is_never_contacted`]. It fails on the code that
//! caused the outage and passes on the fix, which is the only property that keeps the read tier
//! from being one deploy away from a week of downtime.
//!
//! # How the behavioural half works
//!
//! `dig-origin-cert` talks to exactly three programs: `aws`, `certbot`, and `systemctl`. The
//! harness puts fakes for all three first on `PATH` and points the script at a sandbox state
//! directory, so a test can hand it any starting condition — nothing stored, a fresh certificate
//! stored, a corrupt payload stored — and then read back precisely which external calls it made.
//! Asserting on the *calls* is what makes "never contacted Let's Encrypt" a checkable claim
//! rather than a hopeful one.
//!
//! Those tests need a POSIX shell, `tar`, `base64` and `openssl`, so they are `cfg(unix)` and run
//! on the Linux CI runner — the same platform the script is deployed to. The template-invariant
//! tests below them compile everywhere.

use std::path::PathBuf;

/// Repository root, derived from the manifest so the tests do not care about the working
/// directory `cargo` was invoked from.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn user_data() -> String {
    read("infra/user_data.sh.tftpl")
}

// ---------------------------------------------------------------------------------------------
// Template invariants — the second defect on #2037: a bootstrap that lied about what it had done.
// ---------------------------------------------------------------------------------------------

/// The bootstrap must not promise a degraded mode that does not exist.
///
/// It used to log "the gateway will start WITHOUT TLS and CloudFront (https-only) cannot reach
/// it" when certbot failed. The gateway does not start without TLS — it reads the cert path at
/// startup and exits — so an operator reading that line was told the service was limping when it
/// was dead. Either implement the fallback or do not claim it; this test holds the second choice.
/// Only emitted text is inspected, not comments: a comment recording why the claim was wrong is
/// worth keeping, and it is the message reaching the operator that did the damage.
#[test]
fn the_bootstrap_never_claims_the_gateway_runs_without_tls() {
    let script = user_data();
    let offenders: Vec<&str> = script
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.to_lowercase().contains("without tls"))
        .collect();
    assert!(
        offenders.is_empty(),
        "the bootstrap tells the operator the gateway runs without TLS. It cannot — it reads the \
         certificate at startup and exits (dig_ecosystem#2037): {offenders:?}"
    );
}

/// A missing certificate must stop the bootstrap, not hand systemd a unit that cannot start.
///
/// Enabling a gateway with no certificate produces a restart loop, which reads as "starting" in
/// `systemctl status` while the origin is in fact down. The bootstrap must exit non-zero instead.
#[test]
fn the_bootstrap_fails_rather_than_starting_a_gateway_with_no_certificate() {
    let script = user_data();
    let gate = script
        .split_once("--- The gateway starts only with a certificate")
        .map(|(_, rest)| rest)
        .expect("user_data must have an explicit no-certificate gate before enabling the gateway");
    assert!(
        gate.contains("exit 1"),
        "the no-certificate branch must fail the bootstrap loudly (dig_ecosystem#2037)"
    );
}

/// Certificate acquisition must go through the restore-first helper.
///
/// A bare `certbot certonly` in the bootstrap is the outage: it makes every instance replacement
/// buy a new certificate. The template may reference the helper, never the raw order.
#[test]
fn the_bootstrap_does_not_order_a_certificate_directly() {
    assert!(
        !user_data().contains("certbot certonly"),
        "user_data orders a certificate directly; issuance must go through `dig-origin-cert \
         ensure`, which restores first (dig_ecosystem#2037)"
    );
}

/// The renewal timer must publish renewals back to the durable copy.
///
/// A renewal that is not published means the stored copy ages out, and the first replacement
/// after it expires is back to issuing from scratch.
#[test]
fn the_renewal_timer_runs_through_the_helper_so_renewals_are_published() {
    assert!(
        user_data().contains("dig-origin-cert renew"),
        "certbot-renew must call the helper, so a renewed certificate is written back to the \
         durable copy instead of living only on this instance"
    );
}

// ---------------------------------------------------------------------------------------------
// Behavioural tests — the helper driven against fake `aws`, `certbot` and `systemctl`.
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
mod behaviour {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Output};

    const HOST: &str = "node-rpc.dig.net";
    const SAN: &str = "rpc-origin.dig.net";
    const SECRET: &str = "rpc.dig.net/origin-cert";

    /// The test user's own primary group — one it can `chgrp` to without being root.
    fn current_group() -> String {
        let out = Command::new("id").arg("-gn").output().expect("id -gn");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A sandboxed installation of the helper: its own state directory, its own stored-secret
    /// file, and fakes for every external program it can reach.
    struct Sandbox {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Sandbox {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().to_path_buf();
            fs::create_dir_all(root.join("bin")).unwrap();
            fs::create_dir_all(root.join("state")).unwrap();

            let sandbox = Sandbox { _dir: dir, root };
            sandbox.install_fake_aws();
            sandbox.install_fake_certbot();
            sandbox.install_fake_systemctl();
            sandbox
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.root.join(relative)
        }

        /// Where the helper believes `/etc/letsencrypt` is.
        fn state_dir(&self) -> PathBuf {
            self.path("state")
        }

        /// The stand-in for the Secrets Manager value. Absent means "the secret has no version",
        /// which is exactly what a freshly created secret looks like.
        fn stored_secret(&self) -> PathBuf {
            self.path("stored-secret.b64")
        }

        fn write_executable(&self, name: &str, body: &str) {
            let path = self.path("bin").join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        /// `aws` reduced to the two calls the helper makes, backed by a file on disk.
        ///
        /// The failure messages matter as much as the successes. The real API reports "the secret
        /// has no value yet" and "you may not read this secret" through *different* error codes,
        /// and the helper is required to treat them differently — one may lead to an order, the
        /// other must never. A stub that failed the same way for both would make
        /// [`an_unreadable_secret_never_leads_to_an_order`] pass for the wrong reason.
        ///
        /// It also records its full argument list, which is how
        /// [`the_private_key_is_never_passed_on_a_command_line`] can prove the key never reaches
        /// a process listing.
        fn install_fake_aws(&self) {
            self.write_executable(
                "aws",
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/aws.log"
for arg in "$@"; do
  case "$arg" in
    get-secret-value)
      if [ -f "$SANDBOX/aws-unreadable" ]; then
        echo "An error occurred (AccessDeniedException) when calling the GetSecretValue operation: not authorized" >&2
        exit 255
      fi
      if [ -s "$SANDBOX/stored-secret.b64" ]; then
        cat "$SANDBOX/stored-secret.b64"; exit 0
      fi
      echo "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret value for staging label: AWSCURRENT" >&2
      exit 254 ;;
  esac
done
case "$*" in
  *put-secret-value*)
    for arg in "$@"; do
      case "$arg" in file://*) cp "${arg#file://}" "$SANDBOX/stored-secret.b64" ;; esac
    done
    echo '{"VersionId":"fake"}' ;;
  *describe-secret*) echo '{"Name":"fake"}' ;;
esac
exit 0
"#,
            );
        }

        /// `certbot` reduced to "write a certificate where certbot would have written one".
        ///
        /// `renew` only produces a new certificate when a test asks for one, mirroring the real
        /// thing: certbot exits 0 whether or not anything was due.
        fn install_fake_certbot(&self) {
            self.write_executable(
                "certbot",
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/certbot.log"
[ -f "$SANDBOX/certbot-fails" ] && exit 1
case "$1" in
  certonly) "$SANDBOX/bin/make-cert" 90 ;;
  renew)    [ -f "$SANDBOX/renewal-is-due" ] && "$SANDBOX/bin/make-cert" 90 ;;
esac
exit 0
"#,
            );
        }

        fn install_fake_systemctl(&self) {
            self.write_executable(
                "systemctl",
                r#"#!/usr/bin/env bash
printf '%s\n' "$*" >>"$SANDBOX/systemctl.log"
exit 0
"#,
            );
        }

        /// Writes a self-signed certificate into the sandbox state directory, laid out the way
        /// certbot lays one out. `$1` is the number of days it stays valid, so a test can produce
        /// both a comfortably-fresh certificate and one inside the renewal window.
        fn install_cert_writer(&self) {
            self.write_executable(
                "make-cert",
                r#"#!/usr/bin/env bash
set -e
live="$SANDBOX/state/live/node-rpc.dig.net"
mkdir -p "$live" "$SANDBOX/state/renewal" "$SANDBOX/state/accounts"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -days "$1" -subj "/CN=node-rpc.dig.net" \
  -keyout "$live/privkey.pem" -out "$live/cert.pem" 2>/dev/null
cp "$live/cert.pem" "$live/fullchain.pem"
: >"$SANDBOX/state/renewal/node-rpc.dig.net.conf"
"#,
            );
        }

        /// Put a certificate valid for `days` into the state directory.
        fn given_a_certificate_on_disk(&self, days: u32) {
            self.install_cert_writer();
            let status = Command::new(self.path("bin").join("make-cert"))
                .arg(days.to_string())
                .env("SANDBOX", &self.root)
                .status()
                .expect("make-cert");
            assert!(status.success(), "could not build the test certificate");
        }

        /// Store a hand-built archive: a valid certificate for this host, plus whatever a test
        /// wants to smuggle in alongside it. The certificate already on disk is left in place, so
        /// a test can also assert the hostile payload did not displace it.
        ///
        /// This is the shape that matters for the secret's integrity: the payload is written by an
        /// identity the node itself holds, so "it contains a valid certificate" is not evidence
        /// that it is safe to unpack as root.
        fn given_a_stored_archive_smuggling(&self, extra: &[(&str, &str)]) {
            self.given_a_certificate_on_disk(90);

            let hostile = self.path("hostile");
            let _ = fs::remove_dir_all(&hostile);
            let live = hostile.join("live").join(HOST);
            fs::create_dir_all(&live).unwrap();
            for name in ["cert.pem", "fullchain.pem", "privkey.pem"] {
                fs::copy(
                    self.state_dir().join("live").join(HOST).join(name),
                    live.join(name),
                )
                .unwrap();
            }
            for (path, body) in extra {
                let target = hostile.join(path);
                fs::create_dir_all(target.parent().unwrap()).unwrap();
                fs::write(&target, body).unwrap();
            }

            let packed = Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "tar -czf - -C '{}' . | base64 -w0 > '{}'",
                    hostile.display(),
                    self.stored_secret().display()
                ))
                .status()
                .expect("packing the archive");
            assert!(packed.success(), "could not build the test archive");
        }

        /// Put a certificate valid for `days` into the *stored secret*, and leave the disk empty
        /// — the state a replacement instance boots into.
        fn given_a_certificate_only_in_the_secret(&self, days: u32) {
            self.given_a_certificate_on_disk(days);
            self.run("save").expect_success();
            fs::remove_dir_all(self.state_dir()).unwrap();
            fs::create_dir_all(self.state_dir()).unwrap();
        }

        fn run(&self, subcommand: &str) -> Run {
            self.install_cert_writer();
            let script = repo_root().join("infra/dig-origin-cert.sh");
            let path = format!(
                "{}:{}",
                self.path("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            let output = Command::new("bash")
                .arg(&script)
                .arg(subcommand)
                .env("PATH", path)
                .env("SANDBOX", &self.root)
                .env("DIG_ORIGIN_CERT_SECRET", SECRET)
                .env("DIG_ORIGIN_CERT_HOST", HOST)
                .env("DIG_ORIGIN_CERT_SAN", SAN)
                .env("DIG_ORIGIN_CERT_STATE_DIR", self.state_dir())
                .env("DIG_ORIGIN_CERT_RETRY_DELAY", "0")
                // The helper grants the gateway's group read access to the certificate. Tests do
                // not run as root, so point it at a group the test user is already in — the
                // permission logic is still exercised, without needing to create a group.
                .env("DIG_ORIGIN_CERT_GROUP", current_group())
                .env("AWS_DEFAULT_REGION", "us-east-1")
                .output()
                .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
            Run {
                subcommand: subcommand.to_string(),
                output,
            }
        }

        fn log(&self, name: &str) -> String {
            fs::read_to_string(self.path(name)).unwrap_or_default()
        }

        fn certbot_calls(&self) -> String {
            self.log("certbot.log")
        }

        fn aws_calls(&self) -> String {
            self.log("aws.log")
        }

        fn secret_holds_a_certificate(&self) -> bool {
            self.stored_secret().exists()
                && fs::metadata(self.stored_secret())
                    .map(|m| m.len())
                    .unwrap_or(0)
                    > 0
        }

        fn certificate_on_disk(&self) -> Option<Vec<u8>> {
            fs::read(
                self.state_dir()
                    .join("live")
                    .join(HOST)
                    .join("fullchain.pem"),
            )
            .ok()
        }
    }

    struct Run {
        subcommand: String,
        output: Output,
    }

    impl Run {
        fn expect_success(self) -> Run {
            assert!(
                self.output.status.success(),
                "`dig-origin-cert {}` failed:\n{}",
                self.subcommand,
                String::from_utf8_lossy(&self.output.stderr)
            );
            self
        }

        fn expect_failure(self) -> Run {
            assert!(
                !self.output.status.success(),
                "`dig-origin-cert {}` unexpectedly succeeded:\n{}",
                self.subcommand,
                String::from_utf8_lossy(&self.output.stderr)
            );
            self
        }
    }

    /// **The outage regression.** A replacement instance that can restore must not order a
    /// certificate — that is the whole reason the read tier went down.
    #[test]
    fn a_restored_certificate_means_lets_encrypt_is_never_contacted() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_only_in_the_secret(90);

        sandbox.run("ensure").expect_success();

        assert!(
            sandbox.certbot_calls().is_empty(),
            "a replacement ordered a certificate it did not need: {}",
            sandbox.certbot_calls()
        );
        assert!(
            sandbox.certificate_on_disk().is_some(),
            "ensure reported success without leaving a certificate on disk"
        );
    }

    /// **An unreadable secret is not an absent one.** Ordering must never happen on an unknown
    /// state.
    ///
    /// A throttle, an `AccessDenied` while an IAM policy is still propagating, or a network blip
    /// all make the read fail without saying anything about whether a certificate is stored.
    /// Treating that as "nothing stored" spends one of five weekly issuances to re-obtain
    /// something we already had — and five of those is another week of downtime.
    #[test]
    fn an_unreadable_secret_never_leads_to_an_order() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_only_in_the_secret(90);
        sandbox.given_a_certificate_on_disk(90);
        fs::write(sandbox.path("aws-unreadable"), "").unwrap();

        sandbox.run("ensure").expect_success();

        assert!(
            sandbox.certbot_calls().is_empty(),
            "an unreadable secret triggered an order: {}",
            sandbox.certbot_calls()
        );
    }

    /// The same rule with nothing to fall back on: stop, rather than guess.
    ///
    /// Refusing leaves the origin down until an operator looks, which is bad — but it is
    /// recoverable in minutes with the issuance budget intact. Guessing wrong burns the budget and
    /// is recoverable in a week.
    #[test]
    fn an_unreadable_secret_with_nothing_on_disk_stops_instead_of_ordering() {
        let sandbox = Sandbox::new();
        fs::write(sandbox.path("aws-unreadable"), "").unwrap();

        sandbox.run("ensure").expect_failure();

        assert!(
            sandbox.certbot_calls().is_empty(),
            "ordered a certificate against an unknown state: {}",
            sandbox.certbot_calls()
        );
    }

    /// A certificate already on this host is published, not re-bought.
    ///
    /// This is the first boot after the secret is created, and the state the host was left in by
    /// the manual recovery on 2026-08-03: a perfectly good certificate on disk and an empty
    /// secret. Ordering here would be paying for something already in hand.
    #[test]
    fn a_certificate_already_on_disk_is_published_rather_than_reordered() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);

        sandbox.run("ensure").expect_success();

        assert!(
            sandbox.certbot_calls().is_empty(),
            "re-ordered a certificate the host already had: {}",
            sandbox.certbot_calls()
        );
        assert!(
            sandbox.secret_holds_a_certificate(),
            "the existing certificate was not published, so the next boot would order one"
        );
    }

    /// A renewal that fails at boot must not take the origin down.
    ///
    /// The certificate is inside the renewal window but still valid for weeks, and the timer
    /// retries twice a day. Aborting the bootstrap over a Route53 or ACME hiccup would turn a
    /// non-event into an outage — the same shape of failure as #2037 itself.
    #[test]
    fn a_failed_boot_renewal_still_serves_a_valid_certificate() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_only_in_the_secret(5);
        fs::write(sandbox.path("certbot-fails"), "").unwrap();

        sandbox.run("ensure").expect_success();

        assert!(
            sandbox.certbot_calls().contains("renew"),
            "renewal was not even attempted: {}",
            sandbox.certbot_calls()
        );
        assert!(
            sandbox.certificate_on_disk().is_some(),
            "a failed renewal discarded a certificate that was still valid"
        );
    }

    /// With nothing stored there is no alternative to issuing — but it must ask for BOTH names.
    ///
    /// The second name is not decoration. Let's Encrypt rate-limits duplicate certificates per
    /// exact set of identifiers, and the single-name set is the one that was exhausted during the
    /// outage. Dropping it silently moves issuance back onto the burnt bucket.
    #[test]
    fn with_nothing_stored_a_certificate_is_ordered_for_both_names() {
        let sandbox = Sandbox::new();

        sandbox.run("ensure").expect_success();

        let calls = sandbox.certbot_calls();
        assert!(
            calls.contains("certonly"),
            "no certificate was ordered: {calls}"
        );
        assert!(
            calls.contains(&format!("-d {HOST}")) && calls.contains(&format!("-d {SAN}")),
            "the order must name both identifiers so it lands in its own rate-limit bucket: {calls}"
        );
    }

    /// Issuing must publish, or the next replacement issues again and the outage repeats.
    #[test]
    fn a_freshly_issued_certificate_is_published_for_the_next_boot() {
        let sandbox = Sandbox::new();

        sandbox.run("ensure").expect_success();

        assert!(
            sandbox.secret_holds_a_certificate(),
            "an issued certificate was not published, so the next replacement would issue again"
        );
    }

    /// A restored certificate inside the renewal window is renewed rather than re-ordered from
    /// scratch, which keeps it in the same rate-limit bucket and keeps certbot's state coherent.
    #[test]
    fn a_stored_certificate_near_expiry_is_renewed_not_reordered() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_only_in_the_secret(5);
        fs::write(sandbox.path("renewal-is-due"), "").unwrap();

        sandbox.run("ensure").expect_success();

        let calls = sandbox.certbot_calls();
        assert!(
            calls.contains("renew"),
            "a near-expiry certificate was not renewed: {calls}"
        );
        assert!(
            !calls.contains("certonly"),
            "a near-expiry certificate was re-ordered instead of renewed: {calls}"
        );
    }

    /// A corrupt stored payload must not be able to destroy a working certificate.
    ///
    /// Restore replaces the state directory wholesale, so an unvalidated payload could leave the
    /// host with neither the stored copy nor the one it already had — turning a recoverable
    /// problem into the outage again.
    #[test]
    fn a_corrupt_stored_payload_leaves_the_working_certificate_untouched() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);
        let before = sandbox
            .certificate_on_disk()
            .expect("a certificate to protect");
        fs::write(sandbox.stored_secret(), "this is not a base64 tarball").unwrap();

        sandbox.run("restore").expect_failure();

        assert_eq!(
            sandbox.certificate_on_disk().as_deref(),
            Some(before.as_slice()),
            "a corrupt payload destroyed the certificate the host was already serving"
        );
    }

    /// **The secret is an input to a root-privileged unpack, so its integrity is a privilege
    /// boundary.**
    ///
    /// The node's own role can write that secret. An attacker who reaches the unprivileged
    /// `dignode` account — the identity behind the two internet-facing peer ports — can therefore
    /// replace the payload with one that carries a real certificate *and* a certbot hook. certbot
    /// runs those as root, at boot and twice daily. Worse, every future instance restores the same
    /// payload, so tainting and replacing the box — the one remediation this stack has — would
    /// re-infect it.
    #[test]
    fn an_archive_smuggling_a_certbot_hook_is_refused() {
        let sandbox = Sandbox::new();
        sandbox.given_a_stored_archive_smuggling(&[(
            "renewal-hooks/pre/00-pwn.sh",
            "#!/bin/sh\ntouch /tmp/pwned\n",
        )]);
        let before = sandbox
            .certificate_on_disk()
            .expect("a certificate to protect");

        sandbox.run("restore").expect_failure();

        assert_eq!(
            sandbox.certificate_on_disk().as_deref(),
            Some(before.as_slice()),
            "a hostile archive displaced the certificate the host was serving"
        );
        assert!(
            !sandbox.state_dir().join("renewal-hooks").exists(),
            "a directory of root-executed hooks was installed from the stored payload"
        );
    }

    /// The other half of the same vector: a hook recorded *inside* a renewal config.
    ///
    /// This archive is otherwise legitimate, so it restores — but `renew_hook` is a command
    /// certbot runs as root, and it is not part of a certificate. It must not survive the trip.
    #[test]
    fn a_renewal_hook_recorded_in_the_config_is_stripped_on_restore() {
        let sandbox = Sandbox::new();
        sandbox.given_a_stored_archive_smuggling(&[(
            &format!("renewal/{HOST}.conf"),
            "version = 2.11.0\nrenew_hook = /bin/sh -c 'touch /tmp/pwned'\narchive_dir = /etc/letsencrypt/archive/x\n",
        )]);

        sandbox.run("restore").expect_success();

        let installed = fs::read_to_string(
            sandbox
                .state_dir()
                .join("renewal")
                .join(format!("{HOST}.conf")),
        )
        .expect("the renewal config should have been restored");
        assert!(
            !installed.contains("renew_hook"),
            "a root-executed hook survived into the installed renewal config:\n{installed}"
        );
        assert!(
            installed.contains("archive_dir"),
            "stripping hooks must not gut the rest of the config:\n{installed}"
        );
    }

    /// certbot must never be allowed to run its hook directories, on either path.
    ///
    /// Stripping hooks out of the restored config closes one door; `/etc/letsencrypt/renewal-hooks`
    /// is the other, and certbot reads it by default whatever the config says.
    #[test]
    fn certbot_is_never_allowed_to_run_directory_hooks() {
        let sandbox = Sandbox::new();
        sandbox.run("ensure").expect_success();
        assert!(
            sandbox.certbot_calls().contains("--no-directory-hooks"),
            "issuing left directory hooks enabled: {}",
            sandbox.certbot_calls()
        );

        let renewing = Sandbox::new();
        renewing.given_a_certificate_on_disk(90);
        renewing.run("renew").expect_success();
        assert!(
            renewing.certbot_calls().contains("--no-directory-hooks"),
            "renewal left directory hooks enabled: {}",
            renewing.certbot_calls()
        );
    }

    /// "Non-empty" is not "a certificate", and the bootstrap gates the gateway on this answer.
    ///
    /// A one-byte `fullchain.pem` passes a `-s` test, so a payload that is merely *shaped* like a
    /// certificate would be installed, pass the bootstrap's final check, and hand systemd a
    /// gateway that exits at startup — reinstating the crash loop this change exists to remove.
    #[test]
    fn a_certificate_that_does_not_parse_is_not_treated_as_usable() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);
        let live = sandbox.state_dir().join("live").join(HOST);
        fs::write(live.join("fullchain.pem"), "x").unwrap();

        sandbox.run("check").expect_failure();
    }

    /// A key that parses but belongs to a different certificate is not a usable pair either.
    #[test]
    fn a_certificate_and_key_that_do_not_match_are_not_treated_as_usable() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);
        let live = sandbox.state_dir().join("live").join(HOST);
        let stolen = sandbox.path("other-key.pem");
        Command::new("bash")
            .arg("-c")
            .arg(format!(
                "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out '{}' 2>/dev/null",
                stolen.display()
            ))
            .status()
            .expect("generating an unrelated key");
        fs::copy(&stolen, live.join("privkey.pem")).unwrap();

        sandbox.run("check").expect_failure();
    }

    /// What we publish must not be able to carry a hook either — the allowlist on the way in is
    /// only half of it, and a payload written by this host is the one every future host restores.
    #[test]
    fn publishing_never_includes_the_hook_directory() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);
        let hooks = sandbox.state_dir().join("renewal-hooks").join("deploy");
        fs::create_dir_all(&hooks).unwrap();
        fs::write(hooks.join("leftover.sh"), "#!/bin/sh\n").unwrap();

        sandbox.run("save").expect_success();

        let listing = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "base64 -d < '{}' | tar -tzf -",
                sandbox.stored_secret().display()
            ))
            .output()
            .expect("listing the published archive");
        let listing = String::from_utf8_lossy(&listing.stdout);
        assert!(
            !listing.contains("renewal-hooks"),
            "the published payload carries a hook directory:\n{listing}"
        );
        assert!(
            listing.contains(&format!("live/{HOST}/fullchain.pem")),
            "the published payload is missing the certificate:\n{listing}"
        );
    }

    /// A well-formed archive that simply does not contain this host's certificate is refused for
    /// the same reason: it would replace something serving with something that cannot serve.
    #[test]
    fn a_stored_archive_without_this_hosts_certificate_is_refused() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);
        let empty_archive = Command::new("bash")
            .arg("-c")
            .arg("tar -czf - -T /dev/null | base64 -w0")
            .output()
            .expect("building an empty archive");
        fs::write(sandbox.stored_secret(), empty_archive.stdout).unwrap();

        sandbox.run("restore").expect_failure();

        assert!(
            sandbox.certificate_on_disk().is_some(),
            "an archive with no certificate for this host replaced a working one"
        );
    }

    /// The renewal timer runs twice a day. Publishing unconditionally would write a new secret
    /// version and bounce the gateway every time, for months, with nothing having changed.
    #[test]
    fn renewal_publishes_only_when_the_certificate_actually_changed() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);

        sandbox.run("renew").expect_success();
        assert!(
            !sandbox.aws_calls().contains("put-secret-value"),
            "a no-op renewal published a new version: {}",
            sandbox.aws_calls()
        );
        assert!(
            !sandbox.log("systemctl.log").contains("rpc-gateway"),
            "a no-op renewal restarted the gateway"
        );

        fs::write(sandbox.path("renewal-is-due"), "").unwrap();
        sandbox.run("renew").expect_success();
        assert!(
            sandbox.aws_calls().contains("put-secret-value"),
            "a real renewal was not published, so the stored copy would go stale"
        );
        assert!(
            sandbox.log("systemctl.log").contains("rpc-gateway"),
            "a renewed certificate was not served — the gateway holds the old one until it \
             restarts"
        );
    }

    /// The private key must reach Secrets Manager through a file, never through `argv`.
    ///
    /// Anything on a command line is readable by any process on the host via `/proc`, and this
    /// box is deliberately internet-facing.
    #[test]
    fn the_private_key_is_never_passed_on_a_command_line() {
        let sandbox = Sandbox::new();
        sandbox.given_a_certificate_on_disk(90);

        sandbox.run("save").expect_success();

        let calls = sandbox.aws_calls();
        assert!(
            calls.contains("put-secret-value"),
            "nothing was published: {calls}"
        );
        assert!(
            calls.contains("file://"),
            "the payload must be handed over as a file reference: {calls}"
        );
        assert!(
            !calls.contains("BEGIN") && !calls.contains("PRIVATE KEY"),
            "key material appeared in an argument list"
        );
    }

    /// The bootstrap exactly as an instance receives it: every Terraform placeholder filled in and
    /// the helper injected into its heredoc.
    ///
    /// Both the syntax check and the size check need this, and they need it to be *faithful* — a
    /// render that leaves placeholders in measures a script shorter than the real one and parses a
    /// script that is not the one that boots.
    fn render_bootstrap() -> String {
        // Substitute the scalars and check for leftovers BEFORE injecting the helper. The helper is
        // full of legitimate `${...}` shell expansions, so once it is in there is no way left to
        // tell a shell expansion from a Terraform placeholder nobody substituted.
        //
        // Values are representative in LENGTH, not just in shape, because the size check below
        // depends on them.
        let substitutions = [
            ("cache_root", "/var/lib/dig-node/cache"),
            ("capsule_bucket", "dig-rpc-node-capsules"),
            ("region", "us-east-1"),
            ("cache_cap", "18446744073709551615"),
            ("gateway_port", "443"),
            ("dig_node_version", "v0.84.0"),
            (
                "dig_node_url",
                "https://github.com/DIG-Network/dig-node/releases/download/v0.84.0/dig-node-0.84.0-linux-arm64",
            ),
            (
                "dig_node_sha256",
                "6e52bc28c4b13a20aca608a45861976d256bf94fe56917b12c19bf0df8229a91",
            ),
            (
                "gateway_url",
                "https://github.com/DIG-Network/rpc.dig.net/releases/download/v0.84.0/rpc-gateway-aarch64",
            ),
            (
                "gateway_sha256",
                "b3c1f0a9d47e2856190b4fd3a0c7e5218f6d9b40c2a713e85f0d6c94ab27e531",
            ),
            ("peer_host", "node-rpc.dig.net"),
            (
                "origin_cert_secret",
                "arn:aws:secretsmanager:us-east-1:000000000000:secret:rpc.dig.net/origin-cert-XXXXXX",
            ),
            ("origin_cert_san", "rpc-origin.dig.net"),
        ];

        let mut rendered = user_data();
        for (name, value) in substitutions {
            rendered = rendered.replace(&format!("${{{name}}}"), value);
        }
        assert_eq!(
            rendered.matches("${").count(),
            1,
            "the only placeholder left should be ${{origin_cert_script}}; an unsubstituted \
             Terraform variable means this renders a different script than the instance runs — add \
             it to the list above"
        );

        rendered.replace("${origin_cert_script}", &read("infra/dig-origin-cert.sh"))
    }

    /// The bootstrap embeds the helper in a heredoc, so a rendered template — not the template —
    /// is what the instance runs. Parse the rendered form.
    ///
    /// This is the only place the two files are combined, and a broken combination is invisible
    /// until an instance boots: cloud-init would run a mangled script, the gateway would never
    /// start, and the failure would surface as an outage rather than as a red build.
    #[test]
    fn the_rendered_bootstrap_is_valid_bash() {
        let rendered = render_bootstrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user_data.sh");
        fs::write(&path, &rendered).unwrap();

        let check = Command::new("bash")
            .arg("-n")
            .arg(&path)
            .output()
            .expect("bash -n");
        assert!(
            check.status.success(),
            "the rendered bootstrap is not valid bash:\n{}",
            String::from_utf8_lossy(&check.stderr)
        );
    }

    /// The bootstrap must fit in EC2's user-data limit, checked here rather than at deploy time.
    ///
    /// EC2 caps user data at 16 KiB. This bootstrap renders to roughly 24 KiB, so it is shipped
    /// gzipped — cloud-init decompresses it on the instance — and the cap therefore applies to the
    /// compressed size. Terraform enforces the same bound with a precondition, but that only fires
    /// during a deploy, and the provider's own rejection quotes the entire script back at you.
    /// Failing here instead turns "the deploy exploded" into a review comment.
    #[test]
    fn the_bootstrap_fits_in_the_user_data_limit_once_compressed() {
        /// EC2's ceiling on the bytes handed to `RunInstances`.
        const USER_DATA_LIMIT: usize = 16 * 1024;

        let rendered = render_bootstrap();

        // Terraform's base64gzip uses Go's default compression level, which is gzip's own default.
        let compressed = Command::new("bash")
            .arg("-c")
            .arg("gzip -c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(rendered.as_bytes())?;
                child.wait_with_output()
            })
            .expect("gzip");

        let size = compressed.stdout.len();
        assert!(
            size <= USER_DATA_LIMIT,
            "the compressed bootstrap is {size} bytes, over EC2's {USER_DATA_LIMIT}-byte user-data \
             limit. Move its long tail out of user_data rather than deleting the comments that \
             explain why the code is the way it is."
        );
    }

    /// The helper must survive being carried through a heredoc unchanged.
    ///
    /// A line in the helper equal to the heredoc terminator would truncate it mid-script, and the
    /// instance would install a half-written file that still looks plausible.
    #[test]
    fn the_helper_cannot_terminate_the_heredoc_that_carries_it() {
        let helper = read("infra/dig-origin-cert.sh");
        assert!(
            !helper
                .lines()
                .any(|line| line.trim_end() == "ORIGIN_CERT_SCRIPT"),
            "a line in the helper matches the heredoc terminator and would truncate it"
        );
    }

    /// Refusing to publish nothing keeps an empty state directory from overwriting a good stored
    /// copy — the inverse of the corrupt-payload case.
    #[test]
    fn saving_with_no_certificate_on_disk_is_refused() {
        let sandbox = Sandbox::new();

        sandbox.run("save").expect_failure();

        assert!(
            !sandbox.secret_holds_a_certificate(),
            "an empty state directory was published over the stored certificate"
        );
    }
}

/// `repo_root` is used by both halves of this file; keep it exercised when `cfg(unix)` is off.
#[test]
fn the_helper_ships_alongside_the_bootstrap_that_installs_it() {
    let helper = repo_root().join("infra/dig-origin-cert.sh");
    assert!(
        helper.exists(),
        "infra/dig-origin-cert.sh is missing; user_data installs it verbatim"
    );
    assert!(
        user_data().contains("dig-origin-cert"),
        "the bootstrap does not install the helper it depends on"
    );
}

/// Guard against the helper being rewritten to shell out with the state directory hardcoded,
/// which would make every behavioural test above silently untestable.
#[test]
fn the_helper_allows_its_state_directory_to_be_overridden() {
    let helper = read("infra/dig-origin-cert.sh");
    assert!(
        helper.contains("DIG_ORIGIN_CERT_STATE_DIR"),
        "the state directory must stay overridable or none of the behavioural tests can run"
    );
}
