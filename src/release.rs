//! Choosing which `dig-node` release this host should run.
//!
//! The node behind `rpc.dig.net` tracks the newest **stable** `dig-node` release automatically
//! (`.github/workflows/auto-update-node.yml`). Everything that decides *which* release that is
//! lives here, as a pure function over the GitHub releases JSON, so the choice is settled in code
//! a test can drive exhaustively rather than in shell inside a workflow.
//!
//! The rules exist because each has a way of going wrong on this specific host:
//!
//! | rule | what it prevents |
//! |---|---|
//! | prereleases and drafts are ineligible | the rolling `nightly` tag is the newest tag in the API response on most days; taking it would ship untagged work to the public read tier |
//! | the tag must be exactly `vMAJOR.MINOR.PATCH` | ordering is numeric, so `v0.9.0` never outranks `v0.84.0` the way a string sort would |
//! | the asset name is **constructed**, never discovered | this host is Graviton and installs a raw executable; a substring search for "arm64" also matches `dig-node_0.93.9_arm64.deb`, and installing a Debian package as the node binary bricks it |
//! | the download URL must match the canonical release-download form | the URL is handed to `curl` running as root on the node, so it may not be an arbitrary string the API happened to return |
//!
//! The checksum is deliberately *not* here. It is computed from the bytes actually downloaded
//! (see the workflow), never read from the API or a checksum file, so it cannot describe bytes
//! other than the ones that get installed.

use serde::Deserialize;

/// Where releases are published. Pinned rather than parameterised: the URL this produces is
/// executed as root on the node host, so the host it points at is part of the contract.
const RELEASE_HOST: &str = "https://github.com/DIG-Network/dig-node/releases/download";

/// The platform slug in a `dig-node` release asset name for this host.
///
/// `linux-arm64` is not a preference — `t4g.small` is Graviton (see `infra/variables.tf`), and the
/// raw executable is what `user_data` installs to `/usr/local/bin/dig-node`.
const PLATFORM: &str = "linux-arm64";

/// One release as the GitHub API reports it. Only the fields the choice depends on.
#[derive(Debug, Deserialize)]
pub struct Release {
    /// The git tag, e.g. `v0.93.9` — or `nightly`, which is why [`Candidate`] parses it.
    pub tag_name: String,
    /// GitHub's prerelease flag. Nightlies set it.
    #[serde(default)]
    pub prerelease: bool,
    /// GitHub's draft flag. A draft's assets are not publicly fetchable.
    #[serde(default)]
    pub draft: bool,
    /// Published assets.
    #[serde(default)]
    pub assets: Vec<Asset>,
}

/// One published release asset.
#[derive(Debug, Deserialize)]
pub struct Asset {
    /// The asset's file name, e.g. `dig-node-0.93.9-linux-arm64`.
    pub name: String,
    /// The public download URL the API reports for it.
    pub browser_download_url: String,
}

/// A release this host could install: a stable tag that actually ships a `linux-arm64` executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The release tag, `v`-prefixed, e.g. `v0.93.9`.
    pub tag: String,
    /// The bare version, e.g. `0.93.9`.
    pub version: String,
    /// The asset file name.
    pub asset: String,
    /// The URL to download the asset from.
    pub url: String,
}

/// What the workflow should do with the release set it fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The host already runs the chosen release. Nothing to install.
    UpToDate {
        /// The tag both the host and the choice landed on.
        tag: String,
    },
    /// The host should move to this release.
    Install(Candidate),
}

/// Why no installable release could be chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// The input was not a JSON array of releases.
    Malformed(String),
    /// No release qualified: every one was a draft, a prerelease, or oddly tagged.
    NoStableRelease,
    /// The requested tag is not a published stable release.
    NoSuchStableRelease {
        /// The tag that was asked for.
        tag: String,
    },
    /// A stable release exists but publishes no executable for this platform.
    ///
    /// Reported rather than worked around. The alternative — falling back to *some* other asset —
    /// is how a `.deb` reaches `/usr/local/bin/dig-node`.
    MissingAsset {
        /// The release that is missing it.
        tag: String,
        /// The exact asset name that was required.
        expected: String,
    },
    /// The asset's download URL is not the canonical release-download URL for that asset.
    UntrustedUrl {
        /// What the API reported.
        got: String,
        /// What it had to be.
        expected: String,
    },
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "releases JSON is not a list of releases: {why}"),
            Self::NoStableRelease => write!(
                f,
                "no stable vMAJOR.MINOR.PATCH release found (drafts and prereleases are ineligible)"
            ),
            Self::NoSuchStableRelease { tag } => {
                write!(f, "{tag} is not a published stable release")
            }
            Self::MissingAsset { tag, expected } => write!(
                f,
                "{tag} publishes no {expected}; refusing to substitute another asset"
            ),
            Self::UntrustedUrl { got, expected } => {
                write!(f, "asset download URL is {got}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for SelectError {}

/// Decide what the host should install, given every release and the tag it currently runs.
///
/// `require` names an exact tag to install — the deliberate-rollback path. It bypasses the
/// newest-wins ordering (and therefore permits a downgrade) but nothing else: the tag must still
/// be a published stable release that ships this platform's executable at a canonical URL.
///
/// With `require` unset, the newest stable release wins, and a `current` that is already newest
/// yields [`Plan::UpToDate`].
pub fn plan(
    releases_json: &str,
    current: &str,
    require: Option<&str>,
) -> Result<Plan, SelectError> {
    let releases: Vec<Release> =
        serde_json::from_str(releases_json).map_err(|e| SelectError::Malformed(e.to_string()))?;

    let chosen = match require {
        Some(tag) => stable_release_tagged(&releases, tag)?,
        None => newest_stable_release(&releases)?,
    };

    if chosen.tag == current {
        return Ok(Plan::UpToDate { tag: chosen.tag });
    }
    Ok(Plan::Install(chosen))
}

/// Render a plan as `GITHUB_OUTPUT` lines for the workflow to consume.
///
/// `update` is the only key a caller must branch on; the rest describe the release to install and
/// are absent when there is nothing to install, so a workflow that ignores `update` and uses `url`
/// anyway fails on an empty value rather than silently reinstalling.
pub fn github_output(plan: &Plan) -> String {
    match plan {
        Plan::UpToDate { tag } => format!("update=false\ntag={tag}\n"),
        Plan::Install(c) => format!(
            "update=true\ntag={}\nversion={}\nasset={}\nurl={}\n",
            c.tag, c.version, c.asset, c.url
        ),
    }
}

/// The highest-versioned stable release that ships this platform's executable.
fn newest_stable_release(releases: &[Release]) -> Result<Candidate, SelectError> {
    let newest = releases
        .iter()
        .filter(|r| is_stable(r))
        .filter_map(|r| semver(&r.tag_name).map(|v| (v, r)))
        .max_by_key(|(v, _)| *v)
        .map(|(_, r)| r)
        .ok_or(SelectError::NoStableRelease)?;

    candidate_from(newest)
}

/// The stable release carrying exactly `tag`.
fn stable_release_tagged(releases: &[Release], tag: &str) -> Result<Candidate, SelectError> {
    let found = releases
        .iter()
        .filter(|r| is_stable(r))
        .find(|r| r.tag_name == tag && semver(&r.tag_name).is_some())
        .ok_or_else(|| SelectError::NoSuchStableRelease {
            tag: tag.to_string(),
        })?;

    candidate_from(found)
}

/// Published, and not a nightly.
fn is_stable(release: &Release) -> bool {
    !release.draft && !release.prerelease
}

/// `v0.93.9` → `(0, 93, 9)`. Anything else — `nightly`, `v1.2`, `0.1.0` — is not a stable tag.
///
/// Comparing the tuple is what makes `v0.84.0` outrank `v0.9.0`; comparing the strings would not.
fn semver(tag: &str) -> Option<(u64, u64, u64)> {
    let mut parts = tag.strip_prefix('v')?.split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let triple = (next()?, next()?, next()?);
    parts.next().is_none().then_some(triple)
}

/// Build the candidate for a release, requiring the exact platform asset at a canonical URL.
fn candidate_from(release: &Release) -> Result<Candidate, SelectError> {
    let tag = release.tag_name.clone();
    let version = tag.trim_start_matches('v').to_string();

    // CONSTRUCTED, not searched. A search for an arm64-looking Linux asset also finds
    // `dig-node_<v>_arm64.deb`, and installing that as the node executable bricks the host.
    let expected_asset = format!("dig-node-{version}-{PLATFORM}");

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == expected_asset)
        .ok_or_else(|| SelectError::MissingAsset {
            tag: tag.clone(),
            expected: expected_asset.clone(),
        })?;

    let expected_url = format!("{RELEASE_HOST}/{tag}/{expected_asset}");
    if asset.browser_download_url != expected_url {
        return Err(SelectError::UntrustedUrl {
            got: asset.browser_download_url.clone(),
            expected: expected_url,
        });
    }

    Ok(Candidate {
        tag,
        version,
        asset: expected_asset,
        url: expected_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A release with the full published asset set, as `dig-node` actually ships it.
    fn stable(version: &str) -> String {
        // The packaged and same-arch-lookalike artifacts come FIRST on purpose. Any selection that
        // scans for an arm64-ish Linux asset instead of constructing the exact name will reach one
        // of these before the real executable, and the tests below will say so. With the real
        // asset listed first, a broken search picks correctly by luck and the tests pass vacuously.
        let assets = [
            format!("dig-node_{version}_arm64.deb"),
            format!("dig-node_{version}_amd64.deb"),
            format!("dign-{version}-linux-arm64"),
            format!("dig-node-{version}-macos-arm64"),
            format!("dig-node-{version}-linux-x64"),
            format!("dig-node-{version}-linux-arm64"),
        ]
        .iter()
        .map(|name| asset_json(version, name))
        .collect::<Vec<_>>()
        .join(",");
        format!(
            r#"{{"tag_name":"v{version}","prerelease":false,"draft":false,"assets":[{assets}]}}"#
        )
    }

    fn asset_json(version: &str, name: &str) -> String {
        format!(r#"{{"name":"{name}","browser_download_url":"{RELEASE_HOST}/v{version}/{name}"}}"#)
    }

    fn releases(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    fn install(plan: Plan) -> Candidate {
        match plan {
            Plan::Install(c) => c,
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn picks_the_newest_stable_release_and_its_raw_arm64_executable() {
        let json = releases(&[stable("0.84.0"), stable("0.93.9"), stable("0.73.0")]);

        let chosen = install(plan(&json, "v0.84.0", None).unwrap());

        assert_eq!(chosen.tag, "v0.93.9");
        assert_eq!(chosen.version, "0.93.9");
        assert_eq!(chosen.asset, "dig-node-0.93.9-linux-arm64");
        assert_eq!(
            chosen.url,
            "https://github.com/DIG-Network/dig-node/releases/download/v0.93.9/dig-node-0.93.9-linux-arm64"
        );
    }

    /// The `.deb` is the artifact that bricks this node, and it sorts adjacent to the real one.
    #[test]
    fn never_selects_a_packaged_artifact() {
        let json = releases(&[stable("0.93.9")]);

        let chosen = install(plan(&json, "v0.84.0", None).unwrap());

        assert!(
            !chosen.asset.ends_with(".deb") && !chosen.url.ends_with(".deb"),
            "selected a Debian package: {chosen:?}"
        );
        assert_eq!(chosen.asset, "dig-node-0.93.9-linux-arm64");
    }

    /// If the raw executable is absent, say so. Substituting the `.deb` that IS present is the
    /// failure this refuses to have.
    #[test]
    fn a_release_shipping_only_a_deb_is_an_error_not_a_fallback() {
        let json = format!(
            r#"[{{"tag_name":"v1.0.0","prerelease":false,"draft":false,"assets":[{}]}}]"#,
            asset_json("1.0.0", "dig-node_1.0.0_arm64.deb")
        );

        assert_eq!(
            plan(&json, "v0.93.9", None).unwrap_err(),
            SelectError::MissingAsset {
                tag: "v1.0.0".into(),
                expected: "dig-node-1.0.0-linux-arm64".into(),
            }
        );
    }

    /// `nightly` is the newest tag in the API response most days, and it is not releasable here.
    #[test]
    fn ignores_nightlies() {
        let json = format!(
            r#"[{},{},{}]"#,
            r#"{"tag_name":"nightly","prerelease":true,"draft":false,"assets":[]}"#,
            r#"{"tag_name":"nightly-20260804","prerelease":true,"draft":false,"assets":[]}"#,
            stable("0.93.9"),
        );

        assert_eq!(
            install(plan(&json, "v0.84.0", None).unwrap()).tag,
            "v0.93.9"
        );
    }

    /// The FLAG has to be what excludes it, not the tag shape.
    ///
    /// The two `nightly*` tags above are also unparseable as versions, so they are refused twice
    /// over and prove nothing about the flag — deleting the prerelease check left the whole suite
    /// green. This release is fully formed: higher-versioned, correctly tagged, carrying the real
    /// `linux-arm64` executable. The only thing making it ineligible is `prerelease: true`.
    #[test]
    fn a_semver_tagged_prerelease_is_still_ineligible() {
        let prerelease = stable("2.0.0").replace(r#""prerelease":false"#, r#""prerelease":true"#);
        let json = releases(&[prerelease, stable("0.93.9")]);

        assert_eq!(
            install(plan(&json, "v0.84.0", None).unwrap()).tag,
            "v0.93.9",
            "a prerelease must never be selected automatically"
        );
        assert_eq!(
            plan(&json, "v0.93.9", Some("v2.0.0")).unwrap_err(),
            SelectError::NoSuchStableRelease {
                tag: "v2.0.0".into()
            },
            "naming a prerelease explicitly must not install it either"
        );
    }

    /// Same shape, for drafts: a draft's assets are not publicly fetchable.
    #[test]
    fn a_semver_tagged_draft_is_still_ineligible() {
        let draft = stable("2.0.0").replace(r#""draft":false"#, r#""draft":true"#);
        let json = releases(&[draft, stable("0.93.9")]);

        assert_eq!(
            install(plan(&json, "v0.84.0", None).unwrap()).tag,
            "v0.93.9"
        );
        assert_eq!(
            plan(&json, "v0.93.9", Some("v2.0.0")).unwrap_err(),
            SelectError::NoSuchStableRelease {
                tag: "v2.0.0".into()
            },
        );
    }

    /// String ordering puts `v0.9.0` above `v0.84.0`. Numeric ordering is the whole point.
    #[test]
    fn orders_versions_numerically_not_lexically() {
        let json = releases(&[stable("0.9.0"), stable("0.84.0"), stable("0.100.1")]);

        assert_eq!(
            install(plan(&json, "v0.9.0", None).unwrap()).tag,
            "v0.100.1"
        );
    }

    #[test]
    fn already_on_the_newest_release_is_a_no_op() {
        let json = releases(&[stable("0.84.0"), stable("0.93.9")]);

        assert_eq!(
            plan(&json, "v0.93.9", None).unwrap(),
            Plan::UpToDate {
                tag: "v0.93.9".into()
            }
        );
    }

    /// Automatic selection is newest-wins, so it can only ever move the host forward.
    #[test]
    fn automatic_selection_cannot_downgrade() {
        let json = releases(&[stable("0.84.0"), stable("0.93.9")]);

        // The host is somehow ahead of every published release.
        assert_eq!(
            install(plan(&json, "v0.99.0", None).unwrap()).tag,
            "v0.93.9",
            "sanity: newest-wins is what bounds this"
        );

        // …and from anywhere behind, the answer is always the single newest release.
        for current in ["v0.73.0", "v0.84.0"] {
            assert_eq!(install(plan(&json, current, None).unwrap()).tag, "v0.93.9");
        }
    }

    /// The rollback path: name a tag and get exactly it, older than current on purpose.
    #[test]
    fn an_explicit_tag_may_move_the_host_backwards() {
        let json = releases(&[stable("0.84.0"), stable("0.93.9")]);

        let chosen = install(plan(&json, "v0.93.9", Some("v0.84.0")).unwrap());

        assert_eq!(chosen.tag, "v0.84.0");
        assert_eq!(chosen.asset, "dig-node-0.84.0-linux-arm64");
    }

    #[test]
    fn an_explicit_tag_still_has_to_be_a_published_stable_release() {
        let json = format!(
            r#"[{},{}]"#,
            stable("0.93.9"),
            r#"{"tag_name":"nightly","prerelease":true,"draft":false,"assets":[]}"#,
        );

        for tag in ["v9.9.9", "nightly"] {
            assert_eq!(
                plan(&json, "v0.93.9", Some(tag)).unwrap_err(),
                SelectError::NoSuchStableRelease { tag: tag.into() },
                "{tag} must not be installable"
            );
        }
    }

    #[test]
    fn an_explicit_tag_equal_to_the_current_one_is_a_no_op() {
        let json = releases(&[stable("0.93.9")]);

        assert_eq!(
            plan(&json, "v0.93.9", Some("v0.93.9")).unwrap(),
            Plan::UpToDate {
                tag: "v0.93.9".into()
            }
        );
    }

    /// The URL is handed to `curl` running as root on the node, so it is checked, not trusted.
    #[test]
    fn rejects_an_asset_url_that_is_not_the_canonical_download_url() {
        let json = format!(
            r#"[{{"tag_name":"v1.2.3","prerelease":false,"draft":false,"assets":[{}]}}]"#,
            r#"{"name":"dig-node-1.2.3-linux-arm64","browser_download_url":"https://evil.example/dig-node-1.2.3-linux-arm64"}"#
        );

        assert!(matches!(
            plan(&json, "v0.93.9", None).unwrap_err(),
            SelectError::UntrustedUrl { .. }
        ));
    }

    #[test]
    fn an_empty_or_all_prerelease_list_is_an_error() {
        assert_eq!(
            plan("[]", "v0.93.9", None).unwrap_err(),
            SelectError::NoStableRelease
        );

        let only_nightly =
            r#"[{"tag_name":"nightly","prerelease":true,"draft":false,"assets":[]}]"#;
        assert_eq!(
            plan(only_nightly, "v0.93.9", None).unwrap_err(),
            SelectError::NoStableRelease
        );
    }

    #[test]
    fn malformed_input_is_reported_rather_than_panicking() {
        assert!(matches!(
            plan("not json", "v0.93.9", None).unwrap_err(),
            SelectError::Malformed(_)
        ));
    }

    #[test]
    fn only_three_part_v_prefixed_tags_are_versions() {
        assert_eq!(semver("v0.93.9"), Some((0, 93, 9)));
        for bad in [
            "nightly", "v1.2", "1.2.3", "v1.2.3.4", "v1.2.x", "v", "vx.y.z",
        ] {
            assert_eq!(semver(bad), None, "{bad} must not parse as a version");
        }
    }

    #[test]
    fn github_output_carries_everything_the_workflow_installs_with() {
        let json = releases(&[stable("0.93.9")]);

        let out = github_output(&plan(&json, "v0.84.0", None).unwrap());

        assert_eq!(
            out,
            "update=true\n\
             tag=v0.93.9\n\
             version=0.93.9\n\
             asset=dig-node-0.93.9-linux-arm64\n\
             url=https://github.com/DIG-Network/dig-node/releases/download/v0.93.9/dig-node-0.93.9-linux-arm64\n"
        );
    }

    /// A no-op must not emit a url, so a workflow that skips the `update` check breaks loudly.
    #[test]
    fn github_output_for_a_no_op_names_no_artifact() {
        let out = github_output(&Plan::UpToDate {
            tag: "v0.93.9".into(),
        });

        assert_eq!(out, "update=false\ntag=v0.93.9\n");
        assert!(!out.contains("url="), "a no-op must not offer an artifact");
    }

    #[test]
    fn every_error_says_what_went_wrong() {
        let cases = [
            SelectError::Malformed("eof".into()),
            SelectError::NoStableRelease,
            SelectError::NoSuchStableRelease {
                tag: "v9.9.9".into(),
            },
            SelectError::MissingAsset {
                tag: "v1.0.0".into(),
                expected: "dig-node-1.0.0-linux-arm64".into(),
            },
            SelectError::UntrustedUrl {
                got: "https://evil.example/x".into(),
                expected: "https://github.com/x".into(),
            },
        ];
        for case in cases {
            assert!(!case.to_string().is_empty(), "{case:?} has no message");
        }
    }
}
