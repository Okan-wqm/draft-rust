//! Repository-wide rules of the specification that are properties of the
//! source tree and its configuration rather than of one module:
//! ARC-02 (hexagonal ports with testkit fakes), LIC-01 (licence policy in
//! `deny.toml`), TST-07 (quality gates in CI) and TST-08 (deterministic
//! tests).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: impl AsRef<Path>) -> String {
    let path = repo_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every `.rs` file below `dir` (relative to the repository root).
fn rust_files(dir: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_root().join(dir), &mut out);
    out.sort();
    out
}

/// `crates/<name>` directories of the workspace.
fn crate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(repo_root().join("crates"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("Cargo.toml").exists())
        .collect();
    dirs.sort();
    dirs
}

/// The production part of a source file: everything before its
/// `#[cfg(test)]` module (the workspace convention puts unit tests last).
fn production_part(text: &str) -> &str {
    text.find("#[cfg(test)]\nmod ")
        .and_then(|end| text.get(..end))
        .unwrap_or(text)
}

// ---------------------------------------------------------------- ARC-02

/// Every port trait of `authn-core` has a fake in `authn-testkit`, so a
/// module can be tested without the outside world.
#[test]
fn arc_02_every_port_has_a_testkit_fake() {
    let mut ports = BTreeSet::new();
    for file in rust_files("crates/authn-core/src/ports") {
        let text = std::fs::read_to_string(&file).unwrap();
        for line in text.lines() {
            if let Some(rest) = line.trim_start().strip_prefix("pub trait ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                ports.insert(name);
            }
        }
    }
    assert!(ports.len() >= 15, "{ports:?}");
    let fakes: String = rust_files("crates/authn-testkit/src")
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect();
    let missing: Vec<&String> = ports
        .iter()
        .filter(|port| {
            !fakes.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("impl") && l.contains(&format!(" {port} for "))
            })
        })
        .collect();
    assert!(
        missing.is_empty(),
        "ports without a testkit fake: {missing:?}"
    );
}

/// Libraries that talk to the outside world (SMTP, HTTP, DNS, Redis) are
/// normal dependencies only of the adapter crates that implement the ports;
/// every other crate reaches the outside world through `authn-core` ports.
#[test]
fn arc_02_outside_world_libraries_stay_in_adapter_crates() {
    let allowed: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("lettre", &["authn-notify"][..]),
        ("reqwest", &["authn-protect"][..]),
        ("hickory-resolver", &["authn-protect", "authn-org"][..]),
        ("fred", &["authn-protect"][..]),
        ("redis", &[][..]),
    ]);
    let mut violations = Vec::new();
    for dir in crate_dirs() {
        let manifest: toml::Table = std::fs::read_to_string(dir.join("Cargo.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let name = manifest["package"]["name"].as_str().unwrap().to_owned();
        let deps = manifest
            .get("dependencies")
            .and_then(|d| d.as_table())
            .cloned()
            .unwrap_or_default();
        for (library, crates) in &allowed {
            if deps.contains_key(*library) && !crates.contains(&name.as_str()) {
                violations.push(format!("{name} depends on {library}"));
            }
        }
    }
    assert!(violations.is_empty(), "{violations:?}");
}

// ---------------------------------------------------------------- LIC-01

/// The licences the specification permits (LIC-01 "İzinli:" list).
fn permitted_licences() -> BTreeSet<String> {
    let spec = read("docs/spec/requirements.md");
    let line = spec
        .lines()
        .find(|l| l.contains("(LIC-01, MUST)"))
        .expect("LIC-01 paragraph");
    let list = line
        .split_once("İzinli:")
        .expect("permitted list")
        .1
        .split_once(". ")
        .expect("end of the permitted list")
        .0;
    list.split(',')
        .map(|l| l.split('(').next().unwrap().trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// `(crate, licences)` of the `[licenses] exceptions` of a deny.toml.
fn exceptions(deny: &toml::Table) -> BTreeMap<String, Vec<String>> {
    deny["licenses"]["exceptions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["crate"].as_str().unwrap().to_owned(),
                e["allow"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| l.as_str().unwrap().to_owned())
                    .collect(),
            )
        })
        .collect()
}

/// The product licence policy (`deny.toml`, enforced by `cargo deny check`
/// in CI) allows only licences the specification permits, its only
/// exception is MPL-2.0 for the `webauthn-rs` family, and the NCSA-licensed
/// fuzzing runtime is banned from the product graph.
#[test]
fn lic_01_product_licence_policy_matches_the_specification() {
    let permitted = permitted_licences();
    assert!(permitted.contains("MIT") && permitted.contains("Apache-2.0"));
    let deny: toml::Table = read("deny.toml").parse().unwrap();
    let allow: BTreeSet<String> = deny["licenses"]["allow"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    let extra: Vec<&String> = allow.difference(&permitted).collect();
    assert!(
        extra.is_empty(),
        "licences not permitted by LIC-01: {extra:?}"
    );
    for forbidden in ["GPL", "AGPL", "LGPL", "SSPL", "BUSL", "MPL", "NCSA"] {
        assert!(
            !allow.iter().any(|l| l.contains(forbidden)),
            "{forbidden} must not be allowed globally"
        );
    }
    let webauthn_family: BTreeSet<&str> = [
        "webauthn-rs",
        "webauthn-rs-core",
        "webauthn-rs-proto",
        "webauthn-attestation-ca",
        "webauthn-authenticator-rs",
        "base64urlsafedata",
        "crypto-glue",
        "compact_jwt",
    ]
    .into();
    for (krate, licences) in exceptions(&deny) {
        assert!(
            webauthn_family.contains(krate.as_str()),
            "licence exception outside the approved webauthn-rs family: {krate}"
        );
        assert_eq!(licences, ["MPL-2.0"], "{krate}");
    }
    let banned: Vec<String> = deny["bans"]["deny"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["crate"].as_str().unwrap().to_owned())
        .collect();
    assert!(banned.contains(&"libfuzzer-sys".to_owned()), "{banned:?}");
}

/// The development-only fuzz workspace has the same policy plus the
/// approved NCSA exception for `libfuzzer-sys` only.
#[test]
fn lic_01_fuzz_licence_policy_is_scoped_to_libfuzzer() {
    let permitted = permitted_licences();
    let deny: toml::Table = read("fuzz/deny.toml").parse().unwrap();
    for licence in deny["licenses"]["allow"].as_array().unwrap() {
        let licence = licence.as_str().unwrap();
        assert!(permitted.contains(licence), "{licence}");
    }
    for (krate, licences) in exceptions(&deny) {
        match licences.as_slice() {
            [l] if l == "NCSA" => assert_eq!(krate, "libfuzzer-sys"),
            [l] if l == "MPL-2.0" => assert!(
                krate.starts_with("webauthn")
                    || ["base64urlsafedata", "crypto-glue", "compact_jwt"]
                        .contains(&krate.as_str()),
                "{krate}"
            ),
            other => panic!("{krate}: unexpected exception {other:?}"),
        }
    }
    let manifest: toml::Table = read("fuzz/Cargo.toml").parse().unwrap();
    assert_eq!(
        manifest["package"]["publish"].as_bool(),
        Some(false),
        "fuzz binaries are never published"
    );
}

// ---------------------------------------------------------------- TST-07

/// The CI workflow runs every quality gate of TST-07 (and the later ones:
/// rustdoc, licence notices, requirement traceability), and pins every
/// action to a full commit SHA (supply-chain hardening).
#[test]
fn tst_07_ci_runs_every_quality_gate() {
    let ci = read(".github/workflows/ci.yml");
    for gate in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
        "cargo test --workspace --all-features --locked",
        "cargo deny check",
        "cargo audit",
        "cargo llvm-cov --workspace --all-features",
        "cargo +nightly fuzz build",
        "cargo doc --workspace --no-deps --all-features",
        "RUSTDOCFLAGS: \"-D warnings\"",
        "python3 -I licenses/generate_notices.py",
        "scripts/check-requirement-coverage.sh",
    ] {
        assert!(ci.contains(gate), "CI does not run `{gate}`");
    }
    let mut unpinned = Vec::new();
    for line in ci.lines() {
        let Some(action) = line
            .trim_start()
            .trim_start_matches("- ")
            .strip_prefix("uses: ")
        else {
            continue;
        };
        let (reference, comment) = action.split_once(" # ").unwrap_or((action, ""));
        let sha = reference.rsplit_once('@').map_or("", |(_, r)| r);
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) || comment.is_empty() {
            unpinned.push(line.trim().to_owned());
        }
    }
    assert!(
        unpinned.is_empty(),
        "actions must be pinned to a commit SHA with a `# version` comment: {unpinned:?}"
    );
}

// ---------------------------------------------------------------- TST-08

/// Production code never builds a seedable or thread-local RNG (only the
/// OS CSPRNG, CRY-01) and never reads the wall clock outside the `Clock`
/// port, so every time-dependent test drives a `FakeClock`.
#[test]
fn tst_08_production_code_uses_only_injected_time_and_os_randomness() {
    let rng = [
        "SeedableRng",
        "seed_from_u64",
        "StdRng",
        "SmallRng",
        "thread_rng",
        "rand::rng()",
    ];
    let clock = [
        "OffsetDateTime::now_utc()",
        "SystemTime::now()",
        "Utc::now()",
    ];
    let mut violations = Vec::new();
    for dir in crate_dirs() {
        if dir.ends_with("authn-testkit") {
            continue;
        }
        for file in rust_files(&format!(
            "crates/{}/src",
            dir.file_name().unwrap().to_string_lossy()
        )) {
            let text = std::fs::read_to_string(&file).unwrap();
            let production = production_part(&text);
            for (n, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap();
                for pattern in rng.iter().chain(clock.iter()) {
                    if code.contains(pattern) {
                        violations.push(format!("{}:{}: {pattern}", file.display(), n + 1));
                    }
                }
            }
        }
    }
    // The single sanctioned wall-clock read: the production `Clock`.
    violations.retain(|v| !v.contains("authn-core/src/ports/clock.rs"));
    assert!(violations.is_empty(), "{violations:?}");
}

/// The standard test wiring (`TestPorts`, used by every module test and
/// the server's `App`) never reaches the network or the wall clock: the
/// HTTP port answers only canned responses (a real third-party URL fails
/// at once and is recorded, nothing is sent), and the clock moves only
/// when the test advances it. Real third-party protocols are exercised
/// against local `wiremock` servers.
#[tokio::test]
async fn tst_08_test_ports_never_reach_the_network_or_the_wall_clock() {
    use authn_core::ports::{Clock, HttpClient, OutboundRequest, OutboundTarget};

    let ports = authn_testkit::TestPorts::new();
    let url = url::Url::parse("https://api.pwnedpasswords.com/range/5BAA6").unwrap();
    let started = std::time::Instant::now();
    let result = ports
        .http
        .execute(OutboundRequest::get(url.clone(), OutboundTarget::Trusted))
        .await;
    assert!(result.is_err(), "an unconfigured destination must fail");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(ports.http.requests().len(), 1);
    assert_eq!(ports.http.requests()[0].url, url);

    let before = ports.clock.now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert_eq!(
        ports.clock.now(),
        before,
        "the fake clock follows no wall clock"
    );
    ports.clock.advance(std::time::Duration::from_secs(90));
    assert_eq!(
        ports.clock.now() - before,
        time::Duration::seconds(90),
        "only an explicit advance moves it"
    );
}
