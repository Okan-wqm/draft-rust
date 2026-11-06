//! Enforces the allowed crate dependency graph of
//! `docs/architecture/contracts.md` §2 on every `cargo test`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const CORE: &str = "authn-core";
const CRYPTO: &str = "authn-crypto";
const STORE: &str = "authn-store";
const TESTKIT: &str = "authn-testkit";
const WAVE_A: &[&str] = &[
    "authn-password",
    "authn-account",
    "authn-mfa",
    "authn-webauthn",
    "authn-org",
    "authn-protect",
    "authn-audit",
    "authn-notify",
];
const WAVE_B: &[&str] = &[
    "authn-session",
    "authn-oidc-client",
    "authn-admin",
    // Phase 2 (K-80): same layer rules as wave B.
    "authn-oidc-provider",
];
const SERVER: &str = "authn-server";

fn crates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// crate -> (normal + build dependencies, dev dependencies), authn-* only.
fn internal_deps() -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(crates_dir()).unwrap() {
        let path = entry.unwrap().path().join("Cargo.toml");
        if !path.exists() {
            continue;
        }
        let manifest: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let name = manifest["package"]["name"].as_str().unwrap().to_owned();
        let collect = |key: &str| -> BTreeSet<String> {
            manifest
                .get(key)
                .and_then(|t| t.as_table())
                .map(|t| {
                    t.keys()
                        .filter(|k| k.starts_with("authn-"))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut normal = collect("dependencies");
        normal.extend(collect("build-dependencies"));
        out.insert(name, (normal, collect("dev-dependencies")));
    }
    out
}

fn allowed_normal(krate: &str) -> BTreeSet<&'static str> {
    let mut allowed = BTreeSet::new();
    match krate {
        CORE | TESTKIT => {
            if krate == TESTKIT {
                allowed.insert(CORE);
            }
        }
        CRYPTO => {
            allowed.insert(CORE);
        }
        STORE => {
            allowed.extend([CORE, CRYPTO]);
        }
        k if WAVE_A.contains(&k) => {
            allowed.extend([CORE, CRYPTO, STORE]);
        }
        k if WAVE_B.contains(&k) => {
            allowed.extend([CORE, CRYPTO, STORE]);
            allowed.extend(WAVE_A.iter().copied());
        }
        SERVER => {
            allowed.extend([CORE, CRYPTO, STORE]);
            allowed.extend(WAVE_A.iter().copied());
            allowed.extend(WAVE_B.iter().copied());
        }
        other => panic!("crate {other} is not classified in contracts.md"),
    }
    allowed
}

#[test]
fn arc_01_every_crate_is_classified() {
    let deps = internal_deps();
    let mut expected: BTreeSet<&str> = [CORE, CRYPTO, STORE, TESTKIT, SERVER].into_iter().collect();
    expected.extend(WAVE_A.iter().copied());
    expected.extend(WAVE_B.iter().copied());
    let actual: BTreeSet<&str> = deps.keys().map(String::as_str).collect();
    assert_eq!(actual, expected);
}

#[test]
fn arc_01_dependency_graph_follows_the_layering_rules() {
    let mut violations = Vec::new();
    for (krate, (normal, dev)) in internal_deps() {
        let allowed = allowed_normal(&krate);
        for dep in &normal {
            if !allowed.contains(dep.as_str()) {
                violations.push(format!("{krate} -> {dep}"));
            }
        }
        // Dev-dependencies may add the testkit (and, for wave B / server, the
        // same crates as normal deps) but never create sideways wave-A links.
        for dep in dev.iter().filter(|d| d.as_str() != TESTKIT) {
            if !allowed.contains(dep.as_str()) {
                violations.push(format!("{krate} -(dev)-> {dep}"));
            }
        }
        if krate != TESTKIT && normal.contains(TESTKIT) {
            violations.push(format!("{krate} -> {TESTKIT} (dev-dependency only)"));
        }
    }
    assert!(
        violations.is_empty(),
        "forbidden dependencies:\n{}",
        violations.join("\n")
    );
}
