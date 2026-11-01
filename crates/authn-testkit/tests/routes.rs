//! Enforces the path-parameter naming rule of
//! `docs/architecture/contracts.md` §7 on every `cargo test`.
//!
//! axum 0.8 (matchit) treats two routes whose parameter sits at the same
//! position after the same static prefix but has a different *name* as a
//! conflict, and `Router::merge` panics at startup (`/v1/orgs/{id}/members`
//! cannot be merged with `/v1/orgs/{org_id}/webhooks`). Module routers are
//! only merged in authn-server, so the conflict would surface late; this
//! test scans every crate's route and OpenAPI path literals instead.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// String literals that follow `marker` (after optional whitespace), e.g.
/// `.route(` or `path = `.
fn literals_after<'a>(source: &'a str, marker: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some((_, after)) = rest.split_once(marker) {
        rest = after;
        if let Some(body) = rest.trim_start().strip_prefix('"')
            && let Some((literal, _)) = body.split_once('"')
        {
            out.push(literal);
        }
    }
    out
}

/// Every `/v1/…` and `/.well-known/…` route or OpenAPI path in `crates/*/src`
/// and `crates/*/tests`, with the file it came from.
fn route_paths() -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crates_dir()).unwrap() {
        let krate = entry.unwrap().path();
        rust_files(&krate.join("src"), &mut files);
        rust_files(&krate.join("tests"), &mut files);
    }
    let mut out = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        for marker in [".route(", "path = "] {
            for literal in literals_after(&source, marker) {
                if literal.starts_with("/v1/") || literal.starts_with("/.well-known/") {
                    out.push((literal.to_owned(), file.clone()));
                }
            }
        }
    }
    out
}

fn param_name(segment: &str) -> Option<&str> {
    segment.strip_prefix('{')?.strip_suffix('}')
}

/// (invalid parameter names, conflicting names at the same position).
fn check(paths: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    // "/v1/orgs/{}" -> {("org_id", file), …}
    let mut by_position: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    let mut bad_names = Vec::new();
    for (path, file) in paths {
        let segments: Vec<&str> = path.split('/').collect();
        for (i, segment) in segments.iter().enumerate() {
            let Some(name) = param_name(segment) else {
                continue;
            };
            let valid = name.len() <= 64
                && name.starts_with(|c: char| c.is_ascii_lowercase())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if !valid {
                bad_names.push(format!("{path} ({file})"));
            }
            let prefix: Vec<&str> = segments[..i]
                .iter()
                .map(|s| if param_name(s).is_some() { "{}" } else { s })
                .collect();
            by_position
                .entry(prefix.join("/"))
                .or_default()
                .insert((name.to_owned(), file.clone()));
        }
    }
    let conflicts = by_position
        .iter()
        .filter(|(_, names)| names.iter().map(|(n, _)| n).collect::<BTreeSet<_>>().len() > 1)
        .map(|(prefix, names)| format!("{prefix}/{{…}}: {names:?}"))
        .collect();
    (bad_names, conflicts)
}

#[test]
fn arc_09_path_parameter_names_agree_across_routers() {
    let paths: Vec<(String, String)> = route_paths()
        .into_iter()
        .map(|(p, f)| (p, f.display().to_string()))
        .collect();
    assert!(
        paths.iter().any(|(p, _)| p.contains("{org_id}")),
        "the scan found no organization routes; is the parser broken?"
    );
    let (bad_names, conflicts) = check(&paths);
    assert!(
        bad_names.is_empty(),
        "path parameters must be snake_case (contracts §7): {bad_names:?}"
    );
    assert!(
        conflicts.is_empty(),
        "different parameter names at the same route position make Router::merge panic \
         (contracts §7: e.g. always `{{org_id}}` after `/v1/orgs/`): {conflicts:#?}"
    );
}

#[test]
fn arc_09_the_naming_check_detects_merge_conflicts() {
    let paths = |list: &[&str]| -> Vec<(String, String)> {
        list.iter()
            .map(|p| ((*p).to_owned(), "x.rs".to_owned()))
            .collect()
    };
    // The exact case that made axum panic during wave A integration.
    let (_, conflicts) = check(&paths(&[
        "/v1/orgs/{id}/members",
        "/v1/orgs/{org_id}/webhooks",
    ]));
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    // Deeper positions are compared after normalizing earlier parameters.
    let (_, conflicts) = check(&paths(&[
        "/v1/orgs/{org_id}/members/{member_id}",
        "/v1/orgs/{org_id}/members/{user_id}/roles",
    ]));
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    // Different prefixes and identical names are fine.
    let (bad, conflicts) = check(&paths(&[
        "/v1/orgs/{org_id}/members/{member_id}",
        "/v1/orgs/{org_id}/roles/{role_id}",
        "/v1/me/passkeys/{passkey_id}",
    ]));
    assert!(bad.is_empty() && conflicts.is_empty());
    let (bad, _) = check(&paths(&["/v1/orgs/{OrgId}", "/v1/x/{*rest}"]));
    assert_eq!(bad.len(), 2, "{bad:?}");
}

#[test]
fn arc_09_organization_routes_use_org_id() {
    for (path, file) in route_paths() {
        if let Some(rest) = path.strip_prefix("/v1/orgs/")
            && let Some(first) = rest.split('/').next()
            && first.starts_with('{')
        {
            assert_eq!(
                first,
                "{org_id}",
                "{path} in {} (contracts §7)",
                file.display()
            );
        }
    }
}
