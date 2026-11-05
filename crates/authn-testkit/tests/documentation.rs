#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! DOC-01 … DOC-06, DOC-08, DOC-09: the documentation the specification
//! requires exists, covers the required topics, and stays aligned with the
//! code where a mechanical check is possible (every error code is in the
//! catalogue, every configuration section and key is in the reference,
//! every test the ASVS mapping cites exists, every crate README names the
//! requirement ids its crate owns).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: impl AsRef<Path>) -> String {
    let path = repo_root().join(path);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The concatenated Markdown files of a directory (not recursive).
fn read_dir_markdown(dir: &str) -> String {
    let mut files: Vec<PathBuf> = std::fs::read_dir(repo_root().join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "{dir} has no Markdown file");
    files
        .iter()
        .map(|f| std::fs::read_to_string(f).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_mentions(doc: &str, text: &str, topics: &[&str]) {
    let lower = text.to_lowercase();
    let missing: Vec<&&str> = topics
        .iter()
        .filter(|t| !lower.contains(&t.to_lowercase()))
        .collect();
    assert!(missing.is_empty(), "{doc} does not cover {missing:?}");
}

/// Every Rust function name of the workspace (crates and fuzz targets).
fn workspace_function_names() -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if !path.ends_with("target") {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for (at, _) in text.match_indices("fn ") {
                    let name: String = text
                        .get(at + 3..)
                        .unwrap_or("")
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(&repo_root().join("crates"), &mut out);
    walk(&repo_root().join("fuzz"), &mut out);
    out
}

/// Backticked identifiers that look like requirement-named test functions
/// (`pwd_07_reset_token_is_single_use`).
fn cited_test_names(text: &str) -> BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(|s| s.trim_end_matches("()"))
        .filter(|s| {
            let parts: Vec<&str> = s.split('_').collect();
            parts.len() >= 3
                && parts[0].len() >= 2
                && parts[0].len() <= 4
                && parts[0].bytes().all(|b| b.is_ascii_lowercase())
                && parts[1].len() == 2
                && parts[1].bytes().all(|b| b.is_ascii_digit())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn doc_01_readme_has_the_required_sections() {
    let readme = read("README.md");
    assert_mentions(
        "README.md",
        &readme,
        &[
            "rust-authentication",
            "docker compose",
            "passkey",
            "docs/architecture",
            "lisans",
            "LIC-01",
        ],
    );
}

#[test]
fn doc_02_architecture_documents_diagrams_and_decisions() {
    let architecture = read_dir_markdown("docs/architecture");
    assert!(
        architecture.contains("erDiagram"),
        "no data model (ER) diagram"
    );
    assert!(
        architecture.matches("```mermaid").count() >= 4,
        "dependency graph, request flow and data model diagrams expected"
    );
    let adrs = std::fs::read_dir(repo_root().join("docs/architecture/adr"))
        .unwrap()
        .count();
    assert!(adrs >= 2, "{adrs} ADRs");
    assert_mentions(
        "docs/architecture",
        &architecture,
        &["authn-core", "authn-server", "AppState", "FromRef"],
    );
}

#[test]
fn doc_03_security_documents_exist_and_cite_real_tests() {
    for file in [
        "SECURITY.md",
        "docs/security/threat-model.md",
        "docs/security/asvs-mapping.md",
        "docs/security/cryptography.md",
        "docs/security/known-limitations.md",
    ] {
        assert!(repo_root().join(file).is_file(), "{file} missing");
    }
    assert_mentions(
        "threat-model.md",
        &read("docs/security/threat-model.md"),
        &["STRIDE", "güven sınır"],
    );
    assert_mentions(
        "cryptography.md",
        &read("docs/security/cryptography.md"),
        &["Argon2id", "XChaCha20-Poly1305", "Ed25519", "HKDF"],
    );
    // The ASVS mapping's test column points at real tests.
    let mapping = read("docs/security/asvs-mapping.md");
    let cited = cited_test_names(&mapping);
    assert!(cited.len() >= 20, "{} tests cited", cited.len());
    let functions = workspace_function_names();
    let missing: Vec<&String> = cited.difference(&functions).collect();
    assert!(
        missing.is_empty(),
        "asvs-mapping.md cites tests that do not exist: {missing:?}"
    );
}

#[test]
fn doc_04_error_catalogue_lists_every_error_code() {
    let catalogue = read("docs/api/errors.md");
    let missing: Vec<&str> = authn_core::error::codes::all()
        .map(authn_core::error::ErrorCode::code)
        .filter(|code| !catalogue.contains(&format!("`{code}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "codes missing from errors.md: {missing:?}"
    );
    let api = read_dir_markdown("docs/api");
    assert_mentions(
        "docs/api",
        &api,
        &[
            "Authorization: Bearer",
            "x-csrf-token",
            "Retry-After",
            "cursor",
        ],
    );
}

#[test]
fn doc_05_integration_guides_cover_every_client_kind() {
    let guides = read_dir_markdown("docs/integration");
    assert_mentions(
        "docs/integration",
        &guides,
        &[
            "BFF",
            "SPA",
            "Keychain",
            "Sign in with Apple",
            "Credential Manager",
            "Keystore",
            "JWKS",
            "davet",
            "API anahtar",
            "webhook-signature",
        ],
    );
}

/// Every section and key of the annotated example configuration is in the
/// configuration reference, and the runbooks cover the required topics.
#[test]
fn doc_06_operations_cover_every_setting_and_runbook() {
    let reference = read("docs/operations/configuration.md");
    let example: toml::Table = read("config/example.toml").parse().unwrap();
    let mut missing = Vec::new();
    fn walk(prefix: &str, table: &toml::Table, reference: &str, missing: &mut Vec<String>) {
        for (key, value) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            let nested = match value {
                toml::Value::Table(t) => Some(t.clone()),
                toml::Value::Array(items) => items.first().and_then(|v| v.as_table()).cloned(),
                _ => None,
            };
            if let Some(nested) = nested {
                if !reference.contains(&format!("[{path}]")) {
                    missing.push(format!("[{path}]"));
                }
                walk(&path, &nested, reference, missing);
            } else if !reference.contains(&format!("`{key}`")) {
                missing.push(path);
            }
        }
    }
    walk("", &example, &reference, &mut missing);
    assert!(
        missing.is_empty(),
        "configuration.md misses settings of config/example.toml: {missing:?}"
    );
    let operations = read_dir_markdown("docs/operations");
    assert_mentions(
        "docs/operations",
        &operations,
        &[
            "KEK",
            "pepper",
            "rotate-signing-key",
            "rotate-kek",
            "yedek",
            "alarm",
            "authn_apply_least_privilege",
        ],
    );
}

/// Expands `OPS-01 … OPS-09` (also `...`, `–`) into the listed ids.
fn expand_ranges(text: &str) -> String {
    let mut out = text.to_owned();
    for separator in [" … ", " ... ", " – ", "–"] {
        for (at, _) in text.match_indices(separator) {
            let (Some(low), Some(high)) = (
                text.get(at.saturating_sub(6)..at),
                text.get(at + separator.len()..at + separator.len() + 6),
            ) else {
                continue;
            };
            let (Some(prefix), Some(other)) = (low.get(..4), high.get(..4)) else {
                continue;
            };
            if !prefix.ends_with('-') || other != prefix {
                continue;
            }
            let (Ok(a), Ok(b)) = (
                low.get(4..).unwrap_or("").parse::<u32>(),
                high.get(4..).unwrap_or("").parse::<u32>(),
            ) else {
                continue;
            };
            for n in a..=b {
                out.push_str(&format!(" {prefix}{n:02}"));
            }
        }
    }
    out
}

/// Every crate has a README naming each requirement id it owns
/// (contracts §1 ownership table).
#[test]
fn doc_08_every_crate_readme_names_its_requirements() {
    let contracts = read("docs/architecture/contracts.md");
    let mut owners = 0;
    let mut missing = Vec::new();
    for line in contracts.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 4 || !cells[1].starts_with("`authn-") {
            continue;
        }
        let ids: Vec<&str> = cells[2]
            .split(", ")
            .filter(|id| {
                id.len() == 6
                    && id.as_bytes()[3] == b'-'
                    && id.bytes().take(3).all(|b| b.is_ascii_uppercase())
            })
            .collect();
        if ids.is_empty() {
            continue;
        }
        owners += 1;
        let krate = cells[1].trim_matches('`');
        let readme_path = format!("crates/{krate}/README.md");
        let readme = expand_ranges(&read(&readme_path));
        for id in ids {
            if !readme.contains(id) {
                missing.push(format!("{readme_path}: {id}"));
            }
        }
    }
    assert_eq!(owners, 16, "ownership table rows");
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn doc_09_roadmap_covers_phase_2_phase_3_and_extension_points() {
    let roadmap = read("docs/roadmap.md");
    assert!(roadmap.contains("## 7. Faz 2"), "Faz 2 section");
    assert!(roadmap.contains("## 8. Faz 3"), "Faz 3 section");
    assert_mentions(
        "docs/roadmap.md",
        &roadmap,
        &[
            "genişleme noktaları",
            "OIDC",
            "SCIM",
            "DPoP",
            "SAML",
            "identities",
            "amr",
            "JWKS",
        ],
    );
}
