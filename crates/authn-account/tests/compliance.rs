#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! DOC-07: the KVKK / GDPR document exists, has the required sections and
//! its data inventory covers every table of the schema.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn compliance_doc() -> String {
    std::fs::read_to_string(repo_root().join("docs/compliance/kvkk-gdpr.md"))
        .expect("docs/compliance/kvkk-gdpr.md exists")
}

/// Every `CREATE [UNLOGGED] TABLE <name>` of `migrations/`.
fn schema_tables() -> Vec<String> {
    let mut tables = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(repo_root().join("migrations"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sql"))
        .collect();
    entries.sort();
    for path in entries {
        let sql = std::fs::read_to_string(&path).unwrap();
        for line in sql.lines() {
            let line = line.trim();
            let rest = line
                .strip_prefix("CREATE UNLOGGED TABLE ")
                .or_else(|| line.strip_prefix("CREATE TABLE "));
            if let Some(rest) = rest {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                tables.push(name);
            }
        }
    }
    tables
}

#[test]
fn doc_07_data_inventory_covers_every_table() {
    let doc = compliance_doc();
    let tables = schema_tables();
    assert!(tables.len() > 30, "{tables:?}");
    let missing: Vec<&String> = tables
        .iter()
        .filter(|t| !doc.contains(&format!("`{t}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "tables missing from the KVKK/GDPR data inventory (docs/compliance/kvkk-gdpr.md §2): {missing:?}"
    );
}

#[test]
fn doc_07_required_sections_are_present() {
    let doc = compliance_doc();
    for heading in [
        "## 2. Veri envanteri",
        "## 3. Saklama süreleri",
        "## 4. Silme akışı",
        "## 5. Dışa aktarma akışı",
        "## 7. Yurt dışına aktarım",
        "## 9. NIST SP 800-63B",
    ] {
        assert!(doc.contains(heading), "missing section {heading}");
    }
    // Defaults quoted in the document match the configuration.
    let config = authn_core::config::account::AccountConfig::default();
    assert_eq!(config.unverified_purge_after.as_secs(), 7 * 86_400);
    assert!(doc.contains("7 gün sonra tamamen silinir"));
    assert_eq!(config.deletion_grace_period.as_secs(), 30 * 86_400);
    assert!(doc.contains("30 gün bekleme"));
}
