#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ARC-09, OPS-09, DOC-04: the merged OpenAPI document is used to generate
//! clients, so it must be structurally valid and say exactly what the wire
//! format is.
//!
//! * every `operationId` is unique;
//! * every security requirement names a scheme of
//!   `components.securitySchemes`;
//! * every `$ref` resolves;
//! * every enum schema lists exactly the values serde reads and writes;
//! * `docs/api/openapi.json` is the freshly generated document. Regenerate
//!   it with `UPDATE_OPENAPI=1 cargo test -p authn-server --test openapi`
//!   (see `docs/api/README.md`).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn document() -> Value {
    authn_server::openapi::document()
}

fn operations(doc: &Value) -> Vec<(String, String, &Value)> {
    let mut out = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in METHODS {
            if let Some(op) = item.get(method) {
                out.push((method.to_owned(), path.clone(), op));
            }
        }
    }
    out
}

#[test]
fn arc_09_operation_ids_are_unique() {
    let doc = document();
    let mut seen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (method, path, op) in operations(&doc) {
        let id = op["operationId"]
            .as_str()
            .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
        seen.entry(id.to_owned())
            .or_default()
            .push(format!("{} {path}", method.to_ascii_uppercase()));
    }
    let duplicates: Vec<_> = seen.iter().filter(|(_, ops)| ops.len() > 1).collect();
    assert!(
        duplicates.is_empty(),
        "duplicate operationIds: {duplicates:?}"
    );
}

#[test]
fn arc_09_security_requirements_reference_defined_schemes() {
    let doc = document();
    let defined: BTreeSet<&str> = doc["components"]["securitySchemes"]
        .as_object()
        .map(|schemes| schemes.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let mut requirements: Vec<(String, &Value)> = Vec::new();
    if let Some(global) = doc.get("security") {
        requirements.push(("<document>".to_owned(), global));
    }
    for (method, path, op) in operations(&doc) {
        if let Some(security) = op.get("security") {
            requirements.push((format!("{method} {path}"), security));
        }
    }
    let mut undefined = Vec::new();
    let mut referenced = 0;
    for (owner, security) in requirements {
        for requirement in security.as_array().unwrap() {
            for scheme in requirement.as_object().unwrap().keys() {
                referenced += 1;
                if !defined.contains(scheme.as_str()) {
                    undefined.push(format!("{owner}: {scheme}"));
                }
            }
        }
    }
    assert!(referenced > 0, "no security requirement found at all");
    assert!(
        undefined.is_empty(),
        "security requirements naming undefined schemes (defined: {defined:?}): {undefined:?}"
    );
}

fn collect_refs<'a>(value: &'a Value, at: &str, out: &mut Vec<(String, &'a str)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "$ref" {
                    if let Some(target) = child.as_str() {
                        out.push((at.to_owned(), target));
                    }
                } else {
                    collect_refs(child, &format!("{at}/{key}"), out);
                }
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                collect_refs(child, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn arc_09_every_ref_resolves() {
    let doc = document();
    let mut refs = Vec::new();
    collect_refs(&doc, "#", &mut refs);
    assert!(!refs.is_empty());
    let unresolved: Vec<_> = refs
        .iter()
        .filter(|(_, target)| {
            target
                .strip_prefix('#')
                .and_then(|pointer| doc.pointer(pointer))
                .is_none()
        })
        .collect();
    assert!(unresolved.is_empty(), "unresolved $refs: {unresolved:?}");
}

/// The `enum` values of the component schema `name`.
fn schema_values(doc: &Value, name: &str) -> Vec<Value> {
    doc["components"]["schemas"][name]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("schema `{name}` is not an enum schema"))
        .clone()
}

/// Checks the schema of `T` against what serde writes for `variants`
/// (every variant of `T`) and reads back from each schema value.
fn check_serialized<T: Serialize + utoipa::ToSchema>(
    doc: &Value,
    variants: &[T],
    checked: &mut BTreeSet<String>,
) {
    let name = T::name().into_owned();
    let schema: BTreeSet<String> = schema_values(doc, &name)
        .into_iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    let wire: BTreeSet<String> = variants
        .iter()
        .map(|v| match serde_json::to_value(v).unwrap() {
            Value::String(s) => s,
            other => panic!("`{name}` serializes to a non-string: {other}"),
        })
        .collect();
    assert_eq!(
        schema, wire,
        "schema `{name}` enum values differ from serde's"
    );
    assert!(checked.insert(name), "checked twice");
}

/// [`check_serialized`] plus: every schema value deserializes and
/// re-serializes to itself.
fn check_round_trip<T: Serialize + DeserializeOwned + utoipa::ToSchema>(
    doc: &Value,
    variants: &[T],
    checked: &mut BTreeSet<String>,
) {
    check_serialized(doc, variants, checked);
    let name = T::name();
    for value in schema_values(doc, &name) {
        let parsed: T = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("`{name}`: schema value {value} is not accepted: {e}"));
        assert_eq!(serde_json::to_value(parsed).unwrap(), value, "`{name}`");
    }
}

/// Every variant of a derive-based enum. The exhaustive `match` makes a new
/// variant a compile error here until it is listed.
macro_rules! variants {
    ($ty:path { $($variant:ident),+ $(,)? }) => {{
        use $ty as T;
        let all = [$(T::$variant),+];
        for v in &all {
            match v {
                $(T::$variant)|+ => {}
            }
        }
        all
    }};
}

#[test]
fn arc_09_enum_schemas_match_serde() {
    let doc = document();
    let mut checked = BTreeSet::new();

    // `text_enum!` / `org_text_enum!` types: `ALL` and the serde names come
    // from the same text table.
    macro_rules! text_enums {
        ($($ty:ty),+ $(,)?) => {
            $(check_round_trip::<$ty>(&doc, <$ty>::ALL, &mut checked);)+
        };
    }
    text_enums!(
        authn_core::domain::AccountStatus,
        authn_core::domain::AuthMethodRef,
        authn_core::domain::ClientKind,
        authn_core::domain::FactorKind,
        authn_core::domain::LoginMethod,
        authn_core::domain::Locale,
        authn_core::ports::RequiredAction,
        authn_core::config::account::TermsDocument,
        authn_org::model::ApiKeyState,
        authn_org::model::DomainStatus,
        authn_org::model::InvitationStatus,
        authn_org::model::MemberStatus,
        authn_org::model::OrgStatus,
        authn_org::model::ServiceAccountStatus,
        authn_org::Permission,
    );

    // Plain `#[derive(Serialize, ToSchema)]` enums.
    check_round_trip(
        &doc,
        &variants!(authn_audit::query::ActorView {
            Myself,
            Administrator,
            User,
            ServiceAccount,
            ApiKey,
            System,
            Anonymous,
        }),
        &mut checked,
    );
    check_serialized(
        &doc,
        &variants!(authn_protect::routes::ChallengeType {
            None,
            Widget,
            ProofOfWork
        }),
        &mut checked,
    );
    check_serialized(
        &doc,
        &variants!(authn_mfa::FactorState { Pending, Active }),
        &mut checked,
    );
    check_serialized(
        &doc,
        &variants!(authn_mfa::CodeChannel { Email, Sms }),
        &mut checked,
    );
    check_round_trip(
        &doc,
        &variants!(authn_admin::routes::ImpersonationClient { Web, Native }),
        &mut checked,
    );
    check_round_trip(
        &doc,
        &variants!(authn_webauthn::PasskeyUsage {
            Both,
            SecondFactor,
            Passwordless
        }),
        &mut checked,
    );
    #[cfg(feature = "passkey")]
    check_round_trip(
        &doc,
        &variants!(authn_webauthn::RegistrationIntent {
            Passwordless,
            SecondFactor
        }),
        &mut checked,
    );
    check_round_trip(
        &doc,
        &variants!(authn_admin::UserStatusFilter {
            PendingVerification,
            Active,
            Locked,
            Suspended,
            Disabled,
            PendingDeletion,
            Deleted,
        }),
        &mut checked,
    );

    // Coverage: every enum schema of the document is checked above.
    let unchecked: Vec<&String> = doc["components"]["schemas"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, schema)| schema.get("enum").is_some())
        .map(|(name, _)| name)
        .filter(|name| !checked.contains(name.as_str()))
        .collect();
    assert!(
        unchecked.is_empty(),
        "enum schemas without a serde check (add them to this test): {unchecked:?}"
    );
}

/// The committed `docs/api/openapi.json` is the generated document. The
/// documented feature set is the default one (`passkey`, `sms`); `redis`
/// adds no endpoint.
#[cfg(all(feature = "passkey", feature = "sms"))]
#[test]
fn doc_04_committed_openapi_json_is_current() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
    let doc = document();
    let mut rendered = serde_json::to_string_pretty(&doc).unwrap();
    rendered.push('\n');
    if std::env::var_os("UPDATE_OPENAPI").is_some_and(|v| v == "1") {
        std::fs::write(&path, &rendered).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap();
    let committed_value: Value = serde_json::from_str(&committed).unwrap();
    assert!(
        committed_value == doc,
        "docs/api/openapi.json is stale: run \
         `UPDATE_OPENAPI=1 cargo test -p authn-server --test openapi` and \
         `python3 -I docs/api/generate_reference.py`"
    );
    assert_eq!(
        committed, rendered,
        "docs/api/openapi.json is not in the canonical format: regenerate it \
         with `UPDATE_OPENAPI=1 cargo test -p authn-server --test openapi`"
    );
}
