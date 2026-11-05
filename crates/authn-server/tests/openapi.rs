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
//! * every operation declares the credentials it accepts (`security`), and
//!   the declaration is exactly what the assembled router enforces (K-129:
//!   every operation is probed with no credential, a session cookie, a
//!   native access token and an organization API key in both headers);
//! * `docs/api/openapi.json` is the freshly generated document. Regenerate
//!   it with `UPDATE_OPENAPI=1 cargo test -p authn-server --test openapi`
//!   (see `docs/api/README.md`).

mod common;

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

// --- K-129: per-operation security matches the router -------------------------

/// The security schemes in the order the document lists them.
const SCHEMES: [&str; 4] = ["session_cookie", "bearer_jwt", "api_key", "api_key_bearer"];

/// The schemes an operation declares (one scheme per requirement object;
/// `[]` = no credential). `None` when the operation declares nothing.
fn declared_schemes(op: &Value) -> Option<BTreeSet<String>> {
    let security = op.get("security")?.as_array().unwrap();
    let mut out = BTreeSet::new();
    for requirement in security {
        let requirement = requirement.as_object().unwrap();
        assert_eq!(
            requirement.len(),
            1,
            "one scheme per requirement (alternatives), not {requirement:?}"
        );
        out.extend(requirement.keys().cloned());
    }
    Some(out)
}

/// K-129: every operation declares `security`; `[]` exactly for the
/// operations that need no credential.
#[test]
fn arc_09_k129_every_operation_declares_security() {
    let doc = document();
    let mut missing = Vec::new();
    let mut public = 0;
    for (method, path, op) in operations(&doc) {
        match declared_schemes(op) {
            None => missing.push(format!("{} {path}", method.to_ascii_uppercase())),
            Some(schemes) if schemes.is_empty() => public += 1,
            Some(_) => {}
        }
    }
    assert!(
        missing.is_empty(),
        "operations without `security`: {missing:?}"
    );
    assert!(public > 0 && public < operations(&doc).len());
}

const ZERO: &str = "00000000-0000-0000-0000-000000000000";

fn concrete(path: &str, org: &str) -> String {
    path.split('/')
        .map(|seg| match seg {
            "{provider}" => "google",
            "{org_id}" => org,
            s if s.starts_with('{') => ZERO,
            s => s,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A request body that satisfies the operation's documented schema
/// (`{}` without one): every required property gets a well-formed sample
/// value. Some handlers parse their body before they authenticate the
/// caller (introspection, link confirmations taking an optional
/// principal); an invalid body would answer `400`/`422` first and hide the
/// authentication requirement from the probe.
fn probe_body(doc: &Value, op: &Value) -> Value {
    op["requestBody"]["content"]
        .as_object()
        .and_then(|content| content.values().next())
        .map_or_else(
            || serde_json::json!({}),
            |media| sample(doc, &media["schema"], 0),
        )
}

fn sample(doc: &Value, schema: &Value, depth: usize) -> Value {
    use serde_json::json;
    if depth > 8 {
        return Value::Null;
    }
    if let Some(target) = schema["$ref"].as_str() {
        let resolved = doc
            .pointer(target.trim_start_matches('#'))
            .unwrap_or(&Value::Null);
        return sample(doc, resolved, depth + 1);
    }
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(first) = schema[key].as_array().and_then(|v| v.first()) {
            if key != "allOf" {
                return sample(doc, first, depth + 1);
            }
            // allOf: merge the objects.
            let mut merged = serde_json::Map::new();
            for part in schema[key].as_array().into_iter().flatten() {
                if let Value::Object(map) = sample(doc, part, depth + 1) {
                    merged.extend(map);
                }
            }
            return Value::Object(merged);
        }
    }
    if let Some(first) = schema["enum"].as_array().and_then(|v| v.first()) {
        return first.clone();
    }
    let kind = match &schema["type"] {
        Value::Array(kinds) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|k| *k != "null")
            .unwrap_or("null")
            .to_owned(),
        Value::String(kind) => kind.clone(),
        _ if schema.get("properties").is_some() => "object".to_owned(),
        _ => "object".to_owned(),
    };
    match kind.as_str() {
        "object" => {
            let mut out = serde_json::Map::new();
            let required: Vec<&str> = schema["required"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            for name in required {
                out.insert(
                    name.to_owned(),
                    sample(doc, &schema["properties"][name], depth + 1),
                );
            }
            Value::Object(out)
        }
        "array" => json!([]),
        "string" => match schema["format"].as_str() {
            Some("uuid") => json!(ZERO),
            Some("email") => json!("probe@example.com"),
            Some("date-time") => json!("2026-01-01T00:00:00Z"),
            Some("uri") => json!("https://probe.example/"),
            _ => json!("probe"),
        },
        "integer" | "number" => json!(1),
        "boolean" => json!(false),
        _ => Value::Null,
    }
}

/// Whether `response` is the authentication layer's refusal (no accepted
/// credential), as opposed to any answer of an authenticated handler.
fn unauthenticated(response: &authn_testkit::http::TestResponse) -> bool {
    response.status == axum::http::StatusCode::UNAUTHORIZED
        && serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|b| b["error"]["code"].as_str().map(str::to_owned))
            .is_some_and(|code| code == "unauthenticated")
}

/// The credentials the router really accepts on each documented operation:
/// `[]` when an anonymous caller is not refused as unauthenticated,
/// otherwise every scheme whose (valid) credential gets past that refusal.
async fn enforced_schemes(app: &common::App) -> BTreeMap<(String, String), BTreeSet<String>> {
    use authn_testkit::http::TestRequest;
    use common::{ORIGIN, PASSWORD};
    use serde_json::json;

    app.user("prober@example.com").await;
    let web_login = || async {
        let mut browser = app.browser();
        let mut body = browser.login(app, "prober@example.com", PASSWORD).await;
        if body["status"] == "challenge_required" {
            // A new device (RSK-03): the e-mailed confirmation.
            let r = browser
                .send(
                    app,
                    browser.post(
                        "/v1/login/challenge/send-code",
                        &json!({"channel": "email_confirmation"}),
                    ),
                )
                .await;
            assert!(r.status.is_success(), "{}", r.text());
            let authn_core::ports::NotificationKind::LoginCode { code, .. } =
                app.last_notification("login_code")
            else {
                panic!("login code")
            };
            body = browser
                .send(
                    app,
                    browser.post(
                        "/v1/login/challenge/verify",
                        &json!({"method": "email_confirmation", "code": code.expose()}),
                    ),
                )
                .await
                .json();
        }
        assert_eq!(body["status"], "authenticated", "{body}");
        browser.csrf(app).await;
        browser
    };
    let native_login = || async {
        let mut native = app.native();
        let r = app
            .send(native.post(
                "/v1/login/password",
                &json!({"email": "prober@example.com", "password": PASSWORD}),
            ))
            .await;
        let mut body: Value = r.json();
        native.absorb(&body);
        if body["status"] == "challenge_required" {
            // A new device (RSK-03): the e-mailed confirmation.
            let r = app
                .send(native.post(
                    "/v1/login/challenge/send-code",
                    &json!({"channel": "email_confirmation"}),
                ))
                .await;
            assert!(r.status.is_success(), "{}", r.text());
            let authn_core::ports::NotificationKind::LoginCode { code, .. } =
                app.last_notification("login_code")
            else {
                panic!("login code")
            };
            let r = app
                .send(native.post(
                    "/v1/login/challenge/verify",
                    &json!({"method": "email_confirmation", "code": code.expose()}),
                ))
                .await;
            body = r.json();
            native.absorb(&body);
        }
        assert_eq!(body["status"], "authenticated", "{body}");
        native.access.unwrap()
    };
    let mut browser = web_login().await;
    let mut access = native_login().await;
    let r = browser
        .send(
            app,
            browser.post("/v1/orgs", &json!({"name": "Probe", "slug": "probe"})),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let org = r.json::<Value>()["id"].as_str().unwrap().to_owned();
    let r = browser
        .send(
            app,
            browser.post(
                &format!("/v1/orgs/{org}/api-keys"),
                &json!({"name": "probe", "scopes": ["org:read"]}),
            ),
        )
        .await;
    assert!(r.status.is_success(), "{}", r.text());
    let key = r.json::<Value>()["key"].as_str().unwrap().to_owned();

    let doc: Value = app.send(TestRequest::get("/openapi.json")).await.json();
    let mut out = BTreeMap::new();
    for (method, path, op) in operations(&doc) {
        let body = probe_body(&doc, op);
        let upper = method.to_ascii_uppercase();
        let state_changing = matches!(upper.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
        let request = |org: &str| {
            let mut r = TestRequest::new(upper.parse().unwrap(), &concrete(&path, org))
                .header("origin", ORIGIN);
            if state_changing {
                r = r.json(&body);
            }
            r
        };
        let mut accepted = BTreeSet::new();
        if unauthenticated(&app.send(request(ZERO)).await) {
            // Every probe starts with live credentials: an earlier probe
            // (logout, revocation) may have ended them.
            if app.send(browser.get("/v1/me")).await.status != axum::http::StatusCode::OK {
                browser = web_login().await;
            }
            // Session cookie (+ CSRF token): a non-member org id, so no
            // probe changes the probing organization.
            let mut r = request(ZERO).header("x-csrf-token", browser.csrf.as_deref().unwrap());
            for (name, value) in &browser.cookies {
                r = r.cookie(name, value);
            }
            if !unauthenticated(&app.send(r).await) {
                accepted.insert("session_cookie".to_owned());
            }
            // The cookie probe may have ended every session of the user.
            let me = app.send(TestRequest::get("/v1/me").bearer(&access)).await;
            if me.status != axum::http::StatusCode::OK {
                access = native_login().await;
            }
            if !unauthenticated(&app.send(request(ZERO).bearer(&access)).await) {
                accepted.insert("bearer_jwt".to_owned());
            }
            // API keys: the key's own organization (an org:read key).
            if !unauthenticated(&app.send(request(&org).header("x-api-key", &key)).await) {
                accepted.insert("api_key".to_owned());
            }
            if !unauthenticated(&app.send(request(&org).bearer(&key)).await) {
                accepted.insert("api_key_bearer".to_owned());
            }
            assert!(
                !accepted.is_empty(),
                "{upper} {path}: refuses every credential"
            );
        }
        out.insert((upper, path), accepted);
    }
    out
}

/// K-129: the `security` of every operation is exactly what the router
/// enforces. Set `PRINT_ENFORCED_SECURITY=1` to print the enforced table.
#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn arc_09_k129_declared_security_matches_the_router(pool: sqlx::PgPool) {
    // No new-device confirmations: the probe signs in again whenever an
    // operation (logout, revocation) ended its session. No per-IP budget:
    // the probe sends every operation five times from one address.
    let app = common::App::with(pool, |c| {
        c.protect.risk.enabled = false;
        // Hundreds of probes from one address.
        c.protect.rate_limit.requests_per_ip =
            authn_core::ports::RateLimitPolicy::new(100_000, std::time::Duration::from_secs(60));
    })
    .await;
    let enforced = enforced_schemes(&app).await;
    if std::env::var_os("PRINT_ENFORCED_SECURITY").is_some() {
        for ((method, path), schemes) in &enforced {
            println!(
                "ENFORCED {method} {path} {}",
                schemes.iter().cloned().collect::<Vec<_>>().join(",")
            );
        }
    }
    let doc = document();
    let mut mismatches = Vec::new();
    for (method, path, op) in operations(&doc) {
        let key = (method.to_ascii_uppercase(), path.clone());
        let enforced = enforced.get(&key).cloned().unwrap_or_default();
        let declared = declared_schemes(op).unwrap_or_default();
        if declared != enforced {
            mismatches.push(format!(
                "{} {path}: declared {declared:?}, enforced {enforced:?}",
                key.0
            ));
        }
        for scheme in &declared {
            assert!(SCHEMES.contains(&scheme.as_str()), "{scheme}");
        }
    }
    assert!(
        mismatches.is_empty(),
        "declared security differs from the router:\n{}",
        mismatches.join("\n")
    );
}
