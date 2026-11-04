#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! ADM-02: user search (keyset pagination, filters) and details without
//! secrets.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use authn_core::domain::AccountStatus;
use authn_core::id::UserId;
use authn_testkit::http::TestRequest;
use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

async fn walk(h: &Harness, principal: &authn_core::domain::Principal, query: &str) -> Vec<Value> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            Some(c) => format!("/v1/admin/users?limit=3&{query}&cursor={c}"),
            None => format!("/v1/admin/users?limit=3&{query}"),
        };
        let res = h.send(principal, TestRequest::get(&uri)).await;
        res.assert_status(StatusCode::OK);
        let body: Value = res.json();
        let items = body["items"].as_array().unwrap().clone();
        assert!(items.len() <= 3);
        all.extend(items);
        match body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    all
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_02_keyset_pagination_has_no_duplicates_or_skips(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (admin, principal) = h.admin("admin@example.com").await;
    let mut expected = vec![admin];
    // Several accounts share a creation instant (tie-breaker on id).
    for i in 0..10 {
        if i % 3 == 0 {
            h.advance(Duration::from_secs(1));
        }
        expected.push(h.user(&format!("user{i}@example.com")).await);
    }
    let first = walk(&h, &principal, "").await;
    let ids: Vec<String> = first
        .iter()
        .map(|u| u["id"].as_str().unwrap().to_owned())
        .collect();
    let unique: HashSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicates: {ids:?}");
    assert_eq!(ids.len(), expected.len());
    for id in &expected {
        assert!(ids.contains(&id.to_string()), "{id} skipped");
    }
    // Newest first.
    let times: Vec<&str> = first
        .iter()
        .map(|u| u["created_at"].as_str().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted);

    // A sign-up in the middle of a walk neither duplicates nor skips the
    // accounts that existed when it started.
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users?limit=4"))
        .await;
    let page: Value = res.json();
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    h.advance(Duration::from_secs(5));
    h.user("late@example.com").await;
    let mut rest = page["items"].as_array().unwrap().clone();
    let mut next = Some(cursor);
    while let Some(c) = next {
        let res = h
            .send(
                &principal,
                TestRequest::get(&format!("/v1/admin/users?limit=4&cursor={c}")),
            )
            .await;
        let body: Value = res.json();
        rest.extend(body["items"].as_array().unwrap().clone());
        next = body["next_cursor"].as_str().map(str::to_owned);
    }
    assert_eq!(rest.len(), expected.len());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_02_filters_apply(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, principal) = h.admin("root@corp.example").await;
    let suspended = h
        .user_with_status("bob@shop.example", AccountStatus::Suspended)
        .await;
    let pending = h
        .user_with_status("carol@shop.example", AccountStatus::PendingVerification)
        .await;
    let active = h.user("alice@shop.example").await;

    let ids = |items: Vec<Value>| -> Vec<String> {
        items
            .iter()
            .map(|u| u["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let by_status = ids(walk(&h, &principal, "status=suspended").await);
    assert_eq!(by_status, vec![suspended.to_string()]);
    let by_email = ids(walk(&h, &principal, "email=ALICE%40shop").await);
    assert_eq!(by_email, vec![active.to_string()]);
    let unverified = ids(walk(&h, &principal, "email_verified=false").await);
    assert_eq!(unverified, vec![pending.to_string()]);
    let admins = walk(&h, &principal, "platform_admin=true").await;
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0]["email"], "root@corp.example");
    // LIKE wildcards are literal characters of the prefix, not patterns.
    assert!(walk(&h, &principal, "email=%25").await.is_empty());
    assert!(walk(&h, &principal, "email=_").await.is_empty());
    let future = (h.now() + Duration::from_secs(60))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert_eq!(
        walk(&h, &principal, &format!("created_before={future}"))
            .await
            .len(),
        4
    );
    assert!(
        walk(&h, &principal, &format!("created_after={future}"))
            .await
            .is_empty()
    );
    for bad in [
        "status=bogus",
        "created_after=yesterday",
        "cursor=!!",
        "unknown=1",
    ] {
        let res = h
            .send(
                &principal,
                TestRequest::get(&format!("/v1/admin/users?{bad}")),
            )
            .await;
        assert!(res.status.is_client_error(), "{bad}: {}", res.status);
    }
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_02_detail_contains_no_secrets_and_is_audited(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, principal) = h.admin("admin@example.com").await;
    let user = h.user("alice@example.com").await;
    sqlx::query(
        "INSERT INTO mfa_factors (id, user_id, kind, status, phone_e164, created_at, confirmed_at) \
         VALUES ($1, $2, 'sms', 'active', '+905551112233', $3, $3)",
    )
    .bind(uuid::Uuid::now_v7())
    .bind(user)
    .bind(h.now())
    .execute(&h.pool)
    .await
    .unwrap();
    let hash: String =
        sqlx::query_scalar("SELECT password_hash FROM password_credentials WHERE user_id = $1")
            .bind(user)
            .fetch_one(&h.pool)
            .await
            .unwrap();

    let res = h
        .send(
            &principal,
            TestRequest::get(&format!("/v1/admin/users/{user}")),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("no-store"));
    let text = res.text();
    let body: Value = res.json();
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["password"]["set"], true);
    assert_eq!(body["password"]["must_change"], false);
    assert_eq!(body["mfa"]["enabled"], true);
    for secret in [
        hash.as_str(),
        "$argon2",
        "password_hash",
        "pepper",
        "secret",
        "5551112233",
        "905551112233",
    ] {
        assert!(!text.contains(secret), "detail leaks {secret}: {text}");
    }
    let viewed = h.admin_events("user_viewed").await;
    assert_eq!(viewed.len(), 1);

    // Unknown ids and malformed ids are 404 / 4xx without detail.
    let res = h
        .send(
            &principal,
            TestRequest::get(&format!("/v1/admin/users/{}", UserId::generate())),
        )
        .await;
    res.assert_error(StatusCode::NOT_FOUND, "not_found");
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users/not-a-uuid"))
        .await;
    assert!(res.status.is_client_error());
}

#[sqlx::test(migrator = "authn_testkit::MIGRATOR")]
async fn adm_02_listing_contains_no_secrets(pool: sqlx::PgPool) {
    let h = Harness::new(pool).await;
    let (_, principal) = h.admin("admin@example.com").await;
    h.user("alice@example.com").await;
    let res = h
        .send(&principal, TestRequest::get("/v1/admin/users"))
        .await;
    let text = res.text();
    for secret in ["$argon2", "password", "hash", "secret"] {
        assert!(!text.contains(secret), "listing leaks {secret}");
    }
}
