//! HTTP request metrics (OPS-04: latency histograms).
//!
//! The module crates count their own events (logins by reason code, MFA
//! usage, registrations, reset requests, rate-limit triggers, token reuse,
//! outbox depth); this layer adds the request latency histogram of every
//! route. Labels are bounded vocabularies — the matched route *template*
//! (`/v1/orgs/{org_id}/members`, never the concrete path), the method and
//! the status class — so neither user data nor attacker-chosen paths can
//! grow the series count.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use http::{Method, StatusCode};

/// Request latency in seconds, by `method`, `route` and `status` class.
pub const HTTP_REQUEST_DURATION: &str = "authn_http_request_duration_seconds";

/// Histogram buckets (seconds) of [`HTTP_REQUEST_DURATION`]: from a cached
/// token check to an Argon2 verification under load.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Route label of requests no route matched (404s, probes of random paths).
pub const UNMATCHED_ROUTE: &str = "unmatched";

/// Middleware recording [`HTTP_REQUEST_DURATION`] (installed by
/// [`crate::app::build_router`]).
pub async fn http_metrics(request: Request, next: Next) -> Response {
    let method = method_label(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| UNMATCHED_ROUTE.to_owned(), |p| p.as_str().to_owned());
    let started = Instant::now();
    let response = next.run(request).await;
    metrics::histogram!(
        HTTP_REQUEST_DURATION,
        "method" => method,
        "route" => route,
        "status" => status_class(response.status()),
    )
    .record(started.elapsed().as_secs_f64());
    response
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_04_labels_are_bounded_vocabularies() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(
            method_label(&Method::from_bytes(b"PROPFIND").unwrap()),
            "other"
        );
        assert_eq!(status_class(StatusCode::OK), "2xx");
        assert_eq!(status_class(StatusCode::TOO_MANY_REQUESTS), "4xx");
        assert_eq!(status_class(StatusCode::SERVICE_UNAVAILABLE), "5xx");
        assert!(LATENCY_BUCKETS.windows(2).all(|w| w[0] < w[1]));
    }
}
