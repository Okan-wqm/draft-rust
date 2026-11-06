//! `[telemetry]` — optional OpenTelemetry trace export (OPS-11, K-92;
//! owner: authn-server, which needs the `otel` cargo feature to honour
//! `enabled = true`).
//!
//! Spans go to an OTLP/HTTP (protobuf) collector. Export never blocks a
//! request: spans wait in a bounded queue that drops on overflow, and an
//! export that does not finish within `export_timeout` is abandoned.
//! Spans never carry personal data or secrets (OPS-12).

use std::time::Duration;

use serde::Deserialize;
use url::Url;

use super::common::{ConfigProblems, secs};

/// Longest accepted `service_name`.
pub const MAX_SERVICE_NAME_LEN: usize = 64;

/// `[telemetry]` section.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Export traces. Default `false`.
    pub enabled: bool,
    /// OTLP/HTTP traces endpoint, the full URL including the path (e.g.
    /// `http://127.0.0.1:4318/v1/traces`). Required when `enabled`. No
    /// user info, query or fragment (credentials never live in a URL).
    pub endpoint: Option<Url>,
    /// `service.name` resource attribute. Default `rust-authentication`.
    pub service_name: String,
    /// Fraction of new traces that are sampled, `0.0` … `1.0`. Default
    /// `0.1`.
    pub sampling_ratio: f64,
    /// Continue the caller's trace from an incoming W3C `traceparent`
    /// header. Default `true`.
    pub propagate_incoming: bool,
    /// Follow the caller's "sampled" flag. Default `false`: anyone on the
    /// internet can send `traceparent`, so by default the local
    /// `sampling_ratio` alone decides (a client cannot force every request
    /// into the exporter); the trace id is still continued.
    pub respect_remote_sampling: bool,
    /// Per-export timeout. Default `5s` (1s … 30s).
    #[serde(with = "super::duration")]
    pub export_timeout: Duration,
    /// Delay between batch exports. Default `5s` (100ms … 60s).
    #[serde(with = "super::duration")]
    pub scheduled_delay: Duration,
    /// Spans waiting for export; newer spans are dropped when full. Default
    /// 2048 (64 … 65536).
    pub max_queue_size: usize,
    /// Spans per export request. Default 512 (1 … `max_queue_size`).
    pub max_export_batch_size: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: "rust-authentication".to_owned(),
            sampling_ratio: 0.1,
            propagate_incoming: true,
            respect_remote_sampling: false,
            export_timeout: secs(5),
            scheduled_delay: secs(5),
            max_queue_size: 2048,
            max_export_batch_size: 512,
        }
    }
}

impl TelemetryConfig {
    /// Collects problems (keys and rules, never values).
    pub fn validate(&self, p: &mut ConfigProblems) {
        if self.enabled {
            match &self.endpoint {
                None => p.push(
                    "telemetry.endpoint",
                    "is required when telemetry is enabled",
                ),
                Some(url) => validate_endpoint(url, p),
            }
        } else if let Some(url) = &self.endpoint {
            validate_endpoint(url, p);
        }
        p.require(
            !self.service_name.trim().is_empty()
                && self.service_name.len() <= MAX_SERVICE_NAME_LEN
                && self
                    .service_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "telemetry.service_name",
            "must be 1-64 characters of A-Z, a-z, 0-9, '-', '_' or '.'",
        );
        p.require(
            self.sampling_ratio.is_finite() && (0.0..=1.0).contains(&self.sampling_ratio),
            "telemetry.sampling_ratio",
            "must be between 0.0 and 1.0",
        );
        p.require_range(
            self.export_timeout,
            secs(1),
            secs(30),
            "telemetry.export_timeout",
        );
        p.require_range(
            self.scheduled_delay,
            Duration::from_millis(100),
            secs(60),
            "telemetry.scheduled_delay",
        );
        p.require(
            (64..=65_536).contains(&self.max_queue_size),
            "telemetry.max_queue_size",
            "must be between 64 and 65536",
        );
        p.require(
            (1..=self.max_queue_size).contains(&self.max_export_batch_size),
            "telemetry.max_export_batch_size",
            "must be between 1 and telemetry.max_queue_size",
        );
    }
}

fn validate_endpoint(url: &Url, p: &mut ConfigProblems) {
    p.require(
        matches!(url.scheme(), "http" | "https") && url.host().is_some(),
        "telemetry.endpoint",
        "must be an absolute http(s) URL",
    );
    p.require(
        url.username().is_empty() && url.password().is_none(),
        "telemetry.endpoint",
        "must not contain user info (credentials never live in a URL)",
    );
    p.require(
        url.query().is_none() && url.fragment().is_none(),
        "telemetry.endpoint",
        "must not contain a query or fragment",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(config: &TelemetryConfig) -> Vec<String> {
        let mut p = ConfigProblems::default();
        config.validate(&mut p);
        p.problems().to_vec()
    }

    #[test]
    fn ops_11_telemetry_is_off_by_default_and_valid() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
        assert!(problems(&config).is_empty());
    }

    #[test]
    fn ops_11_enabled_telemetry_needs_a_clean_endpoint() {
        let mut config = TelemetryConfig {
            enabled: true,
            ..TelemetryConfig::default()
        };
        assert!(problems(&config)[0].starts_with("telemetry.endpoint"));
        for bad in [
            "ftp://collector/v1/traces",
            "https://user:pw@collector/v1/traces",
            "https://collector/v1/traces?token=x",
            "https://collector/v1/traces#x",
        ] {
            config.endpoint = Some(Url::parse(bad).unwrap());
            let found = problems(&config);
            assert!(
                found.iter().any(|m| m.starts_with("telemetry.endpoint")),
                "{bad}: {found:?}"
            );
            // Messages never echo the value (it may hold a credential).
            assert!(
                found
                    .iter()
                    .all(|m| !m.contains("pw") && !m.contains("token=x"))
            );
        }
        config.endpoint = Some(Url::parse("http://127.0.0.1:4318/v1/traces").unwrap());
        assert!(problems(&config).is_empty());
    }

    #[test]
    fn ops_11_ranges_are_enforced() {
        for config in [
            TelemetryConfig {
                sampling_ratio: 1.5,
                ..TelemetryConfig::default()
            },
            TelemetryConfig {
                sampling_ratio: f64::NAN,
                ..TelemetryConfig::default()
            },
            TelemetryConfig {
                service_name: "bad name\n".to_owned(),
                ..TelemetryConfig::default()
            },
            TelemetryConfig {
                export_timeout: Duration::from_millis(10),
                ..TelemetryConfig::default()
            },
            TelemetryConfig {
                max_queue_size: 10,
                max_export_batch_size: 8,
                ..TelemetryConfig::default()
            },
            TelemetryConfig {
                max_export_batch_size: 4096,
                ..TelemetryConfig::default()
            },
        ] {
            assert_eq!(problems(&config).len(), 1, "{config:?}");
        }
    }
}
