//! Structured logging (OPS-03) and optional OpenTelemetry tracing (OPS-11,
//! OPS-12; K-92).
//!
//! JSON lines by default. Every request runs inside the `http_request` span
//! created by the request-context middleware and the `http` span of the
//! tracing layer ([`make_http_span`]), so each log line carries the
//! `request_id`. Never log secrets; mask personal data with
//! `authn_core::redact`.
//!
//! # OpenTelemetry (cargo feature `otel`, `[telemetry]`)
//!
//! * Export: OTLP over HTTP/protobuf to `telemetry.endpoint`, through a
//!   batch processor with a **bounded queue that drops** when full and a
//!   per-export timeout, on its own thread (HTTP through authn-protect's
//!   `HttpClient` port, operator-configured target): a slow or unreachable collector
//!   never blocks or fails a request. Collector headers (e.g. an API key)
//!   come from the standard `OTEL_EXPORTER_OTLP_TRACES_HEADERS` /
//!   `OTEL_EXPORTER_OTLP_HEADERS` environment variables, never from the
//!   configuration file.
//! * Propagation: W3C Trace Context (`traceparent`) of incoming requests is
//!   continued when `telemetry.propagate_incoming`; the caller's
//!   `tracestate` is dropped (foreign, unvetted data) and its "sampled" flag
//!   is ignored unless `telemetry.respect_remote_sampling` (anyone on the
//!   internet can send it: a client must not be able to push every request
//!   into the exporter, and since it also picks the trace id, a remote
//!   parent is sampled by an independent CSPRNG draw, not by trace id).
//! * Correlation: the exported `http` span carries the server-generated
//!   `request_id` (also in every log line and the `x-request-id` header);
//!   the log span carries the `trace_id`.
//! * **No personal data or secrets in spans (OPS-12).** Only spans are
//!   exported — never log events — and only the spans of this workspace
//!   (`authn_*` targets) except the request-context span (it holds the raw
//!   path). The `http` span holds the method, the route **template**
//!   (`/v1/orgs/{org_id}/members`, `unmatched` for 404s), the status code
//!   and the request id: no path values, query strings, headers, cookies,
//!   bodies, client IPs (not even truncated: the request id leads to the
//!   masked IP in the logs) or user ids. `tests/telemetry.rs` runs the
//!   login, registration, refresh and password-reset flows and checks every
//!   exported name and attribute.

use authn_core::config::AppConfig;
use authn_core::config::server::{LogFormat, ServerConfig};
use authn_core::http::REQUEST_ID_HEADER;
use axum::extract::MatchedPath;
use tracing::Span;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::error::ServerError;
use crate::metrics::UNMATCHED_ROUTE;

/// Name of the authn-core request-context span (never exported: it holds
/// the raw path).
pub const REQUEST_CONTEXT_SPAN: &str = "http_request";

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

fn log_layer(config: &ServerConfig) -> Result<BoxedLayer, ServerError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .map_err(|e| ServerError::Telemetry(e.to_string()))?;
    Ok(match config.log_format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .with_target(true)
            .with_filter(filter)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .pretty()
            .with_filter(filter)
            .boxed(),
    })
}

/// Installs the global subscriber (logs only; CLI commands). `RUST_LOG`
/// overrides `server.log_filter`.
pub fn init(config: &ServerConfig) -> Result<(), ServerError> {
    tracing_subscriber::registry()
        .with(log_layer(config)?)
        .try_init()
        .map_err(|e| ServerError::Telemetry(e.to_string()))
}

/// Refuses `telemetry.enabled = true` in a binary built without the `otel`
/// feature (`serve` and `check-config`).
pub fn check(config: &AppConfig) -> Result<(), ServerError> {
    if config.telemetry.enabled && !cfg!(feature = "otel") {
        return Err(ServerError::Telemetry(
            "telemetry.enabled = true needs a binary built with the `otel` cargo feature"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Flushes and stops the trace exporter on shutdown (no-op without one).
#[derive(Debug, Default)]
pub struct TelemetryGuard {
    #[cfg(feature = "otel")]
    provider: Option<(
        opentelemetry_sdk::trace::SdkTracerProvider,
        std::time::Duration,
    )>,
}

impl TelemetryGuard {
    /// Exports what is queued (bounded by the export timeout) and stops the
    /// exporter thread. Never fails the shutdown: errors are logged.
    pub async fn shutdown(self) {
        #[cfg(feature = "otel")]
        if let Some((provider, timeout)) = self.provider {
            let result = tokio::task::spawn_blocking(move || {
                provider.shutdown_with_timeout(timeout + std::time::Duration::from_secs(1))
            })
            .await;
            match result {
                Ok(Ok(())) => tracing::info!("trace exporter stopped"),
                Ok(Err(err)) => tracing::warn!(error = %err, "trace exporter shutdown incomplete"),
                Err(err) => tracing::warn!(error = %err, "trace exporter shutdown task failed"),
            }
        }
    }
}

/// `serve`: logs plus, when `telemetry.enabled`, the OpenTelemetry layer.
/// Must run inside the Tokio runtime (the exporter sends through it).
pub fn init_serve(config: &AppConfig) -> Result<TelemetryGuard, ServerError> {
    check(config)?;
    let logs = log_layer(&config.server)?;
    #[cfg(feature = "otel")]
    if config.telemetry.enabled {
        let provider = otel::otlp_provider(&config.telemetry, &config.protect.outbound)?;
        otel::activate(&config.telemetry);
        tracing_subscriber::registry()
            .with(logs)
            .with(otel::layer(&provider))
            .try_init()
            .map_err(|e| ServerError::Telemetry(e.to_string()))?;
        tracing::info!(
            sampling_ratio = config.telemetry.sampling_ratio,
            "OpenTelemetry trace export enabled"
        );
        return Ok(TelemetryGuard {
            provider: Some((provider, config.telemetry.export_timeout)),
        });
    }
    tracing_subscriber::registry()
        .with(logs)
        .try_init()
        .map_err(|e| ServerError::Telemetry(e.to_string()))?;
    Ok(TelemetryGuard::default())
}

/// The `http` span of the tracing layer (OPS-02 slot 2). Fields are
/// OPS-12-safe (see the module docs); the OpenTelemetry parent comes from
/// `traceparent` when propagation is on.
pub fn make_http_span<B>(request: &http::Request<B>) -> Span {
    // The request-context middleware has already replaced `x-request-id`
    // with a server-generated UUIDv7.
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNMATCHED_ROUTE, MatchedPath::as_str);
    let method = request.method().as_str();
    let span = tracing::info_span!(
        "http",
        otel.name = %format_args!("{method} {route}"),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        request_id = %request_id,
        http.request.method = %method,
        http.route = %route,
        http.response.status_code = tracing::field::Empty,
        trace_id = tracing::field::Empty,
    );
    #[cfg(feature = "otel")]
    otel::link(&span, request.headers());
    span
}

/// Records the response status on the `http` span.
pub fn record_response<B>(response: &http::Response<B>, span: &Span) {
    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "error");
    }
}

/// OpenTelemetry plumbing (feature `otel`). Public for the tests.
#[cfg(feature = "otel")]
pub mod otel {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use authn_core::config::protect::OutboundHttpConfig;
    use authn_core::config::telemetry::TelemetryConfig;
    use authn_core::ports::{OutboundRequest, OutboundTarget};
    use bytes::Bytes;
    use opentelemetry::propagation::TextMapCompositePropagator;
    use opentelemetry::trace::{
        Link, SpanKind, TraceContextExt, TraceId, TraceState, TracerProvider as _,
    };
    use opentelemetry::{Context, KeyValue};
    use opentelemetry_http::{HeaderExtractor, HttpClient, HttpError, Request, Response};
    use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::{
        BatchConfigBuilder, BatchSpanProcessor, Sampler, SamplingDecision, SamplingResult,
        SdkTracerProvider, ShouldSample, SpanLimits, TracerProviderBuilder,
    };
    use tracing::{Metadata, Span};
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    use tracing_subscriber::Layer;
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::registry::LookupSpan;

    use super::REQUEST_CONTEXT_SPAN;
    use crate::error::ServerError;

    /// Largest collector response read (OTLP responses are tiny).
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;

    /// Whether a span may be exported (OPS-12): spans only (log events
    /// never), info level or above, this workspace's own spans, never the
    /// request-context span.
    #[must_use]
    pub fn exported(meta: &Metadata<'_>) -> bool {
        meta.is_span()
            && *meta.level() <= tracing::Level::INFO
            && meta.target().starts_with("authn_")
            && meta.name() != REQUEST_CONTEXT_SPAN
    }

    /// The OpenTelemetry layer over `provider`, filtered by [`exported`].
    pub fn layer<S>(provider: &SdkTracerProvider) -> impl Layer<S> + Send + Sync + use<S>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("rust-authentication"))
            .with_location(false)
            .with_threads(false)
            .with_target(false)
            .with_level(false)
            .with_tracked_inactivity(false)
            .with_error_fields_to_exceptions(false)
            .with_error_events_to_status(false)
            .with_error_events_to_exceptions(false)
            .with_filter(filter_fn(exported))
    }

    /// Sampler, resource and limits of `config` (no processor yet; tests
    /// add an in-memory exporter).
    #[must_use]
    pub fn provider_builder(config: &TelemetryConfig) -> TracerProviderBuilder {
        let limits = SpanLimits {
            max_events_per_span: 0,
            max_attributes_per_span: 32,
            max_links_per_span: 0,
            max_attributes_per_event: 0,
            max_attributes_per_link: 0,
        };
        SdkTracerProvider::builder()
            .with_sampler(LocalSampler::new(config))
            .with_span_limits(limits)
            .with_resource(
                Resource::builder_empty()
                    .with_service_name(config.service_name.clone())
                    .build(),
            )
    }

    /// The production provider: OTLP/HTTP exporter behind a bounded batch
    /// processor.
    pub fn otlp_provider(
        config: &TelemetryConfig,
        outbound: &OutboundHttpConfig,
    ) -> Result<SdkTracerProvider, ServerError> {
        let endpoint = config
            .endpoint
            .as_ref()
            .ok_or_else(|| ServerError::Telemetry("telemetry.endpoint is not set".to_owned()))?;
        let client = ExportClient::new(config, outbound)?;
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(client)
            .with_endpoint(endpoint.as_str())
            .with_timeout(config.export_timeout)
            .build()
            .map_err(|e| ServerError::Telemetry(format!("OTLP exporter: {e}")))?;
        let batch = BatchConfigBuilder::default()
            .with_max_queue_size(config.max_queue_size)
            .with_max_export_batch_size(config.max_export_batch_size)
            .with_scheduled_delay(config.scheduled_delay)
            .build();
        let processor = BatchSpanProcessor::builder(exporter)
            .with_batch_config(batch)
            .build();
        Ok(provider_builder(config)
            .with_span_processor(processor)
            .build())
    }

    /// Whether [`activate`] ran (request spans then look for a parent and
    /// record the trace id; otherwise they skip that work).
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Turns trace linking on and installs the W3C Trace Context propagator
    /// (or none when `propagate_incoming = false`).
    pub fn activate(config: &TelemetryConfig) {
        ACTIVE.store(true, Ordering::Relaxed);
        if config.propagate_incoming {
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_sdk::propagation::TraceContextPropagator::new(),
            );
        } else {
            opentelemetry::global::set_text_map_propagator(TextMapCompositePropagator::new(
                Vec::new(),
            ));
        }
    }

    /// Continues the caller's trace (when propagation is on) and records
    /// the `trace_id` for log correlation.
    pub(super) fn link(span: &Span, headers: &http::HeaderMap) {
        if !ACTIVE.load(Ordering::Relaxed) {
            return;
        }
        let parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(headers))
        });
        if parent.span().span_context().is_valid() {
            // Only fails when the span is disabled (not exported).
            let _ = span.set_parent(parent);
        }
        let context = span.context();
        let span_context = context.span().span_context().clone();
        if span_context.is_valid() {
            span.record("trace_id", tracing::field::display(span_context.trace_id()));
        }
    }

    /// Local sampling decision (see the module docs of
    /// [`crate::telemetry`]).
    #[derive(Debug, Clone)]
    pub struct LocalSampler {
        ratio: f64,
        by_trace_id: Sampler,
        respect_remote: bool,
    }

    impl LocalSampler {
        /// From `telemetry.sampling_ratio` / `respect_remote_sampling`.
        #[must_use]
        pub fn new(config: &TelemetryConfig) -> Self {
            Self {
                ratio: config.sampling_ratio,
                by_trace_id: Sampler::TraceIdRatioBased(config.sampling_ratio),
                respect_remote: config.respect_remote_sampling,
            }
        }

        fn random_draw(&self) -> bool {
            if self.ratio >= 1.0 {
                return true;
            }
            if self.ratio <= 0.0 {
                return false;
            }
            // CSPRNG; on failure, do not sample (fail closed, nothing lost
            // but a trace).
            getrandom::u64().is_ok_and(|n| {
                #[allow(clippy::cast_precision_loss)]
                let draw = (n >> 11) as f64 / (1_u64 << 53) as f64;
                draw < self.ratio
            })
        }
    }

    fn decided(sampled: bool, trace_state: TraceState) -> SamplingResult {
        SamplingResult {
            decision: if sampled {
                SamplingDecision::RecordAndSample
            } else {
                SamplingDecision::Drop
            },
            attributes: Vec::new(),
            trace_state,
        }
    }

    impl ShouldSample for LocalSampler {
        fn should_sample(
            &self,
            parent_context: Option<&Context>,
            trace_id: TraceId,
            name: &str,
            span_kind: &SpanKind,
            attributes: &[KeyValue],
            links: &[Link],
        ) -> SamplingResult {
            if let Some(parent) = parent_context.filter(|cx| cx.has_active_span()) {
                let parent = parent.span().span_context().clone();
                if !parent.is_remote() {
                    // A child of a local span follows it.
                    return decided(parent.is_sampled(), parent.trace_state().clone());
                }
                // Remote parent: the caller's tracestate is dropped.
                let sampled = if self.respect_remote {
                    parent.is_sampled()
                } else {
                    self.random_draw()
                };
                return decided(sampled, TraceState::default());
            }
            let mut result = self
                .by_trace_id
                .should_sample(None, trace_id, name, span_kind, attributes, links);
            result.trace_state = TraceState::default();
            result
        }
    }

    /// The exporter's HTTP client: the `HttpClient` port of authn-protect
    /// (ARC-02: only adapter crates talk HTTP) with an operator-configured
    /// (`Trusted`) target — no proxy, no redirects, capped response, total
    /// timeout `telemetry.export_timeout` — driven on the server's Tokio
    /// runtime, so the batch processor's own thread can export without a
    /// runtime of its own.
    #[derive(Clone)]
    pub struct ExportClient {
        http: Arc<dyn authn_core::ports::HttpClient>,
        timeout: Duration,
        runtime: tokio::runtime::Handle,
    }

    impl std::fmt::Debug for ExportClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ExportClient")
                .field("timeout", &self.timeout)
                .finish_non_exhaustive()
        }
    }

    impl ExportClient {
        /// Must be called inside the Tokio runtime, after
        /// `authn_core::tls::install_crypto_provider`.
        pub fn new(
            config: &TelemetryConfig,
            outbound: &OutboundHttpConfig,
        ) -> Result<Self, ServerError> {
            let runtime = tokio::runtime::Handle::try_current()
                .map_err(|e| ServerError::Telemetry(format!("no Tokio runtime: {e}")))?;
            let http = authn_protect::outbound::SsrfSafeHttpClient::new(outbound)
                .map_err(|e| ServerError::Telemetry(format!("OTLP HTTP client: {e}")))?;
            Ok(Self {
                http: Arc::new(http),
                timeout: config.export_timeout,
                runtime,
            })
        }
    }

    #[async_trait]
    impl HttpClient for ExportClient {
        async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
            let (parts, body) = request.into_parts();
            let url = url::Url::parse(&parts.uri.to_string())?;
            let mut outbound = OutboundRequest::post(url, body.to_vec(), OutboundTarget::Trusted);
            outbound.method = parts.method;
            outbound.headers = parts.headers;
            outbound.timeout = Some(self.timeout);
            outbound.max_response_bytes = Some(MAX_RESPONSE_BYTES);
            let http = self.http.clone();
            let response = self
                .runtime
                .spawn(async move { http.execute(outbound).await })
                .await??;
            let mut builder = Response::builder().status(response.status);
            if let Some(headers) = builder.headers_mut() {
                *headers = response.headers;
            }
            Ok(builder.body(Bytes::from(response.body))?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_11_enabled_telemetry_needs_the_otel_feature() {
        let mut config = authn_testkit::config::test_config();
        assert!(check(&config).is_ok(), "disabled is always fine");
        config.telemetry.enabled = true;
        assert_eq!(check(&config).is_ok(), cfg!(feature = "otel"));
    }
}
