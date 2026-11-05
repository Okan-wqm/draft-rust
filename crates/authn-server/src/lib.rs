//! # authn-server
//!
//! The `rust-authentication` binary as a library (so it can be tested):
//!
//! * [`cli`] — subcommands (OPS-01) and their dispatch.
//! * [`state`] — [`AppState`](state::AppState), the only application state
//!   type of the workspace (ARC-03), and its `FromRef` projections.
//! * [`app`] — router assembly and the middleware stack (OPS-02).
//! * [`cors`] — the cross-origin admin console preflight (K-67).
//! * [`routes`] — health probes (OPS-05) and the reference example module
//!   showing the `router<S>()` + `FromRef` convention.
//! * [`telemetry`] — structured JSON logging (OPS-03).
//! * [`services`] — building every module service in dependency order (§15).
//! * [`hooks`] — the hook traits the server implements (§15.1).
//! * [`jobs`] — background maintenance jobs (OPS-06).
//! * [`serve`] — the HTTP server with graceful shutdown (OPS-07).

pub mod app;
pub mod cli;
pub mod cors;
pub mod error;
pub mod hooks;
pub mod jobs;
pub mod openapi;
pub mod operations;
pub mod routes;
pub mod serve;
pub mod services;
pub mod state;
pub mod telemetry;

pub use error::ServerError;
