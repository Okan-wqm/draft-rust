//! # authn-server
//!
//! The `rust-authentication` binary as a library (so it can be tested):
//!
//! * [`cli`] — subcommands (OPS-01) and their dispatch.
//! * [`state`] — [`AppState`](state::AppState), the only application state
//!   type of the workspace (ARC-03), and its `FromRef` projections.
//! * [`app`] — router assembly and the middleware stack (OPS-02).
//! * [`routes`] — health probes (OPS-05) and the reference example module
//!   showing the `router<S>()` + `FromRef` convention.
//! * [`telemetry`] — structured JSON logging (OPS-03).
//! * [`serve`] — the HTTP server with graceful shutdown (OPS-07).

pub mod app;
pub mod cli;
pub mod error;
pub mod openapi;
pub mod routes;
pub mod serve;
pub mod state;
pub mod telemetry;

pub use error::ServerError;
