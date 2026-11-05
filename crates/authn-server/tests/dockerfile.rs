#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-109 / OPS-08: the `Dockerfile` stays consistent with the binary (no
//! Docker daemon needed): the image is built with features that exist and
//! include `redis`, the metrics listener is reachable from outside the
//! container, and every listener port is exposed.

use std::net::SocketAddr;

const DOCKERFILE: &str = include_str!("../../../Dockerfile");
const MANIFEST: &str = include_str!("../Cargo.toml");

/// Logical lines of the Dockerfile (`\` continuations joined, comments
/// dropped).
fn instructions() -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for raw in DOCKERFILE.lines() {
        let line = raw.trim();
        if line.starts_with('#') && current.is_empty() {
            continue;
        }
        if let Some(head) = line.strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
            continue;
        }
        current.push_str(line);
        if !current.trim().is_empty() {
            lines.push(current.trim().to_owned());
        }
        current.clear();
    }
    lines
}

/// Feature names of the server manifest's `[features]` table.
fn server_features() -> Vec<String> {
    let section = MANIFEST
        .split_once("\n[features]\n")
        .expect("[features] table")
        .1
        .split("\n[")
        .next()
        .unwrap();
    section
        .lines()
        .filter_map(|line| {
            line.split_once(" = ")
                .map(|(name, _)| name.trim().to_owned())
        })
        .collect()
}

fn build_command() -> String {
    instructions()
        .into_iter()
        .find(|line| line.contains("cargo build"))
        .expect("cargo build instruction")
}

fn env_value(name: &str) -> Option<String> {
    instructions().into_iter().find_map(|line| {
        let rest = line.strip_prefix("ENV ")?;
        let (key, value) = rest.split_once('=')?;
        (key.trim() == name).then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn exposed_ports() -> Vec<u16> {
    instructions()
        .into_iter()
        .filter_map(|line| line.strip_prefix("EXPOSE ").map(str::to_owned))
        .flat_map(|ports| {
            ports
                .split_whitespace()
                .map(|p| p.trim_end_matches("/tcp").parse::<u16>().unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn k_109_image_is_built_with_existing_features_including_redis() {
    let build = build_command();
    assert!(
        build.contains("-p authn-server") && build.contains("--locked"),
        "{build}"
    );
    let words: Vec<&str> = build.split_whitespace().collect();
    let features: Vec<&str> = words
        .windows(2)
        .filter(|w| w[0] == "--features")
        .flat_map(|w| w[1].split(','))
        .collect();
    assert!(features.contains(&"redis"), "{build}");
    assert!(!build.contains("--no-default-features"), "{build}");
    let known = server_features();
    for feature in features {
        assert!(
            known.iter().any(|k| k == feature),
            "unknown feature {feature}"
        );
    }
}

#[test]
fn k_109_metrics_listener_is_reachable_and_exposed() {
    let value = env_value("AUTHN__SERVER__METRICS_BIND_ADDR")
        .expect("the image sets the metrics listener explicitly");
    let addr: SocketAddr = value.parse().unwrap();
    assert!(
        addr.ip().is_unspecified(),
        "{addr}: loopback is unreachable outside the container"
    );
    let ports = exposed_ports();
    assert!(ports.contains(&addr.port()), "{ports:?}");
    // The public listener's default port is exposed as well.
    assert!(ports.contains(&8080), "{ports:?}");
    assert_ne!(addr.port(), 8080);
}
