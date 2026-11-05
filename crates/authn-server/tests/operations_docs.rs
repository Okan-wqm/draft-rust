#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // integration-test crate
//! K-75 (DOC, OPS-01): the operations guide `docs/operations/admin-recovery.md`
//! must match the code. Every documented `rust-authentication …` command
//! line is parsed by the real CLI parser, every documented `--flag` exists
//! and every documented `/v1/…` path is in the OpenAPI document.

use std::collections::BTreeSet;
use std::path::PathBuf;

use authn_server::cli::Cli;
use clap::{CommandFactory, Parser};

const GUIDE: &str = "docs/operations/admin-recovery.md";

fn guide() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(GUIDE);
    std::fs::read_to_string(path).unwrap()
}

/// Inline code spans (`` `…` ``) outside fenced blocks, and every line of
/// fenced blocks.
fn code_fragments(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            out.push(line.trim().to_owned());
            continue;
        }
        let mut parts = line.split('`');
        parts.next();
        while let Some(span) = parts.next() {
            out.push(span.to_owned());
            parts.next();
        }
    }
    out
}

/// Minimal POSIX-like word splitting with double quotes (enough for the
/// documented commands; anything fancier fails the parse and the test).
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quotes in `{line}`");
    if started {
        words.push(current);
    }
    words
}

fn documented_commands(text: &str) -> Vec<String> {
    code_fragments(text)
        .into_iter()
        .filter(|f| f.starts_with("rust-authentication "))
        .collect()
}

/// K-75: every documented command line parses with the real CLI, and the
/// guide covers every admin recovery command.
#[test]
fn ops_01_k75_documented_cli_commands_parse() {
    let text = guide();
    let commands = documented_commands(&text);
    let mut used = BTreeSet::new();
    for line in &commands {
        let words = shell_words(line);
        let cli = Cli::try_parse_from(&words)
            .unwrap_or_else(|e| panic!("{GUIDE}: `{line}` does not parse:\n{e}"));
        used.insert(cli.command.name());
    }
    for required in [
        "create-admin",
        "admin-enrollment-link",
        "suspend-admin",
        "unsuspend-admin",
        "revoke-admin-sessions",
        "grant-admin",
        "revoke-admin",
        "rotate-signing-key",
        "verify-audit-chain",
        "check-config",
    ] {
        assert!(
            used.contains(required),
            "{GUIDE} shows no runnable `{required}` example (have {used:?})"
        );
    }
}

/// K-75: every backticked subcommand name in a table row and every
/// backticked `--flag` of the guide exists in the CLI.
#[test]
fn ops_01_k75_documented_subcommands_and_flags_exist() {
    let cli = Cli::command();
    let subcommands: BTreeSet<String> = cli
        .get_subcommands()
        .map(|c| c.get_name().to_owned())
        .collect();
    let mut flags: BTreeSet<String> = cli
        .get_arguments()
        .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
        .collect();
    for sub in cli.get_subcommands() {
        flags.extend(
            sub.get_arguments()
                .filter_map(|a| a.get_long().map(|l| format!("--{l}"))),
        );
    }
    let text = guide();
    for fragment in code_fragments(&text) {
        for word in fragment.split_whitespace() {
            if let Some(flag) = word.strip_prefix("--") {
                let flag: String = flag
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                let flag = format!("--{flag}");
                assert!(flags.contains(&flag), "{GUIDE}: unknown flag `{flag}`");
            }
        }
    }
    // The first cell of each CLI table row names a subcommand.
    let mut rows = 0;
    for line in text.lines() {
        let Some(cell) = line.strip_prefix("| `") else {
            continue;
        };
        let name: String = cell.chars().take_while(|c| *c != '`').collect();
        let looks_like_command = !name.is_empty()
            && name.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            && name.contains('-');
        if looks_like_command {
            assert!(
                subcommands.contains(&name),
                "{GUIDE}: `{name}` is not a subcommand"
            );
            rows += 1;
        }
    }
    assert!(rows >= 10, "the CLI table was not found ({rows} rows)");
}

/// K-75: every documented API path exists in the OpenAPI document (path
/// parameters must use the same names).
#[test]
fn adm_01_k75_documented_admin_paths_exist() {
    let document = authn_server::openapi::document();
    let paths: BTreeSet<String> = document["paths"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let text = guide();
    let mut checked = 0;
    for fragment in code_fragments(&text) {
        for tail in fragment.split("/v1/").skip(1) {
            let rest: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || "/-_{}".contains(*c))
                .collect();
            let path = format!("/v1/{rest}");
            assert!(
                paths.contains(&path),
                "{GUIDE}: `{path}` is not an API path"
            );
            checked += 1;
        }
    }
    assert!(checked >= 15, "only {checked} paths found in {GUIDE}");
}

/// K-75 audit: a documented `METHOD /v1/…` pair exists with that method,
/// every documented `?query=` parameter is a parameter of that operation,
/// and the exit-code table matches the CLI's `ServerError::exit_code`.
#[test]
fn ops_01_k75_documented_methods_and_exit_codes_match() {
    let document = authn_server::openapi::document();
    let text = guide();
    let mut checked = 0;
    for fragment in code_fragments(&text) {
        let words: Vec<&str> = fragment.split_whitespace().collect();
        for pair in words.windows(2) {
            let method = pair[0];
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method) {
                continue;
            }
            let Some(target) = pair[1].strip_prefix("/v1/") else {
                continue;
            };
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let path = format!("/v1/{path}");
            let operation = &document["paths"][&path][method.to_ascii_lowercase()];
            assert!(
                operation.is_object(),
                "{GUIDE}: `{method} {path}` is not an API operation"
            );
            for param in query.split('&').filter(|q| !q.is_empty()) {
                let name = param.split('=').next().unwrap();
                let known = operation["parameters"]
                    .as_array()
                    .is_some_and(|ps| ps.iter().any(|p| p["name"] == name && p["in"] == "query"));
                assert!(
                    known,
                    "{GUIDE}: `{method} {path}` has no query parameter `{name}`"
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 15,
        "only {checked} method/path pairs found in {GUIDE}"
    );

    // Exit-code table: `| <code> | … |` rows after the "Çıkış kodu" header.
    let documented: BTreeSet<u8> = text
        .lines()
        .skip_while(|l| !l.starts_with("| Çıkış kodu"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(|l| {
            l.trim_start_matches('|')
                .split('|')
                .next()
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        })
        .collect();
    use authn_server::error::ServerError;
    let code = |e: ServerError| format!("{:?}", e.exit_code());
    let err = || authn_core::error::AuthError::internal("x");
    assert_eq!(documented, BTreeSet::from([0, 1, 65, 69, 78]), "{GUIDE}");
    assert_eq!(
        code(ServerError::Input(String::new())),
        format!("{:?}", std::process::ExitCode::from(65))
    );
    assert_eq!(
        code(ServerError::Startup(err())),
        format!("{:?}", std::process::ExitCode::from(69))
    );
    assert_eq!(
        code(ServerError::InvalidSettings(err())),
        format!("{:?}", std::process::ExitCode::from(78))
    );
    assert_eq!(
        code(ServerError::Integrity(String::new())),
        format!("{:?}", std::process::ExitCode::from(1))
    );
}
