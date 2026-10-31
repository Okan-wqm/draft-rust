//! `rust-authentication` binary entry point.

use std::process::ExitCode;

use authn_server::cli::{Cli, Outcome, run};
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            report(&format!("cannot start async runtime: {err}"));
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(Outcome::Done) => ExitCode::SUCCESS,
        Ok(Outcome::Message(message)) => {
            #[allow(clippy::print_stdout)] // CLI output, contains no secrets
            {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            report(&format!("error: {err}"));
            err.exit_code()
        }
    }
}

/// Prints to stderr (used before / outside of the tracing subscriber).
#[allow(clippy::print_stderr)] // CLI error output; ServerError never contains secrets
fn report(message: &str) {
    eprintln!("{message}");
}
