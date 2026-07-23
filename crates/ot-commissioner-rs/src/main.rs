//! The `ot-commissioner-rs` interactive CLI binary: a faithful reimplementation
//! of the C++ `ot-commissioner` command-line REPL on top of the pure-Rust
//! commissioner library. The full command surface lives in
//! [`ot_commissioner_rs::cli`].
//!
//! ```text
//! ot-commissioner-rs -h|--help
//! ot-commissioner-rs -v|--version
//! ot-commissioner-rs [-r|--registry <registryFileName>] [-c|--config <configFileName>]
//! ot-commissioner-rs [-r|--registry <registryFileName>] [configFileName]
//! ```

use std::process::ExitCode;

use ot_commissioner_rs::cli;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .map(String::as_str)
        .unwrap_or("ot-commissioner-rs")
        .to_string();

    match cli::parse_invocation(args.get(1..).unwrap_or(&[])) {
        cli::CliInvocation::Usage => {
            cli::print_usage(&program);
            ExitCode::SUCCESS
        }
        cli::CliInvocation::Version => {
            cli::print_version();
            ExitCode::SUCCESS
        }
        cli::CliInvocation::UsageError => {
            cli::print_usage(&program);
            ExitCode::FAILURE
        }
        cli::CliInvocation::Run(config_path) => {
            cli::print_logo();
            match cli::run(config_path.as_deref()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
    }
}
