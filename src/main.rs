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

use std::path::PathBuf;
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

    let mut config_path: Option<PathBuf> = None;
    let mut positional: Option<PathBuf> = None;
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                cli::print_usage(&program);
                return ExitCode::SUCCESS;
            }
            "-v" | "--version" => {
                cli::print_version();
                return ExitCode::SUCCESS;
            }
            "-c" | "--config" => match rest.next() {
                Some(path) => config_path = Some(PathBuf::from(path)),
                None => {
                    cli::print_usage(&program);
                    return ExitCode::FAILURE;
                }
            },
            "-r" | "--registry" => {
                // The persistent network registry is out of scope for this
                // build; accept the flag and its argument for CLI parity.
                if rest.next().is_none() {
                    cli::print_usage(&program);
                    return ExitCode::FAILURE;
                }
            }
            other => {
                // The first non-option argument is treated as the config file,
                // matching the C++ `[configFileName]` positional form.
                if !other.starts_with('-') && positional.is_none() {
                    positional = Some(PathBuf::from(other));
                }
            }
        }
    }

    // An explicit `-c`/`--config` wins over the positional config file, exactly
    // as in the C++ entry point.
    let config_path = config_path.or(positional);

    cli::print_logo();
    match cli::run(config_path.as_deref()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
