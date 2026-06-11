//! The `ot-commissioner-rs` command-line REPL.
//!
//! This module reimplements the interactive command surface, prompt, colored
//! `[done]`/`[failed]` output, startup logo, and usage banner of the C++
//! `ot-commissioner` CLI on top of the pure-Rust [`crate::commissioner`] API.
//! It is only compiled with the `cli` feature and is driven by the
//! `ot-commissioner-rs` binary (`src/main.rs`).
//!
//! Commands that exercise the non-CCM commissioner protocol are fully wired to
//! the library. Commands outside that scope (CCM token flows, the persistent
//! network registry, mDNS discovery, and multi-network job execution) keep
//! their exact usage text but report `[failed]` with an explanatory message.

mod config;
mod console;
mod interpreter;
mod json;
mod value;

use std::path::Path;

use console::Color;
use interpreter::Interpreter;

/// The startup logo: the C++ CLI banner (font "Slant") re-rendered with the
/// text "OT-commissioner-rs CLI", with Ferris (from `ferris-says`) perched
/// under the "-rs". Printed in blue like the reference.
const LOGO: &str = concat!(
    r"   ____  ______                                   _           _                                          ________    ____",
    "\n",
    r"  / __ \/_  __/   _________  ____ ___  ____ ___  (_)_________(_)___  ____  ___  _____      __________   / ____/ /   /  _/",
    "\n",
    r" / / / / / /_____/ ___/ __ \/ __ `__ \/ __ `__ \/ / ___/ ___/ / __ \/ __ \/ _ \/ ___/_____/ ___/ ___/  / /   / /    / /",
    "\n",
    r"/ /_/ / / /_____/ /__/ /_/ / / / / / / / / / / / (__  |__  ) / /_/ / / / /  __/ /  /_____/ /  (__  )  / /___/ /____/ /",
    "\n",
    r"\____/ /_/      \___/\____/_/ /_/ /_/_/ /_/ /_/_/____/____/_/\____/_/ /_/\___/_/        /_/  /____/   \____/_____/___/",
    "\n",
    r"                                                                                         _~^~^~_",
    "\n",
    r"                                                                                     \) /  o o  \ (/",
    "\n",
    r"                                                                                       '_   -   _'",
    "\n",
    r"                                                                                       \ '-----' /",
    "\n",
);

/// Prints the startup logo in blue, matching the C++ CLI.
pub fn print_logo() {
    console::write(LOGO, Color::Blue);
}

/// Prints the crate version, matching `ot-commissioner -v`.
pub fn print_version() {
    console::write(crate::version(), Color::White);
}

/// Prints the usage banner for `program`, matching the C++ `PrintUsage`.
pub fn print_usage(program: &str) {
    let usage = format!(
        "usage: \n\
         help digest:\n    {program} -h|--help\n\
         version:\n    {program} -v|--version\n\
         common options\n    {program} [-r|--registry <registryFileName>] [-c|--config <configFileName>]\n\
         or\n    {program} [-r|--registry <registryFileName>] [configFileName]"
    );
    console::write(&usage, Color::White);
}

/// Loads the configuration (defaulting to non-CCM with an unset PSKc when no
/// file is given, as the C++ CLI does) and runs the REPL until `exit`/`quit`
/// or end-of-input. On a configuration-load failure it prints the C++-style
/// startup error and returns it.
pub async fn run(config_path: Option<&Path>) -> crate::Result<()> {
    let config = match config_path {
        Some(path) => match config::CliConfig::load(path) {
            Ok(config) => config,
            Err(err) => {
                console::write(
                    &format!("start OT-commissioner CLI failed: {err}"),
                    Color::Red,
                );
                return Err(err);
            }
        },
        None => config::CliConfig::default(),
    };

    let mut interpreter = Interpreter::new(config);
    while !interpreter.should_exit() {
        match console::read() {
            Some(line) => interpreter.evaluate_and_print(&line).await,
            None => break,
        }
    }
    Ok(())
}
