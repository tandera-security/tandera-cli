//! Thin binary entry point — argv parsing and process exit code only. All
//! real logic lives in the library crate (`tandera_cli`) so it's testable
//! without spawning a subprocess.

use std::process::ExitCode;

use clap::Parser;
use tandera_cli::commands::{run, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => {
            let code: u8 = code.try_into().unwrap_or(1);
            ExitCode::from(code)
        }
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
