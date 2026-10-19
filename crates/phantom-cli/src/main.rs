//! Command-line requests using Phantom's public library.

mod arguments;
mod diagnostics;
mod profiles;
mod request;

use std::{fmt, process::ExitCode, time::Duration};

type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug)]
struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn operation(error: impl fmt::Display) -> Self {
        Self {
            code: 1,
            message: error.to_string(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }

    fn interrupted() -> Self {
        Self {
            code: 130,
            message: "request interrupted".into(),
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::operation(error)
    }
}

fn main() -> ExitCode {
    let arguments = arguments::command().get_matches();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("phantom: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        match arguments.subcommand() {
            Some(("request", arguments)) => request::run(arguments).await,
            Some(("profiles", arguments)) => profiles::run(arguments).await,
            _ => Err(CliError::invalid("expected request or profiles")),
        }
    });
    // Files and terminal I/O can use blocking workers. They must not make
    // shutdown wait forever after the request future has been cancelled.
    runtime.shutdown_timeout(Duration::from_millis(500));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("phantom: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}
