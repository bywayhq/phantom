use std::{error::Error, fmt};

use tokio::time::error::Elapsed;

#[derive(Debug)]
pub(crate) struct FixtureDeadline {
    message: &'static str,
    elapsed: Elapsed,
}

impl FixtureDeadline {
    pub(crate) fn new(message: &'static str, elapsed: Elapsed) -> Self {
        Self { message, elapsed }
    }
}

impl fmt::Display for FixtureDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for FixtureDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.elapsed)
    }
}
