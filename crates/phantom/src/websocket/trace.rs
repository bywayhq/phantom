use tracing::{Span, field};

use super::WebSocketErrorKind;

pub(super) struct OperationOutcome {
    span: Span,
    recorded: bool,
}

impl OperationOutcome {
    pub(super) fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    pub(super) fn finish(mut self, outcome: &'static str, error: Option<WebSocketErrorKind>) {
        self.span.record("outcome", outcome);
        if let Some(error) = error {
            self.span.record("error_kind", field::debug(error));
        }
        self.recorded = true;
    }
}

impl Drop for OperationOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record(
                "outcome",
                if std::thread::panicking() {
                    "panicked"
                } else {
                    "cancelled"
                },
            );
        }
    }
}
