//! Terminal trailer projection; the ordinary read completion owns its bounds.

use phantom::ResponseTrailers;
use serde::Serialize;
use serde_json::Value;

use crate::error::Failure;

#[derive(Serialize)]
struct Snapshot<'a> {
    state: &'static str,
    headers: Vec<Field<'a>>,
}

#[derive(Serialize)]
struct Field<'a> {
    name: &'a str,
    value: &'a [u8],
    sensitive: bool,
}

pub(super) fn snapshot(trailers: &ResponseTrailers) -> Result<Value, Failure> {
    let (state, headers) = match trailers {
        ResponseTrailers::Unavailable => ("unavailable", Vec::new()),
        ResponseTrailers::Complete(headers) => (
            "complete",
            headers
                .iter()
                .map(|field| Field {
                    name: field.name(),
                    value: field.value(),
                    sensitive: field.is_sensitive(),
                })
                .collect(),
        ),
        // EOF must never turn an unfinished or future state into empty success.
        _ => return Err(Failure::new("unsupported_response_trailers")),
    };
    // Global::finish applies the existing 256 KiB cap to this complete reply,
    // replacing an oversized projection with a correlated metadata_limit error.
    serde_json::to_value(Snapshot { state, headers }).map_err(|_| Failure::new("internal"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_projection_distinguishes_empty_completion_and_unavailable() -> Result<(), Failure> {
        assert_eq!(
            snapshot(&ResponseTrailers::Unavailable)?,
            serde_json::json!({
                "state": "unavailable", "headers": []
            })
        );
        assert_eq!(
            snapshot(&ResponseTrailers::Complete(Default::default()))?,
            serde_json::json!({
                "state": "complete", "headers": []
            })
        );
        assert_eq!(
            snapshot(&ResponseTrailers::Pending)
                .err()
                .map(|error| error.kind),
            Some("unsupported_response_trailers")
        );
        Ok(())
    }
}
