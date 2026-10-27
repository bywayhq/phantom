//! Terminal trailer projection; the ordinary read completion owns its bounds.

use phantom::ResponseTrailers;
use serde::Serialize;

use crate::{client::Header, error::Failure};

#[derive(Serialize)]
pub(crate) struct Snapshot {
    pub(crate) state: &'static str,
    pub(crate) headers: Vec<Header>,
}

pub(super) fn snapshot(trailers: &ResponseTrailers) -> Result<Snapshot, Failure> {
    let (state, headers) = match trailers {
        ResponseTrailers::Unavailable => ("unavailable", Vec::new()),
        ResponseTrailers::Complete(headers) => (
            "complete",
            headers
                .iter()
                .map(|field| Header {
                    name: field.name().to_owned(),
                    value: field.value().to_vec(),
                    sensitive: field.is_sensitive(),
                })
                .collect(),
        ),
        _ => return Err(Failure::new("unsupported_response_trailers")),
    };
    Ok(Snapshot { state, headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_projection_distinguishes_empty_completion_and_unavailable() -> Result<(), Failure> {
        assert_eq!(
            serde_json::to_value(snapshot(&ResponseTrailers::Unavailable)?)
                .map_err(|_| Failure::new("internal"))?,
            serde_json::json!({
                "state": "unavailable", "headers": []
            })
        );
        assert_eq!(
            serde_json::to_value(snapshot(&ResponseTrailers::Complete(Default::default()))?)
                .map_err(|_| Failure::new("internal"))?,
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
