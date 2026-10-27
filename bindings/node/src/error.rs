//! Redacted failures for the JavaScript adapter.

use napi::{Error, Status};

pub(crate) fn failure(code: &str, message: &str) -> Error {
    // The JS facade turns this private transport prefix into PhantomError.code.
    Error::new(Status::GenericFailure, format!("PHANTOM:{code}:{message}"))
}

pub(crate) fn request(error: phantom::RequestError) -> Error {
    request_ref(&error)
}

pub(crate) fn request_ref(error: &phantom::RequestError) -> Error {
    if let Some(error) = crate::multipart::request_error(error) {
        return error;
    }
    let protocol = match error.protocol() {
        Some(phantom::HttpProtocol::Http1) => "http1",
        Some(phantom::HttpProtocol::Http2) => "http2",
        Some(phantom::HttpProtocol::Http3) => "http3",
        _ => "",
    };
    let phase = match error.timeout_phase() {
        Some(phantom::TimeoutPhase::PoolAdmission) => "poolAdmission",
        Some(phantom::TimeoutPhase::Connect) => "connect",
        Some(phantom::TimeoutPhase::ResponseHead) => "responseHead",
        Some(phantom::TimeoutPhase::ReadIdle) => "readIdle",
        Some(phantom::TimeoutPhase::Total) => "total",
        Some(phantom::TimeoutPhase::WebSocketHandshake) => "webSocketHandshake",
        _ => "",
    };
    let details = connect_io_details(error.kind(), error).unwrap_or_default();
    Error::new(
        Status::GenericFailure,
        format!(
            "PHANTOM_REQUEST:{:?}:{protocol}:{phase}:{error}{details}",
            error.kind()
        ),
    )
}

pub(crate) fn total_timeout() -> Error {
    Error::new(
        Status::GenericFailure,
        "PHANTOM_REQUEST:Timeout::total:request deadline expired",
    )
}

// Error displays can contain caller input. Only copy the closed I/O category and
// numeric OS code, and bound traversal even for a cyclic third-party source.
fn connect_io_details(
    kind: phantom::RequestErrorKind,
    error: &(dyn std::error::Error + 'static),
) -> Option<String> {
    if kind != phantom::RequestErrorKind::Connect {
        return None;
    }

    let mut source = Some(error);
    let mut first_io_kind = None;
    for _ in 0..16 {
        let Some(error) = source else {
            break;
        };

        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            let io_kind = *first_io_kind.get_or_insert(error.kind());
            if let Some(code) = error.raw_os_error() {
                return Some(format!(" (I/O: {io_kind}, os error {code})"));
            }

            source = match error.get_ref() {
                Some(inner) => Some(inner),
                None => std::error::Error::source(error),
            };
        } else {
            source = error.source();
        }
    }
    first_io_kind.map(|kind| format!(" (I/O: {kind})"))
}

#[cfg(test)]
mod tests {
    use std::{error::Error as StdError, fmt, io};

    use super::*;

    #[derive(Debug)]
    struct PrivateError(Option<Box<dyn StdError>>);

    impl fmt::Display for PrivateError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("https://user:secret@example.test/private")
        }
    }

    impl StdError for PrivateError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.0.as_deref()
        }
    }

    #[test]
    fn connect_details_preserve_os_code_without_source_text() {
        let error = io::Error::from_raw_os_error(10013);
        let expected = format!(" (I/O: {}, os error 10013)", error.kind());
        let source = PrivateError(Some(Box::new(error)));
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &source),
            Some(expected)
        );
    }

    #[test]
    fn nested_io_errors_keep_outer_kind_and_inner_os_code() {
        let source = io::Error::other(io::Error::from_raw_os_error(10013));
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &source),
            Some(" (I/O: other error, os error 10013)".into())
        );
    }

    #[test]
    fn wrapped_io_errors_keep_nested_os_code_without_source_text() {
        let source = PrivateError(Some(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            io::Error::from_raw_os_error(10013),
        ))));
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &source),
            Some(" (I/O: permission denied, os error 10013)".into())
        );
    }

    #[test]
    fn custom_io_details_preserve_kind_without_private_message() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "password=private");
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &error),
            Some(" (I/O: permission denied)".into())
        );
    }

    #[test]
    fn absent_io_and_non_connect_errors_add_no_details() {
        let error = PrivateError(None);
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &error),
            None
        );
        let error = io::Error::from_raw_os_error(10013);
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Timeout, &error),
            None
        );
    }

    #[test]
    fn cyclic_sources_stop_without_formatting_the_source() {
        #[derive(Debug)]
        struct Cycle;
        impl fmt::Display for Cycle {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("source display must not be called")
            }
        }
        impl StdError for Cycle {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(self)
            }
        }
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &Cycle),
            None
        );

        let error = io::Error::new(io::ErrorKind::PermissionDenied, Cycle);
        assert_eq!(
            connect_io_details(phantom::RequestErrorKind::Connect, &error),
            Some(" (I/O: permission denied)".into())
        );
    }
}
