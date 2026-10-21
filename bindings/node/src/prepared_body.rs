//! Core request-body encoding on owned inputs, away from the JavaScript thread.

use napi::{Error, Result, Status};
use phantom::{MultipartPart, PreparedBodyError, PreparedBodyErrorKind, PreparedRequestBody};

pub(crate) fn failure(kind: &str) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("PHANTOM_PREPARED:{kind}:request body preparation failed"),
    )
}

pub(crate) fn core_error(error: PreparedBodyError) -> Error {
    let kind = match error.kind() {
        PreparedBodyErrorKind::TooLarge => "too_large",
        PreparedBodyErrorKind::Allocation => "allocation",
        PreparedBodyErrorKind::InvalidName => "invalid_name",
        PreparedBodyErrorKind::InvalidFilename => "invalid_filename",
        PreparedBodyErrorKind::InvalidContentType => "invalid_content_type",
        PreparedBodyErrorKind::InvalidBoundary => "invalid_boundary",
        PreparedBodyErrorKind::BoundaryCollision => "boundary_collision",
        PreparedBodyErrorKind::TooManyParts => "too_many_parts",
        _ => "unknown",
    };
    failure(kind)
}

pub(crate) enum PartData {
    Text(String),
    Bytes(Vec<u8>),
}

pub(crate) struct Part {
    pub(crate) name: String,
    pub(crate) data: PartData,
    pub(crate) filename: Option<String>,
    pub(crate) content_type: Option<String>,
}

pub(crate) async fn form(
    pairs: Vec<(String, String)>,
    maximum: usize,
) -> Result<PreparedRequestBody> {
    tokio::task::spawn_blocking(move || {
        PreparedRequestBody::form(pairs, maximum).map_err(core_error)
    })
    .await
    .map_err(|_| failure("backend"))?
}

pub(crate) async fn multipart(
    boundary: String,
    parts: Vec<Part>,
    maximum: usize,
) -> Result<PreparedRequestBody> {
    // Only native-owned input crosses this boundary. Dropping the awaiting
    // future does not preempt CPU work; an unpublished result is dropped.
    tokio::task::spawn_blocking(move || {
        let parts = parts
            .iter()
            .map(|part| {
                let mut field = match &part.data {
                    PartData::Text(value) => MultipartPart::text(&part.name, value),
                    PartData::Bytes(value) => MultipartPart::bytes(&part.name, value),
                }?;
                if let Some(filename) = &part.filename {
                    field = field.with_filename(filename)?;
                }
                if let Some(content_type) = &part.content_type {
                    field = field.with_content_type(content_type)?;
                }
                Ok(field)
            })
            .collect::<std::result::Result<Vec<_>, PreparedBodyError>>()
            .map_err(core_error)?;
        PreparedRequestBody::multipart(&boundary, parts, maximum).map_err(core_error)
    })
    .await
    .map_err(|_| failure("backend"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_encoders_preserve_owned_data_and_enforce_encoded_limits() -> Result<()> {
        let form = form(vec![("x".into(), "+".into()), ("x".into(), " ".into())], 9).await?;
        assert_eq!(form.bytes().as_ref(), b"x=%2B&x=+");
        let Some(error) = super::form(vec![("private".into(), "value".into())], 1)
            .await
            .err()
        else {
            return Err(failure("test_expected_limit"));
        };
        assert!(error.reason.starts_with("PHANTOM_PREPARED:too_large:"));
        let body = multipart(
            "b".into(),
            vec![Part {
                name: "x".into(),
                data: PartData::Bytes(vec![0, 255]),
                filename: None,
                content_type: None,
            }],
            256,
        )
        .await?;
        assert!(body.bytes().windows(2).any(|window| window == [0, 255]));
        assert_eq!(body.content_type(), "multipart/form-data; boundary=b");
        assert!(
            super::form(Vec::new(), usize::MAX)
                .await?
                .bytes()
                .is_empty()
        );
        Ok(())
    }
}
