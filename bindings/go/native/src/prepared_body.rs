//! Replayable encodings, prepared outside the HTTP runtime's state lock.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use phantom::{MultipartPart, PreparedBodyError, PreparedBodyErrorKind, PreparedRequestBody};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{error::Failure, operations::MAX_UPLOAD};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Span {
    offset: usize,
    length: usize,
}

impl Span {
    fn bytes<'a>(&self, input: &'a [u8]) -> Result<&'a [u8], Failure> {
        let end = self
            .offset
            .checked_add(self.length)
            .ok_or_else(|| Failure::new("invalid_prepared_body"))?;
        input
            .get(self.offset..end)
            .ok_or_else(|| Failure::new("invalid_prepared_body"))
    }

    fn text<'a>(&self, input: &'a [u8]) -> Result<&'a str, Failure> {
        std::str::from_utf8(self.bytes(input)?).map_err(|_| Failure::new("invalid_prepared_body"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Field {
    name: Span,
    value: Span,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PartKind {
    Text,
    Bytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    kind: PartKind,
    name: String,
    data: Span,
    filename: Option<String>,
    content_type: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Encoding {
    Form { fields: Vec<Field> },
    Multipart { boundary: String, parts: Vec<Part> },
}

#[derive(Default)]
struct Registry {
    last: u64,
    bodies: HashMap<u64, PreparedRequestBody>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

pub(super) fn prepare(encoding: Encoding, input: &[u8], maximum: usize) -> Result<Value, Failure> {
    // Buffered Go bodies retain the existing 8 MiB per-body boundary.
    let maximum = maximum.min(MAX_UPLOAD);
    let body = match encoding {
        Encoding::Form { fields } => {
            let fields = fields
                .iter()
                .map(|field| Ok((field.name.text(input)?, field.value.text(input)?)))
                .collect::<Result<Vec<_>, Failure>>()?;
            PreparedRequestBody::form(fields, maximum).map_err(failure)?
        }
        Encoding::Multipart { boundary, parts } => {
            if parts.len() > 1024 {
                return Err(Failure::new("prepared_body_too_many_parts"));
            }
            let parts = parts
                .iter()
                .map(|part| {
                    let mut field = match part.kind {
                        PartKind::Text => MultipartPart::text(&part.name, part.data.text(input)?),
                        PartKind::Bytes => {
                            MultipartPart::bytes(&part.name, part.data.bytes(input)?)
                        }
                    }
                    .map_err(failure)?;
                    if let Some(filename) = &part.filename {
                        field = field.with_filename(filename).map_err(failure)?;
                    }
                    if let Some(content_type) = &part.content_type {
                        field = field.with_content_type(content_type).map_err(failure)?;
                    }
                    Ok(field)
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            PreparedRequestBody::multipart(&boundary, parts, maximum).map_err(failure)?
        }
    };
    let mut registry = registry().lock().map_err(|_| Failure::new("internal"))?;
    if registry.bodies.len() >= 64 {
        return Err(Failure::new("capacity"));
    }
    let id = registry
        .last
        .checked_add(1)
        .ok_or_else(|| Failure::new("capacity"))?;
    registry.last = id;
    let value =
        json!({"id": id, "length": body.bytes().len(), "content_type": body.content_type()});
    registry.bodies.insert(id, body);
    Ok(value)
}

pub(super) fn get(id: u64) -> Result<PreparedRequestBody, Failure> {
    registry()
        .lock()
        .map_err(|_| Failure::new("internal"))?
        .bodies
        .get(&id)
        .cloned()
        .ok_or_else(|| Failure::new("invalid_handle"))
}

pub(super) fn release(id: u64) -> Result<Value, Failure> {
    registry()
        .lock()
        .map_err(|_| Failure::new("internal"))?
        .bodies
        .remove(&id);
    Ok(json!({}))
}

fn failure(error: PreparedBodyError) -> Failure {
    Failure::new(match error.kind() {
        PreparedBodyErrorKind::TooLarge => "prepared_body_too_large",
        PreparedBodyErrorKind::Allocation => "prepared_body_allocation",
        PreparedBodyErrorKind::InvalidName => "prepared_body_invalid_name",
        PreparedBodyErrorKind::InvalidFilename => "prepared_body_invalid_filename",
        PreparedBodyErrorKind::InvalidContentType => "prepared_body_invalid_content_type",
        PreparedBodyErrorKind::InvalidBoundary => "prepared_body_invalid_boundary",
        PreparedBodyErrorKind::BoundaryCollision => "prepared_body_boundary_collision",
        PreparedBodyErrorKind::TooManyParts => "prepared_body_too_many_parts",
        _ => "prepared_body",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_owner_keeps_independent_encoded_bytes_after_release()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoding: Encoding = serde_json::from_value(json!({
            "encoding": "form", "fields": [
                {"name": {"offset": 0, "length": 1}, "value": {"offset": 1, "length": 3}},
                {"name": {"offset": 0, "length": 1}, "value": {"offset": 4, "length": 0}}
            ]
        }))?;
        let value = prepare(encoding, b"qa +", 20).map_err(|error| error.kind)?;
        let id = value["id"].as_u64().ok_or("missing owner")?;
        let body = get(id).map_err(|error| error.kind)?;
        release(id).map_err(|error| error.kind)?;
        assert_eq!(body.bytes().as_ref(), b"q=a+%2B&q=");
        assert_eq!(
            body.content_type(),
            "application/x-www-form-urlencoded;charset=UTF-8"
        );
        assert!(get(id).is_err());
        Ok(())
    }

    #[test]
    fn malformed_ranges_and_utf8_fail_without_an_owner() {
        for span in [
            Span {
                offset: usize::MAX,
                length: 1,
            },
            Span {
                offset: 1,
                length: 1,
            },
            Span {
                offset: 0,
                length: 1,
            },
        ] {
            assert!(span.text(b"\xff").is_err());
        }
    }
}
