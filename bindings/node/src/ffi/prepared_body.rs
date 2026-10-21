//! Bounded form and multipart encoding into reusable native body owners.

use std::fmt;

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, BigInt, Buffer},
};
use napi_derive::napi;

use super::buffer::copy_buffer;
use crate::error::failure;

/// One ordered form pair, copied before native encoding.
#[napi(object)]
pub struct FormField {
    /// UTF-8 name, including an empty or duplicate name.
    pub name: String,
    /// UTF-8 value, without host-side coercion.
    pub value: String,
}

/// One ordered multipart part with exactly one text or byte payload.
#[napi(object)]
pub struct MultipartField {
    /// Exact UTF-8 name.
    pub name: String,
    /// Text receives the core's CRLF normalization.
    pub text: Option<String>,
    /// Bytes remain byte-exact.
    pub bytes: Option<Buffer>,
    /// Optional exact filename, not a filesystem path to read.
    pub filename: Option<String>,
    /// Optional token/token media type.
    pub content_type: Option<String>,
}

impl fmt::Debug for FormField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FormField").finish_non_exhaustive()
    }
}

impl fmt::Debug for MultipartField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultipartField")
            .finish_non_exhaustive()
    }
}

/// Replayable body and content-type policy owned entirely by the native core.
#[derive(Debug)]
#[napi]
pub struct NativePreparedBody {
    pub(super) body: phantom::PreparedRequestBody,
}

#[napi]
impl NativePreparedBody {
    /// Exact encoded media type; never inserted by the facade.
    #[napi(getter)]
    #[must_use]
    pub fn content_type(&self) -> String {
        self.body.content_type().to_owned()
    }
    /// Exact encoded length, without JavaScript number rounding.
    #[napi(getter)]
    #[must_use]
    pub fn byte_length(&self) -> BigInt {
        BigInt {
            sign_bit: false,
            words: vec![self.body.bytes().len() as u64],
        }
    }
}

pub(super) fn prepared_maximum(value: BigInt) -> Result<usize> {
    match (value.sign_bit, value.words.as_slice()) {
        (false, []) => Ok(0),
        (false, [value]) => usize::try_from(*value)
            .map_err(|_| failure("InvalidArgument", "maximumBytes must fit usize")),
        _ => Err(failure("InvalidArgument", "maximumBytes must fit usize")),
    }
}

pub(super) fn prepared_charge(remaining: &mut usize, count: usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(count)
        .ok_or_else(|| crate::prepared_body::failure("too_large"))?;
    Ok(())
}

/// Encodes form inputs off the JavaScript thread, after bounded input ownership.
#[napi]
pub fn prepared_form(
    env: Env,
    pairs: Vec<FormField>,
    maximum: BigInt,
) -> Result<AsyncBlock<NativePreparedBody>> {
    let maximum = prepared_maximum(maximum)?;
    let mut remaining = maximum;
    for pair in &pairs {
        prepared_charge(&mut remaining, pair.name.len())?;
        prepared_charge(&mut remaining, pair.value.len())?;
        prepared_charge(&mut remaining, 1)?;
    }
    let pairs = pairs
        .into_iter()
        .map(|pair| (pair.name, pair.value))
        .collect();
    AsyncBlockBuilder::new(async move {
        crate::prepared_body::form(pairs, maximum)
            .await
            .map(|body| NativePreparedBody { body })
    })
    .build(&env)
}

/// Copies ordinary bytes on their Env, then runs only core multipart encoding.
#[napi]
pub fn prepared_multipart(
    env: Env,
    boundary: String,
    fields: Vec<MultipartField>,
    maximum: BigInt,
) -> Result<AsyncBlock<NativePreparedBody>> {
    use crate::prepared_body::{Part, PartData, core_error};
    let maximum = prepared_maximum(maximum)?;
    if fields.len() > 1024 {
        return Err(crate::prepared_body::failure("too_many_parts"));
    }
    phantom::PreparedRequestBody::multipart(&boundary, [], usize::MAX).map_err(core_error)?;
    let mut remaining = maximum;
    prepared_charge(&mut remaining, boundary.len())?;
    // Validate every metadata field before copying any byte payload.
    for field in &fields {
        if field.text.is_some() == field.bytes.is_some() {
            return Err(failure(
                "InvalidArgument",
                "multipart part requires exactly one text or bytes field",
            ));
        }
        let mut part = phantom::MultipartPart::text(&field.name, "").map_err(core_error)?;
        prepared_charge(&mut remaining, field.name.len())?;
        if let Some(filename) = &field.filename {
            part = part.with_filename(filename).map_err(core_error)?;
            prepared_charge(&mut remaining, filename.len())?;
        }
        if let Some(content_type) = &field.content_type {
            part.with_content_type(content_type).map_err(core_error)?;
            prepared_charge(&mut remaining, content_type.len())?;
        }
        if let Some(text) = &field.text {
            prepared_charge(&mut remaining, text.len())?;
        }
    }
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(fields.len())
        .map_err(|_| crate::prepared_body::failure("allocation"))?;
    for field in fields {
        let data = match (field.text, field.bytes) {
            (Some(text), None) => PartData::Text(text),
            (None, Some(bytes)) => {
                let bytes = copy_buffer(&env, bytes, remaining).map_err(|error| {
                    if error.reason.starts_with("PHANTOM:InputLimit:") {
                        crate::prepared_body::failure("too_large")
                    } else if error.reason.starts_with("PHANTOM:Allocation:") {
                        crate::prepared_body::failure("allocation")
                    } else {
                        error
                    }
                })?;
                remaining -= bytes.len();
                PartData::Bytes(bytes)
            }
            _ => {
                return Err(failure(
                    "InvalidArgument",
                    "multipart part requires exactly one payload",
                ));
            }
        };
        parts.push(Part {
            name: field.name,
            data,
            filename: field.filename,
            content_type: field.content_type,
        });
    }
    AsyncBlockBuilder::new(async move {
        crate::prepared_body::multipart(boundary, parts, maximum)
            .await
            .map(|body| NativePreparedBody { body })
    })
    .build(&env)
}
