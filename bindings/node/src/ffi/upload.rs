//! One-shot upload credits, multipart inputs and producer admission custody.

use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
};

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, BigInt, Buffer},
};
use napi_derive::napi;

use super::{
    buffer::{buffer_info, copy_buffer, copy_buffer_info},
    options::FileUpload,
    prepared_body::{prepared_charge, prepared_maximum},
};
use crate::{error::failure, request::MAXIMUM_HEADER_BYTES, response::Exchange};

/// Private owned multipart input. Sources themselves never cross Node-API.
#[napi(object)]
pub struct StreamingMultipartField {
    /// Exact ordered field name.
    pub name: String,
    /// Buffered normalized text.
    pub text: Option<String>,
    /// Buffered exact bytes.
    pub bytes: Option<Buffer>,
    /// A foreign source selected by its index.
    pub stream: Option<bool>,
    /// Lazily opened native file.
    pub file: Option<FileUpload>,
    /// Exact filename metadata.
    pub filename: Option<String>,
    /// Exact media type.
    pub content_type: Option<String>,
}

impl fmt::Debug for StreamingMultipartField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamingMultipartField { inputs redacted }")
    }
}

/// Private one-shot upload bridge. Every write copies on the owning Env.
#[derive(Debug)]
#[napi]
pub struct NativeUpload {
    pub(super) state: Arc<crate::upload::Upload>,
    pub(super) owner: Mutex<Option<Arc<Exchange>>>,
}

#[napi]
impl NativeUpload {
    /// Creates a source with an optional exact length.
    #[napi(constructor)]
    pub fn new(length: Option<BigInt>) -> Result<Self> {
        let length = length
            .map(|value| match (value.sign_bit, value.words.as_slice()) {
                (false, [value]) => Ok(*value),
                _ => Err(failure("InvalidArgument", "bodyLength must fit u64")),
            })
            .transpose()?;
        Ok(Self {
            state: crate::upload::Upload::new(length),
            owner: Mutex::new(None),
        })
    }
    /// Copies bounded payloads after validating every part and core metadata.
    #[napi]
    pub fn configure_multipart(
        &self,
        env: Env,
        boundary: String,
        mut fields: Vec<StreamingMultipartField>,
        maximum: BigInt,
    ) -> Result<()> {
        use crate::{
            multipart::{Data, Part},
            prepared_body::core_error,
        };
        let maximum = prepared_maximum(maximum)?;
        if self.state.multipart().is_some() || fields.len() > 1024 {
            return Err(failure(
                "InvalidArgument",
                "multipart requires at most 1024 parts and one configuration",
            ));
        }
        let mut metadata_remaining = MAXIMUM_HEADER_BYTES;
        let mut remaining = maximum;
        let mut validation = Vec::with_capacity(fields.len());
        let mut buffers = Vec::with_capacity(fields.len());
        // No byte input is copied until the complete metadata shape passes.
        for field in &mut fields {
            if usize::from(field.text.is_some())
                + usize::from(field.bytes.is_some())
                + usize::from(field.stream == Some(true))
                + usize::from(field.file.is_some())
                != 1
                || field.stream == Some(false)
            {
                return Err(failure(
                    "InvalidArgument",
                    "multipart part requires one payload",
                ));
            }
            let mut part = if field.text.is_some() {
                phantom::StreamingMultipartPart::text(&field.name, "", maximum)
            } else {
                phantom::StreamingMultipartPart::bytes(&field.name, bytes::Bytes::new())
            }
            .map_err(core_error)?;
            let mut charge = |count| -> Result<()> {
                metadata_remaining = metadata_remaining.checked_sub(count).ok_or_else(|| {
                    failure("InputLimit", "multipart metadata exceeds 65536 bytes")
                })?;
                Ok(())
            };
            charge(field.name.len())?;
            if let Some(value) = &field.filename {
                charge(value.len())?;
                part = part.with_filename(value).map_err(core_error)?;
            }
            if let Some(value) = &field.content_type {
                charge(value.len())?;
                part = part.with_content_type(value).map_err(core_error)?;
            }
            if let Some(file) = &field.file {
                if file.path.is_empty() || file.path.len() > 4096 {
                    return Err(failure(
                        "InputLimit",
                        "multipart path must contain 1..4096 UTF-8 bytes",
                    ));
                }
                charge(file.path.len())?;
            }
            if let Some(text) = &field.text {
                prepared_charge(&mut remaining, text.len())?;
            }
            // Env-local handles root backing storage throughout this synchronous
            // method, as in certificate parsing. No JS runs between validation
            // and copying all extents.
            let info = field
                .bytes
                .take()
                .map(|value| buffer_info(&env, value))
                .transpose()?;
            if let Some((_, length)) = info {
                prepared_charge(&mut remaining, length)?;
            }
            buffers.push(info);
            validation.push(part);
        }
        phantom::StreamingMultipartBody::new(&boundary, validation, maximum).map_err(core_error)?;
        let mut parts = Vec::with_capacity(fields.len());
        for (field, buffer) in fields.into_iter().zip(buffers) {
            let data = if let Some(text) = field.text {
                Data::Text(text)
            } else if let Some(info) = buffer {
                Data::Bytes(copy_buffer_info(info, info.1)?)
            } else if let Some(file) = field.file {
                Data::File {
                    path: file.path,
                    maximum: u64::from(file.maximum_bytes),
                }
            } else {
                Data::Stream
            };
            parts.push(Part {
                name: field.name,
                data,
                filename: field.filename,
                content_type: field.content_type,
            });
        }
        self.state
            .configure_multipart(crate::multipart::Multipart::new(&boundary, parts, maximum)?)
    }
    /// Waits for the core encoder to poll its next foreign source.
    #[napi]
    pub fn next_part(&self, env: Env) -> Result<AsyncBlock<Option<u32>>> {
        let state = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move { state.next_part().await }).build(&env)
    }
    /// Waits for native body polling before pulling another source frame.
    #[napi]
    pub fn ready(&self, env: Env) -> Result<AsyncBlock<bool>> {
        let state = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move { Ok(state.ready().await) }).build(&env)
    }
    /// Copies one owned frame synchronously before any future work.
    #[napi]
    pub fn write(&self, env: Env, bytes: Buffer) -> Result<()> {
        self.state
            .write(copy_buffer(&env, bytes, crate::upload::MAXIMUM_CHUNK)?)
    }
    /// Marks successful producer EOF, checking exact length.
    #[napi]
    pub fn end(&self) -> Result<()> {
        self.state.end()
    }
    /// Reports a redacted producer failure.
    #[napi]
    pub fn fail(&self) {
        self.state.fail();
    }
    /// Stops pulling without labelling an early response as a source failure.
    #[napi]
    pub fn stop(&self) {
        self.state.stop();
    }
    /// Waits for upload termination, independently of response headers.
    #[napi]
    pub fn stopped(&self, env: Env) -> Result<AsyncBlock<()>> {
        let state = Arc::clone(&self.state);
        AsyncBlockBuilder::new(async move {
            state.stopped().await;
            Ok(())
        })
        .build(&env)
    }
    /// Releases JS-producer ownership only after cooperative cleanup settles.
    #[napi]
    pub fn settled(&self) {
        self.state.settled();
        self.owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

impl Drop for NativeUpload {
    fn drop(&mut self) {
        // Env teardown cannot run JS cleanup; release only native ownership here.
        self.state.stop();
        self.state.settled();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    #[test]
    fn upload_owner_retains_admission_after_the_response_owner_disappears() -> Result<()> {
        let admission = Arc::new(Semaphore::new(1));
        let exchange = Exchange::new();
        let weak = Arc::downgrade(&exchange);
        exchange.claim(
            Arc::clone(&admission)
                .try_acquire_owned()
                .map_err(|_| failure("TestAdmission", "initial admission failed"))?,
            None,
        )?;
        let upload = NativeUpload::new(None)?;
        exchange.upload(Arc::clone(&upload.state));
        *upload.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&exchange));
        exchange.cancel();
        drop(exchange);
        assert!(weak.upgrade().is_some());
        assert_eq!(admission.available_permits(), 0);
        upload.settled();
        assert!(weak.upgrade().is_none());
        assert_eq!(admission.available_permits(), 1);
        Ok(())
    }
}
