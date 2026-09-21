use crate::frame::{self, Head, Kind, StreamId};
use crate::tracing;

use bytes::{BufMut, Bytes};

/// Largest accepted `Origin` or `Alt-Svc-Field-Value`, in bytes.
///
/// RFC 7838 section 4 places no limit on either part; this keeps retained
/// client state small while comfortably exceeding a serialized origin.
pub const MAX_ALTSVC_PART_LEN: usize = 16 * 1024;

/// An ALTSVC frame (RFC 7838 section 4).
///
/// ```text
/// +-------------------------------+-------------------------------+
/// |         Origin-Len (16)       | Origin? (*)                 ...
/// +-------------------------------+-------------------------------+
/// |                   Alt-Svc-Field-Value (*)                   ...
/// +---------------------------------------------------------------+
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct AltSvc {
    stream_id: StreamId,
    origin: Bytes,
    field_value: Bytes,
}

impl AltSvc {
    pub fn new(stream_id: StreamId, origin: Bytes, field_value: Bytes) -> AltSvc {
        AltSvc {
            stream_id,
            origin,
            field_value,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn origin(&self) -> &Bytes {
        &self.origin
    }

    pub fn field_value(&self) -> &Bytes {
        &self.field_value
    }

    /// Decodes an ALTSVC payload, returning `None` for a frame that RFC 7838
    /// requires to be ignored or that exceeds the local size bound.
    ///
    /// A malformed ALTSVC frame is never a connection or stream error: the
    /// extension is optional and unknown or invalid extension frames are
    /// discarded (RFC 9113 section 5.5).
    pub fn load(head: Head, payload: Bytes) -> Option<AltSvc> {
        let stream_id = head.stream_id();
        if payload.len() < 2 {
            tracing::debug!("ignoring ALTSVC frame with truncated Origin-Len");
            return None;
        }
        let origin_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
        if origin_len > payload.len() - 2 {
            tracing::debug!("ignoring ALTSVC frame whose Origin-Len exceeds its payload");
            return None;
        }
        let origin = payload.slice(2..2 + origin_len);
        let field_value = payload.slice(2 + origin_len..);
        // RFC 7838 section 4: stream 0 requires an origin, and any other
        // stream must leave it empty because the stream supplies the origin.
        if stream_id.is_zero() == origin.is_empty() {
            tracing::debug!("ignoring ALTSVC frame with invalid origin scope");
            return None;
        }
        if origin.len() > MAX_ALTSVC_PART_LEN || field_value.len() > MAX_ALTSVC_PART_LEN {
            tracing::debug!("ignoring oversized ALTSVC frame");
            return None;
        }
        Some(AltSvc {
            stream_id,
            origin,
            field_value,
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        tracing::trace!("encoding ALTSVC; id={:?}", self.stream_id);
        let origin_len = u16::try_from(self.origin.len()).unwrap_or(u16::MAX);
        let origin = &self.origin[..usize::from(origin_len)];
        let head = Head::new(Kind::AltSvc, 0, self.stream_id);
        head.encode(2 + origin.len() + self.field_value.len(), dst);
        dst.put_u16(origin_len);
        dst.put_slice(origin);
        dst.put_slice(&self.field_value);
    }
}

impl<B> From<AltSvc> for frame::Frame<B> {
    fn from(src: AltSvc) -> Self {
        frame::Frame::AltSvc(src)
    }
}

impl std::fmt::Debug for AltSvc {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("AltSvc")
            .field("stream_id", &self.stream_id)
            .field("origin_len", &self.origin.len())
            .field("field_value_len", &self.field_value.len())
            .finish()
    }
}
