//! HTTP/2 client-preface and initial-frame capture.

mod frame;

pub use frame::{
    CapturedFrame, FrameDecodeError, FrameHeader, Setting, SettingsDecodeError, SettingsFrame,
    WindowUpdateDecodeError, WindowUpdateFrame,
};

use std::{error::Error, fmt, io};

use frame::FRAME_HEADER_LENGTH;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{Instant, timeout_at},
};

/// The exact HTTP/2 client connection preface.
pub const CLIENT_CONNECTION_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Resource limits applied while capturing initial HTTP/2 client frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    max_frame_payload_bytes: usize,
    max_total_bytes: usize,
    max_frames: usize,
}

impl CaptureLimits {
    /// Creates explicit limits for one capture.
    ///
    /// `max_total_bytes` includes the connection preface and every captured
    /// frame header and payload.
    #[must_use]
    pub const fn new(
        max_frame_payload_bytes: usize,
        max_total_bytes: usize,
        max_frames: usize,
    ) -> Self {
        Self {
            max_frame_payload_bytes,
            max_total_bytes,
            max_frames,
        }
    }
}

/// The observable event that completes an initial client-frame capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptureCompletion {
    /// Stop after the first valid, non-acknowledgement SETTINGS frame.
    InitialSettings,
    /// Stop after both initial SETTINGS and a connection WINDOW_UPDATE appear.
    InitialSettingsAndConnectionWindowUpdate,
}

/// A validated client connection preface and ordered initial frames.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientFrameCapture {
    preface: [u8; 24],
    frames: Vec<CapturedFrame>,
}

impl ClientFrameCapture {
    /// Returns the exact received client connection preface.
    #[must_use]
    pub const fn preface_bytes(&self) -> &[u8; 24] {
        &self.preface
    }

    /// Returns captured frames in their exact wire order.
    #[must_use]
    pub fn frames(&self) -> &[CapturedFrame] {
        &self.frames
    }
}

/// Failure returned while capturing initial HTTP/2 client frames.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureError {
    /// The overall capture deadline elapsed.
    DeadlineExceeded,
    /// The input ended before the full client connection preface arrived.
    TruncatedPreface,
    /// The received client connection preface did not match HTTP/2.
    InvalidPreface {
        /// Index of the first mismatched byte.
        index: usize,
        /// Expected byte at `index`.
        expected: u8,
        /// Received byte at `index`.
        actual: u8,
    },
    /// The input ended partway through a frame header.
    TruncatedFrameHeader,
    /// The input ended cleanly before the requested completion event occurred.
    InputEndedBeforeCompletion {
        /// Completion event that was still required.
        completion: CaptureCompletion,
    },
    /// The input ended partway through a frame payload.
    TruncatedFramePayload {
        /// Payload length declared by the frame header.
        expected: usize,
    },
    /// Reading the input failed for a reason other than truncation.
    Io(io::Error),
    /// A frame declared a payload larger than the configured limit.
    FramePayloadLimitExceeded {
        /// Declared payload length.
        length: usize,
        /// Configured maximum payload length.
        maximum: usize,
    },
    /// Capturing another frame would exceed the configured frame count.
    FrameCountLimitExceeded {
        /// Configured maximum frame count.
        maximum: usize,
    },
    /// Reading the next capture unit would exceed the total-byte limit.
    TotalByteLimitExceeded {
        /// Total bytes the capture unit would produce.
        attempted: usize,
        /// Configured maximum total bytes.
        maximum: usize,
    },
    /// A SETTINGS frame required for completion was malformed.
    InvalidSettings(SettingsDecodeError),
    /// The first frame was not SETTINGS, as required by HTTP/2 clients.
    InitialFrameNotSettings {
        /// Type of the unexpected first frame.
        frame_type: u8,
    },
    /// The first frame acknowledged settings instead of advertising client settings.
    InitialSettingsAcknowledgement,
    /// A WINDOW_UPDATE frame was malformed.
    InvalidWindowUpdate(WindowUpdateDecodeError),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => formatter.write_str("HTTP/2 capture deadline exceeded"),
            Self::TruncatedPreface => {
                formatter.write_str("input ended before the HTTP/2 client preface completed")
            }
            Self::InvalidPreface {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "HTTP/2 client preface differs at byte {index}: expected {expected:#04x}, received {actual:#04x}"
            ),
            Self::TruncatedFrameHeader => {
                formatter.write_str("input ended partway through an HTTP/2 frame header")
            }
            Self::InputEndedBeforeCompletion { completion } => write!(
                formatter,
                "HTTP/2 input ended before capture completion {completion:?}"
            ),
            Self::TruncatedFramePayload { expected } => write!(
                formatter,
                "input ended before the declared {expected}-byte HTTP/2 frame payload completed"
            ),
            Self::Io(error) => write!(formatter, "failed to read HTTP/2 input: {error}"),
            Self::FramePayloadLimitExceeded { length, maximum } => write!(
                formatter,
                "HTTP/2 frame payload is {length} bytes; maximum is {maximum}"
            ),
            Self::FrameCountLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "capture requires more than {maximum} HTTP/2 frames"
                )
            }
            Self::TotalByteLimitExceeded { attempted, maximum } => write!(
                formatter,
                "HTTP/2 capture would use {attempted} bytes; maximum is {maximum}"
            ),
            Self::InvalidSettings(error) => write!(formatter, "invalid SETTINGS frame: {error}"),
            Self::InitialFrameNotSettings { frame_type } => write!(
                formatter,
                "initial HTTP/2 client frame has type {frame_type:#04x}, not SETTINGS"
            ),
            Self::InitialSettingsAcknowledgement => formatter.write_str(
                "initial HTTP/2 client SETTINGS frame is an acknowledgement, not an advertisement",
            ),
            Self::InvalidWindowUpdate(error) => {
                write!(formatter, "invalid WINDOW_UPDATE frame: {error}")
            }
        }
    }
}

impl Error for CaptureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidSettings(error) => Some(error),
            Self::InvalidWindowUpdate(error) => Some(error),
            _ => None,
        }
    }
}

/// Captures an HTTP/2 client preface and the requested initial frame sequence.
///
/// `deadline` bounds the entire operation rather than each read. Capture ends
/// as soon as `completion` is satisfied. After an error, the reader may be
/// partially consumed and must be discarded or reset to a known boundary.
pub async fn capture_client_frames<R>(
    reader: &mut R,
    deadline: Instant,
    limits: CaptureLimits,
    completion: CaptureCompletion,
) -> Result<ClientFrameCapture, CaptureError>
where
    R: AsyncRead + Unpin,
{
    match timeout_at(
        deadline,
        capture_client_frames_inner(reader, limits, completion),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(CaptureError::DeadlineExceeded),
    }
}

async fn capture_client_frames_inner<R>(
    reader: &mut R,
    limits: CaptureLimits,
    completion: CaptureCompletion,
) -> Result<ClientFrameCapture, CaptureError>
where
    R: AsyncRead + Unpin,
{
    if CLIENT_CONNECTION_PREFACE.len() > limits.max_total_bytes {
        return Err(CaptureError::TotalByteLimitExceeded {
            attempted: CLIENT_CONNECTION_PREFACE.len(),
            maximum: limits.max_total_bytes,
        });
    }

    let mut preface = [0u8; 24];
    read_exact(reader, &mut preface, CaptureStage::Preface).await?;
    if let Some(index) = preface
        .iter()
        .zip(CLIENT_CONNECTION_PREFACE)
        .position(|(actual, expected)| actual != expected)
    {
        return Err(CaptureError::InvalidPreface {
            index,
            expected: CLIENT_CONNECTION_PREFACE[index],
            actual: preface[index],
        });
    }

    let mut total_bytes = CLIENT_CONNECTION_PREFACE.len();
    let mut frames = Vec::new();
    let mut saw_initial_settings = false;
    let mut saw_connection_window_update = false;

    loop {
        if frames.len() >= limits.max_frames {
            return Err(CaptureError::FrameCountLimitExceeded {
                maximum: limits.max_frames,
            });
        }

        checked_total(total_bytes, FRAME_HEADER_LENGTH, limits)?;
        let mut header_bytes = [0u8; FRAME_HEADER_LENGTH];
        read_frame_header(reader, &mut header_bytes, completion).await?;
        let header = FrameHeader::decode(header_bytes);

        if header.payload_length() > limits.max_frame_payload_bytes {
            return Err(CaptureError::FramePayloadLimitExceeded {
                length: header.payload_length(),
                maximum: limits.max_frame_payload_bytes,
            });
        }
        let frame_length = FRAME_HEADER_LENGTH
            .checked_add(header.payload_length())
            .ok_or(CaptureError::TotalByteLimitExceeded {
                attempted: usize::MAX,
                maximum: limits.max_total_bytes,
            })?;
        let next_total = checked_total(total_bytes, frame_length, limits)?;

        let mut wire = vec![0; frame_length];
        wire[..FRAME_HEADER_LENGTH].copy_from_slice(&header_bytes);
        read_exact(
            reader,
            &mut wire[FRAME_HEADER_LENGTH..],
            CaptureStage::FramePayload {
                expected: header.payload_length(),
            },
        )
        .await?;

        let frame = CapturedFrame { header, wire };
        let settings = frame.settings().map_err(CaptureError::InvalidSettings)?;
        if frames.is_empty() {
            match settings {
                Some(settings) if !settings.is_acknowledgement() => {
                    saw_initial_settings = true;
                }
                Some(_) => return Err(CaptureError::InitialSettingsAcknowledgement),
                None => {
                    return Err(CaptureError::InitialFrameNotSettings {
                        frame_type: frame.header().frame_type(),
                    });
                }
            }
        }
        if let Some(window_update) = frame
            .window_update()
            .map_err(CaptureError::InvalidWindowUpdate)?
        {
            saw_connection_window_update |=
                frame.header().stream_id() == 0 && window_update.increment() != 0;
        }
        frames.push(frame);
        total_bytes = next_total;

        let complete = match completion {
            CaptureCompletion::InitialSettings => saw_initial_settings,
            CaptureCompletion::InitialSettingsAndConnectionWindowUpdate => {
                saw_initial_settings && saw_connection_window_update
            }
        };
        if complete {
            return Ok(ClientFrameCapture { preface, frames });
        }
    }
}

fn checked_total(
    current: usize,
    additional: usize,
    limits: CaptureLimits,
) -> Result<usize, CaptureError> {
    let attempted =
        current
            .checked_add(additional)
            .ok_or(CaptureError::TotalByteLimitExceeded {
                attempted: usize::MAX,
                maximum: limits.max_total_bytes,
            })?;
    if attempted > limits.max_total_bytes {
        return Err(CaptureError::TotalByteLimitExceeded {
            attempted,
            maximum: limits.max_total_bytes,
        });
    }
    Ok(attempted)
}

#[derive(Clone, Copy)]
enum CaptureStage {
    Preface,
    FramePayload { expected: usize },
}

async fn read_frame_header<R>(
    reader: &mut R,
    bytes: &mut [u8; FRAME_HEADER_LENGTH],
    completion: CaptureCompletion,
) -> Result<(), CaptureError>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read(&mut bytes[filled..]).await {
            Ok(0) if filled == 0 => {
                return Err(CaptureError::InputEndedBeforeCompletion { completion });
            }
            Ok(0) => return Err(CaptureError::TruncatedFrameHeader),
            Ok(read) => filled += read,
            Err(error) => return Err(CaptureError::Io(error)),
        }
    }
    Ok(())
}

async fn read_exact<R>(
    reader: &mut R,
    bytes: &mut [u8],
    stage: CaptureStage,
) -> Result<(), CaptureError>
where
    R: AsyncRead + Unpin,
{
    reader.read_exact(bytes).await.map(|_| ()).map_err(|error| {
        if error.kind() != io::ErrorKind::UnexpectedEof {
            return CaptureError::Io(error);
        }

        match stage {
            CaptureStage::Preface => CaptureError::TruncatedPreface,
            CaptureStage::FramePayload { expected } => {
                CaptureError::TruncatedFramePayload { expected }
            }
        }
    })
}

#[cfg(test)]
mod tests;
