//! HTTP/3 client builder

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicUsize, Arc},
};

use bytes::{Buf, Bytes};

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    proto::frame::{self, SettingsError},
    quic::{self},
    shared_state::SharedState,
};

use super::connection::{Connection, SendRequest};

/// Start building a new HTTP/3 client
pub fn builder() -> Builder {
    Builder::new()
}

/// Create a new HTTP/3 client with default settings
pub async fn new<C, O>(
    conn: C,
) -> Result<(Connection<C, Bytes>, SendRequest<O, Bytes>), ConnectionError>
where
    C: quic::Connection<Bytes, OpenStreams = O>,
    C::SendStream: quic::SendStreamUnframed<Bytes>,
    O: quic::OpenStreams<Bytes>,
{
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
    //= type=implication
    //# Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
    //# address and UDP port, where the IP address and port might be derived
    //# from a URI, a selected alternative service ([ALTSVC]), a configured
    //# proxy, or name resolution of any of these.
    Builder::new().build(conn).await
}

/// HTTP/3 client builder
///
/// Set the configuration for a new client.
///
/// # Examples
/// ```rust
/// # use h3::quic;
/// # async fn doc<C, O, B>(quic: C)
/// # where
/// #   C: quic::Connection<B, OpenStreams = O>,
/// #   C::SendStream: quic::SendStreamUnframed<B>,
/// #   O: quic::OpenStreams<B>,
/// #   B: bytes::Buf,
/// # {
/// let h3_conn = h3::client::builder()
///     .max_field_section_size(8192)
///     .build(quic)
///     .await
///     .expect("Failed to build connection");
/// # }
/// ```
pub struct Builder {
    config: Config,
}

impl Builder {
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Set the maximum header size this client is willing to accept
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease = enabled;
        self
    }

    /// Replaces the generated SETTINGS frame with the supplied entries.
    ///
    /// Identifier and value pairs are emitted in slice order using the
    /// shortest QUIC variable-length integer encoding. Automatic GREASE and
    /// the other setting builder methods do not alter an explicit list, so
    /// call this after configuring those options.
    ///
    /// The list is rejected if it contains duplicate or forbidden
    /// identifiers, values outside the QUIC variable-length integer range, or
    /// invalid values for settings with constrained domains.
    pub fn ordered_settings(&mut self, entries: &[(u64, u64)]) -> Result<&mut Self, SettingsError> {
        let settings = frame::Settings::from_ordered(entries)?;
        let semantic_settings: crate::config::Settings = (&settings).into();
        crate::config::validate_local_qpack_max_table_capacity(
            semantic_settings.qpack_max_table_capacity,
        )?;
        self.config.settings = semantic_settings;
        self.config.ordered_settings = Some(settings);
        Ok(self)
    }

    /// Indicates that the client supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.config.settings.enable_datagram = enabled;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// Enables stateful QPACK encoding for request fields.
    ///
    /// When enabled, requests wait for the peer's SETTINGS frame and the
    /// encoder stream before publishing a dependent HEADERS frame. The default
    /// remains stateless request encoding.
    pub fn enable_dynamic_qpack(&mut self, enabled: bool) -> &mut Self {
        self.config.dynamic_qpack = enabled;
        self
    }

    /// Create a new HTTP/3 client from a `quic` connection
    pub async fn build<C, O, B>(
        &mut self,
        quic: C,
    ) -> Result<(Connection<C, B>, SendRequest<O, B>), ConnectionError>
    where
        C: quic::Connection<B, OpenStreams = O>,
        C::SendStream: quic::SendStreamUnframed<B>,
        O: quic::OpenStreams<B>,
        B: Buf,
    {
        let open = quic.opener();
        let shared = SharedState::default();

        let conn_state = Arc::new(shared);

        let mut inner = ConnectionInner::new(quic, conn_state.clone(), self.config).await?;
        let qpack_decoder = inner.qpack_decoder();
        let outbound_qpack = inner.take_outbound_qpack_sender();
        let send_request = SendRequest {
            open,
            conn_state,
            qpack_decoder,
            max_field_section_size: self.config.settings.max_field_section_size,
            sender_count: Arc::new(AtomicUsize::new(1)),
            send_grease_frame: self.config.send_grease,
            outbound_qpack,
            _buf: PhantomData,
        };

        Ok((
            Connection {
                inner,
                sent_closing: None,
                recv_closing: None,
            },
            send_request,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{coding::Encode, frame::Settings},
        stream::UniStreamHeader,
    };

    const CHROME_SETTINGS: [(u64, u64); 5] = [
        (0x1, 65_536),
        (0x6, 262_144),
        (0x7, 100),
        (0x33, 1),
        (47_398_610_487, 289_824_385),
    ];

    fn configured_settings(builder: &Builder) -> Settings {
        Settings::try_from(builder.config).expect("builder settings must be valid")
    }

    #[test]
    fn dynamic_qpack_is_explicitly_enabled() {
        let mut builder = Builder::new();
        assert!(!builder.config.dynamic_qpack);
        builder.enable_dynamic_qpack(true);
        assert!(builder.config.dynamic_qpack);
    }

    fn settings_frame_bytes(builder: &Builder) -> Vec<u8> {
        let settings = configured_settings(builder);
        let mut bytes = Vec::new();
        settings.encode(&mut bytes);
        bytes
    }

    #[test]
    fn generated_settings_bytes_are_unchanged_without_override() {
        let mut builder = Builder::new();
        builder.send_grease(false);

        assert_eq!(
            settings_frame_bytes(&builder),
            [
                0x04, 0x17, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0xab,
                0x60, 0x37, 0x42, 0x00, 0x33, 0x00, 0xab, 0x60, 0x37, 0x43, 0x00,
            ]
        );
        assert!(builder.config.ordered_settings.is_none());
    }

    #[test]
    fn retained_chrome_settings_keep_entry_order_and_varint_widths() {
        let mut builder = Builder::new();
        builder
            .ordered_settings(&CHROME_SETTINGS)
            .expect("retained Chrome settings must be valid");

        assert_eq!(builder.config.settings.qpack_max_table_capacity, 65_536);
        assert_eq!(builder.config.settings.qpack_blocked_streams, 100);

        let settings = configured_settings(&builder);
        let mut bytes = Vec::new();
        UniStreamHeader::Control(settings).encode(&mut bytes);

        assert_eq!(
            bytes,
            [
                0x00, 0x04, 0x1b, 0x01, 0x80, 0x01, 0x00, 0x00, 0x06, 0x80, 0x04, 0x00, 0x00, 0x07,
                0x40, 0x64, 0x33, 0x01, 0xc0, 0x00, 0x00, 0x0b, 0x09, 0x2d, 0x66, 0x37, 0x91, 0x46,
                0x5e, 0x81,
            ]
        );
    }

    #[test]
    fn ordered_settings_reject_duplicates_and_forbidden_identifiers() {
        let mut builder = Builder::new();
        assert_eq!(
            builder.ordered_settings(&[(0x1, 0), (0x1, 1)]).err(),
            Some(SettingsError::Repeated(0x1))
        );

        for identifier in [0x0, 0x2, 0x3, 0x4, 0x5] {
            assert_eq!(
                builder.ordered_settings(&[(identifier, 0)]).err(),
                Some(SettingsError::InvalidSettingId(identifier))
            );
        }
    }

    #[test]
    fn ordered_settings_reject_out_of_range_and_constrained_values() {
        let mut builder = Builder::new();
        let out_of_range = 1 << 62;

        assert_eq!(
            builder.ordered_settings(&[(out_of_range, 0)]).err(),
            Some(SettingsError::InvalidSettingId(out_of_range))
        );
        assert_eq!(
            builder.ordered_settings(&[(0x1, 1 << 30)]).err(),
            Some(SettingsError::InvalidSettingValue(0x1, 1 << 30))
        );
        assert_eq!(
            builder.ordered_settings(&[(0x7, out_of_range)]).err(),
            Some(SettingsError::InvalidSettingValue(0x7, out_of_range))
        );

        for identifier in [0x8, 0x33, 0x2b60_3742, 0xffd277] {
            assert_eq!(
                builder.ordered_settings(&[(identifier, 2)]).err(),
                Some(SettingsError::InvalidSettingValue(identifier, 2))
            );
        }

        let too_many = [
            (0x21, 0),
            (0x40, 0),
            (0x5f, 0),
            (0x7e, 0),
            (0x9d, 0),
            (0xbc, 0),
            (0xdb, 0),
            (0xfa, 0),
            (0x119, 0),
        ];
        assert_eq!(
            builder.ordered_settings(&too_many).err(),
            Some(SettingsError::Exceeded)
        );
    }
}
