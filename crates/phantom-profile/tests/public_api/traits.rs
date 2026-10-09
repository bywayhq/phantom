//! Compile checks for the supported public profile value contracts.

use phantom_profile::{
    AlpsSettings, CertificateCompression, CipherSuite, ClientHelloExtension,
    ClientHelloExtensionOrder, ClientHint, ClientHintDelivery, ClientHintSettings, ClientProfile,
    CookiePlacement, DnsCacheSettings, EchGreaseAead, EchGreasePayloadLength, EchGreaseSettings,
    EchSettings, Http1IdleTimeout, Http1Settings, Http2CookieCrumbs, Http2FieldIndexing,
    Http2HpackSettings, Http2HuffmanCoding, Http2IdleTimeout, Http2IndexingLimit,
    Http2NameReference, Http2Priority, Http2ProxyConnections, Http2PseudoHeader,
    Http2RejectedConnect, Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings,
    Http2StaticNameIndex, Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch,
    Http3AltUsed, Http3ClientSettings, Http3CookieCrumbs, Http3PseudoHeader,
    Http3QpackDecoderStream, Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder,
    Http3RequestSettings, Http3Setting, Http3SettingOrder, Http3Settings,
    InvalidClientHintSettings, InvalidHttp1Settings, InvalidHttp2Settings,
    InvalidHttp3RequestSettings, InvalidHttp3Settings, InvalidProxyConnectTemplate,
    InvalidRequestTemplate, InvalidTcpSettings, InvalidTlsSettings, InvalidWebSocketSettings,
    NamedGroup, ProxyAuthorizationAttempt, ProxyConnectField, ProxyConnectTemplate, RequestField,
    RequestTemplate, SessionTicketOrder, SessionTickets, SignatureScheme, TcpAddressAdvance,
    TcpAddressRacing, TcpAddressSelection, TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy,
    TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings, TlsSettings, TlsVersion,
    TlsVersionRange, TrustAnchorIds, TrustAnchorOrder, TrustAnchorOrders, UdpSettings,
    WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
    WebSocketField, WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
    WebSocketSettings,
    quic::{
        GoogleConnectionOption, InvalidQuicTransportSettings, QuicAckFrequencyDraft,
        QuicConnectionIdLength, QuicTransportGrease, QuicTransportParameter,
        QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
        QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
    },
};
use std::{error::Error, fmt::Debug, hash::Hash};

fn value<T: Clone + Debug + Eq + Send + Sync>() {}
fn validator_error<T: Clone + Debug + Eq + Error + Send + Sync>() {}

#[test]
fn checked_selectors_and_cipher_conversion_keep_public_value_contracts() {
    fn checked<T: Copy + Clone + Debug + Eq + Hash + Send + Sync>() {}
    checked::<phantom_profile::UrlTrust>();
    checked::<phantom_profile::ValidationErrorKind>();
    checked::<phantom_profile::UnknownCipherSuite>();
    validator_error::<phantom_profile::UnknownCipherSuite>();
    fn conversion<T: TryFrom<u16, Error = phantom_profile::UnknownCipherSuite>>() {}
    conversion::<CipherSuite>();
    fn identifier<T: From<CipherSuite>>() {}
    identifier::<u16>();
}

#[test]
fn public_records_support_cloning_equality_and_thread_transfer() {
    value::<AlpsSettings>();
    value::<ClientHint>();
    value::<ClientHintSettings>();
    value::<ClientProfile>();
    value::<CookiePlacement>();
    value::<DnsCacheSettings>();
    value::<EchGreaseSettings>();
    value::<Http1Settings>();
    value::<Http2HpackSettings>();
    value::<Http2Priority>();
    value::<Http2Settings>();
    value::<Http2StreamSettings>();
    value::<Http3ClientSettings>();
    value::<Http3RequestSettings>();
    value::<Http3Settings>();
    value::<ProxyConnectTemplate>();
    value::<QuicTransportGrease>();
    value::<QuicTransportParameter>();
    value::<QuicTransportSettings>();
    value::<QuicVersionInformation>();
    value::<RequestTemplate>();
    value::<SessionTickets>();
    value::<TcpAddressRacing>();
    value::<TcpBackupConnection>();
    value::<TcpKeepalive>();
    value::<TcpKeepaliveSchedule>();
    value::<TcpPortRandomization>();
    value::<TcpSettings>();
    value::<TlsSettings>();
    value::<TlsVersionRange>();
    value::<TrustAnchorOrder>();
    value::<TrustAnchorOrders>();
    value::<UdpSettings>();
    value::<WebSocketConnectionPolicy>();
    value::<WebSocketSettings>();
}

#[test]
fn public_enums_support_cloning_equality_and_thread_transfer() {
    value::<CertificateCompression>();
    value::<CipherSuite>();
    value::<ClientHelloExtension>();
    value::<ClientHelloExtensionOrder>();
    value::<ClientHintDelivery>();
    value::<EchGreaseAead>();
    value::<EchGreasePayloadLength>();
    value::<EchSettings>();
    value::<GoogleConnectionOption>();
    value::<Http1IdleTimeout>();
    value::<Http2CookieCrumbs>();
    value::<Http2FieldIndexing>();
    value::<Http2HuffmanCoding>();
    value::<Http2IdleTimeout>();
    value::<Http2IndexingLimit>();
    value::<Http2NameReference>();
    value::<Http2ProxyConnections>();
    value::<Http2PseudoHeader>();
    value::<Http2RejectedConnect>();
    value::<Http2SensitiveProxyAuthorization>();
    value::<Http2Setting>();
    value::<Http2StaticNameIndex>();
    value::<Http2TableSizeUpdates>();
    value::<Http2UnindexedMatch>();
    value::<Http3AltUsed>();
    value::<Http3CookieCrumbs>();
    value::<Http3PseudoHeader>();
    value::<Http3QpackDecoderStream>();
    value::<Http3QpackEncoderStream>();
    value::<Http3QpackEncoding>();
    value::<Http3QpackStreamOrder>();
    value::<Http3Setting>();
    value::<Http3SettingOrder>();
    value::<NamedGroup>();
    value::<ProxyAuthorizationAttempt>();
    value::<ProxyConnectField>();
    value::<QuicAckFrequencyDraft>();
    value::<QuicConnectionIdLength>();
    value::<QuicTransportParameterKind>();
    value::<QuicTransportParameterOrder>();
    value::<QuicVarIntWidth>();
    value::<QuicVersionGrease>();
    value::<RequestField>();
    value::<SessionTicketOrder>();
    value::<SignatureScheme>();
    value::<TcpAddressAdvance>();
    value::<TcpAddressSelection>();
    value::<TcpKeepalivePolicy>();
    value::<TlsVersion>();
    value::<TrustAnchorIds>();
    value::<WebSocketDeflateParameter>();
    value::<WebSocketEmptyMessageCompression>();
    value::<WebSocketField>();
    value::<WebSocketNewConnection>();
    value::<WebSocketProxiedSession>();
    value::<WebSocketRefusedStreamRetry>();
}

#[test]
fn validation_errors_keep_standard_error_and_value_traits() {
    validator_error::<InvalidClientHintSettings>();
    validator_error::<InvalidHttp1Settings>();
    validator_error::<InvalidHttp2Settings>();
    validator_error::<InvalidHttp3RequestSettings>();
    validator_error::<InvalidHttp3Settings>();
    validator_error::<InvalidProxyConnectTemplate>();
    validator_error::<InvalidQuicTransportSettings>();
    validator_error::<InvalidRequestTemplate>();
    validator_error::<InvalidTcpSettings>();
    validator_error::<InvalidTlsSettings>();
    validator_error::<InvalidWebSocketSettings>();
}

#[test]
fn types_with_copy_keep_their_value_semantics() {
    fn copy<T: Copy>() {}
    copy::<CertificateCompression>();
    copy::<CipherSuite>();
    copy::<ClientHelloExtension>();
    copy::<ClientHintDelivery>();
    copy::<DnsCacheSettings>();
    copy::<EchGreaseAead>();
    copy::<EchGreasePayloadLength>();
    copy::<GoogleConnectionOption>();
    copy::<Http1IdleTimeout>();
    copy::<Http1Settings>();
    copy::<Http2CookieCrumbs>();
    copy::<Http2FieldIndexing>();
    copy::<Http2HuffmanCoding>();
    copy::<Http2IdleTimeout>();
    copy::<Http2IndexingLimit>();
    copy::<Http2NameReference>();
    copy::<Http2Priority>();
    copy::<Http2ProxyConnections>();
    copy::<Http2PseudoHeader>();
    copy::<Http2RejectedConnect>();
    copy::<Http2SensitiveProxyAuthorization>();
    copy::<Http2Setting>();
    copy::<Http2StaticNameIndex>();
    copy::<Http2StreamSettings>();
    copy::<Http2TableSizeUpdates>();
    copy::<Http2UnindexedMatch>();
    copy::<Http3AltUsed>();
    copy::<Http3CookieCrumbs>();
    copy::<Http3PseudoHeader>();
    copy::<Http3QpackDecoderStream>();
    copy::<Http3QpackEncoderStream>();
    copy::<Http3QpackEncoding>();
    copy::<Http3QpackStreamOrder>();
    copy::<Http3Setting>();
    copy::<Http3SettingOrder>();
    copy::<NamedGroup>();
    copy::<ProxyAuthorizationAttempt>();
    copy::<QuicAckFrequencyDraft>();
    copy::<QuicConnectionIdLength>();
    copy::<QuicTransportGrease>();
    copy::<QuicTransportParameterOrder>();
    copy::<QuicVarIntWidth>();
    copy::<QuicVersionGrease>();
    copy::<QuicVersionInformation>();
    copy::<SessionTicketOrder>();
    copy::<SessionTickets>();
    copy::<SignatureScheme>();
    copy::<TcpAddressAdvance>();
    copy::<TcpAddressRacing>();
    copy::<TcpAddressSelection>();
    copy::<TcpBackupConnection>();
    copy::<TcpKeepalive>();
    copy::<TcpKeepalivePolicy>();
    copy::<TcpKeepaliveSchedule>();
    copy::<TcpPortRandomization>();
    copy::<TcpSettings>();
    copy::<TlsVersion>();
    copy::<TlsVersionRange>();
    copy::<UdpSettings>();
    copy::<WebSocketDeflateParameter>();
    copy::<WebSocketEmptyMessageCompression>();
    copy::<WebSocketNewConnection>();
    copy::<WebSocketProxiedSession>();
    copy::<WebSocketRefusedStreamRetry>();
}

#[test]
fn checked_tls_values_keep_their_hash_and_ordering_traits() {
    fn hash<T: Hash>() {}
    hash::<EchGreaseAead>();
    hash::<EchGreasePayloadLength>();
    hash::<EchGreaseSettings>();
    hash::<EchSettings>();
    hash::<SessionTickets>();
    hash::<TlsVersion>();
    hash::<TlsVersionRange>();
    hash::<TrustAnchorIds>();
    hash::<TrustAnchorOrder>();
    hash::<TrustAnchorOrders>();

    fn ordered<T: Ord>() {}
    ordered::<TlsVersion>();
}

#[test]
fn provided_defaults_remain_available() {
    fn provided_default<T: Default>() {}
    provided_default::<CookiePlacement>();
    provided_default::<EchGreasePayloadLength>();
    provided_default::<Http1IdleTimeout>();
    provided_default::<Http2CookieCrumbs>();
    provided_default::<Http2FieldIndexing>();
    provided_default::<Http2HpackSettings>();
    provided_default::<Http2HuffmanCoding>();
    provided_default::<Http2IdleTimeout>();
    provided_default::<Http2IndexingLimit>();
    provided_default::<Http2NameReference>();
    provided_default::<Http2ProxyConnections>();
    provided_default::<Http2RejectedConnect>();
    provided_default::<Http2SensitiveProxyAuthorization>();
    provided_default::<Http2StaticNameIndex>();
    provided_default::<Http2StreamSettings>();
    provided_default::<Http2TableSizeUpdates>();
    provided_default::<Http2UnindexedMatch>();
    provided_default::<Http3CookieCrumbs>();
    provided_default::<TcpAddressAdvance>();
    provided_default::<TcpAddressSelection>();
    provided_default::<TcpKeepalivePolicy>();
    provided_default::<TcpSettings>();
    provided_default::<UdpSettings>();
}

#[test]
fn checked_tls_values_keep_recoverable_conversions_and_borrowed_access() {
    fn checked<T: TryFrom<Input, Error = InvalidTlsSettings>, Input>() {}
    checked::<TlsVersionRange, (TlsVersion, TlsVersion)>();
    checked::<SessionTickets, u8>();
    checked::<TrustAnchorOrder, Vec<Box<[u8]>>>();
    checked::<TrustAnchorOrders, Vec<TrustAnchorOrder>>();

    fn infallible<T: From<Input>, Input>() {}
    infallible::<TlsVersionRange, TlsVersion>();

    fn borrowed<T: AsRef<Target>, Target: ?Sized>() {}
    borrowed::<TrustAnchorOrder, [Box<[u8]>]>();
    borrowed::<TrustAnchorOrders, [TrustAnchorOrder]>();
}
