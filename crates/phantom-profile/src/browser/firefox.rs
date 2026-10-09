//! Wire settings retained from Firefox browser observations.

//!
//! ## Android
//!
//! Wire settings retained from Firefox for Android observations.
//!
//! Firefox 156.0.1 for Android, as the Google Play Store served it to the
//! `phantom-api35-play` Android 15 emulator. A release Firefox for Android
//! reads GeckoView's debug configuration when it is the device's debug app,
//! so a capture can set preferences such as `network.dns.localDomains`, but
//! it cannot place a certificate override in the app's private profile. No
//! capture can therefore complete a TLS handshake with a test certificate, and
//! only the TCP ClientHello is captured. It has a recipe here.
//!
//! There is no Firefox for Android H2, WebSocket, request template, TCP,
//! HTTP/1.1 connection, address-cache, proxy CONNECT, or cookie-placement
//! recipe: none of those layers was captured on Android.

use crate::{ClientProfile, Http3ClientSettings};

mod android;

pub use android::v156_android_tcp_tls;

use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

use crate::{
    cookie::CookiePlacement,
    dns_cache::DnsCacheSettings,
    http1::{Http1IdleTimeout, Http1Settings},
    http2::{
        Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
        Http2IdleTimeout, Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader,
        Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
        Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch,
    },
    http3::{
        Http3AltUsed, Http3CookieCrumbs, Http3PseudoHeader, Http3QpackDecoderStream,
        Http3QpackEncoderStream, Http3QpackEncoding, Http3QpackStreamOrder, Http3RequestSettings,
        Http3Setting, Http3SettingOrder, Http3Settings,
    },
    proxy_connect::{
        Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate,
    },
    quic::{
        QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportParameter,
        QuicTransportParameterKind, QuicTransportParameterOrder, QuicTransportSettings,
        QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
    },
    request_template::{ProxyAuthorizationAttempt, RequestField, RequestTemplate},
    tcp::{
        TcpAddressSelection, TcpBackupConnection, TcpKeepalivePolicy, TcpKeepaliveSchedule,
        TcpSettings,
    },
    tls::{
        CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
        NamedGroup, SessionTicketOrder, SignatureScheme, TlsSettings, TlsVersion,
    },
    websocket::{
        WebSocketConnectionPolicy, WebSocketEmptyMessageCompression, WebSocketField,
        WebSocketNewConnection, WebSocketProxiedSession, WebSocketRefusedStreamRetry,
        WebSocketSettings,
    },
};

/// Returns the automatic `Cookie` field position for Firefox 157.
///
/// Firefox adds `Cookie` in `nsHttpChannel::PrepareToConnect`, then
/// `Upgrade-Insecure-Requests` and the `Sec-Fetch-*` fields in
/// `OnBeforeConnect`, the validators of a revalidation in
/// `OnCacheEntryCheck`, and `Priority`, `Pragma`, and `Cache-Control` in
/// `SetupChannelForTransaction`; its HTTP/2 compressor appends `te` last. The
/// retained Firefox 157 HTTP/1.1 EventSource reconnect capture sends `Cookie`
/// after `Referer` and before `Sec-Fetch-Dest`. The other neighbors come from
/// Firefox source, not from a capture.
#[must_use]
pub fn v157_cookie_placement() -> CookiePlacement {
    CookiePlacement::before_fields([
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "if-modified-since",
        "if-none-match",
        "priority",
        "pragma",
        "cache-control",
        "te",
    ])
}

/// Returns TLS settings captured from Firefox 157.0 on Windows 11.
///
/// Captured from five fresh Firefox 157.0 processes (Windows 11 build
/// 26200), the fingerprint snapshots under `fixtures/http3/firefox/157.0/`;
/// `fixtures/tls/firefox/157.0/` keeps two of their ClientHellos, one for
/// each ECH GREASE AEAD. The fixed extension order retains the stable wire
/// shape observed across those captures.
/// Firefox picks its ECH GREASE AEAD per connection from AES-128-GCM and
/// ChaCha20-Poly1305 with equal probability; this recipe lists both, so each
/// connection draws one the same way. The delegated-credential vector includes
/// legacy ECDSA-SHA1 because Firefox advertised it; TLS 1.3 authentication
/// cannot select that legacy scheme.
///
/// NSS sizes the ECH GREASE payload from the ClientHello that carries it,
/// padded for a `maximum_name_length` of 100
/// ([`crate::EchGreasePayloadLength::FromClientHello`]). Every fresh ClientHello to a
/// host name in the captures carries 240 payload bytes, every resumed one
/// 368, and a fresh one to `127.0.0.1` or `[::1]` 240. The recipe sends the
/// same fresh lengths; a resumed length depends on the server's ticket, and
/// with a ticket as long as the capture servers' it is 368. Firefox takes the
/// 100 from
/// `security.tls.ech.grease_size` over TCP, and NSS sends the TLS 1.2
/// `extended_master_secret` and `renegotiation_info` extensions whatever its
/// minimum version ([`TlsSettings::tls12_extensions_in_tls13_client_hello`]),
/// which matters only to [`v157_quic_tls`].
///
/// Ticket resumption over TCP follows the retained `resumption-*.txt`
/// captures. A resumed ClientHello omits the empty `session_ticket`
/// extension and adds `pre_shared_key` last. Firefox used each of the eight
/// tickets one connection issued, once. The recipe keeps up to ten per
/// origin, as Firefox's default ticket-cache preference allows. It offers them
/// [`SessionTicketOrder::OldestConnectionFirst`], as Firefox on Windows
/// does: in every `resumption-websocket-http1` run, the request after the
/// WebSocket resumed a ticket of the page's connection. When a ticket
/// permits early data, a direct connection also offers `early_data`,
/// between `key_share` and `supported_versions`, and sends replay-safe
/// requests in it ([`TlsSettings::tcp_early_data`]), as Firefox does on
/// every such resumption in those captures. Firefox disables early data on proxy
/// connections (`TlsHandshaker::InitSSLParams`,
/// `netwerk/protocol/http/TlsHandshaker.cpp:134-137` at tag
/// `FIREFOX_157_0_RELEASE`), and so does this recipe.
///
/// The returned value is an ordinary owned [`TlsSettings`], so callers can
/// customize it before constructing a transport.
#[must_use]
pub fn v157_tcp_tls() -> TlsSettings {
    TlsSettings {
        versions: crate::TlsVersionRange::TLS12_TO_TLS13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::RsaAes256CbcSha,
        ],
        groups: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
        ],
        key_shares: vec![
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
        ],
        signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::RsaPkcs1Sha1,
        ],
        delegated_credential_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ],
        session_tickets: crate::tls::TEN_SESSION_TICKETS,
        session_ticket_order: SessionTicketOrder::OldestConnectionFirst,
        session_ticket_extension_when_resuming: false,
        tcp_early_data: true,
        record_size_limit: Some(16_385),
        tls12_extensions_in_tls13_client_hello: true,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::Fixed(vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ExtendedMasterSecret,
            ClientHelloExtension::RenegotiationInfo,
            ClientHelloExtension::SupportedGroups,
            ClientHelloExtension::EcPointFormats,
            ClientHelloExtension::SessionTicket,
            ClientHelloExtension::Alpn,
            ClientHelloExtension::StatusRequest,
            ClientHelloExtension::DelegatedCredential,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::EarlyData,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::RecordSizeLimit,
            ClientHelloExtension::CertificateCompression,
            ClientHelloExtension::EncryptedClientHello,
        ]),
        ech: crate::EchSettings::Grease(crate::tls::firefox_ech_grease()),
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
        close_notify: true,
    }
}

/// Returns the TCP socket options and keepalive of Firefox 157.0 on Windows.
///
/// From the Firefox 157.0 socket hook logs taken on Windows 11 under
/// `fixtures/socket-hooks/firefox/157.0/windows-11-26200/`, which the
/// recipe's hook tests replay, and from source at tag
/// `FIREFOX_157_0_RELEASE`:
///
/// - Before it connects, `nsSocketTransport::InitiateSocket` sets
///   `TCP_NODELAY` and, on Windows only, a 524,288-byte `SO_SNDBUF`
///   (`netwerk/base/nsSocketTransport2.cpp:1449-1465`,
///   `netwerk/base/nsSocketTransportService2.cpp:1536-1538`).
/// - Keepalive follows [`TcpKeepaliveSchedule`] with the
///   `network.http.tcp_keepalive.*` defaults: 10 seconds idle while
///   short-lived, 600 seconds once long-lived, and a 60-second short-lived
///   time (`modules/libpref/init/all.js:1263-1270`). The probe interval is
///   the connection's setup time in whole seconds, at least one
///   (`netwerk/protocol/http/nsHttpConnection.cpp:2146`, the time from
///   `netwerk/protocol/http/DnsAndConnectSocket.cpp:941` to `:1134-1138`),
///   and Windows' fixed count of 10 probes
///   (`netwerk/base/nsSocketTransportService2.h:63-70`) puts the switch 72
///   seconds after a request's dispatch with a one-second interval
///   (`netwerk/protocol/http/nsHttpConnection.cpp:2167-2190`). Each request
///   restarts the short-lived period (`:686`), an idle pooled connection
///   stays short-lived (`:1411-1414`), HTTP/2 disables keepalive
///   (`:405-406`), and a WebSocket upgrade switches at once (`:1303-1320`).
/// - Addresses are chosen as [`TcpBackupConnection`] describes. Release
///   builds keep the newer Happy Eyeballs behind the nightly-only
///   `network.http.happy_eyeballs_enabled`
///   (`modules/libpref/init/StaticPrefList.yaml:17153-17156`), so
///   `DnsAndConnectSocket` opens an IPv4 backup attempt 250 ms after a first
///   attempt that has not connected (`modules/libpref/init/all.js:1205`,
///   `:1237`; `netwerk/protocol/http/DnsAndConnectSocket.cpp:179-186`,
///   `:222-225`, `:242-265`, `:307-329`), keeps the slower attempt's
///   connection, and pools it (`:671-745`). Once an origin's address family
///   is known, both attempts use it alone and each backup connect gets
///   `network.http.fallback-connection-timeout`, 5 seconds
///   (`modules/libpref/init/all.js:1220`; `DnsAndConnectSocket.cpp:167-178`,
///   `:1295-1303`). An attempt moves to its next address only after a
///   refused, unreachable, or timed-out connect
///   (`netwerk/base/nsSocketTransport2.cpp:169-200`, `:1747-1755`). In the
///   hook logs the backup started 254 to 260 ms after a slow first attempt,
///   the first attempt's slower connection carried a later request, and
///   every later connection tried IPv4 alone.
/// - No socket in the hook logs sets `SO_RANDOMIZE_PORT`, so Windows gives
///   each connection the next free local port, and
///   [`TcpSettings::port_randomization`] is `None`.
///
/// Not modeled:
///
/// - Firefox keeps the slower connection, and remembers the address family,
///   on every connection entry (`DnsAndConnectSocket.cpp:671-745`). Phantom
///   does so only for direct HTTP/1.1 and negotiated requests. Connections
///   to a proxy, WebSocket connections, exact HTTP/2 requests, and
///   connections that offer ECH from HTTPS records start the backup, close
///   the slower attempt, and neither use nor learn the family.
/// - Firefox marks an address that failed to connect as unusable in its
///   cached DNS record and skips it on later connections
///   (`netwerk/base/nsSocketTransport2.cpp:1742-1745`); Phantom tries it
///   again.
/// - Firefox remembers an origin's address family until a prune finds its
///   connection entry empty
///   (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:2614-2618`). Phantom
///   prunes on the timer of [`Http1IdleTimeout::ClosedOnTimer`], which notices
///   a server's close of an idle connection only when it fires; Firefox
///   notices at once and can stop its timer, so it may remember a family
///   longer.
/// - On Windows Firefox also sets `SO_LINGER` to `{1, 0}`
///   (`netwerk/base/nsSocketTransport2.cpp:1473-1485`), but it shuts the
///   socket down with `SD_BOTH` before closing it
///   (`netwerk/base/nsSocketTransport2.cpp:3407-3413`,
///   `netwerk/base/ShutdownLayer.cpp:33`), so the peer sees a FIN, as it
///   does from Phantom.
/// - Firefox sets `SO_SNDBUF` on Windows only. On Linux a fixed send buffer
///   turns off the kernel's send buffer autotuning, so clear
///   [`TcpSettings::send_buffer_size`] for a profile used elsewhere.
/// - On macOS Firefox sets only the keepalive idle time and assumes 8 probes;
///   on Linux and Android it also sets `TCP_KEEPCNT` to 4. Phantom sets the
///   interval wherever it can and never sets a probe count.
#[must_use]
pub fn v157_tcp() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        send_buffer_size: NonZeroU32::new(524_288),
        keepalive: TcpKeepalivePolicy::Schedule(TcpKeepaliveSchedule {
            short_lived_idle: Duration::from_secs(10),
            long_lived_idle: Duration::from_secs(600),
            minimum_interval: Duration::from_secs(1),
            short_lived_time: Duration::from_secs(60),
            probe_count: 10,
        }),
        address_selection: TcpAddressSelection::Backup(TcpBackupConnection {
            delay: Duration::from_millis(250),
            known_family_backup_timeout: Some(Duration::from_secs(5)),
        }),
        port_randomization: None,
    }
}

/// Returns the address cache of Firefox 157.0 release builds.
///
/// From Firefox source at tag `FIREFOX_157_0_RELEASE`, not from a capture.
/// `network.dnsCacheEntries` is 1600 outside nightly builds
/// (`modules/libpref/init/StaticPrefList.yaml:15647-15655`), and an answer
/// without a TTL from the operating system is kept for
/// `network.dnsCacheExpiration`, 60 seconds (`:15657-15661`;
/// `netwerk/dns/nsHostResolver.cpp:1311-1318`). A failed lookup is kept for
/// `NEGATIVE_RECORD_LIFETIME`, 60 seconds
/// (`netwerk/dns/nsHostResolver.cpp:66-68`, `:1304-1309`).
///
/// On Windows `network.dns.get-ttl` is on
/// (`modules/libpref/init/StaticPrefList.yaml:15663-15671`): after each
/// system lookup Firefox resolves the name again and reads the smallest
/// record TTL from the operating system's cache with `DnsQuery_A`
/// (`netwerk/dns/nsHostResolver.cpp:1625-1645`,
/// `netwerk/dns/GetAddrInfo.cpp:150-175`), then keeps the answer for that
/// TTL, without a lower bound (`nsHostResolver.cpp:1311-1318`), hence a zero
/// `min_record_ttl`. Its socket hook logs show a 1,757-second TTL kept.
/// Phantom's system lookups report no TTL, so a Phantom client keeps those
/// answers for 60 seconds; only a resolver that reports TTLs applies the
/// record rule.
///
/// Firefox also serves an expired answer for up to
/// `network.dnsCacheExpirationGracePeriod`, 600 seconds, while it resolves
/// the name again in the background (`:15680-15685`;
/// `netwerk/dns/nsHostResolver.cpp:1266-1284`); Phantom resolves an expired
/// name before it connects.
#[must_use]
pub fn v157_dns_cache() -> DnsCacheSettings {
    DnsCacheSettings {
        max_entries: NonZeroUsize::new(1600).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(60),
        min_record_ttl: Duration::ZERO,
        negative_ttl: Some(Duration::from_secs(60)),
    }
}

/// Returns the HTTP/1.1 connection policy of Firefox 157.0.
///
/// From Firefox source at tag `FIREFOX_157_0_RELEASE`, not from a capture:
/// `network.http.max-persistent-connections-per-server` is 6
/// (`modules/libpref/init/all.js:1150-1153`). Firefox applies it to direct
/// and CONNECT-tunneled connections and counts active connections together
/// with those still connecting
/// (`netwerk/protocol/http/nsHttpConnectionMgr.cpp:1202-1209`, `:1394-1430`;
/// `netwerk/protocol/http/ConnectionEntry.cpp:289-297`).
///
/// Three differences are not modeled. Phantom also counts idle connections,
/// which Firefox reuses before it opens another. Firefox uses
/// `network.http.max-persistent-connections-per-proxy`, 32, for plaintext
/// requests forwarded through an HTTP proxy (`modules/libpref/init/all.js:1159-1162`),
/// where this recipe keeps 6. And urgent-start requests may exceed the limit
/// by `network.http.max-urgent-start-excessive-connections-per-host`, 3
/// (`modules/libpref/init/all.js:1155-1157`).
///
/// Firefox reuses a connection only while it has been idle less than
/// `network.http.keep-alive.timeout`, 115 seconds
/// (`modules/libpref/init/all.js:1136`;
/// `netwerk/protocol/http/nsHttpConnection.cpp:965-983`), and closes it on a
/// timer once that time passes, with no request pending
/// (`nsHttpConnection::TimeToLive`, `:1009-1025`;
/// `netwerk/protocol/http/nsHttpConnectionMgr.cpp:258-271`, `:2572-2625`,
/// `:4075-4084`), which [`Http1IdleTimeout::ClosedOnTimer`] models. In the
/// Firefox 157 socket hook logs it closed an idle connection 115.5 seconds
/// after its last response, and the server read a FIN. Firefox also honors
/// the `timeout` of a response's `Keep-Alive` field (`:1120-1129`), which
/// Phantom ignores.
#[must_use]
pub fn v157_http1() -> Http1Settings {
    Http1Settings {
        max_connections_per_origin: NonZeroUsize::new(6).unwrap_or(NonZeroUsize::MIN),
        idle_timeout: Http1IdleTimeout::ClosedOnTimer(Duration::from_secs(115)),
    }
}

/// Returns HTTP/2 settings observed from Firefox 157.0 on Windows 11.
///
/// The initial SETTINGS, connection window, request pseudo-header order, and
/// navigation HEADERS priority come from the retained local H2 session
/// captures of the Firefox 157 WebSocket fixture set, three fresh-profile runs
/// over six connections. No raw Firefox 157 startup-frame fixture exists: the
/// raw startup tool needs WebDriver certificate trust for Firefox, and
/// geckodriver is not installed on the capture host.
///
/// The extended CONNECT shape comes from the same captures: `:method`,
/// `:path`, `:authority`, `:scheme`, `:protocol`, and HEADERS priority
/// non-exclusive on stream 0 with weight 22 instead of the navigation's 42.
///
/// The HPACK choices come from every block in those captures and from
/// `Http2Compressor` in `netwerk/protocol/http/Http2Compression.cpp`. Every
/// pseudo-header but `:path` may enter the dynamic table, so `:method:
/// CONNECT` and `:protocol` are indexed incrementally. `:path` is always a
/// literal without indexing, even `/`, which names entry 4
/// ([`Http2UnindexedMatch::Literal`]). A literal names the highest-numbered
/// entry with its name: the oldest dynamic entry once one exists, otherwise
/// the higher static entry, so `:method` is named with 3 and `:path` with 5
/// ([`Http2NameReference::OldestDynamic`]). Every literal string is
/// Huffman-coded, an empty one included
/// ([`Http2HuffmanCoding::AlwaysIncludingEmpty`]); none of the 831 strings
/// in the retained Firefox captures is sent raw. `authorization` is a
/// never-indexed literal and every other ordinary field may be indexed
/// ([`Http2FieldIndexing::NeverIndexAuthorization`]). A field larger than
/// half the table is not indexed ([`Http2IndexingLimit::Half`]). Every
/// `SETTINGS_HEADER_TABLE_SIZE` from the peer is announced at the start of
/// the next block, even an unchanged 4,096
/// ([`Http2TableSizeUpdates::EverySetting`]). Every HEADERS block of the
/// retained Firefox WebSocket and cookie sessions equals Phantom's byte for
/// byte.
///
/// Each `cookie` field is split at `"; "` into one field per cookie. A crumb
/// shorter than 20 bytes is a never-indexed literal and a longer one is
/// inserted into the dynamic table ([`Http2CookieCrumbs::NeverIndexShort`]),
/// as the retained cookie captures (`fixtures/cookies/`) show for crumbs of
/// 19 and 20 bytes and as `Http2Compressor::EncodeHeaderBlock` states.
///
/// Each connection's first request is stream 3. `Http2Session` starts
/// `mNextStreamID` at 3 and reserves stream 1 for an HTTP/1.1 Upgrade
/// (`netwerk/protocol/http/Http2Session.cpp:172` at mozilla-central
/// `4d5216592535`). It would open RFC 7540 priority-group streams 3 to 13
/// first (`:1179-1199`), but only while `network.http.http2.enabled.deps` is
/// set (`:1139-1141`), and that preference is off by default
/// (`modules/libpref/init/StaticPrefList.yaml:16554-16557`). Every HTTP/2
/// connection in the retained cookie, WebSocket, and `https-proxy-*`
/// captures sends its first request on stream 3 and counts up by 2.
///
/// Until the peer states `SETTINGS_MAX_CONCURRENT_STREAMS`, at most 100
/// streams are open. `mMaxConcurrent` starts at
/// `network.http.http2.default-concurrent`, 100 (`Http2Session.cpp:236`;
/// `StaticPrefList.yaml:16638-16641`), `TryToActivate` queues a stream while
/// it is reached (`Http2Session.cpp:873-880`), and only a stated value
/// replaces it (`:1880-1883`), with no cap on a large value. No capture shows
/// the limit, because every capture server states 100.
///
/// No PING precedes a request on a read-idle connection. Instead, after 58
/// seconds without a read, a PING with a zero payload goes out whether or not
/// requests are open, and one unanswered with nothing read for 8 seconds
/// closes the connection with `GOAWAY(0, INTERNAL_ERROR)`. `Http2Session`'s
/// read-timeout tick sends the PING once `network.http.http2.ping-threshold`,
/// 58, has passed since the last read, and closes the session with
/// `NS_ERROR_NET_TIMEOUT` once `network.http.http2.ping-timeout`, 8, has
/// passed since the PING with nothing read (`Http2Session.cpp:436-503`;
/// `modules/libpref/init/StaticPrefList.yaml:16497-16505` at tag
/// `FIREFOX_157_0_RELEASE`). The payload is zero (`Http2Session.cpp:990`),
/// and a close for a failure sends `INTERNAL_ERROR` with last stream ID 0 and
/// no debug data (`:1033-1051`, `:3597-3610`). The retained capture
/// (`fixtures/lifecycle/firefox/157.0/windows-11-26200/idle-ping.txt`) shows
/// the PING 59.95 seconds after the last read, later than 58 because Firefox
/// checks on a one-second tick that its timer thread may delay; Phantom sends
/// it at 58. `nsHttpTransaction::Close` does not restart a request the close
/// failed (`nsHttpTransaction.cpp:1546-1553`), so none is sent again. A PING
/// Firefox sends on a network change (`Http2Session.cpp:4190-4212`) is not
/// modeled.
///
/// A connection that has read no response HEADERS or DATA for 170 seconds
/// takes no new stream, and the connection manager's prune timer closes it
/// with `GOAWAY(0, NO_ERROR)` within a second, or when its last stream ends
/// ([`Http2IdleTimeout::ClosedOnTimer`]). The limit is
/// `network.http.http2.timeout` (`StaticPrefList.yaml:16477-16480`), which
/// `nsHttpConnection::StartSpdy` applies
/// (`netwerk/protocol/http/nsHttpConnection.cpp:414`, `:965-983`); the idle
/// time counts from the session's start or its last HEADERS or DATA read,
/// so PING ACKs do not extend it (`Http2Session.cpp:239`, `:432-434`,
/// `:1629`, `:2820`, `:3203`). The prune marks such a connection
/// don't-reuse (`netwerk/protocol/http/ConnectionEntry.cpp:486-500`), which
/// closes an idle session with `NS_OK` and so `NO_ERROR`
/// (`Http2Session.cpp:812-826`, `:1033-1052`, `:3570-3615`). After a
/// response, the idle PING therefore goes out about 58 and 116 seconds
/// later, and the `GOAWAY` 170 to 171 seconds later. No capture shows a
/// close on the idle timer; Firefox 157 sent the same `GOAWAY` at browser
/// exit.
#[must_use]
pub fn v157_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ],
        initial_connection_window_size: 12_582_912,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ],
        extended_connect_pseudo_header_order: Some(vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Protocol,
        ]),
        extended_connect_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        }),
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
        hpack: Http2HpackSettings {
            literal_pseudo_headers: Vec::new(),
            static_name_index: Http2StaticNameIndex::Highest,
            huffman_coding: Http2HuffmanCoding::AlwaysIncludingEmpty,
            cookie_crumbs: Http2CookieCrumbs::NeverIndexShort,
            field_indexing: Http2FieldIndexing::NeverIndexAuthorization,
            name_reference: Http2NameReference::OldestDynamic,
            unindexed_match: Http2UnindexedMatch::Literal,
            indexing_limit: Http2IndexingLimit::Half,
            table_size_updates: Http2TableSizeUpdates::EverySetting,
            sensitive_proxy_authorization: Http2SensitiveProxyAuthorization::FieldIndexing,
        },
        streams: Http2StreamSettings {
            first_stream_id: 3,
            assumed_max_concurrent_streams: Some(100),
            max_concurrent_streams_cap: None,
        },
        preface_ping_after: None,
        ping_timeout: None,
        ping_failure_retries: 0,
        idle_ping_after: Some(Duration::from_secs(58)),
        idle_ping_timeout: Some(Duration::from_secs(8)),
        idle_timeout: Http2IdleTimeout::ClosedOnTimer(Duration::from_secs(170)),
    }
}

/// Returns WebSocket settings observed from Firefox 157.0 on Windows 11.
///
/// From the retained Windows 11 (build 26200) WebSocket captures. A `wss://`
/// WebSocket uses a pooled H2 session to the origin when its peer enabled
/// extended CONNECT. With no H2 session, Firefox opens a new connection with
/// its ordinary `h2,http/1.1` offer and sends extended CONNECT. When the
/// session's peer did not enable extended CONNECT, it opens a new TLS
/// connection offering only `http/1.1` and sends an HTTP/1.1 Upgrade. The
/// captures record that connection's ALPN offer, not its complete
/// ClientHello.
///
/// The opening templates keep the captured field order and spelling.
/// `User-Agent`, `Accept-Language`, and `Origin` are caller slots because
/// their values are persona and page data; the H2 template also places
/// `sec-fetch-storage-access`, which Firefox sent from a cross-site page. The
/// captures carry no cookies, so the cookie placeholder's final position is
/// not observed. The compression offer is bare `permessage-deflate`; Firefox
/// always sends it, while Phantom sends it only when the caller enables
/// compression.
///
/// `Accept-Encoding` and the three `Sec-Fetch-*` fields are
/// [`WebSocketField::ByTrust`] entries, as on ordinary requests: Firefox
/// offers `br` and `zstd`, and sends `Sec-Fetch-*` at all, only to a
/// potentially trustworthy URL. The retained proxy route captures show the
/// `ws://` Upgrade to `127.0.0.1` with `gzip, deflate, br, zstd` and
/// `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, and `Sec-Fetch-Site` between
/// `Connection` and `Pragma`, and the one to the plaintext name
/// `origin.phantom.test` with `gzip, deflate` and no `Sec-Fetch-*` field,
/// direct and through both proxies; the remaining fields keep their order.
/// `Sec-Fetch-Site` defaults to `same-origin`, the value every same-origin
/// page in the captures sent; a page on another site sends `cross-site`, as
/// in the `fresh-origin` capture. A caller field with the name of any of
/// these entries replaces the recipe's value in place, to any URL.
///
/// In the `refused-stream` captures Firefox answers
/// `RST_STREAM(REFUSED_STREAM)` by failing the WebSocket with close code
/// 1006, on every run, so its refusal is not retried. In the `accept-deflate`
/// captures it sends a zero-length text message uncompressed, with RSV1 clear
/// and an empty payload, while compressing every non-empty message.
///
/// The 20-second handshake timeout is Firefox's default, not a capture:
/// `WebSocketChannel` starts its open timer once the HTTP channel opens,
/// cancels it in `CallStartWebsocketData` when the handshake completes, and
/// aborts the connection with `NS_ERROR_NET_TIMEOUT_EXTERNAL` when it fires
/// (`netwerk/protocol/websocket/WebSocketChannel.cpp` lines 1200, 1403-1420,
/// 2974-2980, and 3342-3351 at `FIREFOX_157_0_RELEASE`). The value is the
/// `network.websocket.timeout.open` preference, 20 seconds by default
/// (`modules/libpref/init/all.js` line 1317). Firefox resolves the host for
/// its per-host admission queue before that timer starts; Phantom's deadline
/// includes that lookup.
///
/// [`WebSocketProxiedSession::Reuse`] is source, not a capture: no retained
/// capture opens a `wss://` WebSocket through a proxy. At tag
/// `FIREFOX_157_0_RELEASE`, a WebSocket upgrade stays eligible for HTTP/2
/// whatever the proxy (`netwerk/protocol/http/nsHttpChannel.cpp` lines
/// 1192-1207), the connection entry's hash key holds the proxy
/// (`nsHttpConnectionInfo.cpp` lines 211-231), and a WebSocket finding an
/// active HTTP/2 connection in its entry opens an extended CONNECT stream on
/// it when the peer allows one (`nsHttpConnectionMgr.cpp` lines 1619-1630
/// and 1811-1875).
#[must_use]
pub fn v157_websocket() -> WebSocketSettings {
    WebSocketSettings {
        connection: WebSocketConnectionPolicy {
            without_http2_session: WebSocketNewConnection::Http2ExtendedConnect,
            with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
            http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
            refused_stream_retry: WebSocketRefusedStreamRetry::None,
            proxied_http2_session: WebSocketProxiedSession::Reuse,
        },
        http1_fields: vec![
            WebSocketField::authority("Host"),
            WebSocketField::caller("User-Agent"),
            WebSocketField::literal("Accept", "*/*"),
            WebSocketField::caller("Accept-Language"),
            websocket_accept_encoding("Accept-Encoding"),
            WebSocketField::literal("Sec-WebSocket-Version", "13"),
            WebSocketField::caller("Origin"),
            WebSocketField::permessage_deflate("Sec-WebSocket-Extensions"),
            WebSocketField::key("Sec-WebSocket-Key"),
            WebSocketField::literal("Connection", "Upgrade"),
            WebSocketField::trustworthy_only("Sec-Fetch-Dest", "empty"),
            WebSocketField::trustworthy_only("Sec-Fetch-Mode", "websocket"),
            WebSocketField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
            WebSocketField::literal("Pragma", "no-cache"),
            WebSocketField::literal("Cache-Control", "no-cache"),
            WebSocketField::literal("Upgrade", "websocket"),
            WebSocketField::client_cookies("Cookie"),
        ],
        http2_fields: vec![
            WebSocketField::caller("user-agent"),
            WebSocketField::literal("accept", "*/*"),
            WebSocketField::caller("accept-language"),
            websocket_accept_encoding("accept-encoding"),
            WebSocketField::literal("sec-websocket-version", "13"),
            WebSocketField::caller("origin"),
            WebSocketField::permessage_deflate("sec-websocket-extensions"),
            WebSocketField::caller("sec-fetch-storage-access"),
            WebSocketField::trustworthy_only("sec-fetch-dest", "empty"),
            WebSocketField::trustworthy_only("sec-fetch-mode", "websocket"),
            WebSocketField::trustworthy_only("sec-fetch-site", "same-origin"),
            WebSocketField::literal("pragma", "no-cache"),
            WebSocketField::literal("cache-control", "no-cache"),
            WebSocketField::client_cookies("cookie"),
        ],
        permessage_deflate_offer: Vec::new(),
        empty_message_compression: WebSocketEmptyMessageCompression::Uncompressed,
        handshake_timeout: Some(Duration::from_secs(20)),
    }
}

/// Returns the CONNECT request fields observed from Firefox 157.0 on Windows 11.
///
/// From the retained proxy route captures, three runs of each scenario.
/// Every HTTP/1.1 CONNECT for the page's `ws://` origin sends `User-Agent`,
/// `Proxy-Connection: keep-alive`, `Connection: keep-alive`, and `Host`,
/// then `Proxy-Authorization` when the proxy asked for credentials
/// (`http-proxy-*` and `http-proxy-auth-*`). Every HTTP/2 CONNECT to the TLS
/// proxy sends `user-agent` after `:method` and `:authority`, then
/// `proxy-authorization` (`https-proxy-*` and `https-proxy-auth-*`). The
/// `*-secure-hostname` captures show the same fields on the CONNECT for an
/// `https://` fetch and a `wss://` opening, anonymous, challenged, on the
/// replay after a `407`, and with remembered credentials.
///
/// Firefox's `User-Agent` there is its own, which the captures show equal to
/// the page request's. The recipe copies the `User-Agent` of the request
/// that opens the tunnel: the caller's field, or the request template's
/// value.
///
/// After an HTTP/2 CONNECT is challenged, Firefox sends nothing more on the
/// challenged stream (`https-proxy-auth-secure-hostname`).
///
/// In every `https-proxy-*` capture, Firefox opens three HTTP/2 connections
/// to the proxy for one page: one for the navigation and `fetch()`, one for
/// the `https://` CONNECTs, and one for the `ws://` and `wss://` CONNECTs,
/// so the recipe keeps the three apart ([`Http2ProxyConnections::ByPurpose`]).
#[must_use]
pub fn v157_proxy_connect() -> ProxyConnectTemplate {
    ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::from_request("User-Agent"),
            ProxyConnectField::literal("Proxy-Connection", "keep-alive"),
            ProxyConnectField::literal("Connection", "keep-alive"),
            ProxyConnectField::authority("Host"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            ProxyConnectField::from_request("user-agent"),
            ProxyConnectField::proxy_authorization("proxy-authorization"),
        ],
        http2_rejected: Http2RejectedConnect::LeaveOpen,
        http2_connections: Http2ProxyConnections::ByPurpose,
    }
}

/// Returns TLS settings for the Firefox 157 HTTP/3 offer on Windows 11.
///
/// Firefox's QUIC stack, neqo, runs its handshake on NSS with a configuration
/// of its own, so the QUIC ClientHello differs from [`v157_tcp_tls`]. The retained
/// Firefox 157.0 QUIC ClientHellos (`fixtures/http3/firefox/157.0/`, three
/// fresh processes and the first connection of each resumption run) offer TLS
/// 1.3 alone, the three TLS 1.3 cipher suites in the TCP order, the `h3` ALPN
/// protocol, and the TCP groups, key shares, status request,
/// `record_size_limit` (16385), and ECH GREASE (one of the two AEADs, with a
/// payload sized from the ClientHello: 240 bytes fresh, 368 resumed, and 208
/// to `127.0.0.1`), and the TCP `delegated_credentials` schemes. Like the TCP
/// offer, they carry an empty `extended_master_secret` and a
/// `renegotiation_info` of one zero byte, which BoringSSL leaves out of a TLS
/// 1.3-only ClientHello unless
/// [`TlsSettings::tls12_extensions_in_tls13_client_hello`] is set. They differ
/// from the TCP offer in these fields:
///
/// - `signature_algorithms` moves ECDSA-SHA1 after the other ECDSA schemes,
///   and offers no ML-DSA scheme: `security.tls.enable_mldsa`, off by default,
///   removes ML-DSA from the NSS policy that filters neqo's default list
///   (`security/manager/ssl/nsNSSComponent.cpp:1025-1033` at
///   `FIREFOX_157_0_RELEASE`);
/// - `compress_certificate` lists zlib, zstd, then brotli;
/// - no `ec_point_formats`, `session_ticket`, or `signed_certificate_timestamp`;
/// - the extension order changes on every connection, except that
///   `quic_transport_parameters` and then `encrypted_client_hello` always
///   come last, before `pre_shared_key`
///   ([`ClientHelloExtensionOrder::PermutedWithTail`]).
///
/// QUIC carries no TLS records, so `record_size_limit` limits nothing on
/// these connections; Firefox sends it anyway, and so does the recipe.
///
/// `session_tickets` is enabled because Firefox resumes QUIC sessions: in the
/// retained resumption captures a resumed ClientHello adds `early_data` and,
/// last, `pre_shared_key`, as [`v157_quic`] allows.
#[must_use]
pub fn v157_quic_tls() -> TlsSettings {
    let mut settings = v157_tcp_tls();
    settings.versions = crate::TlsVersionRange::only(TlsVersion::Tls13);
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Chacha20Poly1305Sha256,
        CipherSuite::Aes256GcmSha384,
    ];
    settings.signature_schemes = vec![
        SignatureScheme::EcdsaSecp256r1Sha256,
        SignatureScheme::EcdsaSecp384r1Sha384,
        SignatureScheme::EcdsaSecp521r1Sha512,
        SignatureScheme::EcdsaSha1,
        SignatureScheme::RsaPssRsaeSha256,
        SignatureScheme::RsaPssRsaeSha384,
        SignatureScheme::RsaPssRsaeSha512,
        SignatureScheme::RsaPkcs1Sha256,
        SignatureScheme::RsaPkcs1Sha384,
        SignatureScheme::RsaPkcs1Sha512,
        SignatureScheme::RsaPkcs1Sha1,
    ];
    settings.certificate_compression = vec![
        CertificateCompression::Zlib,
        CertificateCompression::Zstd,
        CertificateCompression::Brotli,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.request_signed_certificate_timestamps = false;
    settings.extension_order = ClientHelloExtensionOrder::PermutedWithTail(vec![
        ClientHelloExtension::QuicTransportParameters,
        ClientHelloExtension::EncryptedClientHello,
    ]);
    // QUIC early data follows `v157_quic`; this field covers TCP only.
    settings.tcp_early_data = false;
    settings
}

/// Returns QUIC transport settings observed from Firefox 157.0 on Windows 11.
///
/// Every parameter, its identifier and length widths, its value width, and
/// the fixed order come from the retained Firefox 157.0 QUIC ClientHellos:
/// three fresh processes and, in the resumption capture, fifteen more
/// connections, all with the same layout. The order is neqo's
/// transport-parameter table order.
///
/// - The receive windows differ by stream class: 12 MiB for streams Firefox
///   opens, 1 MiB for streams the server opens, 24 MiB for the connection.
/// - `max_ack_delay` is 20 ms and `active_connection_id_limit` is 8.
/// - The Source Connection ID is 3 bytes.
/// - `version_information` lists a reserved version first, then QUIC v2, then
///   QUIC v1. A fresh connection chooses v1; the aioquic capture server then
///   moved every such connection to v2 by compatible version negotiation.
///   Phantom follows a server that does so. A connection that presents a
///   ticket starts in the version of the connection that received it, as
///   every resumed Firefox connection started in v2.
/// - The empty `reset_stream_at` parameter (`0x1d`) and draft 02's
///   `min_ack_delay` (`0xff02de1a`, 1000 microseconds, an 8-byte identifier)
///   precede `max_datagram_frame_size` (65535).
/// - `max_udp_payload_size`, `grease_quic_bit`, and a reserved parameter are
///   absent.
///
/// The five snapshots record every Initial datagram Firefox sent over IPv4
/// loopback: 1252 bytes each, a 1280-byte path MTU less the IPv4 and UDP
/// headers, as neqo 0.31.1 computes it (`neqo-transport/src/pmtud.rs`). The
/// recipe sets that MTU, so Initial datagrams are 1252 bytes over IPv4 and
/// 1232 over IPv6. The first Initials' Destination Connection IDs were 8, 14,
/// 13, 8, and 8 bytes. The recipe draws that length as neqo's
/// `ConnectionId::generate_initial` does: `max(8, 5 + (b & (b >> 4)))` for a
/// random byte `b` (`neqo-transport/src/cid.rs` lines 54 to 59 in neqo
/// 0.31.1, the version Firefox 157.0 vendors).
///
/// A resumed Firefox connection offers early data, so `early_data` is set;
/// it takes effect with TLS settings that enable session tickets, such as
/// [`v157_quic_tls`]. No resumed connection sent `initial_rtt_us`.
#[must_use]
pub fn v157_quic() -> QuicTransportSettings {
    use QuicTransportParameterKind as Kind;
    use QuicVarIntWidth::{Eight, Four, One, Two};

    let parameter = |kind, id_width| QuicTransportParameter {
        kind,
        id_width,
        length_width: One,
    };

    QuicTransportSettings {
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 65_527,
        initial_max_data: 25_165_824,
        initial_max_stream_data_bidi_local: 12_582_912,
        initial_max_stream_data_bidi_remote: 1_048_576,
        initial_max_stream_data_uni: 1_048_576,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        max_datagram_frame_size: Some(65_535),
        max_ack_delay_ms: 20,
        active_connection_id_limit: 8,
        min_ack_delay_us: Some(1_000),
        reset_stream_at: true,
        initial_path_mtu: Some(1_280),
        initial_destination_connection_id: Some(QuicConnectionIdLength::MaskedRandom {
            minimum: 8,
            base: 5,
        }),
        wire_parameters: vec![
            parameter(Kind::MaxIdleTimeout { value_width: Four }, One),
            parameter(Kind::InitialMaxData { value_width: Four }, One),
            parameter(
                Kind::InitialMaxStreamDataBidiLocal { value_width: Four },
                One,
            ),
            parameter(
                Kind::InitialMaxStreamDataBidiRemote { value_width: Four },
                One,
            ),
            parameter(Kind::InitialMaxStreamDataUni { value_width: Four }, One),
            parameter(Kind::InitialMaxStreamsBidi { value_width: Two }, One),
            parameter(Kind::InitialMaxStreamsUni { value_width: Two }, One),
            parameter(Kind::MaxAckDelay { value_width: One }, One),
            parameter(Kind::ActiveConnectionIdLimit { value_width: One }, One),
            parameter(Kind::InitialSourceConnectionId { length: 3 }, One),
            parameter(
                Kind::VersionInformation(QuicVersionInformation {
                    available_version_count: 2,
                    grease: QuicVersionGrease::First,
                }),
                One,
            ),
            parameter(Kind::ResetStreamAt, One),
            parameter(
                Kind::MinAckDelay {
                    draft: QuicAckFrequencyDraft::Draft02,
                    value_width: Two,
                },
                Eight,
            ),
            parameter(Kind::MaxDatagramFrameSize { value_width: Four }, One),
        ],
        parameter_order: QuicTransportParameterOrder::Fixed,
        early_data: true,
    }
}

/// Returns HTTP/3 settings observed from Firefox 157.0 on Windows 11.
///
/// The six settings and their order come from the retained Firefox 157.0
/// control streams: a 64 KiB QPACK table, 20 blocked streams, draft 02's
/// `SETTINGS_ENABLE_WEBTRANSPORT` set to 0, the draft (`0xffd277`) and final
/// `SETTINGS_H3_DATAGRAM` set to 1, and `SETTINGS_ENABLE_CONNECT_PROTOCOL`
/// set to 1, each with a minimal-width value. The same control-stream write
/// carries one reserved frame after SETTINGS; its first STREAM frame held 35
/// to 39 bytes, 11 to 15 more than the type and SETTINGS, as neqo's
/// `HFrame::Grease` gives with an 8-byte type and 0 to 7 payload bytes.
///
/// The resumption capture that records client unidirectional streams shows
/// the control stream as client stream 2, the QPACK encoder stream as 6, and
/// the decoder stream as 10, each with its type in the first frame. The
/// encoder stream's first frame carried the Set Dynamic Table Capacity
/// instruction for the server's 4096-byte table with the type. The QPACK
/// encoding follows neqo: see [`Http3QpackEncoding::DynamicUnmatchedNames`],
/// whose unit test reproduces the captured encoder stream and field sections.
#[must_use]
pub fn v157_http3() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(65_536),
            Http3Setting::QpackBlockedStreams(20),
            Http3Setting::EnableWebTransportDraft02(false),
            Http3Setting::H3DatagramDraft04(true),
            Http3Setting::H3Datagram(true),
            Http3Setting::EnableConnectProtocol(true),
        ],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::DynamicUnmatchedNames,
        qpack_decoder_stream: Http3QpackDecoderStream::Eager,
        qpack_encoder_stream: Http3QpackEncoderStream::Eager,
        qpack_stream_order: Http3QpackStreamOrder::EncoderFirst,
        reserved_frame_after_settings: true,
    }
}

/// Returns HTTP/3 request ordering observed from Firefox 157.0 on Windows 11.
///
/// Every captured HTTP/3 request sends `:method`, `:scheme`, `:authority`,
/// and `:path` in that order. No capture backs an HTTP/3 extended CONNECT,
/// so [`Http3RequestSettings::extended_connect_pseudo_header_order`] is
/// `None`. The retained cookie captures (`fixtures/cookies/firefox/`) show
/// one joined `cookie` field over HTTP/3 ([`Http3CookieCrumbs::Whole`]).
///
/// A request to an alternative service carries `Alt-Used`
/// ([`Http3AltUsed::Append`]): Firefox names the field in
/// `netwerk/protocol/http/nsHttpAtomList.inc` (`Alternate_Service_Used`).
/// The retained cookie captures carry it on every HTTP/3 request, and the
/// snapshots on the fetch that follows the first navigation over HTTP/3,
/// which carries none. Phantom sends it on every request to an alternative,
/// and appends it last, where Firefox sends it after `accept-encoding`, or
/// after `referer` when there is one.
#[must_use]
pub fn v157_http3_request() -> Http3RequestSettings {
    Http3RequestSettings {
        pseudo_header_order: vec![
            Http3PseudoHeader::Method,
            Http3PseudoHeader::Scheme,
            Http3PseudoHeader::Authority,
            Http3PseudoHeader::Path,
        ],
        extended_connect_pseudo_header_order: None,
        cookie_crumbs: Http3CookieCrumbs::Whole,
        alt_used: Http3AltUsed::Append,
    }
}

const V157_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";
const V157_PLAINTEXT_ACCEPT_ENCODING: &str = "gzip, deflate";
const V157_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.9";
const V157_NAVIGATION_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const V157_WINDOWS_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0";
const V157_MACOS_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101 Firefox/157.0";

/// Returns Firefox 157's `Accept-Encoding` entry: `br` and `zstd` are offered
/// only to a potentially trustworthy URL.
///
/// `HttpBaseChannel::Init` passes `isSecureOrTrustworthyURL` (an `https`
/// scheme, or a loopback URL while `network.http.encoding.trustworthy_is_https`
/// is true, its default) to `nsHttpHandler::AddStandardRequestHeaders`, which
/// then sends `network.http.accept-encoding.secure` instead of
/// `network.http.accept-encoding` (`netwerk/protocol/http/HttpBaseChannel.cpp`
/// lines 325-329 and 351, `nsHttpHandler.cpp` lines 814-820, and
/// `modules/libpref/init/all.js` lines 1179-1180 at `FIREFOX_157_0_RELEASE`).
fn accept_encoding(name: &str) -> RequestField {
    RequestField::by_trust(name, V157_ACCEPT_ENCODING, V157_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns [`accept_encoding`] for a WebSocket opening template.
fn websocket_accept_encoding(name: &str) -> WebSocketField {
    WebSocketField::by_trust(name, V157_ACCEPT_ENCODING, V157_PLAINTEXT_ACCEPT_ENCODING)
}

/// Returns Firefox 157's position of forwarded proxy credentials it
/// remembers from an earlier challenge: before `Connection` on HTTP/1.1, and
/// where `Connection` would be on HTTP/2.
///
/// The retained `http-proxy-auth-*` and `https-proxy-auth-*` proxy route
/// captures show it after `Referer` on the `fetch()` that follows the
/// challenged navigation, and the `*-auth-remembered-hostname` captures show
/// it after `Accept-Encoding` on a navigation sent with remembered
/// credentials.
fn preemptive_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Preemptive)
}

/// Returns Firefox 157's position of forwarded proxy credentials on the
/// replay after a `407`: after every template field on HTTP/1.1, and before
/// `te` on HTTP/2.
///
/// The same captures show it there on the replayed navigation, the
/// `*-auth-remembered-hostname` captures on a replayed default-mode
/// `fetch()`, and the `*-auth-nostore-*` captures on a replayed no-store
/// `fetch()`, after `Pragma` and `Cache-Control`. Those captures also show
/// the remembered-credentials slot on a no-store `fetch()`.
fn replay_proxy_authorization(name: &str) -> RequestField {
    RequestField::proxy_authorization(name, ProxyAuthorizationAttempt::Replay)
}

/// Returns navigation request fields observed from Firefox 157.0 on Windows 11.
///
/// A top-level navigation the user starts from the address bar: an HTML
/// document request with `Sec-Fetch-Site: none` and `Sec-Fetch-User: ?1`.
/// The HTTP/1.1 order comes from plaintext loopback page loads in the
/// retained SSE and WebSocket captures and the HTTP/2 order from the page
/// requests of the WebSocket captures; every run agrees. Firefox sends
/// `Priority` on HTTP/1.1 too and ends HTTP/2 requests with `te: trailers`.
/// The HTTP/3 list is the HTTP/2 order without `te`. The retained Firefox
/// 157.0 HTTP/3 snapshots and cookie captures show a script navigation,
/// which adds `referer` after `accept-encoding` and has no `Sec-Fetch-User`;
/// the fields it shares with this list come in the same order. On requests
/// to an origin it reached through Alt-Svc, Firefox sends `Alt-Used` after
/// `accept-encoding`, or after `referer` when there is one. Phantom
/// generates that field and appends it last. Each captured HTTP/2 page
/// request carries HEADERS priority weight 42, not exclusive, on stream 0,
/// which is also [`v157_http2`]'s connection priority.
///
/// The `User-Agent` value is the one Firefox sent in those headless
/// captures. `Accept-Language` is the capture machine's `en-US` locale. A
/// caller field with the same name replaces a captured value in place.
/// Firefox sends no client hints, so the template has no client-hint slot,
/// and the `phantom` client refuses it with a profile that sends default
/// client hints.
///
/// Firefox sends the `Sec-Fetch-*` fields, and `br` and `zstd` in
/// `Accept-Encoding`, only to a potentially trustworthy URL, so those entries
/// are [`RequestField::ByTrust`]. `SecFetch::AddSecFetchHeader` returns early
/// unless `nsMixedContentBlocker::IsPotentiallyTrustworthyOrigin` holds
/// (`dom/security/SecFetch.cpp` lines 383-387 at `FIREFOX_157_0_RELEASE`). The
/// retained proxy route captures show the navigation to the plaintext name
/// `origin.phantom.test` without them, with `Accept-Encoding: gzip, deflate`,
/// and with the remaining fields in the same order on HTTP/1.1 and HTTP/2.
#[must_use]
pub fn v157_windows_navigation_template() -> RequestTemplate {
    navigation_template(V157_WINDOWS_USER_AGENT)
}

/// Returns navigation request fields observed from Firefox 157.0 on macOS
/// 15.5 arm64.
///
/// The fields, order, values, and HTTP/2 priority are those of
/// [`v157_windows_navigation_template`], except `User-Agent`, which is the
/// value Firefox 157.0 sent in the headless WebSocket and client-hint
/// captures on macOS 15.5 (24F74) on Apple silicon:
/// `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:157.0) Gecko/20100101
/// Firefox/157.0`. It names `Intel Mac OS X 10.15`, not the host's 15.5 or
/// its Apple silicon CPU. `Accept-Language` is the capture host's `en-US`
/// locale.
#[must_use]
pub fn v157_macos_navigation_template() -> RequestTemplate {
    navigation_template(V157_MACOS_USER_AGENT)
}

/// Builds the Firefox navigation lists with a literal `User-Agent`.
fn navigation_template(user_agent: &str) -> RequestTemplate {
    RequestTemplate {
        http1_fields: vec![
            RequestField::literal("User-Agent", user_agent),
            RequestField::literal("Accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("Accept-Language", V157_ACCEPT_LANGUAGE),
            accept_encoding("Accept-Encoding"),
            preemptive_proxy_authorization("Proxy-Authorization"),
            RequestField::literal("Connection", "keep-alive"),
            RequestField::literal("Upgrade-Insecure-Requests", "1"),
            RequestField::trustworthy_only("Sec-Fetch-Dest", "document"),
            RequestField::trustworthy_only("Sec-Fetch-Mode", "navigate"),
            RequestField::trustworthy_only("Sec-Fetch-Site", "none"),
            RequestField::trustworthy_only("Sec-Fetch-User", "?1"),
            RequestField::literal("Priority", "u=0, i"),
            replay_proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            RequestField::literal("user-agent", user_agent),
            RequestField::literal("accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
            accept_encoding("accept-encoding"),
            preemptive_proxy_authorization("proxy-authorization"),
            RequestField::literal("upgrade-insecure-requests", "1"),
            RequestField::trustworthy_only("sec-fetch-dest", "document"),
            RequestField::trustworthy_only("sec-fetch-mode", "navigate"),
            RequestField::trustworthy_only("sec-fetch-site", "none"),
            RequestField::trustworthy_only("sec-fetch-user", "?1"),
            RequestField::literal("priority", "u=0, i"),
            replay_proxy_authorization("proxy-authorization"),
            RequestField::literal("te", "trailers"),
        ],
        http3_fields: Some(vec![
            RequestField::literal("user-agent", user_agent),
            RequestField::literal("accept", V157_NAVIGATION_ACCEPT),
            RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
            accept_encoding("accept-encoding"),
            RequestField::literal("upgrade-insecure-requests", "1"),
            RequestField::trustworthy_only("sec-fetch-dest", "document"),
            RequestField::trustworthy_only("sec-fetch-mode", "navigate"),
            RequestField::trustworthy_only("sec-fetch-site", "none"),
            RequestField::trustworthy_only("sec-fetch-user", "?1"),
            RequestField::literal("priority", "u=0, i"),
        ]),
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
        requested_client_hint_placement: false,
        // Firefox sends no client hints and ignores ACCEPT_CH.
        restarts_for_connection_accept_ch: false,
    }
}

/// Returns same-origin `fetch` request fields observed from Firefox 157.0 on Windows 11.
///
/// A script `fetch(url, {cache: "no-store"})` GET to the page's own origin;
/// the cache mode adds `Pragma` and `Cache-Control`, which Firefox sends
/// last on HTTP/1.1 and before `te: trailers` on HTTP/2. The orders come from
/// the final report request of the WebSocket captures, and every run agrees.
/// Each captured HTTP/2 fetch carries HEADERS priority weight 22, not
/// exclusive, on stream 0, unlike the navigation's 42 in [`v157_http2`];
/// [`RequestTemplate::http2_priority`] records it so the fetch does not go
/// out with the connection's navigation weight.
/// `Referer` is a caller slot because its value is the page URL. The
/// `User-Agent` value matches [`v157_windows_navigation_template`]. Like it,
/// this template has no client-hint slot, and the `phantom` client refuses
/// it with a profile that sends default client hints.
///
/// As on the navigation, the `Sec-Fetch-*` fields and the `br` and `zstd`
/// codings are sent only to a potentially trustworthy URL. The proxy route
/// captures back that shape with a same-origin `fetch()` in the default cache
/// mode, and the `*-auth-nostore-*` captures with a no-store `fetch()` through
/// a proxy to both kinds of origin, `Pragma` and `Cache-Control` included.
#[must_use]
pub fn v157_windows_fetch_no_store_template() -> RequestTemplate {
    fetch_template(V157_WINDOWS_USER_AGENT, FetchCache::NoStore)
}

/// Returns same-origin `fetch` request fields observed from Firefox 157.0 on
/// macOS 15.5 arm64.
///
/// The fields, order, values, and HTTP/2 priority are those of
/// [`v157_windows_fetch_no_store_template`], except `User-Agent`, which
/// matches [`v157_macos_navigation_template`].
#[must_use]
pub fn v157_macos_fetch_no_store_template() -> RequestTemplate {
    fetch_template(V157_MACOS_USER_AGENT, FetchCache::NoStore)
}

/// Returns same-origin `fetch` request fields of Firefox 157 on Windows 11 in
/// the default cache mode, with slots for the validators of a revalidation.
///
/// A script `fetch(url)` GET to the page's own origin. The fields, values,
/// and HTTP/2 priority are those of
/// [`v157_windows_fetch_no_store_template`] without `Pragma` and
/// `Cache-Control`, which only the no-store mode adds; the proxy route
/// captures show the default-mode `fetch()` with that shape. When the cache
/// revalidates a response, Firefox adds `If-Modified-Since`, then
/// `If-None-Match`, after `Sec-Fetch-Site` and before `Priority`. Phantom has
/// no HTTP cache, so both are optional caller slots: a caller that
/// revalidates its own cached response supplies the fields, and they go
/// there. The retained Firefox 157 revalidation capture shows that HTTP/2
/// order with either field and with both. The HTTP/1.1 and HTTP/3 positions
/// follow from Firefox source: `nsHttpChannel::OnCacheEntryCheck` adds the
/// validators after the `Sec-Fetch-*` fields and before
/// `SetupChannelForTransaction` adds `Priority`
/// (`netwerk/protocol/http/nsHttpChannel.cpp:5598`, `:5605`, `:1866` at tag
/// `FIREFOX_157_0_RELEASE`), and every protocol keeps the request's order.
#[must_use]
pub fn v157_windows_fetch_template() -> RequestTemplate {
    fetch_template(V157_WINDOWS_USER_AGENT, FetchCache::Default)
}

/// Returns same-origin POST upload fields for Firefox 157 on Windows 11.
///
/// You supply `Origin`, `Referer`, and HTTP/1.1 `Priority`. `Content-Type` and
/// `Content-Length` are optional caller slots. `prepared_body()` fills these
/// slots automatically. With a raw `body()`, an omitted length follows these
/// fields when the body is nonempty, has a known length, and has no trailers.
///
/// The field order follows `upload-{h1,h2}.txt` under
/// `fixtures/lifecycle/firefox/157.0/windows-11-26200/`.
/// Text, Blob, and multipart uploads share this order. A Blob without a type
/// omits `Content-Type`. The captures record multipart body byte counts,
/// not boundary formatting or escaping. They
/// record the `Priority` name without its value, so HTTP/1.1 requires yours.
/// Other values, HTTP/2 priority, `priority: u=4`, `te: trailers`, and proxy
/// credential placement use [`v157_windows_fetch_template`]'s same-origin
/// fetch policy. There is no HTTP/3, navigation POST, or form-submit list.
#[must_use]
pub fn v157_windows_fetch_upload_template() -> RequestTemplate {
    let mut template = v157_windows_fetch_template();
    for (fields, content_type, length, origin, referer) in [
        (
            &mut template.http1_fields,
            "Content-Type",
            "Content-Length",
            "Origin",
            "Referer",
        ),
        (
            &mut template.http2_fields,
            "content-type",
            "content-length",
            "origin",
            "referer",
        ),
    ] {
        let mut upload = Vec::with_capacity(fields.len() + 1);
        for field in fields.drain(..) {
            let name = field.name().unwrap_or("");
            if name.eq_ignore_ascii_case("if-none-match")
                || name.eq_ignore_ascii_case("if-modified-since")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("referer") {
                upload.extend([
                    RequestField::required_caller(referer),
                    RequestField::caller(content_type),
                    RequestField::caller(length),
                    RequestField::required_caller(origin),
                ]);
            } else if name == "Priority" {
                upload.push(RequestField::required_caller("Priority"));
            } else {
                upload.push(field);
            }
        }
        *fields = upload;
    }
    template.http3_fields = None;
    template
}

/// Returns same-origin `fetch` request fields of Firefox 157 on macOS 15.5
/// arm64 in the default cache mode, with slots for the validators of a
/// revalidation.
///
/// The fields, order, values, and HTTP/2 priority are those of
/// [`v157_windows_fetch_template`], except `User-Agent`, which matches
/// [`v157_macos_navigation_template`].
#[must_use]
pub fn v157_macos_fetch_template() -> RequestTemplate {
    fetch_template(V157_MACOS_USER_AGENT, FetchCache::Default)
}

/// The cache mode of a same-origin `fetch`, which decides its cache fields.
#[derive(Clone, Copy, Eq, PartialEq)]
enum FetchCache {
    /// The default mode: no cache fields of its own, and the validators of a
    /// cached response when the cache revalidates it.
    Default,
    /// `no-store`: `Pragma` and `Cache-Control` set to `no-cache`.
    NoStore,
}

/// Builds the Firefox `fetch` lists for `cache` with a literal `User-Agent`.
fn fetch_template(user_agent: &str, cache: FetchCache) -> RequestTemplate {
    let cache_fields = |pragma: &str, cache_control: &str| match cache {
        FetchCache::NoStore => vec![
            RequestField::literal(pragma, "no-cache"),
            RequestField::literal(cache_control, "no-cache"),
        ],
        FetchCache::Default => Vec::new(),
    };
    let validators = |if_modified_since: &str, if_none_match: &str| match cache {
        FetchCache::Default => vec![
            RequestField::caller(if_modified_since),
            RequestField::caller(if_none_match),
        ],
        FetchCache::NoStore => Vec::new(),
    };
    let mut http1_fields = vec![
        RequestField::literal("User-Agent", user_agent),
        RequestField::literal("Accept", "*/*"),
        RequestField::literal("Accept-Language", V157_ACCEPT_LANGUAGE),
        accept_encoding("Accept-Encoding"),
        RequestField::caller("Referer"),
        preemptive_proxy_authorization("Proxy-Authorization"),
        RequestField::literal("Connection", "keep-alive"),
        RequestField::trustworthy_only("Sec-Fetch-Dest", "empty"),
        RequestField::trustworthy_only("Sec-Fetch-Mode", "cors"),
        RequestField::trustworthy_only("Sec-Fetch-Site", "same-origin"),
    ];
    http1_fields.extend(validators("If-Modified-Since", "If-None-Match"));
    http1_fields.push(RequestField::literal("Priority", "u=4"));
    http1_fields.extend(cache_fields("Pragma", "Cache-Control"));
    http1_fields.push(replay_proxy_authorization("Proxy-Authorization"));
    let mut http2_fields = vec![
        RequestField::literal("user-agent", user_agent),
        RequestField::literal("accept", "*/*"),
        RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
        accept_encoding("accept-encoding"),
        RequestField::caller("referer"),
        preemptive_proxy_authorization("proxy-authorization"),
        RequestField::trustworthy_only("sec-fetch-dest", "empty"),
        RequestField::trustworthy_only("sec-fetch-mode", "cors"),
        RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
    ];
    http2_fields.extend(validators("if-modified-since", "if-none-match"));
    http2_fields.push(RequestField::literal("priority", "u=4"));
    http2_fields.extend(cache_fields("pragma", "cache-control"));
    http2_fields.extend([
        replay_proxy_authorization("proxy-authorization"),
        RequestField::literal("te", "trailers"),
    ]);
    let mut http3_fields = vec![
        RequestField::literal("user-agent", user_agent),
        RequestField::literal("accept", "*/*"),
        RequestField::literal("accept-language", V157_ACCEPT_LANGUAGE),
        accept_encoding("accept-encoding"),
        RequestField::caller("referer"),
        RequestField::trustworthy_only("sec-fetch-dest", "empty"),
        RequestField::trustworthy_only("sec-fetch-mode", "cors"),
        RequestField::trustworthy_only("sec-fetch-site", "same-origin"),
    ];
    http3_fields.extend(validators("if-modified-since", "if-none-match"));
    http3_fields.push(RequestField::literal("priority", "u=4"));
    http3_fields.extend(cache_fields("pragma", "cache-control"));
    RequestTemplate {
        http1_fields,
        http2_fields,
        http3_fields: Some(http3_fields),
        http2_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 22,
            exclusive: false,
        }),
        requested_client_hint_placement: false,
        // Firefox sends no client hints and ignores ACCEPT_CH.
        restarts_for_connection_accept_ch: false,
    }
}

/// Returns the Windows connection profile for Firefox 157.
///
/// Includes TCP, HTTP/1.1 policy, address cache, HTTP/2, HTTP/3, WebSocket,
/// proxy CONNECT fields, and cookie placement.
/// Firefox sends no client hints, and no UDP socket recipe is supplied.
/// No request template is selected. Choose one for your request kind.
#[must_use]
pub fn v157_windows() -> ClientProfile {
    ClientProfile::new(v157_tcp_tls())
        .with_tcp(v157_tcp())
        .with_dns_cache(v157_dns_cache())
        .with_http1(v157_http1())
        .with_http2(v157_http2())
        .with_http3(Http3ClientSettings::new(
            v157_quic_tls(),
            v157_quic(),
            v157_http3(),
            v157_http3_request(),
        ))
        .with_websocket(v157_websocket())
        .with_proxy_connect(v157_proxy_connect())
        .with_cookie_placement(v157_cookie_placement())
}

/// Returns the captured Android layers for Firefox 156.
///
/// Supplies TCP TLS only.
/// TCP socket, UDP socket, HTTP/1.1 policy, address-cache, proxy CONNECT,
/// and cookie-placement recipes are absent. Their generic defaults remain.
/// No request template is selected. These captures came from emulators.
#[must_use]
pub fn v156_android() -> ClientProfile {
    ClientProfile::new(v156_android_tcp_tls())
}

#[cfg(test)]
mod hook_tests;

#[cfg(test)]
mod tests;
