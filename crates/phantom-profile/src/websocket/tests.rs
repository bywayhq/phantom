use std::collections::BTreeMap;

use super::{
    WebSocketConnectionPolicy, WebSocketDeflateParameter, WebSocketEmptyMessageCompression,
    WebSocketField, WebSocketNewConnection, WebSocketRefusedStreamRetry, WebSocketSettings,
};
use crate::{
    AlpsSettings, Http2Priority, Http2PseudoHeader, Http2Settings, TlsSettings, chromium, firefox,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SCENARIOS: [&str; 9] = [
    "accept",
    "accept-deflate",
    "extension-mismatch",
    "fresh-origin",
    "h1-accept",
    "h1-accept-deflate",
    "no-connect-protocol",
    "refused-stream",
    "reject-403",
];

macro_rules! fixture_set {
    ($browser:literal, $version:literal) => {
        [
            fixture_set!(@one $browser, $version, "accept"),
            fixture_set!(@one $browser, $version, "accept-deflate"),
            fixture_set!(@one $browser, $version, "extension-mismatch"),
            fixture_set!(@one $browser, $version, "fresh-origin"),
            fixture_set!(@one $browser, $version, "h1-accept"),
            fixture_set!(@one $browser, $version, "h1-accept-deflate"),
            fixture_set!(@one $browser, $version, "no-connect-protocol"),
            fixture_set!(@one $browser, $version, "refused-stream"),
            fixture_set!(@one $browser, $version, "reject-403"),
        ]
    };
    (@one $browser:literal, $version:literal, $scenario:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/websocket/",
            $browser,
            "/",
            $version,
            "/windows-11-26200/",
            $scenario,
            ".txt"
        ))
    };
}

const CHROME: [&str; 9] = fixture_set!("chrome", "153.0.8010.48");
const EDGE: [&str; 9] = fixture_set!("edge", "153.0.4234.48");
const FIREFOX: [&str; 9] = fixture_set!("firefox", "156.0");

#[test]
fn chromium_153_websocket_recipe_matches_chrome_and_edge_captures() -> TestResult {
    let recipe = chromium::v153_websocket();
    let http2 = chromium::v153_http2();
    let tls = chromium::v153_tls();
    // Chrome used its page session in two of three `refused-stream` runs; in
    // the third the session closed before the socket opened.
    // Chrome's first `refused-stream` run opened over HTTP/1.1 instead, so it
    // carries no refusal to compare.
    for (fixtures, client, reused, http1, refused) in [
        (CHROME, "Google Chrome", 14, 7, 2),
        (EDGE, "Microsoft Edge", 15, 6, 3),
    ] {
        let summary = assert_recipe_matches(&fixtures, client, &recipe, &http2, &tls)?;
        assert_eq!(summary.reused_sessions, reused, "{client}");
        assert_eq!(summary.new_http2_connections, 0, "{client}");
        assert_eq!(summary.http1_upgrade_connections, http1, "{client}");
        assert_eq!(summary.empty_message_runs, 6, "{client}");
        assert_eq!(summary.refused_stream_runs, refused, "{client}");
    }
    Ok(())
}

#[test]
fn firefox_156_websocket_recipe_matches_captures() -> TestResult {
    let summary = assert_recipe_matches(
        &FIREFOX,
        "Mozilla Firefox",
        &firefox::v156_websocket(),
        &firefox::v156_http2(),
        &firefox::v156_tls(),
    )?;
    assert_eq!(summary.reused_sessions, 15);
    assert_eq!(summary.new_http2_connections, 3);
    assert_eq!(summary.http1_upgrade_connections, 3);
    assert_eq!(summary.empty_message_runs, 6);
    assert_eq!(summary.refused_stream_runs, 3);
    Ok(())
}

#[test]
fn http1_upgrade_tls_settings_replace_only_alpn_and_unoffered_alps() {
    let policy = chromium::v153_websocket().connection;
    let base = chromium::v153_tls();
    let derived = policy.http1_tls_settings(&base);

    assert_eq!(derived.alpn_protocols, [Box::from(*b"http/1.1")]);
    assert_eq!(derived.alps, None);
    let mut restored = derived;
    restored.alpn_protocols.clone_from(&base.alpn_protocols);
    restored.alps.clone_from(&base.alps);
    assert_eq!(restored, base);

    let mut http1_alps = base;
    http1_alps.alps = Some(AlpsSettings {
        protocol: Box::from(*b"http/1.1"),
        settings: Box::from([]),
        use_new_codepoint: true,
    });
    assert_eq!(policy.http1_tls_settings(&http1_alps).alps, http1_alps.alps);
}

#[test]
fn validation_rejects_alpn_that_cannot_carry_an_upgrade() {
    let mut settings = firefox::v156_websocket();
    settings.connection.http1_alpn_protocols = vec![Box::from(*b"h2"), Box::from(*b"http/1.1")];
    assert_eq!(
        settings.validate().map_err(|error| error.field()),
        Err("connection.http1_alpn_protocols")
    );
    settings.connection.http1_alpn_protocols = Vec::new();
    assert!(settings.validate().is_err());
}

#[test]
fn validation_rejects_templates_unusable_by_their_protocol() {
    let mut settings = chromium::v153_websocket();
    settings
        .http2_fields
        .push(WebSocketField::caller("User-Agent"));
    assert_eq!(
        settings.validate().map_err(|error| error.field()),
        Err("http2_fields")
    );

    let mut settings = chromium::v153_websocket();
    settings
        .http2_fields
        .push(WebSocketField::key("sec-websocket-key"));
    assert!(settings.validate().is_err());

    let mut settings = chromium::v153_websocket();
    settings
        .http1_fields
        .retain(|field| !matches!(field, WebSocketField::Key { .. }));
    assert_eq!(
        settings.validate().map_err(|error| error.field()),
        Err("http1_fields")
    );

    let mut settings = chromium::v153_websocket();
    settings
        .http1_fields
        .push(WebSocketField::literal("Bad Name", "x"));
    assert!(settings.validate().is_err());
}

#[test]
fn validation_rejects_invalid_deflate_offers() {
    let mut settings = firefox::v156_websocket();
    settings.permessage_deflate_offer = vec![
        WebSocketDeflateParameter::ClientMaxWindowBits(None),
        WebSocketDeflateParameter::ClientMaxWindowBits(Some(10)),
    ];
    assert!(settings.validate().is_err());
    settings.permessage_deflate_offer = vec![WebSocketDeflateParameter::ServerMaxWindowBits(16)];
    assert_eq!(
        settings.validate().map_err(|error| error.field()),
        Err("permessage_deflate_offer")
    );
}

#[derive(Default)]
struct PolicySummary {
    reused_sessions: usize,
    new_http2_connections: usize,
    http1_upgrade_connections: usize,
    /// Runs that sent an empty message over a compressed socket.
    empty_message_runs: usize,
    /// Runs whose extended CONNECT stream was refused.
    refused_stream_runs: usize,
}

fn assert_recipe_matches(
    fixtures: &[&str; 9],
    client: &str,
    recipe: &WebSocketSettings,
    http2: &Http2Settings,
    tls: &TlsSettings,
) -> TestResult<PolicySummary> {
    recipe.validate()?;
    http2.validate()?;
    let expected_pseudo = http2
        .extended_connect_pseudo_header_order
        .as_deref()
        .ok_or("recipe omits the extended CONNECT order")?;
    let expected_priority = http2
        .extended_connect_priority
        .ok_or("recipe omits the extended CONNECT priority")?;
    let offer = render_offer(&recipe.permessage_deflate_offer);
    let mut summary = PolicySummary::default();

    for (input, scenario) in fixtures.iter().zip(SCENARIOS) {
        let capture = Capture::parse(input)?;
        assert_eq!(capture.value("client")?, client);
        assert_eq!(capture.value("scenario")?, scenario);
        let secure = capture.value("socket_scheme")? == "wss";
        for run in 0..capture.value("repeat_count")?.parse::<usize>()? {
            if let Some(observed) = capture.empty_message_compression(run)? {
                assert_eq!(
                    observed, recipe.empty_message_compression,
                    "{client} {scenario} run {run}"
                );
                summary.empty_message_runs += 1;
            }
            if let Some(observed) = capture.refused_stream_retry(run)? {
                assert_eq!(
                    observed, recipe.connection.refused_stream_retry,
                    "{client} {scenario} run {run}"
                );
                summary.refused_stream_runs += 1;
            }
            let mut websocket_connection = None;
            for connect in capture.connect_headers(run)? {
                assert_eq!(connect.pseudo, expected_pseudo, "{scenario} run {run}");
                assert_eq!(connect.priority, expected_priority, "{scenario} run {run}");
                assert_template(&recipe.http2_fields, &connect.fields, &offer)?;
                websocket_connection = Some((connect.connection, true));
            }
            for request in capture.websocket_requests(run)? {
                assert_template(&recipe.http1_fields, &request.fields, &offer)?;
                websocket_connection = Some((request.connection, false));
            }
            let (connection, extended_connect) =
                websocket_connection.ok_or("run opened no WebSocket")?;
            if !secure {
                assert!(!extended_connect);
                assert_eq!(capture.connection(run, connection)?.alpn_offer, "none");
                continue;
            }
            let record = capture.connection(run, connection)?;
            match (extended_connect, record.carried_navigation) {
                (true, true) => summary.reused_sessions += 1,
                (true, false) => {
                    assert_eq!(
                        recipe.connection.without_http2_session,
                        WebSocketNewConnection::Http2ExtendedConnect
                    );
                    assert_eq!(record.alpn_offer, render_alpn(&tls.alpn_protocols));
                    summary.new_http2_connections += 1;
                }
                (false, _) => {
                    let case = if capture.value("page_listener")? == "tls"
                        && capture.value("server_connect_protocol")? == "false"
                    {
                        recipe.connection.with_incapable_http2_session
                    } else {
                        recipe.connection.without_http2_session
                    };
                    assert_eq!(case, WebSocketNewConnection::Http1Upgrade, "{scenario}");
                    assert_eq!(
                        record.alpn_offer,
                        render_alpn(&recipe.connection.http1_alpn_protocols)
                    );
                    summary.http1_upgrade_connections += 1;
                }
            }
        }
    }
    Ok(summary)
}

/// Checks that captured ordinary fields are the template with optional slots
/// removed: literals must appear with their exact value, caller slots and the
/// compression placeholder may be absent, and cookies are never captured.
fn assert_template(
    template: &[WebSocketField],
    observed: &[(String, String)],
    offer: &str,
) -> TestResult {
    let mut observed = observed.iter().peekable();
    for field in template {
        let (name, value, required) = match field {
            WebSocketField::Literal { name, value } => (name, Some(value.as_ref()), true),
            WebSocketField::Authority { name } | WebSocketField::Key { name } => (name, None, true),
            WebSocketField::Caller { name } => (name, None, false),
            WebSocketField::PerMessageDeflate { name } => (name, Some(offer), false),
            WebSocketField::ClientCookies { .. } => continue,
        };
        match observed.peek() {
            Some((observed_name, observed_value)) if observed_name == name.as_ref() => {
                if let Some(value) = value {
                    assert_eq!(observed_value, value, "{name}");
                }
                observed.next();
            }
            _ if required => return Err(format!("capture omitted {name}").into()),
            _ => {}
        }
    }
    if let Some((name, _)) = observed.next() {
        return Err(format!("capture field {name} is outside the template").into());
    }
    Ok(())
}

fn render_offer(parameters: &[WebSocketDeflateParameter]) -> String {
    let mut offer = String::from("permessage-deflate");
    for parameter in parameters {
        offer.push_str("; ");
        match parameter {
            WebSocketDeflateParameter::ServerNoContextTakeover => {
                offer.push_str("server_no_context_takeover");
            }
            WebSocketDeflateParameter::ClientNoContextTakeover => {
                offer.push_str("client_no_context_takeover");
            }
            WebSocketDeflateParameter::ServerMaxWindowBits(bits) => {
                offer.push_str(&format!("server_max_window_bits={bits}"));
            }
            WebSocketDeflateParameter::ClientMaxWindowBits(None) => {
                offer.push_str("client_max_window_bits");
            }
            WebSocketDeflateParameter::ClientMaxWindowBits(Some(bits)) => {
                offer.push_str(&format!("client_max_window_bits={bits}"));
            }
        }
    }
    offer
}

fn render_alpn(protocols: &[Box<[u8]>]) -> String {
    protocols
        .iter()
        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
        .collect::<Vec<_>>()
        .join(";")
}

struct Capture<'a> {
    fields: BTreeMap<&'a str, &'a str>,
}

struct ConnectionRecord<'a> {
    alpn_offer: &'a str,
    carried_navigation: bool,
}

struct ConnectHeaders {
    connection: usize,
    pseudo: Vec<Http2PseudoHeader>,
    priority: Http2Priority,
    fields: Vec<(String, String)>,
}

struct UpgradeRequest {
    connection: usize,
    fields: Vec<(String, String)>,
}

impl<'a> Capture<'a> {
    fn parse(input: &'a str) -> TestResult<Self> {
        let mut fields = BTreeMap::new();
        for line in input.lines() {
            let (key, value) = line.split_once('=').ok_or("capture line is missing `=`")?;
            if fields.insert(key, value).is_some() {
                return Err(format!("capture repeats {key}").into());
            }
        }
        let capture = Self { fields };
        assert_eq!(capture.value("format")?, "phantom-http2-websocket-v1");
        Ok(capture)
    }

    fn value(&self, key: &str) -> TestResult<&'a str> {
        self.fields
            .get(key)
            .copied()
            .ok_or_else(|| format!("capture omitted {key}").into())
    }

    fn connection(&self, run: usize, connection: usize) -> TestResult<ConnectionRecord<'a>> {
        let prefix = format!("run_{run}_connection_{connection}");
        let record = self.value(&prefix)?;
        let mut carried_navigation = false;
        for index in 0..self.header_count(&prefix)? {
            let block = self.header_block(&format!("{prefix}_headers_{index}"))?;
            carried_navigation |= block
                .iter()
                .any(|(name, value)| name == ":method" && value == "GET");
        }
        Ok(ConnectionRecord {
            alpn_offer: attribute(record, "alpn_offer")?,
            carried_navigation,
        })
    }

    fn connect_headers(&self, run: usize) -> TestResult<Vec<ConnectHeaders>> {
        let mut found = Vec::new();
        for connection in 0..self
            .value(&format!("run_{run}_connection_count"))?
            .parse()?
        {
            let prefix = format!("run_{run}_connection_{connection}");
            for index in 0..self.header_count(&prefix)? {
                let key = format!("{prefix}_headers_{index}");
                let block = self.header_block(&key)?;
                if !block
                    .iter()
                    .any(|(name, value)| name == ":method" && value == "CONNECT")
                {
                    continue;
                }
                let record = self.value(&key)?;
                let pseudo = block
                    .iter()
                    .filter(|(name, _)| name.starts_with(':'))
                    .map(|(name, _)| parse_pseudo_header(name))
                    .collect::<TestResult<Vec<_>>>()?;
                found.push(ConnectHeaders {
                    connection,
                    pseudo,
                    priority: Http2Priority {
                        dependency_stream_id: attribute(record, "depends_on")?.parse()?,
                        weight: attribute(record, "weight")?.parse()?,
                        exclusive: attribute(record, "priority:exclusive")? == "true",
                    },
                    fields: block
                        .into_iter()
                        .filter(|(name, _)| !name.starts_with(':'))
                        .collect(),
                });
            }
        }
        Ok(found)
    }

    fn websocket_requests(&self, run: usize) -> TestResult<Vec<UpgradeRequest>> {
        let Some(count) = self.fields.get(format!("run_{run}_request_count").as_str()) else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for index in 0..count.parse::<usize>()? {
            let prefix = format!("run_{run}_request_{index}");
            let record = self.value(&prefix)?;
            if attribute(record, "kind")? != "websocket" {
                continue;
            }
            let mut fields = Vec::new();
            for field in 0..self
                .value(&format!("{prefix}_header_count"))?
                .parse::<usize>()?
            {
                let line = decode_hex(self.value(&format!("{prefix}_header_{field}"))?)?;
                let (name, value) = line.split_once(": ").ok_or("H1 field has no `: `")?;
                fields.push((name.to_owned(), value.to_owned()));
            }
            found.push(UpgradeRequest {
                connection: attribute(record, "connection")?.parse()?,
                fields,
            });
        }
        Ok(found)
    }

    /// The empty-message rule this run's compressed socket followed, if it
    /// sent an empty message while `permessage-deflate` was in use.
    fn empty_message_compression(
        &self,
        run: usize,
    ) -> TestResult<Option<WebSocketEmptyMessageCompression>> {
        for socket in 0..self.value(&format!("run_{run}_websocket_count"))?.parse()? {
            let prefix = format!("run_{run}_websocket_{socket}");
            if self.value(&format!("{prefix}_extensions_selected_hex"))? == "none" {
                continue;
            }
            let Some(count) = self.fields.get(format!("{prefix}_message_count").as_str()) else {
                continue;
            };
            for index in 0..count.parse::<usize>()? {
                let message = self.value(&format!("{prefix}_message_{index}"))?;
                if attribute(message, "decoded_length")? != "0" {
                    continue;
                }
                return Ok(Some(if attribute(message, "rsv1")? == "true" {
                    WebSocketEmptyMessageCompression::Compressed
                } else {
                    WebSocketEmptyMessageCompression::Uncompressed
                }));
            }
        }
        Ok(None)
    }

    /// What this run did after an extended CONNECT stream was refused, if one
    /// was refused at all.
    fn refused_stream_retry(&self, run: usize) -> TestResult<Option<WebSocketRefusedStreamRetry>> {
        let count: usize = self.value(&format!("run_{run}_websocket_count"))?.parse()?;
        let mut refused = None;
        for socket in 0..count {
            let record = self.value(&format!("run_{run}_websocket_{socket}"))?;
            if attribute(record, "protocol")? != "h2" {
                continue;
            }
            let connection = attribute(record, "connection")?;
            let stream: u32 = attribute(record, "stream")?.parse()?;
            match attribute(record, "outcome")? {
                "refused" => refused = Some((connection, stream)),
                "accepted" => {
                    if refused.is_some_and(|(refused_connection, refused_stream)| {
                        refused_connection == connection && stream > refused_stream
                    }) {
                        return Ok(Some(WebSocketRefusedStreamRetry::SameSessionOnce));
                    }
                }
                _ => {}
            }
        }
        Ok(refused.map(|_| WebSocketRefusedStreamRetry::None))
    }

    fn header_count(&self, prefix: &str) -> TestResult<usize> {
        self.fields
            .get(format!("{prefix}_headers_count").as_str())
            .map_or(Ok(0), |count| Ok(count.parse()?))
    }

    /// Decoded names and values of one client HEADERS block, in wire order.
    fn header_block(&self, key: &str) -> TestResult<Vec<(String, String)>> {
        let count: usize = self.value(&format!("{key}_field_count"))?.parse()?;
        let mut fields = Vec::with_capacity(count);
        for index in 0..count {
            let field = self.value(&format!("{key}_field_{index}"))?;
            if attribute(field, "repr")? == "size-update" {
                continue;
            }
            fields.push((
                decode_hex(attribute(field, "name_hex")?)?,
                decode_hex(attribute(field, "value_hex")?)?,
            ));
        }
        Ok(fields)
    }
}

/// Returns `name:value` from a comma-separated capture record.
fn attribute<'a>(record: &'a str, name: &str) -> TestResult<&'a str> {
    record
        .split(',')
        .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
        .ok_or_else(|| format!("capture record omitted {name}").into())
}

fn decode_hex(value: &str) -> TestResult<String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal value".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(String::from_utf8(bytes)?)
}

fn parse_pseudo_header(name: &str) -> TestResult<Http2PseudoHeader> {
    match name {
        ":method" => Ok(Http2PseudoHeader::Method),
        ":authority" => Ok(Http2PseudoHeader::Authority),
        ":scheme" => Ok(Http2PseudoHeader::Scheme),
        ":path" => Ok(Http2PseudoHeader::Path),
        ":protocol" => Ok(Http2PseudoHeader::Protocol),
        _ => Err(format!("unsupported pseudo-header {name}").into()),
    }
}

#[test]
fn policy_type_is_plain_profile_data() {
    let policy = WebSocketConnectionPolicy {
        without_http2_session: WebSocketNewConnection::Http2ExtendedConnect,
        with_incapable_http2_session: WebSocketNewConnection::Http1Upgrade,
        http1_alpn_protocols: vec![Box::from(*b"http/1.1")],
        refused_stream_retry: WebSocketRefusedStreamRetry::None,
    };
    assert_eq!(policy, firefox::v156_websocket().connection);
}
