mod hash_set_order;

use super::{v135_macos_client_hints, v136_http3_tls, v136_tls, v136_windows_client_hints};
use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};
use crate::http2::{
    Http2HpackSettings, Http2Settings, Http2StreamSettings, session_capture::SessionCapture,
};
use crate::{TrustAnchorIds, chromium};

const CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/136.0.6008.52/windows-11-26200/navigation.txt"
));
const MACOS_CLIENT_HINT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/client-hints/opera/135.0.5973.92/macos-15.5-arm64/navigation.txt"
));
const TRUST_ANCHOR_ORDERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/tls/opera/136.0.6008.52/windows-11-26200/trust-anchor-orders.txt"
));
const SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/opera/136.0.6008.52/windows-11-26200/accept.txt"
));

#[test]
fn opera_136_windows_client_hints_match_navigation_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v136_windows_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

#[test]
fn opera_client_hints_share_the_chromium_names_order_and_delivery() {
    let names = |settings: crate::ClientHintSettings| {
        settings
            .hints()
            .iter()
            .map(|hint| (hint.name().to_owned(), hint.delivery()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(v136_windows_client_hints()),
        names(chromium::v154_windows_client_hints())
    );
}

#[test]
fn opera_136_recipes_keep_the_backend_ech_grease_aead_policy() {
    for settings in [v136_tls(), v136_http3_tls()] {
        assert!(settings.ech_grease);
        assert!(settings.ech_grease_aeads.is_empty());
        assert!(settings.aes_hardware);
    }
}

/// The IDs every order of `ids` lists, sorted; the drawn variants require
/// each order to list the same IDs.
fn id_set(ids: &TrustAnchorIds) -> Vec<Box<[u8]>> {
    let mut set = ids.orders().first().cloned().unwrap_or_default();
    set.sort_unstable();
    set
}

/// Opera 136 sends the Chromium offers with its own 32 trust-anchor IDs: the
/// TCP offer in one order per process, the QUIC offer in one per connection.
#[test]
fn opera_136_tls_recipes_are_chromium_s_with_opera_trust_anchor_ids()
-> Result<(), Box<dyn std::error::Error>> {
    let opera = v136_tls();
    opera.validate()?;
    let Some(ids @ TrustAnchorIds::PerClient(orders)) = &opera.requested_trust_anchor_ids else {
        return Err("Opera 136 recipe does not draw its trust-anchor order per client".into());
    };
    assert_eq!(orders.len(), 29);
    let ids_listed = id_set(ids);
    assert_eq!(ids_listed.len(), 32);
    let mut expected = chromium::v154_tls();
    let Some(TrustAnchorIds::Fixed(chrome_ids)) = &expected.requested_trust_anchor_ids else {
        return Err("Chrome 154 recipe omitted its fixed trust-anchor IDs".into());
    };
    assert!(chrome_ids.iter().all(|id| ids_listed.contains(id)));
    let added = ids_listed
        .iter()
        .filter(|id| !chrome_ids.contains(id))
        .map(|id| id.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(
        added,
        [
            &[0xd6, 0x79, 0x09, 0x02][..],
            &[0xd6, 0x79, 0x09, 0x03],
            &[0xd6, 0x79, 0x09, 0x09],
            &[0xd6, 0x79, 0x09, 0x0e],
        ]
    );
    expected.requested_trust_anchor_ids = opera.requested_trust_anchor_ids.clone();
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);

    let opera = v136_http3_tls();
    opera.validate()?;
    let Some(quic_ids @ TrustAnchorIds::PerConnection(quic_orders)) =
        &opera.requested_trust_anchor_ids
    else {
        return Err(
            "Opera 136 H3 recipe does not draw its trust-anchor order per connection".into(),
        );
    };
    assert_eq!(quic_orders.len(), 20);
    assert_eq!(id_set(quic_ids), ids_listed);
    let mut expected = chromium::v154_http3_tls();
    expected.requested_trust_anchor_ids = opera.requested_trust_anchor_ids.clone();
    expected.ech_from_https_records = false;
    assert_eq!(opera, expected);
    Ok(())
}

macro_rules! retained {
    ($($path:literal),* $(,)?) => {
        [$(($path, include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/", $path)))),*]
    };
}

/// Every fixture `trust-anchor-orders.txt` names as a source.
const ORDER_SOURCES: [(&str, &str); 35] = retained![
    "tls/opera/136.0.6008.52/windows-11-26200/client-hello.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-1.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-2.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-4.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-5.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-6.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-7.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-8.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-9.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-10.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-11.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-12.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-13.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-14.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-15.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-16.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-17.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-18.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-19.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/startup-runs/client-hello-20.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-issue-once.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-methods-http1.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-methods.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-no-early-data.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-origins.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-parallel.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-partition.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-sequential-http1.txt",
    "tls/opera/136.0.6008.52/windows-11-26200/resumption-sequential.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/quic-client-hello-1.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/quic-client-hello-2.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/quic-client-hello-3.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/resumption-accept-delayed.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/resumption-accept.txt",
    "http3/opera/136.0.6008.52/windows-11-26200/resumption-reject.txt",
];

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn hex_bytes(hex: &str) -> TestResult<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&hex[index..index + 2], 16)?))
        .collect()
}

/// The trust-anchor IDs, in wire order, of a ClientHello given as a TLS
/// record or a bare handshake message.
fn client_hello_trust_anchor_ids(bytes: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    let take = |offset: &mut usize, length: usize| -> TestResult<&[u8]> {
        let slice = bytes
            .get(*offset..*offset + length)
            .ok_or("ClientHello is truncated")?;
        *offset += length;
        Ok(slice)
    };
    let u16_at = |slice: &[u8]| usize::from(u16::from_be_bytes([slice[0], slice[1]]));
    // A record header, then the handshake header, version, and random.
    let mut offset = if bytes.first() == Some(&0x16) { 5 } else { 0 };
    take(&mut offset, 4 + 2 + 32)?;
    let session_id = usize::from(take(&mut offset, 1)?[0]);
    take(&mut offset, session_id)?;
    let suites = u16_at(take(&mut offset, 2)?);
    take(&mut offset, suites)?;
    let compression = usize::from(take(&mut offset, 1)?[0]);
    take(&mut offset, compression)?;
    let extensions = u16_at(take(&mut offset, 2)?);
    let end = offset + extensions;
    while offset < end {
        let header = take(&mut offset, 4)?;
        let (kind, length) = (u16_at(header), u16_at(&header[2..]));
        let body = take(&mut offset, length)?;
        if kind == 0xca34 {
            let list = body.get(2..2 + u16_at(body)).ok_or("bad ID list")?;
            let mut ids = Vec::new();
            let mut at = 0;
            while at < list.len() {
                let length = usize::from(list[at]);
                ids.push(list.get(at + 1..at + 1 + length).ok_or("bad ID")?.to_vec());
                at += 1 + length;
            }
            return Ok(ids);
        }
    }
    Err("ClientHello has no trust-anchor IDs".into())
}

/// The trust-anchor orders of a retained file's ClientHellos, in connection
/// order: the startup files hold one, and `#run_0` names every raw
/// ClientHello of a resumption capture's first run.
fn retained_orders(source: &str) -> TestResult<Vec<Vec<Vec<u8>>>> {
    let (path, run) = match source.split_once('#') {
        Some((path, run)) => (path, Some(run)),
        None => (source, None),
    };
    let text = ORDER_SOURCES
        .iter()
        .find_map(|(name, text)| (*name == path).then_some(*text))
        .ok_or_else(|| format!("{path} is not a retained order source"))?;
    let mut hellos = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let connection = match run {
            Some(run) => key
                .strip_prefix(run)
                .and_then(|rest| rest.strip_prefix("_connection_"))
                .and_then(|rest| rest.strip_suffix("_client_hello_hex"))
                .map(str::parse::<usize>)
                .transpose()?,
            None if key == "record_0_hex" || key == "handshake_hex" => Some(0),
            None => None,
        };
        if let Some(connection) = connection {
            hellos.push((
                connection,
                client_hello_trust_anchor_ids(&hex_bytes(value)?)?,
            ));
        }
    }
    hellos.sort();
    Ok(hellos.into_iter().map(|(_, ids)| ids).collect())
}

struct TrustAnchorOrders<'a>(std::collections::HashMap<&'a str, &'a str>);

impl<'a> TrustAnchorOrders<'a> {
    fn value(&self, key: &str) -> Result<&'a str, String> {
        self.0
            .get(key)
            .copied()
            .ok_or_else(|| format!("trust-anchor orders omit {key}"))
    }
}

fn order_ids(value: &str) -> Result<Vec<Box<[u8]>>, Box<dyn std::error::Error>> {
    let (_, ids) = value.split_once(",ids:").ok_or("order has no ids")?;
    ids.split(',')
        .map(|id| {
            (0..id.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&id[index..index + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map(Vec::into_boxed_slice)
                .map_err(Into::into)
        })
        .collect()
}

fn order_count(value: &str) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(value
        .strip_prefix("count:")
        .and_then(|rest| rest.split(',').next())
        .ok_or("order has no count")?
        .parse()?)
}

/// Each order of `orders` repeated `counts` times, sorted.
fn observed(orders: &[Vec<Vec<u8>>], counts: &[usize]) -> Vec<Vec<Vec<u8>>> {
    let mut observed = orders
        .iter()
        .zip(counts)
        .flat_map(|(order, count)| std::iter::repeat_n(order.clone(), *count))
        .collect::<Vec<_>>();
    observed.sort_unstable();
    observed
}

/// The orders a recipe draws from, sorted.
fn recipe_orders(ids: Option<TrustAnchorIds>) -> TestResult<Vec<Vec<Vec<u8>>>> {
    let ids = ids.ok_or("Opera 136 recipe omitted trust-anchor IDs")?;
    let mut orders = ids
        .orders()
        .iter()
        .map(|order| order.iter().map(|id| id.to_vec()).collect())
        .collect::<Vec<_>>();
    orders.sort_unstable();
    Ok(orders)
}

/// The tally in `trust-anchor-orders.txt` follows from the retained bytes:
/// each process's ClientHellos, read again from the fixture the tally names,
/// carry the orders it records, over TCP one per process and over QUIC one
/// per connection. The TCP recipe draws from the tallied processes' orders,
/// each listed once per process that sent it, and the QUIC recipe from the
/// tallied QUIC ClientHellos' orders, each once per ClientHello.
#[test]
fn opera_136_trust_anchor_recipes_draw_from_the_retained_orders() -> TestResult<()> {
    let orders = TrustAnchorOrders(
        TRUST_ANCHOR_ORDERS
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect(),
    );
    assert_eq!(orders.value("format")?, "phantom-trust-anchor-orders-v1");
    assert_eq!(orders.value("browser")?, "Opera");
    assert_eq!(orders.value("browser_version")?, "136.0.6008.52");
    let field = |value: &'static str, key: &str| -> TestResult<&'static str> {
        Ok(value
            .split(',')
            .find_map(|part| part.strip_prefix(key))
            .ok_or_else(|| format!("{value} has no {key}"))?)
    };
    let order_list = |prefix: &str, count: &str| -> TestResult<Vec<Vec<Vec<u8>>>> {
        (0..orders.value(count)?.parse::<usize>()?)
            .map(|index| {
                Ok(order_ids(orders.value(&format!("{prefix}{index}"))?)?
                    .into_iter()
                    .map(Vec::from)
                    .collect())
            })
            .collect()
    };
    let mut sources = std::collections::HashSet::new();

    // TCP: every ClientHello of a process carries the process's order.
    let tcp_orders = order_list("order_", "distinct_order_count")?;
    let mut tcp_counts = vec![0; tcp_orders.len()];
    let processes = orders.value("process_count")?.parse::<usize>()?;
    let mut hellos = 0;
    for index in 0..processes {
        let process = orders.value(&format!("process_{index}"))?;
        let source = field(process, "source:")?;
        let order = field(process, "order:")?.parse::<usize>()?;
        let derived = retained_orders(source)?;
        assert_eq!(derived.len().to_string(), field(process, "client_hellos:")?);
        assert!(
            derived.iter().all(|ids| *ids == tcp_orders[order]),
            "{source}"
        );
        tcp_counts[order] += 1;
        hellos += derived.len();
        sources.insert(source.split('#').next().unwrap_or(source));
    }
    assert_eq!(hellos.to_string(), orders.value("client_hello_count")?);
    for (index, count) in tcp_counts.iter().enumerate() {
        let recorded = order_count(orders.value(&format!("order_{index}"))?)?;
        assert_eq!(*count, recorded, "order_{index}");
    }
    assert_eq!(
        recipe_orders(v136_tls().requested_trust_anchor_ids)?,
        observed(&tcp_orders, &tcp_counts)
    );

    // QUIC: each ClientHello carries the order its position names.
    let quic_orders = order_list("quic_order_", "quic_distinct_order_count")?;
    let mut quic_counts = vec![0; quic_orders.len()];
    let quic_processes = orders.value("quic_process_count")?.parse::<usize>()?;
    for index in 0..quic_processes {
        let process = orders.value(&format!("quic_process_{index}"))?;
        let source = field(process, "source:")?;
        let derived = retained_orders(source)?;
        let recorded = field(process, "orders:")?
            .split(' ')
            .map(str::parse::<usize>)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(derived.len(), recorded.len(), "{source}");
        for (ids, order) in derived.iter().zip(&recorded) {
            assert_eq!(*ids, quic_orders[*order], "{source}");
            quic_counts[*order] += 1;
        }
        sources.insert(source.split('#').next().unwrap_or(source));
    }
    for (index, count) in quic_counts.iter().enumerate() {
        let recorded = order_count(orders.value(&format!("quic_order_{index}"))?)?;
        assert_eq!(*count, recorded, "quic_order_{index}");
    }
    assert_eq!(
        recipe_orders(v136_http3_tls().requested_trust_anchor_ids)?,
        observed(&quic_orders, &quic_counts)
    );

    // Every retained source is in the tally, and nothing else is.
    assert_eq!(sources.len(), ORDER_SOURCES.len());
    Ok(())
}

#[test]
fn opera_136_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "136.0.6008.52");
    assert_eq!(capture.value("scenario")?, "accept");
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    let settings = chromium::v154_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

#[test]
fn opera_135_macos_client_hints_match_navigation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v135_macos_client_hints();
    settings.validate()?;
    let capture = NavigationCapture::parse(MACOS_CLIENT_HINT_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(capture.value("client_version")?, "135.0.5973.92");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("launch_mode")?, "headless");
    assert_eq!(capture.value("repeat_count")?, "3");
    capture.assert_runs_agree()?;
    assert_eq!(profile_hints(&settings), capture.hints()?);
    Ok(())
}

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn opera_135_macos_http2_session_capture_matches_the_chromium_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/opera/135.0.5973.92/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Opera");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("scenario")?, "accept");
    let settings = chromium::v154_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but neither the assumed limit
        // nor the cap, and one navigation shows no preface PING.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
            ..settings.streams
        },
        preface_ping_after: None,
        ping_timeout: None,
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
