use std::sync::Arc;

use super::{AlternativeHost, HOST_B, PROBE_BODY};
use crate::{CaptureResult, Captured, DnsAnswers, HOSTNAME, Scenario, dns_response};

mod native;
mod native_bootstrap;

fn state() -> CaptureResult<AlternativeHost> {
    Ok(AlternativeHost::new(
        "127.0.0.1:8443".parse()?,
        "127.0.0.1:9443".parse()?,
    )?)
}

fn query(name: &str, kind: u16) -> CaptureResult<Vec<u8>> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(u8::try_from(label.len())?);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    Ok(bytes)
}

fn header(bytes: &[u8]) -> CaptureResult<[u16; 6]> {
    let mut fields = [0; 6];
    for (index, field) in fields.iter_mut().enumerate() {
        *field = u16::from_be_bytes(
            bytes
                .get(index * 2..index * 2 + 2)
                .ok_or("short DNS header")?
                .try_into()?,
        );
    }
    Ok(fields)
}

#[test]
fn logical_origin_nodata_and_destination_https_have_distinct_wire_answers() -> CaptureResult<()> {
    let alternative = Arc::new(state()?);
    let answers = DnsAnswers {
        address: "127.0.0.1".parse()?,
        port: 8443,
        ech_config_list: None,
        quic: true,
        alternative: Some(Arc::clone(&alternative)),
    };
    let question = query("_8443._https.server.phantom.test", 65)?;
    let (response, _) = dns_response(&question, &answers).ok_or("A HTTPS query rejected")?;
    assert_eq!(header(&response)?, [0x1234, 0x8180, 1, 0, 0, 0]);
    assert_eq!(response.get(12..), question.get(12..));
    for name in [HOSTNAME, HOST_B] {
        let question = query(name, 1)?;
        let (response, _) = dns_response(&question, &answers).ok_or("address query rejected")?;
        assert_eq!(header(&response)?, [0x1234, 0x8180, 1, 1, 0, 0]);
        assert_eq!(
            response.get(question.len()..),
            Some(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1][..])
        );
    }
    let expected = Scenario::AlternativeHost
        .ech_setup()?
        .ok_or("missing destination keys")?;
    for name in [HOST_B, "_9443._https.alternative.phantom.test"] {
        let question = query(name, 65)?;
        let (response, _) = dns_response(&question, &answers).ok_or("B HTTPS query rejected")?;
        assert_eq!(header(&response)?, [0x1234, 0x8180, 1, 1, 0, 0]);
        let rdata = response
            .get(question.len() + 12..)
            .ok_or("missing HTTPS RDATA")?;
        // RFC 9460: priority 1, target '.', ALPN h3/h2, then ECHConfigList.
        assert_eq!(
            rdata.get(..15),
            Some(&[0, 1, 0, 0, 1, 0, 6, 2, b'h', b'3', 2, b'h', b'2', 0, 5][..])
        );
        let config_length =
            u16::from_be_bytes(rdata.get(15..17).ok_or("missing ech length")?.try_into()?);
        assert_eq!(usize::from(config_length), expected.published.len());
        assert_eq!(rdata.get(17..), Some(expected.published.as_slice()));
        // One list entry, draft ECHConfig version, then config_id 2.
        assert_eq!(expected.published.get(6), Some(&2));
        assert_eq!(expected.server.get(4), Some(&2));
    }
    let unknown = query("other.phantom.test", 65)?;
    let (response, _) = dns_response(&unknown, &answers).ok_or("unknown query rejected")?;
    assert_eq!(header(&response)?, [0x1234, 0x8183, 1, 0, 0, 0]);
    for length in 0..question.len() {
        assert!(dns_response(&question[..length], &answers).is_none());
    }
    let compressed = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 65, 0, 1,
    ];
    assert!(dns_response(&compressed, &answers).is_none());
    Ok(())
}

#[test]
fn dns_evidence_is_bounded_without_requiring_any_destination_query() -> CaptureResult<()> {
    let alternative = state()?;
    let mut output = Vec::new();
    alternative.write(&mut output)?;
    assert!(String::from_utf8(output)?.contains("alternative_dns_count=0\n"));
    assert!(
        alternative
            .record_dns(HOST_B, &vec![0; crate::MAX_DOH_QUERY_BYTES], &[])
            .is_some()
    );
    assert!(alternative.record_dns(HOST_B, &[0], &[]).is_none());
    assert_eq!(
        alternative
            .dns
            .lock()
            .map_err(|_| "DNS evidence poisoned")?
            .len(),
        1
    );
    let alternative = state()?;
    for _ in 0..crate::MAX_DOH_QUERIES {
        assert!(alternative.record_dns(HOSTNAME, &[], &[]).is_some());
    }
    assert!(alternative.record_dns(HOSTNAME, &[], &[]).is_none());
    Ok(())
}

fn request(path: &str) -> CaptureResult<http::Request<()>> {
    Ok(http::Request::get(format!("https://server.phantom.test:8443{path}")).body(())?)
}

#[tokio::test]
async fn only_a_completed_h3_probe_then_final_report_completes_capture() -> CaptureResult<()> {
    let alternative = state()?;
    let captured = Captured::default();
    for path in ["/", "/learn"] {
        let response = alternative.response("http/1.1", 0, &request(path)?).await?;
        alternative.completed(&response, &captured)?;
        assert!(!captured.page_served());
    }
    assert!(
        alternative
            .response("http/1.1", 0, &request("/probe")?)
            .await
            .is_err()
    );
    assert!(
        alternative
            .response("h3", 1, &request("/done?ok=1")?)
            .await
            .is_err()
    );
    let response = alternative.response("h3", 1, &request("/probe")?).await?;
    assert_eq!(&response.body[..], PROBE_BODY);
    assert!(
        alternative
            .response("h3", 1, &request("/done?ok=1")?)
            .await
            .is_err()
    );
    alternative.completed(&response, &captured)?;
    assert!(!captured.page_served());
    let response = alternative
        .response("h3", 1, &request("/done?ok=1")?)
        .await?;
    assert!(!captured.page_served());
    alternative.completed(&response, &captured)?;
    assert!(captured.page_served());
    let mut output = Vec::new();
    alternative.write(&mut output)?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("authority=server.phantom.test:8443 path=/probe completed=true"));
    assert!(
        output.contains(
            "alternative_request_2_response_body_hex=616c7465726e61746976652d70726f6265\n"
        )
    );
    Ok(())
}

#[tokio::test]
async fn wrong_authority_credentials_paths_and_excess_requests_fail_closed() -> CaptureResult<()> {
    let alternative = state()?;
    for uri in [
        "https://alternative.phantom.test:8443/probe",
        "https://server.phantom.test:9443/probe",
    ] {
        assert!(
            alternative
                .response("h3", 0, &http::Request::get(uri).body(())?)
                .await
                .is_err()
        );
    }
    for name in ["cookie", "authorization", "proxy-authorization"] {
        let mut request = request("/probe")?;
        request.headers_mut().insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static("secret"),
        );
        assert!(alternative.response("h3", 0, &request).await.is_err());
    }
    assert!(
        alternative
            .response("h3", 0, &request("/unknown")?)
            .await
            .is_err()
    );
    assert!(
        alternative
            .requests
            .lock()
            .map_err(|_| "requests poisoned")?
            .is_empty()
    );
    for _ in 0..super::MAX_REQUESTS {
        alternative
            .response("http/1.1", 0, &request("/learn")?)
            .await?;
    }
    assert!(
        alternative
            .response("http/1.1", 0, &request("/learn")?)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn alternative_arguments_require_firefox_quic_identity_without_resumption() -> CaptureResult<()> {
    let metadata = [
        "alternative-host",
        "127.0.0.1:0",
        "Firefox",
        "157.0",
        "Windows",
        "DoH",
        "headful",
        "firefox",
    ];
    let parse = |prefix: Vec<&str>, metadata: &[&str]| {
        crate::Arguments::parse(
            prefix
                .into_iter()
                .chain(metadata.iter().copied())
                .map(str::to_owned),
        )
    };
    let prefix = vec!["--quic", "--identity", "leaf.pem", "key.pem"];
    let parsed = parse(prefix.clone(), &metadata)?;
    assert!(matches!(parsed.scenario, Scenario::AlternativeHost));
    assert!(parse(vec!["--quic"], &metadata).is_err());
    assert!(parse(vec!["--identity", "leaf.pem", "key.pem"], &metadata).is_err());
    let mut other = metadata;
    other[2] = "Chrome";
    assert!(parse(prefix.clone(), &other).is_err());
    let mut resumed = prefix;
    resumed.extend(["--resumption", "early-accept"]);
    assert!(parse(resumed, &metadata).is_err());
    Ok(())
}
