//! Per-request catalog and owned contexts on one shared connection.

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader,
    profile::{
        ClientProfile,
        browser::chrome,
        catalog::{self, RequestTemplateKind},
    },
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

use super::{
    ConnectionPeer, H2_ALPN, RecordingIo, TEST_TIMEOUT, TestIdentity, TestResult, accept_tls,
    complete_peer, headers_priority,
};

#[tokio::test]
async fn concurrent_navigation_fetch_and_raw_requests_share_one_connection() -> TestResult<()> {
    let profile = catalog::profile_for("chrome-154-windows", RequestTemplateKind::Navigation)?;
    mixed_contexts_share_one_connection(profile).await
}

#[tokio::test]
async fn windows156_navigation_fetch_and_raw_requests_share_one_connection() -> TestResult<()> {
    let profile = catalog::profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    mixed_contexts_share_one_connection(profile).await
}

#[tokio::test]
async fn owned_navigation_fetch_and_raw_requests_share_one_connection() -> TestResult<()> {
    let navigation = chrome::v154_windows_navigation_template();
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_request_template(navigation.clone())
        .with_request_contexts([
            (RequestTemplateKind::Navigation, navigation),
            (
                RequestTemplateKind::Fetch,
                chrome::v154_windows_fetch_template(),
            ),
        ]);
    mixed_contexts_share_one_connection(profile).await
}

#[cfg(feature = "fingerprint-import")]
#[tokio::test]
async fn imported_navigation_fetch_and_raw_requests_share_one_connection() -> TestResult<()> {
    let profile = catalog::profile_for("chrome-154-windows", RequestTemplateKind::Navigation)?;
    let bytes = phantom::fingerprint::export_profile_json(&profile)?;
    let imported = phantom::fingerprint::import_profile_json(&bytes)?;
    assert!(imported.request_context_profile().is_none());
    drop(bytes);
    drop(profile);
    mixed_contexts_share_one_connection(imported).await
}

async fn mixed_contexts_share_one_connection(profile: ClientProfile) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("https://{}", listener.local_addr()?);
    let acceptor = identity.acceptor(H2_ALPN)?;
    let (done, mut wait) = oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        let wire = Arc::new(Mutex::new(Vec::new()));
        let stream = RecordingIo {
            inner: accept_tls(listener, acceptor).await?,
            read: Arc::clone(&wire),
        };
        let mut connection = ::http2::server::handshake(stream).await?;
        let mut observed = BTreeMap::new();
        loop {
            tokio::select! {
                accepted = connection.accept() => {
                    let (request, mut respond) = accepted.ok_or("shared H2 closed early")??;
                    let priority = headers_priority(&wire.lock().map_err(|_| "wire lock poisoned")?, u32::from(respond.stream_id()))?;
                    observed.insert(request.uri().path().to_owned(), (request.headers().clone(), priority));
                    respond.send_response(http::Response::builder().status(StatusCode::NO_CONTENT).body(())?, true)?;
                }
                _ = &mut wait => break,
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
    });
    let operation: TestResult<Client> = match timeout(TEST_TIMEOUT, async {
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        // Warm the pool before the concurrent stream openings.
        client
            .get_with_protocol(HttpProtocol::Http2, &format!("{url}/warm"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        let fetch = client
            .get_with_protocol(HttpProtocol::Http2, &format!("{url}/fetch"))?
            .context(RequestTemplateKind::Fetch)?
            .header(RequestHeader::new("referer", format!("{url}/warm")))
            .send();
        let navigation = client
            .get_with_protocol(HttpProtocol::Http2, &format!("{url}/navigation"))?
            .send();
        let raw = client
            .get_with_protocol(HttpProtocol::Http2, &format!("{url}/raw"))?
            .without_template()
            .send();
        let (fetch, navigation, raw) = tokio::join!(fetch, navigation, raw);
        for response in [fetch?, navigation?, raw?] {
            response.into_body().collect().await?;
        }
        // A closed receiver means the peer already failed; complete_peer retains that error.
        let _ = done.send(());
        Ok(client)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let (_client, observed) = complete_peer(peer, operation).await?;
    assert_eq!(observed.len(), 4);
    for path in ["/warm", "/navigation"] {
        let (headers, priority) = observed.get(path).ok_or("navigation missing")?;
        assert_eq!(
            headers
                .get("sec-fetch-mode")
                .and_then(|value| value.to_str().ok()),
            Some("navigate")
        );
        assert_eq!(
            headers
                .get("sec-fetch-dest")
                .and_then(|value| value.to_str().ok()),
            Some("document")
        );
        assert!(
            headers
                .get("accept")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        );
        assert_eq!(*priority, Some((true, 0, 256)));
    }
    let (fetch, priority) = observed.get("/fetch").ok_or("fetch missing")?;
    assert_eq!(
        fetch
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok()),
        Some("cors")
    );
    assert_eq!(
        fetch
            .get("sec-fetch-dest")
            .and_then(|value| value.to_str().ok()),
        Some("empty")
    );
    assert_eq!(
        fetch.get("accept").and_then(|value| value.to_str().ok()),
        Some("*/*")
    );
    assert_eq!(*priority, Some((true, 0, 220)));
    let (raw, _) = observed.get("/raw").ok_or("raw missing")?;
    assert!(!raw.contains_key("sec-fetch-mode"));
    assert!(!raw.contains_key("accept"));
    Ok(())
}

#[tokio::test]
async fn unavailable_contexts_open_no_connection() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut invalid = chrome::v154_windows_fetch_template();
    invalid
        .http2_fields
        .push(phantom::profile::RequestField::literal(
            "Uppercase",
            "invalid",
        ));
    let owned = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_request_contexts([
            (
                RequestTemplateKind::Fetch,
                chrome::v154_windows_fetch_template(),
            ),
            (RequestTemplateKind::Script, invalid),
        ]);
    for (profile, kind) in [
        (chrome::v154_windows(), RequestTemplateKind::Font),
        (owned.clone(), RequestTemplateKind::Navigation),
        (owned, RequestTemplateKind::Script),
    ] {
        let client = Client::builder(profile).build()?;
        let error = client
            .get(&format!("https://{}/", listener.local_addr()?))?
            .context(kind)
            .err()
            .ok_or("unavailable or invalid context accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestTemplate);
    }
    assert!(
        timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
