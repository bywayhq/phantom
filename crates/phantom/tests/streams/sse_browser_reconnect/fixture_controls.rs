use super::*;

#[test]
fn malformed_hex_returns_an_error_without_unwinding() -> TestResult<()> {
    for text in ["0é0", "☃0", "0", "gg"] {
        assert!(decode_hex(text).is_err(), "{text:?}");
    }
    assert_eq!(decode_hex("00aAff")?, [0, 170, 255]);
    assert!(decode_hex("")?.is_empty());
    Ok(())
}

#[test]
fn invalid_medians_and_counts_return_fixture_errors() -> TestResult<()> {
    for median in ["-1", "NaN", "inf", "1e300"] {
        let fixture = Fixture {
            fields: HashMap::from([(
                "attempt_1_after_stimulus_ms".to_owned(),
                format!("median:{median}"),
            )]),
        };
        assert!(fixture.median_after_stimulus(1).is_err(), "{median}");
    }
    let fixture = Fixture {
        fields: HashMap::from([("repeat_count".to_owned(), usize::MAX.to_string())]),
    };
    assert!(fixture.runs().is_err());
    let fixture = Fixture {
        fields: HashMap::from([("repeat_count".to_owned(), "0".to_owned())]),
    };
    assert!(fixture.runs().is_err());
    Ok(())
}

#[test]
fn retained_browser_runs_keep_their_literal_fields_and_medians() -> TestResult<()> {
    for browser in Browser::ALL {
        for name in [
            "id-then-close",
            "retry-750",
            "retry-100",
            "retry-0",
            "default-delay",
            "retry-persists-across-reconnect",
            "invalid-retry-ignored",
            "empty-id-resets",
            "non-ascii-id",
            "reconnect-204",
            "reconnect-404",
            "reconnect-500",
            "reconnect-wrong-content-type",
            "set-cookie-then-close",
        ] {
            let fixture = Fixture::load(browser, name)?;
            for run in 0..fixture.runs()? {
                let requests = fixture.sse_requests(run)?;
                assert_eq!(requests.len(), scenario(name).len());
                for request in requests {
                    assert!(!request.lines.is_empty());
                    for field in request.lines {
                        split_field(&field)?;
                    }
                }
            }
            for key in fixture.fields.keys() {
                if key.starts_with("attempt_") && key.ends_with("_after_stimulus_ms") {
                    let attempt = key
                        .strip_prefix("attempt_")
                        .and_then(|key| key.strip_suffix("_after_stimulus_ms"))
                        .ok_or("invalid retained median key")?
                        .parse()?;
                    fixture.median_after_stimulus(attempt)?;
                }
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_early_terminal_client_bounds_and_joins_the_original_replay_peer() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    let result = replay_on(listener, client, "default-delay", |builder| {
        builder.max_reconnects(0)
    })
    .await;
    let error = result
        .err()
        .ok_or("unfinished scripted peer was accepted")?;
    assert!(error.is::<tokio::time::error::Elapsed>());
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn invalid_request_fields_release_the_original_listener() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    let result = replay_on(listener, client, "id-then-close", |builder| {
        builder.headers(vec![SseHeader::field(RequestHeader::new("bad\nname", "x"))])
    })
    .await;
    assert!(result.is_err());
    let rebound = TcpListener::bind(address).await?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}
