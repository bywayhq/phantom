//! Mapping eligibility is sampled before setup and retained for one request hop.

use super::*;
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace,
    profile::{Http3AltUsed, RequestField, RequestTemplate},
};

fn mapping_settings() -> Http3ClientSettings {
    let base = client_settings();
    let mut request = base.request().clone();
    request.alt_used = Http3AltUsed::ValidatedMapping;
    Http3ClientSettings::new(
        base.tls().clone(),
        base.quic_transport().clone(),
        base.http3().clone(),
        request,
    )
}

fn slotted_template() -> TestResult<phantom::PreparedRequestTemplate> {
    Ok(phantom::PreparedRequestTemplate::new(RequestTemplate {
        http1_fields: Vec::new(),
        http2_fields: Vec::new(),
        http3_fields: Some(vec![
            RequestField::literal("x-before", "one"),
            RequestField::AltUsed,
            RequestField::literal("x-after", "two"),
        ]),
        http2_priority: None,
        requested_client_hint_placement: false,
        restarts_for_connection_accept_ch: false,
    })?)
}

#[tokio::test]
async fn checked_setup_validates_only_later_plans_for_sequential_and_raced_alternatives()
-> TestResult<()> {
    for raced in [false, true] {
        bounded(async {
            let identity = TestIdentity::generate()?;
            let fixture = Http3UpgradeFixture::spawn(
                &identity,
                ORIGIN_NAME,
                UpgradeScript::new(
                    [PlannedResponse::new(StatusCode::OK).advertise_alternative()],
                    AlternativeBehavior::responses([
                        PlannedResponse::new(StatusCode::OK),
                        PlannedResponse::new(StatusCode::OK),
                    ]),
                ),
            )
            .await?;
            let teacher = upgrade_client_with(&identity, mapping_settings())?;
            drain(teacher.get(&fixture.origin_url("/learn"))?.send().await?).await?;
            let snapshot = teacher.export_alt_svc().ok_or("Alt-Svc store missing")?;
            drop(teacher);
            let mut builder = upgrade_client_builder_with(&identity, mapping_settings())
                .alt_svc(NonZeroUsize::MIN);
            if raced {
                builder = builder.alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
                    Duration::from_secs(30),
                    AltSvcBrokenBackoff::CHROMIUM_153,
                )));
            }
            let client = builder.build()?;
            // Import keeps the advertisement unvalidated and avoids an idle
            // origin H2 lease, which would bypass the raced origin delay.
            client.import_alt_svc(&snapshot)?;
            let template = slotted_template()?;
            for path in ["/before-validation", "/after-validation"] {
                let response = client
                    .get(&fixture.origin_url(path))?
                    .template(&template)
                    .send()
                    .await?;
                assert_eq!(protocol(&response)?, HttpProtocol::Http3);
                drain(response).await?;
            }
            drop(client);
            let authority = fixture.alternative_address().to_string();
            let observed = fixture.finish().await?;
            assert_eq!(observed.origin_requests.len(), 1);
            assert_eq!(observed.alternative_connections, 1);
            assert_eq!(observed.alternative_requests.len(), 2);
            assert_eq!(
                field_pairs(&observed.alternative_requests[0]),
                [
                    ("x-before", b"one".as_slice()),
                    ("x-after", b"two".as_slice()),
                ]
            );
            assert_eq!(
                field_pairs(&observed.alternative_requests[1]),
                [
                    ("x-before", b"one".as_slice()),
                    ("alt-used", authority.as_bytes()),
                    ("x-after", b"two".as_slice()),
                ]
            );
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn pinned_mapping_policy_sends_the_first_generated_field() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [],
                AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)]),
            ),
        )
        .await?;
        let client = upgrade_client_with(&identity, mapping_settings())?;
        let template = slotted_template()?;
        drain(
            client
                .get_with_protocol(HttpProtocol::Http3, &fixture.origin_url("/pinned"))?
                .alt_svc_alternative(ORIGIN_NAME, fixture.alternative_address().port())
                .template(&template)
                .send()
                .await?,
        )
        .await?;
        drop(client);
        let authority = fixture.alternative_address().to_string();
        let observed = fixture.finish().await?;
        assert!(observed.origin_requests.is_empty());
        assert_eq!(observed.alternative_requests.len(), 1);
        assert_eq!(
            field_pairs(&observed.alternative_requests[0]),
            [
                ("x-before", b"one".as_slice()),
                ("alt-used", authority.as_bytes()),
                ("x-after", b"two".as_slice()),
            ]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn critical_ch_replay_keeps_the_unvalidated_plan_after_setup() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            ORIGIN_NAME,
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK).advertise_alternative()],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK)
                        .header("accept-ch", HeaderValue::from_static("Sec-CH-UA-Arch"))
                        .header("critical-ch", HeaderValue::from_static("Sec-CH-UA-Arch")),
                    PlannedResponse::new(StatusCode::NO_CONTENT),
                    PlannedResponse::new(StatusCode::OK),
                ]),
            ),
        )
        .await?;
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(mapping_settings())
            .with_client_hints(ClientHintSettings::new(vec![ClientHint::new(
                "sec-ch-ua-arch",
                "\"arm\"",
                ClientHintDelivery::AcceptCh,
            )]));
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN)
            .build()?;
        drain(client.get(&fixture.origin_url("/learn"))?.send().await?).await?;
        let response = client
            .get(&fixture.origin_url("/critical"))?
            .header(RequestHeader::new("x-stable", "caller"))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        drain(response).await?;
        drain(client.get(&fixture.origin_url("/later"))?.send().await?).await?;
        drop(client);
        let authority = fixture.alternative_address().to_string();
        let observed = fixture.finish().await?;
        assert_eq!(observed.alternative_requests.len(), 3);
        assert_eq!(
            field_pairs(&observed.alternative_requests[0]),
            [("x-stable", b"caller".as_slice()),]
        );
        assert_eq!(
            field_pairs(&observed.alternative_requests[1]),
            [
                ("sec-ch-ua-arch", b"\"arm\"".as_slice()),
                ("x-stable", b"caller".as_slice()),
            ]
        );
        assert_eq!(
            field_pairs(&observed.alternative_requests[2]),
            [
                ("sec-ch-ua-arch", b"\"arm\"".as_slice()),
                ("alt-used", authority.as_bytes()),
            ]
        );
        Ok(())
    })
    .await
}
