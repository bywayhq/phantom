use super::*;
use phantom::dns::{HttpsLookupError, HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};
use std::sync::atomic::{AtomicUsize, Ordering};

const KEY: &[u8; 32] = &[72; 32];

fn checkpoint_client(identity: &TestIdentity, resolver: HttpsRecordResolver) -> TestResult<Client> {
    Ok(Client::builder(profile(true))
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .alt_svc_policy(AltSvcPolicy::sequential())
        .https_record_discovery(resolver)
        .https_record_checkpoint_namespace("loopback/quic-ech-v1")
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?)
}

#[tokio::test]
async fn restored_checkpoint_offers_ech_on_its_first_quic_connection_without_a_lookup()
-> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(
            &[b"h3"],
            &ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]),
        ))?;
        let source_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&source_calls);
        let source = checkpoint_client(
            &identity,
            HttpsRecordResolver::from_fn(move |host, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                let record = record.clone();
                async move {
                    Ok(HttpsRecordLookup::new(
                        vec![HttpsRecordAnswer::new(host, 300, record)],
                        None,
                    ))
                }
            }),
        )?;
        let received_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&received_calls);
        let receiver = checkpoint_client(
            &identity,
            HttpsRecordResolver::from_fn(move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(HttpsLookupError::other(std::io::Error::other(
                        "unexpected lookup",
                    )))
                }
            }),
        )?;
        let result = async {
            get(&source, Some(HttpProtocol::Http3), &origin.url("/source")).await?;
            let checkpoint = source.export_session(KEY)?;
            let restored = receiver.restore_session(&checkpoint, KEY, &[])?;
            get(
                &restored,
                Some(HttpProtocol::Http3),
                &origin.url("/restored"),
            )
            .await?;
            get(
                &source,
                Some(HttpProtocol::Http3),
                &origin.url("/source-retained"),
            )
            .await?;
            assert_eq!(source_calls.load(Ordering::SeqCst), 1);
            assert_eq!(received_calls.load(Ordering::SeqCst), 0);
            Ok(())
        }
        .await;
        let (connections, tcp) = origin.finish_result(result, 3, 0).await?;
        assert_eq!(tcp, 0);
        for connection in &connections[1..] {
            assert_accepted(connection);
        }
        Ok(())
    })
    .await
}
