use super::*;
use phantom::dns::{HttpsLookupError, HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};
use std::sync::atomic::{AtomicUsize, Ordering};

const KEY: &[u8; 32] = &[71; 32];

fn checkpoint_client(identity: &TestIdentity, resolver: HttpsRecordResolver) -> TestResult<Client> {
    Ok(Client::builder(
        ClientProfile::new(ech_tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings()),
    )
    .add_root_certificate_der(identity.root_der.clone())
    .alt_svc(NonZeroUsize::MIN)
    .https_record_discovery(resolver)
    .https_record_checkpoint_namespace("loopback/ech-v1")
    .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
    .build()?)
}

#[tokio::test]
async fn restored_checkpoint_offers_ech_on_its_first_tcp_connection_without_a_lookup()
-> TestResult<()> {
    bounded(async {
        let identity = ech_support::origin_identity()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = spawn_origin(listener, ech_acceptor(&identity)?, 3);
        let record = HttpsRecord::from_rdata(&https_rdata(&ech_config_list(&[ech_config(
            1,
            &TEST_ECH_KEYS[0],
            PUBLIC_NAME,
        )])))?;
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
        let url = format!("https://{ORIGIN_NAME}:{port}/source");
        source
            .get_negotiated(&url)?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        let checkpoint = source.export_session(KEY)?;
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
        let restored = receiver.restore_session(&checkpoint, KEY, &[])?;
        restored
            .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}/restored"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        // Export/restore does not consume or clear the source's discovery state.
        source
            .get_negotiated(&url)?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        let seen = server.await??;
        for connection in &seen[1..] {
            assert!(connection.ech_accepted);
            assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
            assert_eq!(connection.inner_server_name.as_deref(), Some(ORIGIN_NAME));
        }
        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        assert_eq!(received_calls.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .await
}
