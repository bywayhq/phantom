use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use phantom::{
    Client,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{sync::oneshot, task::JoinSet, time::timeout};

use super::partial_download::{CleanupFailures, PartialDownload};
use super::{
    BoxError, Config, MAX_REQUESTS, download_all, download_all_with_cleanup, download_one,
    download_one_owned, target::DownloadTarget,
};

type TestResult<T = ()> = Result<T, BoxError>;
const PEER_TIMEOUT: Duration = Duration::from_secs(10);
const SENTINEL: &[u8] = b"caller-owned partial bytes";
const WIRE_BODY: &[u8] = b"independently observed HTTP/3 download";

struct DownloadDirectory(Option<PathBuf>);

impl DownloadDirectory {
    fn create() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("phantom-download-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(Some(path)))
    }

    fn path(&self) -> TestResult<&Path> {
        self.0
            .as_deref()
            .ok_or_else(|| "download directory already removed".into())
    }

    fn finish(mut self) -> TestResult {
        std::fs::remove_dir_all(self.path()?)?;
        self.0.take();
        Ok(())
    }
}

impl Drop for DownloadDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            // Failed assertions still own this uniquely created directory.
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn offline_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(chrome::v154_tcp_tls())).build()?)
}

async fn recorded_download_one(
    client: Client,
    directory: PathBuf,
    target: DownloadTarget,
    cleanup: CleanupFailures,
) -> TestResult {
    let result = download_one_owned(client, directory, target, cleanup.clone()).await;
    cleanup.finish(result)
}

#[tokio::test]
async fn refused_pre_existing_partial_keeps_its_original_bytes() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let partial = directory.path()?.join(".first.part");
    std::fs::write(&partial, SENTINEL)?;
    let target = DownloadTarget::parse("https://server/first")?;
    let failure = timeout(
        PEER_TIMEOUT,
        download_one(offline_client()?, directory.path()?.to_owned(), target),
    )
    .await?
    .err()
    .ok_or("pre-existing partial was accepted")?;
    let cause = failure
        .downcast_ref::<io::Error>()
        .ok_or("refusal did not retain the file error")?;
    assert_eq!(cause.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&partial)?, SENTINEL);
    assert!(!directory.path()?.join("first").exists());

    directory.finish()
}

#[tokio::test]
async fn batch_refusal_before_creation_preserves_pre_existing_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let final_path = directory.path()?.join("first");
    let partial = directory.path()?.join(".first.part");
    std::fs::write(&final_path, b"caller-owned completed bytes")?;
    std::fs::write(&partial, SENTINEL)?;
    let config = Config::parse(
        "https://server/first",
        PathBuf::from("unused-ca.pem"),
        directory.path()?.to_owned(),
    )?;
    let failure = timeout(PEER_TIMEOUT, download_all(offline_client()?, config))
        .await?
        .err()
        .ok_or("pre-existing completed download was accepted")?;
    let cause = failure
        .downcast_ref::<io::Error>()
        .ok_or("batch refusal did not retain its cause")?;
    assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
    assert!(
        cause
            .to_string()
            .starts_with("refusing to replace existing download ")
    );
    assert_eq!(std::fs::read(&partial)?, SENTINEL);
    assert_eq!(std::fs::read(&final_path)?, b"caller-owned completed bytes");

    directory.finish()
}

struct LoopbackPeer {
    address: SocketAddr,
    client: Client,
    request: Option<oneshot::Receiver<(Method, String)>>,
    respond: Option<oneshot::Sender<()>>,
    stop: Option<oneshot::Sender<()>>,
    tasks: JoinSet<TestResult>,
}

impl LoopbackPeer {
    fn bind(status: StatusCode) -> TestResult<Self> {
        let mut root_params = CertificateParams::new(Vec::<String>::new())?;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate()?)?;
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_owned()])?;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate()?;
        let leaf = leaf_params.signed_by(&leaf_key, &root)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
            phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let address = endpoint.local_addr()?;

        let settings = Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        );
        let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http3(settings);
        let client = Client::builder(profile)
            .add_root_certificate_der(root.der().to_vec())
            .build()?;

        let (observed, request) = oneshot::channel();
        let (respond, ready) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            timeout(PEER_TIMEOUT, async {
                let incoming = endpoint.accept().await.ok_or("loopback endpoint closed")?;
                let connection = incoming.await?;
                let mut connection =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await?;
                let resolver = connection.accept().await?.ok_or("client sent no request")?;
                let (request, mut stream) = resolver.resolve_request().await?;

                observed
                    .send((request.method().clone(), request.uri().path().to_owned()))
                    .map_err(|_| "observation receiver dropped")?;

                ready.await?;
                stream
                    .send_response(Response::builder().status(status).body(())?)
                    .await?;
                if status.is_success() {
                    stream.send_data(Bytes::from_static(WIRE_BODY)).await?;
                    stream.finish().await?;
                }

                stopped.await?;
                drop(connection);
                Ok::<(), BoxError>(())
            })
            .await?
        });

        Ok(Self {
            address,
            client,
            request: Some(request),
            respond: Some(respond),
            stop: Some(stop),
            tasks,
        })
    }

    async fn observed(&mut self) -> TestResult<(Method, String)> {
        timeout(
            PEER_TIMEOUT,
            self.request.take().ok_or("request already observed")?,
        )
        .await?
        .map_err(Into::into)
    }

    fn respond(&mut self) -> TestResult {
        self.respond
            .take()
            .ok_or("response already released")?
            .send(())
            .map_err(|()| "response peer stopped".into())
    }

    async fn cancel(mut self) -> TestResult {
        self.tasks.abort_all();
        timeout(PEER_TIMEOUT, async {
            while let Some(result) = self.tasks.join_next().await {
                let error = result.err().ok_or("cancelled peer completed normally")?;
                assert!(error.is_cancelled());
            }
            Ok::<(), BoxError>(())
        })
        .await?
    }

    async fn finish(mut self) -> TestResult {
        self.stop
            .take()
            .ok_or("peer already stopped")?
            .send(())
            .map_err(|()| "loopback peer stopped before cleanup")?;
        timeout(PEER_TIMEOUT, async {
            while let Some(result) = self.tasks.join_next().await {
                result??;
            }
            Ok::<(), BoxError>(())
        })
        .await?
    }
}

#[tokio::test]
async fn successful_download_publishes_only_its_observed_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let target = DownloadTarget::loopback(peer.address)?;

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    assert!(partial.exists());
    assert!(!directory.path()?.join("first").exists());

    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;
    result??;

    assert_eq!(std::fs::read(directory.path()?.join("first"))?, WIRE_BODY);
    assert!(!partial.exists());
    assert!(!partial.parent().ok_or("stage has no parent")?.exists());

    directory.finish()
}

#[tokio::test]
async fn failed_observed_download_removes_its_created_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::SERVICE_UNAVAILABLE)?;
    let target = DownloadTarget::loopback(peer.address)?;

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    assert!(partial.exists());

    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;

    let failure = result?.err().ok_or("503 download was accepted")?;
    let cause = failure
        .downcast_ref::<io::Error>()
        .ok_or("HTTP failure did not retain its cause")?;
    assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
    assert!(cause.to_string().contains("returned HTTP 503"));
    assert!(!partial.exists());
    assert!(!partial.parent().ok_or("stage has no parent")?.exists());
    assert!(!directory.path()?.join("first").exists());

    directory.finish()
}

#[tokio::test]
async fn failed_download_preserves_caller_replacement_of_shared_legacy_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::SERVICE_UNAVAILABLE)?;
    let target = DownloadTarget::loopback(peer.address)?;
    let partial = directory.path()?.join(".first.part");
    let sibling = directory.path()?.join("caller-sibling.part");
    std::fs::write(&sibling, SENTINEL)?;

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let owned = cleanup.created_partial()?;
    assert_eq!(std::fs::read(&owned)?, b"");
    assert!(!partial.exists());
    std::fs::write(&partial, b"caller-created legacy partial")?;
    std::fs::rename(&partial, directory.path()?.join("caller-moved-file"))?;
    std::fs::write(&partial, SENTINEL)?;
    assert_eq!(std::fs::read(&partial)?, SENTINEL);

    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;

    let failure = result?.err().ok_or("503 download was accepted")?;
    let cause = failure
        .downcast_ref::<io::Error>()
        .or_else(|| failure.source()?.downcast_ref::<io::Error>())
        .ok_or("HTTP failure did not retain its cause")?;
    assert_eq!(cause.kind(), io::ErrorKind::InvalidData);
    assert!(cause.to_string().contains("returned HTTP 503"));
    assert_eq!(std::fs::read(&partial)?, SENTINEL);
    assert!(!directory.path()?.join("first").exists());
    assert!(!owned.exists());
    assert!(!owned.parent().ok_or("stage has no parent")?.exists());
    assert_eq!(std::fs::read(&sibling)?, SENTINEL);
    assert_eq!(
        std::fs::read(directory.path()?.join("caller-moved-file"))?,
        b"caller-created legacy partial"
    );

    directory.finish()
}

#[tokio::test]
async fn successful_download_preserves_caller_replacement_of_shared_legacy_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let target = DownloadTarget::loopback(peer.address)?;
    let partial = directory.path()?.join(".first.part");
    let sibling = directory.path()?.join("caller-sibling.part");
    std::fs::write(&sibling, SENTINEL)?;

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let owned = cleanup.created_partial()?;
    assert_eq!(std::fs::read(&owned)?, b"");
    assert!(!partial.exists());
    std::fs::write(&partial, b"caller-created legacy partial")?;
    std::fs::rename(&partial, directory.path()?.join("caller-moved-file"))?;
    std::fs::write(&partial, SENTINEL)?;
    assert_eq!(std::fs::read(&partial)?, SENTINEL);

    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;
    result??;

    assert!(!owned.exists());
    assert_eq!(std::fs::read(directory.path()?.join("first"))?, WIRE_BODY);
    assert_eq!(std::fs::read(&partial)?, SENTINEL);
    assert_eq!(std::fs::read(&sibling)?, SENTINEL);
    assert_eq!(
        std::fs::read(directory.path()?.join("caller-moved-file"))?,
        b"caller-created legacy partial"
    );
    assert!(!owned.parent().ok_or("stage has no parent")?.exists());

    directory.finish()
}

#[test]
fn cancelled_queued_write_cleans_its_exclusively_created_partial() -> TestResult {
    use tokio::io::AsyncWriteExt as _;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?;
    let directory = DownloadDirectory::create()?;
    let path = directory.path()?.join(".first.part");
    let cleanup = CleanupFailures::default();
    let (started, ready) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();

    // Occupy the only blocking worker so the file write remains queued when
    // its owning future is dropped. Dropping release also ends this worker.
    let blocker = runtime.spawn_blocking(move || -> TestResult {
        started.send(())?;
        released.recv_timeout(PEER_TIMEOUT)?;
        Ok(())
    });
    ready.recv_timeout(PEER_TIMEOUT)?;
    runtime.block_on(async {
        let path = path.clone();
        let task_cleanup = cleanup.clone();
        let (written, queued) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut partial = PartialDownload::create(path, task_cleanup)?;
            partial.file()?.write_all(WIRE_BODY).await?;
            written
                .send(())
                .map_err(|()| "queued-write observer dropped")?;
            std::future::pending::<()>().await;
            Ok::<(), BoxError>(())
        });
        timeout(PEER_TIMEOUT, queued).await??;
        tasks.abort_all();
        let joined = timeout(PEER_TIMEOUT, tasks.join_next())
            .await?
            .ok_or("file writer task missing")?;
        assert!(
            joined
                .err()
                .ok_or("cancelled writer completed normally")?
                .is_cancelled()
        );
        cleanup.finish(Ok(()))
    })?;
    // The single worker consumes its FIFO queue; this marker runs after the
    // queued file write releases its retained handle.
    let drained = runtime.spawn_blocking(|| ());

    release.send(())?;
    runtime.block_on(async { timeout(PEER_TIMEOUT, blocker).await })???;
    runtime.block_on(async { timeout(PEER_TIMEOUT, drained).await })??;
    runtime.shutdown_timeout(PEER_TIMEOUT);
    assert!(!path.exists());
    let owned = cleanup.created_partial()?;
    assert!(!owned.exists());
    assert!(!owned.parent().ok_or("stage has no parent")?.exists());
    directory.finish()
}

#[tokio::test]
async fn cancelled_batch_cleans_observed_partial_without_touching_foreign_paths() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let foreign = directory.path()?.join(".unrelated.part");
    std::fs::write(&foreign, SENTINEL)?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let config = Config {
        ca_pem: PathBuf::from("unused-ca.pem"),
        download_directory: directory.path()?.to_owned(),
        targets: vec![DownloadTarget::loopback(peer.address)?],
    };

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(download_all_with_cleanup(
        peer.client.clone(),
        config,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    assert!(partial.exists());
    tasks.abort_all();
    let joined = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("batch task missing")?;
    assert!(
        joined
            .err()
            .ok_or("cancelled batch completed")?
            .is_cancelled()
    );
    peer.cancel().await?;

    let stage = partial.parent().ok_or("stage has no parent")?;
    timeout(PEER_TIMEOUT, async {
        while partial.exists() || stage.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(std::fs::read(foreign)?, SENTINEL);
    assert!(!directory.path()?.join("first").exists());
    directory.finish()
}

#[tokio::test]
async fn output_created_during_download_is_preserved_and_owned_partial_removed() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let target = DownloadTarget::loopback(peer.address)?;
    let output = directory.path()?.join("first");

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    assert!(partial.exists());
    std::fs::write(&output, SENTINEL)?;
    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;

    let error = result?.err().ok_or("late output was replaced")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("publication lost its file error")?
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(output)?, SENTINEL);
    assert!(!partial.exists());
    assert!(!partial.parent().ok_or("stage has no parent")?.exists());
    directory.finish()
}

#[tokio::test]
async fn batch_failure_retains_http_cause_and_reports_partial_cleanup_failure() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::SERVICE_UNAVAILABLE)?;
    let config = Config {
        ca_pem: PathBuf::from("unused-ca.pem"),
        download_directory: directory.path()?.to_owned(),
        targets: vec![DownloadTarget::loopback(peer.address)?],
    };

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(download_all_with_cleanup(
        peer.client.clone(),
        config,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    // Replace the observed owned file with a test-owned directory. remove_file
    // must fail, so the cleanup diagnostic cannot silently disappear.
    std::fs::rename(&partial, directory.path()?.join("moved-owned-file"))?;
    std::fs::create_dir(&partial)?;
    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("batch task missing")?;
    peer.finish().await?;

    let error = result?.err().ok_or("failed batch was accepted")?;
    let source = error
        .source()
        .ok_or("cleanup failure lost the original HTTP cause")?
        .downcast_ref::<io::Error>()
        .ok_or("original HTTP cause changed type")?;
    assert_eq!(source.kind(), io::ErrorKind::InvalidData);
    assert!(source.to_string().contains("returned HTTP 503"));
    assert!(error.to_string().contains("cleanup of "));
    assert!(error.to_string().contains("download.part failed: "));
    assert!(!directory.path()?.join("first").exists());
    directory.finish()
}

#[cfg(windows)]
#[tokio::test]
async fn removal_failure_after_publication_keeps_completed_file_and_reports_both_causes()
-> TestResult {
    use std::os::windows::fs::OpenOptionsExt as _;

    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let target = DownloadTarget::loopback(peer.address)?;

    let cleanup = CleanupFailures::default();
    let mut tasks = JoinSet::new();
    tasks.spawn(recorded_download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
        cleanup.clone(),
    ));

    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    let partial = cleanup.created_partial()?;
    // Permit the active writer and hard-link creation, but deny deletion.
    let blocker = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(&partial)?;
    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;

    let error = result?.err().ok_or("failed partial removal was ignored")?;
    let publication = error
        .source()
        .ok_or("partial cleanup lost the publication failure")?;
    assert!(publication.to_string().starts_with("published download "));
    let source = publication
        .source()
        .ok_or("publication failure lost its original file cause")?
        .downcast_ref::<io::Error>()
        .ok_or("partial removal changed its error type")?;
    assert_eq!(source.raw_os_error(), Some(32));
    assert!(error.to_string().contains("cleanup of "));
    assert_eq!(std::fs::read(directory.path()?.join("first"))?, WIRE_BODY);
    assert_eq!(std::fs::read(&partial)?, WIRE_BODY);

    drop(blocker);
    directory.finish()
}

#[test]
fn staging_cleanup_reports_unowned_entries_without_removing_them() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let cleanup = CleanupFailures::default();
    let owner = PartialDownload::create(directory.path()?.join(".first.part"), cleanup.clone())?;
    let partial = cleanup.created_partial()?;
    let stage = partial.parent().ok_or("stage has no parent")?;
    let unowned = stage.join("injected-cleanup-obstruction");
    std::fs::write(&unowned, SENTINEL)?;

    drop(owner);
    let error = cleanup
        .finish(Ok(()))
        .err()
        .ok_or("nonempty stage cleanup failure was ignored")?;
    assert!(error.to_string().contains("cleanup of "));
    assert!(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .is_some()
    );
    assert!(!partial.exists());
    assert_eq!(std::fs::read(unowned)?, SENTINEL);
    assert!(stage.exists());

    directory.finish()
}

#[tokio::test]
async fn concurrent_download_owners_publish_once_and_clean_only_their_staging() -> TestResult {
    use tokio::io::AsyncWriteExt as _;

    let directory = DownloadDirectory::create()?;
    let legacy = directory.path()?.join(".first.part");
    let output = directory.path()?.join("first");
    let first_cleanup = CleanupFailures::default();
    let second_cleanup = CleanupFailures::default();
    let mut first = PartialDownload::create(legacy.clone(), first_cleanup.clone())?;
    let mut second = PartialDownload::create(legacy.clone(), second_cleanup.clone())?;
    let first_partial = first_cleanup.created_partial()?;
    let second_partial = second_cleanup.created_partial()?;
    let first_stage = first_partial.parent().ok_or("first stage has no parent")?;
    let second_stage = second_partial
        .parent()
        .ok_or("second stage has no parent")?;

    assert_ne!(first_stage, second_stage);
    assert!(!legacy.exists());

    first.file()?.write_all(WIRE_BODY).await?;
    first.file()?.flush().await?;
    second.file()?.write_all(SENTINEL).await?;
    second.file()?.flush().await?;
    first.publish(&output)?;

    assert_eq!(std::fs::read(&output)?, WIRE_BODY);
    assert!(!first_stage.exists());
    assert_eq!(std::fs::read(&second_partial)?, SENTINEL);
    assert!(second_stage.exists());

    let error = second
        .publish(&output)
        .err()
        .ok_or("second publication replaced the output")?;
    assert_eq!(
        error
            .downcast_ref::<io::Error>()
            .ok_or("publication changed the file error type")?
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&output)?, WIRE_BODY);

    drop(first);
    drop(second);
    first_cleanup.finish(Ok(()))?;
    second_cleanup.finish(Ok(()))?;
    assert!(!first_stage.exists());
    assert!(!second_stage.exists());
    assert!(!legacy.exists());
    assert_eq!(std::fs::read(output)?, WIRE_BODY);

    directory.finish()
}

#[cfg(unix)]
#[test]
fn distinct_staging_directories_have_owner_only_unix_permissions() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = DownloadDirectory::create()?;
    let legacy = directory.path()?.join(".first.part");
    let first_cleanup = CleanupFailures::default();
    let second_cleanup = CleanupFailures::default();
    let first = PartialDownload::create(legacy.clone(), first_cleanup.clone())?;
    let second = PartialDownload::create(legacy, second_cleanup.clone())?;
    let first_partial = first_cleanup.created_partial()?;
    let second_partial = second_cleanup.created_partial()?;
    let first_stage = first_partial.parent().ok_or("first stage has no parent")?;
    let second_stage = second_partial
        .parent()
        .ok_or("second stage has no parent")?;

    assert_ne!(first_stage, second_stage);
    assert_eq!(
        std::fs::metadata(first_stage)?.permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(second_stage)?.permissions().mode() & 0o777,
        0o700
    );
    drop(first);
    drop(second);
    first_cleanup.finish(Ok(()))?;
    second_cleanup.finish(Ok(()))?;
    assert!(!first_stage.exists());
    assert!(!second_stage.exists());

    directory.finish()
}

#[test]
fn config_accepts_distinct_runner_urls() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::parse(
        "https://server:443/first https://server:443/second",
        PathBuf::from("ca.pem"),
        PathBuf::from("downloads"),
    )?;

    assert_eq!(config.targets.len(), 2);
    assert_eq!(config.targets[0].file_name(), "first");
    assert_eq!(config.targets[1].file_name(), "second");
    Ok(())
}

#[test]
fn config_rejects_empty_duplicate_and_unbounded_requests() {
    let parse = |requests: &str| {
        Config::parse(
            requests,
            PathBuf::from("ca.pem"),
            PathBuf::from("downloads"),
        )
    };

    assert!(parse("").is_err());
    assert!(parse("https://server/same https://server/same").is_err());
    let too_many = std::iter::repeat_n("https://server/file", MAX_REQUESTS + 1)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(parse(&too_many).is_err());
}

#[test]
fn config_requires_one_origin() {
    assert!(
        Config::parse(
            "https://server/first https://server4/second",
            PathBuf::from("ca.pem"),
            PathBuf::from("downloads"),
        )
        .is_err()
    );
}
