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

use super::{BoxError, Config, MAX_REQUESTS, download_all, download_one, target::DownloadTarget};

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
async fn successful_download_renames_only_its_observed_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::OK)?;
    let target = DownloadTarget::loopback(peer.address)?;
    let mut tasks = JoinSet::new();
    tasks.spawn(download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
    ));
    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    assert!(directory.path()?.join(".first.part").exists());
    assert!(!directory.path()?.join("first").exists());
    peer.respond()?;
    let result = timeout(PEER_TIMEOUT, tasks.join_next())
        .await?
        .ok_or("download task missing")?;
    peer.finish().await?;
    result??;
    assert_eq!(std::fs::read(directory.path()?.join("first"))?, WIRE_BODY);
    assert!(!directory.path()?.join(".first.part").exists());
    directory.finish()
}

#[tokio::test]
async fn failed_observed_download_removes_its_created_partial() -> TestResult {
    let directory = DownloadDirectory::create()?;
    let mut peer = LoopbackPeer::bind(StatusCode::SERVICE_UNAVAILABLE)?;
    let target = DownloadTarget::loopback(peer.address)?;
    let mut tasks = JoinSet::new();
    tasks.spawn(download_one(
        peer.client.clone(),
        directory.path()?.to_owned(),
        target,
    ));
    assert_eq!(peer.observed().await?, (Method::GET, "/first".to_owned()));
    assert!(directory.path()?.join(".first.part").exists());
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
    assert!(!directory.path()?.join(".first.part").exists());
    assert!(!directory.path()?.join("first").exists());
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
