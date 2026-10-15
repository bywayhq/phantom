//! An owned, in-future CONNECT/TLS peer; no spawned fixture tasks.
use super::{Auth, TestResult};
use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::X509,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::{io, net::Ipv4Addr, pin::Pin};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_btls::SslStream;

pub(super) fn identity() -> TestResult<(Vec<u8>, SslAcceptor)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;
    let mut leaf = CertificateParams::new(Vec::<String>::new())?;
    leaf.subject_alt_names = vec![SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let key = KeyPair::generate()?;
    let leaf = leaf.signed_by(&key, &root)?;
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    let certificate = X509::from_der(leaf.der())?;
    let private_key = PKey::private_key_from_pkcs8(&key.serialize_der())?;
    acceptor.set_certificate(&certificate)?;
    acceptor.set_private_key(&private_key)?;
    acceptor.add_extra_chain_cert(X509::from_der(root.der())?)?;
    acceptor.set_alpn_select_callback(|_, offered| {
        btls::ssl::select_next_proto(b"\x08http/1.1", offered).ok_or(btls::ssl::AlpnError::NOACK)
    });
    Ok((root.der().to_vec(), acceptor.build()))
}

pub(super) async fn head(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == 32 * 1024 {
            return Err(io::Error::other("test request exceeds bound"));
        }
        stream.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    Ok(head)
}

pub(super) async fn serve(mut stream: TcpStream, acceptor: SslAcceptor, auth: Auth) -> TestResult {
    let anonymous = head(&mut stream).await?;
    assert_eq!(
        anonymous,
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\n\r\n"
    );
    if !matches!(auth, Auth::None) {
        let challenge = match auth {
            Auth::None => return Err("anonymous exchange was challenged".into()),
            Auth::Basic => "Basic realm=\"proxy\"",
            Auth::Digest => {
                "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\""
            }
        };
        stream.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
        let replay = String::from_utf8(head(&mut stream).await?)?;
        assert!(replay.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: second\r\nhost: 127.0.0.1:443\r\nProxy-Authorization: "));
        match auth {
            Auth::Basic => assert!(replay.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
            Auth::Digest => {
                assert!(replay.contains("Proxy-Authorization: Digest "));
                assert!(replay.contains("nc=00000001"));
                assert!(replay.contains("uri=\"127.0.0.1:443\""));
            }
            Auth::None => return Err("anonymous exchange replayed credentials".into()),
        }
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls = SslStream::new(ssl, stream)?;
    Pin::new(&mut tls).accept().await?;
    assert_eq!(
        head(&mut tls).await?,
        b"GET /claimed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    );
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    Ok(())
}
