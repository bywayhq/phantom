use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use wreq::{Client, Version, tls::trust::CertStore};
use wreq_util::Emulation;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("expected DER certificate, two URLs, and output directory".into());
    }
    let certificate = std::fs::read(&args[0])?;
    let store = CertStore::builder()
        .add_der_cert(certificate.as_slice())
        .build()?;
    let urls = [
        args[1].to_str().ok_or("first URL is not UTF-8")?,
        args[2].to_str().ok_or("second URL is not UTF-8")?,
    ];
    let output = PathBuf::from(&args[3]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let client = Client::builder()
            .emulation(Emulation::SafariIos26)
            .tls_cert_store(store)
            .resolve(
                "server.phantom.test",
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()?;
        tokio::time::timeout(Duration::from_secs(35), async {
            for (index, url) in urls.into_iter().enumerate() {
                let response = client.get(url).send().await?;
                if response.version() != Version::HTTP_2 {
                    return Err("request did not negotiate HTTP/2".into());
                }
                let status = response.status().as_u16();
                let expected_status = if index == 0 { 200 } else { 204 };
                if status != expected_status {
                    return Err(format!("unexpected response status: {status}").into());
                }
                let body = response.bytes().await?;
                let expected = if index == 0 {
                    b"peer capture\n".as_slice()
                } else {
                    b""
                };
                if body.as_ref() != expected {
                    return Err("response body did not match the controlled peer".into());
                }
                std::fs::write(output.join(format!("response-{}.body", index + 1)), &body)?;
                println!(
                    "request={} protocol=h2 status={status} bytes={}",
                    index + 1,
                    body.len()
                );
            }
            Ok::<_, Box<dyn Error>>(())
        })
        .await?
    })?;
    Ok(())
}
