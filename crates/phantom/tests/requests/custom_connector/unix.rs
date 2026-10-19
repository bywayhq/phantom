use super::*;

#[tokio::test]
async fn unix_socket_preserves_http_authority_without_dns() -> TestResult<()> {
    timeout(LIMIT, async {
        struct SocketPath(std::path::PathBuf);
        impl Drop for SocketPath {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = SocketPath(
            std::env::temp_dir().join(format!("ph-{}-{unique:x}.sock", std::process::id())),
        );
        let path = &path.0;
        let listener = tokio::net::UnixListener::bind(path)?;
        let client = builder(TcpConnector::unix_socket(path.clone())).build()?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            assert!(
                head.windows(b"Host: unresolved.invalid:4321\r\n".len())
                    .any(|part| part == b"Host: unresolved.invalid:4321\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(get(&client), peer)?;
        Ok(())
    })
    .await?
}
