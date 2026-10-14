//! Directly owned pinned Python process for explicit interoperability tests.

use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use serde_json::Value;

use super::*;

static NEXT_PEER: AtomicU64 = AtomicU64::new(0);

pub(crate) struct PythonPeer {
    pub(crate) address: SocketAddr,
    directory: PathBuf,
    child: Child,
}

impl PythonPeer {
    pub(crate) async fn spawn(
        identity: &TestIdentity,
        leg: &str,
        challenge: bool,
    ) -> TestResult<Self> {
        let interpreter = std::env::var_os("PHANTOM_CONNECT_UDP_PYTHON").ok_or("set PHANTOM_CONNECT_UDP_PYTHON to an interpreter with aioquic 1.3.0, h2 4.4.1 and hpack 4.2.0")?;
        let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let directory = project
            .join("target/transport-profile-campaign/connect-udp-peer")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT_PEER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("certificate.der"), identity.leaf_der())?;
        fs::write(directory.join("key.der"), identity.private_key_der())?;
        let mut command = Command::new(interpreter);
        command
            .current_dir(&project)
            .args([
                "-m",
                "scripts.conformance.connect_udp_peer",
                "--leg",
                leg,
                "--directory",
            ])
            .arg(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(fs::File::create(directory.join("stdout.log"))?))
            .stderr(Stdio::from(fs::File::create(directory.join("stderr.log"))?));
        if challenge {
            command.arg("--challenge");
        }
        let child = command.spawn()?;
        let mut peer = Self {
            address: "127.0.0.1:1".parse()?,
            directory,
            child,
        };
        timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = peer.child.try_wait()? {
                    return Err(format!(
                        "Python CONNECT-UDP peer stopped before readiness: {status}; see {}",
                        peer.directory.display()
                    )
                    .into());
                }
                let ready = peer.directory.join("ready.json");
                if ready.exists() {
                    let value: Value = serde_json::from_slice(&fs::read(ready)?)?;
                    let port = value["port"]
                        .as_u64()
                        .and_then(|p| u16::try_from(p).ok())
                        .filter(|p| *p != 0)
                        .ok_or("invalid Python peer port")?;
                    assert_eq!(value["aioquic"], "1.3.0");
                    assert_eq!(value["h2"], "4.4.1");
                    assert_eq!(value["hpack"], "4.2.0");
                    assert_eq!(value["leg"], leg);
                    peer.address.set_port(port);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        Ok(peer)
    }

    pub(crate) fn template(&self) -> String {
        format!(
            "https://127.0.0.1:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            self.address.port()
        )
    }
    pub(crate) fn stats(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&fs::read(
            self.directory.join("stats.json"),
        )?)?)
    }

    pub(crate) async fn finish(&mut self) -> TestResult<()> {
        fs::write(self.directory.join("stop"), [])?;
        let status = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = self.child.try_wait()? {
                    return Ok::<_, io::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        assert!(status.success(), "Python peer exit {status}");
        assert_eq!(self.stats()?["failures"], serde_json::json!([]));
        Ok(())
    }
}

impl Drop for PythonPeer {
    fn drop(&mut self) {
        // The child is the Python interpreter itself, not a launcher. Killing
        // it cannot strand a relay process beneath an intermediate parent.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
