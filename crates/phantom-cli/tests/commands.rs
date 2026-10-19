//! Exercise the installed command boundary against controlled loopback peers.

#[path = "commands/bundles.rs"]
mod bundles;

use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const PROFILE: &str = "chrome/154.0.8037.97/windows-11-26200/r1";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Directory(PathBuf);

impl Directory {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!(
            "phantom-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_phantom"))
}

fn request(url: &str) -> Command {
    let mut command = command();
    command.args([
        "request",
        url,
        "--profile",
        PROFILE,
        "--protocol",
        "h1",
        "--timeout-ms",
        "5000",
    ]);
    command
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn listener() -> TestResult<TcpListener> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?)
}

fn accept(listener: &TcpListener) -> TestResult<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Windows accepts inherit the listener's nonblocking mode.
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn head(stream: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        output.push(byte[0]);
        if output.ends_with(b"\r\n\r\n") {
            return Ok(output);
        }
        if output.len() > 16384 {
            return Err("oversized head".into());
        }
    }
}

#[test]
fn explicit_selection_and_profile_round_trip() -> TestResult {
    let version = command().arg("--version").output()?;
    success(&version);
    assert!(String::from_utf8(version.stdout)?.starts_with("phantom "));
    let listed = command().args(["profiles", "list"]).output()?;
    success(&listed);
    assert!(
        String::from_utf8(listed.stdout)?
            .lines()
            .any(|id| id == PROFILE)
    );
    let exported = command().args(["profiles", "export", PROFILE]).output()?;
    success(&exported);
    let directory = Directory::new()?;
    let source = directory.path("profile.json");
    fs::write(&source, &exported.stdout)?;
    let imported = command()
        .args(["profiles", "import"])
        .arg(&source)
        .output()?;
    success(&imported);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&exported.stdout)?,
        serde_json::from_slice::<serde_json::Value>(&imported.stdout)?
    );
    let missing = command()
        .args(["request", "https://example.invalid", "--protocol", "h1"])
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    let missing = command()
        .args(["request", "https://example.invalid", "--profile", PROFILE])
        .output()?;
    assert_eq!(missing.status.code(), Some(2));
    let description = command().args(["profiles", "describe", PROFILE]).output()?;
    success(&description);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&description.stdout)?["id"],
        PROFILE
    );
    Ok(())
}

#[test]
fn headers_keep_order_stdout_is_body_only_and_diagnostics_finish() -> TestResult {
    let directory = Directory::new()?;
    let diagnostics = directory.path("report.json");
    let listener = listener()?;
    let url = format!("http://{}/test?q=one", listener.local_addr()?);
    let peer = thread::spawn(move || -> TestResult<Vec<u8>> {
        let mut stream = accept(&listener)?;
        let head = head(&mut stream)?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")?;
        Ok(head)
    });
    let output = request(&url)
        .args([
            "--header",
            "X-First: one",
            "--header",
            "X-First: two",
            "--header",
            "x-Last: three",
            "--diagnostics",
        ])
        .arg(&diagnostics)
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .output()?;
    success(&output);
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty());
    let head = peer.join().map_err(|_| "peer panicked")??;
    let head = String::from_utf8(head)?;
    assert!(head.starts_with("GET /test?q=one HTTP/1.1\r\n"));
    assert!(head.contains("X-First: one\r\nX-First: two\r\nx-Last: three\r\n"));
    let report: serde_json::Value = serde_json::from_slice(&fs::read(diagnostics)?)?;
    assert_eq!(report["outcome"], "response_head");
    let events = report["events"].as_array().ok_or("no events")?;
    let body = events
        .iter()
        .find(|event| event["phase"] == "response_body")
        .ok_or("no body event")?;
    assert_eq!(body["outcome"], "completed");
    assert!(body["finished_seconds"].is_number());
    assert!(events.iter().any(|event| event["connection"].is_null()));
    let connection = events
        .iter()
        .find(|event| event["phase"] == "connection_use")
        .ok_or("no connection")?;
    assert_eq!(connection["connection"]["origin_tls"]["state"], "not_used");
    Ok(())
}

#[test]
fn file_upload_and_chunked_download_stream_through_the_command() -> TestResult {
    let directory = Directory::new()?;
    let input = directory.path("upload.bin");
    let download = directory.path("download.bin");
    let expected: Vec<u8> = (0..1_048_576).map(|index| (index % 251) as u8).collect();
    fs::write(&input, &expected)?;
    let listener = listener()?;
    let url = format!("http://{}/upload", listener.local_addr()?);
    let peer = thread::spawn(move || -> TestResult<Vec<u8>> {
        let mut stream = accept(&listener)?;
        let head = String::from_utf8(head(&mut stream)?)?;
        assert!(head.starts_with("PUT /upload HTTP/1.1\r\n"));
        assert!(
            head.to_ascii_lowercase()
                .contains("content-length: 1048576\r\n")
        );
        let mut received = vec![0; 1_048_576];
        stream.read_exact(&mut received)?;
        stream.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )?;
        for chunk in received.chunks(4096) {
            write!(stream, "{:x}\r\n", chunk.len())?;
            stream.write_all(chunk)?;
            stream.write_all(b"\r\n")?;
        }
        stream.write_all(b"0\r\n\r\n")?;
        Ok(received)
    });
    let output = request(&url)
        .args(["--method", "PUT", "--upload"])
        .arg(&input)
        .arg("--output")
        .arg(&download)
        .output()?;
    success(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(peer.join().map_err(|_| "peer panicked")??, expected);
    assert_eq!(fs::read(download)?, expected);
    Ok(())
}

#[test]
fn attempt_zero_and_incompatible_proxy_protocol_never_send() -> TestResult {
    let listener = listener()?;
    let address = listener.local_addr()?;
    let zero = request(&format!("http://{address}/"))
        .args(["--attempts", "0"])
        .output()?;
    assert_eq!(zero.status.code(), Some(1));
    listener.set_nonblocking(true)?;
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    let incompatible = command()
        .args([
            "request",
            "https://example.invalid/",
            "--profile",
            PROFILE,
            "--protocol",
            "h3",
            "--proxy",
            &format!("http://{address}"),
        ])
        .output()?;
    assert_eq!(incompatible.status.code(), Some(1));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn explicit_http_and_socks5_remote_proxy_routes_work() -> TestResult {
    for scheme in ["http", "socks5h"] {
        let listener = listener()?;
        let proxy = format!("{scheme}://{}", listener.local_addr()?);
        let peer = thread::spawn(move || -> TestResult {
            let mut stream = accept(&listener)?;
            if scheme == "socks5h" {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting)?;
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0])?;
                let mut destination = [0; 5];
                stream.read_exact(&mut destination)?;
                assert_eq!(&destination[..4], &[5, 1, 0, 3]);
                let mut host_port = vec![0; usize::from(destination[4]) + 2];
                stream.read_exact(&mut host_port)?;
                assert_eq!(&host_port[..host_port.len() - 2], b"origin.invalid");
                stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
            }
            let head = String::from_utf8(head(&mut stream)?)?;
            assert!(head.starts_with(if scheme == "http" {
                "GET http://origin.invalid/path HTTP/1.1\r\n"
            } else {
                "GET /path HTTP/1.1\r\n"
            }));
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproxy",
            )?;
            Ok(())
        });
        let output = request("http://origin.invalid/path")
            .args(["--proxy", &proxy])
            .output()?;
        success(&output);
        assert_eq!(output.stdout, b"proxy");
        peer.join().map_err(|_| "peer panicked")??;
    }
    Ok(())
}

#[test]
fn deadline_ends_a_stalled_body_and_retains_incomplete_diagnostics() -> TestResult {
    let directory = Directory::new()?;
    let diagnostics = directory.path("deadline.json");
    let listener = listener()?;
    let url = format!("http://{}/", listener.local_addr()?);
    let peer = thread::spawn(move || -> TestResult {
        let mut stream = accept(&listener)?;
        let _head = head(&mut stream)?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\na")?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                Ok(())
            }
            _ => Err("client did not cancel the incomplete body".into()),
        }
    });
    let output = command()
        .args([
            "request",
            &url,
            "--profile",
            PROFILE,
            "--protocol",
            "h1",
            "--timeout-ms",
            "250",
            "--diagnostics",
        ])
        .arg(&diagnostics)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, b"a");
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&diagnostics)?)?;
    let body = report["events"]
        .as_array()
        .ok_or("no events")?
        .iter()
        .find(|event| event["phase"] == "response_body")
        .ok_or("no body phase")?;
    assert_ne!(body["outcome"], "completed");
    peer.join().map_err(|_| "peer panicked")??;
    Ok(())
}

#[test]
fn existing_outputs_are_preserved_and_invalid_profiles_are_bounded() -> TestResult {
    let directory = Directory::new()?;
    let output = directory.path("existing");
    fs::write(&output, b"keep")?;
    let response = request("http://127.0.0.1:1/")
        .arg("--output")
        .arg(&output)
        .output()?;
    assert_eq!(response.status.code(), Some(1));
    assert_eq!(fs::read(&output)?, b"keep");
    let profile = directory.path("oversized.json");
    fs::File::create(&profile)?.set_len(16 * 1024 * 1024 + 1)?;
    let response = command()
        .args(["profiles", "import"])
        .arg(profile)
        .output()?;
    assert_eq!(response.status.code(), Some(2));
    assert!(response.stdout.is_empty());
    Ok(())
}

#[test]
fn a_closed_stdout_pipe_is_an_operation_error() -> TestResult {
    let listener = listener()?;
    let url = format!("http://{}/", listener.local_addr()?);
    let peer = thread::spawn(move || -> TestResult {
        let mut stream = accept(&listener)?;
        let _head = head(&mut stream)?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n")?;
        match stream.write_all(&[42; 65536]) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    });
    let mut child = request(&url)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    drop(child.stdout.take());
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!output.stderr.is_empty());
    peer.join().map_err(|_| "peer panicked")??;
    Ok(())
}

#[test]
fn http_error_status_requires_fail_and_keeps_the_downloaded_body() -> TestResult {
    for fail in [false, true] {
        let listener = listener()?;
        let url = format!("http://{}/missing", listener.local_addr()?);
        let peer = thread::spawn(move || -> TestResult {
            let mut stream = accept(&listener)?;
            let _head = head(&mut stream)?;
            stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing",
            )?;
            Ok(())
        });
        let mut command = request(&url);
        if fail {
            command.arg("--fail");
        }
        let output = command.output()?;
        assert_eq!(output.status.code(), Some(if fail { 22 } else { 0 }));
        assert_eq!(output.stdout, b"missing");
        peer.join().map_err(|_| "peer panicked")??;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn control_c_cancels_proxy_setup_upload_and_body_reads() -> TestResult {
    use std::{process::Stdio, sync::mpsc};
    for stage in ["setup", "upload", "body"] {
        let directory = Directory::new()?;
        let report = directory.path("report.json");
        let upload = directory.path("upload.bin");
        fs::File::create(&upload)?.set_len(32 * 1024 * 1024)?;
        let listener = listener()?;
        let address = listener.local_addr()?;
        let (ready, wait) = mpsc::channel();
        let peer = thread::spawn(move || -> TestResult {
            let mut stream = accept(&listener)?;
            let _head = head(&mut stream)?;
            if stage == "body" {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\na")?;
            }
            ready.send(())?;
            // Stop reading an upload until cancellation closes its connection.
            thread::sleep(Duration::from_millis(100));
            let mut bytes = [0; 8192];
            loop {
                match stream.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });
        let url = format!("http://{address}/");
        let mut command = request(&url);
        if stage == "setup" {
            command = request("https://origin.example/");
            command.args(["--proxy", &format!("http://{address}")]);
        } else if stage == "upload" {
            command.args(["--method", "PUT", "--upload"]).arg(&upload);
        }
        let mut child = command
            .arg("--diagnostics")
            .arg(&report)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        wait.recv_timeout(Duration::from_secs(10))?;
        assert!(
            Command::new("kill")
                .args(["-INT", &child.id().to_string()])
                .status()?
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(6);
        while child.try_wait()?.is_none() {
            if Instant::now() > deadline {
                child.kill()?;
                return Err("cancelled command did not exit".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output()?;
        assert_eq!(output.status.code(), Some(130));
        let report: serde_json::Value = serde_json::from_slice(&fs::read(&report)?)?;
        assert_ne!(report["outcome"], "pending");
        peer.join().map_err(|_| "peer panicked")??;
    }
    Ok(())
}
