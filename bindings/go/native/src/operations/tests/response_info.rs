use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    num::NonZeroUsize,
    thread,
    time::{Duration, Instant},
};

fn peer(listener: TcpListener) -> std::io::Result<Vec<String>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut targets = Vec::new();
    for reply in [
        "HTTP/1.1 302 Found\r\nLocation: /middle\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: /final%2Fpath?x=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    ] {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::other("request did not reach peer"));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            head.push(byte[0]);
            if head.len() > 32 * 1024 {
                return Err(std::io::Error::other("request head exceeded peer limit"));
            }
        }
        let line = head.split(|byte| *byte == b'\r').next().unwrap_or_default();
        targets.push(String::from_utf8_lossy(line).into_owned());
        stream.write_all(reply.as_bytes())?;
    }
    Ok(targets)
}

#[test]
fn actual_redirect_chain_serializes_response_info_and_requires_it() -> Result<(), Failure> {
    let global = test_global()?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| Failure::new("peer_io"))?;
    let address = listener.local_addr().map_err(|_| Failure::new("peer_io"))?;
    let worker = thread::spawn(move || peer(listener));
    let client = phantom::Client::builder(
        phantom_profile::browser::chrome::v154_windows().without_request_template(),
    )
    .redirect_policy(phantom::RedirectPolicy::limited(
        NonZeroUsize::new(2).ok_or_else(|| Failure::new("internal"))?,
    ))
    .request_timeouts(phantom::RequestTimeouts::new().total(Duration::from_secs(5)))
    .build()
    .map_err(Failure::from)?;
    let response = global.runtime.block_on(async {
        client
            .request(
                phantom::HttpProtocol::Http1,
                http::Method::GET,
                &format!("http://{address}/original?x=a%20b"),
            )
            .map_err(Failure::from)?
            .send()
            .await
            .map_err(Failure::from)
    })?;
    let head = response_head(response, 1, global.upload(0)?)?;
    let id = global.lock().reserve(Target::Request(1))?.0;
    global.finish(id, Ok(Outcome::Head(head)));
    {
        let mut state = global.lock();
        let completion = state
            .ready
            .pop_front()
            .ok_or_else(|| Failure::new("internal"))?
            .completion;
        let metadata: Value =
            serde_json::from_slice(&completion.metadata).map_err(|_| Failure::new("internal"))?;
        assert_eq!(
            metadata["value"]["effective_url"],
            format!("http://{address}/final%2Fpath?x=1")
        );
        assert_eq!(metadata["value"]["redirects_followed"], 2);
        assert_eq!(metadata["value"]["connection_setup_retries"], 0);
        assert_eq!(metadata["value"]["status"], 200);
        assert_eq!(metadata["value"]["protocol"], "h1");
        let headers = metadata["value"]["headers"]
            .as_array()
            .ok_or_else(|| Failure::new("internal"))?;
        let duplicate_values: Vec<_> = headers
            .iter()
            .filter(|header| header["name"] == "X-Duplicate")
            .map(|header| header["value"].clone())
            .collect();
        assert_eq!(
            duplicate_values,
            [json!([111, 110, 101]), json!([116, 119, 111])]
        );
        state.cancel(id);
        assert!(state.bodies.is_empty());
    }
    let mut response = global.runtime.block_on(async {
        client
            .request(
                phantom::HttpProtocol::Http1,
                http::Method::GET,
                &format!("http://{address}/missing"),
            )
            .map_err(Failure::from)?
            .send()
            .await
            .map_err(Failure::from)
    })?;
    response.extensions_mut().remove::<phantom::ResponseInfo>();
    assert_eq!(
        response_head(response, 1, global.upload(0)?)
            .err()
            .map(|error| error.kind),
        Some("response_info_unavailable")
    );
    let targets = worker
        .join()
        .map_err(|_| Failure::new("peer_panic"))?
        .map_err(|_| Failure::new("peer_io"))?;
    assert_eq!(
        targets,
        [
            "GET /original?x=a%20b HTTP/1.1",
            "GET /middle HTTP/1.1",
            "GET /final%2Fpath?x=1 HTTP/1.1",
            "GET /missing HTTP/1.1",
        ]
    );
    Ok(())
}
