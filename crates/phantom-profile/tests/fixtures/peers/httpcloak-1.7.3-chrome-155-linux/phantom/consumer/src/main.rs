use std::{error::Error, io::Write, net::Ipv4Addr, path::Path, time::Duration};

use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestHeader, RequestTimeouts, ResponseInfo,
    RetryPolicy, Route, Uri,
    fingerprint::export_profile_json,
    profile::catalog::{self, ProfileLayer, RequestTemplateKind},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:?}");
        let mut cause = error.source();
        for _ in 0..8 {
            let Some(error) = cause else {
                break;
            };
            eprintln!("caused by: {error}");
            cause = error.source();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| "argument is not UTF-8"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if args.len() != 5 {
        return Err(
            "expected certificate.pem, base URL, output, baseline|boundary and run token".into(),
        );
    }
    let base: Uri = args[1].parse()?;
    let port = base
        .port_u16()
        .filter(|&port| port != 0)
        .ok_or("missing port")?;
    if base.scheme_str() != Some("https")
        || base.host() != Some("server.phantom.test")
        || base.authority().map(|a| a.as_str())
            != Some(format!("server.phantom.test:{port}").as_str())
        || base.path_and_query().is_some_and(|p| p.as_str() != "/")
    {
        return Err("base URL must be https://server.phantom.test:PORT".into());
    }
    let token = &args[4];
    if token.is_empty()
        || token.len() > 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("run token must contain 1 to 64 lowercase letters, digits or hyphens".into());
    }
    let mut cases = vec!["first", "reused"];
    match args[3].as_str() {
        "baseline" => {}
        "boundary" => cases.extend([
            "cookie-first",
            "cookie-reused",
            "above-three-quarters",
            "full-table",
            "marker-before-oversized",
            "oversized",
            "marker-after-oversized",
        ]),
        _ => return Err("mode must be baseline or boundary".into()),
    }
    // The shared driver writes this DER certificate beside the PEM argument.
    let certificate = Path::new(&args[0]).with_extension("der");
    let certificate = std::fs::read(certificate)?;
    if certificate.len() > 65536 {
        return Err("certificate DER exceeds 65536 bytes".into());
    }
    let output = Path::new(&args[2]);
    let definition = catalog::profile("chrome-155-linux")?;
    let profile = definition
        .instantiate(&[
            ProfileLayer::TcpTls,
            ProfileLayer::Http2,
            ProfileLayer::CookiePlacement,
        ])?
        .with_request_template(definition.request_template(RequestTemplateKind::Navigation)?);
    write_new(
        &output.join("effective-profile.json"),
        &export_profile_json(&profile)?,
    )?;
    let client = Client::builder(profile)
        .add_root_certificate_der(certificate)
        .resolve("server.phantom.test", [Ipv4Addr::LOCALHOST.into()])
        .route(Route::Direct)
        .retry_policy(RetryPolicy::none())
        .redirect_policy(RedirectPolicy::none())
        .request_timeouts(
            RequestTimeouts::new()
                .connect(Duration::from_secs(5))
                .total(Duration::from_secs(15)),
        )
        .build()?;
    println!("selector={} id={}", definition.selector(), definition.id());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let operation = tokio::time::timeout(Duration::from_secs(55), async {
                requests(&client, &cases, port, token, output).await
            })
            .await
            .map_err(|error| Box::new(error) as Box<dyn Error>)
            .and_then(|result| result);
            let cleanup = tokio::time::timeout(Duration::from_secs(5), client.shutdown()).await;
            match (operation, cleanup) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error),
                (Ok(()), Err(error)) => Err(Box::new(error) as Box<dyn Error>),
                (Err(error), Err(cleanup)) => {
                    Err(format!("request sequence: {error}; shutdown: {cleanup}").into())
                }
            }
        })
}

async fn requests(
    client: &Client,
    cases: &[&str],
    port: u16,
    token: &str,
    output: &Path,
) -> Result<()> {
    for (index, label) in cases.iter().enumerate() {
        let path = if index == cases.len() - 1 {
            "/done"
        } else {
            "/ws.html"
        };
        let target = format!("https://server.phantom.test:{port}{path}?case={label}&run={token}");
        let mut request = client.get(HttpProtocol::Http2, &target)?;
        let extra = match *label {
            "cookie-first" | "cookie-reused" => {
                Some(RequestHeader::new("Cookie", "one=alpha; two=beta"))
            }
            "above-three-quarters" | "full-table" | "oversized" => {
                let size = match *label {
                    "above-three-quarters" => 3073,
                    "full-table" => 4096,
                    _ => 4097,
                };
                Some(RequestHeader::new(
                    "x-hpack-size",
                    "x".repeat(size - 32 - "x-hpack-size".len()),
                ))
            }
            "marker-before-oversized" | "marker-after-oversized" => {
                Some(RequestHeader::new("x-table-marker", "retained-marker"))
            }
            _ => None,
        };
        if let Some(header) = extra {
            request = request.header(header);
        }
        let response = request.send().await?;
        if response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("missing response metadata")?
            .protocol()
            != HttpProtocol::Http2
        {
            return Err("response did not use exact HTTP/2".into());
        }
        let (status, expected): (u16, &[u8]) = if path == "/done" {
            (204, b"")
        } else {
            (200, b"peer capture\n")
        };
        if response.status().as_u16() != status {
            return Err(format!(
                "unexpected response {} status {}",
                index + 1,
                response.status()
            )
            .into());
        }
        let headers = response.headers();
        let header_count = headers.iter().count();
        let header_bytes: usize = headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum();
        if header_count > 16
            || header_bytes > 4096
            || headers.get_all("cache-control").iter().count() != 1
            || headers.get("cache-control").map(|v| v.as_bytes()) != Some(b"no-store".as_slice())
            || headers.get_all("content-length").iter().count() != 1
            || headers.get("content-length").map(|v| v.as_bytes())
                != Some(expected.len().to_string().as_bytes())
        {
            return Err("response headers differ from the controlled peer".into());
        }
        let body = response.into_body().collect_with_limit(4096).await?;
        if body.as_ref() != expected {
            return Err(format!("response {} body differs", index + 1).into());
        }
        write_new(&output.join(format!("response-{}.body", index + 1)), &body)?;
        println!(
            "request={} case={label} protocol=h2 status={status} bytes={} header_fields={header_count} header_bytes={header_bytes}",
            index + 1,
            body.len()
        );
    }
    Ok::<_, Box<dyn Error>>(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}
