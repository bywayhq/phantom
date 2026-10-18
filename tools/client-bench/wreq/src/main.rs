//! Pinned public wreq client, isolated from Phantom and its native dependencies.

use futures_util::StreamExt;
use serde::Serialize;
use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use wreq::Client;

mod config;
use config::{Config, Ready};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Serialize)]
struct Sample {
    id: usize,
    scheduled_ns: u64,
    started_ns: u64,
    application_wait_ns: u64,
    build_ns: u64,
    head_ns: Option<u64>,
    first_byte_ns: Option<u64>,
    complete_ns: u64,
    bytes: usize,
    error: Option<String>,
}

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

fn sample(id: usize) -> Sample {
    Sample {
        id,
        scheduled_ns: 0,
        started_ns: 0,
        application_wait_ns: 0,
        build_ns: 0,
        head_ns: None,
        first_byte_ns: None,
        complete_ns: 0,
        bytes: 0,
        error: None,
    }
}

fn client(config: &Config, ready: &Ready) -> Result<Client> {
    let emulation = wreq_util::Emulation::builder()
        .profile(wreq_util::Profile::Chrome149)
        .platform(wreq_util::Platform::Windows)
        .headers(false)
        .build();
    let builder = Client::builder()
        .emulation(emulation)
        .tls_cert_store(wreq::tls::trust::CertStore::from_der_certs([ready
            .root_der
            .as_slice()])?)
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .retry(wreq::retry::Policy::never())
        .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    Ok(if config.protocol == "h1" {
        builder.http1_only()
    } else {
        builder.http2_only()
    }
    .build()?)
}

async fn request(
    config: &Config,
    ready: &Ready,
    shared: &Client,
    record: &mut Sample,
) -> Result<()> {
    let start = Instant::now();
    let owned;
    let selected = if config.cold {
        owned = client(config, ready)?;
        record.build_ns = nanos(start.elapsed());
        &owned
    } else {
        shared
    };
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(start + Duration::from_secs(15)),
        async {
            let url = ready.urls[record.id % ready.urls.len()].as_str();
            let request = if config.method == "POST" {
                selected.post(url).body(vec![b'U'; config.upload_bytes])
            } else {
                selected.get(url)
            };
            let response = request.send().await?;
            record.head_ns = Some(nanos(start.elapsed()));
            let expected = if config.protocol == "h1" {
                http::Version::HTTP_11
            } else {
                http::Version::HTTP_2
            };
            if response.status() != 200 || response.version() != expected {
                return Err("unexpected response status or protocol".into());
            }
            if config.consume == "collect" {
                let data = response.bytes().await?;
                record.bytes = data.len();
                if !data.iter().all(|byte| *byte == b'Z') {
                    return Err("incorrect response content".into());
                }
            } else {
                let mut stream = response.bytes_stream();
                while let Some(data) = stream.next().await {
                    let data = data?;
                    if !data.is_empty() && record.first_byte_ns.is_none() {
                        record.first_byte_ns = Some(nanos(start.elapsed()));
                    }
                    record.bytes += data.len();
                    if !data.iter().all(|byte| *byte == b'Z') {
                        return Err("incorrect response content".into());
                    }
                }
            }
            if record.bytes != config.bytes {
                return Err("incorrect response length".into());
            }
            record.complete_ns = nanos(start.elapsed());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        },
    )
    .await??;
    Ok(())
}

async fn execute(config: &Config, ready: &Ready, shared: &Client, record: &mut Sample) {
    let start = Instant::now();
    if let Err(error) = request(config, ready, shared, record).await {
        record.complete_ns = nanos(start.elapsed());
        record.error = Some(format!("{error:?}"));
    }
}

fn signal(event: &str) -> Result<()> {
    println!("{{\"event\":\"{event}\"}}");
    io::stdout().flush()?;
    Ok(())
}

fn control(expected: &str) -> Result<()> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    if line.trim() != expected {
        return Err("controller disconnected or sent an invalid command".into());
    }
    Ok(())
}

async fn run(config: Config, ready: Ready, output: &Path) -> Result<()> {
    let shared = client(&config, &ready)?;
    let (config, ready) = (Arc::new(config), Arc::new(ready));
    let mut warmup = JoinSet::new();
    for worker in 0..config.concurrency {
        let (config, ready, shared) = (config.clone(), ready.clone(), shared.clone());
        warmup.spawn(async move {
            for id in (worker..config.warmup).step_by(config.concurrency) {
                let mut record = sample(id);
                execute(&config, &ready, &shared, &mut record).await;
                if let Some(error) = record.error {
                    return Err(format!("warmup failed: {error}"));
                }
            }
            Ok::<_, String>(())
        });
    }
    while let Some(result) = warmup.join_next().await {
        result??;
    }
    let groups: Vec<Vec<Sample>> = (0..config.concurrency)
        .map(|worker| {
            (worker..config.requests)
                .step_by(config.concurrency)
                .map(sample)
                .collect()
        })
        .collect();
    let observer_storage_bytes = groups.iter().map(|group| group.capacity()).sum::<usize>()
        * std::mem::size_of::<Sample>()
        + groups.capacity() * std::mem::size_of::<Vec<Sample>>();
    signal("ready")?;
    control("go")?;
    let start = Instant::now();
    let mut tasks = JoinSet::new();
    for mut records in groups {
        let (config, ready, shared) = (config.clone(), ready.clone(), shared.clone());
        tasks.spawn(async move {
            for record in &mut records {
                let planned = Duration::from_micros(config.arrival_interval_us * record.id as u64);
                if config.arrival_interval_us != 0 {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(start + planned)).await;
                }
                let now = nanos(start.elapsed());
                record.scheduled_ns = if config.arrival_interval_us == 0 {
                    now
                } else {
                    nanos(planned)
                };
                record.started_ns = now;
                record.application_wait_ns = now.saturating_sub(record.scheduled_ns);
                execute(&config, &ready, &shared, record).await;
            }
            records
        });
    }
    let mut groups = Vec::with_capacity(config.concurrency);
    while let Some(result) = tasks.join_next().await {
        groups.push(result?);
    }
    let elapsed_ns = nanos(start.elapsed());
    signal("phase_end")?;
    control("save")?;
    let mut samples: Vec<_> = groups.into_iter().flatten().collect();
    samples.sort_unstable_by_key(|record| record.id);
    let result = serde_json::json!({
        "config": &*config, "elapsed_ns": elapsed_ns,
        "heap_instrumented": false, "observer_storage_bytes": observer_storage_bytes,
        "samples": samples,
        "adapter_settings": {
            "library": "wreq=0.16.1", "recipes": "wreq-util=0.2.0 Chrome149 Windows",
            "automatic_headers": false, "retry": "never", "redirects": false,
            "environment_proxy": false, "connect_timeout_ms": 5000,
            "application_timeout_ms": 15000, "pool_limits": "library defaults",
            "runtime_workers": config.workers,
        },
    });
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut writer = io::BufWriter::new(file);
    serde_json::to_writer(&mut writer, &result)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    signal("saved")?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || args[1] != "run" {
        return Err("usage: phantom-wreq-bench run CONFIG READY RESULT".into());
    }
    let config: Config = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    config.validate()?;
    let ready: Ready = serde_json::from_slice(&std::fs::read(&args[3])?)?;
    ready.validate(config.origins)?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()?
        .block_on(run(config, ready, Path::new(&args[4])))
}
