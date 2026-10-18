use http_body_util::BodyExt;
use phantom::{
    Client, ContentDecoding, HttpProtocol, HttpProxy, RequestHeader, RequestTimeouts, ResponseInfo,
    Route, Socks5Proxy,
    profile::browser::{chrome, firefox},
};
use serde::Serialize;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

use crate::{Config, Ready, Result, control, signal, write_json};

#[derive(Debug, Serialize)]
struct Sample {
    id: usize,
    scheduled_ns: u64,
    started_ns: u64,
    application_wait_ns: u64,
    build_ns: u64,
    head_ns: u64,
    first_byte_ns: Option<u64>,
    complete_ns: u64,
    bytes: usize,
    error: Option<String>,
}

pub(crate) fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

fn client(config: &Config, ready: &Ready) -> Result<Client> {
    let mut profile = match config.profile.as_str() {
        "firefox" => firefox::v157_windows(),
        _ => chrome::v154_windows(),
    };
    if config.template {
        profile = profile.with_request_template(match config.profile.as_str() {
            "firefox" => firefox::v157_windows_navigation_template(),
            _ => chrome::v154_windows_navigation_template(),
        });
    }
    let mut builder = Client::builder(profile)
        .add_root_certificate_der(ready.root_der.clone())
        .request_timeouts(
            RequestTimeouts::new()
                .connect(Duration::from_secs(5))
                .total(Duration::from_secs(15)),
        );
    builder = match config.route.as_str() {
        "connect" => builder.route(Route::http_proxy({
            let proxy = HttpProxy::new(&format!("http://{}", ready.proxy))?
                .with_speculative_tls(config.speculative_tls);
            if config.proxy_auth {
                proxy.with_basic_auth("bench", "bench")?
            } else {
                proxy
            }
        })),
        "socks5" => builder.route(Route::socks5(Socks5Proxy::new(&format!(
            "socks5://{}",
            ready.proxy
        ))?)),
        _ => builder,
    };
    Ok(builder.build()?)
}

fn protocol(config: &Config) -> HttpProtocol {
    match config.protocol.as_str() {
        "h1" => HttpProtocol::Http1,
        "h3" => HttpProtocol::Http3,
        _ => HttpProtocol::Http2,
    }
}

async fn request(
    config: &Config,
    ready: &Ready,
    shared: &Client,
    sample: &mut Sample,
) -> Result<()> {
    let start = Instant::now();
    let owned;
    let selected = if config.cold {
        owned = client(config, ready)?;
        sample.build_ns = nanos(start.elapsed());
        &owned
    } else {
        shared
    };
    let url = &ready.urls[sample.id % ready.urls.len()];
    let mut request = if config.method == "POST" {
        selected
            .request(protocol(config), http::Method::POST, url)?
            .body(vec![b'U'; config.upload_bytes])
    } else {
        selected.get(protocol(config), url)?
    };
    if config.gzip {
        request = request
            .header(RequestHeader::new("accept-encoding", "gzip"))
            .content_decoding(ContentDecoding::advertised(config.bytes as u64));
    }
    if let Some(hops) = std::num::NonZeroUsize::new(config.redirects) {
        request = request.redirect_policy(phantom::RedirectPolicy::limited(hops));
    }
    let diagnostics = std::num::NonZeroUsize::new(config.diagnostic_events)
        .map(|capacity| request.diagnostics(capacity));
    let response = request.send().await?;
    sample.head_ns = nanos(start.elapsed());
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("missing response metadata")?;
    if response.status() != 200
        || info.protocol() != protocol(config)
        || info.retries_performed() != 0
        || info.redirects_followed() != config.redirects
    {
        return Err("unexpected status, protocol or replay".into());
    }
    let mut body = response.into_body();
    if config.consume == "collect" {
        let body = body.collect_with_limit(config.bytes).await?;
        sample.bytes = body.len();
        if !body.iter().all(|byte| *byte == b'Z') {
            return Err("incorrect response content".into());
        }
        // Collection hides the first data frame; do not invent its timestamp.
    } else {
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                if sample.first_byte_ns.is_none() {
                    sample.first_byte_ns = Some(nanos(start.elapsed()));
                }
                sample.bytes += data.len();
                if !data.iter().all(|byte| *byte == b'Z') {
                    return Err("incorrect response content".into());
                }
            }
        }
    }
    if sample.bytes != config.bytes {
        return Err("incorrect response length".into());
    }
    if let Some(diagnostics) = diagnostics.filter(|_| config.diagnostic_snapshot) {
        let timeline = diagnostics.snapshot();
        let body = timeline
            .events
            .iter()
            .find(|event| event.phase == phantom::RequestTimingPhase::ResponseBody);
        if timeline.admitted_attempts != config.redirects + 1
            || timeline.outcome != phantom::RequestTimelineOutcome::ResponseHead
            || body.is_some_and(|event| event.outcome != phantom::RequestTimingOutcome::Completed)
            || (body.is_none() && timeline.dropped_events == 0)
        {
            return Err("incomplete request diagnostics".into());
        }
    }
    sample.complete_ns = nanos(start.elapsed());
    Ok(())
}

fn sample(id: usize, scheduled_ns: u64, started_ns: u64) -> Sample {
    Sample {
        id,
        scheduled_ns,
        started_ns,
        application_wait_ns: started_ns.saturating_sub(scheduled_ns),
        build_ns: 0,
        head_ns: 0,
        first_byte_ns: None,
        complete_ns: 0,
        bytes: 0,
        error: None,
    }
}

async fn execute(config: &Config, ready: &Ready, shared: &Client, mut sample: Sample) -> Sample {
    let start = Instant::now();
    if let Err(error) = request(config, ready, shared, &mut sample).await {
        sample.complete_ns = nanos(start.elapsed());
        let mut details = format!("{error:?}");
        let mut cause = error.source();
        for _ in 0..16 {
            let Some(current) = cause else {
                break;
            };
            details.push_str(&format!("; caused by: {current:?}"));
            cause = current.source();
        }
        sample.error = Some(details);
    }
    sample
}

pub(crate) async fn run(config: Config, ready: Ready, output: &Path) -> Result<()> {
    let shared = client(&config, &ready)?;
    if config.protocol == "construct" {
        for _ in 0..config.warmup {
            std::hint::black_box(client(&config, &ready)?);
        }
    } else {
        let mut warmup = JoinSet::new();
        for worker in 0..config.concurrency {
            let (config, ready, shared) = (config.clone(), ready.clone(), shared.clone());
            warmup.spawn(async move {
                for id in (worker..config.warmup).step_by(config.concurrency) {
                    let result = execute(&config, &ready, &shared, sample(id, 0, 0)).await;
                    if let Some(error) = result.error {
                        return Err(format!("warmup failed: {error}"));
                    }
                }
                Ok::<_, String>(())
            });
        }
        while let Some(result) = warmup.join_next().await {
            result??;
        }
    }
    // Allocate and touch observation storage before the measured phase. Its
    // fixed footprint remains visible in start RSS, not request-driven growth.
    let mut groups: Vec<Vec<Sample>> = (0..config.concurrency)
        .map(|worker| {
            (worker..config.requests)
                .step_by(config.concurrency)
                .map(|id| sample(id, 0, 0))
                .collect()
        })
        .collect();
    #[cfg(feature = "heap")]
    let profiler = dhat::Profiler::builder()
        .file_name(output.with_extension("dhat.json"))
        .build();
    signal("ready")?;
    control("go")?;
    let runtime_start = crate::runtime_metrics::Snapshot::capture();
    let start = Instant::now();
    if config.protocol == "construct" {
        for record in &mut groups[0] {
            let offset = nanos(start.elapsed());
            record.scheduled_ns = offset;
            record.started_ns = offset;
            let build_start = Instant::now();
            let built = client(&config, &ready)?;
            record.build_ns = nanos(build_start.elapsed());
            std::hint::black_box(built);
            record.complete_ns = nanos(build_start.elapsed());
        }
    } else {
        let config = Arc::new(config.clone());
        let ready = Arc::new(ready);
        let mut tasks = JoinSet::new();
        for mut records in groups.drain(..) {
            let (config, ready, shared) = (config.clone(), ready.clone(), shared.clone());
            tasks.spawn(async move {
                for record in &mut records {
                    let planned =
                        Duration::from_micros(config.arrival_interval_us * record.id as u64);
                    if config.arrival_interval_us != 0 {
                        tokio::time::sleep_until(tokio::time::Instant::from_std(start + planned))
                            .await;
                    }
                    let now = nanos(start.elapsed());
                    let scheduled = if config.arrival_interval_us == 0 {
                        now
                    } else {
                        nanos(planned)
                    };
                    *record =
                        execute(&config, &ready, &shared, sample(record.id, scheduled, now)).await;
                }
                records
            });
        }
        while let Some(result) = tasks.join_next().await {
            groups.push(result?);
        }
    }
    let elapsed_ns = nanos(start.elapsed());
    let runtime_end = crate::runtime_metrics::Snapshot::capture();
    signal("phase_end")?;
    control("save")?;
    #[cfg(feature = "heap")]
    drop(profiler);
    let mut samples: Vec<_> = groups.into_iter().flatten().collect();
    samples.sort_unstable_by_key(|record| record.id);
    write_json(
        output,
        &serde_json::json!({"config": config, "elapsed_ns": elapsed_ns, "heap_instrumented": cfg!(feature="heap"), "observer_storage_bytes": config.requests * std::mem::size_of::<Sample>(), "runtime_start": runtime_start, "runtime_end": runtime_end, "samples": samples}),
    )?;
    signal("saved")?;
    Ok(())
}
