//! Isolated public-client workloads. The controller owns process measurements.

use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::Path,
};

mod client;
mod peer;
mod runtime_metrics;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(feature = "heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    name: String,
    protocol: String,
    profile: String,
    route: String,
    concurrency: usize,
    requests: usize,
    warmup: usize,
    bytes: usize,
    method: String,
    upload_bytes: usize,
    redirects: usize,
    cancel_after_bytes: usize,
    cancel_stage: String,
    consume: String,
    cold: bool,
    origins: usize,
    server_delay_ms: u64,
    chunk_bytes: usize,
    chunk_delay_ms: u64,
    gzip: bool,
    template: bool,
    arrival_interval_us: u64,
    workers: usize,
    peer_workers: Option<usize>,
    speculative_tls: bool,
    proxy_delay_ms: u64,
    proxy_auth: bool,
    diagnostic_events: usize,
    diagnostic_snapshot: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: "warm-h2".into(),
            protocol: "h2".into(),
            profile: "chrome".into(),
            route: "direct".into(),
            concurrency: 1,
            requests: 2000,
            warmup: 100,
            bytes: 1024,
            method: "GET".into(),
            upload_bytes: 0,
            redirects: 0,
            cancel_after_bytes: 0,
            cancel_stage: "body".into(),
            consume: "stream".into(),
            cold: false,
            origins: 1,
            server_delay_ms: 0,
            chunk_bytes: 16384,
            chunk_delay_ms: 0,
            gzip: false,
            template: false,
            arrival_interval_us: 0,
            workers: 2,
            peer_workers: None,
            speculative_tls: false,
            proxy_delay_ms: 0,
            proxy_auth: false,
            diagnostic_events: 0,
            diagnostic_snapshot: true,
        }
    }
}

impl Config {
    fn validate(&self) -> Result<()> {
        if !["h1", "h2", "h3", "construct"].contains(&self.protocol.as_str())
            || !["chrome", "firefox"].contains(&self.profile.as_str())
            || !["direct", "connect", "socks5"].contains(&self.route.as_str())
            || !["stream", "collect"].contains(&self.consume.as_str())
            || !(1..=256).contains(&self.concurrency)
            || !(1..=1_000_000).contains(&self.requests)
            || self.warmup > 100_000
            || !(1..=128).contains(&self.origins)
            || self.bytes > 16 * 1024 * 1024
            || !["GET", "POST"].contains(&self.method.as_str())
            || self.upload_bytes > 16 * 1024 * 1024
            || self.redirects > 3
            || !(1..=65536).contains(&self.chunk_bytes)
            || !(1..=16).contains(&self.workers)
            || self
                .peer_workers
                .is_some_and(|workers| !(1..=16).contains(&workers))
            || self.server_delay_ms > 1000
            || self.chunk_delay_ms > 1000
            || self.arrival_interval_us > 1_000_000
            || self.proxy_delay_ms > 250
            || self.diagnostic_events > 4096
        {
            return Err("invalid or unbounded benchmark configuration".into());
        }
        if self.redirects != 0
            && (self.method != "GET" || self.consume != "collect" || self.protocol == "construct")
        {
            return Err("redirect workloads require collected GET requests".into());
        }
        if (self.method == "GET" || self.protocol == "construct") && self.upload_bytes != 0 {
            return Err("uploads require a POST request workload".into());
        }
        if self.protocol == "construct" && self.method != "GET" {
            return Err("construction runs cannot issue POST requests".into());
        }
        if self.proxy_auth && (self.route != "connect" || self.protocol == "construct") {
            return Err("proxy authentication requires the CONNECT route".into());
        }
        if self.protocol == "h3" && self.route != "direct" {
            return Err("TCP proxies do not support exact HTTP/3".into());
        }
        if (self.speculative_tls || self.proxy_delay_ms != 0) && self.route != "connect" {
            return Err("speculative TLS and proxy delay require the CONNECT route".into());
        }
        if self.protocol == "construct" && (self.concurrency != 1 || self.arrival_interval_us != 0)
        {
            return Err("construction runs are sequential".into());
        }
        if !["body", "upload"].contains(&self.cancel_stage.as_str()) {
            return Err("unsupported cancellation stage".into());
        }
        if self.cancel_stage == "upload"
            && (self.protocol != "h2"
                || self.route != "direct"
                || self.consume != "stream"
                || self.cold
                || self.origins != 1
                || self.method != "POST"
                || self.upload_bytes == 0
                || self.gzip
                || self.redirects != 0
                || self.warmup != 1
                || self.concurrency != 2
                || self.requests != 2
                || self.cancel_after_bytes != 0
                || self.arrival_interval_us != 0
                || self.diagnostic_events != 0
                || self.template)
        {
            return Err(
                "upload cancellation requires two warm direct H2 operations and a nonempty POST"
                    .into(),
            );
        }
        if self.cancel_after_bytes != 0
            && (!["h1", "h2", "h3"].contains(&self.protocol.as_str())
                || self.route != "direct"
                || self.consume != "stream"
                || self.cold
                || self.origins != 1
                || self.method != "GET"
                || self.gzip
                || self.redirects != 0
                || self.warmup != 1
                || self.concurrency != 2
                || self.requests < 2
                || !self.requests.is_multiple_of(2)
                || self.cancel_after_bytes >= self.bytes
                || self.chunk_delay_ms == 0
                || self.arrival_interval_us != 0)
        {
            return Err(
                "body cancellation requires warm direct H1/H2/H3 responses, one origin and two workers"
                    .into(),
            );
        }
        Ok(())
    }

    fn runtime_workers(&self, peer: bool) -> usize {
        if peer {
            self.peer_workers.unwrap_or(self.workers)
        } else {
            self.workers
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Ready {
    urls: Vec<String>,
    root_der: Vec<u8>,
    proxy: String,
    #[serde(default)]
    proxy_password: String,
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    // Output paths are fresh: never erase a previous measurement.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut file = io::BufWriter::new(file);
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn signal(event: &str) -> Result<()> {
    println!("{{\"event\":\"{event}\"}}");
    io::stdout().flush()?;
    Ok(())
}

fn control(expected: &str) -> Result<()> {
    if read_control()? != expected {
        return Err("controller disconnected or sent an invalid command".into());
    }
    Ok(())
}

fn read_control() -> Result<String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || !["serve", "run"].contains(&args[1].as_str()) {
        return Err("usage: phantom-client-bench serve|run CONFIG READY RESULT".into());
    }
    let config: Config = serde_json::from_slice(&std::fs::read(&args[2])?)?;
    config.validate()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.runtime_workers(args[1] == "serve"))
        .enable_all()
        .build()?;
    if args[1] == "serve" {
        runtime.block_on(peer::serve(
            config,
            Path::new(&args[3]),
            Path::new(&args[4]),
        ))
    } else {
        let ready: Ready = serde_json::from_slice(&std::fs::read(&args[3])?)?;
        runtime.block_on(client::run(config, ready, Path::new(&args[4])))
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn peer_workers_can_be_held_fixed_while_client_workers_change() {
        let mut config = Config::default();
        assert_eq!(config.runtime_workers(true), 2);
        config.workers = 8;
        assert_eq!(config.runtime_workers(false), 8);
        assert_eq!(config.runtime_workers(true), 8);
        config.peer_workers = Some(2);
        assert_eq!(config.runtime_workers(false), 8);
        assert_eq!(config.runtime_workers(true), 2);
        assert!(config.validate().is_ok());
        config.peer_workers = Some(0);
        assert!(config.validate().is_err());
        config.peer_workers = Some(17);
        assert!(config.validate().is_err());
    }

    #[test]
    fn upload_work_is_explicit_and_bounded() {
        let mut config = Config {
            method: "POST".into(),
            ..Config::default()
        };
        assert!(config.validate().is_ok());
        config.upload_bytes = 16 * 1024 * 1024;
        assert!(config.validate().is_ok());
        config.upload_bytes += 1;
        assert!(config.validate().is_err());
        config.upload_bytes = 1;
        config.method = "GET".into();
        assert!(config.validate().is_err());
        config.method = "POST".into();
        config.protocol = "construct".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn body_cancel_requires_a_partial_stream_and_a_live_sibling() {
        let mut config = Config {
            protocol: "h2".into(),
            route: "direct".into(),
            consume: "stream".into(),
            cold: false,
            origins: 1,
            method: "GET".into(),
            gzip: false,
            redirects: 0,
            warmup: 1,
            concurrency: 2,
            requests: 2,
            bytes: 65536,
            cancel_after_bytes: 1024,
            chunk_delay_ms: 1,
            arrival_interval_us: 0,
            ..Config::default()
        };
        assert!(config.validate().is_ok());
        config.cancel_after_bytes = config.bytes;
        assert!(config.validate().is_err());
        config.cancel_after_bytes = 1024;
        config.cold = true;
        assert!(config.validate().is_err());
        config.cold = false;
        config.protocol = "h1".into();
        assert!(config.validate().is_ok());
        config.protocol = "h3".into();
        assert!(config.validate().is_ok());
        config.protocol = "construct".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn upload_cancel_requires_one_post_and_one_get_on_warmed_h2() {
        let mut config = Config {
            cancel_stage: "upload".into(),
            method: "POST".into(),
            upload_bytes: 65536,
            requests: 2,
            warmup: 1,
            concurrency: 2,
            ..Config::default()
        };
        assert!(config.validate().is_ok());
        config.requests = 4;
        assert!(config.validate().is_err());
        config.requests = 2;
        config.cancel_after_bytes = 1;
        assert!(config.validate().is_err());
        config.cancel_after_bytes = 0;
        config.upload_bytes = 0;
        assert!(config.validate().is_err());
        config.upload_bytes = 65536;
        config.protocol = "h3".into();
        assert!(config.validate().is_err());
    }
}
