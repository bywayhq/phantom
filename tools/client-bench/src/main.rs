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
            || !(1..=65536).contains(&self.chunk_bytes)
            || !(1..=16).contains(&self.workers)
            || self
                .peer_workers
                .is_some_and(|workers| !(1..=16).contains(&workers))
            || self.server_delay_ms > 1000
            || self.chunk_delay_ms > 1000
            || self.arrival_interval_us > 1_000_000
        {
            return Err("invalid or unbounded benchmark configuration".into());
        }
        if self.protocol == "h3" && self.route != "direct" {
            return Err("TCP proxies do not support exact HTTP/3".into());
        }
        if self.protocol == "construct" && (self.concurrency != 1 || self.arrival_interval_us != 0)
        {
            return Err("construction runs are sequential".into());
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
}
