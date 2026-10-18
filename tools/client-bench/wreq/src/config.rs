use serde::{Deserialize, Serialize};

use crate::Result;

// The controller supplies every effective field. Missing or new fields fail
// rather than inheriting a different workload when either tool changes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub name: String,
    pub protocol: String,
    pub profile: String,
    pub route: String,
    pub concurrency: usize,
    pub requests: usize,
    pub warmup: usize,
    pub bytes: usize,
    pub method: String,
    pub upload_bytes: usize,
    pub consume: String,
    pub cold: bool,
    pub origins: usize,
    pub server_delay_ms: u64,
    pub chunk_bytes: usize,
    pub chunk_delay_ms: u64,
    pub gzip: bool,
    pub template: bool,
    pub arrival_interval_us: u64,
    pub workers: usize,
    pub peer_workers: Option<usize>,
    pub speculative_tls: bool,
    pub proxy_delay_ms: u64,
    pub diagnostic_events: usize,
    pub diagnostic_snapshot: bool,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !["h1", "h2"].contains(&self.protocol.as_str()) {
            return Err("wreq adapter supports exact HTTP/1.1 and HTTP/2 only".into());
        }
        if self.profile != "chrome"
            || self.route != "direct"
            || self.gzip
            || self.template
            || self.speculative_tls
            || self.proxy_delay_ms != 0
            || self.diagnostic_events != 0
        {
            return Err("wreq adapter requires Chrome, direct routing and no optional work".into());
        }
        if !["stream", "collect"].contains(&self.consume.as_str())
            || !(1..=256).contains(&self.concurrency)
            || !(1..=1_000_000).contains(&self.requests)
            || self.warmup > 100_000
            || !(1..=128).contains(&self.origins)
            || self.bytes > 16 * 1024 * 1024
            || !["GET", "POST"].contains(&self.method.as_str())
            || self.upload_bytes > 16 * 1024 * 1024
            || (self.method == "GET" && self.upload_bytes != 0)
            || !(1..=65536).contains(&self.chunk_bytes)
            || !(1..=16).contains(&self.workers)
            || self.peer_workers.is_some_and(|n| !(1..=16).contains(&n))
            || self.server_delay_ms > 1000
            || self.chunk_delay_ms > 1000
            || self.arrival_interval_us > 1_000_000
        {
            return Err("invalid or unbounded wreq benchmark configuration".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Ready {
    pub urls: Vec<String>,
    pub root_der: Vec<u8>,
}

impl Ready {
    pub fn validate(&self, origins: usize) -> Result<()> {
        if self.urls.len() != origins || self.root_der.is_empty() {
            return Err("peer identity differs from the configured workload".into());
        }
        for url in &self.urls {
            let url = url::Url::parse(url)?;
            if url.scheme() != "https"
                || url.host_str() != Some("127.0.0.1")
                || url.port().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err("wreq adapter requires HTTPS peers on IPv4 loopback".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            name: "control".into(),
            protocol: "h2".into(),
            profile: "chrome".into(),
            route: "direct".into(),
            concurrency: 2,
            requests: 8,
            warmup: 2,
            bytes: 32768,
            method: "GET".into(),
            upload_bytes: 0,
            consume: "stream".into(),
            cold: false,
            origins: 1,
            server_delay_ms: 0,
            chunk_bytes: 1024,
            chunk_delay_ms: 1,
            gzip: false,
            template: false,
            arrival_interval_us: 0,
            workers: 2,
            peer_workers: Some(2),
            speculative_tls: false,
            proxy_delay_ms: 0,
            diagnostic_events: 0,
            diagnostic_snapshot: true,
        }
    }

    #[test]
    fn unsupported_work_is_rejected_instead_of_changed() {
        let unsupported: &[fn(&mut Config)] = &[
            |c| c.protocol = "h3".into(),
            |c| c.protocol = "construct".into(),
            |c| c.profile = "firefox".into(),
            |c| c.route = "connect".into(),
            |c| c.gzip = true,
            |c| c.template = true,
            |c| c.speculative_tls = true,
            |c| c.proxy_delay_ms = 1,
            |c| c.diagnostic_events = 1,
            |c| c.concurrency = 0,
            |c| c.requests = 0,
            |c| c.workers = 0,
            |c| c.peer_workers = Some(0),
            |c| c.bytes = 16 * 1024 * 1024 + 1,
            |c| c.upload_bytes = 1,
            |c| c.method = "PATCH".into(),
        ];
        for change in unsupported {
            let mut config = config();
            change(&mut config);
            assert!(config.validate().is_err(), "{config:?}");
        }
    }

    #[test]
    fn cold_collection_and_scheduled_multi_origin_work_is_supported() -> Result<()> {
        let mut config = config();
        for protocol in ["h1", "h2"] {
            config.protocol = protocol.into();
            config.cold = true;
            config.consume = "collect".into();
            config.origins = 3;
            config.arrival_interval_us = 1000;
            config.method = "POST".into();
            config.upload_bytes = 65536;
            config.validate()?;
        }
        Ok(())
    }

    #[test]
    fn effective_fields_cannot_be_omitted_or_supplemented() -> Result<()> {
        let mut fields = serde_json::to_value(config())?;
        let object = fields.as_object_mut().ok_or("config is not an object")?;
        object.remove("cold");
        assert!(serde_json::from_value::<Config>(fields).is_err());
        let mut fields = serde_json::to_value(config())?;
        fields["unknown"] = true.into();
        assert!(serde_json::from_value::<Config>(fields).is_err());
        Ok(())
    }

    #[test]
    fn peer_identity_must_match_the_secure_loopback_workload() {
        for url in [
            "http://127.0.0.1:1234/",
            "https://example.com:443/",
            "https://user@127.0.0.1:1234/",
            "https://127.0.0.1/",
            "https://127.0.0.1:1234/#fragment",
        ] {
            let ready = Ready {
                urls: vec![url.into()],
                root_der: vec![1],
            };
            assert!(ready.validate(1).is_err(), "{url}");
        }
        let ready = Ready {
            urls: vec!["https://127.0.0.1:1234/".into()],
            root_der: vec![1],
        };
        assert!(ready.validate(1).is_ok());
        assert!(ready.validate(2).is_err());
    }
}
