use crate::config::Config;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub struct ResolverPool {
    endpoints: Arc<Vec<SocketAddr>>,
    cursor: AtomicUsize,
}

impl ResolverPool {
    pub fn new(cfg: &Config) -> Result<Self> {
        let mut endpoints = Vec::new();

        if !cfg.resolver_endpoints().is_empty() {
            for raw in cfg.resolver_endpoints() {
                if let Some(addr) = parse_endpoint(raw)? {
                    endpoints.push(addr);
                }
            }
        }

        if endpoints.is_empty() {
            endpoints = discover_system_resolvers().unwrap_or_default();
        }

        if endpoints.is_empty() {
            endpoints.push("8.8.8.8:53".parse().unwrap());
        }

        Ok(Self {
            endpoints: Arc::new(endpoints),
            cursor: AtomicUsize::new(0),
        })
    }

    pub fn next(&self) -> SocketAddr {
        let len = self.endpoints.len();
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
        self.endpoints[idx]
    }
}

fn parse_endpoint(raw: &str) -> Result<Option<SocketAddr>> {
    if raw.trim().is_empty() {
        return Ok(None);
    }

    let endpoint = if raw.contains(':') {
        raw.to_string()
    } else {
        format!("{}:53", raw)
    };
    let mut addrs = endpoint
        .to_socket_addrs()
        .with_context(|| format!("invalid resolver {raw}"))?;
    Ok(addrs.next())
}

fn discover_system_resolvers() -> Result<Vec<SocketAddr>> {
    #[cfg(target_family = "unix")]
    {
        let file = File::open("/etc/resolv.conf").context("open /etc/resolv.conf")?;
        let reader = BufReader::new(file);
        let mut addrs = Vec::new();
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some(ip) = line.strip_prefix("nameserver ") {
                    if let Some(addr) = parse_endpoint(ip.trim())? {
                        addrs.push(addr);
                    }
                }
            }
        }
        return Ok(addrs);
    }

    #[cfg(not(target_family = "unix"))]
    {
        // TODO: Add Win32 resolver discovery. Fallback to public DNS for now.
        Ok(Vec::new())
    }
}
