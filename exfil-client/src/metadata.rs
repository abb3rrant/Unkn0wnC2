use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Clone)]
pub struct ExfilJobContext {
    pub data: Vec<u8>,
    pub chunk_size: usize,
    pub total_size: usize,
    pub total_chunks: usize,
    pub file_name: String,
    pub note: String,
    pub job_id: u32,
}

pub struct ExfilSession {
    pub job: ExfilJobContext,
    pub session_id: u32,
    pub next_chunk: usize,
    metadata_frames: usize,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid session id")]
    InvalidSession,
}

impl ExfilJobContext {
    pub fn from_source(data: &[u8], path: Option<&Path>, note: &str, chunk_size: usize) -> Self {
        let total_size = data.len();
        let total_chunks = (total_size + chunk_size - 1) / chunk_size;
        let file_name = path
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("stdin")
            .to_string();

        let mut hasher = Sha256::new();
        hasher.update(file_name.as_bytes());
        hasher.update(&total_size.to_be_bytes());
        hasher.update(data);
        let digest = hasher.finalize();
        let job_id = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);

        ExfilJobContext {
            data: data.to_vec(),
            chunk_size,
            total_size,
            total_chunks: total_chunks.max(1),
            file_name,
            note: note.to_string(),
            job_id,
        }
    }
}

impl ExfilSession {
    pub fn new(job: ExfilJobContext) -> Self {
        let session_id = rand::thread_rng().gen::<u32>();
        ExfilSession {
            job,
            session_id,
            next_chunk: 0,
            metadata_frames: 1,
        }
    }

    pub fn total_frames(&self) -> usize {
        self.job.total_chunks + self.metadata_frames()
    }

    pub fn resume(job: &ExfilJobContext, hex_id: String) -> Result<Self, SessionError> {
        let session_id = u32::from_str_radix(hex_id.trim_start_matches("0x"), 16)
            .map_err(|_| SessionError::InvalidSession)?;
        Ok(ExfilSession {
            job: job.clone(),
            session_id,
            next_chunk: 0,
            metadata_frames: 1,
        })
    }

    pub fn session_id_hex(&self) -> String {
        format!("{:#010x}", self.session_id)
    }

    pub fn chunk_range(&self, index: usize) -> (usize, usize) {
        let start = index * self.job.chunk_size;
        let mut end = start + self.job.chunk_size;
        if end > self.job.total_size {
            end = self.job.total_size;
        }
        (start, end)
    }

    pub fn set_metadata_frames(&mut self, frames: usize) {
        self.metadata_frames = frames.max(1);
    }

    pub fn metadata_frames(&self) -> usize {
        self.metadata_frames.max(1)
    }
}
