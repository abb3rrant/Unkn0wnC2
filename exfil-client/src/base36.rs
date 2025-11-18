use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Base36Error {
    #[error("invalid base36 string")]
    Invalid,
}

pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let num = BigUint::from_bytes_be(bytes);
    let mut value = num;
    let mut encoded = Vec::new();
    let radix = BigUint::from(36u32);

    while !value.is_zero() {
        let (quot, rem) = value.div_mod_floor(&radix);
        let rem_digits = rem.to_u32_digits();
        let digit = rem_digits.first().copied().unwrap_or(0);
        encoded.push(to_char(digit as u8));
        value = quot;
    }

    encoded.reverse();
    encoded.into_iter().collect()
}

pub fn decode(text: &str) -> Result<Vec<u8>, Base36Error> {
    if text.is_empty() {
        return Ok(Vec::new());
    }

    let mut value = BigUint::zero();
    let radix = BigUint::from(36u32);

    for ch in text.chars() {
        let digit = match ch {
            '0'..='9' => ch as u8 - b'0',
            'a'..='z' => 10 + (ch as u8 - b'a'),
            'A'..='Z' => 10 + (ch as u8 - b'A'),
            _ => return Err(Base36Error::Invalid),
        } as u32;
        value = &value * &radix + BigUint::from(digit);
    }

    Ok(value.to_bytes_be())
}

fn to_char(idx: u8) -> char {
    match idx {
        0..=9 => (b'0' + idx) as char,
        10..=35 => (b'a' + (idx - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn round_trip_random_buffers() {
        let mut rng = StdRng::seed_from_u64(0x41414141);
        for size in [0_usize, 1, 5, 32, 255, 512] {
            let mut buf = vec![0u8; size];
            rng.fill_bytes(&mut buf);
            let encoded = encode(&buf);
            let decoded = decode(&encoded).expect("decode must succeed");
            assert_eq!(buf, decoded);
        }
    }
}

