use serde_json::Value;

/// Categorize entropy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyLevel {
    /// < 2.0 bits — static/predictable content
    Low,
    /// 2.0–4.0 bits — structured data
    Medium,
    /// 4.0–6.0 bits — variable content
    High,
    /// > 6.0 bits — random/encrypted/compressed or high info leakage
    VeryHigh,
}

/// Compute Shannon entropy of a byte sequence in bits.
///
/// H(X) = -Σ p(x) log₂ p(x)
///
/// Returns 0.0 for empty input.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;

    // Count byte frequencies.
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }

    h
}

/// Compute entropy of a string.
pub fn string_entropy(s: &str) -> f64 {
    entropy(s.as_bytes())
}

/// Compute the entropy of a JSON value (serialized to compact form).
pub fn json_entropy(value: &Value) -> f64 {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    entropy(serialized.as_bytes())
}

/// Entropy ratio: actual entropy / maximum possible entropy.
///
/// Returns a value in 0.0–1.0 where 1.0 = maximum randomness.
/// Returns 0.0 for empty input or single-byte input.
pub fn entropy_ratio(data: &[u8]) -> f64 {
    if data.len() <= 1 {
        return 0.0;
    }

    // Maximum entropy for data of this length is log₂(min(len, 256)).
    // With N distinct possible symbols the max entropy is log₂(N).
    // The number of distinct symbols that *could* appear is at most
    // min(data.len(), 256).
    let max_symbols = data.len().min(256) as f64;
    let max_entropy = max_symbols.log2();

    if max_entropy == 0.0 {
        return 0.0;
    }

    let h = entropy(data);
    (h / max_entropy).clamp(0.0, 1.0)
}

/// Classify the entropy level of a byte sequence.
pub fn classify_entropy(data: &[u8]) -> EntropyLevel {
    let h = entropy(data);
    if h < 2.0 {
        EntropyLevel::Low
    } else if h < 4.0 {
        EntropyLevel::Medium
    } else if h < 6.0 {
        EntropyLevel::High
    } else {
        EntropyLevel::VeryHigh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_has_zero_entropy() {
        assert_eq!(entropy(b""), 0.0);
    }

    #[test]
    fn single_byte_has_zero_entropy() {
        assert_eq!(entropy(b"a"), 0.0);
    }

    #[test]
    fn uniform_bytes_have_zero_entropy() {
        // All bytes are the same — perfectly predictable.
        assert_eq!(entropy(b"aaaa"), 0.0);
        assert_eq!(entropy(b"aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn two_equally_likely_symbols_have_one_bit() {
        // "ab" repeated → p(a)=0.5, p(b)=0.5 → H = 1.0 bit
        let data = b"abababababababab";
        let h = entropy(data);
        assert!((h - 1.0).abs() < 1e-10, "expected ~1.0 bit, got {h}");
    }

    #[test]
    fn four_equally_likely_symbols_have_two_bits() {
        let data = b"abcdabcdabcdabcd";
        let h = entropy(data);
        assert!((h - 2.0).abs() < 1e-10, "expected ~2.0 bits, got {h}");
    }

    #[test]
    fn random_bytes_have_high_entropy() {
        // Construct a sequence with all 256 byte values equally represented.
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        let h = entropy(&data);
        // Maximum entropy for 256 symbols = 8.0 bits.
        assert!(
            (h - 8.0).abs() < 1e-10,
            "expected ~8.0 bits for uniform distribution, got {h}"
        );
    }

    #[test]
    fn string_entropy_works() {
        assert_eq!(string_entropy(""), 0.0);
        assert_eq!(string_entropy("aaaa"), 0.0);
        assert!(string_entropy("hello world") > 0.0);
    }

    #[test]
    fn json_entropy_works() {
        let v = serde_json::json!({"key": "value"});
        let h = json_entropy(&v);
        assert!(h > 0.0);
    }

    #[test]
    fn entropy_ratio_bounds() {
        assert_eq!(entropy_ratio(b""), 0.0);
        assert_eq!(entropy_ratio(b"a"), 0.0);
        assert_eq!(entropy_ratio(b"aaaa"), 0.0);

        // Uniform distribution over 256 symbols should give ratio close to 1.0.
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        let r = entropy_ratio(&data);
        assert!(
            (r - 1.0).abs() < 1e-6,
            "expected ratio ~1.0 for uniform data, got {r}"
        );
    }

    #[test]
    fn classify_entropy_levels() {
        // All same bytes → 0 bits → Low.
        assert_eq!(classify_entropy(b"aaaa"), EntropyLevel::Low);

        // Single bit of entropy → Low.
        assert_eq!(classify_entropy(b"abababababababab"), EntropyLevel::Low);

        // 2 bits → Medium.
        assert_eq!(classify_entropy(b"abcdabcdabcdabcd"), EntropyLevel::Medium);

        // Uniform 256 symbols → 8 bits → VeryHigh.
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
        assert_eq!(classify_entropy(&data), EntropyLevel::VeryHigh);
    }

    // -- Property-based tests --

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn entropy_is_non_negative(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let h = entropy(&data);
            prop_assert!(h >= 0.0, "entropy must be >= 0.0, got {}", h);
        }

        #[test]
        fn entropy_at_most_eight_bits(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let h = entropy(&data);
            prop_assert!(h <= 8.0 + 1e-10, "entropy must be <= 8.0 bits, got {}", h);
        }

        #[test]
        fn entropy_ratio_in_zero_one(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let r = entropy_ratio(&data);
            prop_assert!(r >= 0.0 && r <= 1.0, "ratio must be in [0,1], got {}", r);
        }
    }
}
