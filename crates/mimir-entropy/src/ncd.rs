use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::Write;

/// Compute compressed size of `data` using DEFLATE (best compression).
fn compressed_size(data: &[u8]) -> usize {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("DEFLATE write failed");
    let compressed = encoder.finish().expect("DEFLATE finish failed");
    compressed.len()
}

/// Normalized Compression Distance between two byte sequences.
///
/// NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
///
/// Returns a value typically in \[0.0, ~1.0\].
///   - 0.0 means the sequences are identical (or extremely similar).
///   - Values near 1.0 mean the sequences share almost no information.
///
/// Due to compression overhead the result can occasionally slightly exceed 1.0.
///
/// Both inputs empty → returns 0.0.
pub fn ncd(a: &[u8], b: &[u8]) -> f64 {
    // Identical (or both empty) inputs have zero distance by definition.
    if a == b {
        return 0.0;
    }

    let ca = compressed_size(a);
    let cb = compressed_size(b);

    // Concatenation: a ++ b.
    let mut ab = Vec::with_capacity(a.len() + b.len());
    ab.extend_from_slice(a);
    ab.extend_from_slice(b);
    let cab = compressed_size(&ab);

    let min_c = ca.min(cb);
    let max_c = ca.max(cb);

    if max_c == 0 {
        return 0.0;
    }

    let raw = (cab as f64 - min_c as f64) / max_c as f64;

    // Clamp to [0, +inf). Compression artifacts can make the numerator
    // negative for very small inputs; floor at 0.
    raw.max(0.0)
}

/// NCD between two strings.
pub fn string_ncd(a: &str, b: &str) -> f64 {
    ncd(a.as_bytes(), b.as_bytes())
}

/// NCD between two JSON values (serialized to compact form).
pub fn json_ncd(a: &Value, b: &Value) -> f64 {
    let sa = serde_json::to_string(a).unwrap_or_default();
    let sb = serde_json::to_string(b).unwrap_or_default();
    ncd(sa.as_bytes(), sb.as_bytes())
}

/// Given a baseline response and a set of test responses, find outliers.
///
/// Returns indices of responses whose NCD from the baseline exceeds
/// `threshold`.
pub fn find_outliers(baseline: &[u8], responses: &[&[u8]], threshold: f64) -> Vec<usize> {
    responses
        .iter()
        .enumerate()
        .filter_map(|(i, resp)| {
            let d = ncd(baseline, resp);
            if d > threshold {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_bytes_have_zero_ncd() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let d = ncd(data, data);
        assert!(
            d < 0.1,
            "NCD of identical data should be ~0.0, got {d}"
        );
    }

    #[test]
    fn identical_strings_have_low_ncd() {
        let d = string_ncd("hello world", "hello world");
        assert!(d < 0.1, "NCD of identical strings should be ~0.0, got {d}");
    }

    #[test]
    fn completely_different_data_has_high_ncd() {
        // Two long unrelated strings should have NCD close to 1.0.
        let a: Vec<u8> = (0..1024).map(|i| (i % 128) as u8).collect();
        let b: Vec<u8> = (0..1024).map(|i| ((i * 7 + 53) % 128) as u8).collect();
        let d = ncd(&a, &b);
        assert!(
            d > 0.5,
            "NCD of very different data should be high, got {d}"
        );
    }

    #[test]
    fn empty_inputs_give_zero() {
        assert_eq!(ncd(b"", b""), 0.0);
    }

    #[test]
    fn json_ncd_identical() {
        let v = serde_json::json!({"user": "alice", "role": "admin"});
        let d = json_ncd(&v, &v);
        assert!(d < 0.1, "NCD of identical JSON should be ~0.0, got {d}");
    }

    #[test]
    fn json_ncd_different() {
        let a = serde_json::json!({"user": "alice", "role": "admin", "email": "alice@example.com"});
        let b = serde_json::json!({"status": 500, "error": "internal server error"});
        let d = json_ncd(&a, &b);
        assert!(d > 0.3, "NCD of different JSON should be significant, got {d}");
    }

    #[test]
    fn find_outliers_basic() {
        let baseline = b"normal response content here for testing purposes and analysis";
        let similar = b"normal response content here for testing purposes and review";
        let outlier = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

        let responses: Vec<&[u8]> = vec![similar, outlier, baseline];
        let outliers = find_outliers(baseline, &responses, 0.5);

        // The outlier (index 1) should exceed threshold; identical (index 2) should not.
        assert!(
            outliers.contains(&1),
            "Expected index 1 (outlier) to be flagged, got {:?}",
            outliers
        );
        assert!(
            !outliers.contains(&2),
            "Expected index 2 (identical) to NOT be flagged, got {:?}",
            outliers
        );
    }

    // -- Property-based tests --

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ncd_is_non_negative(
            a in proptest::collection::vec(any::<u8>(), 1..512),
            b in proptest::collection::vec(any::<u8>(), 1..512),
        ) {
            let d = ncd(&a, &b);
            prop_assert!(d >= 0.0, "NCD must be >= 0.0, got {}", d);
        }

        #[test]
        fn ncd_bounded_above(
            a in proptest::collection::vec(any::<u8>(), 1..512),
            b in proptest::collection::vec(any::<u8>(), 1..512),
        ) {
            let d = ncd(&a, &b);
            // NCD can slightly exceed 1.0 due to compression overhead but should
            // not blow up.
            prop_assert!(d <= 1.2, "NCD must be <= ~1.2, got {}", d);
        }

        #[test]
        fn ncd_self_is_low(data in proptest::collection::vec(any::<u8>(), 8..512)) {
            let d = ncd(&data, &data);
            prop_assert!(d < 0.2, "NCD(x, x) should be near 0.0, got {}", d);
        }
    }
}
