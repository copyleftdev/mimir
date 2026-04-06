use serde_json::Value;
use std::collections::BTreeMap;

use crate::ncd;
use crate::shannon;

/// Result of comparing two JSON responses.
#[derive(Debug, Clone)]
pub struct DifferentialResult {
    /// Fields present in `a` but not `b`.
    pub only_in_a: Vec<String>,
    /// Fields present in `b` but not `a`.
    pub only_in_b: Vec<String>,
    /// Fields present in both but with different values: (path, value_a, value_b).
    pub value_diffs: Vec<(String, String, String)>,
    /// Entropy of the difference (higher = more information leaked).
    pub diff_entropy: f64,
    /// NCD between the two responses.
    pub ncd: f64,
}

/// Compare an authenticated response with an unauthenticated one.
///
/// High `diff_entropy` indicates that the authentication state leaks
/// significant information.
pub fn differential_analysis(authed: &Value, unauthed: &Value) -> DifferentialResult {
    let paths_a = collect_paths(authed, "");
    let paths_b = collect_paths(unauthed, "");

    let map_a: BTreeMap<String, String> = paths_a.into_iter().collect();
    let map_b: BTreeMap<String, String> = paths_b.into_iter().collect();

    let mut only_in_a = Vec::new();
    let mut only_in_b = Vec::new();
    let mut value_diffs = Vec::new();

    // Fields in a but not b, and fields with differing values.
    for (path, val_a) in &map_a {
        match map_b.get(path) {
            None => only_in_a.push(path.clone()),
            Some(val_b) if val_a != val_b => {
                value_diffs.push((path.clone(), val_a.clone(), val_b.clone()));
            }
            _ => {}
        }
    }

    // Fields in b but not a.
    for path in map_b.keys() {
        if !map_a.contains_key(path) {
            only_in_b.push(path.clone());
        }
    }

    // Build a textual representation of the difference to measure its entropy.
    let mut diff_text = String::new();
    for p in &only_in_a {
        diff_text.push_str("+a:");
        diff_text.push_str(p);
        diff_text.push('=');
        if let Some(v) = map_a.get(p) {
            diff_text.push_str(v);
        }
        diff_text.push('\n');
    }
    for p in &only_in_b {
        diff_text.push_str("+b:");
        diff_text.push_str(p);
        diff_text.push('=');
        if let Some(v) = map_b.get(p) {
            diff_text.push_str(v);
        }
        diff_text.push('\n');
    }
    for (p, va, vb) in &value_diffs {
        diff_text.push_str("~:");
        diff_text.push_str(p);
        diff_text.push('=');
        diff_text.push_str(va);
        diff_text.push_str(" -> ");
        diff_text.push_str(vb);
        diff_text.push('\n');
    }

    let diff_entropy = shannon::entropy(diff_text.as_bytes());

    let sa = serde_json::to_string(authed).unwrap_or_default();
    let sb = serde_json::to_string(unauthed).unwrap_or_default();
    let ncd_val = ncd::ncd(sa.as_bytes(), sb.as_bytes());

    DifferentialResult {
        only_in_a,
        only_in_b,
        value_diffs,
        diff_entropy,
        ncd: ncd_val,
    }
}

/// Walk a JSON value and collect all leaf paths with their values.
///
/// Paths use dot-separated keys and bracket indices for arrays, e.g.
/// `data.users[0].name`.
fn collect_paths(value: &Value, prefix: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                result.extend(collect_paths(val, &path));
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let path = format!("{prefix}[{i}]");
                result.extend(collect_paths(val, &path));
            }
        }
        // Leaf values.
        _ => {
            let display = match value {
                Value::Null => "null".to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                _ => unreachable!(),
            };
            result.push((prefix.to_string(), display));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collect_paths_flat_object() {
        let v = json!({"a": 1, "b": "hello"});
        let paths = collect_paths(&v, "");
        let map: BTreeMap<String, String> = paths.into_iter().collect();
        assert_eq!(map.get("a").unwrap(), "1");
        assert_eq!(map.get("b").unwrap(), "hello");
    }

    #[test]
    fn collect_paths_nested_object() {
        let v = json!({"data": {"user": {"name": "alice"}}});
        let paths = collect_paths(&v, "");
        let map: BTreeMap<String, String> = paths.into_iter().collect();
        assert_eq!(map.get("data.user.name").unwrap(), "alice");
    }

    #[test]
    fn collect_paths_array() {
        let v = json!({"items": [10, 20, 30]});
        let paths = collect_paths(&v, "");
        let map: BTreeMap<String, String> = paths.into_iter().collect();
        assert_eq!(map.get("items[0]").unwrap(), "10");
        assert_eq!(map.get("items[1]").unwrap(), "20");
        assert_eq!(map.get("items[2]").unwrap(), "30");
    }

    #[test]
    fn collect_paths_null_and_bool() {
        let v = json!({"x": null, "y": true});
        let paths = collect_paths(&v, "");
        let map: BTreeMap<String, String> = paths.into_iter().collect();
        assert_eq!(map.get("x").unwrap(), "null");
        assert_eq!(map.get("y").unwrap(), "true");
    }

    #[test]
    fn differential_identical_responses() {
        let v = json!({"data": {"user": "alice", "role": "admin"}});
        let result = differential_analysis(&v, &v);
        assert!(result.only_in_a.is_empty());
        assert!(result.only_in_b.is_empty());
        assert!(result.value_diffs.is_empty());
        assert_eq!(result.diff_entropy, 0.0);
    }

    #[test]
    fn differential_detects_added_fields() {
        let authed =
            json!({"data": {"user": "alice", "email": "alice@example.com", "role": "admin"}});
        let unauthed = json!({"data": {"user": "alice"}});

        let result = differential_analysis(&authed, &unauthed);

        assert!(
            result.only_in_a.contains(&"data.email".to_string()),
            "expected 'data.email' in only_in_a, got {:?}",
            result.only_in_a
        );
        assert!(
            result.only_in_a.contains(&"data.role".to_string()),
            "expected 'data.role' in only_in_a, got {:?}",
            result.only_in_a
        );
        assert!(result.only_in_b.is_empty());
    }

    #[test]
    fn differential_detects_removed_fields() {
        let authed = json!({"data": {"user": "alice"}});
        let unauthed = json!({"data": {"user": "alice", "public_key": "ssh-rsa AAAA"}});

        let result = differential_analysis(&authed, &unauthed);

        assert!(result.only_in_a.is_empty());
        assert!(
            result.only_in_b.contains(&"data.public_key".to_string()),
            "expected 'data.public_key' in only_in_b, got {:?}",
            result.only_in_b
        );
    }

    #[test]
    fn differential_detects_changed_values() {
        let authed = json!({"data": {"balance": 9999, "status": "active"}});
        let unauthed = json!({"data": {"balance": 0, "status": "restricted"}});

        let result = differential_analysis(&authed, &unauthed);

        assert!(result.only_in_a.is_empty());
        assert!(result.only_in_b.is_empty());
        assert_eq!(result.value_diffs.len(), 2);

        let paths: Vec<&str> = result
            .value_diffs
            .iter()
            .map(|(p, _, _)| p.as_str())
            .collect();
        assert!(paths.contains(&"data.balance"));
        assert!(paths.contains(&"data.status"));
    }

    #[test]
    fn differential_entropy_increases_with_more_difference() {
        // Identical responses → zero diff entropy.
        let same = json!({"x": 1});
        let r1 = differential_analysis(&same, &same);

        // Significantly different responses → nonzero diff entropy.
        let a = json!({"secret": "s3cr3t-t0k3n", "flag": "CTF{found_it}", "internal_id": 42});
        let b = json!({"error": "unauthorized"});
        let r2 = differential_analysis(&a, &b);

        assert!(
            r2.diff_entropy > r1.diff_entropy,
            "More different responses should have higher diff entropy: {} vs {}",
            r2.diff_entropy,
            r1.diff_entropy
        );
    }

    #[test]
    fn differential_ncd_populated() {
        let a = json!({"a": 1});
        let b = json!({"b": 2});
        let result = differential_analysis(&a, &b);
        // NCD should be a finite non-negative number.
        assert!(result.ncd >= 0.0);
        assert!(result.ncd.is_finite());
    }
}
