use chrono::Utc;
use tracing::{debug, info};

use crate::clock::{LamportClock, LamportTimestamp, TimestampedOp};
use crate::race::{RaceCondition, RaceType};

/// Detect potential race conditions in a sequence of operations.
pub struct RaceDetector {
    /// Operations recorded with Lamport timestamps.
    operations: Vec<TimestampedOp>,
    /// Clock for ordering.
    clock: LamportClock,
}

impl Default for RaceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RaceDetector {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            clock: LamportClock::new(),
        }
    }

    /// Record an operation.
    pub fn record(&mut self, op: TimestampedOp) {
        self.clock.receive(op.timestamp);
        self.operations.push(op);
    }

    /// Record from raw fields (convenience).
    pub fn record_op(
        &mut self,
        name: &str,
        query: &str,
        variables: serde_json::Value,
        status: u16,
        is_mutation: bool,
    ) -> LamportTimestamp {
        let timestamp = self.clock.tick();
        let op = TimestampedOp {
            timestamp,
            wall_time: Utc::now(),
            operation_name: name.to_string(),
            query: query.to_string(),
            variables,
            response_status: status,
            is_mutation,
        };
        self.operations.push(op);
        timestamp
    }

    /// Analyze recorded operations for potential race conditions.
    ///
    /// Two operations can race if:
    /// 1. At least one is a mutation
    /// 2. They operate on overlapping types/fields (inferred from operation names)
    /// 3. Their wall-time difference is small enough for concurrent execution
    pub fn detect_races(&self, max_wall_time_gap_ms: u64) -> Vec<RaceCondition> {
        let mut races = Vec::new();
        let n = self.operations.len();

        info!(operations = n, max_wall_time_gap_ms, "Analyzing for races");

        for i in 0..n {
            for j in (i + 1)..n {
                let a = &self.operations[i];
                let b = &self.operations[j];

                // At least one must be a mutation
                if !a.is_mutation && !b.is_mutation {
                    continue;
                }

                // Check wall-time proximity
                let diff = (a.wall_time - b.wall_time)
                    .num_milliseconds()
                    .unsigned_abs();
                if diff > max_wall_time_gap_ms {
                    continue;
                }

                // Check if they could conflict
                if !Self::could_conflict(a, b) {
                    continue;
                }

                let race_type = Self::classify_race(a, b);
                let confidence = Self::compute_confidence(a, b, diff, max_wall_time_gap_ms);

                // Assign reader/writer roles
                let (reader, writer) = if a.is_mutation && b.is_mutation {
                    // Both mutations: earlier is "reader" (first write), later is "writer"
                    (a.clone(), b.clone())
                } else if a.is_mutation {
                    (b.clone(), a.clone())
                } else {
                    (a.clone(), b.clone())
                };

                debug!(
                    reader = %reader.operation_name,
                    writer = %writer.operation_name,
                    race_type = %race_type,
                    confidence,
                    "Detected potential race"
                );

                races.push(RaceCondition {
                    reader,
                    writer,
                    race_type,
                    confidence,
                });
            }
        }

        info!(count = races.len(), "Race detection complete");
        races
    }

    /// Check if two operations could conflict (heuristic based on operation names and queries).
    fn could_conflict(a: &TimestampedOp, b: &TimestampedOp) -> bool {
        // Extract type-like tokens from operation names and queries
        let a_tokens = Self::extract_resource_tokens(&a.operation_name, &a.query);
        let b_tokens = Self::extract_resource_tokens(&b.operation_name, &b.query);

        // Check for overlapping resource tokens
        for at in &a_tokens {
            for bt in &b_tokens {
                if Self::tokens_overlap(at, bt) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract resource-related tokens from an operation name and query.
    fn extract_resource_tokens(name: &str, query: &str) -> Vec<String> {
        let mut tokens = Vec::new();

        // Split camelCase/PascalCase operation name into parts
        let name_parts = Self::split_camel_case(name);
        tokens.extend(name_parts);

        // Look for type names in the query (words starting with uppercase after common keywords)
        for word in query.split(|c: char| !c.is_alphanumeric() && c != '_') {
            let trimmed = word.trim();
            if trimmed.len() > 2 && trimmed.chars().next().is_some_and(|c| c.is_uppercase()) {
                tokens.push(trimmed.to_lowercase());
            }
        }

        tokens
    }

    /// Split a camelCase or PascalCase string into lowercase parts.
    fn split_camel_case(s: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut current = String::new();

        for ch in s.chars() {
            if ch.is_uppercase() && !current.is_empty() {
                parts.push(current.to_lowercase());
                current.clear();
            }
            current.push(ch);
        }

        if !current.is_empty() {
            parts.push(current.to_lowercase());
        }

        parts
    }

    /// Check if two resource tokens overlap (case-insensitive substring or equality).
    fn tokens_overlap(a: &str, b: &str) -> bool {
        if a == b {
            return true;
        }
        // Check if one contains the other (for cases like "form" matches "formvalue")
        if a.len() >= 3 && b.contains(a) {
            return true;
        }
        if b.len() >= 3 && a.contains(b) {
            return true;
        }
        false
    }

    /// Classify the type of race between two operations.
    fn classify_race(a: &TimestampedOp, b: &TimestampedOp) -> RaceType {
        match (a.is_mutation, b.is_mutation) {
            (true, true) => {
                // Check for TOCTOU pattern: one operation name suggests checking/reading
                // while the other suggests writing/submitting
                let a_name_lower = a.operation_name.to_lowercase();
                let b_name_lower = b.operation_name.to_lowercase();

                let check_words = [
                    "get", "check", "verify", "validate", "fetch", "read", "load",
                ];
                // State-setting words: operations that establish state
                let setup_words = ["set", "create", "write", "modify"];
                // Finalizing words: operations that act on previously established state
                let finalize_words = [
                    "submit", "transfer", "send", "delete", "remove", "confirm", "approve",
                    "finalize", "complete",
                ];
                let act_words = [
                    "set", "submit", "create", "update", "delete", "remove", "write", "modify",
                    "transfer", "send",
                ];

                let a_is_check = check_words.iter().any(|w| a_name_lower.contains(w));
                let b_is_check = check_words.iter().any(|w| b_name_lower.contains(w));
                let a_is_act = act_words.iter().any(|w| a_name_lower.contains(w));
                let b_is_act = act_words.iter().any(|w| b_name_lower.contains(w));

                // Classic TOCTOU: check/read then act
                if (a_is_check && b_is_act) || (b_is_check && a_is_act) {
                    return RaceType::Toctou;
                }

                // Setup-then-finalize TOCTOU: one mutation sets state, another finalizes it
                let a_is_setup = setup_words.iter().any(|w| a_name_lower.contains(w));
                let b_is_setup = setup_words.iter().any(|w| b_name_lower.contains(w));
                let a_is_finalize = finalize_words.iter().any(|w| a_name_lower.contains(w));
                let b_is_finalize = finalize_words.iter().any(|w| b_name_lower.contains(w));

                if (a_is_setup && b_is_finalize) || (b_is_setup && a_is_finalize) {
                    return RaceType::Toctou;
                }

                RaceType::WriteWrite
            }
            // One is a mutation, one is a query
            _ => {
                // Check if the query side looks like a validation/authorization check
                let query_op = if a.is_mutation { b } else { a };
                let query_name_lower = query_op.operation_name.to_lowercase();

                let auth_words = [
                    "auth",
                    "permission",
                    "check",
                    "verify",
                    "validate",
                    "can",
                    "allowed",
                ];
                if auth_words.iter().any(|w| query_name_lower.contains(w)) {
                    RaceType::Toctou
                } else {
                    RaceType::ReadWrite
                }
            }
        }
    }

    /// Compute a confidence score for a race condition.
    fn compute_confidence(
        a: &TimestampedOp,
        b: &TimestampedOp,
        wall_time_diff_ms: u64,
        max_gap_ms: u64,
    ) -> f64 {
        let mut confidence = 0.5;

        // Closer in wall time → higher confidence
        if max_gap_ms > 0 {
            let time_factor = 1.0 - (wall_time_diff_ms as f64 / max_gap_ms as f64);
            confidence += 0.2 * time_factor;
        }

        // Both mutations → higher risk
        if a.is_mutation && b.is_mutation {
            confidence += 0.15;
        }

        // Similar operation names → higher confidence
        let a_lower = a.operation_name.to_lowercase();
        let b_lower = b.operation_name.to_lowercase();
        if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_op(
        name: &str,
        query: &str,
        is_mutation: bool,
        wall_time: chrono::DateTime<chrono::Utc>,
        timestamp: LamportTimestamp,
    ) -> TimestampedOp {
        TimestampedOp {
            timestamp,
            wall_time,
            operation_name: name.to_string(),
            query: query.to_string(),
            variables: serde_json::Value::Null,
            response_status: 200,
            is_mutation,
        }
    }

    #[test]
    fn test_concurrent_set_and_submit_is_toctou() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "setFormValue",
            "mutation SetFormValue($input: FormInput!) { setFormValue(input: $input) { id } }",
            true,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "submitForm",
            "mutation SubmitForm($id: ID!) { submitForm(id: $id) { status } }",
            true,
            now + Duration::milliseconds(10),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].race_type, RaceType::Toctou);
    }

    #[test]
    fn test_two_reads_no_race() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "getUser",
            "query GetUser { user { id name } }",
            false,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "getUser",
            "query GetUser { user { id email } }",
            false,
            now + Duration::milliseconds(5),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert!(races.is_empty());
    }

    #[test]
    fn test_mutations_far_apart_no_race() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "setFormValue",
            "mutation SetFormValue { setFormValue { id } }",
            true,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "submitForm",
            "mutation SubmitForm { submitForm { status } }",
            true,
            now + Duration::seconds(60),
            LamportTimestamp(2),
        ));

        // Gap of only 100ms allowed
        let races = detector.detect_races(100);
        assert!(races.is_empty());
    }

    #[test]
    fn test_read_write_race() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "getFormRender",
            "query GetFormRender { formRender { fields } }",
            false,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "updateFormRender",
            "mutation UpdateFormRender { updateFormRender { id } }",
            true,
            now + Duration::milliseconds(20),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].race_type, RaceType::ReadWrite);
    }

    #[test]
    fn test_write_write_race() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "updateUserProfile",
            "mutation UpdateUserProfile { updateUser { id } }",
            true,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "updateUserEmail",
            "mutation UpdateUserEmail { updateUser { email } }",
            true,
            now + Duration::milliseconds(5),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].race_type, RaceType::WriteWrite);
    }

    #[test]
    fn test_record_op_convenience() {
        let mut detector = RaceDetector::new();

        let ts1 = detector.record_op(
            "setFormValue",
            "mutation { setFormValue { id } }",
            serde_json::Value::Null,
            200,
            true,
        );

        let ts2 = detector.record_op(
            "submitForm",
            "mutation { submitForm { status } }",
            serde_json::Value::Null,
            200,
            true,
        );

        assert!(ts2 > ts1);

        // These will have very close wall times since they run sequentially
        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
    }

    #[test]
    fn test_no_conflict_different_resources() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "createUser",
            "mutation CreateUser { createUser { id } }",
            true,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "deleteProduct",
            "mutation DeleteProduct { deleteProduct { id } }",
            true,
            now + Duration::milliseconds(5),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert!(races.is_empty());
    }

    #[test]
    fn test_toctou_with_auth_query() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        detector.record(make_op(
            "checkUserPermission",
            "query CheckUserPermission($userId: ID!) { userPermission(userId: $userId) { canEdit } }",
            false,
            now,
            LamportTimestamp(1),
        ));

        detector.record(make_op(
            "updateUserProfile",
            "mutation UpdateUserProfile($input: UserInput!) { updateUser(input: $input) { id } }",
            true,
            now + Duration::milliseconds(15),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].race_type, RaceType::Toctou);
    }

    #[test]
    fn test_confidence_higher_when_closer_in_time() {
        let mut detector = RaceDetector::new();
        let now = Utc::now();

        // Very close pair
        detector.record(make_op(
            "updateFormValue",
            "mutation { updateFormValue { id } }",
            true,
            now,
            LamportTimestamp(1),
        ));
        detector.record(make_op(
            "deleteFormValue",
            "mutation { deleteFormValue { id } }",
            true,
            now + Duration::milliseconds(1),
            LamportTimestamp(2),
        ));

        let races = detector.detect_races(1000);
        assert_eq!(races.len(), 1);
        // Close in time should have higher confidence
        assert!(races[0].confidence > 0.5);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_two_reads_never_race(
            name1 in "[a-z]{3,10}",
            name2 in "[a-z]{3,10}",
            gap_ms in 0u64..1000
        ) {
            let mut detector = RaceDetector::new();
            let now = Utc::now();

            detector.record(TimestampedOp {
                timestamp: LamportTimestamp(1),
                wall_time: now,
                operation_name: name1,
                query: "query { field }".to_string(),
                variables: serde_json::Value::Null,
                response_status: 200,
                is_mutation: false,
            });

            detector.record(TimestampedOp {
                timestamp: LamportTimestamp(2),
                wall_time: now + chrono::Duration::milliseconds(gap_ms as i64),
                operation_name: name2,
                query: "query { field }".to_string(),
                variables: serde_json::Value::Null,
                response_status: 200,
                is_mutation: false,
            });

            let races = detector.detect_races(gap_ms + 1);
            prop_assert!(races.is_empty(), "Two reads should never produce a race");
        }

        #[test]
        fn prop_confidence_bounded(gap_ms in 0u64..500) {
            let mut detector = RaceDetector::new();
            let now = Utc::now();

            detector.record(TimestampedOp {
                timestamp: LamportTimestamp(1),
                wall_time: now,
                operation_name: "updateForm".to_string(),
                query: "mutation { updateForm { id } }".to_string(),
                variables: serde_json::Value::Null,
                response_status: 200,
                is_mutation: true,
            });

            detector.record(TimestampedOp {
                timestamp: LamportTimestamp(2),
                wall_time: now + chrono::Duration::milliseconds(gap_ms as i64),
                operation_name: "deleteForm".to_string(),
                query: "mutation { deleteForm { id } }".to_string(),
                variables: serde_json::Value::Null,
                response_status: 200,
                is_mutation: true,
            });

            let races = detector.detect_races(gap_ms + 1);
            for race in &races {
                prop_assert!(race.confidence >= 0.0 && race.confidence <= 1.0,
                    "Confidence {} out of bounds", race.confidence);
            }
        }
    }
}
