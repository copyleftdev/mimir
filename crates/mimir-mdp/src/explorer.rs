use crate::state::ApiState;

/// Keywords that indicate auth-related errors.
const AUTH_KEYWORDS: &[&str] = &[
    "unauthorized",
    "unauthenticated",
    "forbidden",
    "access denied",
    "permission denied",
    "invalid token",
    "expired token",
    "not authenticated",
    "authentication required",
    "login required",
];

/// Check if a message is auth-related.
fn is_auth_related(message: &str) -> bool {
    let lower = message.to_lowercase();
    AUTH_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Compute reward from an API response. Higher reward = more security-interesting.
///
/// Reward breakdown:
/// - +1.0 for new state discovered (fingerprint changed)
/// - +0.5 for new error message type
/// - +0.3 for status code change (especially 200->500 or 403->200)
/// - +0.2 for high entropy error (>4.0 bits)
/// - +1.5 for auth-related error appearing or disappearing
/// - -0.1 for repeated same state (diminishing returns)
pub fn compute_reward(
    previous_state: &ApiState,
    new_state: &ApiState,
    status_code: u16,
    errors: &[String],
    response_entropy: f64,
) -> f64 {
    let mut reward = 0.0;

    // +1.0 for new state discovered
    let is_new_state = previous_state.fingerprint != new_state.fingerprint;
    if is_new_state {
        reward += 1.0;
    } else {
        // -0.1 for repeated same state
        reward -= 0.1;
    }

    // +0.5 for each new error message type
    for error in errors {
        if !previous_state.error_messages.contains(error) {
            reward += 0.5;
        }
    }

    // +0.3 for status code change
    if let Some(&last_status) = previous_state.status_codes.last() {
        if last_status != status_code {
            reward += 0.3;

            // Extra bonus for security-interesting transitions
            // 200 -> 500 (server error from success)
            // 403 -> 200 (bypass of access control)
            if (last_status == 200 && status_code == 500)
                || (last_status == 403 && status_code == 200)
            {
                reward += 0.3; // Additional bonus for these transitions
            }
        }
    }

    // +0.2 for high entropy error (>4.0 bits)
    if response_entropy > 4.0 {
        reward += 0.2;
    }

    // +1.5 for auth-related error appearing or disappearing
    let prev_has_auth = previous_state
        .error_messages
        .iter()
        .any(|m| is_auth_related(m));
    let new_has_auth = errors.iter().any(|m| is_auth_related(m));

    if prev_has_auth != new_has_auth {
        reward += 1.5;
    }

    reward
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(fingerprint: &str, errors: &[&str], status_codes: &[u16]) -> ApiState {
        ApiState {
            fingerprint: fingerprint.to_string(),
            status_codes: status_codes.to_vec(),
            error_messages: errors.iter().map(|e| e.to_string()).collect(),
            response_shapes: Vec::new(),
            tokens: Vec::new(),
            step_count: 0,
        }
    }

    #[test]
    fn reward_positive_for_new_state() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-b", &[], &[200]);

        let reward = compute_reward(&prev, &new, 200, &[], 0.0);
        assert!(
            reward > 0.0,
            "discovering a new state should give positive reward, got {reward}"
        );
    }

    #[test]
    fn reward_negative_for_same_state() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-a", &[], &[200]);

        let reward = compute_reward(&prev, &new, 200, &[], 0.0);
        assert!(
            reward < 0.0,
            "repeating the same state with no changes should give negative reward, got {reward}"
        );
    }

    #[test]
    fn reward_bonus_for_new_error() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-a", &[], &[200]);

        let errors = vec!["some new error".to_string()];
        let reward = compute_reward(&prev, &new, 200, &errors, 0.0);

        // -0.1 for same state + 0.5 for new error = 0.4
        assert!(
            reward > 0.0,
            "new error should offset same-state penalty, got {reward}"
        );
    }

    #[test]
    fn reward_bonus_for_status_code_change() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-a", &[], &[500]);

        let reward = compute_reward(&prev, &new, 500, &[], 0.0);
        // -0.1 for same state + 0.3 for status change + 0.3 for 200->500 = 0.5
        assert!(
            reward > 0.0,
            "status code change should give positive reward, got {reward}"
        );
    }

    #[test]
    fn reward_bonus_for_auth_bypass() {
        let prev = make_state("state-a", &["forbidden"], &[403]);
        let new = make_state("state-b", &[], &[200]);

        let reward = compute_reward(&prev, &new, 200, &[], 0.0);
        // +1.0 for new state + 0.3 for status change + 0.3 for 403->200 + 1.5 for auth change = 3.1
        assert!(
            reward >= 2.0,
            "auth bypass should give high reward, got {reward}"
        );
    }

    #[test]
    fn reward_bonus_for_auth_error_appearing() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-b", &[], &[401]);

        let errors = vec!["Unauthorized".to_string()];
        let reward = compute_reward(&prev, &new, 401, &errors, 0.0);
        // +1.0 new state + 0.5 new error + 0.3 status change + 1.5 auth change = 3.3
        assert!(
            reward >= 2.0,
            "auth error appearing should give high reward, got {reward}"
        );
    }

    #[test]
    fn reward_bonus_for_high_entropy() {
        let prev = make_state("state-a", &[], &[200]);
        let new = make_state("state-a", &[], &[200]);

        let reward_low = compute_reward(&prev, &new, 200, &[], 2.0);
        let reward_high = compute_reward(&prev, &new, 200, &[], 5.0);
        assert!(
            reward_high > reward_low,
            "high entropy should give more reward: low={reward_low}, high={reward_high}"
        );
    }

    #[test]
    fn is_auth_related_detects_keywords() {
        assert!(is_auth_related("Unauthorized access"));
        assert!(is_auth_related("FORBIDDEN"));
        assert!(is_auth_related("Access denied for user"));
        assert!(is_auth_related("invalid token provided"));
        assert!(!is_auth_related("some other error"));
        assert!(!is_auth_related("field not found"));
    }
}
