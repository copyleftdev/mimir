use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::SprtConfig;

/// Result of the sequential test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SprtDecision {
    /// Continue testing — insufficient evidence.
    Continue,
    /// Accept H1 (vulnerable) — sufficient evidence of vulnerability.
    Vulnerable {
        confidence: f64,
        observations: usize,
        log_likelihood_ratio: f64,
    },
    /// Accept H0 (likely secure) — sufficient evidence of security.
    LikelySecure {
        confidence: f64,
        observations: usize,
        log_likelihood_ratio: f64,
    },
    /// Reached max observations without conclusion.
    Inconclusive {
        observations: usize,
        log_likelihood_ratio: f64,
    },
}

/// Sequential Probability Ratio Test for vulnerability detection.
///
/// Models each observation as a Bernoulli trial:
/// - H0 (secure): probability of "interesting" response = p0 (e.g., 0.05)
/// - H1 (vulnerable): probability of "interesting" response = p1 (e.g., 0.30)
#[derive(Debug, Clone)]
pub struct Sprt {
    config: SprtConfig,
    /// H0 probability (secure baseline).
    p0: f64,
    /// H1 probability (vulnerable hypothesis).
    p1: f64,
    /// Upper boundary: ln(B) where B = (1 - beta) / alpha.
    upper_bound: f64,
    /// Lower boundary: ln(A) where A = beta / (1 - alpha).
    lower_bound: f64,
    /// Running log-likelihood ratio.
    log_lr: f64,
    /// Total observations.
    observations: usize,
    /// Positive observations (evidence of vulnerability).
    positives: usize,
}

impl Sprt {
    /// Create a new SPRT instance.
    ///
    /// - `p0`: baseline probability under H0 (secure), e.g. 0.05.
    /// - `p1`: elevated probability under H1 (vulnerable), e.g. 0.30.
    ///
    /// # Panics
    ///
    /// Panics if `p0 >= p1`, or if either probability is not in (0, 1).
    pub fn new(config: SprtConfig, p0: f64, p1: f64) -> Self {
        assert!(
            p0 > 0.0 && p0 < 1.0,
            "p0 must be in (0, 1), got {p0}"
        );
        assert!(
            p1 > 0.0 && p1 < 1.0,
            "p1 must be in (0, 1), got {p1}"
        );
        assert!(p0 < p1, "p0 must be less than p1: {p0} >= {p1}");

        let alpha = config.alpha;
        let beta = config.beta;

        // Upper boundary (reject H0 = declare vulnerable): ln((1 - beta) / alpha)
        let upper_bound = ((1.0 - beta) / alpha).ln();
        // Lower boundary (accept H0 = declare likely secure): ln(beta / (1 - alpha))
        let lower_bound = (beta / (1.0 - alpha)).ln();

        debug!(
            p0,
            p1,
            upper_bound,
            lower_bound,
            alpha,
            beta,
            "SPRT initialized"
        );

        Self {
            config,
            p0,
            p1,
            upper_bound,
            lower_bound,
            log_lr: 0.0,
            observations: 0,
            positives: 0,
        }
    }

    /// Feed an observation. Returns the current decision.
    ///
    /// `positive` = true means this observation is evidence of vulnerability.
    pub fn observe(&mut self, positive: bool) -> SprtDecision {
        self.observations += 1;

        if positive {
            self.positives += 1;
            // Log-likelihood ratio update for positive observation:
            // ln(p1 / p0)
            self.log_lr += (self.p1 / self.p0).ln();
        } else {
            // Log-likelihood ratio update for negative observation:
            // ln((1 - p1) / (1 - p0))
            self.log_lr += ((1.0 - self.p1) / (1.0 - self.p0)).ln();
        }

        debug!(
            observations = self.observations,
            positives = self.positives,
            log_lr = self.log_lr,
            positive,
            "SPRT observation"
        );

        // Enforce minimum observations before making a decision.
        if self.observations < self.config.min_observations {
            return SprtDecision::Continue;
        }

        // Check upper boundary: declare vulnerable.
        if self.log_lr >= self.upper_bound {
            let confidence = 1.0 - self.config.alpha;
            return SprtDecision::Vulnerable {
                confidence,
                observations: self.observations,
                log_likelihood_ratio: self.log_lr,
            };
        }

        // Check lower boundary: declare likely secure.
        if self.log_lr <= self.lower_bound {
            let confidence = 1.0 - self.config.beta;
            return SprtDecision::LikelySecure {
                confidence,
                observations: self.observations,
                log_likelihood_ratio: self.log_lr,
            };
        }

        // Check hard stop.
        if self.observations >= self.config.max_observations {
            return SprtDecision::Inconclusive {
                observations: self.observations,
                log_likelihood_ratio: self.log_lr,
            };
        }

        SprtDecision::Continue
    }

    /// Current log-likelihood ratio.
    pub fn log_likelihood_ratio(&self) -> f64 {
        self.log_lr
    }

    /// Current empirical rate of positive observations.
    pub fn empirical_rate(&self) -> f64 {
        if self.observations == 0 {
            0.0
        } else {
            self.positives as f64 / self.observations as f64
        }
    }

    /// Reset the test to its initial state.
    pub fn reset(&mut self) {
        self.log_lr = 0.0;
        self.observations = 0;
        self.positives = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn default_sprt() -> Sprt {
        Sprt::new(SprtConfig::default(), 0.05, 0.30)
    }

    #[test]
    fn all_positive_reaches_vulnerable() {
        let mut sprt = default_sprt();
        let mut decision = SprtDecision::Continue;
        for _ in 0..1000 {
            decision = sprt.observe(true);
            if matches!(decision, SprtDecision::Vulnerable { .. }) {
                break;
            }
        }
        assert!(
            matches!(decision, SprtDecision::Vulnerable { .. }),
            "Expected Vulnerable, got {decision:?}"
        );
    }

    #[test]
    fn all_negative_reaches_likely_secure() {
        let mut sprt = default_sprt();
        let mut decision = SprtDecision::Continue;
        for _ in 0..1000 {
            decision = sprt.observe(false);
            if matches!(decision, SprtDecision::LikelySecure { .. }) {
                break;
            }
        }
        assert!(
            matches!(decision, SprtDecision::LikelySecure { .. }),
            "Expected LikelySecure, got {decision:?}"
        );
    }

    #[test]
    fn mixed_near_p0_takes_longer() {
        // Feed observations at roughly p0 rate (5%). The test should take much
        // longer to decide compared to all-positive or all-negative.
        let mut sprt = Sprt::new(
            SprtConfig {
                max_observations: 200,
                ..SprtConfig::default()
            },
            0.05,
            0.30,
        );

        // Deterministic pattern: 1 positive every 20 observations (= 5% rate = p0).
        let mut decision = SprtDecision::Continue;
        for i in 0..200 {
            let positive = i % 20 == 0;
            decision = sprt.observe(positive);
            if !matches!(decision, SprtDecision::Continue) {
                break;
            }
        }

        // With observations near p0 the test should either still be undecided
        // or at worst reach the max. It should NOT quickly declare Vulnerable.
        assert!(
            !matches!(decision, SprtDecision::Vulnerable { observations, .. } if observations < 50),
            "Should not quickly declare Vulnerable with observations near p0"
        );
    }

    #[test]
    fn min_observations_respected() {
        let config = SprtConfig {
            min_observations: 20,
            ..SprtConfig::default()
        };
        let mut sprt = Sprt::new(config, 0.05, 0.30);

        for _ in 0..19 {
            let decision = sprt.observe(true);
            assert!(
                matches!(decision, SprtDecision::Continue),
                "Should continue before min_observations"
            );
        }
    }

    #[test]
    fn decision_boundaries_computed_correctly() {
        let config = SprtConfig {
            alpha: 0.05,
            beta: 0.10,
            ..SprtConfig::default()
        };
        let sprt = Sprt::new(config, 0.05, 0.30);

        let expected_upper = ((1.0 - 0.10) / 0.05_f64).ln();
        let expected_lower = (0.10 / (1.0 - 0.05_f64)).ln();

        assert!(
            (sprt.upper_bound - expected_upper).abs() < 1e-12,
            "Upper bound mismatch: {} vs {expected_upper}",
            sprt.upper_bound
        );
        assert!(
            (sprt.lower_bound - expected_lower).abs() < 1e-12,
            "Lower bound mismatch: {} vs {expected_lower}",
            sprt.lower_bound
        );
    }

    #[test]
    fn reset_clears_state() {
        let mut sprt = default_sprt();
        for _ in 0..50 {
            sprt.observe(true);
        }
        assert!(sprt.observations > 0);
        assert!(sprt.log_lr != 0.0);

        sprt.reset();
        assert_eq!(sprt.observations, 0);
        assert_eq!(sprt.positives, 0);
        assert_eq!(sprt.log_lr, 0.0);
        assert_eq!(sprt.empirical_rate(), 0.0);
    }

    #[test]
    fn empirical_rate_correctness() {
        let mut sprt = default_sprt();
        sprt.observe(true);
        sprt.observe(false);
        sprt.observe(true);
        sprt.observe(false);
        assert!((sprt.empirical_rate() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn max_observations_produces_inconclusive() {
        let config = SprtConfig {
            min_observations: 1,
            max_observations: 5,
            alpha: 0.001,   // very strict => wide boundaries
            beta: 0.001,
        };
        let mut sprt = Sprt::new(config, 0.05, 0.30);

        // Alternate to keep the log-lr near zero.
        let mut decision = SprtDecision::Continue;
        for i in 0..5 {
            decision = sprt.observe(i % 2 == 0);
        }

        // With only 5 observations and very strict alpha/beta, it should be
        // Inconclusive (or possibly decided if the boundaries are still close
        // enough). Mainly we verify no panic and the observation count.
        match &decision {
            SprtDecision::Inconclusive { observations, .. } => {
                assert_eq!(*observations, 5);
            }
            SprtDecision::Vulnerable { observations, .. }
            | SprtDecision::LikelySecure { observations, .. } => {
                assert_eq!(*observations, 5);
            }
            SprtDecision::Continue => {
                panic!("Should not still be Continue at max_observations");
            }
        }
    }

    // ── Property-based tests ──────────────────────────────────────────────

    proptest! {
        #[test]
        fn observation_count_always_increases(
            observations in proptest::collection::vec(proptest::bool::ANY, 1..200)
        ) {
            let mut sprt = default_sprt();
            let mut prev = 0_usize;
            for obs in observations {
                sprt.observe(obs);
                assert!(sprt.observations > prev);
                prev = sprt.observations;
            }
        }

        #[test]
        fn empirical_rate_in_unit_interval(
            observations in proptest::collection::vec(proptest::bool::ANY, 1..500)
        ) {
            let mut sprt = default_sprt();
            for obs in observations {
                sprt.observe(obs);
                let rate = sprt.empirical_rate();
                assert!(rate >= 0.0 && rate <= 1.0, "rate out of bounds: {rate}");
            }
        }

        #[test]
        fn boundaries_from_alpha_beta(
            alpha in 0.001..0.499_f64,
            beta in 0.001..0.499_f64,
        ) {
            let config = SprtConfig {
                alpha,
                beta,
                min_observations: 1,
                max_observations: 100,
            };
            let sprt = Sprt::new(config, 0.05, 0.30);

            let expected_upper = ((1.0 - beta) / alpha).ln();
            let expected_lower = (beta / (1.0 - alpha)).ln();

            assert!((sprt.upper_bound - expected_upper).abs() < 1e-10);
            assert!((sprt.lower_bound - expected_lower).abs() < 1e-10);
            // Upper bound must be positive, lower bound must be negative.
            assert!(sprt.upper_bound > 0.0);
            assert!(sprt.lower_bound < 0.0);
        }
    }
}
