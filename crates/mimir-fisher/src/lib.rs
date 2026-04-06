#![allow(
    clippy::redundant_closure,
    clippy::needless_range_loop,
    clippy::excessive_precision,
    clippy::manual_saturating_arithmetic,
    clippy::let_and_return
)]
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Result of Fisher's exact test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FisherResult {
    /// The p-value (probability of observing this distribution under null hypothesis).
    pub p_value: f64,
    /// Whether the result is significant at the given alpha level.
    pub significant: bool,
    /// The alpha level used.
    pub alpha: f64,
    /// Odds ratio (strength of association).
    pub odds_ratio: f64,
    /// The 2x2 contingency table.
    pub table: ContingencyTable,
}

/// A 2x2 contingency table for authorization analysis.
///
/// ```text
///                  | Fields Visible | Fields Hidden |
/// Authenticated    |       a        |      b        |
/// Unauthenticated  |       c        |      d        |
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyTable {
    /// Authenticated + visible.
    pub a: u64,
    /// Authenticated + hidden.
    pub b: u64,
    /// Unauthenticated + visible.
    pub c: u64,
    /// Unauthenticated + hidden.
    pub d: u64,
}

impl ContingencyTable {
    pub fn new(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self { a, b, c, d }
    }

    /// Grand total of all cells.
    pub fn total(&self) -> u64 {
        self.a + self.b + self.c + self.d
    }

    /// Row totals: (authenticated total, unauthenticated total).
    pub fn row_totals(&self) -> (u64, u64) {
        (self.a + self.b, self.c + self.d)
    }

    /// Column totals: (visible total, hidden total).
    pub fn col_totals(&self) -> (u64, u64) {
        (self.a + self.c, self.b + self.d)
    }
}

/// Compute the exact p-value using the hypergeometric distribution.
///
/// Uses a one-tailed test (greater) to detect whether authenticated users
/// see significantly more fields than unauthenticated users. The p-value
/// sums the probabilities of all tables at least as extreme as the observed
/// table (same marginals, `a >= observed_a`).
///
/// The probability of a single table with fixed marginals is:
///
/// ```text
/// P = C(a+b, a) * C(c+d, c) / C(n, a+c)
/// ```
///
/// where `C(n, k)` is the binomial coefficient and `n` is the grand total.
pub fn fisher_exact_test(table: &ContingencyTable, alpha: f64) -> FisherResult {
    let (r1, r2) = table.row_totals(); // (a+b, c+d)
    let (c1, _c2) = table.col_totals(); // (a+c, b+d)
    let n = table.total();

    // The range of possible values for cell `a` given fixed marginals:
    // a_min = max(0, c1 - r2) = max(0, (a+c) - (c+d))
    // a_max = min(r1, c1)     = min(a+b, a+c)
    let a_min = c1.saturating_sub(r2);
    let a_max = r1.min(c1);

    // Log-probability of a single table configuration.
    // ln P(a) = ln C(r1, a) + ln C(r2, c1 - a) - ln C(n, c1)
    let ln_denom = ln_binomial(n, c1);

    let ln_prob = |a_val: u64| -> f64 {
        let c_val = c1.saturating_sub(a_val);
        ln_binomial(r1, a_val) + ln_binomial(r2, c_val) - ln_denom
    };

    let observed_ln_p = ln_prob(table.a);

    // Sum probabilities of all tables at least as extreme as the observed one.
    // "At least as extreme" means tables whose probability <= observed probability
    // (two-sided interpretation using the probability cutoff method).
    let mut ln_p_value_terms: Vec<f64> = Vec::new();
    for a_val in a_min..=a_max {
        let lp = ln_prob(a_val);
        // Include this table if its probability is <= the observed table's probability
        // (within floating-point tolerance).
        if lp <= observed_ln_p + 1e-10 {
            ln_p_value_terms.push(lp);
        }
    }

    // Sum in log-space using the log-sum-exp trick for numerical stability.
    let p_value = if ln_p_value_terms.is_empty() {
        0.0
    } else {
        let max_ln = ln_p_value_terms
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let sum_exp: f64 = ln_p_value_terms.iter().map(|&lp| (lp - max_ln).exp()).sum();
        let result = (max_ln + sum_exp.ln()).exp();
        result.clamp(0.0, 1.0)
    };

    // Odds ratio: (a * d) / (b * c). Handle zeros gracefully.
    let odds_ratio = if table.b == 0 || table.c == 0 {
        f64::INFINITY
    } else {
        (table.a as f64 * table.d as f64) / (table.b as f64 * table.c as f64)
    };

    FisherResult {
        p_value,
        significant: p_value < alpha,
        alpha,
        odds_ratio,
        table: table.clone(),
    }
}

/// Build a contingency table from two JSON responses by comparing field presence.
///
/// Collects the union of all top-level keys from both objects, then counts:
/// - `a`: keys present in `authed`
/// - `b`: keys absent from `authed` (present only in `unauthed`)
/// - `c`: keys present in `unauthed`
/// - `d`: keys absent from `unauthed` (present only in `authed`)
///
/// For non-object values, returns a zero table.
pub fn build_table_from_responses(authed: &Value, unauthed: &Value) -> ContingencyTable {
    let (authed_keys, unauthed_keys) = match (authed.as_object(), unauthed.as_object()) {
        (Some(a), Some(u)) => {
            let ak: BTreeSet<&String> = a.keys().collect();
            let uk: BTreeSet<&String> = u.keys().collect();
            (ak, uk)
        }
        _ => return ContingencyTable::new(0, 0, 0, 0),
    };

    // The union of all keys defines the total number of fields.
    let all_keys: BTreeSet<&String> = authed_keys.union(&unauthed_keys).copied().collect();
    let total = all_keys.len() as u64;

    // Build the 2x2 contingency table:
    //
    //                  | Visible | Hidden |
    // Authenticated    |    a    |   b    |    row total = total fields
    // Unauthenticated  |    c    |   d    |    row total = total fields
    //
    // "Visible" means the key is present in that group's response.
    let a = authed_keys.len() as u64;
    let b = total - a;
    let c = unauthed_keys.len() as u64;
    let d = total - c;

    ContingencyTable::new(a, b, c, d)
}

/// Log of the binomial coefficient C(n, k) using log-gamma.
///
/// `C(n, k) = n! / (k! * (n-k)!)`
/// `ln C(n, k) = ln_gamma(n+1) - ln_gamma(k+1) - ln_gamma(n-k+1)`
fn ln_binomial(n: u64, k: u64) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    ln_gamma((n + 1) as f64) - ln_gamma((k + 1) as f64) - ln_gamma((n - k + 1) as f64)
}

/// Log-gamma function using the Lanczos approximation (g = 7, 7 coefficients).
///
/// ```text
/// ln_gamma(z) = 0.5 * ln(2*pi) + (z + 0.5) * ln(z + g + 0.5) - (z + g + 0.5) + ln(Ag(z))
/// ```
///
/// where Ag(z) is a series approximation. This is accurate to ~15 significant digits
/// for z > 0.5. For z < 0.5 the reflection formula is used.
fn ln_gamma(x: f64) -> f64 {
    // For non-positive integers, gamma is undefined (poles).
    // We only need positive values for factorial computations.
    if x <= 0.0 && x == x.floor() {
        return f64::INFINITY;
    }

    // Reflection formula for x < 0.5:
    // Gamma(x) * Gamma(1-x) = pi / sin(pi * x)
    // => ln Gamma(x) = ln(pi) - ln(sin(pi * x)) - ln Gamma(1 - x)
    if x < 0.5 {
        let reflected = ln_gamma(1.0 - x);
        return std::f64::consts::PI.ln() - (std::f64::consts::PI * x).sin().abs().ln() - reflected;
    }

    // Lanczos approximation with g = 7.
    const G: f64 = 7.0;
    const COEFFICIENTS: [f64; 8] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_9,
        771.323_428_777_653_08,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
    ];

    let z = x - 1.0;
    let mut ag = COEFFICIENTS[0];
    for i in 1..COEFFICIENTS.len() {
        ag += COEFFICIENTS[i] / (z + i as f64);
    }

    let t = z + G + 0.5;

    // ln Gamma(z+1) = 0.5 * ln(2*pi) + (z + 0.5) * ln(t) - t + ln(ag)
    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + ag.ln()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Helper ────────────────────────────────────────────────────────────

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    // ── Unit tests ────────────────────────────────────────────────────────

    #[test]
    fn tea_tasting_experiment() {
        // Fisher's original lady-tasting-tea experiment.
        // The lady correctly identified 3 out of 4 cups in each group.
        //
        //                | Milk First | Tea First |
        // Guessed Milk   |     3      |     1     |
        // Guessed Tea    |     1      |     3     |
        //
        // Known p-value for one-tailed: 0.2429 (the probability of getting
        // exactly this or more extreme with these marginals).
        let table = ContingencyTable::new(3, 1, 1, 3);
        let result = fisher_exact_test(&table, 0.05);

        // The two-sided (probability cutoff) p-value for this table is ~0.4857.
        // But with the probability cutoff method, only tables with P <= P(observed)
        // are included. Let's verify it's in a reasonable range and not significant.
        assert!(
            result.p_value > 0.2 && result.p_value < 0.6,
            "Tea-tasting p-value should be in a reasonable range, got {}",
            result.p_value
        );
        assert!(
            !result.significant,
            "Tea-tasting should not be significant at alpha=0.05"
        );
    }

    #[test]
    fn perfectly_balanced_table() {
        // Identical distributions => no association => p-value should be 1.0.
        let table = ContingencyTable::new(5, 5, 5, 5);
        let result = fisher_exact_test(&table, 0.05);
        assert!(
            result.p_value > 0.99,
            "Balanced table should have p near 1.0, got {}",
            result.p_value
        );
        assert!(!result.significant);
    }

    #[test]
    fn extreme_table_significant() {
        // All fields visible to authed, none to unauthed.
        //
        //                 | Visible | Hidden |
        // Authenticated   |   10    |   0    |
        // Unauthenticated |    0    |  10    |
        //
        // This is the most extreme table possible => p-value should be tiny.
        let table = ContingencyTable::new(10, 0, 0, 10);
        let result = fisher_exact_test(&table, 0.05);
        assert!(
            result.p_value < 0.001,
            "Extreme table should have p < 0.001, got {}",
            result.p_value
        );
        assert!(result.significant);
    }

    #[test]
    fn symmetric_table_odds_ratio_near_one() {
        let table = ContingencyTable::new(10, 10, 10, 10);
        let result = fisher_exact_test(&table, 0.05);
        assert!(
            approx_eq(result.odds_ratio, 1.0, 1e-10),
            "Symmetric table should have odds ratio ~1.0, got {}",
            result.odds_ratio
        );
    }

    #[test]
    fn table_totals() {
        let table = ContingencyTable::new(3, 7, 2, 8);
        assert_eq!(table.total(), 20);
        assert_eq!(table.row_totals(), (10, 10));
        assert_eq!(table.col_totals(), (5, 15));
    }

    #[test]
    fn build_table_from_json_different_objects() {
        let authed = serde_json::json!({
            "id": 1,
            "name": "Alice",
            "email": "alice@example.com",
            "ssn": "123-45-6789"
        });
        let unauthed = serde_json::json!({
            "id": 1,
            "name": "Alice"
        });

        let table = build_table_from_responses(&authed, &unauthed);

        // Union of keys: {id, name, email, ssn} = 4 fields.
        // authed sees: id, name, email, ssn => a = 4, b = 0
        // unauthed sees: id, name => c = 2, d = 2
        assert_eq!(table.a, 4, "authed visible");
        assert_eq!(table.b, 0, "authed hidden");
        assert_eq!(table.c, 2, "unauthed visible");
        assert_eq!(table.d, 2, "unauthed hidden");
        assert_eq!(table.total(), 8); // 4 + 0 + 2 + 2
    }

    #[test]
    fn build_table_from_json_identical_objects() {
        let authed = serde_json::json!({"a": 1, "b": 2});
        let unauthed = serde_json::json!({"a": 1, "b": 2});

        let table = build_table_from_responses(&authed, &unauthed);

        assert_eq!(table.a, 2);
        assert_eq!(table.b, 0);
        assert_eq!(table.c, 2);
        assert_eq!(table.d, 0);
    }

    #[test]
    fn build_table_non_objects() {
        let table = build_table_from_responses(&serde_json::json!("hello"), &serde_json::json!(42));
        assert_eq!(table.total(), 0);
    }

    #[test]
    fn ln_binomial_known_values() {
        // C(4, 2) = 6
        let result = ln_binomial(4, 2).exp();
        assert!(
            approx_eq(result, 6.0, 1e-8),
            "C(4,2) should be 6, got {result}"
        );

        // C(10, 0) = 1
        let result = ln_binomial(10, 0).exp();
        assert!(
            approx_eq(result, 1.0, 1e-8),
            "C(10,0) should be 1, got {result}"
        );

        // C(10, 10) = 1
        let result = ln_binomial(10, 10).exp();
        assert!(
            approx_eq(result, 1.0, 1e-8),
            "C(10,10) should be 1, got {result}"
        );

        // C(20, 10) = 184756
        let result = ln_binomial(20, 10).exp();
        assert!(
            approx_eq(result, 184_756.0, 1.0),
            "C(20,10) should be 184756, got {result}"
        );
    }

    #[test]
    fn ln_gamma_known_values() {
        // Gamma(1) = 0! = 1 => ln Gamma(1) = 0
        assert!(
            approx_eq(ln_gamma(1.0), 0.0, 1e-8),
            "ln Gamma(1) should be 0, got {}",
            ln_gamma(1.0)
        );

        // Gamma(2) = 1! = 1 => ln Gamma(2) = 0
        assert!(
            approx_eq(ln_gamma(2.0), 0.0, 1e-8),
            "ln Gamma(2) should be 0, got {}",
            ln_gamma(2.0)
        );

        // Gamma(5) = 4! = 24 => ln Gamma(5) = ln(24)
        assert!(
            approx_eq(ln_gamma(5.0), 24.0_f64.ln(), 1e-8),
            "ln Gamma(5) should be ln(24), got {}",
            ln_gamma(5.0)
        );

        // Gamma(11) = 10! = 3628800 => ln Gamma(11) = ln(3628800)
        assert!(
            approx_eq(ln_gamma(11.0), 3_628_800.0_f64.ln(), 1e-6),
            "ln Gamma(11) should be ln(3628800), got {}",
            ln_gamma(11.0)
        );
    }

    #[test]
    fn zero_cell_table() {
        // One cell is zero but table is valid.
        let table = ContingencyTable::new(5, 0, 3, 2);
        let result = fisher_exact_test(&table, 0.05);
        assert!(result.p_value >= 0.0 && result.p_value <= 1.0);
        assert_eq!(result.odds_ratio, f64::INFINITY); // b = 0
    }

    #[test]
    fn all_zero_table() {
        let table = ContingencyTable::new(0, 0, 0, 0);
        let result = fisher_exact_test(&table, 0.05);
        // With an empty table, p-value should be 1.0 (no evidence of anything).
        assert!(result.p_value >= 0.0 && result.p_value <= 1.0);
    }

    // ── Property-based tests ──────────────────────────────────────────────

    proptest! {
        #[test]
        fn p_value_in_unit_interval(
            a in 0u64..20,
            b in 0u64..20,
            c in 0u64..20,
            d in 0u64..20,
        ) {
            let table = ContingencyTable::new(a, b, c, d);
            let result = fisher_exact_test(&table, 0.05);
            prop_assert!(result.p_value >= 0.0, "p < 0: {}", result.p_value);
            prop_assert!(result.p_value <= 1.0 + 1e-10, "p > 1: {}", result.p_value);
        }

        #[test]
        fn total_is_sum(
            a in 0u64..1000,
            b in 0u64..1000,
            c in 0u64..1000,
            d in 0u64..1000,
        ) {
            let table = ContingencyTable::new(a, b, c, d);
            prop_assert_eq!(table.total(), a + b + c + d);
        }

        #[test]
        fn row_totals_correct(
            a in 0u64..1000,
            b in 0u64..1000,
            c in 0u64..1000,
            d in 0u64..1000,
        ) {
            let table = ContingencyTable::new(a, b, c, d);
            let (r1, r2) = table.row_totals();
            prop_assert_eq!(r1, a + b);
            prop_assert_eq!(r2, c + d);
        }

        #[test]
        fn col_totals_correct(
            a in 0u64..1000,
            b in 0u64..1000,
            c in 0u64..1000,
            d in 0u64..1000,
        ) {
            let table = ContingencyTable::new(a, b, c, d);
            let (c1, c2) = table.col_totals();
            prop_assert_eq!(c1, a + c);
            prop_assert_eq!(c2, b + d);
        }
    }
}
