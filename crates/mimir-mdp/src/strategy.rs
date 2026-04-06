/// Trait for exploration strategies.
pub trait ExplorationStrategy {
    /// Select the next action given available actions and history.
    /// Returns the index of the selected action.
    fn select(&mut self, action_count: usize) -> usize;

    /// Update the strategy with the outcome of the last action.
    fn update(&mut self, action_index: usize, reward: f64);
}

/// Epsilon-greedy: exploit best action (1-epsilon), explore randomly (epsilon).
pub struct EpsilonGreedy {
    epsilon: f64,
    action_rewards: Vec<(f64, usize)>, // (total_reward, count)
    rng_state: u64,
}

impl EpsilonGreedy {
    /// Create a new epsilon-greedy strategy.
    ///
    /// `epsilon` controls the exploration rate (0.0 = pure exploitation, 1.0 = pure exploration).
    /// `seed` is the initial RNG state.
    pub fn new(epsilon: f64, seed: u64) -> Self {
        Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            action_rewards: Vec::new(),
            rng_state: seed,
        }
    }

    /// Simple xorshift64 PRNG returning a value in [0, 1).
    fn next_random(&mut self) -> f64 {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        // Map to [0, 1)
        (self.rng_state as f64) / (u64::MAX as f64)
    }

    fn ensure_capacity(&mut self, action_count: usize) {
        while self.action_rewards.len() < action_count {
            self.action_rewards.push((0.0, 0));
        }
    }
}

impl ExplorationStrategy for EpsilonGreedy {
    fn select(&mut self, action_count: usize) -> usize {
        assert!(action_count > 0, "must have at least one action");
        self.ensure_capacity(action_count);

        let r = self.next_random();
        if r < self.epsilon {
            // Explore: pick a random action
            let idx = (self.next_random() * action_count as f64) as usize;
            idx.min(action_count - 1)
        } else {
            // Exploit: pick the action with the highest mean reward
            let mut best_idx = 0;
            let mut best_mean = f64::NEG_INFINITY;
            for (i, &(total, count)) in self.action_rewards.iter().enumerate().take(action_count) {
                let mean = if count == 0 {
                    0.0
                } else {
                    total / count as f64
                };
                if mean > best_mean {
                    best_mean = mean;
                    best_idx = i;
                }
            }
            best_idx
        }
    }

    fn update(&mut self, action_index: usize, reward: f64) {
        self.ensure_capacity(action_index + 1);
        self.action_rewards[action_index].0 += reward;
        self.action_rewards[action_index].1 += 1;
    }
}

/// Upper Confidence Bound (UCB1).
///
/// score = mean_reward + c * sqrt(ln(total_tries) / tries_for_action)
pub struct Ucb1 {
    c: f64,
    action_stats: Vec<(f64, usize)>, // (total_reward, count)
    total_count: usize,
}

impl Ucb1 {
    /// Create a new UCB1 strategy.
    ///
    /// `c` is the exploration constant; sqrt(2) is the theoretical optimum.
    pub fn new(c: f64) -> Self {
        Self {
            c,
            action_stats: Vec::new(),
            total_count: 0,
        }
    }

    /// Create a UCB1 strategy with the default exploration constant sqrt(2).
    pub fn default_c() -> Self {
        Self::new(std::f64::consts::SQRT_2)
    }

    fn ensure_capacity(&mut self, action_count: usize) {
        while self.action_stats.len() < action_count {
            self.action_stats.push((0.0, 0));
        }
    }

    /// Compute the UCB1 score for an action.
    fn score(&self, action_index: usize) -> f64 {
        let (total_reward, count) = self.action_stats[action_index];
        if count == 0 {
            return f64::INFINITY; // Force exploration of untried actions
        }
        let mean = total_reward / count as f64;
        let exploration = self.c * ((self.total_count as f64).ln() / count as f64).sqrt();
        mean + exploration
    }
}

impl ExplorationStrategy for Ucb1 {
    fn select(&mut self, action_count: usize) -> usize {
        assert!(action_count > 0, "must have at least one action");
        self.ensure_capacity(action_count);

        let mut best_idx = 0;
        let mut best_score = f64::NEG_INFINITY;
        for i in 0..action_count {
            let s = self.score(i);
            if s > best_score {
                best_score = s;
                best_idx = i;
            }
        }
        best_idx
    }

    fn update(&mut self, action_index: usize, reward: f64) {
        self.ensure_capacity(action_index + 1);
        self.action_stats[action_index].0 += reward;
        self.action_stats[action_index].1 += 1;
        self.total_count += 1;
    }
}

/// Thompson Sampling with Beta distribution approximation.
///
/// Maintains alpha/beta parameters for each action's reward distribution.
pub struct ThompsonSampling {
    action_params: Vec<(f64, f64)>, // (alpha, beta) for each action
    rng_state: u64,
}

impl ThompsonSampling {
    /// Create a new Thompson Sampling strategy.
    ///
    /// `seed` is the initial RNG state (must be non-zero).
    pub fn new(seed: u64) -> Self {
        Self {
            action_params: Vec::new(),
            rng_state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Simple xorshift64 PRNG returning a value in [0, 1).
    fn next_random(&mut self) -> f64 {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        (self.rng_state as f64) / (u64::MAX as f64)
    }

    fn ensure_capacity(&mut self, action_count: usize) {
        while self.action_params.len() < action_count {
            // Prior: Beta(1, 1) = uniform
            self.action_params.push((1.0, 1.0));
        }
    }

    /// Sample from the Beta distribution for a given action using an approximation.
    ///
    /// sample = alpha / (alpha + beta) + noise scaled by the variance.
    fn sample_beta(&mut self, alpha: f64, beta: f64) -> f64 {
        let mean = alpha / (alpha + beta);
        let variance = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let std_dev = variance.sqrt();
        // Generate noise in [-1, 1] and scale by standard deviation
        let noise = (self.next_random() * 2.0 - 1.0) * std_dev;
        (mean + noise).clamp(0.0, 1.0)
    }
}

impl ExplorationStrategy for ThompsonSampling {
    fn select(&mut self, action_count: usize) -> usize {
        assert!(action_count > 0, "must have at least one action");
        self.ensure_capacity(action_count);

        let mut best_idx = 0;
        let mut best_sample = f64::NEG_INFINITY;
        for i in 0..action_count {
            let (alpha, beta) = self.action_params[i];
            let sample = self.sample_beta(alpha, beta);
            if sample > best_sample {
                best_sample = sample;
                best_idx = i;
            }
        }
        best_idx
    }

    fn update(&mut self, action_index: usize, reward: f64) {
        self.ensure_capacity(action_index + 1);
        // Treat reward as a Bernoulli-like signal: reward > 0 increases alpha, otherwise beta.
        // Scale the update by the magnitude of the reward.
        let clamped = reward.clamp(0.0, 1.0);
        self.action_params[action_index].0 += clamped;
        self.action_params[action_index].1 += 1.0 - clamped;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ucb1_selects_unexplored_actions_first() {
        let mut ucb = Ucb1::default_c();
        // With 3 actions and no history, UCB1 should select action 0 first (all infinite, first wins)
        let first = ucb.select(3);
        assert_eq!(first, 0);

        // After updating action 0, it should select action 1 next (still unexplored = infinity)
        ucb.update(0, 1.0);
        let second = ucb.select(3);
        assert_eq!(second, 1);

        // After updating action 1, it should select action 2 next
        ucb.update(1, 0.5);
        let third = ucb.select(3);
        assert_eq!(third, 2);
    }

    #[test]
    fn ucb1_converges_to_best_action() {
        let mut ucb = Ucb1::default_c();
        let action_count = 3;

        // Explore all actions first
        for i in 0..action_count {
            ucb.update(i, 0.0);
        }

        // Give action 1 consistently high rewards
        for _ in 0..100 {
            ucb.update(1, 1.0);
        }
        // Give others low rewards
        for _ in 0..100 {
            ucb.update(0, 0.1);
            ucb.update(2, 0.1);
        }

        // After many updates, UCB1 should prefer action 1
        let selected = ucb.select(action_count);
        assert_eq!(selected, 1);
    }

    #[test]
    fn epsilon_greedy_explores_proportional_to_epsilon() {
        // With epsilon = 1.0, every selection should be random (explore)
        let mut eg = EpsilonGreedy::new(1.0, 42);
        let action_count = 5;

        // Give action 0 a very high reward so it would always be chosen in exploit mode
        eg.update(0, 100.0);
        for i in 1..action_count {
            eg.update(i, 0.0);
        }

        let mut counts = vec![0usize; action_count];
        let trials = 1000;
        for _ in 0..trials {
            let idx = eg.select(action_count);
            counts[idx] += 1;
        }

        // With epsilon=1.0, all actions should get some selections
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                count > 0,
                "action {i} was never selected with epsilon=1.0"
            );
        }
    }

    #[test]
    fn epsilon_greedy_exploits_with_zero_epsilon() {
        let mut eg = EpsilonGreedy::new(0.0, 42);
        let action_count = 3;

        // Give action 2 the highest mean reward
        eg.update(0, 0.1);
        eg.update(1, 0.5);
        eg.update(2, 1.0);

        // With epsilon=0, it should always pick the best action
        for _ in 0..100 {
            let idx = eg.select(action_count);
            assert_eq!(idx, 2, "epsilon=0 should always pick the best action");
        }
    }

    #[test]
    fn thompson_sampling_selects_within_range() {
        let mut ts = ThompsonSampling::new(42);
        let action_count = 4;

        for _ in 0..50 {
            let idx = ts.select(action_count);
            assert!(idx < action_count);
            ts.update(idx, 0.5);
        }
    }

    #[test]
    fn thompson_sampling_favors_rewarded_actions() {
        let mut ts = ThompsonSampling::new(123);
        let action_count = 3;

        // Heavily reward action 1
        for _ in 0..50 {
            ts.update(1, 1.0);
        }
        // Punish others
        for _ in 0..50 {
            ts.update(0, 0.0);
            ts.update(2, 0.0);
        }

        let mut counts = vec![0usize; action_count];
        for _ in 0..200 {
            let idx = ts.select(action_count);
            counts[idx] += 1;
        }

        // Action 1 should be selected most often
        assert!(
            counts[1] > counts[0] && counts[1] > counts[2],
            "Thompson sampling should favor the most rewarded action: counts={counts:?}"
        );
    }
}
