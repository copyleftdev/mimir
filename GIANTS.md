# Standing on the Shoulders of Giants

The additions that make gql-sweep not just a tool, but a *proof* that computer science applies to security.

---

## 1. Abraham Wald — Sequential Probability Ratio Test (SPRT)

**The mind:** Wald (1902–1950) invented sequential analysis at Columbia during WWII. Instead of fixing a sample size in advance, his SPRT lets you make a decision as soon as the evidence is strong enough — accepting or rejecting a hypothesis with bounded error rates.

**Applied to gql-sweep:** Instead of running a fixed number of operations, SPRT tells us *when to stop*. After each operation, we compute the likelihood ratio:

```
Λₙ = P(observations | vulnerable) / P(observations | secure)
```

If `Λₙ ≥ B`, stop and report "vulnerable" (with confidence 1-β).
If `Λₙ ≤ A`, stop and report "likely secure" (with confidence 1-α).
If `A < Λₙ < B`, continue testing.

**Why this matters:** Every other security scanner runs N checks blindly. SPRT stops the moment it has statistical evidence — faster when vulnerabilities exist, more thorough when they don't.

**Reference:** Wald, A. (1945). "Sequential Tests of Statistical Hypotheses." *Annals of Mathematical Statistics.*

---

## 2. John Hughes — Stateful Shrinking

**The mind:** Hughes (b. 1958) invented QuickCheck at Chalmers. His key insight beyond random testing: when you find a failing case, *shrink it* to the minimal reproduction.

**Applied to gql-sweep:** When the MDP explorer finds a vulnerability via a 47-operation sequence, shrinking reduces it to the 3 operations that actually matter. The algorithm:

1. Record the full action sequence that triggered the finding
2. Try removing each action — if the vulnerability still reproduces, that action was irrelevant
3. Binary search for the minimal prefix that triggers it
4. Output: "These 3 operations, in this order, reproduce the vulnerability"

**Why this matters:** A 200-operation trace is useless for a bug report. A 3-operation reproduction is actionable. This is the difference between "we found something" and "here's exactly how to fix it."

**Reference:** Claessen, K., Hughes, J. (2000). "QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs." *ICFP.*

---

## 3. Ronald Fisher — Exact Test for Differential Significance

**The mind:** Fisher (1890–1962) at Rothamsted. The Fisher exact test determines whether two categorical distributions are significantly different, even with small sample sizes.

**Applied to gql-sweep:** When comparing authenticated vs. unauthenticated responses, we need to know: is the difference *statistically significant* or just noise?

```
Contingency table:
              | Fields visible | Fields hidden |
Authenticated |       a        |       b       |
Unauthenticated|      c        |       d       |

p-value = Fisher's exact test on this 2×2 table
```

If `p < 0.05`, the authorization boundary is real. If `p > 0.05`, the "protection" might be inconsistent or nonexistent.

**Why this matters:** Current tools say "these fields are different." We say "these fields are different with p=0.003, meaning there's a 0.3% chance this is coincidence." That's the difference between an observation and evidence.

**Reference:** Fisher, R.A. (1922). "On the Interpretation of χ² from Contingency Tables." *Journal of the Royal Statistical Society.*

---

## 4. Leslie Lamport — Happens-Before for Race Detection

**The mind:** Lamport (b. 1941), Turing Award 2013. His happens-before relation defines causal ordering in distributed systems.

**Applied to gql-sweep:** GraphQL mutations can race. If mutation A reads authorization state and mutation B modifies it, and there's no synchronization, a TOCTOU vulnerability exists.

Define happens-before (→) for GraphQL operations:
- `op_A → op_B` if A's response was received before B's request was sent
- If `op_A ∥ op_B` (concurrent), check: does the outcome change depending on execution order?

Send `setFormValue(field=email, value="attacker@evil.com")` concurrently with `submitForm()`. If the form submits with the attacker's email instead of the original, that's a race condition.

**Why this matters:** Single-request testing can't find concurrency bugs. Lamport ordering gives us a formal framework for reasoning about what happens when operations overlap.

**Reference:** Lamport, L. (1978). "Time, Clocks, and the Ordering of Events in a Distributed System." *Communications of the ACM.*

---

## 5. Andrey Markov — Steady-State Analysis

**The mind:** Markov (1856–1922), father of stochastic processes. The stationary distribution of a Markov chain tells you the long-run probability of being in each state.

**Applied to gql-sweep:** After building the MDP state transition matrix from exploration, compute the stationary distribution π where `πP = π`. States with high π are "attractors" — the API naturally gravitates toward them.

**Why this matters:** High-probability states are the ones most users (and attackers) will encounter. If a high-probability state has a vulnerability, it's more exploitable than one in a rare edge state. This lets us weight findings by their practical exploitability.

**Reference:** Markov, A. (1906). "Extension of the law of large numbers to dependent quantities."

---

## 6. Thomas Bayes — Vulnerability Network

**The mind:** Bayes (1701–1761). Bayesian inference updates prior beliefs with evidence.

**Applied to gql-sweep:** Model vulnerability dependencies as a Bayesian network:

```
P(data_extraction | introspection_enabled, no_rate_limit, weak_auth)
  = P(extraction | introspection) × P(extraction | no_rate_limit) × ...
```

After each finding, update the posterior probability of compound vulnerabilities. If we find introspection is enabled, the probability that data extraction is possible increases — even before we've tested it directly.

**Why this matters:** Findings don't exist in isolation. A Bayesian network captures "introspection + no rate limiting + weak auth = critical compound risk" as a formal probability, not a vibes-based severity override.

**Reference:** Bayes, T. (1763). "An Essay towards solving a Problem in the Doctrine of Chances." *Philosophical Transactions.*

---

## Architecture: New Crates

```
crates/
├── gql-wald        Wald's SPRT for early stopping
├── gql-shrink      Hughes-style stateful shrinking of attack sequences
├── gql-fisher      Fisher exact test for differential significance
├── gql-lamport     Happens-before race detection for concurrent mutations
├── gql-markov      Steady-state analysis of the API state space
└── gql-bayes       Bayesian vulnerability network
```

Each crate: one mathematician, one proven theorem, one novel application to GraphQL security.
