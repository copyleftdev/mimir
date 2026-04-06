# gql-sweep

**Deterministic GraphQL security auditor built on mathematical foundations.**

> Every other GraphQL security tool is a bag of heuristics. This one is a state machine explorer with proofs.

---

## The Problem

Existing GraphQL security tools (graphql-cop, InQL, CrackQL, BatchQL) work by running a checklist of known misconfigurations. They're useful but fundamentally limited:

1. **They check for what's known, not what's possible.** A checklist can't find novel authorization bypasses or unexpected state transitions.
2. **They're not composable.** Running batched mutations after a specific sequence of queries might expose a vulnerability that no single check would find.
3. **They're not reproducible.** Run the same tool twice, get different results (network timing, race conditions, server state).
4. **They're Python.** Slow startup, GIL-limited parallelism, heavy containers.

## The Approach

Model the GraphQL API as a **formal system** and use mathematical techniques to explore its state space systematically.

### Core Insight

A GraphQL schema defines a **typed directed graph**. Mutations are **state transitions**. Authorization is a **policy overlay** on that graph. Security vulnerabilities are **reachable states that violate invariants**.

This maps directly to well-studied mathematical frameworks:

---

## Mathematical Foundations

### 1. Graph Theory — Schema as Attack Surface

The GraphQL schema is a typed graph: nodes are types, edges are fields/relationships. Standard graph algorithms reveal structural properties that correlate with security exposure.

**Applied techniques:**
- **Betweenness centrality** — Types that sit on many shortest paths between other types are high-value targets. A `User` type that connects `Order`, `Payment`, and `Address` is more security-critical than a leaf type.
- **Strongly connected components** — Type clusters where every type is reachable from every other type via field traversal. These clusters represent zones of mutual accessibility — if you compromise access to one type, you potentially access all of them.
- **All-pairs shortest paths (Floyd-Warshall / Dijkstra)** — Enumerate every path from an entry point (query/mutation root) to a sensitive type. This is what graphql-path-enum does, but we compute it as a matrix, not a list.
- **Cycle detection** — Cycles in the type graph enable recursive queries (DoS via depth). Identifying and measuring cycles informs complexity limits.
- **Minimum vertex cut** — The smallest set of fields that, if authorization-gated, would disconnect public types from sensitive types. This tells you where authorization *should* be, regardless of where it *is*.

### 2. Markov Decision Processes — Mutation Discovery as Exploration

Model the API as an MDP:
- **States** = observable API state (response shapes, error messages, cookies/tokens received)
- **Actions** = GraphQL operations (queries, mutations, subscriptions)
- **Transitions** = how the API state changes after an operation
- **Rewards** = security-relevant observations (new error type, auth bypass, data leak, status code change)

Then use **exploration strategies** from reinforcement learning to efficiently discover interesting states:

- **Epsilon-greedy** — Mostly exploit known interesting paths, occasionally try random mutations
- **Upper Confidence Bound (UCB1)** — Balance exploration vs exploitation mathematically: `score = mean_reward + c * sqrt(ln(total_tries) / tries_for_this_action)`
- **Thompson sampling** — Bayesian approach: maintain a probability distribution over each mutation's "interestingness" and sample from it

This is fundamentally different from fuzzing. Fuzzing generates random inputs. MDP exploration generates **strategically chosen sequences** that maximize the probability of discovering new states.

### 3. Information Theory — Measuring Leakage

**Shannon entropy** of API responses measures information content:

```
H(X) = -Σ p(x) log₂ p(x)
```

Applied to GraphQL security:
- **Error message entropy** — High entropy error messages leak more information. Compare: "Not authorized" (low entropy, safe) vs "User 12345 does not have permission to access field 'ssn' on type 'Patient' in organization 'AcmeCorp'" (high entropy, leaking IDs, field names, type names, org names).
- **Differential response analysis** — Send the same query with and without auth. Measure the mutual information `I(Auth; Response)`. If `I > 0` for fields that should be invisible to unauthorized users, there's an information leak.
- **Response fingerprinting** — Cluster responses by their entropy profile. Outliers indicate unexpected behavior.

### 4. Combinatorial Testing — Covering Arrays for Parameter Space

Instead of testing every possible mutation×input×auth combination (exponential), use **t-way covering arrays** to achieve mathematical guarantees with polynomial test cases.

A **2-way covering array** guarantees that every pair of parameter values appears in at least one test case. Research (NIST, Kuhn et al.) shows that 2-way coverage catches ~70% of bugs, 3-way catches ~95%.

For GraphQL: generate a covering array over:
- Mutation name
- Input field values (null, empty, valid, boundary, type-confused)
- Authentication state (none, expired, valid, admin)
- Query depth
- Batch size

A 2-way array over 5 factors with ~10 levels each requires only ~100 test cases instead of 100,000 — with mathematical guarantees on pairwise coverage.

### 5. Temporal Logic — Security Invariants as Formal Properties

Express security properties in **Linear Temporal Logic (LTL)**:

- **Safety**: `G(¬authenticated → ¬mutation_success)` — "Globally, if not authenticated, then no mutation succeeds"
- **Information flow**: `G(¬authorized(field) → response_unchanged(field))` — "If not authorized for a field, the response is identical whether the field exists or not"
- **IDOR**: `G(user_A_token → ¬access(user_B_data))` — "User A's token never accesses User B's data"
- **Rate limiting**: `G(requests_in_window > N → throttled)` — "If requests exceed N in a window, throttling occurs"

The DST engine evaluates these properties at every step of the exploration, flagging violations immediately with the exact seed and action sequence for reproduction.

### 6. Kolmogorov Complexity — Anomaly Detection

The **normalized compression distance (NCD)** between two API responses measures their similarity:

```
NCD(x, y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
```

Where `C(x)` is the compressed size of `x`. Responses that are structurally similar compress well together (low NCD). A response that suddenly has high NCD compared to its peers is anomalous — potentially a different code path triggered, an error leak, or an authorization boundary crossed.

---

## Architecture

```
gql-sweep/
├── crates/
│   ├── gql-schema       Schema parser, type graph, introspection client
│   ├── gql-graph         Graph theory analysis (centrality, SCC, paths, cuts)
│   ├── gql-gen           Query/mutation generator (grammar-aware, covering arrays)
│   ├── gql-mdp           MDP state machine, exploration strategies (UCB1, Thompson)
│   ├── gql-entropy       Information theory (Shannon entropy, NCD, differential)
│   ├── gql-oracle        Security invariant checker (LTL properties)
│   ├── gql-dst           Deterministic simulation engine (seed-driven, reproducible)
│   ├── gql-transport     HTTP client, request/response capture, replay
│   ├── gql-report        SARIF/JSON/HTML output, finding deduplication
│   └── gql-cli           CLI interface
├── properties/            LTL security property definitions
├── covering-arrays/       Pre-computed covering arrays for common parameter sets
└── rfcs/                  Design documents
```

### Crate Dependency Graph

```
gql-schema ─────┬──→ gql-graph
                │
                ├──→ gql-gen ──→ gql-mdp
                │                  │
                │                  ▼
gql-transport ──┴──→ gql-dst ──→ gql-oracle
                                   │
gql-entropy ───────────────────────┘
                                   │
                                   ▼
                              gql-report
                                   │
                                   ▼
                               gql-cli
```

### Key Design Decisions

1. **Schema-first.** Everything starts from the introspected (or reconstructed) schema. The type graph is the foundation for all analysis.

2. **Deterministic by default.** Every exploration run is reproducible by seed. The DST engine controls all randomness through a single PRNG.

3. **Separation of concerns.** Generation (gql-gen), execution (gql-transport), and evaluation (gql-oracle) are completely separate. You can generate test cases without executing them, or evaluate recorded traffic without generating new queries.

4. **Property-driven.** Security properties are declared, not hardcoded. Users can write custom LTL properties for their specific API.

5. **Single binary.** The CLI compiles to one static binary. No Python, no runtime, no dependencies.

---

## Exploration Loop

```
1. INTROSPECT schema → build type graph
2. ANALYZE graph → compute centrality, SCC, paths, cuts
3. GENERATE initial covering array for mutations × inputs × auth
4. INITIALIZE MDP state = (schema, no auth, empty session)
5. LOOP (seed-driven):
   a. SELECT action via exploration strategy (UCB1/Thompson)
   b. GENERATE query/mutation from grammar + covering array
   c. EXECUTE via transport layer
   d. OBSERVE response → update MDP state
   e. MEASURE entropy, NCD vs baseline
   f. CHECK LTL properties against current state
   g. UPDATE exploration strategy rewards
   h. IF violation found → RECORD finding with full replay trace
   i. IF new state discovered → EXPAND exploration frontier
6. REPORT findings with severity, evidence, reproduction seed
```

---

## What This Enables That Nothing Else Can

| Capability | Existing Tools | gql-sweep |
|-----------|---------------|-----------|
| Detect known misconfigs | Checklist (graphql-cop) | Covering array + property checks |
| Find auth bypasses | Manual testing | MDP exploration discovers mutation sequences |
| Measure information leakage | None | Shannon entropy + differential analysis |
| Find multi-step attack paths | None | State machine tracks cumulative effects |
| Prioritize fields by risk | None | Betweenness centrality ranks types |
| Guarantee coverage | None | t-way covering arrays with mathematical proofs |
| Reproduce any finding | Rarely | Every finding has a seed + action sequence |
| Detect anomalous responses | None | NCD-based outlier detection |

---

## Prior Art and References

- Kuhn, D.R., Wallace, D.R., Gallo, A.M. (2004). "Software Fault Interactions and Implications for Software Testing." *IEEE Transactions on Software Engineering.* — Covering array theory.
- Sutton, R.S., Barto, A.G. (2018). *Reinforcement Learning: An Introduction.* — MDP, UCB1, Thompson sampling.
- Shannon, C.E. (1948). "A Mathematical Theory of Communication." — Information entropy.
- Cilibrasi, R., Vitányi, P.M.B. (2005). "Clustering by Compression." — Normalized compression distance.
- Pnueli, A. (1977). "The Temporal Logic of Programs." — LTL for property specification.
- TigerBeetle (2023). "Deterministic Simulation Testing." — Seed-driven reproducibility.
- Greef, J.D. (2023). "Testing Distributed Systems with Deterministic Simulation." — DST methodology.

---

## Name

**gql-sweep**: Systematic sweep of the GraphQL attack surface. Clean, searchable, describes exactly what it does.
