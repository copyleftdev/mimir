<p align="center">
  <h1 align="center">mimir</h1>
  <p align="center"><strong>Deterministic GraphQL security auditor built on proven mathematics.</strong></p>
</p>

<p align="center">
  <code>16 crates</code> &nbsp;&middot;&nbsp;
  <code>299 tests</code> &nbsp;&middot;&nbsp;
  <code>~13,000 lines of Rust</code> &nbsp;&middot;&nbsp;
  <code>5.7MB binary</code> &nbsp;&middot;&nbsp;
  <code>MIT</code>
</p>

---

In Norse mythology, **Mimir** guards the Well of Wisdom beneath the world tree Yggdrasil. Odin tore out his own eye and dropped it into the well to gain knowledge of all things. **mimir** drinks from your GraphQL schema and tells you what it finds.

```bash
mimir sweep https://api.example.com/graphql
```

---

## Why mimir Exists

Every GraphQL security tool on the market is a bag of heuristics -- a checklist of known misconfigurations run in sequence. They find what they already know to look for and nothing else. They are not composable, not reproducible, and not mathematically grounded.

**mimir is different.** It models your GraphQL API as a formal system -- a typed directed graph with state transitions -- and uses proven mathematical techniques to explore its state space systematically.

Where existing tools run checklists, mimir brings:

| Technique | What It Does |
|-----------|-------------|
| **MDP exploration** | Strategically chosen operation sequences, not random fuzzing |
| **Shannon entropy** | Quantified information leakage measurement |
| **Graph centrality** | Risk-ranked types by structural importance |
| **Covering arrays** | Mathematical coverage guarantees with polynomial test cases |
| **SPRT early stopping** | Stops when evidence is sufficient, not after N checks |
| **Fisher exact test** | Statistical significance for auth boundary differences |
| **Lamport ordering** | Formal race condition detection in concurrent mutations |
| **Markov steady-state** | Findings weighted by practical exploitability |
| **Bayesian network** | Compound vulnerability reasoning across findings |
| **Hughes shrinking** | Minimal reproduction sequences, not 200-operation traces |

The result: a single static binary that finds things no checklist can, proves what it finds with statistics, and reproduces every finding deterministically from a seed.

---

## Quick Start

```bash
# Install from release
curl -sSL https://github.com/copyleftdev/mimir/releases/latest/download/mimir-$(uname -s)-$(uname -m) -o mimir
chmod +x mimir

# Or build from source
cargo install --path crates/mimir-cli

# Full security sweep
mimir sweep https://api.example.com/graphql

# Fetch and inspect schema
mimir introspect https://api.example.com/graphql

# Graph theory analysis
mimir analyze https://api.example.com/graphql

# Generate test queries without executing
mimir generate https://api.example.com/graphql
```

---

## Commands

### `sweep` -- Full Security Sweep

Runs the complete exploration loop: introspect, analyze, generate, execute, and evaluate.

```bash
mimir sweep https://api.example.com/graphql \
  --seed 42 \
  --max-ops 500 \
  --max-depth 4 \
  --strategy ucb1 \
  --auth-header "Authorization:Bearer eyJhbG..." \
  --timeout 10 \
  --format pretty
```

| Flag | Default | Description |
|------|---------|-------------|
| `--seed` | `0` | Seed for deterministic exploration. Same seed = same results. |
| `--max-ops` | `1000` | Maximum operations to execute before stopping. |
| `--max-depth` | `3` | Maximum query nesting depth. |
| `--strategy` | `ucb1` | Exploration strategy: `ucb1`, `epsilon-greedy`, `thompson`. |
| `--auth-header` | -- | Auth header as `Key:Value`. Repeatable for multiple headers. |
| `--timeout` | `10` | Per-request timeout in seconds. |
| `--format` | `pretty` | Output format: `pretty`, `json`, `sarif`. |
| `--execute-mutations` | `false` | Actually send mutations. **CAUTION: modifies server state.** |

### `introspect` -- Schema Introspection

Fetches the schema via the standard introspection query and displays it.

```bash
mimir introspect https://api.example.com/graphql
mimir introspect https://api.example.com/graphql --format json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `pretty` | Output format: `pretty` or `json`. |

### `analyze` -- Graph Theory Analysis

Computes structural metrics on the schema's type graph: centrality, strongly connected components, cycles, reachability depth.

```bash
mimir analyze https://api.example.com/graphql --top-k 15
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `pretty` | Output format: `pretty` or `json`. |
| `--top-k` | `10` | Number of top types to display by centrality score. |

### `generate` -- Test Query Generation

Generates queries and mutations from the schema without executing them. Useful for review, export to other tools, or dry-run inspection.

```bash
mimir generate https://api.example.com/graphql --seed 42 --max-depth 4
```

| Flag | Default | Description |
|------|---------|-------------|
| `--seed` | `0` | Seed for deterministic generation. |
| `--max-depth` | `3` | Maximum query nesting depth. |

---

## The Mathematics

This is the core of mimir. Ten mathematical frameworks, each solving a specific problem that heuristics cannot.

| # | Mathematician | Framework | Replaces | Enables |
|---|--------------|-----------|----------|---------|
| 1 | **Claude Shannon** (1948) | Information entropy | "The error message looks detailed" | Quantified information leakage: `H(X) = -Sum p(x) log2 p(x)`. High-entropy error messages are measured, not guessed. |
| 2 | **Richard Bellman** | Markov Decision Processes | Random fuzzing | Strategic exploration via UCB1/Thompson sampling. Operations chosen to maximize discovery of new states. |
| 3 | **Leonhard Euler** | Graph theory | Manual schema review | Betweenness centrality, SCCs, cycle detection, minimum vertex cuts. The schema *is* the attack surface. |
| 4 | **D. Richard Kuhn** | Covering arrays | "Test all the things" | t-way combinatorial coverage. 2-way arrays catch ~70% of bugs with ~100 test cases instead of 100,000. |
| 5 | **Abraham Wald** (1945) | Sequential Probability Ratio Test | "Run N checks, then stop" | Evidence-based early stopping. Halts the moment statistical confidence is reached -- faster for vulnerable targets, more thorough for secure ones. |
| 6 | **Ronald Fisher** (1922) | Fisher exact test | "These responses look different" | Statistical significance for auth boundaries. Reports p-values, not vibes. p=0.003 means 0.3% chance of coincidence. |
| 7 | **John Hughes** (2000) | Stateful shrinking | 200-operation bug reports | Minimal reproduction: a 47-operation trace shrinks to the 3 operations that matter. Actionable, not overwhelming. |
| 8 | **Leslie Lamport** (1978) | Happens-before ordering | "We don't test concurrency" | Formal race detection. Concurrent mutations tested for TOCTOU violations using causal ordering. |
| 9 | **Andrey Markov** (1906) | Steady-state distribution | Equal-weight findings | Findings weighted by exploitability. High-probability states (where users and attackers actually land) are prioritized. |
| 10 | **Thomas Bayes** (1763) | Bayesian network | Severity = vibes | Compound vulnerability reasoning. "Introspection enabled + no rate limiting + weak auth" has a computed probability, not a gut-feel severity. |

---

## Architecture

### Crate Map

```
mimir/
  crates/
    mimir-schema       Schema parser, type graph, introspection client
    mimir-graph        Graph theory (centrality, SCC, paths, cuts)
    mimir-gen          Query/mutation generator (grammar-aware, covering arrays)
    mimir-mdp          MDP state machine, exploration strategies (UCB1, Thompson)
    mimir-entropy      Information theory (Shannon entropy, NCD, differential)
    mimir-oracle       Security invariant checker (LTL properties)
    mimir-dst          Deterministic simulation engine (seed-driven, reproducible)
    mimir-transport    HTTP client, request/response capture, replay
    mimir-report       SARIF / JSON / pretty output, finding deduplication
    mimir-cli          CLI interface (the `mimir` binary)
    mimir-wald         Wald's SPRT for early stopping
    mimir-shrink       Hughes-style stateful shrinking of attack sequences
    mimir-fisher       Fisher exact test for differential significance
    mimir-lamport      Happens-before race detection for concurrent mutations
    mimir-markov       Steady-state analysis of the API state space
    mimir-bayes        Bayesian vulnerability network
```

### Dependency Graph

```
mimir-schema ─────┬──> mimir-graph
                  |
                  ├──> mimir-gen ──> mimir-mdp
                  |                    |
                  |                    v
mimir-transport ──┴──> mimir-dst ──> mimir-oracle
                                       |
mimir-entropy ─────────────────────────┘
                                       |
                    mimir-wald ─────────┤
                    mimir-fisher ───────┤
                    mimir-lamport ──────┤
                    mimir-markov ───────┤
                    mimir-bayes ────────┤
                    mimir-shrink ───────┘
                                       |
                                       v
                                  mimir-report
                                       |
                                       v
                                   mimir-cli
```

### Key Design Decisions

1. **Schema-first.** Everything starts from the introspected schema. The type graph is the foundation for all analysis.
2. **Deterministic by default.** Every run is reproducible by seed. The DST engine controls all randomness through a single PRNG.
3. **Separation of concerns.** Generation, execution, and evaluation are independent. Generate test cases without executing them. Evaluate recorded traffic without generating new queries.
4. **Property-driven.** Security properties are declared in LTL, not hardcoded. Custom properties for your specific API.
5. **Single binary.** One static binary. No Python, no runtime, no dependencies.

---

## Output Formats

### Pretty (default)

ANSI-colored terminal output. Human-readable, designed for interactive use.

```bash
mimir sweep https://api.example.com/graphql --format pretty
```

### JSON

Machine-readable structured output for scripting and integration.

```bash
mimir sweep https://api.example.com/graphql --format json
```

### SARIF v2.1.0

Static Analysis Results Interchange Format. Integrates directly with GitHub Code Scanning, Azure DevOps, and any SARIF-compatible viewer.

```bash
mimir sweep https://api.example.com/graphql --format sarif > results.sarif
```

---

## Example Output

```
  mimir sweep v0.1.0
  Target: https://api.example.com/graphql
  Seed: 42 | Strategy: UCB1 | Max ops: 1000 | Max depth: 3

  Schema
  ======
  Types:        87
  Queries:      24
  Mutations:    18

  Graph Analysis
  ==============
  Nodes: 87 | Edges: 214 | Cycles: yes
  SCC count: 3 | Largest SCC: 12 types
  Top centrality: User (0.3842), Account (0.2917), Organization (0.2103)

  Exploration
  ===========
  Operations executed: 347 / 1000 (SPRT early stop)
  States discovered:   23
  Unique responses:    41

  Findings (2)
  ============

  [MEDIUM] Information Leakage via Error Messages
    Location:   mutation { updateUser(id: "...", input: {...}) }
    Evidence:   Error response entropy H=4.72 bits (threshold: 3.0)
                Response contains: type name, field name, internal ID format
    Confidence: p=0.0041 (Fisher exact test)
    Reproduce:  mimir sweep https://api.example.com/graphql --seed 42

  [LOW] Introspection Enabled in Production
    Location:   __schema query
    Evidence:   Full schema returned (87 types, 42 operations)
    Confidence: deterministic (always reproducible)

  Summary
  =======
  2 findings | 0 high | 1 medium | 1 low | 0 info
  Scan completed in 12.4s
```

---

## Building from Source

```bash
git clone https://github.com/copyleftdev/mimir
cd mimir
cargo test
cargo build --release

# Binary is at target/release/mimir (~5.7MB stripped)
strip target/release/mimir
```

Requires Rust 2024 edition (1.85+).

---

## CI Integration

```yaml
# GitHub Actions example
- name: Run mimir
  run: |
    mimir sweep ${{ secrets.GRAPHQL_ENDPOINT }} \
      --auth-header "Authorization:Bearer ${{ secrets.API_TOKEN }}" \
      --format sarif \
      > mimir-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mimir-results.sarif
```

---

## License

MIT

---

## The Name

In Norse mythology, Mimir guards the Well of Wisdom beneath the world tree Yggdrasil. Odin sacrificed his eye to drink from it and gain knowledge of all things. **mimir** drinks from your GraphQL schema and tells you what it finds.
