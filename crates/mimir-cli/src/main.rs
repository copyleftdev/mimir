use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use mimir_dst::{OutputFormat, StrategyKind, SweepConfig, SweepEngine};
use mimir_gen::generator::{GenConfig, generate_mutation_suite, generate_query};
use mimir_graph::analysis::analyze_schema;
use mimir_report::json_report::to_json;
use mimir_report::pretty::to_pretty;
use mimir_report::sarif::to_sarif;
use mimir_schema::parse_introspection_response;
use mimir_transport::GraphqlClient;

/// mimir -- Deterministic GraphQL Security Auditor
#[derive(Parser, Debug)]
#[command(name = "mimir", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run full security sweep against a GraphQL endpoint
    Sweep {
        /// Target GraphQL endpoint URL
        url: String,

        /// Seed for deterministic exploration
        #[arg(long, default_value_t = 0)]
        seed: u64,

        /// Maximum operations to execute
        #[arg(long, default_value_t = 1000)]
        max_ops: usize,

        /// Maximum query depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,

        /// Exploration strategy: ucb1, epsilon-greedy, thompson
        #[arg(long, default_value = "ucb1")]
        strategy: String,

        /// Add authentication header (format: Key:Value, repeatable)
        #[arg(long = "auth-header", value_name = "K:V")]
        auth_headers: Vec<String>,

        /// Request timeout in seconds
        #[arg(long, default_value_t = 10)]
        timeout: u64,

        /// Output format: pretty, json, sarif
        #[arg(long, default_value = "pretty")]
        format: String,

        /// Actually send mutations (CAUTION: modifies server state)
        #[arg(long)]
        execute_mutations: bool,
    },

    /// Fetch and display the schema via introspection
    Introspect {
        /// Target GraphQL endpoint URL
        url: String,

        /// Output format: json or pretty
        #[arg(long, default_value = "pretty")]
        format: String,
    },

    /// Analyze schema structure (graph theory metrics)
    Analyze {
        /// Target GraphQL endpoint URL
        url: String,

        /// Output format: json or pretty
        #[arg(long, default_value = "pretty")]
        format: String,

        /// Top N types by centrality
        #[arg(long, default_value_t = 10)]
        top_k: usize,
    },

    /// Generate test queries/mutations from schema (without executing)
    Generate {
        /// Target GraphQL endpoint URL
        url: String,

        /// Seed for deterministic generation
        #[arg(long, default_value_t = 0)]
        seed: u64,

        /// Maximum query depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Sweep {
            url,
            seed,
            max_ops,
            max_depth,
            strategy,
            auth_headers,
            timeout,
            format,
            execute_mutations,
        } => {
            let strategy_kind = parse_strategy(&strategy)?;
            let output_format = parse_output_format(&format)?;
            let parsed_headers = parse_headers(&auth_headers)?;

            let config = SweepConfig {
                target_url: url,
                seed,
                max_operations: max_ops,
                max_depth,
                strategy: strategy_kind,
                auth_headers: parsed_headers,
                timeout_secs: timeout,
                output_format,
                execute_mutations,
            };

            let mut engine = SweepEngine::new(config);
            let report = engine.run().await.context("sweep failed")?;

            let output = match output_format {
                OutputFormat::Pretty => to_pretty(&report),
                OutputFormat::Json => serde_json::to_string_pretty(&to_json(&report))
                    .context("failed to serialize JSON report")?,
                OutputFormat::Sarif => serde_json::to_string_pretty(&to_sarif(&report))
                    .context("failed to serialize SARIF report")?,
            };

            println!("{output}");
        }

        Commands::Introspect { url, format } => {
            let mut client = GraphqlClient::new(&url).with_timeout(Duration::from_secs(30));

            info!(url = %url, "fetching schema via introspection");
            let json = client.introspect().await.context("introspection failed")?;

            let schema = parse_introspection_response(&json).context("failed to parse schema")?;

            match format.as_str() {
                "json" => {
                    let output = serde_json::to_string_pretty(&schema)
                        .context("failed to serialize schema")?;
                    println!("{output}");
                }
                _ => {
                    println!("Schema Summary");
                    println!("==============");
                    if let Some(ref qt) = schema.query_type {
                        println!("Query type:        {qt}");
                    }
                    if let Some(ref mt) = schema.mutation_type {
                        println!("Mutation type:     {mt}");
                    }
                    if let Some(ref st) = schema.subscription_type {
                        println!("Subscription type: {st}");
                    }
                    println!();
                    println!("Types ({}):", schema.type_names().len());
                    for name in schema.type_names() {
                        if let Some(t) = schema.get_type(name) {
                            println!("  {:<30} {}", name, t.kind);
                        }
                    }
                    println!();
                    println!("Queries ({}):", schema.queries().len());
                    for field in schema.queries() {
                        println!(
                            "  {:<30} -> {}",
                            field.name,
                            field.field_type.display_type()
                        );
                    }
                    println!();
                    println!("Mutations ({}):", schema.mutations().len());
                    for field in schema.mutations() {
                        println!(
                            "  {:<30} -> {}",
                            field.name,
                            field.field_type.display_type()
                        );
                    }
                }
            }
        }

        Commands::Analyze { url, format, top_k } => {
            let mut client = GraphqlClient::new(&url).with_timeout(Duration::from_secs(30));

            info!(url = %url, "fetching schema for analysis");
            let json = client.introspect().await.context("introspection failed")?;

            let schema = parse_introspection_response(&json).context("failed to parse schema")?;

            let analysis = analyze_schema(&schema);

            match format.as_str() {
                "json" => {
                    let output = serde_json::to_string_pretty(&analysis)
                        .context("failed to serialize analysis")?;
                    println!("{output}");
                }
                _ => {
                    println!("Schema Graph Analysis");
                    println!("=====================");
                    println!("Nodes (types):    {}", analysis.node_count);
                    println!("Edges (refs):     {}", analysis.edge_count);
                    println!("Has cycles:       {}", analysis.has_cycles);
                    println!("SCC count:        {}", analysis.scc_count);
                    println!("Largest SCC:      {} types", analysis.largest_scc_size);
                    if !analysis.largest_scc_types.is_empty() {
                        println!("  Types: {}", analysis.largest_scc_types.join(", "));
                    }
                    if let Some(d) = analysis.max_depth_from_query {
                        println!("Max depth (query): {d}");
                    }
                    if let Some(d) = analysis.max_depth_from_mutation {
                        println!("Max depth (mutation): {d}");
                    }
                    println!("Queries:          {}", analysis.query_count);
                    println!("Mutations:        {}", analysis.mutation_count);
                    println!();
                    let limit = top_k.min(analysis.top_central_types.len());
                    println!("Top {limit} types by centrality:");
                    for (name, score) in analysis.top_central_types.iter().take(top_k) {
                        println!("  {name:<30} {score:.4}");
                    }
                }
            }
        }

        Commands::Generate {
            url,
            seed,
            max_depth,
        } => {
            let mut client = GraphqlClient::new(&url).with_timeout(Duration::from_secs(30));

            info!(url = %url, "fetching schema for query generation");
            let json = client.introspect().await.context("introspection failed")?;

            let schema = parse_introspection_response(&json).context("failed to parse schema")?;

            let gen_config = GenConfig {
                max_depth,
                include_args: true,
                include_fragments: false,
                seed,
            };

            println!("# Generated Queries");
            println!("# Seed: {seed}, Max depth: {max_depth}");
            println!();

            for field in schema.queries() {
                let query = generate_query(&schema, field, &gen_config);
                println!("# Query: {}", field.name);
                println!("{query}");
                println!();
            }

            let mutation_suite = generate_mutation_suite(&schema, &gen_config);
            if !mutation_suite.is_empty() {
                println!(
                    "# Generated Mutations ({} test cases)",
                    mutation_suite.len()
                );
                println!();
                for (op_name, query, variables) in &mutation_suite {
                    println!("# Mutation: {op_name}");
                    println!("{query}");
                    if !variables.is_null() && variables.as_object().is_some_and(|m| !m.is_empty())
                    {
                        println!(
                            "# Variables: {}",
                            serde_json::to_string(variables).unwrap_or_default()
                        );
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Parse a strategy string into a StrategyKind.
fn parse_strategy(s: &str) -> Result<StrategyKind> {
    match s.to_lowercase().as_str() {
        "ucb1" => Ok(StrategyKind::Ucb1),
        "thompson" => Ok(StrategyKind::Thompson),
        s if s.starts_with("epsilon-greedy") => {
            // Support "epsilon-greedy" (default eps=0.1) or "epsilon-greedy:0.2"
            if let Some(eps_str) = s.strip_prefix("epsilon-greedy:") {
                let eps: f64 = eps_str
                    .parse()
                    .context("invalid epsilon value for epsilon-greedy strategy")?;
                Ok(StrategyKind::EpsilonGreedy(eps))
            } else {
                Ok(StrategyKind::EpsilonGreedy(0.1))
            }
        }
        other => anyhow::bail!(
            "unknown strategy '{other}'. Valid options: ucb1, epsilon-greedy, thompson"
        ),
    }
}

/// Parse output format string.
fn parse_output_format(s: &str) -> Result<OutputFormat> {
    match s.to_lowercase().as_str() {
        "pretty" => Ok(OutputFormat::Pretty),
        "json" => Ok(OutputFormat::Json),
        "sarif" => Ok(OutputFormat::Sarif),
        other => {
            anyhow::bail!("unknown output format '{other}'. Valid options: pretty, json, sarif")
        }
    }
}

/// Parse "Key:Value" header strings into (key, value) tuples.
fn parse_headers(headers: &[String]) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|h| {
            let (key, value) = h
                .split_once(':')
                .context(format!("invalid header format '{h}', expected 'Key:Value'"))?;
            Ok((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}
