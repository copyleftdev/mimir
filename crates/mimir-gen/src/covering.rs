use mimir_schema::types::{Field, Schema, TypeKind};
use serde_json::Value;

use crate::values::generate_scalar_values;

/// A factor in the covering array (one parameter).
#[derive(Debug, Clone)]
pub struct Factor {
    pub name: String,
    pub levels: Vec<Value>,
}

/// A test case: one value per factor.
pub type TestCase = Vec<(String, Value)>;

/// Generate a 2-way covering array (pairwise coverage).
///
/// Guarantees every pair of factor values appears in at least one test case.
/// Uses a greedy algorithm: for each uncovered pair, find or create a test case
/// that covers it.
pub fn pairwise_covering_array(factors: &[Factor]) -> Vec<TestCase> {
    if factors.is_empty() {
        return vec![];
    }

    if factors.len() == 1 {
        // Single factor: one test case per level.
        return factors[0]
            .levels
            .iter()
            .map(|v| vec![(factors[0].name.clone(), v.clone())])
            .collect();
    }

    // Collect all uncovered pairs: (factor_i, level_i, factor_j, level_j).
    let mut uncovered: Vec<(usize, usize, usize, usize)> = Vec::new();
    for i in 0..factors.len() {
        for j in (i + 1)..factors.len() {
            for li in 0..factors[i].levels.len() {
                for lj in 0..factors[j].levels.len() {
                    uncovered.push((i, li, j, lj));
                }
            }
        }
    }

    let mut test_cases: Vec<Vec<Option<usize>>> = Vec::new();

    while !uncovered.is_empty() {
        // Create a new test case with all slots unset.
        let mut test_case: Vec<Option<usize>> = vec![None; factors.len()];

        // Greedily fill the test case to cover as many uncovered pairs as possible.
        // First, pick the uncovered pair that constrains the most.
        let &(fi, li, fj, lj) = &uncovered[0];
        test_case[fi] = Some(li);
        test_case[fj] = Some(lj);

        // For each remaining unset factor, pick the level that covers the most
        // additional uncovered pairs.
        for f in 0..factors.len() {
            if test_case[f].is_some() {
                continue;
            }

            let mut best_level = 0;
            let mut best_count = 0;

            for l in 0..factors[f].levels.len() {
                // Count how many uncovered pairs would be covered if we set
                // factor f to level l.
                let count = uncovered
                    .iter()
                    .filter(|&&(fi2, li2, fj2, lj2)| {
                        (fi2 == f && li2 == l && test_case[fj2].is_none_or(|v| v == lj2))
                            || (fj2 == f && lj2 == l && test_case[fi2].is_none_or(|v| v == li2))
                    })
                    .count();

                if count > best_count {
                    best_count = count;
                    best_level = l;
                }
            }

            test_case[f] = Some(best_level);
        }

        // Remove all pairs that are now covered by this test case.
        uncovered.retain(|&(fi2, li2, fj2, lj2)| {
            !(test_case[fi2] == Some(li2) && test_case[fj2] == Some(lj2))
        });

        test_cases.push(test_case);
    }

    // Convert from index-based to named test cases.
    test_cases
        .into_iter()
        .map(|tc| {
            tc.into_iter()
                .enumerate()
                .map(|(i, level_idx)| {
                    let idx = level_idx.unwrap_or(0);
                    let value = factors[i].levels[idx].clone();
                    (factors[i].name.clone(), value)
                })
                .collect()
        })
        .collect()
}

/// Generate factors from a mutation's arguments.
///
/// Each argument becomes a factor. The levels are generated from the argument's
/// type using `generate_scalar_values` for scalars, enum values for enums, and
/// a fallback for input objects.
pub fn mutation_to_factors(schema: &Schema, mutation: &Field) -> Vec<Factor> {
    mutation
        .args
        .iter()
        .map(|arg| {
            let inner_name = arg.input_type.inner_name().unwrap_or("String");
            let levels = resolve_levels(schema, inner_name);
            Factor {
                name: arg.name.clone(),
                levels,
            }
        })
        .collect()
}

/// Resolve the set of test levels for a given type name.
fn resolve_levels(schema: &Schema, type_name: &str) -> Vec<Value> {
    if let Some(full_type) = schema.get_type(type_name) {
        match full_type.kind {
            TypeKind::Enum => {
                let mut levels: Vec<Value> = full_type
                    .enum_values
                    .iter()
                    .map(|ev| Value::String(ev.name.clone()))
                    .collect();
                levels.insert(0, Value::Null);
                levels
            }
            TypeKind::InputObject => {
                // For input objects, generate a few representative instances.
                let mut levels = Vec::new();
                levels.push(Value::Null);
                for seed in 0..3 {
                    levels.push(crate::values::generate_input_object(
                        schema, type_name, seed,
                    ));
                }
                levels
            }
            _ => generate_scalar_values(type_name),
        }
    } else {
        generate_scalar_values(type_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimir_schema::types::*;
    use indexmap::IndexMap;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn empty_factors_produce_empty_array() {
        let result = pairwise_covering_array(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn single_factor_produces_one_case_per_level() {
        let factors = vec![Factor {
            name: "x".to_string(),
            levels: vec![json!(1), json!(2), json!(3)],
        }];
        let result = pairwise_covering_array(&factors);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn two_factors_cover_all_pairs() {
        let factors = vec![
            Factor {
                name: "a".to_string(),
                levels: vec![json!(1), json!(2)],
            },
            Factor {
                name: "b".to_string(),
                levels: vec![json!("x"), json!("y")],
            },
        ];

        let result = pairwise_covering_array(&factors);

        // Collect all (a, b) pairs present in the result.
        let mut covered_pairs: HashSet<(String, String)> = HashSet::new();
        for tc in &result {
            let a_val = tc.iter().find(|(n, _)| n == "a").unwrap().1.to_string();
            let b_val = tc.iter().find(|(n, _)| n == "b").unwrap().1.to_string();
            covered_pairs.insert((a_val, b_val));
        }

        // There should be 2 * 2 = 4 pairs.
        assert_eq!(
            covered_pairs.len(),
            4,
            "Expected all 4 pairs, got {:?}",
            covered_pairs
        );
    }

    #[test]
    fn three_factors_pairwise_coverage() {
        let factors = vec![
            Factor {
                name: "a".to_string(),
                levels: vec![json!(1), json!(2)],
            },
            Factor {
                name: "b".to_string(),
                levels: vec![json!("x"), json!("y")],
            },
            Factor {
                name: "c".to_string(),
                levels: vec![json!(true), json!(false)],
            },
        ];

        let result = pairwise_covering_array(&factors);

        // Check all pairs between (a,b), (a,c), (b,c) are covered.
        let names = ["a", "b", "c"];
        for i in 0..3 {
            for j in (i + 1)..3 {
                let mut pairs: HashSet<(String, String)> = HashSet::new();
                for tc in &result {
                    let vi = tc
                        .iter()
                        .find(|(n, _)| n == names[i])
                        .unwrap()
                        .1
                        .to_string();
                    let vj = tc
                        .iter()
                        .find(|(n, _)| n == names[j])
                        .unwrap()
                        .1
                        .to_string();
                    pairs.insert((vi, vj));
                }
                let expected = factors[i].levels.len() * factors[j].levels.len();
                assert_eq!(
                    pairs.len(),
                    expected,
                    "Missing pairwise coverage for ({}, {}): got {} of {}",
                    names[i],
                    names[j],
                    pairs.len(),
                    expected
                );
            }
        }
    }

    #[test]
    fn mutation_to_factors_basic() {
        let mut types = IndexMap::new();
        for name in &["String", "Int"] {
            types.insert(
                name.to_string(),
                FullType {
                    name: name.to_string(),
                    kind: TypeKind::Scalar,
                    description: None,
                    fields: vec![],
                    input_fields: vec![],
                    interfaces: vec![],
                    enum_values: vec![],
                    possible_types: vec![],
                },
            );
        }

        let schema = Schema {
            query_type: None,
            mutation_type: None,
            subscription_type: None,
            types,
            directives: vec![],
        };

        let mutation = Field {
            name: "createUser".to_string(),
            description: None,
            args: vec![
                InputValue {
                    name: "name".to_string(),
                    description: None,
                    input_type: TypeRef {
                        name: Some("String".to_string()),
                        kind: TypeKind::Scalar,
                        of_type: None,
                    },
                    default_value: None,
                },
                InputValue {
                    name: "age".to_string(),
                    description: None,
                    input_type: TypeRef {
                        name: Some("Int".to_string()),
                        kind: TypeKind::Scalar,
                        of_type: None,
                    },
                    default_value: None,
                },
            ],
            field_type: TypeRef {
                name: Some("String".to_string()),
                kind: TypeKind::Scalar,
                of_type: None,
            },
            is_deprecated: false,
        };

        let factors = mutation_to_factors(&schema, &mutation);
        assert_eq!(factors.len(), 2);
        assert_eq!(factors[0].name, "name");
        assert_eq!(factors[1].name, "age");
        assert!(!factors[0].levels.is_empty());
        assert!(!factors[1].levels.is_empty());
    }
}
