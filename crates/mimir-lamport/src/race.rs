use serde::{Deserialize, Serialize};

use crate::clock::TimestampedOp;

/// A potential race condition between two operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceCondition {
    /// The operation that reads state.
    pub reader: TimestampedOp,
    /// The operation that writes state.
    pub writer: TimestampedOp,
    /// Type of race.
    pub race_type: RaceType,
    /// Confidence that this is exploitable (0.0-1.0).
    pub confidence: f64,
}

/// Classification of race condition types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaceType {
    /// Time-of-check-time-of-use: read authorization, then write state.
    Toctou,
    /// Write-write: two mutations modifying the same state concurrently.
    WriteWrite,
    /// Read-write: query reads state while mutation modifies it.
    ReadWrite,
}

impl std::fmt::Display for RaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaceType::Toctou => write!(f, "TOCTOU"),
            RaceType::WriteWrite => write!(f, "Write-Write"),
            RaceType::ReadWrite => write!(f, "Read-Write"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_race_type_display() {
        assert_eq!(format!("{}", RaceType::Toctou), "TOCTOU");
        assert_eq!(format!("{}", RaceType::WriteWrite), "Write-Write");
        assert_eq!(format!("{}", RaceType::ReadWrite), "Read-Write");
    }
}
