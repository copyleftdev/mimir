use serde::{Deserialize, Serialize};

/// A Lamport timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LamportTimestamp(pub u64);

/// A logical clock that tracks causal ordering.
#[derive(Debug, Clone)]
pub struct LamportClock {
    current: u64,
}

impl Default for LamportClock {
    fn default() -> Self {
        Self::new()
    }
}

impl LamportClock {
    pub fn new() -> Self {
        Self { current: 0 }
    }

    /// Increment and return the new timestamp (local event).
    pub fn tick(&mut self) -> LamportTimestamp {
        self.current += 1;
        LamportTimestamp(self.current)
    }

    /// Update from a received timestamp and tick (receive event).
    /// Takes max(local, remote) + 1.
    pub fn receive(&mut self, other: LamportTimestamp) -> LamportTimestamp {
        self.current = self.current.max(other.0) + 1;
        LamportTimestamp(self.current)
    }

    /// Current timestamp without incrementing.
    pub fn now(&self) -> LamportTimestamp {
        LamportTimestamp(self.current)
    }
}

/// A timestamped operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedOp {
    pub timestamp: LamportTimestamp,
    pub wall_time: chrono::DateTime<chrono::Utc>,
    pub operation_name: String,
    pub query: String,
    pub variables: serde_json::Value,
    pub response_status: u16,
    pub is_mutation: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tick_monotonically_increasing() {
        let mut clock = LamportClock::new();
        let t1 = clock.tick();
        let t2 = clock.tick();
        let t3 = clock.tick();

        assert!(t1 < t2);
        assert!(t2 < t3);
        assert_eq!(t1.0, 1);
        assert_eq!(t2.0, 2);
        assert_eq!(t3.0, 3);
    }

    #[test]
    fn test_receive_takes_max_plus_one() {
        let mut clock = LamportClock::new();
        clock.tick(); // current = 1
        clock.tick(); // current = 2

        // Receive a timestamp from a more advanced clock
        let remote = LamportTimestamp(10);
        let result = clock.receive(remote);

        // Should be max(2, 10) + 1 = 11
        assert_eq!(result.0, 11);
        assert_eq!(clock.now().0, 11);
    }

    #[test]
    fn test_receive_local_ahead() {
        let mut clock = LamportClock::new();
        // Advance local clock far ahead
        for _ in 0..20 {
            clock.tick();
        }

        // Receive a smaller remote timestamp
        let remote = LamportTimestamp(5);
        let result = clock.receive(remote);

        // Should be max(20, 5) + 1 = 21
        assert_eq!(result.0, 21);
    }

    #[test]
    fn test_now_does_not_increment() {
        let mut clock = LamportClock::new();
        clock.tick();
        let ts = clock.now();
        assert_eq!(ts.0, 1);
        // Calling now again should give the same value
        let ts2 = clock.now();
        assert_eq!(ts, ts2);
    }

    #[test]
    fn test_initial_timestamp() {
        let clock = LamportClock::new();
        assert_eq!(clock.now().0, 0);
    }

    #[test]
    fn test_timestamp_ordering_is_total() {
        let a = LamportTimestamp(1);
        let b = LamportTimestamp(2);
        let c = LamportTimestamp(2);

        assert!(a < b);
        assert!(b > a);
        assert_eq!(b, c);
        assert!(a <= b);
        assert!(b >= a);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_tick_always_increases(n in 1usize..100) {
            let mut clock = LamportClock::new();
            let mut prev = LamportTimestamp(0);

            for _ in 0..n {
                let ts = clock.tick();
                prop_assert!(ts > prev);
                prev = ts;
            }
        }

        #[test]
        fn prop_receive_always_advances(local_ticks in 0usize..50, remote in 0u64..1000) {
            let mut clock = LamportClock::new();
            for _ in 0..local_ticks {
                clock.tick();
            }

            let before = clock.now();
            let after = clock.receive(LamportTimestamp(remote));
            prop_assert!(after > before);
        }

        #[test]
        fn prop_timestamp_total_order(a in 0u64..1000, b in 0u64..1000) {
            let ta = LamportTimestamp(a);
            let tb = LamportTimestamp(b);

            // Total order: exactly one of <, =, > must hold
            let lt = ta < tb;
            let eq = ta == tb;
            let gt = ta > tb;
            prop_assert_eq!(lt as u8 + eq as u8 + gt as u8, 1);
        }
    }
}
