//! Deterministic 1-in-N sampling.

/// Keeps every `every`-th event it is offered (the 1st, the N+1th, ...).
///
/// Deterministic on purpose: the same input stream always yields the same
/// sample, which keeps tests and investigations reproducible. It is not a
/// statistically unbiased sampler for periodic workloads.
#[derive(Debug, Clone)]
pub struct Sampler {
    every: u64,
    seen: u64,
}

impl Sampler {
    /// Creates a sampler. `every` of 0 or 1 keeps everything.
    pub fn new(every: u64) -> Self {
        Self {
            every: every.max(1),
            seen: 0,
        }
    }

    /// Returns true if the next event should be kept.
    pub fn admit(&mut self) -> bool {
        let keep = self.seen.is_multiple_of(self.every);
        self.seen = self.seen.wrapping_add(1);
        keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_one_in_n() {
        let mut s = Sampler::new(4);
        let kept: Vec<bool> = (0..9).map(|_| s.admit()).collect();
        assert_eq!(
            kept,
            [true, false, false, false, true, false, false, false, true]
        );
    }

    #[test]
    fn zero_and_one_keep_all() {
        for n in [0, 1] {
            let mut s = Sampler::new(n);
            assert!((0..10).all(|_| s.admit()));
        }
    }
}
