use std::sync::Arc;

use atuin_client::history::{CommandCapture, HistoryId};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::Serialize;

use super::corpus::{Corpus, Kind};

pub const BURST_COMMANDS: u32 = 5;
const DAY_MILLIS: u64 = 86_400_000;
const EPOCH_MILLIS: u64 = 1_735_689_600_000;

#[derive(Clone, Serialize)]
pub struct Workload {
    pub seed: u64,
    pub commands_per_day: u32,
    #[serde(skip)]
    corpus: Arc<Corpus>,
}

pub struct Record {
    pub id: HistoryId,
    pub capture: CommandCapture,
    pub kind: Kind,
    pub sample: usize,
    pub output: usize,
}

impl Record {
    #[must_use]
    pub fn output_bytes(&self) -> u64 {
        u64::try_from(
            self.capture.output_start.len()
                + self.capture.output_end.as_deref().map_or(0, str::len),
        )
        .expect("capture length fits in u64")
    }
}

impl Workload {
    #[must_use]
    pub fn new(seed: u64, commands_per_day: u32, corpus: Arc<Corpus>) -> Self {
        assert!(commands_per_day > 0);
        Self {
            seed,
            commands_per_day,
            corpus,
        }
    }

    #[must_use]
    pub fn day(&self, index: u64) -> u64 {
        index / u64::from(self.commands_per_day)
    }

    #[must_use]
    pub fn record(&self, index: u64) -> Record {
        /* Sampling is repeatable; the captured text is never filled in, resized or synthesized. */
        let mut rng = StdRng::seed_from_u64(self.seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let id = self.id(index, &mut rng);
        let (kind, sample, output, capture) = self.corpus.sample(&mut rng);
        Record {
            id,
            capture,
            kind,
            sample,
            output,
        }
    }

    fn id(&self, index: u64, rng: &mut StdRng) -> HistoryId {
        let day = self.day(index);
        let weekday = day / 5 * 7 + day % 5;
        let slot = index % u64::from(self.commands_per_day);
        let bursts = u64::from(self.commands_per_day.div_ceil(BURST_COMMANDS));
        let millis = EPOCH_MILLIS
            + weekday * DAY_MILLIS
            + slot / u64::from(BURST_COMMANDS) * (8 * 3_600_000 / bursts)
            + slot % u64::from(BURST_COMMANDS) * 800;
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        HistoryId::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    fn workload() -> Workload {
        let corpus = Corpus::load(&crate::corpus::default_path()).unwrap();
        Workload::new(42, 300, Arc::new(corpus))
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(4)]
    #[case(299)]
    #[case(1499)]
    #[case(78_001)]
    fn records_are_reproducible_and_time_ordered(workload: Workload, #[case] index: u64) {
        let first = workload.record(index);
        let again = workload.record(index);
        assert_eq!(first.id, again.id);
        assert_eq!(first.capture, again.capture);
        assert_eq!(first.sample, again.sample);
        assert!(first.id.into_bytes() < workload.record(index + 1).id.into_bytes());
        assert_eq!(first.id.into_bytes()[6] >> 4, 7);
        assert_eq!(first.id.into_bytes()[8] >> 6, 2);
    }
}
