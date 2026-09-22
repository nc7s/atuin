use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use atuin_client::history::CommandCapture;
use atuin_client::settings::CaptureLimits;
use eyre::{Result, ensure};
use rand::{Rng, rngs::StdRng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Silent,
    Short,
    Listing,
    Search,
    Git,
    Build,
    Test,
    Help,
    Data,
}

/* Activity weights, not size buckets. Output lengths come entirely from the recorded commands. */
const MIX: [(Kind, u32); 9] = [
    (Kind::Silent, 20),
    (Kind::Short, 18),
    (Kind::Listing, 12),
    (Kind::Search, 16),
    (Kind::Git, 12),
    (Kind::Build, 8),
    (Kind::Test, 6),
    (Kind::Help, 3),
    (Kind::Data, 5),
];

#[derive(Deserialize)]
struct Manifest {
    format_version: u32,
    captured_at: String,
    normalization: String,
    sources: Vec<Source>,
    records: Vec<Sample>,
}

#[derive(Deserialize)]
struct Sample {
    project: String,
    kind: Kind,
    output: String,
    bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Source {
    project: String,
    revision: String,
    build_workspace_differs: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub captured_at: String,
    pub normalization: String,
    pub sources: Vec<Source>,
    pub samples: usize,
    pub unique_outputs: usize,
    pub projects: BTreeMap<String, usize>,
    pub kinds: BTreeMap<Kind, usize>,
    pub min_bytes: u64,
    pub median_bytes: u64,
    pub p95_bytes: u64,
    pub max_bytes: u64,
    pub capture_limit: usize,
}

pub struct Corpus {
    pub summary: Summary,
    outputs: Vec<CommandCapture>,
    samples: Vec<usize>,
    pools: BTreeMap<Kind, Vec<usize>>,
}

impl Corpus {
    pub fn load(path: &Path) -> Result<Self> {
        let manifest: Manifest =
            serde_json::from_reader(std::fs::File::open(path.join("manifest.json"))?)?;
        ensure!(manifest.format_version == 1, "unsupported corpus format");
        ensure!(!manifest.records.is_empty(), "empty corpus");
        let limit = usize::try_from(CaptureLimits::default().max_output_size.as_u64())?;
        let mut outputs = Vec::new();
        let mut samples = Vec::new();
        let mut names = BTreeMap::new();
        let mut pools = BTreeMap::<_, Vec<_>>::new();
        let mut projects = BTreeMap::new();
        let mut sizes = Vec::new();
        for sample in manifest.records {
            ensure!(
                Path::new(&sample.output)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
                "corpus output must be a relative path without traversal"
            );
            let output = if let Some(&index) = names.get(&sample.output) {
                index
            } else {
                let text = std::fs::read_to_string(path.join(&sample.output))?;
                let index = outputs.len();
                outputs.push(capture(text, limit));
                names.insert(sample.output, index);
                index
            };
            ensure!(
                outputs[output].output_observed_bytes == sample.bytes,
                "corpus output length mismatch"
            );
            pools.entry(sample.kind).or_default().push(samples.len());
            samples.push(output);
            sizes.push(sample.bytes);
            *projects.entry(sample.project).or_insert(0) += 1;
        }
        for (kind, _) in MIX {
            ensure!(pools.contains_key(&kind), "missing corpus category: {kind:?}");
        }
        sizes.sort_unstable();
        let summary = Summary {
            captured_at: manifest.captured_at,
            normalization: manifest.normalization,
            sources: manifest.sources,
            samples: samples.len(),
            unique_outputs: outputs.len(),
            projects,
            kinds: pools.iter().map(|(kind, pool)| (*kind, pool.len())).collect(),
            min_bytes: sizes[0],
            median_bytes: sizes[sizes.len() / 2],
            p95_bytes: sizes[(sizes.len() - 1) * 95 / 100],
            max_bytes: *sizes.last().expect("nonempty corpus"),
            capture_limit: limit,
        };
        Ok(Self {
            summary,
            outputs,
            samples,
            pools,
        })
    }

    pub fn sample(&self, rng: &mut StdRng) -> (Kind, usize, usize, CommandCapture) {
        let mut choice = rng.gen_range(0..MIX.iter().map(|(_, weight)| weight).sum::<u32>());
        for (kind, weight) in MIX {
            if choice < weight {
                let pool = &self.pools[&kind];
                let sample = pool[rng.gen_range(0..pool.len())];
                let output = self.samples[sample];
                return (kind, sample, output, self.outputs[output].clone());
            }
            choice -= weight;
        }
        unreachable!("weights cover the selection range")
    }
}

#[must_use]
pub fn default_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/output_store/corpus")
}

fn capture(text: String, limit: usize) -> CommandCapture {
    let observed = u64::try_from(text.len()).expect("output length fits");
    let (output_start, output_end) = if text.len() <= limit {
        (text, None)
    } else {
        let mut start = limit / 2;
        let mut end = text.len() - (limit - start);
        while !text.is_char_boundary(start) {
            start -= 1;
        }
        while !text.is_char_boundary(end) {
            end += 1;
        }
        (text[..start].to_owned(), Some(text[end..].to_owned()))
    };
    CommandCapture {
        output_start,
        output_end,
        output_observed_bytes: observed,
        terminal_width: 120,
        terminal_height: 40,
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    #[case("", 10, "", None)]
    #[case("1234567890", 10, "1234567890", None)]
    #[case("12345678901", 10, "12345", Some("78901"))]
    #[case("世世世世", 7, "世", Some("世"))]
    fn capture_preserves_boundaries(
        #[case] text: &str,
        #[case] limit: usize,
        #[case] start: &str,
        #[case] end: Option<&str>,
    ) {
        let capture = super::capture(text.to_owned(), limit);
        assert_eq!(capture.output_start, start);
        assert_eq!(capture.output_end.as_deref(), end);
        assert_eq!(capture.output_observed_bytes, u64::try_from(text.len()).unwrap());
    }
}
