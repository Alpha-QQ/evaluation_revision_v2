# Reproducible Evaluation

This repository contains the manuscript-aligned implementation and benchmark
artifacts for the proposed DID/VC privacy framework.

## Files

- `proposed.py`: URS, SDVS, and holder-key linkage implementation.
- `benchmark_candidate_sizes.py`: candidate-set benchmark for
  `n = 50, 100, 200, 500`, disclosed-attribute counts 1--20, and 100
  repetitions per setting.
- `test_proposed_protocol.py`: protocol correctness and rejection checks.
- `results_for_paper_v2.json`: environment metadata and summarized measurements
  used in the paper.

## Run

```text
python -m pip install -r requirements.txt
python -m unittest test_proposed_protocol.py -v
python benchmark_candidate_sizes.py
```

The benchmark reports latency, peak Python-traced memory, and serialized
artifact size. These are distinct measurements: `tracemalloc` records peak
traced allocations, while serialized size is the UTF-8 byte length of the
compact JSON artifact.
