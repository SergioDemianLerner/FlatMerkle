# FlatMerkle

Logarithmic-space inclusion proofs over a single linear (Merkle–Damgård) hash stream, by re-injecting the hash function's own past chaining states into the stream. This repository contains the paper and the reference implementation that every FlatMerkle number, table and figure in it was checked against.

## Contents

- `paper/` — LaTeX source (`main.tex`, `sections/`, `refs.bib`, `figures/`) and the compiled `main.pdf`.
- `python/` — reference implementation:
  - `loglink.py` — construction, single-element proofs and multiproofs over a toy compression function (32-byte state and block).
  - `loglink_annex.py` — the same over real SHA-256 (64-byte blocks), as used in the Bitcoin annex application.
  - `sha256_core.py` — from-scratch SHA-256 compression function with exposed chaining state.
  - `fraud_proof.py`, `simulate_fraud_proofs.py` — fraud proofs for non-canonical files (paper §5.5) and their test cases.
  - `experiments.py` — proof-size and multiproof-savings experiments (§6, §7).
  - `benchmark.py` — construction-speed comparison against Merkle trees (§8).
  - `illustrate.py` — generates the paper's figures.
- `benchmark_data/` — raw timing results behind the §8 table.
- `java/` — a line-by-line Java transliteration of the core algorithms, for cross-language sanity checks (not an independent implementation).

The working name of the project was LogLink; some filenames keep it.

## Running the tests

Python 3.10+. `illustrate.py`, and the fraud-proof modules that reuse its layout function, need `matplotlib`; everything else uses only the standard library.

```
cd python
python3 loglink.py                  # construction, proofs, multiproofs, tamper tests
python3 loglink_annex.py            # real SHA-256 variant
python3 simulate_fraud_proofs.py    # fraud-proof soundness and completeness cases
python3 experiments.py              # size and multiproof experiments (slow at N = 2^20)
```

## Building the paper

```
cd paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
```
