# Candidate-set credential presentation: evaluation code

Version: v4.1 (2026-11-19). Python 3.12, secp256k1 (coincurve), SHA-256.
Comparison schemes: SD-JWT (sd-jwt 0.10.4), BBS (BLS12-381-SHA-256, py_arkworks_bls12381 0.5.0), zk-SNARK (Groth16, snarkjs 0.7.5 on Node.js).

## Files

| File | Purpose |
|---|---|
| `main.py` | Single entry point. Edit only the settings block at the top. |
| `proposed.py` | Protocol: Schnorr issuance, URS rows, joint designated-verifier proof, SDVS, candidate lists, presentation, verification, verifier simulator. |
| `test_proposed_protocol.py` | Unit tests (run automatically by `main.py`). |
| `attack_checks.py` | Attack regression checks (lent credential, verifier simulation, labels, same-list and cross-list comparison). |
| `saliency_analysis.py` | Decoy-saliency study (correlated population, three generators, two classifiers). |
| `benchmark.py` | Latency, peak traced memory, and presentation size. |
| `comparison.py` | Issuance, presentation, verification and size of SD-JWT, BBS and the zk-SNARK credential on the same 20-attribute credential. |
| `bbs.py` | BBS signatures and proofs following the IRTF CFRG draft (ciphersuite BLS12-381-SHA-256). |
| `test_bbs.py` | Checks `bbs.py` against all signature and proof test vectors of the draft (`fixtures/bbs`, from https://github.com/decentralized-identity/bbs-signature). |
| `zk/` | zk-SNARK credential: circuit `circuit/disclose.circom`, compiled circuit and proving key in `build/`, benchmark script `bench.js`, `package.json`. |
| `fill_paper.py` | Writes the numbers of `results/results.json` into the paper's `%% BEGIN AUTO` blocks. |

All settings and results (parameters, means, standard deviations, confidence intervals, environment) are written to `results/results.json`.

## Run on Windows

Install Node.js 22 LTS from https://nodejs.org first (only needed once). On the first run `main.py` installs the pinned Node packages into `zk/node_modules` by itself. Then, in this folder:

```bat
python -m pip install -r requirements.txt
cmd /c start /affinity 0xFFF /wait /b python main.py
python fill_paper.py results\results.json path\to\cas-dc-template.tex
```

Before running, set `MACHINE_LABEL` in `main.py`. `PROFILE = "quick"` runs a smoke test in a few seconds; `PROFILE = "paper"` is the full run.
Do not run other timing experiments at the same time.

## Rebuilding the zk-SNARK circuit (optional)

`zk/build/` already contains the compiled circuit (`disclose_js/disclose.wasm`), the Groth16 proving key (`disclose.zkey`) and the verification key (`vkey.json`), so circom is not needed to run the benchmark. They were produced with circom 2.2.2 and snarkjs 0.7.5:

```sh
circom circuit/disclose.circom --r1cs --wasm -l node_modules -o build
npx snarkjs powersoftau new bn128 14 build/pot0.ptau
npx snarkjs powersoftau contribute build/pot0.ptau build/pot1.ptau -e="<entropy>"
npx snarkjs powersoftau prepare phase2 build/pot1.ptau build/pot14.ptau
npx snarkjs groth16 setup build/disclose.r1cs build/pot14.ptau build/d0.zkey
npx snarkjs zkey contribute build/d0.zkey build/disclose.zkey -e="<entropy>"
npx snarkjs zkey export verificationkey build/disclose.zkey build/vkey.json
```

The single-party setup is adequate for benchmarking only.
