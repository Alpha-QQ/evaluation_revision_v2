# Candidate-set credential presentation: evaluation code

Python 3.12, secp256k1 (coincurve), SHA-256.

## Files

| File | Purpose |
|---|---|
| `main.py` | Single entry point. Edit only the settings block at the top. |
| `proposed.py` | Protocol: Schnorr issuance, URS conversion, SDVS, linkage proof, presentation, verification. Decoy values are drawn from attribute value domains, and every candidate carries a status entry (an index in its issuer's revocation status list) in the same format. |
| `test_proposed_protocol.py` | Unit tests of the protocol. |
| `benchmark_candidate_sizes.py` | Latency, peak traced memory, and artifact size for candidate-set sizes and disclosed attributes (manuscript results: `results/results.json` and the raw files in `results/_original_scripts/`; `results_for_paper_v2.json` is an earlier recorded run). |
| `saliency_analysis.py` | Decoy-saliency study (recorded result: `results/saliency_results.json`). |
| `netbench.py` | End-to-end network evaluation of one presentation (see below). |
| `protocol_adapter.py` | Connects `netbench.py` to `proposed.py`, using the credential and serialization of the benchmark. |
| `test_netbench.py` | Unit tests of the network evaluation. |
| `comparison.py` | SD-JWT, BBS+ and zk-SNARK: issuance, presentation, verification and size on the same 20-attribute credential. |
| `bbs.py` | BBS signatures and proofs (IRTF CFRG draft, ciphersuite BLS12-381-SHA-256). |
| `test_bbs.py` | Checks `bbs.py` against the signature and proof test vectors of the draft (`fixtures/bbs`, from https://github.com/decentralized-identity/bbs-signature). |
| `zk/` | zk-SNARK credential: circuit `circuit/disclose.circom`, compiled circuit and proving key in `build/`, benchmark script `bench.js`. Run with Node.js; `main.py` installs the pinned Node packages on the first run. |

## Run on Windows

In this folder:

```bat
cmd /c start /affinity 0xFFF /wait /b python main.py
```

`main.py` switches to Python 3.12 if another version starts it (and installs Python 3.12 with winget if none is found), installs the packages in `requirements.txt` when they are missing, runs the unit tests, and then the enabled experiments. All settings and results are written to `results/results.json`.

`PROFILE = "quick"` runs a smoke test in about a minute; `PROFILE = "paper"` is the full run (about one hour). By default all experiments run: `RUN_BENCHMARK` (protocol benchmark), `RUN_COMPARISON` (SD-JWT, BBS+, zk-SNARK; needs Node.js, which `main.py` installs with winget if it is missing), `RUN_NETWORK` (network evaluation) and `RUN_SALIENCY` (decoy saliency). Do not run other timing experiments at the same time.

## Network evaluation

Everything runs on the local machine. A verifier service and a verifiable data registry (VDR) run as HTTP/1.1 servers on 127.0.0.1. The VDR serves a did:web document for each issuer and one Bitstring Status List (131072 entries, 1% revoked) per issuer. The holder and the verifier reach the servers through clients whose traffic is shaped in software:

- a new connection costs two round-trip times (TCP and a TLS 1.3 handshake, without the TLS cryptography);
- each request and each response is delayed by half the round-trip time;
- request and response bodies are paced to the link bandwidth, and all connections of one host share its uplink and downlink.

One run measures, from the holder's side: reading and decrypting the credential from the wallet (AES-GCM file), fetching the verifier's request, resolving the issuer DIDs of the candidate list and checking their status entries, generating the presentation, and submitting it; the verifier fetches the status lists of all candidates and verifies the presentation before it answers. In the `cold` scenario nothing is cached; in the `warm` scenario both parties use cached DID documents and status lists. The grid covers candidate-set sizes, bandwidths, round-trip times, and both scenarios, in shuffled order.
