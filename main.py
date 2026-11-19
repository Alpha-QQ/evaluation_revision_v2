#!/usr/bin/env python3
"""Single entry point.  Edit only the settings block below, then run

    python main.py

All settings and results are written to results/results.json.
"""
# ============================ settings ============================
PROFILE = "paper"            # "paper" (full run) or "quick" (smoke test)
MACHINE_LABEL = "Intel Core i7-12700H laptop, 16 GB, Windows 11 Home 25H2"

PROFILES = {
    "paper": dict(candidate_sizes=[50, 100, 200, 500], attribute_counts=list(range(1, 21)),
                  fixed_n=100, fixed_d=20, latency_reps=100, memory_reps=20,
                  saliency_sizes=[50, 100, 200, 500], train_lists=600, test_lists=2000,
                  comparison_counts=[1, 5, 10, 15, 20], comparison_reps=100,
                  comparison_memory_reps=20, zk_reps=30),
    "quick": dict(candidate_sizes=[50, 100], attribute_counts=[1, 10, 20],
                  fixed_n=50, fixed_d=20, latency_reps=3, memory_reps=1,
                  saliency_sizes=[50], train_lists=100, test_lists=200,
                  comparison_counts=[1, 20], comparison_reps=3,
                  comparison_memory_reps=1, zk_reps=2),
}
WHITELISTED_ISSUERS = 20     # size of the verifier whitelist used by the cover sets
HOLDER_POOL = 1000           # public holder DIDs available as cover identities
SEED = 20261119
OUTPUT = "results/results.json"
# ==================================================================

import importlib
import json
import os
import platform
import sys
import time
import unittest

REQUIRED = {"coincurve": "21.0.0", "numpy": None, "sklearn": None, "sd_jwt": None,
            "jwcrypto": None, "py_arkworks_bls12381": None}


def _check_packages():
    missing = []
    for name in REQUIRED:
        try:
            importlib.import_module(name)
        except ImportError:
            missing.append(name)
    if missing:
        sys.exit("Missing packages: %s. Run: python -m pip install -r requirements.txt"
                 % ", ".join(missing))
    import shutil
    here = os.path.dirname(os.path.abspath(__file__))
    if shutil.which("node") is None:
        sys.exit("Node.js not found (needed for the zk-SNARK comparison). Install Node.js 22 LTS.")
    zk = os.path.join(here, "zk")
    if not os.path.isdir(os.path.join(zk, "node_modules", "snarkjs")):
        # Install the pinned Node packages automatically (bypasses the
        # PowerShell script policy that can block npm.ps1 on Windows).
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if npm is None:
            sys.exit("npm not found. Reinstall Node.js 22 LTS with the default options.")
        print("installing snarkjs and circomlibjs into zk/node_modules (one time) ...")
        import subprocess
        if subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=zk).returncode != 0:
            sys.exit("npm ci failed; see the messages above")
        if not os.path.isdir(os.path.join(zk, "node_modules", "snarkjs")):
            sys.exit("snarkjs still missing after npm ci")


def _versions():
    from importlib.metadata import version
    return {p: version(p) for p in ("coincurve", "numpy", "scikit-learn", "sd-jwt",
                                    "jwcrypto", "py_arkworks_bls12381")}


def main():
    _check_packages()
    import attack_checks
    import benchmark
    import comparison
    import saliency_analysis
    cfg = PROFILES[PROFILE]
    started = time.time()

    print("[1/5] unit tests (proposed protocol, BBS draft test vectors)")
    suite = unittest.defaultTestLoader.loadTestsFromNames(["test_proposed_protocol", "test_bbs"])
    res = unittest.TextTestRunner(verbosity=0).run(suite)
    if not res.wasSuccessful():
        sys.exit("unit tests failed; stopping")

    print("[2/5] attack regression checks")
    attacks = attack_checks.run(10)
    print("  ", attacks)
    if attacks["A4_lent_credential_accepted"] or not attacks["honest_transcripts_accepted"]:
        sys.exit("attack checks failed; stopping")

    print("[3/5] decoy-saliency study")
    saliency = saliency_analysis.run_saliency(cfg["saliency_sizes"], cfg["train_lists"],
                                              cfg["test_lists"], seed=SEED)

    print("[4/5] performance benchmark")
    perf = benchmark.run_benchmark(cfg["candidate_sizes"], cfg["attribute_counts"],
                                   cfg["fixed_n"], cfg["fixed_d"], cfg["latency_reps"],
                                   cfg["memory_reps"], WHITELISTED_ISSUERS, HOLDER_POOL, SEED)

    print("[5/5] comparison with SD-JWT, BBS and zk-SNARK")
    comp = comparison.run_comparison(cfg["comparison_counts"], cfg["comparison_reps"],
                                     cfg["comparison_memory_reps"], cfg["zk_reps"], SEED)

    out = {
        "profile": PROFILE,
        "machine_label": MACHINE_LABEL,
        "environment": {"python": sys.version, "platform": platform.platform(),
                        "processor": platform.processor(), "packages": _versions(),
                        "curve": "secp256k1", "hash": "SHA-256"},
        "settings": {"profile": cfg, "whitelisted_issuers": WHITELISTED_ISSUERS,
                     "holder_pool": HOLDER_POOL, "seed": SEED},
        "unit_tests_run": res.testsRun,
        "attack_checks": attacks,
        "saliency": saliency,
        "performance": perf,
        "comparison": comp,
        "elapsed_seconds": round(time.time() - started, 1),
    }
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", OUTPUT, "in", out["elapsed_seconds"], "s")


if __name__ == "__main__":
    main()
