#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from intersection_analysis import run_intersection
from saliency_analysis import run_saliency


ROOT = Path(__file__).resolve().parent


def parse_ints(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item.strip()]


def package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_raw_performance(path: Path) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            rows.append({
                "candidate_size": int(row["candidate_size"]),
                "attribute_count": int(row["attribute_count"]),
                "run": int(row["run"]),
                "serialized_artifact_bytes": int(
                    row["serialized_artifact_bytes"]
                ),
                "workflow": row["workflow"],
                "latency_ms": float(row["latency_ms"]),
                "peak_traced_memory_kb": float(
                    row["peak_traced_memory_kb"]
                ),
            })
    return rows


def run_performance(
    candidate_sizes: list[int],
    attribute_counts: list[int],
    repeats: int,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="didvc-benchmark-") as temp_dir:
        output_dir = Path(temp_dir)
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "benchmark_candidate_sizes.py"),
                "--candidate-sizes",
                ",".join(map(str, candidate_sizes)),
                "--attribute-counts",
                ",".join(map(str, attribute_counts)),
                "--repeats",
                str(repeats),
                "--output-dir",
                str(output_dir),
            ],
            cwd=ROOT,
            check=True,
        )
        result = json.loads(
            (output_dir / "results_for_paper.json").read_text(
                encoding="utf-8"
            )
        )
        result["raw_runs"] = load_raw_performance(
            output_dir / "candidate_size_raw_runs.csv"
        )
        return result


def validate_complete(
    results: dict,
    candidate_sizes: list[int],
    attribute_counts: list[int],
    repeats: int,
    saliency_test_lists: int,
    intersection_sessions: int,
    intersection_trials: int,
) -> dict:
    expected_performance_rows = (
        len(candidate_sizes) * len(attribute_counts) * repeats * 2
    )
    expected_summary_rows = len(candidate_sizes) * len(attribute_counts) * 2
    expected_saliency_rows = len(candidate_sizes) * 2
    expected_intersection_rows = intersection_sessions * 2
    checks = {
        "performance_raw_rows": {
            "expected": expected_performance_rows,
            "actual": len(results["performance"]["raw_runs"]),
        },
        "performance_summary_rows": {
            "expected": expected_summary_rows,
            "actual": len(results["performance"]["summary"]),
        },
        "saliency_summary_rows": {
            "expected": expected_saliency_rows,
            "actual": len(results["saliency"]["summary"]),
        },
        "saliency_test_lists_per_row": {
            "expected": saliency_test_lists,
            "actual": min(
                row["test_lists"] for row in results["saliency"]["summary"]
            ),
        },
        "intersection_summary_rows": {
            "expected": expected_intersection_rows,
            "actual": len(results["intersection"]["summary"]),
        },
        "intersection_raw_trials": {
            "expected": intersection_trials,
            "actual": len(
                results["intersection"]["raw_intersection_sizes"]
            ),
        },
    }
    for name, check in checks.items():
        check["complete"] = check["expected"] == check["actual"]
        if not check["complete"]:
            raise RuntimeError(f"incomplete result set: {name}: {check}")
    if any(
        len(sample) != intersection_sessions
        for sample in results["intersection"]["raw_intersection_sizes"]
    ):
        raise RuntimeError("incomplete intersection session data")
    return checks


def collect_all(args: argparse.Namespace) -> dict:
    performance = run_performance(
        args.candidate_sizes,
        args.attribute_counts,
        args.repeats,
    )
    saliency = run_saliency(
        args.candidate_sizes,
        args.saliency_train_lists,
        args.saliency_test_lists,
        args.saliency_field_count,
        args.saliency_domain_size,
        args.saliency_zipf_exponent,
        args.seed,
    )
    intersection = run_intersection(
        args.intersection_universe_size,
        args.intersection_candidate_size,
        args.intersection_sessions,
        args.intersection_trials,
        args.seed,
        include_raw=True,
    )
    tracked_files = [
        "proposed.py",
        "benchmark_candidate_sizes.py",
        "saliency_analysis.py",
        "intersection_analysis.py",
        "run_all_experiments.py",
        "requirements.txt",
    ]
    results = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "packages": {
                name: package_version(name)
                for name in ("coincurve", "ecdsa", "numpy", "scikit-learn")
            },
            "source_sha256": {
                name: sha256(ROOT / name) for name in tracked_files
            },
        },
        "performance": performance,
        "saliency": saliency,
        "intersection": intersection,
        "scope": {
            "prototype": "joint same-index cryptographic core",
            "included": [
                "generation and verification latency",
                "generation and verification peak Python-traced memory",
                "serialized artifact size",
                "classifier-based decoy saliency",
                "multi-session candidate-set intersection",
            ],
            "excluded": [
                "live DID resolution and network communication",
                "online revocation retrieval",
                "legacy cross-method measurements that cannot be reproduced by the current dependency set",
            ],
        },
    }
    results["completeness"] = validate_complete(
        results,
        args.candidate_sizes,
        args.attribute_counts,
        args.repeats,
        args.saliency_test_lists,
        args.intersection_sessions,
        args.intersection_trials,
    )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run all reproducible experiments and write one JSON file."
    )
    parser.add_argument(
        "--candidate-sizes", type=parse_ints, default=[50, 100, 200, 500]
    )
    parser.add_argument(
        "--attribute-counts", type=parse_ints, default=list(range(1, 21))
    )
    parser.add_argument("--repeats", type=int, default=100)
    parser.add_argument("--saliency-train-lists", type=int, default=600)
    parser.add_argument("--saliency-test-lists", type=int, default=2_000)
    parser.add_argument("--saliency-field-count", type=int, default=19)
    parser.add_argument("--saliency-domain-size", type=int, default=8)
    parser.add_argument("--saliency-zipf-exponent", type=float, default=1.4)
    parser.add_argument("--intersection-universe-size", type=int, default=10_000)
    parser.add_argument("--intersection-candidate-size", type=int, default=100)
    parser.add_argument("--intersection-sessions", type=int, default=5)
    parser.add_argument("--intersection-trials", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260731)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/all_results.json"),
    )
    args = parser.parse_args()
    results = collect_all(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary_output.write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    temporary_output.replace(args.output)
    print(f"Wrote complete result set to {args.output}")


if __name__ == "__main__":
    main()
