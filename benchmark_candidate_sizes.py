#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gc
import json
import math
import platform
import secrets
import statistics
import sys
import time
import tracemalloc
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from coincurve import PrivateKey

from proposed import issue_credential, sign_urs_dvs, verify_urs_dvs


USER = {
    "name": "Alice",
    "age": 25,
    "score": 88,
    "nationality": "Taiwan",
    "level": 4,
    "experience": 6,
    "gender": 0,
    "login_days": 62,
    "purchase_count": 13,
    "review_score": 74,
    "contribution": 32,
    "training_hours": 7,
    "active": True,
    "member": False,
    "passed_kyc": False,
    "admin": True,
    "certified": True,
    "has_photo": True,
    "verified": True,
    "student": False,
}


def parse_ints(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item.strip()]


def serialize_artifact(bundle: dict) -> bytes:
    return json.dumps(
        bundle, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def measure(callable_):
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    result = callable_()
    elapsed_ms = (time.perf_counter() - started) * 1000
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, elapsed_ms, peak_bytes / 1024


def summarize(values: list[float]) -> dict[str, float]:
    mean = statistics.fmean(values)
    stddev = statistics.stdev(values) if len(values) > 1 else 0.0
    z_975 = statistics.NormalDist().inv_cdf(0.975)
    ci_half = z_975 * stddev / math.sqrt(len(values)) if values else 0.0
    return {
        "mean": mean,
        "median": statistics.median(values),
        "stddev": stddev,
        "ci95_low": mean - ci_half,
        "ci95_high": mean + ci_half,
    }


def package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark Proposed across candidate-set sizes."
    )
    parser.add_argument(
        "--candidate-sizes",
        type=parse_ints,
        default=[50, 100, 200, 500],
    )
    parser.add_argument(
        "--attribute-counts",
        type=parse_ints,
        default=list(range(1, 21)),
    )
    parser.add_argument("--repeats", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()

    if args.repeats < 2:
        raise ValueError("--repeats must be at least 2 for standard deviation")
    if min(args.candidate_sizes) < 2:
        raise ValueError("candidate sizes must be at least 2")
    if min(args.attribute_counts) < 1 or max(args.attribute_counts) > len(USER):
        raise ValueError(f"attribute counts must be between 1 and {len(USER)}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    holder_key = PrivateKey()
    issuer_key = PrivateKey()
    verifier_key = PrivateKey()
    issuer_ring_keys = [
        PrivateKey().public_key for _ in range(max(args.candidate_sizes) - 1)
    ]
    attributes = list(USER)
    authentic_credential = {
        **USER,
        "issuer_public_key": issuer_key.public_key.format(
            compressed=True
        ).hex(),
        "holder_public_key": holder_key.public_key.format(
            compressed=True
        ).hex(),
        "credential_status": {
            "entry": "authentic",
            "state": "ok",
            "source": "issuer",
        },
    }
    issuer_signature = issue_credential(issuer_key, authentic_credential)
    issuer_whitelist = [issuer_key.public_key, *issuer_ring_keys]
    credential_schema = list(authentic_credential)
    warmup_context = {
        "session_id": secrets.token_hex(16),
        "policy": [attributes[0]],
    }

    warmup = sign_urs_dvs(
        holder_key,
        issuer_ring_keys,
        authentic_credential,
        issuer_signature,
        verifier_key.public_key,
        issuer_vk=issuer_key.public_key,
        reveal_keys=attributes[:1],
        ring_size=min(args.candidate_sizes),
        context=warmup_context,
    )
    assert verify_urs_dvs(
        warmup,
        verifier_key,
        issuer_whitelist,
        expected_context=warmup_context,
        expected_schema=credential_schema,
    )[0]

    raw_rows = []
    raw_path = args.output_dir / "candidate_size_raw_runs.csv"
    total = (
        len(args.candidate_sizes)
        * len(args.attribute_counts)
        * args.repeats
    )
    completed = 0

    for candidate_size in args.candidate_sizes:
        for attribute_count in args.attribute_counts:
            reveal_keys = attributes[:attribute_count]
            for run in range(1, args.repeats + 1):
                context = {
                    "session_id": secrets.token_hex(16),
                    "policy": sorted(reveal_keys),
                }

                def generate():
                    bundle = sign_urs_dvs(
                        holder_key,
                        issuer_ring_keys,
                        authentic_credential,
                        issuer_signature,
                        verifier_key.public_key,
                        issuer_vk=issuer_key.public_key,
                        reveal_keys=reveal_keys,
                        ring_size=candidate_size,
                        context=context,
                    )
                    return bundle, serialize_artifact(bundle)

                (bundle, encoded), gen_ms, gen_memory = measure(generate)

                def verify():
                    parsed = json.loads(encoded)
                    return verify_urs_dvs(
                        parsed,
                        verifier_key,
                        issuer_whitelist,
                        expected_context=context,
                        expected_schema=credential_schema,
                    )

                verification, ver_ms, ver_memory = measure(verify)
                assert verification[0], "Proposed verification failed"

                common = {
                    "candidate_size": candidate_size,
                    "attribute_count": attribute_count,
                    "run": run,
                    "serialized_artifact_bytes": len(encoded),
                }
                raw_rows.append({
                    **common,
                    "workflow": "generation",
                    "latency_ms": gen_ms,
                    "peak_traced_memory_kb": gen_memory,
                })
                raw_rows.append({
                    **common,
                    "workflow": "verification",
                    "latency_ms": ver_ms,
                    "peak_traced_memory_kb": ver_memory,
                })

                completed += 1
                print(
                    f"\rCompleted {completed}/{total}: "
                    f"n={candidate_size}, attributes={attribute_count}, run={run}",
                    end="",
                    flush=True,
                )
            write_csv(raw_path, raw_rows)
    print()

    summary_rows = []
    for candidate_size in args.candidate_sizes:
        for attribute_count in args.attribute_counts:
            for workflow in ("generation", "verification"):
                group = [
                    row for row in raw_rows
                    if row["candidate_size"] == candidate_size
                    and row["attribute_count"] == attribute_count
                    and row["workflow"] == workflow
                ]
                latency = summarize([row["latency_ms"] for row in group])
                memory = summarize(
                    [row["peak_traced_memory_kb"] for row in group]
                )
                artifact = summarize(
                    [row["serialized_artifact_bytes"] for row in group]
                )
                summary_rows.append({
                    "candidate_size": candidate_size,
                    "attribute_count": attribute_count,
                    "workflow": workflow,
                    "runs": len(group),
                    "mean_latency_ms": latency["mean"],
                    "median_latency_ms": latency["median"],
                    "stddev_latency_ms": latency["stddev"],
                    "latency_ci95_low_ms": latency["ci95_low"],
                    "latency_ci95_high_ms": latency["ci95_high"],
                    "mean_peak_traced_memory_kb": memory["mean"],
                    "stddev_peak_traced_memory_kb": memory["stddev"],
                    "memory_ci95_low_kb": memory["ci95_low"],
                    "memory_ci95_high_kb": memory["ci95_high"],
                    "mean_serialized_artifact_bytes": artifact["mean"],
                    "stddev_serialized_artifact_bytes": artifact["stddev"],
                })

    summary_path = args.output_dir / "candidate_size_summary.csv"
    write_csv(summary_path, summary_rows)
    (args.output_dir / "candidate_size_summary.json").write_text(
        json.dumps(summary_rows, indent=2), encoding="utf-8"
    )
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "curve": "secp256k1",
        "hash": "SHA-256",
        "urs": "Tso US(1,n) Schnorr conversion with cyclic witness-hiding proof",
        "sdvs": "Saeednia-Kremer-Markowitch (r,s,t) construction",
        "linkage_proof": "Fiat-Shamir Chaum-Pedersen Sigma-OR",
        "serialization": "canonical compact JSON (UTF-8)",
        "garbage_collection": "gc.collect() before each measured call",
        "confidence_interval": "normal-approximation 95% CI",
        "candidate_sizes": args.candidate_sizes,
        "attribute_counts": args.attribute_counts,
        "repeats": args.repeats,
        "packages": {
            "coincurve": package_version("coincurve"),
            "ecdsa": package_version("ecdsa"),
        },
    }
    (args.output_dir / "environment.json").write_text(
        json.dumps(environment, indent=2), encoding="utf-8"
    )
    paper_results_path = args.output_dir / "results_for_paper.json"
    paper_results_path.write_text(
        json.dumps({
            "environment": environment,
            "summary": summary_rows,
        }, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {raw_path}")
    print(f"Wrote {summary_path}")
    print(f"Wrote {paper_results_path}")


if __name__ == "__main__":
    main()
