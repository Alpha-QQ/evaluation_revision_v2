#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import statistics
from pathlib import Path


def run_trial(
    universe_size: int,
    candidate_size: int,
    sessions: int,
    rng: random.Random,
) -> list[int]:
    authentic = 0
    population = range(1, universe_size)
    intersection = {authentic}
    intersection.update(rng.sample(population, candidate_size - 1))
    counts = [len(intersection)]
    for _ in range(1, sessions):
        current = {authentic}
        current.update(rng.sample(population, candidate_size - 1))
        intersection.intersection_update(current)
        counts.append(len(intersection))
    return counts


def run_intersection(
    universe_size: int = 10_000,
    candidate_size: int = 100,
    sessions: int = 5,
    trials: int = 10_000,
    seed: int = 20260731,
    include_raw: bool = True,
) -> dict:
    if not 1 < candidate_size <= universe_size:
        raise ValueError("candidate size must be in [2, universe size]")
    if sessions < 1 or trials < 1:
        raise ValueError("sessions and trials must be positive")

    rng = random.Random(seed)
    samples = [
        run_trial(universe_size, candidate_size, sessions, rng)
        for _ in range(trials)
    ]
    summary = []
    for session in range(1, sessions + 1):
        values = [sample[session - 1] for sample in samples]
        expected_false = (
            (candidate_size - 1) ** session
            / (universe_size - 1) ** (session - 1)
        )
        summary.append({
            "strategy": "independent_resampling",
            "sessions": session,
            "mean_intersection_size": statistics.fmean(values),
            "median_intersection_size": statistics.median(values),
            "probability_unique_authentic": sum(
                value == 1 for value in values
            ) / trials,
            "expected_false_candidates": expected_false,
        })
        summary.append({
            "strategy": "service_scoped_reuse",
            "sessions": session,
            "mean_intersection_size": float(candidate_size),
            "median_intersection_size": float(candidate_size),
            "probability_unique_authentic": 0.0,
            "expected_false_candidates": float(candidate_size - 1),
        })

    result = {
        "parameters": {
            "universe_size": universe_size,
            "candidate_size": candidate_size,
            "sessions": sessions,
            "trials": trials,
            "seed": seed,
        },
        "summary": summary,
    }
    if include_raw:
        result["raw_intersection_sizes"] = samples
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure candidate-set intersection across presentations."
    )
    parser.add_argument("--universe-size", type=int, default=10_000)
    parser.add_argument("--candidate-size", type=int, default=100)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--trials", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260731)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/intersection_results.json"),
    )
    args = parser.parse_args()
    results = run_intersection(
        args.universe_size,
        args.candidate_size,
        args.sessions,
        args.trials,
        args.seed,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
