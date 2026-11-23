#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from statistics import NormalDist

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder


def parse_ints(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item.strip()]


def wilson_interval(hits: int, total: int) -> tuple[float, float]:
    z = NormalDist().inv_cdf(0.975)
    observed = hits / total
    denominator = 1 + z * z / total
    center = (observed + z * z / (2 * total)) / denominator
    half = (
        z
        * math.sqrt(
            observed * (1 - observed) / total
            + z * z / (4 * total * total)
        )
        / denominator
    )
    return center - half, center + half


def zipf_probabilities(domain_size: int, exponent: float) -> np.ndarray:
    ranks = np.arange(1, domain_size + 1, dtype=float)
    probabilities = ranks ** (-exponent)
    return probabilities / probabilities.sum()


def make_lists(
    rng: np.random.Generator,
    list_count: int,
    candidate_size: int,
    field_count: int,
    genuine_probabilities: np.ndarray,
    decoy_source: str,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    domain_size = len(genuine_probabilities)
    if decoy_source == "uniform":
        candidates = rng.integers(
            domain_size,
            size=(list_count, candidate_size, field_count),
            dtype=np.int16,
        )
    elif decoy_source == "matched":
        candidates = rng.choice(
            domain_size,
            size=(list_count, candidate_size, field_count),
            p=genuine_probabilities,
        ).astype(np.int16)
    else:
        raise ValueError("decoy_source must be uniform or matched")

    authentic_indices = rng.integers(candidate_size, size=list_count)
    candidates[np.arange(list_count), authentic_indices] = rng.choice(
        domain_size,
        size=(list_count, field_count),
        p=genuine_probabilities,
    )
    labels = np.zeros((list_count, candidate_size), dtype=np.int8)
    labels[np.arange(list_count), authentic_indices] = 1
    return (
        candidates.reshape(-1, field_count),
        labels.ravel(),
        authentic_indices,
    )


def choose_top_scores(
    rng: np.random.Generator, scores: np.ndarray
) -> np.ndarray:
    guesses = np.empty(scores.shape[0], dtype=int)
    for row_index, row in enumerate(scores):
        tied = np.flatnonzero(row == row.max())
        guesses[row_index] = rng.choice(tied)
    return guesses


def run_saliency(
    candidate_sizes: list[int],
    train_lists: int = 600,
    test_lists: int = 2_000,
    field_count: int = 19,
    domain_size: int = 8,
    zipf_exponent: float = 1.4,
    seed: int = 20260731,
) -> dict:
    if not candidate_sizes or min(candidate_sizes) < 2:
        raise ValueError("candidate sizes must be at least 2")
    if min(train_lists, test_lists, field_count, domain_size) < 1:
        raise ValueError("list, field, and domain sizes must be positive")

    probabilities = zipf_probabilities(domain_size, zipf_exponent)
    rows = []
    for candidate_size in candidate_sizes:
        for source_index, source in enumerate(("uniform", "matched")):
            run_seed = seed + candidate_size * 10 + source_index
            rng = np.random.default_rng(run_seed)
            train_x, train_y, _ = make_lists(
                rng,
                train_lists,
                candidate_size,
                field_count,
                probabilities,
                source,
            )
            encoder = OneHotEncoder(
                categories=[np.arange(domain_size)] * field_count,
                handle_unknown="ignore",
                sparse_output=True,
            )
            encoded_train = encoder.fit_transform(train_x)
            model = LogisticRegression(
                C=1.0,
                class_weight="balanced",
                max_iter=2_000,
                random_state=run_seed,
                solver="lbfgs",
            )
            started = time.perf_counter()
            model.fit(encoded_train, train_y)
            fit_seconds = time.perf_counter() - started

            test_x, _, authentic_indices = make_lists(
                rng,
                test_lists,
                candidate_size,
                field_count,
                probabilities,
                source,
            )
            started = time.perf_counter()
            scores = model.predict_proba(
                encoder.transform(test_x)
            )[:, 1].reshape(test_lists, candidate_size)
            guesses = choose_top_scores(rng, scores)
            score_seconds = time.perf_counter() - started
            hits = int(np.count_nonzero(guesses == authentic_indices))
            accuracy = hits / test_lists
            baseline = 1 / candidate_size
            ci_low, ci_high = wilson_interval(hits, test_lists)
            rows.append({
                "decoy_source": source,
                "candidate_size": candidate_size,
                "train_lists": train_lists,
                "test_lists": test_lists,
                "hits": hits,
                "top1_accuracy": accuracy,
                "baseline": baseline,
                "delta_clf": accuracy - baseline,
                "advantage_point_estimate": max(0.0, accuracy - baseline),
                "accuracy_ci95_low": ci_low,
                "accuracy_ci95_high": ci_high,
                "delta_ci95_low": ci_low - baseline,
                "delta_ci95_high": ci_high - baseline,
                "fit_seconds": fit_seconds,
                "score_seconds": score_seconds,
                "model_iterations": int(model.n_iter_[0]),
                "seed": run_seed,
            })

    return {
        "parameters": {
            "candidate_sizes": candidate_sizes,
            "train_lists": train_lists,
            "test_lists": test_lists,
            "disclosed_fields": 1,
            "undisclosed_fields": field_count,
            "domain_size": domain_size,
            "genuine_distribution": "independent Zipf-like marginals",
            "zipf_exponent": zipf_exponent,
            "decoy_sources": ["uniform", "matched"],
            "feature_encoding": "per-field categorical one-hot",
            "classifier": "scikit-learn LogisticRegression",
            "classifier_parameters": {
                "C": 1.0,
                "class_weight": "balanced",
                "max_iter": 2_000,
                "solver": "lbfgs",
            },
            "confidence_interval": "95% Wilson score interval",
            "seed": seed,
        },
        "summary": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Classifier-based candidate-saliency experiment."
    )
    parser.add_argument(
        "--candidate-sizes", type=parse_ints, default=[50, 100, 200, 500]
    )
    parser.add_argument("--train-lists", type=int, default=600)
    parser.add_argument("--test-lists", type=int, default=2_000)
    parser.add_argument("--field-count", type=int, default=19)
    parser.add_argument("--domain-size", type=int, default=8)
    parser.add_argument("--zipf-exponent", type=float, default=1.4)
    parser.add_argument("--seed", type=int, default=20260731)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/saliency_results.json"),
    )
    args = parser.parse_args()
    results = run_saliency(
        args.candidate_sizes,
        args.train_lists,
        args.test_lists,
        args.field_count,
        args.domain_size,
        args.zipf_exponent,
        args.seed,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
