#!/usr/bin/env python3
"""Decoy-saliency study.

Genuine credentials follow a correlated population: a latent class z is drawn
first, then every undisclosed field is drawn from a class-specific Zipf-like
distribution.  Three holder-side decoy generators are compared:

  uniform   every field uniform over its domain (ignores the population)
  marginal  every field drawn independently from the population marginal
            (what a holder can do with published per-field statistics)
  joint     decoys drawn from the full population model (requires knowledge
            of the joint distribution; upper bound on achievable quality)

Two classifiers score candidates: logistic regression on one-hot features
(no interactions) and histogram gradient boosting on categorical features
(captures field interactions).  The prediction for a list is the candidate
with the highest score; accuracy is compared with 1/n.
"""
from __future__ import annotations

import math
from statistics import NormalDist
from typing import Dict, List

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder

GENERATORS = ("uniform", "marginal", "joint")
CLASSIFIERS = ("logistic", "boosting")


def wilson(hits: int, total: int):
    z = NormalDist().inv_cdf(0.975)
    p = hits / total
    den = 1 + z * z / total
    c = (p + z * z / (2 * total)) / den
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / den
    return c - half, c + half


class Population:
    def __init__(self, rng, fields, domain, classes, zipf):
        ranks = np.arange(1, domain + 1, dtype=float) ** (-zipf)
        base = ranks / ranks.sum()
        self.weights = rng.dirichlet(np.full(classes, 2.0))
        self.cond = np.empty((classes, fields, domain))
        for k in range(classes):
            for f in range(fields):
                self.cond[k, f] = base[rng.permutation(domain)]
        self.marginal = np.einsum("k,kfd->fd", self.weights, self.cond)
        self.fields, self.domain = fields, domain

    def sample_joint(self, rng, count):
        z = rng.choice(len(self.weights), size=count, p=self.weights)
        u = rng.random((count, self.fields, 1))
        cdf = np.cumsum(self.cond[z], axis=2)
        return (u > cdf).sum(axis=2).clip(max=self.domain - 1).astype(np.int16)

    def sample_marginal(self, rng, count):
        u = rng.random((count, self.fields, 1))
        cdf = np.cumsum(self.marginal, axis=1)[None, :, :]
        return (u > cdf).sum(axis=2).clip(max=self.domain - 1).astype(np.int16)

    def sample_uniform(self, rng, count):
        return rng.integers(self.domain, size=(count, self.fields), dtype=np.int16)


def make_lists(rng, pop, lists, n, generator):
    sampler = {"uniform": pop.sample_uniform, "marginal": pop.sample_marginal,
               "joint": pop.sample_joint}[generator]
    cand = sampler(rng, lists * n).reshape(lists, n, pop.fields)
    j = rng.integers(n, size=lists)
    cand[np.arange(lists), j] = pop.sample_joint(rng, lists)
    labels = np.zeros((lists, n), dtype=np.int8)
    labels[np.arange(lists), j] = 1
    return cand.reshape(-1, pop.fields), labels.ravel(), j


def _model(kind, seed, domain, fields):
    if kind == "logistic":
        enc = OneHotEncoder(categories=[np.arange(domain)] * fields,
                            handle_unknown="ignore", sparse_output=True)
        clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000,
                                 random_state=seed, solver="lbfgs")
        return enc, clf
    clf = HistGradientBoostingClassifier(categorical_features=list(range(fields)),
                                         max_iter=200, learning_rate=0.1,
                                         class_weight="balanced", random_state=seed)
    return None, clf


def run_saliency(candidate_sizes: List[int], train_lists=600, test_lists=2000,
                 fields=19, domain=8, classes=4, zipf=1.4, seed=20261119) -> Dict:
    pop = Population(np.random.default_rng(seed), fields, domain, classes, zipf)
    rows = []
    for n in candidate_sizes:
        for gi, gen in enumerate(GENERATORS):
            for ci, kind in enumerate(CLASSIFIERS):
                s = seed + 1000 * n + 10 * gi + ci
                rng = np.random.default_rng(s)
                xtr, ytr, _ = make_lists(rng, pop, train_lists, n, gen)
                enc, clf = _model(kind, s, domain, fields)
                clf.fit(enc.fit_transform(xtr) if enc else xtr, ytr)
                xte, _, j = make_lists(rng, pop, test_lists, n, gen)
                score = clf.predict_proba(enc.transform(xte) if enc else xte)[:, 1]
                score = score.reshape(test_lists, n)
                guess = np.array([rng.choice(np.flatnonzero(r == r.max())) for r in score])
                hits = int((guess == j).sum())
                lo, hi = wilson(hits, test_lists)
                rows.append({"generator": gen, "classifier": kind, "candidate_size": n,
                             "hits": hits, "top1_accuracy": hits / test_lists,
                             "baseline": 1 / n, "delta_clf": hits / test_lists - 1 / n,
                             "accuracy_ci95_low": lo, "accuracy_ci95_high": hi,
                             "delta_ci95_low": lo - 1 / n, "delta_ci95_high": hi - 1 / n,
                             "seed": s})
    return {"parameters": {"candidate_sizes": candidate_sizes, "train_lists": train_lists,
                           "test_lists": test_lists, "undisclosed_fields": fields,
                           "domain_size": domain, "latent_classes": classes,
                           "zipf_exponent": zipf, "seed": seed,
                           "generators": list(GENERATORS), "classifiers": list(CLASSIFIERS),
                           "confidence_interval": "95% Wilson score interval"},
            "summary": rows}


if __name__ == "__main__":
    import json
    print(json.dumps(run_saliency([50], 100, 200), indent=1)[:2000])
