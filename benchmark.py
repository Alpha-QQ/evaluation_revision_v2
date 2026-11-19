"""Performance benchmark for the revised presentation protocol.

Workflows
  first   : first presentation under a policy (candidate-list construction,
            URS rows, joint proof, SDVS); the holder cache is cleared first.
  repeat  : later presentation under the same policy (cached list; fresh
            base, joint proof, SDVS).
  verify  : verifier checks of one transcript (parse, whitelist, schema,
            policy, status lookup, URS rows, joint proof, SDVS).

Latency and traced memory are measured in separate passes, so tracemalloc
overhead does not enter the latency numbers.  Configurations are visited in
a freshly shuffled order in every round to spread drift over all settings.
"""
from __future__ import annotations

import gc
import json
import math
import random
import statistics
import time
import tracemalloc
from typing import Dict, List

from coincurve import PrivateKey

import proposed as P

USER = {
    "name": "Alice", "age": 25, "score": 88, "nationality": "Taiwan", "level": 4,
    "experience": 6, "gender": 0, "login_days": 62, "purchase_count": 13,
    "review_score": 74, "contribution": 32, "training_hours": 7, "active": True,
    "member": False, "passed_kyc": False, "admin": True, "certified": True,
    "has_photo": True, "verified": True, "student": False,
}
WORKFLOWS = ("first", "repeat", "verify")


def _summary(values: List[float]) -> Dict[str, float]:
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    half = statistics.NormalDist().inv_cdf(0.975) * sd / math.sqrt(len(values))
    q = statistics.quantiles(values, n=4) if len(values) > 1 else [mean, mean, mean]
    return {"mean": mean, "median": statistics.median(values), "stddev": sd,
            "ci95_low": mean - half, "ci95_high": mean + half,
            "q1": q[0], "q3": q[2], "runs": len(values)}


class Setup:
    def __init__(self, max_n: int, issuers: int, holder_pool: int):
        self.issuer = PrivateKey()
        self.verifier = PrivateKey()
        self.wl = [self.issuer.public_key] + [PrivateKey().public_key for _ in range(issuers - 1)]
        self.pool = [PrivateKey().public_key for _ in range(max(holder_pool, max_n))]
        self.hsk = PrivateKey()
        self.cred = P.make_credential(self.issuer, self.hsk.public_key, USER, 1234)
        self.sig = P.issue_credential(self.issuer, self.cred)
        self.schema = list(self.cred)
        self.revoked = {P._pb(k).hex(): set(random.sample(range(P.STATUS_LIST_SIZE), 100))
                        - {1234} for k in self.wl}
        self.holders = {}

    def holder(self, n: int) -> P.Holder:
        if n not in self.holders:
            self.holders[n] = P.Holder(self.hsk, self.cred, self.sig, self.issuer.public_key,
                                       P.random_cover(n, self.wl, self.pool),
                                       status_lists=self.revoked)
        return self.holders[n]


def _one(setup: Setup, n: int, d: int, workflow: str, mode: str):
    """Run one measured call; mode is 'latency' or 'memory'."""
    holder = setup.holder(n)
    policy = list(USER)[:d]
    ctx = {"session_id": "%032x" % random.getrandbits(128), "policy": policy}
    if workflow == "first":
        holder.cache.pop(tuple(sorted(policy)), None)
        call = lambda: P.present(holder, setup.verifier.public_key, ctx)
    elif workflow == "repeat":
        holder.candidate_list(policy)
        call = lambda: P.present(holder, setup.verifier.public_key, ctx)
    else:
        encoded = json.dumps(P.present(holder, setup.verifier.public_key, ctx),
                             sort_keys=True, separators=(",", ":")).encode()
        def call():
            ok = P.verify_presentation(json.loads(encoded), setup.verifier, setup.wl,
                                       expected_context=ctx, expected_schema=setup.schema,
                                       revoked=setup.revoked)
            assert ok, "verification failed"
            return ok
    gc.collect()
    if mode == "memory":
        tracemalloc.start()
        result = call()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        value = peak / 1024
    else:
        t0 = time.perf_counter()
        result = call()
        value = (time.perf_counter() - t0) * 1000
    size = None
    if workflow != "verify":
        size = len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) / 1024
    return value, size


def run_benchmark(candidate_sizes: List[int], attribute_counts: List[int],
                  fixed_n: int, fixed_d: int, latency_reps: int, memory_reps: int,
                  issuers: int, holder_pool: int, seed: int, progress: bool = True) -> Dict:
    random.seed(seed)
    setup = Setup(max(candidate_sizes + [fixed_n]), issuers, holder_pool)
    configs = sorted({(n, fixed_d) for n in candidate_sizes} |
                     {(fixed_n, d) for d in attribute_counts})
    data = {(n, d, w, m): [] for n, d in configs for w in WORKFLOWS for m in ("latency", "memory")}
    sizes = {(n, d): [] for n, d in configs}
    for w in WORKFLOWS:  # warm-up
        _one(setup, min(candidate_sizes), 1, w, "latency")
    total = len(configs) * len(WORKFLOWS) * (latency_reps + memory_reps)
    done = 0
    for mode, reps in (("latency", latency_reps), ("memory", memory_reps)):
        for _ in range(reps):
            order = [(n, d, w) for n, d in configs for w in WORKFLOWS]
            random.shuffle(order)
            for n, d, w in order:
                value, size = _one(setup, n, d, w, mode)
                data[(n, d, w, mode)].append(value)
                if size is not None and w == "repeat" and mode == "latency":
                    sizes[(n, d)].append(size)
                done += 1
                if progress and done % 50 == 0:
                    print("\r  benchmark %d/%d" % (done, total), end="", flush=True)
    if progress:
        print()
    rows = []
    for n, d in configs:
        for w in WORKFLOWS:
            row = {"candidate_size": n, "disclosed": d, "workflow": w,
                   "latency_ms": _summary(data[(n, d, w, "latency")])}
            if memory_reps:
                row["peak_traced_memory_kib"] = _summary(data[(n, d, w, "memory")])
            if sizes[(n, d)]:
                row["artifact_kib"] = _summary(sizes[(n, d)])
            rows.append(row)
    return {"parameters": {"candidate_sizes": candidate_sizes,
                           "attribute_counts": attribute_counts, "fixed_n": fixed_n,
                           "fixed_d": fixed_d, "latency_reps": latency_reps,
                           "memory_reps": memory_reps, "whitelisted_issuers": issuers,
                           "holder_pool": holder_pool, "seed": seed,
                           "status_list_size": P.STATUS_LIST_SIZE},
            "summary": rows}
