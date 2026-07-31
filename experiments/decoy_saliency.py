"""Empirical estimate of the deployment-specific decoy identification advantage
eps_dec, for two decoy-generation strategies.

Model.  A presentation carries n candidate credentials that all repeat the
disclosed value (age = 26).  Exactly one candidate is the issuer-authenticated
credential; its undisclosed attributes are drawn from the population
distribution P.  The adversary sees the whole ordered candidate list and tries
to output the authentic index J.

Strategies.
  uniform  : decoy attributes drawn uniformly from each attribute domain,
             ignoring population frequencies.
  matched  : decoy attributes drawn from the same marginals as P.

Adversary.  A logistic-regression scorer trained on labelled candidate lists,
applied at test time by taking the arg-max score within each list.  This is a
concrete PPT distinguisher, so it yields a lower bound on eps_dec.

eps_dec_hat = top-1 accuracy - 1/n.
"""
import json
import numpy as np
from sklearn.linear_model import LogisticRegression

RNG = np.random.default_rng(20260731)

N_FIELDS = 19          # undisclosed fields (20-field VC, 1 disclosed)
DOMAIN = 8             # values per field
N_TRAIN_SETS = 600
N_TEST_SETS = 2000
CAND_SIZES = [50, 100, 200, 500]
ZIPF_S = 1.4           # population skew


def population_marginals():
    """Skewed (Zipf-like) marginal per field; a realistic population is not uniform."""
    ranks = np.arange(1, DOMAIN + 1)
    base = 1.0 / ranks ** ZIPF_S
    probs = []
    for _ in range(N_FIELDS):
        p = base[RNG.permutation(DOMAIN)]
        probs.append(p / p.sum())
    return np.array(probs)


P = population_marginals()
UNIFORM = np.full((N_FIELDS, DOMAIN), 1.0 / DOMAIN)


def sample(probs, size):
    """size x N_FIELDS integer attribute matrix."""
    out = np.empty((size, N_FIELDS), dtype=np.int64)
    for f in range(N_FIELDS):
        out[:, f] = RNG.choice(DOMAIN, size=size, p=probs[f])
    return out


def onehot(mat):
    m = mat.shape[0]
    x = np.zeros((m, N_FIELDS * DOMAIN), dtype=np.float64)
    cols = np.arange(N_FIELDS) * DOMAIN + mat
    x[np.repeat(np.arange(m), N_FIELDS), cols.ravel()] = 1.0
    return x


def make_sets(n, n_sets, decoy_probs):
    """Return (list of onehot candidate blocks, list of authentic indices)."""
    blocks, idxs = [], []
    for _ in range(n_sets):
        genuine = sample(P, 1)
        decoys = sample(decoy_probs, n - 1)
        cand = np.vstack([genuine, decoys])
        order = RNG.permutation(n)
        cand = cand[order]
        j = int(np.where(order == 0)[0][0])
        blocks.append(onehot(cand))
        idxs.append(j)
    return blocks, idxs


def run(n, decoy_probs):
    tr_blocks, tr_idx = make_sets(n, N_TRAIN_SETS, decoy_probs)
    X = np.vstack(tr_blocks)
    y = np.zeros(len(X), dtype=np.int64)
    for k, j in enumerate(tr_idx):
        y[k * n + j] = 1
    clf = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")
    clf.fit(X, y)

    te_blocks, te_idx = make_sets(n, N_TEST_SETS, decoy_probs)
    hits = 0
    for block, j in zip(te_blocks, te_idx):
        s = block @ clf.coef_.ravel()
        if int(np.argmax(s)) == j:
            hits += 1
    acc = hits / N_TEST_SETS
    se = float(np.sqrt(acc * (1 - acc) / N_TEST_SETS))
    return {
        "n": n,
        "top1_accuracy": acc,
        "baseline": 1.0 / n,
        "eps_dec_hat": acc - 1.0 / n,
        "ci95_halfwidth": 1.96 * se,
    }


if __name__ == "__main__":
    results = {"uniform": [], "matched": []}
    for n in CAND_SIZES:
        results["uniform"].append(run(n, UNIFORM))
        results["matched"].append(run(n, P))
    print(json.dumps(results, indent=2))
    with open("experiments/decoy_saliency_results.json", "w") as fh:
        json.dump(results, fh, indent=2)
