#!/usr/bin/env python3
"""Write the numbers of results/results.json into the paper.

    python fill_paper.py results/results.json ../paper/cas-dc-template.tex

Every block between a line '%% BEGIN AUTO:<name>' and '%% END AUTO:<name>'
in the .tex file is regenerated.  Text outside these blocks is not touched.
"""
import json
import re
import sys


def fmt(x, d=1):
    return ("%%.%df" % d) % x


def perf_rows(res):
    return res["performance"]["summary"]


def get(rows, n, d, w):
    for r in rows:
        if r["candidate_size"] == n and r["disclosed"] == d and r["workflow"] == w:
            return r
    raise KeyError((n, d, w))


def block_macros(res):
    p = res["performance"]["parameters"]
    rows = perf_rows(res)
    n0, d0 = p["fixed_n"], p["fixed_d"]
    f, rp, v = (get(rows, n0, d0, w) for w in ("first", "repeat", "verify"))
    dvals = p["attribute_counts"]
    def rng(w, key="latency_ms"):
        vals = [get(rows, n0, d, w)[key]["mean"] for d in dvals]
        return fmt(min(vals)), fmt(max(vals))
    fmin, fmax = rng("first")
    rmin, rmax = rng("repeat")
    vmin, vmax = rng("verify")
    ns = p["candidate_sizes"]
    lo, hi = min(ns), max(ns)
    s = res["saliency"]["summary"]
    def acc(gen, clf, n):
        return next(x for x in s if x["generator"] == gen and x["classifier"] == clf
                    and x["candidate_size"] == n)["top1_accuracy"]
    sn = res["saliency"]["parameters"]["candidate_sizes"]
    marg_boost = [acc("marginal", "boosting", n) for n in sn]
    unif = [acc("uniform", c, n) for c in ("logistic", "boosting") for n in sn]
    env = res["environment"]
    lines = [
        r"\newcommand{\machineLabel}{%s}" % res["machine_label"],
        r"\newcommand{\pyVersion}{%s}" % env["python"].split()[0],
        r"\newcommand{\coincurveVersion}{%s}" % env["packages"]["coincurve"],
        r"\newcommand{\numpyVersion}{%s}" % env["packages"]["numpy"],
        r"\newcommand{\sklearnVersion}{%s}" % env["packages"]["scikit-learn"],
        r"\newcommand{\latReps}{%d}" % p["latency_reps"],
        r"\newcommand{\memReps}{%d}" % p["memory_reps"],
        r"\newcommand{\wlSize}{%d}" % p["whitelisted_issuers"],
        r"\newcommand{\poolSize}{%d}" % p["holder_pool"],
        r"\newcommand{\fixN}{%d}" % n0,
        r"\newcommand{\fixD}{%d}" % d0,
        r"\newcommand{\firstLat}{%s}" % fmt(f["latency_ms"]["mean"]),
        r"\newcommand{\firstLatSD}{%s}" % fmt(f["latency_ms"]["stddev"]),
        r"\newcommand{\repeatLat}{%s}" % fmt(rp["latency_ms"]["mean"]),
        r"\newcommand{\repeatLatSD}{%s}" % fmt(rp["latency_ms"]["stddev"]),
        r"\newcommand{\verifyLat}{%s}" % fmt(v["latency_ms"]["mean"]),
        r"\newcommand{\verifyLatSD}{%s}" % fmt(v["latency_ms"]["stddev"]),
        r"\newcommand{\firstMem}{%s}" % fmt(f["peak_traced_memory_kib"]["mean"]),
        r"\newcommand{\verifyMem}{%s}" % fmt(v["peak_traced_memory_kib"]["mean"]),
        r"\newcommand{\artSize}{%s}" % fmt(rp["artifact_kib"]["mean"]),
        r"\newcommand{\dFirstMin}{%s}\newcommand{\dFirstMax}{%s}" % (fmin, fmax),
        r"\newcommand{\dRepeatMin}{%s}\newcommand{\dRepeatMax}{%s}" % (rmin, rmax),
        r"\newcommand{\dVerifyMin}{%s}\newcommand{\dVerifyMax}{%s}" % (vmin, vmax),
        r"\newcommand{\nLow}{%d}\newcommand{\nHigh}{%d}" % (lo, hi),
        r"\newcommand{\verifyLatLow}{%s}" % fmt(get(rows, lo, d0, "verify")["latency_ms"]["mean"]),
        r"\newcommand{\verifyLatHigh}{%s}" % fmt(get(rows, hi, d0, "verify")["latency_ms"]["mean"]),
        r"\newcommand{\firstLatLow}{%s}" % fmt(get(rows, lo, d0, "first")["latency_ms"]["mean"]),
        r"\newcommand{\firstLatHigh}{%s}" % fmt(get(rows, hi, d0, "first")["latency_ms"]["mean"]),
        r"\newcommand{\sizeLow}{%s}" % fmt(get(rows, lo, d0, "repeat")["artifact_kib"]["mean"]),
        r"\newcommand{\sizeHigh}{%s}" % fmt(get(rows, hi, d0, "repeat")["artifact_kib"]["mean"]),
        r"\newcommand{\margBoostMin}{%s}\newcommand{\margBoostMax}{%s}"
        % (fmt(100 * min(marg_boost)), fmt(100 * max(marg_boost))),
        r"\newcommand{\unifMin}{%s}\newcommand{\unifMax}{%s}"
        % (fmt(100 * min(unif)), fmt(100 * max(unif))),
    ]
    return "\n".join(lines)


def block_perftable(res):
    p = res["performance"]["parameters"]
    rows = perf_rows(res)
    out = []
    for n in p["candidate_sizes"]:
        f, rp, v = (get(rows, n, p["fixed_d"], w) for w in ("first", "repeat", "verify"))
        out.append("        %d & %s & %s & %s & %s & %s & %s \\\\" % (
            n, fmt(f["latency_ms"]["mean"]), fmt(rp["latency_ms"]["mean"]),
            fmt(v["latency_ms"]["mean"]), fmt(f["peak_traced_memory_kib"]["mean"], 0),
            fmt(v["peak_traced_memory_kib"]["mean"], 0), fmt(rp["artifact_kib"]["mean"])))
    return "\n".join(out)


def _coords(pairs):
    return " ".join("(%s,%s)" % (a, fmt(b, 2)) for a, b in pairs)


def block_perffigure(res):
    p = res["performance"]["parameters"]
    rows = perf_rows(res)
    out = []
    styles = {"first": "mark=*", "repeat": "mark=square*", "verify": "mark=triangle*"}
    names = {"first": "First presentation", "repeat": "Repeat presentation",
             "verify": "Verification"}
    out.append(r"\nextgroupplot[xlabel={Candidate-set size $n$ ($d=%d$)}, ylabel={Latency (ms)}, xmode=log, log basis x=10, xtick={50,100,200,500}, xticklabels={50,100,200,500}, legend to name=perflegend, legend columns=3]" % p["fixed_d"])
    for w in ("first", "repeat", "verify"):
        pts = [(n, get(rows, n, p["fixed_d"], w)["latency_ms"]["mean"]) for n in p["candidate_sizes"]]
        out.append(r"\addplot+[%s] coordinates {%s}; \addlegendentry{%s}" % (styles[w], _coords(pts), names[w]))
    out.append(r"\nextgroupplot[xlabel={Disclosed attributes $d$ ($n=%d$)}, ylabel={Latency (ms)}]" % p["fixed_n"])
    for w in ("first", "repeat", "verify"):
        pts = [(d, get(rows, p["fixed_n"], d, w)["latency_ms"]["mean"]) for d in p["attribute_counts"]]
        out.append(r"\addplot+[%s] coordinates {%s};" % (styles[w], _coords(pts)))
    return "\n".join(out)


def block_saliency(res):
    s = res["saliency"]["summary"]
    out = []
    for n in res["saliency"]["parameters"]["candidate_sizes"]:
        cells = []
        for gen in ("uniform", "marginal", "joint"):
            for clf in ("logistic", "boosting"):
                x = next(r for r in s if r["generator"] == gen and r["classifier"] == clf
                         and r["candidate_size"] == n)
                cell = fmt(x["top1_accuracy"], 4)
                if x["delta_ci95_low"] > 0:
                    cell = r"\textbf{%s}" % cell
                cells.append(cell)
        out.append("        %d & %s & %s \\\\" % (n, fmt(1 / n, 4), " & ".join(cells)))
    return "\n".join(out)


def comp_get(res, scheme, w, d):
    for r in res["comparison"]["summary"]:
        if r["scheme"] == scheme and r["workflow"] == w and r["disclosed"] == d:
            return r
    raise KeyError((scheme, w, d))


def block_compmacros(res):
    c = res["comparison"]
    ds = c["parameters"]["attribute_counts"]
    lo, hi = min(ds), max(ds)
    env = res["environment"]["packages"]
    lines = [
        r"\newcommand{\sdjwtVersion}{%s}" % env["sd-jwt"],
        r"\newcommand{\arkworksVersion}{%s}" % env["py_arkworks_bls12381"],
        r"\newcommand{\snarkjsVersion}{%s}" % c["versions"]["snarkjs"],
        r"\newcommand{\nodeVersion}{%s}" % c["versions"]["node"].lstrip("v"),
        r"\newcommand{\compReps}{%d}" % c["parameters"]["latency_reps"],
        r"\newcommand{\zkReps}{%d}" % c["parameters"]["zk_reps"],
        r"\newcommand{\compDLow}{%d}\newcommand{\compDHigh}{%d}" % (lo, hi),
        r"\newcommand{\oursIssue}{%s}" % fmt(comp_get(res, "proposed", "issue", None)["latency_ms"]["mean"], 2),
    ]
    tag = {"sd_jwt": "sdjwt", "bbs": "bbs", "zksnark": "zk"}
    for sch, t in tag.items():
        lines.append(r"\newcommand{\%sIssue}{%s}" % (t, fmt(comp_get(res, sch, "issue", None)["latency_ms"]["mean"], 2)))
        for d, suf in ((lo, "Low"), (hi, "High")):
            pr, vf = comp_get(res, sch, "present", d), comp_get(res, sch, "verify", d)
            lines.append(r"\newcommand{\%sPres%s}{%s}" % (t, suf, fmt(pr["latency_ms"]["mean"], 2)))
            lines.append(r"\newcommand{\%sVer%s}{%s}" % (t, suf, fmt(vf["latency_ms"]["mean"], 2)))
            lines.append(r"\newcommand{\%sSize%s}{%s}" % (t, suf, fmt(pr["artifact_kib"]["mean"], 2)))
    return "\n".join(lines)


def block_comptable(res):
    c = res["comparison"]
    ds = c["parameters"]["attribute_counts"]
    lo, hi = min(ds), max(ds)
    rows = perf_rows(res)
    n0 = res["performance"]["parameters"]["fixed_n"]
    out = []
    names = {"sd_jwt": r"SD-JWT~\cite{rfc9901}", "bbs": r"BBS~\cite{bbsdraft}",
             "zksnark": r"zk-SNARK (Groth16)~\cite{groth2016size}"}
    for sch, label in names.items():
        cells = [fmt(comp_get(res, sch, "issue", None)["latency_ms"]["mean"], 2)]
        cells += [fmt(comp_get(res, sch, "present", d)["latency_ms"]["mean"], 2) for d in (lo, hi)]
        cells += [fmt(comp_get(res, sch, "verify", d)["latency_ms"]["mean"], 2) for d in (lo, hi)]
        cells += [fmt(comp_get(res, sch, "present", d)["artifact_kib"]["mean"], 2) for d in (lo, hi)]
        out.append("        %s & %s \\\\" % (label, " & ".join(cells)))
    cells = [fmt(comp_get(res, "proposed", "issue", None)["latency_ms"]["mean"], 2)]
    cells += [fmt(get(rows, n0, d, "repeat")["latency_ms"]["mean"], 2) + ("$^{a}$" if d == hi else "") for d in (lo, hi)]
    cells += [fmt(get(rows, n0, d, "verify")["latency_ms"]["mean"], 2) for d in (lo, hi)]
    cells += [fmt(get(rows, n0, d, "repeat")["artifact_kib"]["mean"], 2) for d in (lo, hi)]
    out.append("        Ours ($n=%d$) & %s \\\\" % (n0, " & ".join(cells)))
    return "\n".join(out)


BLOCKS = {"macros": block_macros, "compmacros": block_compmacros, "comptable": block_comptable, "perftable": block_perftable,
          "perffigure": block_perffigure, "saliency": block_saliency}


def main():
    res = json.load(open(sys.argv[1], encoding="utf-8"))
    path = sys.argv[2]
    tex = open(path, encoding="utf-8").read()
    for name, fn in BLOCKS.items():
        pat = re.compile(r"(%% BEGIN AUTO:" + name + r"\n).*?(%% END AUTO:" + name + r")", re.S)
        if not pat.search(tex):
            sys.exit("marker for block '%s' not found" % name)
        body = fn(res)
        tex = pat.sub(lambda m: m.group(1) + body + "\n" + m.group(2), tex)
    open(path, "w", encoding="utf-8").write(tex)
    print("updated", path)


if __name__ == "__main__":
    main()
