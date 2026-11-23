#!/usr/bin/env python3
"""Single entry point.  Edit only the settings block below, then run

    python main.py

All settings and results are written to results/results.json.
"""
# ============================ settings ============================
PROFILE = "paper"            # "paper" (full run) or "quick" (smoke test)
MACHINE_LABEL = None         # None: read CPU, memory and OS from this machine

PROFILES = {
    "paper": dict(network=dict(candidate_sizes=[50, 100, 200, 500], bandwidths_mbps=[10, 100],
                               rtts_ms=[20, 100], cache=["cold", "warm"], reps=10),
                  benchmark=dict(candidate_sizes=[50, 100, 200, 500],
                                 attribute_counts=list(range(1, 21)), repeats=100),
                  saliency=dict(candidate_sizes=[50, 100, 200, 500]),
                  comparison=dict(attribute_counts=[1, 5, 10, 15, 20], latency_reps=100,
                                  memory_reps=20, zk_reps=30)),
    "quick": dict(network=dict(candidate_sizes=[10, 50], bandwidths_mbps=[100],
                               rtts_ms=[20], cache=["cold", "warm"], reps=2),
                  benchmark=dict(candidate_sizes=[50], attribute_counts=[1, 20], repeats=2),
                  saliency=dict(candidate_sizes=[50]),
                  comparison=dict(attribute_counts=[1, 20], latency_reps=3, memory_reps=1, zk_reps=2)),
}
NETWORK = dict(handshake_rtts=2,          # new connection: TCP + TLS 1.3 handshake
               parallel_connections=8,    # connections used to fetch DID documents / status lists
               revoked_fraction=0.01,     # revoked entries in each issuer's status list
               disclosed_attributes=20)   # disclosed fields (as in Table 1)
RUN_NETWORK = True           # end-to-end network evaluation: Table 3
RUN_BENCHMARK = True         # protocol benchmark: Table 1, Table 2 (Ours), Figs. of attribute/candidate scaling
RUN_SALIENCY = True          # decoy-saliency study: Table 4 and its figure
RUN_COMPARISON = True        # SD-JWT, BBS+ and zk-SNARK: Table 2 (installs Node.js if missing)
SEED = 20261123
OUTPUT = "results/results.json"
# ==================================================================

import os
import sys

SUPPORTED = ((3, 12), (3, 13), (3, 11))    # the pinned packages have wheels for these


def _find_python():
    """Path of an installed Python 3.12 (else 3.13, 3.11), or None."""
    import glob
    import shutil
    import subprocess

    def works(cmd, ver):
        try:
            r = subprocess.run(cmd + ["-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                               capture_output=True, text=True, timeout=60)
            return r.returncode == 0 and r.stdout.strip() == "%d.%d" % ver
        except Exception:
            return False

    launcher = shutil.which("py")
    local = os.environ.get("LOCALAPPDATA", "")
    for ver in SUPPORTED:
        tag = "%d%d" % ver
        if launcher and works([launcher, "-%d.%d" % ver], ver):
            return [launcher, "-%d.%d" % ver]
        candidates = [os.path.join(local, "Programs", "Python", "Python" + tag, "python.exe"),
                      os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                   "Python" + tag, "python.exe"),
                      r"C:\Python" + tag + r"\python.exe",
                      os.path.join(local, "Microsoft", "WindowsApps", "python%d.%d.exe" % ver)]
        candidates += glob.glob(os.path.join(local, "Programs", "Python", "Python" + tag + "*", "python.exe"))
        found = shutil.which("python%d.%d" % ver)
        if found:
            candidates.append(found)
        for c in candidates:
            if c and os.path.isfile(c) and works([c], ver):
                return [c]
    return None


def _ensure_python():
    """Rerun this script with Python 3.12 (else 3.13 or 3.11) if started with
    another version; install Python 3.12 with winget if none is found."""
    if sys.version_info[:2] in SUPPORTED:
        return
    import shutil
    import subprocess
    here = sys.version_info[:2]
    if os.environ.get("DIDVC_RELAUNCHED"):
        sys.exit("The selected Python is %d.%d, not 3.12; install Python 3.12 and run again." % here)
    cmd = _find_python()
    if cmd is None and shutil.which("winget"):
        print("No Python 3.12 found (this is Python %d.%d); installing Python 3.12 for this user "
              "with winget ..." % here, flush=True)
        subprocess.call(["winget", "install", "-e", "--id", "Python.Python.3.12", "--scope", "user",
                         "--accept-package-agreements", "--accept-source-agreements"])
        cmd = _find_python()
    if cmd is None:
        sys.exit("Python 3.12 is required, but this is Python %d.%d and no Python 3.12 was found. "
                 "Install Python 3.12 from https://www.python.org/downloads/windows/ and run again." % here)
    print("Using %s for this run (this Python is %d.%d)." % (" ".join(cmd), here[0], here[1]), flush=True)
    env = dict(os.environ, DIDVC_RELAUNCHED="1")
    sys.exit(subprocess.call(cmd + sys.argv, env=env))


if __name__ == "__main__":
    _ensure_python()

import importlib
import json
import platform
import subprocess
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ["coincurve", "ecdsa", "numpy", "sklearn", "cryptography"]
COMPARISON_REQUIRED = ["sd_jwt", "jwcrypto", "py_arkworks_bls12381"]


def _missing():
    out = []
    for name in REQUIRED + (COMPARISON_REQUIRED if RUN_COMPARISON else []):
        try:
            importlib.import_module(name)
        except ImportError:
            out.append(name)
    return out


def _check_packages():
    missing = _missing()
    if missing:
        print("installing missing packages (%s) from requirements.txt ..." % ", ".join(missing))
        subprocess.call([sys.executable, "-m", "pip", "install", "-r",
                         os.path.join(HERE, "requirements.txt")])
        importlib.invalidate_caches()
        missing = _missing()
    if missing:
        sys.exit("Missing packages: %s. Run: python -m pip install -r requirements.txt"
                 % ", ".join(missing))


def _find_node_dir():
    """Folder of an installed node.exe (PATH, the usual install folders, nvm), or None."""
    import glob
    import shutil
    found = shutil.which("node")
    if found:
        return os.path.dirname(found)
    env = os.environ
    dirs = [os.path.join(env.get("ProgramFiles", r"C:\Program Files"), "nodejs"),
            os.path.join(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "nodejs"),
            os.path.join(env.get("LOCALAPPDATA", ""), "Programs", "nodejs"),
            env.get("NVM_SYMLINK", "")]
    dirs += sorted(glob.glob(os.path.join(env.get("APPDATA", ""), "nvm", "v*")), reverse=True)
    dirs += sorted(glob.glob(os.path.join(env.get("LOCALAPPDATA", ""), "Volta", "tools", "image",
                                          "node", "*")), reverse=True)
    for d in dirs:
        if d and (os.path.isfile(os.path.join(d, "node.exe")) or os.path.isfile(os.path.join(d, "node"))):
            return d
    return None


def _ensure_node():
    """Make node and npm usable by this run: find an installed Node.js and put
    its folder on PATH, or install Node.js LTS with winget and find it then."""
    import shutil
    import subprocess
    d = _find_node_dir()
    if d is None and shutil.which("winget"):
        print("Node.js not found; installing Node.js LTS with winget (confirm the prompt if one appears) ...",
              flush=True)
        subprocess.call(["winget", "install", "-e", "--id", "OpenJS.NodeJS.LTS",
                         "--accept-package-agreements", "--accept-source-agreements"])
        d = _find_node_dir()
    if d is None:
        return False
    if os.path.normcase(d) not in [os.path.normcase(p) for p in os.environ.get("PATH", "").split(os.pathsep)]:
        os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
    return shutil.which("node") is not None


def _check_node():
    """Node.js and the pinned snarkjs packages for the zk-SNARK comparison."""
    import shutil
    if not _ensure_node():
        sys.exit("Node.js was not found and could not be installed. Install Node.js 22 LTS from "
                 "https://nodejs.org (default options) and run again.")
    zk = os.path.join(HERE, "zk")
    if not os.path.isdir(os.path.join(zk, "node_modules", "snarkjs")):
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if npm is None:
            sys.exit("npm not found. Reinstall Node.js 22 LTS with the default options.")
        print("installing snarkjs and circomlibjs into zk/node_modules (one time) ...")
        if subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=zk).returncode != 0:
            sys.exit("npm ci failed; see the messages above")
        if not os.path.isdir(os.path.join(zk, "node_modules", "snarkjs")):
            sys.exit("snarkjs still missing after npm ci")


def _cpu_name():
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        if os.path.exists("/proc/cpuinfo"):
            for line in open("/proc/cpuinfo", encoding="utf-8", errors="ignore"):
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown CPU"


def _memory_gb():
    try:
        if platform.system() == "Windows":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong),
                            ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                            ("tp", ctypes.c_ulonglong), ("ap", ctypes.c_ulonglong),
                            ("tv", ctypes.c_ulonglong), ("av", ctypes.c_ulonglong),
                            ("ae", ctypes.c_ulonglong)]
            m = MS()
            m.len = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return round(m.total / 2 ** 30)
        return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2 ** 30)
    except Exception:
        return None


def _machine():
    cpu, mem = _cpu_name(), _memory_gb()
    if platform.system() == "Windows":
        osname = "Windows %s (build %s)" % (platform.release(), platform.version())
    else:
        osname = platform.platform()
    auto = ", ".join(x for x in (cpu, "%d GB" % mem if mem else None, osname) if x)
    return {"cpu": cpu, "memory_gb": mem, "os": osname, "logical_cpus": os.cpu_count(),
            "label": MACHINE_LABEL or auto}


def _versions():
    from importlib.metadata import version
    names = ["coincurve", "ecdsa", "numpy", "scikit-learn", "cryptography"]
    if RUN_COMPARISON:
        names += ["sd-jwt", "jwcrypto", "py_arkworks_bls12381"]
    return {p: version(p) for p in names}


def _run_script(args, result_path):
    """Run one of the original evaluation scripts and return its JSON output."""
    if subprocess.call([sys.executable, os.path.join(HERE, args[0])] + args[1:], cwd=HERE) != 0:
        sys.exit("%s failed" % args[0])
    with open(result_path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    _check_packages()
    if RUN_COMPARISON:
        _check_node()
    os.chdir(HERE)
    sys.path.insert(0, HERE)
    cfg = PROFILES[PROFILE]
    started = time.time()
    out = {"profile": PROFILE, "machine": _machine(),
           "environment": {"python": sys.version, "platform": platform.platform(),
                           "packages": _versions(), "curve": "secp256k1", "hash": "SHA-256"},
           "settings": {"profile": cfg, "network": NETWORK, "seed": SEED,
                        "run_network": RUN_NETWORK, "run_benchmark": RUN_BENCHMARK,
                        "run_saliency": RUN_SALIENCY, "run_comparison": RUN_COMPARISON}}

    print("[1] unit tests")
    suite = unittest.defaultTestLoader.loadTestsFromNames(["test_proposed_protocol", "test_netbench"]
                                                        + (["test_bbs"] if RUN_COMPARISON else []))
    res = unittest.TextTestRunner(verbosity=0).run(suite)
    if not res.wasSuccessful():
        sys.exit("unit tests failed; stopping")
    out["unit_tests_run"] = res.testsRun

    if RUN_NETWORK:
        import netbench
        print("[2] end-to-end network evaluation")
        out["network"] = netbench.run_network(dict(cfg["network"], **NETWORK), SEED,
                                              log=lambda s: print(s, flush=True))

    tmp = os.path.join(HERE, "results", "_original_scripts")
    if RUN_BENCHMARK:
        b = cfg["benchmark"]
        print("[3] performance benchmark (benchmark_candidate_sizes.py)")
        out["benchmark"] = _run_script(
            ["benchmark_candidate_sizes.py",
             "--candidate-sizes", ",".join(map(str, b["candidate_sizes"])),
             "--attribute-counts", ",".join(map(str, b["attribute_counts"])),
             "--repeats", str(b["repeats"]), "--output-dir", tmp],
            os.path.join(tmp, "results_for_paper.json"))
    if RUN_SALIENCY:
        s = cfg["saliency"]
        print("[4] decoy-saliency study (saliency_analysis.py)")
        out["saliency"] = _run_script(
            ["saliency_analysis.py", "--candidate-sizes", ",".join(map(str, s["candidate_sizes"])),
             "--output", os.path.join(tmp, "saliency_results.json")],
            os.path.join(tmp, "saliency_results.json"))

    if RUN_COMPARISON:
        import comparison
        c = cfg["comparison"]
        print("[5] comparison with SD-JWT, BBS and zk-SNARK (comparison.py)")
        out["comparison"] = comparison.run_comparison(c["attribute_counts"], c["latency_reps"],
                                                      c["memory_reps"], c["zk_reps"], SEED)

    out["elapsed_seconds"] = round(time.time() - started, 1)
    os.makedirs(os.path.dirname(os.path.join(HERE, OUTPUT)), exist_ok=True)
    with open(os.path.join(HERE, OUTPUT), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", OUTPUT, "in", out["elapsed_seconds"], "s")


if __name__ == "__main__":
    main()
