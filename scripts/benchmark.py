
import json, pickle, platform, resource, time, glob
import numpy as np, psutil, sklearn, networkx, pandas as pd
from _common import ROOT, log
from uniaethel.data import load_capture
from uniaethel.detect import score_capture

b = pickle.load(open(ROOT / "results/models/bundle.pkl", "rb")); cfg = b["cfg"]; base = b["pipe"].baseline_relationships
files = sorted(glob.glob(str(ROOT / "data/test/*.pcap")))[:12] + sorted(glob.glob(str(ROOT / "data/sweeps/ddos_volume_*_s301.pcap")))
rows = []; proc = psutil.Process(); c0 = proc.cpu_times(); t0 = time.perf_counter()
for f in files:
    t = time.perf_counter()
    cap = load_capture(f, cfg, baseline=base, use_cache=False); t_ing = time.perf_counter() - t
    T, recs = score_capture(cap, b); dt = time.perf_counter() - t
    pk = cap["pk"]; dur = cfg["scenarios"]["duration_s"]
    rows.append({"file": f.split("/")[-1], "packets": len(pk), "flows": len(cap["flows"]), "input_pps": len(pk) / dur,
                 "seconds": dt, "ingest_s": t_ing, "pps": len(pk) / dt, "flows_per_s": len(cap["flows"]) / dt,
                 "mbps": pk["bytes"].sum() * 8 / 1e6 / dt, "window_steps": cap["n_w"], "per_step_ms": 1e3 * dt / cap["n_w"],
                 "realtime_factor": dur / dt})
    log.info("%-40s %6d pkts  %.2f s  %7.0f pps  %.0fx real time", rows[-1]["file"], len(pk), dt, rows[-1]["pps"], dur / dt)
wall = time.perf_counter() - t0; c1 = proc.cpu_times(); df = pd.DataFrame(rows)
res = {"hardware": {"cpu": platform.processor() or platform.machine(), "cores": psutil.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 1e9, 1)},
       "os": platform.platform(), "python": platform.python_version(),
       "versions": {"numpy": np.__version__, "pandas": pd.__version__, "scikit-learn": sklearn.__version__, "networkx": networkx.__version__},
       "mode": "batch replay of 300 s captures, single process, parse+flows+windows+4 engines+fusion+classification",
       "captures": len(df), "total_packets": int(df["packets"].sum()),
       "throughput_pps": float(df["packets"].sum() / df["seconds"].sum()), "throughput_flows_per_s": float(df["flows"].sum() / df["seconds"].sum()),
       "throughput_mbps": float((df["mbps"] * df["seconds"]).sum() / df["seconds"].sum()),
       "capture_latency_s": {"p50": float(df["seconds"].quantile(.5)), "p95": float(df["seconds"].quantile(.95)), "p99": float(df["seconds"].quantile(.99))},
       "per_1s_step_ms": {"p50": float(df["per_step_ms"].quantile(.5)), "p95": float(df["per_step_ms"].quantile(.95)), "p99": float(df["per_step_ms"].quantile(.99))},
       "realtime_factor_min": float(df["realtime_factor"].min()), "cpu_utilisation": (c1.user - c0.user + c1.system - c0.system) / wall,
       "peak_rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, "dropped_packets": 0,
       "replay_rates": df[df["file"].str.startswith("ddos_volume")][["file", "input_pps", "pps", "realtime_factor"]].to_dict("records")}
json.dump(res, open(ROOT / "results/benchmark.json", "w"), indent=1, default=float)
log.info("pps %.0f  flows/s %.0f  Mbps %.1f  p50/p95/p99 capture latency %s  peak RSS %.0f MB", res["throughput_pps"],
         res["throughput_flows_per_s"], res["throughput_mbps"], res["capture_latency_s"], res["peak_rss_mb"])
