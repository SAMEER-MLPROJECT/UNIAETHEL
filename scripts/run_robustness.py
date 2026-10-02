"""Robustness sweeps with the FROZEN system (sweep seeds never used elsewhere).
    python scripts/run_robustness.py  -> results/robustness.json + results/figures/robustness.png"""
import json, pickle, glob
import numpy as np
from _common import ROOT, log
from uniaethel.evaluation.runner import classify_incidents, evidence_for
from uniaethel.fusion.decision import PRIMARY, evaluate

b = pickle.load(open(ROOT / "results/models/bundle.pkl", "rb")); pipe, fr, cfg, av = b["pipe"], b["frozen"], b["cfg"], b["attack_vector"]
base = pipe.baseline_relationships; fz = fr[PRIMARY]; res = {}
def run(files, loss=0.0):
    caps, evs, es = evidence_for(files, pipe, cfg, baseline=base, loss=loss)
    r = evaluate(es, fz, cfg); inc = classify_incidents(es, fz, cfg, av["tau_class"], av["delta_margin"])
    mal = inc[inc["truth"] != "BENIGN"]
    return {"detected": int(sum(p["detected"] for p in r["per_episode"])), "episodes": len(r["per_episode"]),
            "correct_label": int((mal["pred"] == mal["truth"]).sum()), "labelled_incidents": len(mal),
            "false_alerts": int(r["false_incidents"]), "latency_median_s": r["latency_median_s"]}
for name, sw in cfg["scenarios"]["sweeps"].items():
    if "type" not in sw:
        continue
    res[name] = {"param": sw["param"], "points": {}}
    for v in sw["values"]:
        res[name]["points"][str(v)] = run(sorted(glob.glob(str(ROOT / f"data/sweeps/{name}_{v}_s*.pcap"))))
        log.info("%-12s %s=%-5s %s", name, sw["param"], v, res[name]["points"][str(v)])
res["packet_loss"] = {"param": "loss", "points": {}}
demo = [str(ROOT / f"data/demo/{n}.pcap") for n in ("demo1_c2", "demo2_recon", "demo3_ddos", "demo4_exfil")]
for L in cfg["scenarios"]["sweeps"]["packet_loss"]["values"]:
    res["packet_loss"]["points"][str(L)] = run(demo, loss=L)
    log.info("packet_loss %.1f %s", L, res["packet_loss"]["points"][str(L)])
res["observation_mode"] = "NOT RUN: engines are trained on the unpaired view; egress/ingress-only need their own baselines (future work)"
json.dump(res, open(ROOT / "results/robustness.json", "w"), indent=1, default=float)
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
fig, ax = plt.subplots(1, 5, figsize=(16, 3))
for a, (k, t) in zip(ax, [("c2_jitter", "C2 jitter"), ("recon_speed", "Recon end rate (probes/s)"), ("ddos_volume", "DDoS peak pps"),
                          ("exfil_speed", "Exfil MB"), ("packet_loss", "Packet loss")]):
    P = res[k]["points"]; xs = list(P)
    a.plot(xs, [P[x]["detected"] / max(P[x]["episodes"], 1) for x in xs], "o-", label="detected")
    a.plot(xs, [P[x]["correct_label"] / max(P[x]["episodes"], 1) for x in xs], "s--", label="correct label")
    a.set_ylim(-0.05, 1.05); a.set_title(t, fontsize=9)
ax[0].legend(fontsize=7); fig.tight_layout(); (ROOT / "results/figures").mkdir(parents=True, exist_ok=True)
fig.savefig(ROOT / "results/figures/robustness.png", dpi=120)
