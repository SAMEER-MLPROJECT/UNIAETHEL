
import json, pickle
import numpy as np, pandas as pd, yaml
from _common import ROOT, log
from uniaethel.data import split_files
from uniaethel.evaluation.runner import classify_incidents, evidence_for
from uniaethel.fusion.decision import PRIMARY, evaluate

b = pickle.load(open(ROOT / "results/models/bundle.pkl", "rb")); pipe, fr, cfg, av = b["pipe"], b["frozen"], b["cfg"], b["attack_vector"]
man = {c["file"]: c for c in yaml.safe_load(open(ROOT / "data/MANIFEST.yaml"))["captures"]}
files = split_files(cfg, "test")
caps, evs, es = evidence_for(files, pipe, cfg, baseline=pipe.baseline_relationships)
rel = lambda f: str(f).replace(str(ROOT) + "/", "")
hn = np.array([bool(man[rel(c["path"])]["hard_negative_for"]) for c in caps])
h_norm = (~hn).sum() * cfg["scenarios"]["duration_s"] / 3600; h_hn = hn.sum() * cfg["scenarios"]["duration_s"] / 3600
out = {"test_captures": len(caps), "hours_normal_and_attack": h_norm, "hours_lookalike": h_hn, "configs": {}}
for name, fz in fr.items():
    r = evaluate(es, fz, cfg)
    fi = r["incidents_df"][r["false_mask"]]
    in_hn = hn[fi["cap"].values] if len(fi) else np.array([], bool)
    pe = pd.DataFrame(r["per_episode"])
    known = pe[pe["family"].isin(["C2", "RECON", "DDOS", "EXFIL"])]
    out["configs"][name] = {"detected": int(pe["detected"].sum()), "episodes": len(pe), "recall": r["recall"],
        "known_detected": int(known["detected"].sum()), "known_episodes": len(known),
        "precision": r["precision"], "f1": r["f1"], "false_normal": int((~in_hn).sum()), "fp_per_hour_normal": float((~in_hn).sum() / h_norm),
        "false_lookalike": int(in_hn.sum()), "fp_per_hour_lookalike": float(in_hn.sum() / h_hn),
        "latency_median_s": r["latency_median_s"], "latency_p95_s": r["latency_p95_s"],
        "recall_by_class": pe.groupby("family")["detected"].agg(lambda x: f"{int(x.sum())}/{len(x)}").to_dict(),
        "tau_sev": fz.tau_sev}
    c = out["configs"][name]
    log.info("%-26s detected %2d/%d  prec %.2f  F1 %.2f  false/h normal %.2f  look-alike alerts %d  lat %s s",
             name, c["detected"], c["episodes"], c["precision"] or 0, c["f1"], c["fp_per_hour_normal"], c["false_lookalike"],
             f"{c['latency_median_s']:.0f}" if c["latency_median_s"] == c["latency_median_s"] else "-")
json.dump(out, open(ROOT / "results/ablation.json", "w"), indent=1, default=float)

inc = classify_incidents(es, fr[PRIMARY], cfg, av["tau_class"], av["delta_margin"])
mal = inc[inc["truth"] != "BENIGN"]
labels = ["C2", "RECON", "DDOS", "EXFIL", "UNKNOWN"]
cm = pd.crosstab(mal["truth"], mal["pred"]).reindex(index=labels, columns=labels, fill_value=0)
known = mal[mal["truth"].isin(labels[:4])]; unk = mal[mal["truth"] == "UNKNOWN"]
look = inc[(inc["truth"] == "BENIGN")]
cls = {"primary": PRIMARY, "tau_class": av["tau_class"], "delta_margin": av["delta_margin"],
       "confusion": cm.to_dict(), "known_incidents": len(known),
       "known_correct": int((known["pred"] == known["truth"]).sum()),
       "known_rejected_as_unknown": int((known["pred"] == "UNKNOWN").sum()),
       "unknown_incidents": len(unk), "unknown_rejected": int((unk["pred"] == "UNKNOWN").sum()),
       "per_class": {k: {"precision": float(cm.loc[k, k] / cm[k].sum()) if cm[k].sum() else None,
                         "recall": float(cm.loc[k, k] / cm.loc[k].sum()) if cm.loc[k].sum() else None} for k in labels},
       "lookalike_alert_labels": look.groupby(["scenario", "pred"]).size().rename("n").reset_index().to_dict("records"),
       "incidents": inc.drop(columns=["_agg"]).to_dict("records")}
json.dump(cls, open(ROOT / "results/classification.json", "w"), indent=1, default=float)
log.info("classification: known %d/%d correct (%d rejected as unknown); unknown rejected %d/%d",
         cls["known_correct"], cls["known_incidents"], cls["known_rejected_as_unknown"], cls["unknown_rejected"], cls["unknown_incidents"])
log.info("confusion (rows=truth, cols=pred):\n%s", cm.to_string())
