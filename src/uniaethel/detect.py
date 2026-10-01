"""Golden path for one capture: windows -> 4 engines -> evidence -> corroboration -> persistence
-> trajectory -> incidents -> attack-vector compatibility -> explainable alert -> forensic record."""
from __future__ import annotations

import hashlib
import json

import numpy as np
import pandas as pd

from .evaluation.metrics import build_evalset, incidents
from .forensics.ledger import Ledger
from .fusion.attack_vector import aggregate_incident, decide_class, window_scores
from .fusion.decision import PRIMARY, decide
from .fusion.trajectory import STATE_NAMES


def score_capture(cap: dict, bundle: dict, config_name: str = PRIMARY) -> tuple[pd.DataFrame, list[dict]]:
    pipe, frozen, cfg = bundle["pipe"], bundle["frozen"], bundle["cfg"]
    fz = frozen[config_name]
    ev = pipe.evidence(cap["pk"], cap["F"], cap["n_w"])
    es = build_evalset([ev], [cap["truth"] if cap["truth"].get("events") is not None else {"events": []}], cap["n_w"])
    alert, aux = decide(es, fz.config, fz.weights, fz.tau_sev, cfg, return_all=True, tau_dom=fz.tau_dom)
    T = es.extra.copy()
    T["host"] = [es.hosts[h] for h in es.host]; T["w"] = es.w
    for k in ("S_sev", "C_t", "P_t", "state"):
        T[k] = aux[k] if aux[k] is not None else 0
    T["state_name"] = T["state"].map(STATE_NAMES); T["alert"] = alert
    T = pd.concat([T, window_scores(T, cfg)], axis=1)
    inc = incidents(alert, es, cfg["decision"]["merge_gap"])
    recs = []
    av = bundle["attack_vector"]
    for i, r in inc.iterrows():
        host = es.hosts[int(r["host_code"])]
        seg = T[(T["host"] == host) & (T["w"] >= r["w_start"]) & (T["w"] <= r["w_end"])]
        agg = aggregate_incident(seg, cfg)
        cls = decide_class(agg, av["tau_class"], av["delta_margin"])
        recs.append({"incident": i, "host": host, "w_start": int(r["w_start"]), "w_end": int(r["w_end"]),
                     "counterparty": counterparty(cap["pk"], host, r["w_start"], r["w_end"], cfg),
                     "agg": agg, "cls": cls, "trajectory": trend(seg), "peak": seg.loc[seg["S_sev"].idxmax()]})
    return T, recs


def trend(seg: pd.DataFrame) -> str:
    s = seg["S_sev"].values
    if len(s) < 3:
        return "Stable"
    k = np.polyfit(np.arange(len(s)), s, 1)[0]
    return "Increasing" if k > 1e-3 else ("Decreasing" if k < -1e-3 else "Stable")


def counterparty(pk: pd.DataFrame, host: str, a: int, b: int, cfg: dict) -> dict:
    w = cfg["windowing"]["window_seconds"]
    o = pk[(pk["src"] == host) & (pk["ts"] > a - w) & (pk["ts"] <= b + 1)]
    i = pk[(pk["dst"] == host) & (pk["ts"] > a - w) & (pk["ts"] <= b + 1)]
    top = o.groupby("dst")["bytes"].agg(["size", "sum"]).sort_values("sum", ascending=False)
    return {"top_destination": top.index[0] if len(top) else None, "distinct_destinations": int(o["dst"].nunique()),
            "distinct_sources": int(i["src"].nunique()), "outbound_bytes": float(o["bytes"].sum()),
            "inbound_packets": int(len(i))}


def graph_snapshot_hash(pk: pd.DataFrame, host: str, a: int, b: int) -> str:
    e = pk[((pk["src"] == host) | (pk["dst"] == host)) & (pk["ts"] >= a) & (pk["ts"] <= b + 1)]
    edges = sorted(set(zip(e["src"], e["dst"])))
    return hashlib.sha256(json.dumps(edges).encode()).hexdigest()


def explain(rec: dict, tau_sev: float, cfg: dict) -> str:
    a, c, p = rec["agg"], rec["cls"], rec["peak"]
    L = [f"INCIDENT #{rec['incident']}", f"Host: {rec['host']}",
         f"Counterparty: {rec['counterparty']['top_destination']} "
         f"({rec['counterparty']['distinct_destinations']} destinations, {rec['counterparty']['distinct_sources']} sources seen)",
         f"Window: {rec['w_start']}-{rec['w_end']} s  (duration {a['duration_s']} s)", "",
         "Evidence vector (incident mean / max):"]
    for k, n in (("A_M", "Mahalanobis"), ("A_IF", "Isolation Forest"), ("A_TCN", "TCN"), ("A_G", "Graph")):
        L.append(f"  {n:17s} {a['A_mean'][k]:.2f} / {a['A_max'][k]:.2f}")
    L += [f"Behavioural anomaly severity (peak): {a['S_sev_max']:.2f}   (tau_sev {tau_sev:.3f}; not a probability)",
          f"Corroboration (mean): {a['C_mean']:.1f}/4   peak {int(p['C_t'])}/4",
          f"Persistence (mean): {a['P_mean']:.2f}", f"Trajectory: {rec['trajectory']}, peak state {p['state_name']}", "",
          "Attack-vector compatibility scores (not probabilities):"]
    for k, v in sorted(a["scores"].items(), key=lambda x: -x[1]):
        L.append(f"  {k:13s} {v:.3f}")
    L += ["", f"Classification: {c['display']}", "Reason:"] + [f"  - {r}" for r in c["reasons"]]
    L.append(f"  - multidomain corroboration {a['C_mean']:.1f}/4, persisted {a['duration_s']} s")
    return "\n".join(L)


def write_ledger(recs: list[dict], cap: dict, ledger_path: str, capture_name: str) -> Ledger:
    try:
        led = Ledger.load(ledger_path)
    except FileNotFoundError:
        led = Ledger()
    for r in recs:
        a = r["agg"]
        led.append(incident_id=f"{capture_name}#{r['incident']}", timestamp=float(r["w_start"]), host=r["host"],
                   destination=str(r["counterparty"]["top_destination"]), A_M=a["A_mean"]["A_M"], A_IF=a["A_mean"]["A_IF"],
                   A_TCN=a["A_mean"]["A_TCN"], A_G=a["A_mean"]["A_G"], S_sev=a["S_sev_max"], C_t=a["C_mean"],
                   P_t=a["P_mean"], state=str(r["peak"]["state_name"]), classification=r["cls"]["label"],
                   class_scores={k: round(v, 6) for k, v in a["scores"].items()},
                   key_features={k: round(v, 4) for k, v in a["phi"].items()},
                   graph_snapshot_hash=graph_snapshot_hash(cap["pk"], r["host"], r["w_start"], r["w_end"]))
    led.save(ledger_path)
    return led
