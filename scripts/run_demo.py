import json, pickle
import networkx as nx
import numpy as np
from _common import ROOT, log
from uniaethel.data import load_capture
from uniaethel.detect import explain, score_capture, write_ledger
from uniaethel.fusion.decision import PRIMARY

b = pickle.load(open(ROOT / "results/models/bundle.pkl", "rb")); cfg = b["cfg"]; base = b["pipe"].baseline_relationships
EXPECT = {"demo1_c2": "C2", "demo2_recon": "RECON", "demo3_ddos": "DDOS", "demo4_exfil": "EXFIL", "demo5_unknown": "UNKNOWN"}
ledger = str(ROOT / "results/ledger.json"); (ROOT / "results/ledger.json").unlink(missing_ok=True)
dash = {"primary": PRIMARY, "tau_sev": b["frozen"][PRIMARY].tau_sev, "attack_vector": b["attack_vector"], "demos": []}
report = []
for name, exp in EXPECT.items():
    cap = load_capture(str(ROOT / f"data/demo/{name}.pcap"), cfg, baseline=base)
    T, recs = score_capture(cap, b)
    ev = cap["truth"]["events"][0]; host = ev["host"]
    mine = [r for r in recs if r["host"] == host and r["w_end"] >= ev["t_start"] and r["w_start"] <= ev["t_end"] + 30]
    main = max(mine, key=lambda r: r["w_end"] - r["w_start"]) if mine else None
    got = main["cls"]["label"] if main else "NOT DETECTED"
    others = len(recs) - len(mine)
    line = f"{name}: expected {exp:8s} got {got:13s} (incidents on {host}: {len(mine)}; other hosts: {others})"
    log.info(line); report.append(line)
    if main:
        txt = explain(main, b["frozen"][PRIMARY].tau_sev, cfg); print("\n" + txt + "\n"); report.append(txt)
    write_ledger(mine, cap, ledger, name)
    h = T[T["host"] == host]
    snap = {}
    if main:                                   
        pk = cap["pk"]; a, z = main["w_start"], main["w_end"]
        cur = pk[((pk.src == host) | (pk.dst == host)) & (pk.ts >= a) & (pk.ts <= z)]
        prev = pk[((pk.src == host) | (pk.dst == host)) & (pk.ts < a) & (pk.ts >= max(0, a - 60))]
        E = cur.groupby(["src", "dst"])["bytes"].agg(["size", "sum"]).reset_index().sort_values("size", ascending=False).head(40)
        pe = set(zip(prev.src, prev.dst))
        G = nx.Graph(); G.add_weighted_edges_from([(s, d, np.log1p(w)) for s, d, w in zip(E.src, E.dst, E["sum"])])
        comm = {n: i for i, c in enumerate(nx.community.louvain_communities(G, seed=42)) for n in c} if G.number_of_edges() else {}
        pos = nx.spring_layout(G, seed=3) if len(G) else {}
        snap = {"nodes": [{"id": n, "x": float(p[0]), "y": float(p[1]), "c": comm.get(n, 0), "focus": n == host} for n, p in pos.items()],
                "edges": [{"s": s, "d": d, "n": int(k), "new": (s, d) not in pe} for s, d, k in zip(E.src, E.dst, E["size"])]}
    dash["demos"].append({"name": name, "expected": exp, "got": got, "host": host, "t_start": ev["t_start"], "t_end": ev["t_end"],
        "series": {k: np.round(h[k].values.astype(float), 4).tolist() for k in
                   ["A_M", "A_IF", "A_TCN", "A_G", "S_sev", "C_t", "P_t", "state", "S_C2", "S_RECON", "S_DDOS", "S_EXFIL"]},
        "incident": None if not main else {"w_start": main["w_start"], "w_end": main["w_end"], "counterparty": main["counterparty"],
                                            "trajectory": main["trajectory"], "scores": main["agg"]["scores"], "A_mean": main["agg"]["A_mean"],
                                            "C_mean": main["agg"]["C_mean"], "P_mean": main["agg"]["P_mean"], "S_sev_max": main["agg"]["S_sev_max"],
                                            "cls": main["cls"], "text": explain(main, b["frozen"][PRIMARY].tau_sev, cfg)},
        "graph": snap})
json.dump(dash, open(ROOT / "results/demo_results.json", "w"), default=float)
(ROOT / "results/demo_report.txt").write_text("\n\n".join(report))
from uniaethel.forensics.ledger import Ledger
ok, bad = Ledger.load(ledger).verify(); log.info("ledger %s: %d records, %s", ledger, len(Ledger.load(ledger).records), "INTACT" if ok else f"BROKEN at {bad}")
