"""SYNTHETIC TRAFFFIC GEN  """
import argparse, time
import yaml
from _common import ROOT, log
from uniaethel.config import load_config, seed_everything
from uniaethel.simulation.generate import generate




ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=42)
ap.add_argument("--backend", default="fast", choices=["fast", "scapy"]); ap.add_argument("--only", default=None)
a = ap.parse_args()
cfg = load_config(ROOT / "configs/default.yaml"); seed_everything(a.seed)
sc = cfg["scenarios"]; items = []
for split in ("train", "val", "test"):
    for e in sc["splits"][split]:
        for s in e["seeds"]:
            tag = "_".join(f"{k}{v}" for k, v in (e.get("params") or {}).items() if k != "dst")
            items.append((split, e["type"], s, e.get("params") or {}, f"data/{split}/{e['type']}{'_' + tag if tag else ''}_s{s}.pcap"))
for e in sc["splits"]["demo"]:
    items.append(("demo", e["type"], e["seeds"][0], e.get("params") or {}, f"data/demo/{e['name']}.pcap"))
for name, sw in sc["sweeps"].items():
    if "type" not in sw:
        continue
    for v in sw["values"]:
        for s in (301, 302):
            items.append(("sweep", sw["type"], s, {sw["param"]: v}, f"data/sweeps/{name}_{v}_s{s}.pcap"))
if a.only:
    items = [i for i in items if i[0] == a.only]
man = []; t0 = time.time()
for split, typ, seed, params, path in items:
    _, tr = generate(typ, seed, cfg, params, str(ROOT / path), backend=a.backend)
    ev = tr["events"][0] if tr["events"] else {}
    man.append({"file": path, "split": split, "scenario": typ, "seed": seed, "class": ev.get("cls", "BENIGN"),
                "malicious": ev.get("cls", "BENIGN") not in ("BENIGN",), "hard_negative_for": ev.get("hard_negative_for"),
                "host": ev.get("host"), "start": ev.get("t_start"), "end": ev.get("t_end"), "packets": tr["packets"],
                "duration_s": tr["duration"], "traffic_direction": "both directions present; processed as unpaired one-way observations",
                "generator_params": {k: v for k, v in (ev.get("params") or params).items()}})
    log.info("%-6s %-20s seed=%-4d pkts=%6d  %s", split, typ, seed, tr["packets"], path)
yaml.safe_dump({"generated_by": "scripts/generate_demo_data.py", "backend": a.backend, "synthetic": True,
                "captures": man}, open(ROOT / "data/MANIFEST.yaml", "w"), sort_keys=False)
log.info("%d captures in %.0f s -> data/MANIFEST.yaml", len(man), time.time() - t0)
