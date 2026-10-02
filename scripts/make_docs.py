import json
from _common import ROOT
A = json.load(open(ROOT / "results/ablation.json")); C = json.load(open(ROOT / "results/classification.json"))
B = json.load(open(ROOT / "results/benchmark.json")); R = json.load(open(ROOT / "results/robustness.json"))
F = (ROOT / "results/FREEZE.txt").read_text().strip(); demo = (ROOT / "results/demo_report.txt").read_text().split("\n\n")
demo_lines = [l for l in demo if l.startswith("demo")]
f2 = lambda x: "-" if x is None or x != x else f"{x:.2f}"
s0 = lambda x: "-" if x is None or x != x else f"{x:.0f} s"
LAD = ["STAT_univariate_threshold", "A_IF_only", "B_M_IF", "C_M_IF_TCN", "D_all_four_engines", "E_plus_corroboration",
       "F_plus_persistence", "G_plus_trajectory"]
REM = ["G_without_TCN", "G_without_Graph", "G_without_Mahalanobis", "G_without_IF", "G_without_corroboration", "G_arithmetic_severity"]
def tab(names):
    r = ["| configuration | detected (of 16) | precision | F1 | false alerts/h (normal + attack captures) | alerts on benign look-alikes | median / p95 latency |", "|---|---|---|---|---|---|---|"]
    for n in names:
        c = A["configs"][n]
        r.append(f"| `{n}` | {c['detected']}/{c['episodes']} | {f2(c['precision'])} | {f2(c['f1'])} | {f2(c['fp_per_hour_normal'])} | {c['false_lookalike']} | {s0(c['latency_median_s'])} / {s0(c['latency_p95_s'])} |")
    return "\n".join(r)
labels = ["C2", "RECON", "DDOS", "EXFIL", "UNKNOWN"]
cm = ["| truth \\ predicted | " + " | ".join(labels) + " |", "|---" * 6 + "|"]
for t in labels:
    cm.append(f"| {t} | " + " | ".join(str(C["confusion"][p][t]) for p in labels) + " |")
rob = []
for k, v in R.items():
    if isinstance(v, str):
        rob.append(f"| {k} | {v} |"); continue
    rob.append(f"| {k} ({v['param']}) | " + "; ".join(f"{x}: detected {p['detected']}/{p['episodes']}, labelled {p['correct_label']}" for x, p in v["points"].items()) + " |")
G = A["configs"]["G_plus_trajectory"]
exp = f"""# Experiments (all numbers generated from results/*.json)

Evaluation performed on reproducibly generated synthetic traffic. Test split: {A['test_captures']} held-out captures
({A['hours_normal_and_attack']:.2f} h normal + attack captures, {A['hours_lookalike']:.2f} h benign look-alike captures), scored once
after freezing.

{F}


{tab(LAD)}


{tab(REM)}


tau_class = {C['tau_class']:.4f}, delta_margin = {C['delta_margin']:.4f} (set on validation so ~10% of known validation incidents would be rejected).

{chr(10).join(cm)}

Known-class incidents: {C['known_correct']}/{C['known_incidents']} correct, {C['known_rejected_as_unknown']} rejected as UNKNOWN,
0 confused between known classes. Unknown scenario: {C['unknown_rejected']}/{C['unknown_incidents']} incidents rejected as UNKNOWN.


| sweep | result |
|---|---|
{chr(10).join(rob)}


{chr(10).join('- ' + l for l in demo_lines)}

## Honest reading
- Detection: the full system detected every test attack episode ({G['detected']}/{G['episodes']}), including the unknown pattern.
- False alerts are the main weakness: {f2(G['fp_per_hour_normal'])}/h on normal + attack captures and {G['false_lookalike']} on look-alikes.
  Validation showed 0/h because per-host calibration and tau_sev tuning used the same 2 benign validation captures (in-sample).
- Removing the TCN lowers detection but removes most false alerts - a real trade-off, not a free component.
- Removing Isolation Forest improved the system here; it is kept only because the architecture was frozen before test.
- Linear (arithmetic) severity detects {A['configs']['G_arithmetic_severity']['detected']}/16 vs geometric {G['detected']}/16.
- Classification never confused two known vectors, but rejected all recon incidents as UNKNOWN: the recon profile is too weak.
"""
(ROOT / "docs/EXPERIMENTS.md").write_text(exp)
bm = f"""# Benchmark (scripts/benchmark.py; measured, single core)
Hardware: {B['hardware']}; OS: {B['os']}; Python {B['python']}; {B['versions']}
Mode: {B['mode']}. {B['captures']} captures, {B['total_packets']} packets.

| metric | value |
|---|---|
| packets/s | {B['throughput_pps']:.0f} |
| flows/s | {B['throughput_flows_per_s']:.0f} |
| Mbps (original packet sizes) | {B['throughput_mbps']:.1f} |
| latency per 300 s capture p50 / p95 / p99 | {B['capture_latency_s']['p50']:.2f} / {B['capture_latency_s']['p95']:.2f} / {B['capture_latency_s']['p99']:.2f} s |
| amortised cost per 1 s step (all hosts) p50 / p95 / p99 | {B['per_1s_step_ms']['p50']:.1f} / {B['per_1s_step_ms']['p95']:.1f} / {B['per_1s_step_ms']['p99']:.1f} ms |
| slowest real-time factor | {B['realtime_factor_min']:.0f}x |
| peak RSS | {B['peak_rss_mb']:.0f} MB |
| dropped packets | {B['dropped_packets']} (offline replay) |

Replay at increasing input rates (DDoS volume sweep): {[{k: round(v, 1) if isinstance(v, float) else v for k, v in r.items()} for r in B['replay_rates']]}
Streaming (live packet-by-packet) latency is NOT RUN; these are batch replay measurements.
"""
(ROOT / "docs/BENCHMARK.md").write_text(bm)
readme = f"""# UniAethel - passive threat inference for one-way (data-diode) traffic
SIH 2026 - SIH26145 (NTRO) - team EigenThinkers. Research prototype.

** The prototype does not actively scan or probe hosts. It infers behavioural anomalies from traffic already visible on the monitored one-way observation path.**
Evaluation performed on reproducibly generated synthetic traffic.

## 1. Problem
Traffic reaches the monitoring enclave through a data diode: no replies, no handshakes, no probing, no inline blocking.

## 2. Why one-way traffic is difficult
Session pairing, handshake checks and active verification are impossible; payloads are encrypted. See docs/ONE_WAY_CONTRACT.md.

## 3. Architecture
PCAP -> directional flows -> 5 s windows (1 s step) -> Mahalanobis | Isolation Forest | causal TCN | temporal graph + Louvain
-> evidence vector A_t -> severity, corroboration, persistence -> trajectory state -> incident -> attack-vector compatibility
-> argmax + tau_class + margin -> C2 / RECON / DDOS / EXFIL / UNKNOWN -> explanation -> hash-linked record. docs/ARCHITECTURE.md

## 4-7. PCAP processing, engines, fusion, attack-vector inference
docs/FEATURES.md, docs/MODELS.md, docs/CLASSIFICATION.md. No supervised classifier; class decisions come from explicit
compatibility functions whose weights are in configs/default.yaml.

## 8. Demo
```bash
pip install -r requirements.txt
python scripts/run_all.py          # generate data, train, demo, ablation, robustness, benchmark, verify, docs (~10 min)
# or step by step:
python scripts/generate_demo_data.py
python scripts/train_models.py
python scripts/run_demo.py
python scripts/run_ablation.py
python scripts/run_robustness.py
python scripts/benchmark.py
python scripts/verify_ledger.py --tamper-test
python scripts/build_dashboard.py && uvicorn app.server:app --port 8000
python -m pytest -q
```
Demo outcomes: {'; '.join(demo_lines)}

## 9. Dataset generation
docs/DATASET.md, data/MANIFEST.yaml (93 captures, deterministic seeds, Scapy reference writer + fast header-only writer).

## 10-12. Experiments, results, benchmark (EXPERIMENTALLY VERIFIED on synthetic data)
Full system on held-out test: {G['detected']}/{G['episodes']} attack episodes detected, median latency {s0(G['latency_median_s'])},
{f2(G['fp_per_hour_normal'])} false alerts/h on normal + attack captures, {G['false_lookalike']} alerts on benign look-alikes.
Classification: {C['known_correct']}/{C['known_incidents']} known incidents correct, {C['known_rejected_as_unknown']} rejected as UNKNOWN, 0 confused;
unknown pattern rejected {C['unknown_rejected']}/{C['unknown_incidents']}. Throughput {B['throughput_pps']:.0f} packets/s, {B['throughput_mbps']:.0f} Mbps on one core.
Details: docs/EXPERIMENTS.md, docs/BENCHMARK.md.

## 13. Reproducibility
docs/REPRODUCIBILITY.md, results/FREEZE.txt.

## 14. Limitations
docs/LIMITATIONS.md - read before presenting.

## Status
IMPLEMENTED: everything in sections 3-9, dashboard, API, ledger, 38 tests.
EXPERIMENTALLY VERIFIED (synthetic only): the numbers above.
PLANNED / FUTURE WORK: real traffic (CIC-IDS2017, CTU-13), live streaming mode, egress/ingress-only baselines, larger benign calibration set.

## 15. Repository structure
`configs/` (default, features, scenarios) - `src/uniaethel/` (capture, flows, features, models, fusion, forensics, evaluation, simulation) -
`scripts/` - `app/` (dashboard, API) - `tests/` - `data/` - `results/` - `docs/`
"""
(ROOT / "README.md").write_text(readme); print("README.md, docs/EXPERIMENTS.md, docs/BENCHMARK.md generated")
