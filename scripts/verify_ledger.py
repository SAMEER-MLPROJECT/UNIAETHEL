import argparse, copy, sys, time
from _common import ROOT
from uniaethel.forensics.ledger import Ledger
ap = argparse.ArgumentParser(); ap.add_argument("--ledger", default=str(ROOT / "results/ledger.json")); ap.add_argument("--tamper-test", action="store_true")
a = ap.parse_args(); led = Ledger.load(a.ledger)
t = time.perf_counter(); ok, bad = led.verify(); ms = 1e3 * (time.perf_counter() - t)
print(f"{len(led.records)} records verified in {ms:.2f} ms: " + ("INTACT" if ok else f"BROKEN at record {bad}"))
if a.tamper_test and led.records:
    for field in ("classification", "S_sev", "host"):
        t2 = copy.deepcopy(led); r = t2.records[len(t2.records) // 2]["event"]
        r[field] = "C2" if field == "classification" and r[field] != "C2" else (0.0 if field == "S_sev" else "10.9.9.9")
        print(f"  tamper '{field}' in record {len(t2.records)//2}: detected -> {not t2.verify()[0]} (breaks at {t2.verify()[1]})")
    t3 = copy.deepcopy(led); del t3.records[0]; print(f"  delete record 0: detected -> {not t3.verify()[0]}")
sys.exit(0 if ok else 1)
