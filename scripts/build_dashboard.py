
import json
from _common import ROOT
from uniaethel.forensics.ledger import Ledger

D = json.load(open(ROOT / "results/demo_results.json")); led = Ledger.load(str(ROOT / "results/ledger.json")); ok, bad = led.verify()
D.update(ledger=led.records, ledger_ok=ok, ledger_bad=bad)

html = open(ROOT / "app/dashboard_template.html").read().replace("/*__DATA__*/", "const D=" + json.dumps(D) + ";")
open(ROOT / "results/dashboard.html", "w").write(html); print("results/dashboard.html", len(html) // 1024, "KB")
