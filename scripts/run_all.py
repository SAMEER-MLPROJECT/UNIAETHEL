import subprocess, sys
from _common import ROOT
steps = ["generate_demo_data.py", "train_models.py", "run_demo.py", "run_ablation.py", "run_robustness.py", "benchmark.py",
         "build_dashboard.py", "make_docs.py"]

for s in steps:
    print(f"==> {s}", flush=True); subprocess.run([sys.executable, str(ROOT / "scripts" / s)], check=True)
subprocess.run([sys.executable, str(ROOT / "scripts/verify_ledger.py"), "--tamper-test"], check=True)
subprocess.run([sys.executable, "-m", "pytest", "-q", str(ROOT / "tests")], check=True)
