# Reproducibility
Seeds: scenario seeds in configs/scenarios.yaml; global seed 42 (Python, NumPy, scikit-learn, TCN, Louvain).
`python scripts/run_all.py` regenerates data, retrains, freezes (results/FREEZE.txt: SHA-256 of all thresholds/weights,
written before the test split is scored), and regenerates every result, figure and document. Data hashes: data/MANIFEST.yaml
+ cached pcap SHA-256 in the loader. Environment: requirements.txt; measured on Python 3.12, one CPU core.
