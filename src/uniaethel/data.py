"""Capture loading: pcap -> packets -> directional flows -> windows (cached by file hash + mode)."""
from __future__ import annotations

import hashlib
import json
import pickle
from pathlib import Path

import numpy as np

from .capture.pcap import read_pcap
from .config import ROOT
from .features.windows import extract_windows
from .flows.flows import build_flows


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_capture(pcap: str, cfg: dict, mode: str | None = None, loss: float = 0.0, baseline: dict | None = None,
                 use_cache: bool = True) -> dict:
    mode = mode or cfg["observation"]["mode"]
    truth_p = Path(pcap.replace(".pcap", ".truth.json"))
    truth = json.load(open(truth_p)) if truth_p.exists() else {"events": [], "duration": None}
    key = f"{Path(pcap).name}|{mode}|{loss}|{bool(baseline)}"
    cache = ROOT / "results/cache" / (hashlib.md5(key.encode()).hexdigest() + ".pkl")
    if use_cache and cache.exists():
        d = pickle.load(open(cache, "rb"))
        if d.get("pcap_sha") == sha256_file(pcap):
            return d
    pk = read_pcap(pcap, cfg, mode=mode, loss=loss, loss_seed=7)
    pk, flows = build_flows(pk, cfg)
    dur = truth.get("duration") or float(np.ceil(pk["ts"].max()))
    n_w = int(np.ceil(dur / cfg["windowing"]["step_seconds"]))
    F = extract_windows(pk, cfg, n_w=n_w, baseline=baseline)
    d = {"pk": pk, "flows": flows, "F": F, "n_w": n_w, "truth": truth, "path": pcap, "pcap_sha": sha256_file(pcap),
         "mode": mode, "loss": loss}
    if use_cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        pickle.dump(d, open(cache, "wb"))
    return d


def split_files(cfg: dict, split: str) -> list[str]:
    import yaml
    man = yaml.safe_load(open(ROOT / "data/MANIFEST.yaml"))
    return [str(ROOT / c["file"]) for c in man["captures"] if c["split"] == split]
