
from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path
from typing import Any
import numpy as np
import yaml

ROOT = Path(__file__).resolve().parents[2]

def load_config(path: str | os.PathLike = "configs/default.yaml") -> dict[str, Any]:
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    cfg = yaml.safe_load(p.read_text())
    cfg["scenarios"] = yaml.safe_load((p.parent / "scenarios.yaml").read_text())
    cfg["features_registry"] = yaml.safe_load((p.parent / "features.yaml").read_text())["features"]
    for k, v in cfg["paths"].items():
        cfg["paths"][k] = str(ROOT / v)
        Path(cfg["paths"][k]).mkdir(parents=True, exist_ok=True)
    return cfg


def config_hash(cfg: dict[str, Any]) -> str:
    c = {k: v for k, v in cfg.items() if k != "paths"}
    return hashlib.sha256(json.dumps(c, sort_keys=True, default=str).encode()).hexdigest()


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)

import ipaddress as _ip

def internal_nets(cfg):
    return [_ip.ip_network(n) for n in cfg["internal_networks"]]

def is_internal(ip, nets):
    try:
        a = _ip.ip_address(ip)
        return any(a in n for n in nets)
    except ValueError:
        return False

def one_way_safe_features(cfg):
    return {f["name"] for f in cfg["features_registry"] if f.get("one_way_safe", True)}
