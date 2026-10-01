"""Four-engine pipeline: fit on BENIGN only -> calibrate on BENIGN validation -> evidence.

The same rolling windows feed all four engines, each through its own representation:
  Mahalanobis       host-relative numerical feature vector (Ledoit-Wolf covariance)
  Isolation Forest  host-relative multivariate feature vector
  Causal TCN        sequence of the host's previous windows (next-window prediction)
  Graph + Louvain   directed communication graph of observed packets (rolling 30 s)
No decision is taken before all four engines have produced evidence.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import seed_everything
from .features.representations import HostBaseline
from .fusion.attack_vector import tail
from .models.calibrate import HostCalibrator
from .models.graph_louvain import GraphEngine
from .models.isolation_forest import IsolationForestEngine
from .models.mahalanobis import MahalanobisEngine
from .models.tcn import TCNEngine

STAT_FEATS = ["log_pps_out", "log_bps_out", "fan_out", "log_pps_in", "fan_in"]
PHI_RAW = ["pps_in", "bps_in", "fan_in", "fan_out", "unique_dst_ports", "bps_out", "max_flow_duration",
           "burst_growth", "new_edges", "persistent_new_edges"]


def tag(F: pd.DataFrame, cid: int) -> pd.DataFrame:
    F = F.copy(); F["cap"] = cid
    return F.set_index("cap", append=True).reorder_levels(["cap", "host", "w"])


def burst_growth(F: pd.DataFrame, k: int = 10) -> np.ndarray:
    """Positive slope of log inbound packet rate over the last k windows (causal)."""
    x = F["log_pps_in"].values
    lagged = F.groupby(level="host")["log_pps_in"].shift(k).values
    return np.clip(np.nan_to_num(x - lagged, nan=0.0), 0, None) / k


class Pipeline:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        e = cfg["engines"]; q = cfg["calibration"]["tail_quantile"]
        seed_everything(cfg["seed"])
        self.maha = MahalanobisEngine(e["mahalanobis"]["features"], q)
        f = e["isolation_forest"]
        self.iforest = IsolationForestEngine(f["features"], n_estimators=f["n_estimators"], max_samples=f["max_samples"],
                                             max_features=f["max_features"], tail_quantile=q, seed=cfg["seed"])
        t = e["tcn"]
        self.tcn = TCNEngine(t["channels"], hidden=t["hidden"], kernel=t["kernel"], dilations=t["dilations"],
                             train_steps=t["train_steps"], batch=t["batch"], crop=t["crop"], lr=t["lr"],
                             error_smoothing=t["error_smoothing"], tail_quantile=q, seed=cfg["seed"])
        self.gcfg = {"graph": e["graph"], "windowing": {"step_s": cfg["windowing"]["step_seconds"],
                                                         "window_s": cfg["windowing"]["window_seconds"]}}
        self.graph = GraphEngine(self.gcfg, q)
        self.cals = {k: HostCalibrator(q) for k in ("M", "IF", "TCN", "G", "STAT")}
        self.phical = {k: HostCalibrator(q) for k in PHI_RAW}
        self.calibrated = False

    # ------------------------------------------------------------------ fit (benign only)
    def fit_graph(self, train: list[dict]) -> dict:
        """Pass 1: learn benign communication relationships (needed for periodicity_new features)."""
        k = max(1, int(round(len(train) * 2 / 3)))
        self.graph.n_w = train[0]["n_w"]
        self.graph.fit([c["pk"] for c in train[:k]], [c["pk"] for c in train[k:]] or [train[0]["pk"]], self.gcfg)
        return self.graph.baseline_nbrs

    def fit(self, train: list[dict]) -> "Pipeline":
        """Pass 2 (after fit_graph, with train features extracted against the baseline): point + sequence engines."""
        Ftr = pd.concat([tag(c["F"], i) for i, c in enumerate(train)])
        cols = sorted(set(self.maha.features) | set(self.iforest.features) | set(self.tcn.channels) | set(STAT_FEATS))
        self.hb = HostBaseline().fit(Ftr, cols)
        Z = self._rep(Ftr)
        self.maha.fit(Z[self.maha.features].values)
        self.iforest.fit(Z[self.iforest.features].values)
        self.tcn.fit(Z)
        return self

    def _rep(self, F: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame(self.hb.transform(F), index=F.index, columns=self.hb.cols)

    @property
    def baseline_relationships(self) -> dict:
        return self.graph.baseline_nbrs

    # ------------------------------------------------------------------ raw scores
    def _raw(self, pk: pd.DataFrame, F: pd.DataFrame, n_w: int) -> dict:
        Z = self._rep(F)
        self.graph.n_w = n_w
        gf = self.graph.structural_features(pk, self.gcfg)
        gf = gf.assign(raw_G=self.graph._combined(gf)).reindex(F.index).fillna(0.0)
        return {"M": self.maha.raw(Z[self.maha.features].values), "IF": self.iforest.raw(Z[self.iforest.features].values),
                "TCN": self.tcn.raw_series(Z).values, "G": gf["raw_G"].values,
                "STAT": np.abs(Z[STAT_FEATS].values).max(axis=1), "graph": gf}

    def _phi_raw(self, F: pd.DataFrame, gf: pd.DataFrame) -> dict:
        d = {c: F[c].values for c in PHI_RAW if c in F}
        d["burst_growth"] = burst_growth(F)
        d["new_edges"] = gf["new_edges"].values; d["persistent_new_edges"] = gf["persistent_new_edges"].values
        return d

    # ------------------------------------------------------------------ calibrate (benign validation only)
    def calibrate(self, val_benign: list[dict]) -> None:
        raws = {k: [] for k in self.cals}; phis = {k: [] for k in PHI_RAW}; hosts = []
        for c in val_benign:
            r = self._raw(c["pk"], c["F"], c["n_w"])
            for k in self.cals:
                raws[k].append(r[k])
            ph = self._phi_raw(c["F"], r["graph"])
            for k in PHI_RAW:
                phis[k].append(ph[k])
            hosts.append(c["F"].index.get_level_values("host").values)
        H = np.concatenate(hosts)
        for k, cal in self.cals.items():
            cal.fit(np.concatenate(raws[k]), H)
        for k, cal in self.phical.items():
            cal.fit(np.concatenate(phis[k]), H)
        self.calibrated = True

    # ------------------------------------------------------------------ evidence
    def evidence(self, pk: pd.DataFrame, F: pd.DataFrame, n_w: int) -> pd.DataFrame:
        assert self.calibrated, "calibrate() first"
        r = self._raw(pk, F, n_w)
        hosts = F.index.get_level_values("host").values
        out = F.copy()
        for k in ("M", "IF", "TCN", "G", "STAT"):
            out["raw_" + k] = r[k]
            out["A_" + k] = self.cals[k].transform(r[k], hosts)
        for k in ("M", "IF", "TCN", "G"):
            out["tail_A_" + k] = tail(out["A_" + k].values)
        for c in r["graph"].columns:
            if c != "raw_G":
                out[c] = r["graph"][c].values
        ph = self._phi_raw(F, r["graph"])
        for k in PHI_RAW:
            out["phi_" + k] = tail(self.phical[k].transform(ph[k], hosts))
        out["phi_focus"] = 1.0 - out["phi_fan_out"]     # recurring relationship with few destinations
        # C2 recurrence terms count only when the recurrence is concentrated (a cyclic scan re-contacts
        # each of many targets on a schedule, which is regular but not concentrated)
        out["phi_c2_periodicity"] = out["periodicity_new"] * out["phi_focus"]
        out["phi_c2_jitter"] = out["jitter_regularity_new"] * out["phi_focus"]
        out["phi_c2_persistence"] = out["destination_persistence"] * out["phi_focus"]
        return out
