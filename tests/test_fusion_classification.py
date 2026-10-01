"""27/09/2026 , 6TH FILE RECHECK AGAIN BEFORE SUBMIT"""
import copy
import numpy as np
import pandas as pd
import pytest
from uniaethel.evaluation.metrics import rolling_fraction
from uniaethel.forensics.ledger import Ledger
from uniaethel.fusion.attack_vector import aggregate_incident, decide_class, tail
from uniaethel.fusion.severity import corroboration, severity
from uniaethel.fusion.trajectory import trajectory
from uniaethel.models.graph_louvain import GraphEngine


def test_severity_and_corroboration():
    w = np.full(4, 0.25)
    assert np.isclose(severity(np.array([[0.7] * 4]), w)[0], 0.7)
    assert np.isclose(severity(np.array([[0.7] * 4]), w, "arithmetic")[0], 0.7)
    assert corroboration(np.array([[0.995, 0.5, 0.999, 0.2]]), np.full(4, 0.99))[0] == 2


def test_persistence_respects_host_boundaries():
    p = rolling_fraction(np.array([1, 1, 1, 1, 0, 0], bool), np.array([0, 0, 0, 3, 3, 3]), 3)
    assert np.allclose(p, [1, 1, 1, 1, 0.5, 1 / 3])


def test_trajectory_escalates_and_holds(cfg):
    sev = np.r_[np.full(10, 0.2), np.full(10, 0.999), np.full(20, 0.2)]
    C = np.r_[np.zeros(14), np.full(6, 3), np.zeros(20)].astype(int)
    P = rolling_fraction(sev > 0.99, np.zeros(40, int), cfg["persistence"]["k"])
    st = trajectory(sev, C, P, cfg, 0.99)
    assert st[:10].max() == 0 and st[10] == 1 and 2 in st[11:14] and st[19] == 3 and st[35] == 0


def _seg(cfg, **phi):
    n = 20
    d = {"w": np.arange(n), "C_t": np.full(n, 3), "P_t": np.ones(n), "S_sev": np.full(n, 0.999),
         "A_M": np.full(n, 0.5), "A_IF": np.full(n, 0.5), "A_TCN": np.full(n, 0.5), "A_G": np.full(n, 0.5)}
    from uniaethel.fusion.attack_vector import PHI_SOURCE
    for j, col in PHI_SOURCE.items():
        d[col] = np.full(n, phi.get(j, 0.0))
    return pd.DataFrame(d)


def test_compatibility_functions_pick_the_matching_profile(cfg):
    cases = {"C2": dict(A_TCN=1, A_G=1, periodicity=1, destination_persistence=1, jitter_regularity=1, destination_focus=1),
             "RECON": dict(A_G=1, new_edge_rate=1, fan_out=1, destination_diversity=1, A_IF=1),
             "DDOS": dict(A_M=1, A_IF=1, packet_rate_anomaly=1, byte_rate_anomaly=1, burst_growth=1, many_to_one=1, destination_focus=1),
             "EXFIL": dict(A_M=1, A_IF=1, outbound_volume=1, flow_duration=1, sustained_transfer=1, destination_novelty=1, destination_focus=1)}
    for true, phi in cases.items():
        agg = aggregate_incident(_seg(cfg, **phi), cfg)
        assert max(agg["scores"], key=agg["scores"].get) == true
        assert all(0 <= v <= 1 for v in agg["scores"].values())


def test_unknown_rejection_threshold_and_margin(cfg):
    agg = aggregate_incident(_seg(cfg, A_TCN=1, A_G=1, periodicity=1, destination_persistence=1, destination_focus=1), cfg)
    assert decide_class(agg, 0.1, 0.05)["label"] == "C2"
    assert decide_class(agg, 0.99, 0.05)["label"] == "UNKNOWN"             
    amb = aggregate_incident(_seg(cfg, A_G=1, A_IF=1, fan_out=0.5, new_edge_rate=0.5, periodicity=0.5,
                                  destination_persistence=0.5, destination_focus=0.5), cfg)
    s = sorted(amb["scores"].values())
    assert decide_class(amb, 0.0, (s[-1] - s[-2]) + 1e-6)["label"] == "UNKNOWN"   


def test_tail_transform_bounds():
    assert np.allclose(tail(np.array([0.0, 0.9, 0.945, 0.99, 1.0])), [0, 0, 0.5, 1, 1])


def test_graph_louvain_communities(cfg):
    g = GraphEngine({"graph": cfg["engines"]["graph"], "windowing": {"step_s": 1, "window_s": 5}})
    a = [f"10.0.1.{i}" for i in range(4)]; b = [f"10.0.2.{i}" for i in range(4)]
    rows = [(s, d) for grp in (a, b) for s in grp for d in grp if s != d]
    d = pd.DataFrame({"src": [r[0] for r in rows], "dstk": [r[1] for r in rows], "bytes": 1000.0})
    comm, st = g._louvain(d)
    assert len({comm[x] for x in a}) == 1 and comm[a[0]] != comm[b[0]] and st["modularity"] > 0.3


def test_ledger_detects_modification_and_deletion(tmp_path):
    led = Ledger()
    for i in range(10):
        led.append(incident_id=f"x#{i}", host="10.0.0.25", S_sev=0.9, classification="C2")
    assert led.verify() == (True, -1)
    t = copy.deepcopy(led); t.records[4]["event"]["classification"] = "EXFIL"; assert t.verify() == (False, 4)
    t = copy.deepcopy(led); del t.records[2]; assert t.verify()[0] is False
    led.save(tmp_path / "l.json"); assert Ledger.load(tmp_path / "l.json").verify()[0]
