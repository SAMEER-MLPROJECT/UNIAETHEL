"""Compatibility functions, unknown/ambiguous rejection, ledger hash chain, corroboration."""
import copy
import numpy as np
import pandas as pd
from uniaethel.forensics.ledger import Ledger
from uniaethel.fusion.attack_vector import PHI_SOURCE, aggregate_incident, decide_class, set_rejection_thresholds
from uniaethel.fusion.severity import corroboration


def _seg(cfg, **phi):
    n = 20
    d = {c: np.zeros(n) for c in set(PHI_SOURCE.values())}
    for k, v in phi.items():
        d[PHI_SOURCE[k]] = np.full(n, v)
    d.update(C_t=np.full(n, 3), P_t=np.ones(n), w=np.arange(n), S_sev=np.linspace(0.9, 1, n),
             A_M=np.zeros(n), A_IF=np.zeros(n), A_TCN=np.zeros(n), A_G=np.zeros(n))
    return pd.DataFrame(d)


def test_profiles_pick_their_class(cfg):
    cases = {"C2": dict(A_TCN=1, A_G=1, periodicity=1, destination_persistence=1, jitter_regularity=1, destination_focus=1),
             "RECON": dict(A_G=1, new_edge_rate=1, fan_out=1, destination_diversity=1),
             "DDOS": dict(A_M=1, packet_rate_anomaly=1, byte_rate_anomaly=1, burst_growth=1, many_to_one=1),
             "EXFIL": dict(A_M=1, outbound_volume=1, flow_duration=1, sustained_transfer=1, destination_novelty=1)}
    for k, phi in cases.items():
        a = aggregate_incident(_seg(cfg, **phi), cfg)
        assert decide_class(a, 0.1, 0.05)["label"] == k


def test_gamma_and_persistence_scale_scores(cfg):
    s = _seg(cfg, A_M=1, outbound_volume=1, sustained_transfer=1)
    full = aggregate_incident(s, cfg)["scores"]["EXFIL"]
    s2 = s.copy(); s2["C_t"] = 1; s2["P_t"] = 0.5
    assert np.isclose(aggregate_incident(s2, cfg)["scores"]["EXFIL"], full * (1 / 3) * 0.5)


def test_unknown_rejection_by_threshold_and_margin(cfg):
    weak = aggregate_incident(_seg(cfg, A_M=0.2), cfg)
    assert decide_class(weak, 0.3, 0.05)["label"] == "UNKNOWN"             # below tau_class
    amb = aggregate_incident(_seg(cfg, A_G=1, A_M=1, fan_out=1, many_to_one=1, new_edge_rate=1, packet_rate_anomaly=1), cfg)
    s = sorted(amb["scores"].values())
    assert decide_class(amb, 0.0, (s[-1] - s[-2]) + 0.01)["label"] == "UNKNOWN"   # margin not met
    assert decide_class(amb, 0.0, 0.0)["label"] != "UNKNOWN"


def test_rejection_thresholds_from_validation_quantiles():
    aggs = [({"scores": {"C2": 0.5 + i / 100, "RECON": 0.1, "DDOS": 0, "EXFIL": 0}}, "C2") for i in range(50)]
    tau, delta = set_rejection_thresholds(aggs, 0.10)
    assert 0.5 <= tau <= 0.53 and 0.39 <= delta <= 0.43


def test_corroboration_counts_domains():
    A = np.array([[0.995, 0.2, 0.999, 0.5], [0.1, 0.1, 0.1, 0.1]])
    assert corroboration(A, np.full(4, 0.99)).tolist() == [2, 0]


def _ledger():
    L = Ledger()
    for i in range(10):
        L.append(incident_id=f"x#{i}", host="10.0.0.25", destination="198.51.100.42", A_M=0.7, A_IF=0.8, A_TCN=0.96,
                 A_G=0.81, S_sev=0.99, C_t=3.0, P_t=0.9, classification="C2", graph_snapshot_hash="ab" * 32)
    return L


def test_ledger_detects_modification_deletion_reorder(tmp_path):
    L = _ledger(); assert L.verify() == (True, -1)
    L.save(tmp_path / "l.json"); M = Ledger.load(tmp_path / "l.json"); assert M.verify()[0]
    T = copy.deepcopy(L); T.records[4]["event"]["classification"] = "BENIGN"; assert T.verify() == (False, 4)
    D = copy.deepcopy(L); del D.records[3]; assert D.verify() == (False, 3)
    R = copy.deepcopy(L); R.records[2], R.records[5] = R.records[5], R.records[2]; assert not R.verify()[0]


def test_hash_formula_matches_spec():
    import hashlib
    from uniaethel.forensics.ledger import GENESIS, canonical_json
    L = _ledger(); r = L.records[0]
    assert r["hash"] == hashlib.sha256((GENESIS + canonical_json(r["event"])).encode()).hexdigest()
