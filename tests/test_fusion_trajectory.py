import numpy as np
from uniaethel.config import load_config
from uniaethel.evaluation.metrics import rolling_fraction
from uniaethel.fusion.severity import corroboration, severity
from uniaethel.fusion.trajectory import trajectory


def test_geometric_pooling_properties():
    w = np.full(4, 0.25)
    same = np.array([[0.7, 0.7, 0.7, 0.7]])
    assert np.isclose(severity(same, w)[0], 0.7) and np.isclose(severity(same, w, "arithmetic")[0], 0.7)
    one_extreme = np.array([[0.99999, 0.5, 0.5, 0.5]])
    spread = np.array([[0.5, 0.5, 0.5, 0.5]])
    
    assert severity(one_extreme, w)[0] > 0.93 and severity(one_extreme, w, "arithmetic")[0] < 0.63
    assert severity(spread, w)[0] < severity(one_extreme, w)[0]




def test_same_severity_different_vectors_is_why_vector_is_kept():
    w = np.full(4, 0.25)
    a = np.array([[0.95, 0.95, 0.05, 0.05]]); b = np.array([[0.5, 0.5, 0.5, 0.5]])
    tau = np.full(4, 0.9)
    assert abs(severity(a, w, "arithmetic")[0] - severity(b, w, "arithmetic")[0]) < 1e-9
    assert corroboration(a, tau)[0] == 2 and corroboration(b, tau)[0] == 0

def test_persistence_respects_host_boundaries():
    x = np.array([1, 1, 1, 1, 0, 0], dtype=bool)
    gs = np.array([0, 0, 0, 3, 3, 3])                 
    p = rolling_fraction(x, gs, k=3)
    assert np.allclose(p, [1, 1, 1, 1, 0.5, 1 / 3])


def test_trajectory_escalates_and_holds_with_hysteresis():
    cfg = load_config(str(__import__("pathlib").Path(__file__).resolve().parents[1] / "configs/default.yaml"))
    n = 40
    sev = np.r_[np.full(10, 0.2), np.full(10, 0.999), np.full(20, 0.2)]
    C = np.r_[np.zeros(10), np.zeros(4), np.full(6, 3), np.zeros(20)].astype(int)
    P = rolling_fraction(sev > 0.99, np.zeros(n, dtype=int), cfg["persistence"]["k"])
    st = trajectory(sev, C, P, cfg, tau_sev=0.99)
    assert st[:10].max() == 0
    assert st[10] == 1                                
    assert 2 in st[11:14]                             
    assert st[19] == 3                                
    assert st[25] == 3 and st[35] == 0                # held for `hysteresis` windows, then released
