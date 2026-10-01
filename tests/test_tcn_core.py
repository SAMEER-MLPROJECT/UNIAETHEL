import numpy as np
from uniaethel.models._tcn_core import CausalTCN


def test_gradients_match_finite_differences():
    rng = np.random.default_rng(1)
    m = CausalTCN(n_in=3, hidden=5, seed=2)
    x = rng.normal(size=(2, 20, 3))
    _, g = m.loss_grad(x)
    for name in ["W0", "W1", "W2", "b1", "b2", "Wo"]:     
        p = m.params[name]
        idx = tuple(rng.integers(s) for s in p.shape)
        old = p[idx]
        p[idx] = old + 1e-5; lp, _ = m.loss_grad(x)
        p[idx] = old - 1e-5; lm, _ = m.loss_grad(x)
        p[idx] = old
        num = (lp - lm) / 2e-5
        assert abs(num - g[name][idx]) < 1e-6 + 1e-4 * abs(num), name

def test_causal_future_does_not_change_past_prediction():
    rng = np.random.default_rng(3)
    m = CausalTCN(n_in=2, seed=0)
    x = rng.normal(size=(1, 30, 2))
    y1, _ = m.forward(x)
    x2 = x.copy(); x2[0, 20:] += 5.0
    y2, _ = m.forward(x2)
    assert np.allclose(y1[0, :20], y2[0, :20])


def test_training_learns_a_periodic_signal():
    t = np.arange(400)
    s = np.stack([np.sin(t / 3), np.cos(t / 5)], 1)
    m = CausalTCN(n_in=2, hidden=12, seed=0)
    hist = m.fit([s], steps=300, batch=8, crop=48)
    assert np.mean(hist[-20:]) < 0.25 * np.mean(hist[:20])


def test_dilated_receptive_field_reaches_back():
    rng = np.random.default_rng(5)
    m = CausalTCN(n_in=1, hidden=8, dilations=(1, 2, 4, 8), seed=1)
    x = rng.normal(size=(1, 60, 1))
    y1, _ = m.forward(x)
    x2 = x.copy(); x2[0, 20] += 3.0
    y2, _ = m.forward(x2)
    assert not np.allclose(y1[0, 50], y2[0, 50])      # WHITE SHIRT GUY 
    assert np.allclose(y1[0, 19], y2[0, 19])          
