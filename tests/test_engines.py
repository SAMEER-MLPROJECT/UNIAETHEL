import numpy as np
from uniaethel.models.mahalanobis import MahalanobisEngine
from uniaethel.models.isolation_forest import IsolationForestEngine


def _corr(n, rng):
    x = rng.normal(size=n)
    return np.c_[x, x + 0.1 * rng.normal(size=n), rng.normal(size=n)]

def test_ledoit_wolf_handles_singular_covariance():
    rng = np.random.default_rng(0)
    X = _corr(500, rng)
    X = np.c_[X, X[:, 0]]                      
    m = MahalanobisEngine(list("abcd")).fit(X)
    assert np.all(np.isfinite(m.raw(X))) and m.shrinkage_ > 0





def test_detects_broken_correlation_with_normal_marginals():
    
    rng = np.random.default_rng(1)
    X = _corr(3000, rng)
    m = MahalanobisEngine(list("abc")).fit(X); m.calibrate(_corr(3000, rng))
    anomaly = np.array([[1.0, -1.0, 0.0]])
    marginal_z = np.abs(anomaly[0, :2]) / X[:, :2].std(0)
    assert marginal_z.max() < 1.2
    assert m.score(anomaly)[0] > 0.999


def test_isolation_forest_is_seed_deterministic():
    X = np.random.default_rng(2).normal(size=(800, 4))
    a = IsolationForestEngine(list("abcd"), seed=42).fit(X).raw(X)
    b = IsolationForestEngine(list("abcd"), seed=42).fit(X).raw(X)
    assert np.array_equal(a, b)
