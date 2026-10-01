import numpy as np
from uniaethel.models.calibrate import TailCalibrator

def test_normal_scores_are_roughly_uniform_and_below_q():
    rng = np.random.default_rng(0)
    cal = TailCalibrator(0.99).fit(rng.lognormal(0, 1, 20000))
    a = cal.transform(rng.lognormal(0, 1, 20000))      
    assert abs(np.median(a) - 0.495) < 0.03
    assert abs((a > 0.99).mean() - 0.01) < 0.004         

def test_monotone_and_bounded_with_tail_resolution():
    cal = TailCalibrator(0.99).fit(np.random.default_rng(1).exponential(1, 5000))
    x = np.array([0, 0.5, 2, 5, 10, 50, 1e6])
    a = cal.transform(x)
    assert np.all(np.diff(a) >= 0) and a.min() >= 0 and a.max() <= 1
    assert a[4] < a[5] < 1.0                               

def test_zero_point_mass_maps_to_zero():
    raw = np.r_[np.zeros(900), np.random.default_rng(2).exponential(1, 100)]
    cal = TailCalibrator(0.99).fit(raw)
    assert cal.transform(np.array([0.0]))[0] == 0.0





def test_per_host_calibration_removes_systematic_host_offset():
    from uniaethel.models.calibrate import HostCalibrator
    rng = np.random.default_rng(3)
    raw = np.r_[rng.lognormal(0, 1, 2000), rng.lognormal(3, 1, 2000)]   
    hosts = np.r_[np.full(2000, "ws"), np.full(2000, "srv")]
    hc = HostCalibrator(0.99).fit(raw, hosts)
    new_raw = np.r_[rng.lognormal(0, 1, 2000), rng.lognormal(3, 1, 2000)]
    a = hc.transform(new_raw, hosts)
    for h in ("ws", "srv"):
        assert abs((a[hosts == h] > 0.99).mean() - 0.01) < 0.008      # person 2 change it before final submit ,white shirt guy 
    pooled = TailCalibrator(0.99).fit(raw).transform(new_raw)
    assert (pooled[hosts == "srv"] > 0.99).mean() > 0.015            
