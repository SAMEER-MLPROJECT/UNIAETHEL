"""Packet parsing, one-way mode, directional flows, rolling windows, feature extraction."""
import numpy as np
import pandas as pd
from uniaethel.capture.pcap import prepare, read_pcap
from uniaethel.features.windows import extract_windows
from uniaethel.flows.flows import build_flows
from uniaethel.simulation.generate import Cap, write_pcap_fast, write_pcap_scapy


def _recs():
    c = Cap()
    for i in range(20):
        c.tcp(1.0 + i, "10.0.0.25", "198.51.100.42", 443, 500, sport=5555)        # forward
        c.tcp(1.05 + i, "198.51.100.42", "10.0.0.25", 5555, 1200, sport=443)     # reverse direction
    c.syn(3.0, "10.0.0.25", "10.0.0.26", 22)
    return sorted(c.recs)


def test_pcap_parsing_both_writers_and_parsers_agree(cfg, tmp_path):
    write_pcap_fast(_recs(), str(tmp_path / "f.pcap")); write_pcap_scapy(_recs(), str(tmp_path / "s.pcap"))
    a = read_pcap(str(tmp_path / "f.pcap"), cfg); b = read_pcap(str(tmp_path / "s.pcap"), cfg, backend="scapy")
    assert len(a) == len(b) == 41
    assert (a[["src", "dst", "sport", "dport", "proto", "length"]].values == b[["src", "dst", "sport", "dport", "proto", "length"]].values).all()
    assert a["syn"].sum() == 1 and a["length"].max() == 1200


def test_directional_flows_never_merge_reverse(cfg, tmp_path):
    write_pcap_fast(_recs(), str(tmp_path / "f.pcap"))
    pk, flows = build_flows(read_pcap(str(tmp_path / "f.pcap"), cfg), cfg)
    fwd = flows[(flows.src == "10.0.0.25") & (flows.dst == "198.51.100.42")]
    rev = flows[(flows.src == "198.51.100.42") & (flows.dst == "10.0.0.25")]
    assert len(fwd) == 1 and len(rev) == 1 and fwd.index[0] != rev.index[0]
    assert fwd["packets"].iloc[0] == 20 and fwd["bytes"].iloc[0] == 20 * 500     # no reverse bytes merged in


def test_reverse_traffic_is_never_required(cfg, tmp_path):
    """Outbound features of a host are identical whether or not the reverse direction is present."""
    write_pcap_fast(_recs(), str(tmp_path / "f.pcap"))
    full = read_pcap(str(tmp_path / "f.pcap"), cfg)
    egress = read_pcap(str(tmp_path / "f.pcap"), cfg, mode="egress_only")
    assert (egress["direction"] != "in").all()
    Ff = extract_windows(build_flows(full, cfg)[0], cfg, n_w=30)
    Fe = extract_windows(build_flows(egress, cfg)[0], cfg, n_w=30)
    cols = ["pps_out", "bps_out", "flow_count", "fan_out", "mean_iat", "jitter", "periodicity", "max_flow_duration"]
    assert np.allclose(Ff.loc["10.0.0.25", cols].values, Fe.loc["10.0.0.25", cols].values)
    reverse_feats = {f["name"] for f in cfg["features_registry"] if f["requires_reverse"]}
    assert reverse_feats and not (reverse_feats & set(Ff.columns))                # disabled automatically


def test_rolling_windows_exact_and_dense(cfg, tmp_path):
    c = Cap(); c.tcp(0.5, "10.0.0.25", "8.8.4.4", 443, 100); c.tcp(1.5, "10.0.0.25", "8.8.4.4", 443, 100); c.tcp(7.2, "10.0.0.25", "8.8.4.4", 443, 100)
    write_pcap_fast(sorted(c.recs), str(tmp_path / "w.pcap"))
    F = extract_windows(build_flows(read_pcap(str(tmp_path / "w.pcap"), cfg), cfg)[0], cfg, n_w=20)
    s = F.loc["10.0.0.25", "packet_count"]
    assert len(s) == 20 and s.loc[1] == 2 and s.loc[4] == 2 and s.loc[5] == 1 and s.loc[6] == 0 and s.loc[7] == 1


def test_periodicity_feature_detects_recurrence_only(cfg, tmp_path):
    c = Cap()
    for t in np.arange(5, 120, 10.0):
        c.tcp(t, "10.0.0.25", "198.51.100.42", 443, 400)
    rng = np.random.default_rng(0)
    for t in np.sort(rng.uniform(5, 120, 12)):
        c.tcp(t, "10.0.0.26", "198.51.100.43", 443, 400)
    write_pcap_fast(sorted(c.recs), str(tmp_path / "p.pcap"))
    F = extract_windows(build_flows(read_pcap(str(tmp_path / "p.pcap"), cfg), cfg)[0], cfg, n_w=120)
    assert F.loc[("10.0.0.25", 100), "periodicity"] > 0.9
    assert F.loc[("10.0.0.26", 100), "periodicity"] < F.loc[("10.0.0.25", 100), "periodicity"] - 0.3
