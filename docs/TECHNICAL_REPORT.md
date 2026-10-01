# UniAethel — Technical Report

## 1. Overview

UniAethel is a passive behavioural threat-inference system for networks monitored through a data diode. The monitoring enclave receives a one-way copy of traffic. The system therefore cannot rely on replies, handshakes, active probing, inline blocking, or payload inspection.

The design treats the observed traffic itself as the sensor signal. Each host is compared with its own learned normal behaviour. Four independent analytical engines then examine the same one-way traffic from different perspectives: joint geometry, multivariate novelty, temporal evolution, and communication topology.

The design intentionally separates four ideas that are often collapsed into a single IDS score:

1. anomaly evidence;
2. severity;
3. corroboration and persistence;
4. attack-vector interpretation.

This separation makes it possible to say **UNKNOWN** when behaviour is anomalous but does not clearly match a known vector.

## 2. Observation contract

The system is passive. A packet observed as A→B remains an A→B observation. It is never paired with an assumed B→A packet.

Processing:

```text
one-way PCAP / packet copy
    ↓
5-tuple directional flows
    ↓
5 s windows, 1 s step
    ↓
per-host feature vectors
```

The current configuration uses 30 windows of temporal history and a 30-second rolling graph. Missing replies are missing observations, not zeros.

## 3. Four engines

### 3.1 Mahalanobis / Ledoit–Wolf

The joint feature deviation is represented by:

\[
D^2=(x-\mu)^T\Sigma^{-1}(x-\mu)
\]

A Ledoit–Wolf covariance estimate is used because network features are correlated. Scores are calibrated per host from normal validation data. A calibrated anomaly value near 0.99 means that the observation is approximately as rare as the upper 1% of that host's normal validation distribution.

### 3.2 Isolation Forest

Isolation Forest provides a second view of multivariate novelty. It asks whether the current feature combination lies in a region that normal observations rarely occupy.

### 3.3 Causal TCN

The TCN receives a causal history and predicts the next behavioural state. It cannot access future observations. Its output represents temporal prediction error rather than a direct malware/C2 label.

This distinction is important: pure periodic beaconing was not independently solved by the TCN in the recorded tests. Persistent new communication relationships are captured by the graph layer.

### 3.4 Graph + Louvain

A directed rolling communication graph represents observed relationships. Louvain operates on an undirected copy only for community detection. Graph evidence includes changes in new edges, peer relationships, persistence and community structure.

## 4. Evidence and incident logic

The raw engine vector is retained:

\[
A_t=[A_M,A_{IF},A_{TCN},A_G]
\]

Severity uses geometric pooling:

\[
S=1-\prod_i(1-A_i)^{w_i}
\]

with equal weights in the frozen configuration.

Agreement is:

\[
C=\sum_i\mathbf1[A_i\ge0.99]
\]

Persistence is the share of the previous six windows whose severity exceeds the configured threshold.

The trajectory layer maps the incident into:

```text
NORMAL → EMERGING → PERSISTENT → HIGH-CONFIDENCE
```

Only persistent, corroborated incidents enter attack-vector classification.

## 5. Attack-vector compatibility

The current implementation does not use a supervised LightGBM classifier. Instead, it uses explicit compatibility functions.

For vector `k`:

\[
S_k=\frac{C}{4}P\sum_jw_{kj}\phi_{kj}
\]

The vector with the largest compatibility score is accepted only when the score passes `τ_class` and the gap to the second-best vector passes `δ_margin`.

Otherwise the system returns `UNKNOWN`.

The validated feature profiles are:

- **C2:** temporal evidence, graph persistence, periodicity, destination persistence, jitter regularity and destination focus;
- **RECON:** graph evidence, new-edge rate, fan-out, destination diversity and IF evidence;
- **DDOS:** Mahalanobis/IF evidence, packet/byte-rate surge, burst growth and many-to-one structure;
- **EXFIL:** Mahalanobis/IF evidence, outbound volume, flow duration, sustained transfer and destination novelty.

These are compatibility scores, not probabilities.

## 6. Why the architecture evolved

The first recorded baseline used a simple univariate threshold. It detected only 2/16 held-out attack episodes. Isolation Forest alone detected 0/16.

Adding Mahalanobis + IF increased detection to 6/16. Adding temporal modelling increased it to 8/16. Adding Graph/Louvain produced 10/16 before persistence and trajectory. Persistence raised the final system to 16/16 on the frozen synthetic test.

The component-removal experiment shows that the graph layer was especially consequential: removing it reduced detection to 4/16. Removing TCN reduced detection to 12/16 while sharply reducing false alerts, demonstrating a genuine trade-off rather than a claim that every model always improves every metric.

## 7. Frozen evaluation

The current evaluation uses synthetic PCAPs from a simulated 22-host network. The held-out test contains 28 PCAP replays across normal/attack and benign look-alike traffic.

Recorded results:

- 16/16 attack episodes detected;
- median detection latency: 19 s;
- 8/14 known incidents named correctly;
- 6/14 known incidents rejected as UNKNOWN;
- 0 known-class confusions;
- 5/5 never-seen pattern incidents rejected as UNKNOWN;
- 10/10 C2 cases named correctly across the recorded 0–50% jitter sweep;
- 4/4 attacks detected at 50% packet loss;
- 9.33 false alerts/hour on the recorded normal + attack evaluation;
- 22,011 packets/s and 162 Mbps on one CPU core;
- 38 automated tests passing.

## 8. Limitations

The current results are synthetic. The false-alert rate is the main weakness. Reconnaissance is detected but rejected as UNKNOWN in the recorded classification evaluation. Some benign periodic agents resemble C2, and slow exfiltration below the host's learned normal transfer range can be missed.

Validation thresholds were frozen before the held-out test, but the benign calibration corpus is small. Real-world validation, live streaming, and controlled data-diode hardware testing remain future work.

## 9. Forensic record

Each alert record is chained as:

\[
H_i=SHA256(E_i\Vert H_{i-1})
\]

Changing an earlier record therefore breaks the subsequent chain. This is a tamper-evident provenance mechanism, not a claim that the prototype requires a blockchain network for every alert.

## 10. Reproducibility

The repository includes deterministic scenario generation, frozen parameters, result files, ablations, robustness sweeps, benchmark output, demo PCAPs and automated tests.

Run:

```bash
python scripts/run_all.py
python -m pytest -q
```

The result files should be read together with `docs/LIMITATIONS.md`; the headline detection number is not a substitute for the full evaluation record.
