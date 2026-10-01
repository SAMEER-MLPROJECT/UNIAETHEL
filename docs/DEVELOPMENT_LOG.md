# UniAethel development log

UniAethel evolved through measured failures rather than by adding models without a testable reason.

## Recorded progression

### 0 — Single-signal baseline
A scalar/statistical threshold was tested first. It detected only 2/16 held-out attack episodes. An Isolation Forest-only baseline detected 0/16.

**Decision:** a single anomaly view was insufficient.

### 1 — Mahalanobis + Isolation Forest
Joint host-relative geometry and multivariate novelty raised detection to 6/16.

**Decision:** retain both because they answer different questions, but add temporal information.

### 2 — Causal TCN
Temporal context raised detection to 8/16, including C2 cases, but increased benign alerts.

**Decision:** TCN becomes an evidence engine, not the final classifier.

### 3 — Graph + Louvain
Communication topology brought the four-engine configuration to 10/16. Removing the graph from the final system reduced detection to 4/16.

**Decision:** topology is a first-class evidence source.

### 4 — Corroboration + persistence
The final incident logic required multiple domains and persistence. Persistence raised detection to 16/16 in the frozen test.

**Decision:** a transient anomaly should not automatically become an incident.

### 5 — Trajectory
Threat state was added to represent whether an incident is emerging, persisting, or reaching high confidence.

**Decision:** preserve time evolution instead of reducing the incident to a single scalar.

### 6 — Attack-vector compatibility
C2, RECON, DDOS and EXFIL compatibility scores were introduced with threshold and margin rejection.

**Decision:** if the evidence does not clearly support a known class, return `UNKNOWN`.

## What did not work

- Arithmetic severity pooling performed poorly on the frozen test compared with the adopted geometric pooling.
- Isolation Forest removal improved some measured metrics; it remains because the architecture was frozen before the test and because it provides an orthogonal novelty view.
- Reconnaissance was detected but remained `UNKNOWN` in the recorded classification evaluation; its compatibility profile needs re-weighting.
- Some benign periodic agents resemble C2 from metadata alone.
- Slow exfiltration inside a host's normal transfer range can be missed.

These are intentionally preserved as limitations rather than hidden behind a single headline metric.
