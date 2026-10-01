# Stage 0 — the failed first baseline

## Hypothesis

The first recorded detection hypothesis was intentionally simple: detect a host when a scalar traffic statistic crosses a threshold. An Isolation Forest-only configuration was also tested as the simplest unsupervised multivariate baseline.

This was useful because it established whether a single anomaly signal was enough before adding architectural complexity.

## What it looked like

```text
PCAP
  ↓
flow/window features
  ↓
one abnormal statistic?
  ↓
ALERT
```

Alternative baseline:

```text
features → Isolation Forest → anomaly / normal
```

There was no temporal reasoning, graph context, persistence requirement, trajectory state, or attack-vector layer.

## Why it failed

On the frozen held-out synthetic evaluation:

- univariate threshold: **2/16** attack episodes detected;
- Isolation Forest only: **0/16**;
- the univariate baseline detected only the high-volume DDoS cases in the recorded class breakdown;
- hard-negative/benign look-alike traffic still produced alerts.

The lesson was not that thresholds or Isolation Forest are useless. It was that **a single view of traffic cannot represent the different ways a threat can manifest in one-way metadata**.

## What changed

The architecture was expanded to use orthogonal evidence:

1. joint geometry — Mahalanobis;
2. multivariate novelty — Isolation Forest;
3. temporal evolution — causal TCN;
4. communication topology — temporal graph + Louvain.

This stage remains in the repository as a baseline because it explains why the final system contains multiple engines rather than being a model zoo added for appearance.
