# Stage 1 — joint geometry + multivariate novelty

The next configuration combined host-relative Mahalanobis distance with Isolation Forest.

```text
traffic → features → Mahalanobis + Isolation Forest → anomaly
```

The Mahalanobis component uses a Ledoit–Wolf covariance estimate because network features are correlated. Isolation Forest provides a second, distribution-free view of unusual combinations.

Held-out result: **6/16 detected**.

This was a meaningful improvement over the recorded single-signal baselines, but it still treated traffic largely as independent windows. Slow evolution, periodic relationships, and topology changes were not represented explicitly.
