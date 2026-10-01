# VERSION 1 THE FIRST FAILED idea 
# INTIAL FILIZED DESIGN 
## PREVIOUS ARCHITECTURE : USED LINEAR COMBINATION OF THE ANOMALY SCORES RETURNED BY FOUR ENGINES ( CALLED IT A_FINAL)
## MAPPED A_FINAL TO DIFFERENT RANGES WHERE EACH RANGE DEPICTED AN DIFFERENT TYPE OF ATTACK 
### DRAWBACK : SEVERE FEATURE LOSS DUE TO NAIVE LINEAR COMBINATION APPROACH AND ALSO CERTAIN FEATURES IN THE INTIAL FEATURE VECTOR HAD 
### CORRELATION, SO Z-SCORE TEST WAS ALSO INACCURATE, THE HYPER PARAMETERS IN THE EARLIEST APPROACH (w1,w2,w3,w4) had been planned to be 
### computed by stochastic gradient descent with lasso regression but was discontinued

# Updated Version
## Engineered A seperate layer for attack vector judgement combining the four domain anomalies using geometric pooling , corrobration
## Replaced Z Score one with mahanolobis distance based approach considering the strong correlation between certain features

## Hypothesis - Stage 0 

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

1. joint geometry - Mahalanobis;
2. multivariate novelty - Isolation Forest;
3. temporal evolution - causal TCN;
4. communication topology - temporal graph + Louvain.

This stage remains in the repository as a baseline because it explains why the final system contains multiple engines rather than being a model zoo added for appearance.
