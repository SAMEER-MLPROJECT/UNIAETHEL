# Models and parameters (configs/default.yaml)
- Mahalanobis: 14 host-relative features, Ledoit-Wolf shrinkage, raw D^2.
- Isolation Forest: 200 trees, max_samples 256, 24 features, seed 42.
- Causal TCN (NumPy, from scratch): kernel 3, dilations 1,2,4,8 (receptive field 31 windows), residual blocks, 16 channels,
  next-window prediction on 7 channels including periodicity_new; causality and gradients unit-tested.
- Graph: rolling 30 s directed graph, external /24 aggregation, hub filtering, Louvain every 5 s; A_G raw = max over
  components of -log10 P_benign(component >= x), extended beyond the benign maximum.
- Calibration: per host, on benign validation captures only; A = 0.99 = top 1% of that host's benign windows.
- Severity: S = 1 - prod (1 - A_i)^w_i with equal weights. Deviation from the linear form, adopted on validation evidence:
  linear pooling gave a C2 beacon S = 0.74 while normal hosts reached 0.96 at the 99th percentile. Linear severity is kept as
  ablation rung G_arithmetic_severity and measured on test (docs/EXPERIMENTS.md).
- Decision: tau_sev per ablation rung chosen on validation normal + attack captures (benign look-alikes never used for tuning),
  <= 1 false alert/h; N_min = 2, K = 6, P_min = 0.5, hysteresis 10 s.
