# Experiments (all numbers generated from results/*.json)

Evaluation performed on reproducibly generated synthetic traffic. Test split: 28 held-out captures
(1.50 h normal + attack captures, 0.83 h benign look-alike captures), scored once
after freezing.

frozen_params.json sha256=8197b215a4045449016ad667b8944d28da6ed861f2466bfd6dadc221c83aee5a
config_hash=d5767031c385f50cbaf6de4cda079218735662dad32f56ad1f32c1bfa58345ab
primary=G_plus_trajectory
frozen_at_unix=1790761074
test captures scored before freeze: 0

## Ablation A-G (held-out test)
| configuration | detected (of 16) | precision | F1 | false alerts/h (normal + attack captures) | alerts on benign look-alikes | median / p95 latency |
|---|---|---|---|---|---|---|
| `STAT_univariate_threshold` | 2/16 | 0.10 | 0.11 | 4.00 | 13 | 4 s / 5 s |
| `A_IF_only` | 0/16 | 0.00 | 0.00 | 4.00 | 11 | - / - |
| `B_M_IF` | 6/16 | 0.30 | 0.33 | 4.00 | 24 | 0 s / 27 s |
| `C_M_IF_TCN` | 8/16 | 0.17 | 0.26 | 5.33 | 30 | 14 s / 36 s |
| `D_all_four_engines` | 10/16 | 0.29 | 0.39 | 1.33 | 28 | 22 s / 162 s |
| `E_plus_corroboration` | 10/16 | 0.25 | 0.36 | 4.00 | 30 | 22 s / 162 s |
| `F_plus_persistence` | 16/16 | 0.35 | 0.52 | 10.67 | 36 | 19 s / 47 s |
| `G_plus_trajectory` | 16/16 | 0.28 | 0.44 | 9.33 | 35 | 19 s / 47 s |

## Component removal from the full system (G)
| configuration | detected (of 16) | precision | F1 | false alerts/h (normal + attack captures) | alerts on benign look-alikes | median / p95 latency |
|---|---|---|---|---|---|---|
| `G_without_TCN` | 12/16 | 0.57 | 0.65 | 0.00 | 9 | 20 s / 27 s |
| `G_without_Graph` | 4/16 | 0.07 | 0.11 | 5.33 | 46 | 5 s / 8 s |
| `G_without_Mahalanobis` | 8/16 | 0.16 | 0.24 | 6.67 | 33 | 16 s / 38 s |
| `G_without_IF` | 16/16 | 0.45 | 0.62 | 2.67 | 24 | 21 s / 48 s |
| `G_without_corroboration` | 16/16 | 0.30 | 0.46 | 8.00 | 33 | 19 s / 47 s |
| `G_arithmetic_severity` | 4/16 | 0.24 | 0.24 | 4.67 | 12 | 12 s / 38 s |

## Attack-vector classification (primary G, incident level)
tau_class = 0.4152, delta_margin = 0.0948 (set on validation so ~10% of known validation incidents would be rejected).

| truth \ predicted | C2 | RECON | DDOS | EXFIL | UNKNOWN |
|---|---|---|---|---|---|
| C2 | 4 | 0 | 0 | 0 | 0 |
| RECON | 0 | 0 | 0 | 0 | 4 |
| DDOS | 0 | 0 | 2 | 0 | 0 |
| EXFIL | 0 | 0 | 0 | 2 | 2 |
| UNKNOWN | 0 | 0 | 0 | 0 | 5 |

Known-class incidents: 8/14 correct, 6 rejected as UNKNOWN,
0 confused between known classes. Unknown scenario: 5/5 incidents rejected as UNKNOWN.

## Robustness (frozen system, dedicated seeds)
| sweep | result |
|---|---|
| c2_jitter (jitter) | 0.0: detected 2/2, labelled 2; 0.1: detected 2/2, labelled 2; 0.2: detected 2/2, labelled 2; 0.3: detected 2/2, labelled 2; 0.5: detected 2/2, labelled 2 |
| recon_speed (end_rate) | 0.5: detected 2/2, labelled 0; 1.0: detected 2/2, labelled 0; 2.0: detected 2/2, labelled 0; 4.0: detected 2/2, labelled 0; 8.0: detected 2/2, labelled 0 |
| ddos_volume (peak_pps) | 25: detected 2/2, labelled 0; 50: detected 2/2, labelled 0; 100: detected 2/2, labelled 2; 200: detected 2/2, labelled 2; 400: detected 2/2, labelled 2 |
| exfil_speed (mbytes) | 1: detected 0/2, labelled 0; 3: detected 2/2, labelled 0; 6: detected 2/2, labelled 0; 12: detected 2/2, labelled 2; 24: detected 2/2, labelled 2 |
| packet_loss (loss) | 0.0: detected 4/4, labelled 3; 0.1: detected 4/4, labelled 3; 0.3: detected 4/4, labelled 2; 0.5: detected 4/4, labelled 1 |
| observation_mode | NOT RUN: engines are trained on the unpaired view; egress/ingress-only need their own baselines (future work) |

## Demo scenarios (scripts/run_demo.py)
- demo1_c2: expected C2       got C2            (incidents on 10.0.0.25: 1; other hosts: 0)
- demo2_recon: expected RECON    got UNKNOWN       (incidents on 10.0.0.25: 1; other hosts: 0)
- demo3_ddos: expected DDOS     got DDOS          (incidents on 10.0.0.80: 1; other hosts: 0)
- demo4_exfil: expected EXFIL    got EXFIL         (incidents on 10.0.0.25: 1; other hosts: 0)
- demo5_unknown: expected UNKNOWN  got UNKNOWN       (incidents on 10.0.0.25: 2; other hosts: 0)

## Honest reading
- Detection: the full system detected every test attack episode (16/16), including the unknown pattern.
- False alerts are the main weakness: 9.33/h on normal + attack captures and 35 on look-alikes.
  Validation showed 0/h because per-host calibration and tau_sev tuning used the same 2 benign validation captures (in-sample).
- Removing the TCN lowers detection but removes most false alerts - a real trade-off, not a free component.
- Removing Isolation Forest improved the system here; it is kept only because the architecture was frozen before test.
- Linear (arithmetic) severity detects 4/16 vs geometric 16/16.
- Classification never confused two known vectors, but rejected all recon incidents as UNKNOWN: the recon profile is too weak.
