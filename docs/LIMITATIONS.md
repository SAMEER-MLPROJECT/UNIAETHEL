# Limitations (CURRENTLY WORKING UPON )
1. Synthetic traffic only; no real-network validation.
2. Small test set (16 attack episodes); each episode is ~6 percentage points of recall.
3. False alerts: several per hour on held-out captures, concentrated on the public web server and two workstations. Per-host
   calibration and threshold tuning used the same 2 benign validation captures, so validation (0/h) was optimistic.
4. Benign look-alikes (periodic agents, software update, load test, flash crowd) raise alerts; most are labelled UNKNOWN,
   some periodic ones are labelled C2 - behaviour-only evidence cannot tell a legitimate new heartbeat from a beacon.
5. Recon is detected but labelled UNKNOWN in every test and sweep case: the RECON profile is too weak.
6. Slow exfiltration below ~3 MB in 150 s is missed; DDoS below 100 pps is detected but not labelled.
7. Removing the TCN reduces false alerts sharply at the cost of recall; removing Isolation Forest improved results.
8. Egress-only / ingress-only observation modes are implemented but not evaluated (need their own baselines).
9. Batch replay, not live streaming; throughput is single-core batch throughput.
