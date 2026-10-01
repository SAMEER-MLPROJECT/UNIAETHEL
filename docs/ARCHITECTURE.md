# Architecture
```
PASSIVE ONE-WAY TRAFFIC (pcap / replay)          capture/pcap.py
  -> directional flows (5-tuple, idle timeout)    flows/flows.py
  -> 5 s windows, 1 s step, dense per host        features/windows.py
  -> four engines, no decision before them:       models/
       Mahalanobis (Ledoit-Wolf, host-relative)   Isolation Forest (host-relative)
       causal TCN (next-window prediction)        temporal graph + Louvain (directed; undirected copy for Louvain)
  -> per-host calibration A_i in [0,1]            models/calibrate.py
  -> evidence vector A_t=[A_M,A_IF,A_TCN,A_G]     pipeline.py
  -> severity S (geometric pooling, equal w)      fusion/severity.py
  -> corroboration C=sum 1[A_i>=tau_i]; persistence P over K=6; trajectory NORMAL/EMERGING/PERSISTENT/HIGH_CONFIDENCE
  -> incidents (alert runs per host)              fusion/decision.py, evaluation/metrics.py
  -> attack-vector compatibility S_k, argmax, tau_class, delta_margin -> C2/RECON/DDOS/EXFIL/UNKNOWN   fusion/attack_vector.py
  -> explanation + hash-linked record              detect.py, forensics/ledger.py
```
