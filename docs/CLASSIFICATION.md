# Attack-vector classification
S_k = gamma(C) * P * sum_j w_kj phi_kj, gamma(C) = C/4, phi in [0,1] (tail-transformed per-host calibrated features, or ratios).
Incident-level: phi, C, P averaged over the incident windows before scoring.
Label = argmax S_k if max S >= tau_class and S_(1) - S_(2) >= delta_margin, else UNKNOWN / AMBIGUOUS.
tau_class, delta_margin: set on validation so ~10% of correctly-argmaxed known validation incidents would be rejected.
Weights (configs/default.yaml): C2 = TCN, graph, periodicity_new, destination persistence, jitter regularity, destination focus;
RECON = graph, new-edge rate, fan-out, port diversity, IF; DDOS = M, IF, packet/byte-rate surge, burst growth, many-to-one;
EXFIL = M, IF, outbound volume, flow duration, sustained transfer, new persistent destination.
Validation change (before test): cyclic scans re-contact targets periodically, so recon read as C2; a destination-focus term
(1 - fan-out anomaly) was added to C2. Scores are compatibility scores, not probabilities.
