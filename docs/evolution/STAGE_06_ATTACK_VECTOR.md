# Stage 6 — attack-vector compatibility and UNKNOWN rejection

Detection and attack-vector naming are deliberately separated.

For each candidate vector `k` in `{C2, RECON, DDOS, EXFIL}`:

```text
S_k = (C/4) · P · Σ_j w_kj φ_kj
```

where:

- `C` is the number of engine scores over their calibrated agreement thresholds;
- `P` is incident persistence;
- `φ_kj` is a normalized feature compatible with vector `k`;
- `w_kj` is the validated weight for that feature.

The winning class is accepted only when:

```text
max(S_k) >= τ_class
AND
max(S_k) - second_best(S_k) >= δ_margin
```

Otherwise the incident becomes `UNKNOWN`.

This was introduced to prevent the system from turning every anomaly into a known attack label. On the frozen evaluation, 8/14 known incidents received a known label, 6 were rejected as `UNKNOWN`, and 5/5 incidents from the never-seen pattern were rejected as `UNKNOWN`.
