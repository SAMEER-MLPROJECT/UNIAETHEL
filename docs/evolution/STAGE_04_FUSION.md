# Stage 4 — corroboration and persistence

The four engines were deliberately prevented from becoming a single opaque score.

The system retains:

```text
A_t = [A_M, A_IF, A_TCN, A_G]
```

and derives separately:

- severity;
- agreement/corroboration;
- persistence.

Persistence is the share of the previous six windows whose severity exceeds the incident threshold.

This distinction matters because one unusual window can be benign. A persistent anomaly supported by multiple domains is treated differently.

In the frozen ablation, adding persistence raised detection from **10/16 to 16/16**. This was one of the key architectural transitions.
