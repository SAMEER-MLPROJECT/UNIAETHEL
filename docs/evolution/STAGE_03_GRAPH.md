# Stage 3 — communication topology

The graph layer was introduced because some attacks are better described by **who communicates with whom** than by packet volume alone.

The system builds a directed rolling graph from observed A→B relationships. An undirected copy is used only for Louvain community detection; the underlying observation remains directional.

```text
observed flows
     ↓
rolling directed graph
     ↓
community / edge-change signals
     ↓
graph anomaly evidence
```

The four-engine configuration detected **10/16** before persistence and trajectory were added.

The component-removal experiment is even more informative: removing Graph + Louvain reduced the final system from **16/16 to 4/16** on the same frozen evaluation.

The graph is therefore not a decorative visualization. It provides information that the per-host statistical engines do not contain.
