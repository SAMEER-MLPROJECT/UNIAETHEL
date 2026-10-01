# Stage 2 — temporal context

A causal TCN was added to model sequences of host behaviour rather than isolated windows.

```text
features(t-k ... t)
        ↓
   causal TCN
        ↓
 temporal anomaly
```

Held-out result: **8/16 detected**.

The addition exposed an important trade-off: temporal modelling increased sensitivity but also increased false alerts on benign periodic or changing applications. This became a reason to retain the TCN as one evidence source rather than allowing it to make the incident decision by itself.

The final implementation uses the TCN as a next-window prediction model. It should not be described as a standalone C2 classifier. The final evaluation explicitly found that pure periodic beacon cases were not independently solved by the TCN; persistent communication relationships were important graph evidence.
