# Stage 5 — trajectory and threat state

A static alert did not adequately represent how a behavioural deviation evolves. The system therefore introduced a small incident state machine:

```text
NORMAL → EMERGING → PERSISTENT → HIGH-CONFIDENCE
```

The trajectory layer uses recent severity/domain evidence and hysteresis rather than treating every window independently.

The full trajectory configuration retained **16/16** detection on the frozen test and produced the incident-level state used by the dashboard and explanation layer.
