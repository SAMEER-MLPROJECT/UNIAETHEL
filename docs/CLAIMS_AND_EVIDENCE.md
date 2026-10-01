# Claims and evidence

This file separates what the repository demonstrates from what remains future work.

## Demonstrated on the supplied synthetic evaluation

- passive PCAP replay without sending packets into the protected network;
- directional 5-tuple flow processing;
- 5 s windows stepped every 1 s;
- four analytical engines;
- per-host calibration;
- evidence fusion, corroboration, persistence and trajectory state;
- attack-vector compatibility with UNKNOWN rejection;
- hash-linked alert records;
- 38 automated tests;
- 16/16 attack episodes detected on the frozen synthetic test;
- 8/14 known incidents named, with 6 rejected as UNKNOWN;
- 5/5 incidents of the never-seen test pattern rejected as UNKNOWN;
- 22,011 packets/s and 162 Mbps in the recorded single-core batch benchmark.

## Not demonstrated yet

- real operational network traffic;
- live streaming deployment;
- production data-diode hardware;
- generalization to arbitrary organisations or host populations;
- robust low false-positive operation in a long-running SOC;
- egress-only/ingress-only baselines under independent validation;
- payload decryption or payload inspection.

All headline results in the current repository are based on synthetic PCAPs. See `docs/LIMITATIONS.md` and `docs/EXPERIMENTS.md`.
