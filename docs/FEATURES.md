# Features
Registry: `configs/features.yaml` (name, group, requires_reverse, one_way_safe). Volume: pps/bps out and in, packet and
flow counts. Packet: mean/std/min/max length. Timing: mean/std IAT, jitter, IAT quantiles, periodicity (1 - CV of contact
intervals over 60 s), jitter regularity, recurrence interval, periodicity_new (only destinations outside the host's learned
relationships). Communication: fan-out, fan-in, destination ports, SYN rate, new-destination rate, destination persistence
(share of 10 s buckets in 60 s). Transfer: outbound bytes, max flow duration, sustained-transfer ratio. Graph: new edges,
persistent new edges, cross-community new edges, fan-out/fan-in change, novel inbound sources, community instability, modularity.
Reverse-dependent (never used): bidirectional_byte_ratio, handshake_completion_rate.
