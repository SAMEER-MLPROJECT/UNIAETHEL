# One-way observation contract

UniAethel is a passive detector for a unidirectional (data-diode) observation path.

ALLOWED                                   FORBIDDEN
- packet capture (read-only)              - packet transmission of any kind
- packet parsing (headers only)           - scanning, pinging, probing hosts
- directional flow construction           - TCP handshakes / DNS queries into the network
- timing and metadata analysis            - TCP RSTs, mitigation or injected packets
- local inference                         - reliance on reverse-direction packets
- local evidence logging (hash chain)     - request/response pairing, payload decryption

How the code enforces it
- `capture/pcap.py` only reads files; no module opens a network socket for sending (the API is read-only).
- `flows/flows.py` keys flows on the directional 5-tuple; A->B and B->A are separate flows.
- `configs/features.yaml` marks every feature `requires_reverse`; the two reverse-dependent features are dropped
  in every one-way mode and are used by no engine.
- `observation.mode`: unpaired (each packet its own observation), egress_only, ingress_only.

Tests: `tests/test_ingest_oneway.py::test_reverse_traffic_is_never_required` (outbound features identical with and
without reverse traffic; reverse features absent), `::test_directional_flows_never_merge_reverse`.
