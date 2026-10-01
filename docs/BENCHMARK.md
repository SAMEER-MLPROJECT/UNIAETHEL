# Benchmark (scripts/benchmark.py; measured, single core)
Hardware: {'cpu': 'x86_64', 'cores': 1, 'ram_gb': 4.2}; OS: Linux-6.18.44-fc-v50-x86_64-with-glibc2.39; Python 3.12.3; {'numpy': '2.4.4', 'pandas': '3.0.2', 'scikit-learn': '1.8.0', 'networkx': '3.6.1'}
Mode: batch replay of 300 s captures, single process, parse+flows+windows+4 engines+fusion+classification. 17 captures, 706546 packets.

| metric | value |
|---|---|
| packets/s | 22011 |
| flows/s | 4402 |
| Mbps (original packet sizes) | 161.7 |
| latency per 300 s capture p50 / p95 / p99 | 1.85 / 2.38 / 2.77 s |
| amortised cost per 1 s step (all hosts) p50 / p95 / p99 | 6.2 / 7.9 / 9.2 ms |
| slowest real-time factor | 104x |
| peak RSS | 549 MB |
| dropped packets | 0 (offline replay) |

Replay at increasing input rates (DDoS volume sweep): [{'file': 'ddos_volume_100_s301.pcap', 'input_pps': 115.7, 'pps': 19657.4, 'realtime_factor': 169.9}, {'file': 'ddos_volume_200_s301.pcap', 'input_pps': 140.7, 'pps': 22774.1, 'realtime_factor': 161.9}, {'file': 'ddos_volume_25_s301.pcap', 'input_pps': 96.9, 'pps': 18156.5, 'realtime_factor': 187.3}, {'file': 'ddos_volume_400_s301.pcap', 'input_pps': 190.7, 'pps': 25766.8, 'realtime_factor': 135.2}, {'file': 'ddos_volume_50_s301.pcap', 'input_pps': 103.2, 'pps': 20007.1, 'realtime_factor': 193.9}]
Streaming (live packet-by-packet) latency is NOT RUN; these are batch replay measurements.
