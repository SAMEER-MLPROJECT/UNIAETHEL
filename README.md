# UniAethel

### Passive behavioural threat detection for networks monitored through a data diode

**Smart India Hackathon 2026 · SIH26145 · NTRO · Team EigenThinkers, INSPIRED BY PREVIOUS RESEARCH MANUSCRIPT ABOUT PREDICTIVE MAINTAINENCE IN POWER GRID**

UniAethel is a research prototype for detecting and interpreting cyber-threat behaviour when a monitoring enclave receives only a **one-way copy of network traffic**. It does not probe hosts, send replies, perform handshakes, or depend on payload decryption.

> **The core idea:** do not ask the network for information that a data diode cannot provide. Instead, learn how each observed host normally behaves and look for corroborating changes in distribution, multivariate structure, time, and communication topology.

---

## Why the problem is different

A conventional IDS can often rely on bidirectional session state, active verification, or payload signatures. A data-diode monitor cannot. UniAethel therefore treats every observed packet as a directional observation and builds behavioural evidence without inventing a reverse packet or a missing reply.

The prototype processes:

flowchart TB

    A["ONE-WAY INPUT<br/>PCAP / Packet Copy<br/><sub>Read-only • No return traffic</sub>"]

    B["DIRECTIONAL FLOW EXTRACTION<br/>5-Tuple Flows<br/><sub>src IP • dst IP • src port • dst port • protocol</sub>"]

    C["TEMPORAL WINDOWING<br/>5 s Rolling Window • 1 s Step<br/><sub>Per-host behavioural observations</sub>"]

    A --> B --> C

    subgraph ENGINES["FOUR COMPLEMENTARY BEHAVIOURAL ENGINES"]
        direction LR

        M[" MAHALANOBIS<br/><b>Joint Geometry</b><br/><sub>Correlated statistical deviation</sub><br/><br/>Output → Aₘ"]

        I[" ISOLATION FOREST<br/><b>Multivariate Novelty</b><br/><sub>Unusual feature combinations</sub><br/><br/>Output → Aᵢғ"]

        T[" CAUSAL TCN<br/><b>Temporal Deviation</b><br/><sub>Past sequence → prediction error</sub><br/><br/>Output → Aₜᴄɴ"]

        G["GRAPH + LOUVAIN<br/><b>Communication Structure</b><br/><sub>Source → destination topology</sub><br/><br/>Output → Aɢ"]
    end

    C --> M
    C --> I
    C --> T
    C --> G

    E["PER-HOST CALIBRATION<br/><b>Evidence Vector</b><br/><br/>Aₜ = [ Aₘ , Aᵢғ , Aₜᴄɴ , Aɢ ]<br/><sub>Each score calibrated to [0,1]</sub>"]

    M --> E
    I --> E
    T --> E
    G --> E

    F[" EVIDENCE FUSION<br/><b>Severity + Agreement + Persistence</b><br/><sub>Independent evidence is retained</sub>"]

    E --> F

    H["THREAT TRAJECTORY<br/><b>Normal → Emerging → Persistent → High-Confidence</b><br/><sub>Incident state evolves over time</sub>"]

    F --> H

    V[" ATTACK-VECTOR COMPATIBILITY<br/><b>Behavioural evidence matching</b><br/><sub>Threshold + margin rejection</sub>"]

    H --> V

    X{"CLASSIFICATION"}

    V --> X

    X -->|High-confidence match| K[" KNOWN VECTOR<br/><b>C2 • RECON • DDoS • EXFIL</b>"]
    X -->|Insufficient / conflicting evidence| U["UNKNOWN<br/><b>Open-set rejection</b>"]

    K --> Z[" EXPLAINED INCIDENT<br/>+ HASH-LINKED EVIDENCE"]
    U --> Z

    classDef input fill:#e8f1ff,stroke:#3973b8,stroke-width:2px,color:#111827;
    classDef process fill:#f4f4f5,stroke:#71717a,stroke-width:1.5px,color:#111827;
    classDef engine fill:#eefbf3,stroke:#3b8f5c,stroke-width:1.5px,color:#111827;
    classDef fusion fill:#fff7e6,stroke:#c78a12,stroke-width:2px,color:#111827;
    classDef decision fill:#f5efff,stroke:#7b57b2,stroke-width:2px,color:#111827;
    classDef alert fill:#fff0f0,stroke:#c84b4b,stroke-width:2px,color:#111827;
    classDef unknown fill:#f2f2f2,stroke:#666666,stroke-width:2px,color:#111827;

    class A input;
    class B,C,E process;
    class M,I,T,G engine;
    class F,H fusion;
    class V,X decision;
    class K,Z alert;
    class U unknown;

    style ENGINES fill:#fafafa,stroke:#9ca3af,stroke-width:1.5px

The implementation is purposefully **not** a supervised LightGBM classifier. The final vector decision uses explicit compatibility functions with threshold and margin rejection; unknown or ambiguous behaviour remains `UNKNOWN`.

---

## What each engine asks

| Engine | Question |
|---|---|
| **Mahalanobis** | Is the joint pattern of volume/timing/features unusual for this host? |
| **Isolation Forest** | Is this combination of features in a region normal traffic rarely visits? |
| **Causal TCN** | Is the host's recent sequence departing from what its past predicts? |
| **Graph + Louvain** | Have communication relationships, peers or communities changed? |

The four scores remain separate:

$$
A_t = [A_M, A_{IF}, A_{TCN}, A_G]
$$

A single high score is not automatically an incident.

---

## Attack-vector decision

For each candidate vector $k \in \{C2, RECON, DDOS, EXFIL\}$:

$$S_k = \frac{C}{4}P\sum_j w_{kj}\phi_{kj}$$

where `C` is engine agreement, `P` is persistence, and $\phi_{kj}$ are normalized behavioural features relevant to the candidate vector.

The winner is accepted only if:
```text
max(S_k) >= τ_class
AND
max(S_k) - second_best(S_k) >= δ_margin
```

Otherwise:

```text
UNKNOWN
```

This is intentional. The system separates **anomaly detection** from **attack-vector naming**.

---

## Architecture evolution

The final system came from tested failures rather than from adding models for presentation value.

| Stage | Architecture | Held-out detection |
|---|---|---:|
| **0 — failed baseline** | scalar threshold | **2/16** |
| **0b** | Isolation Forest only | **0/16** |
| **1** | Mahalanobis + IF | **6/16** |
| **2** | + causal TCN | **8/16** |
| **3** | + Graph/Louvain | **10/16** |
| **4** | + corroboration + persistence | **16/16** |
| **5** | + trajectory | **16/16** |
| **6** | + attack-vector compatibility + UNKNOWN rejection | **16/16 detected; 8/14 known incidents named** |

See [`docs/evolution/`](docs/evolution/) for the reasoning behind each stage.

The earliest baseline is intentionally preserved as a **failed hypothesis**, not hidden. It is the reason the final design uses multiple independent views.

---

## Current evaluation

The current repository contains a frozen synthetic-PCAP evaluation. The important results are:

| Measure | Result |
|---|---:|
| Attack episodes detected | **16 / 16** |
| Median detection latency | **19 s** |
| Known attack-vector incidents named | **8 / 14** |
| Known incidents rejected as UNKNOWN | **6 / 14** |
| Known-class confusions | **0** |
| Never-seen pattern rejected as UNKNOWN | **5 / 5** |
| C2 cases across 0–50% jitter | **10 / 10** named correctly |
| Detection at 50% packet loss | **4 / 4** |
| Recorded false alerts | **9.3 / h** |
| Single-core throughput | **22,011 packets/s, 162 Mbps** |
| Automated tests | **38 passing** |

### Read the numbers correctly

The 16/16 result is **not** a claim of real-world 100% detection. The evaluation uses synthetic PCAPs from a simulated 22-host network. The main present weakness is false alerts, and reconnaissance was detected but rejected as `UNKNOWN` in the recorded classification evaluation.

See [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md) and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

---

## Demonstration

The repository contains five deterministic demo PCAPs:

```text
C2
Recon
DDoS
Exfiltration
Unknown / unseen pattern
```

Run:

```bash
pip install -r requirements.txt
python scripts/run_demo.py
```

Or reproduce the complete experiment pipeline:

```bash
python scripts/run_all.py
```

The full pipeline generates the data, trains the prototype models, runs demonstrations, ablations, robustness sweeps, benchmarks, ledger verification and documentation generation.

Run tests:

```bash
python -m pytest -q
```

---

## Repository map

```text
.
├── src/uniaethel/
│   ├── capture/        PCAP ingestion
│   ├── flows/          directional 5-tuple flows
│   ├── features/       rolling-window features
│   ├── models/         Mahalanobis, IF, TCN, Graph/Louvain
│   ├── fusion/         severity, corroboration, trajectory, vector decision
│   ├── forensics/      hash-linked evidence ledger
│   ├── evaluation/     metrics and evaluation runner
│   └── simulation/     deterministic traffic generation
├── configs/            all tunable parameters
├── scripts/             training, demo, ablation, robustness and benchmark tools
├── tests/                unit/integration tests
├── data/                 demo data and dataset manifest
├── results/              frozen parameters, metrics and demo outputs
├── docs/
│   ├── evolution/        architecture history and failed stages
│   ├── ARCHITECTURE.md
│   ├── MODELS.md
│   ├── CLASSIFICATION.md
│   ├── EXPERIMENTS.md
│   ├── BENCHMARK.md
│   ├── LIMITATIONS.md
│   └── CLAIMS_AND_EVIDENCE.md
└── app/                   read-only API/dashboard
```

---

## Reproducibility and experimental discipline

The repository keeps the test configuration frozen and records hashes for the parameter set. The test split was scored after freezing. The goal is to make the reported result reproducible rather than to tune against the test set until a preferred number appears.

The project also includes ablations for:

- single-signal thresholding;
- Isolation Forest alone;
- Mahalanobis + IF;
- + TCN;
- + Graph;
- + corroboration;
- + persistence;
- + trajectory;
- arithmetic versus geometric severity;
- removal of individual engines.

The component-removal results are particularly useful for understanding what each part actually contributes.

---

## Current limitations and next work

1. **Synthetic traffic only.** Next: replay CIC-IDS2017 / CTU-13 and build a controlled data-diode testbed.
2. **False-alert rate is still too high.** More benign captures and independent calibration are required.
3. **Recon is detected but currently rejected as UNKNOWN.** The RECON compatibility profile needs validation-based re-weighting.
4. **Benign periodic agents can resemble C2.** A service allow-list should be advisory rather than silently overriding behavioural evidence.
5. **Slow exfiltration can remain inside a host's normal range.** A longer horizon and cumulative-volume features are planned.
6. **Live streaming has not yet been evaluated.** Current throughput is a batch benchmark.

These are documented as limitations, not hidden from the evaluation.

---

## Submission material

The SIH26145 submission deck is retained at [`docs/submission/`](docs/submission/).

---

## Research lineage

UniAethel grew from earlier work on behavioural anomaly detection and tamper-evident records in a smart-grid setting. That earlier project provided methodological inspiration; its performance numbers are **not reused** for this network-security evaluation.

See the SIH deck and the research/reference documentation for the stated lineage.

---

## Status

**Implemented:** PCAP ingestion, directional flows, four engines, calibration, fusion, persistence, trajectory, attack-vector layer, UNKNOWN rejection, explanations, hash ledger, API/dashboard, synthetic scenario generator, evaluation and tests.

**Experimentally verified:** frozen synthetic-PCAP evaluation described above.

**Future:** independent real-traffic validation, live streaming, diode hardware testbed, larger benign calibration corpus.
