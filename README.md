# Toph Behavioral SIEM

> Toph Behavioral SIEM is a modular, Python-based, log analyzer and simulator. It generates realistic corporate network logs and analyzes them in order to detect brute-force attacks and suspicious activity.

## Project concept and "Seismic Sense"

The project's name, "Toph", is inspired by Avatar's fictional character "Toph Beifong" and her ability to sense nearly imperceptible  movement, vibrations and danger. In this case, the SIEM-like engine can "sense" the cadence of logs overtime and meticulously analyze them to extract information and conclude if the network is under attack, and what is the severity of said attacks.

## Architecture Overview

* **The Telemetry Simulator:** 'logGenerator.py' generates high-fidelity network behavior. It uses peak-hour weighting and IP variety in order to probabilistically generate accesses and attack bursts, simulating employee workflow, external users visiting and threat actors attempting, and at times managing, to break into the network
* **The Behavioral Detection Engine:** 'toph.py' streams JSON telemetry provided by the log script and maintains an in-memory state table to evaluate what is potentially and attack and estimate the severity of those, using the CVSS metric in order to provide the user with enough tools to mitigate the attacks.

## Sample Output

> The detection engine is currently in active development.
> A real console output sample will be added upon first stable release.
> See `toph.py` for current detection logic and alert formatting.

## Repository Structure

```text
├── logGenerator.py      # Synthetic telemetry generation engine
├── toph.py              # Stateful streaming log analyzer
├── log.json             # Generated network event log dataset
└── README.md            # System documentation
```

## Getting Started

### Prerequisites
* Python 3.x (no external dependencies required)

### Execution

1. **Clone the Repository:**
```bash
   git clone https://github.com/dearkepha/toph-behavioral-siem.git
   cd toph-behavioral-siem
```

2. **Generate the Network Telemetry Dataset:**
```bash
   python logGenerator.py
```
This executes the simulation script, generating a realistic log.json file populated with typical corporate user baseline events alongside anomalous traffic spikes and attack bursts.

3. **Run the Stateful Analyzer:**
```bash
   python toph.py
```
This initializes the detection engine, processing the generated logs and streaming real-time alerts to the console whenever an automated attack or policy violation is discovered.

## Limitations & Future Work

- Log ingestion is file-bound (log.json); planned support for real-time syslog and stdin streaming
- CVSS is currently estimated from attack-pattern heuristics; proper CVSS v3.1 vector string calculation is a planned improvement
- No persistent storage — all state is in-memory and lost between runs;
  a SQLite backend is under consideration
