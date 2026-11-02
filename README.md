# AMAN Emergency Network - Phase 1 & Phase 2 Evaluation

National Emergency Safety Network Simulation using **ns-3 (v3.40)** and **AODV** routing protocol. Evaluates network resilience under attack scenarios and validates mitigation using a dynamic Intrusion Detection System (IDS) and security layer (AES-128 / HMAC-SHA256).

---

## Technical Configuration & Environment

- **Simulator:** ns-3 (v3.40)
- **Routing Protocol:** AODV (Ad hoc On-Demand Distance Vector)
- **Security & Crypto Layer:** AES-128 Encryption & HMAC-SHA256 Authentication
- **Detection System:** Dynamic Promiscuous Mode Intrusion Detection System (IDS)
- **Evaluated Metrics:**
  - Packet Delivery Ratio (PDR %)
  - Throughput (kbps)
  - Average End-to-End Delay (ms)
  - Energy Consumption (%)

---

## Project Structure

```text
AMAN-Secure-Emergency-Network-NS3/
├── README.md               # Complete Project Documentation (Phases 1 & 2)
├── analyze_aman.py         # Automated simulation log parser & metrics processor
├── generate_charts.py      # Automated visualization generator
└── scratch/
    └── aman.cc             # Core C++ ns-3 simulation script
```
Phase 1: Blackhole Attack Baseline Evaluation
Phase 1 establishes baseline performance parameters for normal AODV routing in an emergency disaster response scenario and measures performance degradation under a standard single-node Blackhole attack without active defenses.

Phase 1 Execution Commands
```text
# Clean previous simulation trace outputs
rm -f aman-flow-*.xml energy_*.txt

# Run Baseline Simulation (Normal Network)
./ns3 run "scratch/aman_phase1"

# Run Blackhole Attack Scenario (Unprotected Network)
./ns3 run "scratch/aman_phase1 --blackhole=true"

# Parse metrics and output performance analysis
python3 analyze_aman_phase1.py

# Generate comparison plots
python3 generate_charts_phase1.py
```
Phase 2: Malicious Attack Modeling (Blackhole & Grayhole) & Dynamic IDS Evaluation
Phase 2 models malicious attacks at the Traffic Control Layer within network Choke Points, introducing both Blackhole and Grayhole (selective 15% drop rate) attacks. It measures the defense efficiency of the dynamic IDS (MacTxDrop promiscuous tracking) alongside the cryptographic security overhead.

Key Objectives & Findings
1-Blackhole Attack Modeling: Demonstrates 100% drop rate of data packets exceeding 200 bytes by malicious nodes attracting routing paths, severe PDR drop, and communication blackouts.

2-Grayhole Attack Modeling: Features selective, randomized packet dropping (15%), preserving a deceptively high PDR to evade traditional static detection mechanisms.

3-IDS Detection Efficiency: Dynamic IDS successfully isolated malicious nodes (Node 50 & Node 51) by continuously monitoring Layer-2 drop events (MacTxDrop) against predefined threshold rules.

4-Security & Cryptographic Overhead: Enforcing AES-128/HMAC-SHA256 along with active IDS monitoring introduces a minor, acceptable increase in End-to-End Delay and Energy Consumption (< 10%), well justified for mission-critical emergency communications.

Phase 2 Execution Script
You can execute the entire Phase 2 test matrix (Baseline, Security-Only, Attacks, Mitigation, and 50-Node Scalability Testing) using the following automated command sequence:
```text
#!/bin/bash
# 1. Clean previous simulation artifacts
rm -f aman-flow-*.xml energy_*.txt

# 2. Baseline Scenario
./ns3 run "scratch/aman_phase2"

# 3. Standalone Security Layer Test
./ns3 run "scratch/aman_phase2 --security=true"

# 4. Attack Scenarios (Unprotected vs. Protected)
./ns3 run "scratch/aman_phase2 --blackhole=true"
./ns3 run "scratch/aman_phase2 --blackhole=true --security=true"
./ns3 run "scratch/aman_phase2 --grayhole=true"
./ns3 run "scratch/aman_phase2 --grayhole=true --security=true"
./ns3 run "scratch/aman_phase2 --blackhole=true --grayhole=true --security=true"

# 5. Scalability Testing (50 Mobile Nodes)
./ns3 run "scratch/aman_phase2 --blackhole=true --security=true --nNodes=50"
./ns3 run "scratch/aman_phase2 --grayhole=true --security=true --nNodes=50"

# 6. Parse Data and Generate Visualizations
python3 analyze_aman_phase2.py
python3 generate_charts_phase2.py
xdg-open aman_simulation_results.png &
```
## Academic Context

Developed as part of the Information Technology Engineering graduation project at **Homs University** by **Eng. Ali Morhaf Abdoo** (Information Technology Engineer, specialized in Network & Computer Systems Engineering), focusing on resilient emergency networks, Mobile Ad-Hoc Networks (MANETs), and real-time security mitigation mechanisms.

- **Graduation Project Grade:** 93 / 100 (93%)
- **Degree & Qualification:** Information Technology Engineer (B.Sc. in IT Engineering)
- **Specialization:** Network & Computer Systems Engineering
