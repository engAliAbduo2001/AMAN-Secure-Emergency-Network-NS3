# AMAN Emergency Network - Phase 1: Blackhole Attack Evaluation

## Overview
This repository contains the simulation code for **Project AMAN** (National Emergency Safety Network) developed at Homs University. 
This first phase evaluates the baseline performance and vulnerability of MANETs under a malicious **Blackhole Attack** without active security mitigation.

## Technical Configuration
- **Simulator:** ns-3 (v3.40)
- **Routing Protocol:** AODV
- **Scenario:** Blackhole Attack active, Security/IDS disabled.

## Execution Command
```bash
rm -f aman-*.xml energy_*.txt
touch scratch/aman.cc
./ns3 run "scratch/aman"
./ns3 run "scratch/aman --security=true"
./ns3 run "scratch/aman --blackhole=true"
./ns3 run "scratch/aman --security=true --blackhole=true"
python3 analyze_aman.py
python3 generate_charts.py
xdg-open aman_simulation_results.png &
```
Author
Eng. Ali Morhaf Abdo

Faculty of Information Technology Engineering, Homs University (2026)
