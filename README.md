# CodeAlpha_NetworkIntrusionDetectionSystem

## Overview
This project demonstrates a network-based Intrusion Detection System (NIDS) using Suricata for detection + Python scripts to parse alerts, auto-respond (block offending IPs), and create visualizations.

## Repo structure
- `suricata_rules/` - example custom rules
- `scripts/`
  - `suricata_eve_watcher.py` - realtime watcher: parse `eve.json` and optionally block IPs
  - `extract_alerts.py` - parse `eve.json` and write CSV report
  - `visualize_alerts.py` - build a simple bar chart of alert types
- `README.md` - this file

## Tools used
- Suricata (IDS)
- Python 3.8+ (json, csv, matplotlib)
- iptables (for blocking — root required)
- (Optional) Elasticsearch + Kibana for production visualization

## Installation (Ubuntu / Debian)
1. Install Suricata:
   ```bash
   sudo apt update
   sudo apt install suricata -y
