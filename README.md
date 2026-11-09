# 🦈 Wireshark Network Traffic Analysis

A growing collection of packet-capture investigations. In each case I start from a SIEM alert or clue, pivot through the traffic with Wireshark display filters, and document an incident report with findings, indicators of compromise, MITRE ATT&CK mapping, and practical recommendations.

---

## 📂 Case Studies

| # | Case | Date | Key Skills & Protocols | Report Link |
| :-: | :--- | :-: | :--- | :-: |
| **01** | NetSupport RAT Infection | Nov 2026 | Traffic Pivoting, Unencrypted HTTP over 443, C2 Beacon Analysis, Kerberos / NBNS / SAMR Extraction, MITRE ATT&CK | [Read Case 01 Report](case-01-netsupport-rat/README.md) |

---

## 🛠️ Tools & Frameworks

* **Network Analysis:** Wireshark
* **Threat Mapping:** MITRE ATT&CK Framework

---

## 🔍 General Methodology

For every capture investigated:
1. **Scenario & Triage:** Identify initial indicators from SIEM alerts or background context.
2. **Traffic Pivoting:** Filter down high-volume captures to isolate malicious streams.
3. **Evidence Extraction:** Retrieve host identity, user accounts, and payload artifacts.
4. **Documentation:** Write a formal incident report featuring screenshots, defanged IOC tables, MITRE ATT&CK mapping, and mitigation/detection guidance.

---

## ⚠️ Notes

All packet captures (`.pcap` / `.pcapng`) originate from public security training datasets (e.g., *Malware-Traffic-Analysis.net*) and are linked inside each individual report directory rather than hosted directly in this repository.