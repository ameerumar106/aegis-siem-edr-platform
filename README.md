# AegisGuard: Hybrid SIEM & EDR Security Platform 🛡️

A high-performance, multi-layered cyber defense platform engineered to combine deep network packet telemetry inspection with real-time host file integrity auditing (HIDS). 

## 🚀 Key Architectural Pillars

* **Network Telemetry Layer (`live_sniffer.py`):** Utilizes Scapy for real-time deep packet inspection (DPI). Implements automated Reverse DNS resolution and offline GeoIP country enrichment via MaxMind.
* **Host EDR Layer (`fim_worker.py`):** Leverages a cryptographic SHA-256 baseline mapping matrix to monitor critical malware dropzones (`%APPDATA%`) and network configurations (`hosts` file) using event-driven file hooks.
* **Intelligent Anomaly Detection:** Features a rolling statistical baseline engine utilizing standard deviation ($\mu + 3\sigma$) to catch volumetric traffic spikes without heavy ML dependencies.
* **Enterprise SOC Escalation:** Implements a low-overhead memory batching buffer to protect SQLite from write-locks, paired with zero-latency webhook streams to Slack channels for immediate incident triage.


## 🖥️ Application Interface

![Aegis SIEM EDR Platform](preview.png)

---
## 🛠️ Local Deployment

1. Install requirements: `pip install scapy watchdog geoip2`
2. Place your `GeoLite2-Country.mmdb` inside the `storage/` directory.
3. Boot the sensor stack:
   ```bash
   python live_sniffer.py
   python fim_worker.py
   python -m dashboard.app