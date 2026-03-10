#  YARA Rules & Malware Hunting Lab
This repository documents my hands-on training for **Threat Hunting** and **Malware Analysis** using YARA rules and Memory Forensics tools.

---

##  Case Study 1: WannaCry Ransomware (Memory Forensics)

### 🔍 Overview
WannaCry is a notorious ransomware that targets Windows systems. One of its key behaviors is deleting **Volume Shadow Copies** to prevent users from recovering their files.

###  Investigation Methodology
1. **Threat Intel:** Identified that the malware uses `vssadmin.exe` to delete shadows.
2. **Memory Analysis:** Used **Volatility Framework** with the `yarascan` plugin to search for this behavior in a memory dump (`compromised_system.raw`).

###  Hunting Command
```bash
vol.py -f compromised_system.raw yarascan -U "vssadmin"
