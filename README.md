# TESTERPy2 - T1059.006 EDR/AV Testing Platform

<p align="center">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-T1059.006-red?style=for-the-badge" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green?style=for-the-badge" alt="Platform">
</p>

## Overview

**TESTERPy2** is an open-source security testing platform designed to evaluate EDR/AV detection capabilities against Python-based offensive techniques. The platform focuses exclusively on **MITRE ATT&CK T1059.006** (Command and Scripting Interpreter: Python), testing whether security solutions can detect malicious activities executed through Python.

### Why T1059.006?

Python is increasingly used by sophisticated threat actors because:
- **Cross-platform**: Same code runs on Windows, Linux, and macOS
- **Rich standard library**: Built-in modules for system interaction (ctypes, subprocess, socket)
- **Legitimate presence**: Python is often pre-installed or used for legitimate development
- **Easy obfuscation**: Code can be compiled, packed, or obfuscated
- **Living-off-the-land**: No need to drop additional binaries

### Known APT Groups Using Python

| Group | Country | Malware |
|-------|---------|---------|
| APT29 | Russia | SeaDuke |
| Lazarus | North Korea | InvisibleFerret |
| APT39 | Iran | Chafer tools |
| MuddyWater | Iran | Out1 |
| APT31 | China | ZIRCONIUM implants |
| Machete | Venezuela | Machete malware |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     TESTERPy2 Dashboard                       │
│                    (Flask Web Application)                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Agents    │  │    Tests    │  │        Results          │ │
│  │   Panel     │  │    Panel    │  │         Panel           │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP API
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│    Agent      │   │    Agent      │   │    Agent      │
│   (Windows)   │   │   (Linux)     │   │   (macOS)     │
│               │   │               │   │               │
│ ┌───────────┐ │   │ ┌───────────┐ │   │ ┌───────────┐ │
│ │ 5 Tests   │ │   │ │ 5 Tests   │ │   │ │ 5 Tests   │ │
│ └───────────┘ │   │ └───────────┘ │   │ └───────────┘ │
└───────────────┘   └───────────────┘   └───────────────┘
```

## Test Scenarios

### T001: Python Shellcode Loader
**Techniques:** T1059.006, T1055.001, T1106

Tests EDR detection of Python-based shellcode injection using ctypes for:
- Memory allocation via `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`
- Shellcode copying to allocated memory
- Thread creation pointing to shellcode

**Detection Points:**
- Python process calling VirtualAlloc with RWX permissions
- CreateThread from Python with suspicious start address
- Memory regions with execute permissions

### T002: Python Defense Evasion
**Techniques:** T1059.006, T1562.001, T1027

Tests EDR detection of security product tampering:
- AMSI bypass via AmsiScanBuffer location
- ETW provider enumeration
- Ntdll reading from disk (unhooking preparation)
- Environment variable manipulation

**Detection Points:**
- Access to amsi.dll exports
- ETW provider tampering indicators
- Reading system DLLs from disk

### T003: Python Credential Dumper
**Techniques:** T1059.006, T1003.001, T1003.002, T1552.001

Tests EDR detection of credential access:
- SAM registry hive access attempt
- LSASS process enumeration and memory access
- DPAPI master key directory access
- Linux /etc/shadow access
- SSH private key enumeration

**Detection Points:**
- Registry access to SAM/SECURITY hives
- OpenProcess on LSASS
- DPAPI directory enumeration
- Shadow file read attempts

### T004: Python Browser Stealer
**Techniques:** T1059.006, T1555.003, T1539

Tests EDR detection of browser data theft:
- Chrome Login Data SQLite extraction
- Chrome Cookies database copying
- Firefox logins.json parsing
- Edge credential file access

**Detection Points:**
- Access to browser profile directories
- SQLite operations on credential databases
- Copying browser data files

### T005: Python Discovery & Collection
**Techniques:** T1059.006, T1082, T1083, T1056.001, T1113

Tests EDR detection of reconnaissance and surveillance:
- System information enumeration
- Network configuration discovery
- Process listing
- Screenshot capability check
- Keyboard state access (keylogger prep)
- File system traversal

**Detection Points:**
- Bulk system enumeration patterns
- GetDC/screenshot API calls
- Keyboard hook indicators
- Rapid file system access

## Installation

### Requirements
- Python 3.8+
- Flask
- requests

### Server Setup

```bash
# Clone or download the project
cd testerpy2

# Install dependencies
pip install flask requests

# Start the dashboard
python app.py
```

The dashboard will be available at `http://localhost:5000`

### Agent Deployment

```bash
# On target system (Windows/Linux/macOS)
python agent.py --server http://<server-ip>:5000

# With custom beacon interval
python agent.py --server http://192.168.1.100:5000 --interval 5
```

## Usage

### 1. Start the Dashboard
```bash
python app.py
```

### 2. Deploy Agent(s)
```bash
python agent.py -s http://<dashboard-ip>:5000
```

### 3. Execute Tests
- Select an agent from the Connected Agents panel
- Click "Execute" on individual tests or "Run All Tests"
- Monitor results in the Results panel

### 4. Interpret Results

| Status | Meaning |
|--------|---------|
| **Success** (Green) | Test completed without EDR intervention - technique bypassed |
| **Detected** (Yellow) | EDR blocked or flagged the activity |
| **Failed** (Red) | Test encountered an error (not detection-related) |
| **Skipped** (Gray) | Test not applicable to this platform |
| **Pending** (Blue) | Test queued, waiting for execution |

## API Endpoints

### Agent Communication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agent/register` | POST | Register new agent |
| `/api/agent/beacon` | POST | Agent check-in, retrieve commands |
| `/api/agent/result` | POST | Submit test results |

### Dashboard
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agents` | GET | List all agents |
| `/api/tests` | GET | Get test definitions |
| `/api/results` | GET | Get all results |
| `/api/execute` | POST | Queue single test |
| `/api/execute_all` | POST | Queue all tests |
| `/api/stats` | GET | Dashboard statistics |

## Security Considerations

⚠️ **WARNING: This tool is for authorized security testing only.**

1. **Legal Authorization**: Only use on systems you own or have explicit written permission to test
2. **Isolated Environment**: Run tests in isolated lab environments when possible
3. **Network Segmentation**: Keep the dashboard on a separate network segment
4. **Logging**: All test executions are logged on the dashboard
5. **Benign Payloads**: All tests use non-destructive, benign payloads

## Detection Development

Use TESTERPy2 results to develop detections for:

### Windows (KQL/Defender)
```kql
DeviceProcessEvents
| where FileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| where ProcessCommandLine has_any ("ctypes", "VirtualAlloc", "CreateThread")
| where ProcessCommandLine has_any ("-c", "-m", "exec", "eval")
```

### Linux (Sigma)
```yaml
title: Suspicious Python Execution
logsource:
    product: linux
    service: auditd
detection:
    selection:
        exe|endswith: '/python'
    keywords:
        - '/etc/shadow'
        - 'ctypes'
        - 'subprocess'
    condition: selection and keywords
```

## References

- [MITRE ATT&CK T1059.006](https://attack.mitre.org/techniques/T1059/006/)
- [Atomic Red Team - T1059.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.006/T1059.006.md)
- [APT29 SeaDuke Analysis](http://www.symantec.com/connect/blogs/forkmeiamfamous-seaduke-latest-weapon-duke-armory)
- [InvisibleFerret Analysis](https://www.welivesecurity.com/en/eset-research/deceptivedevelopment-targets-freelance-developers/)

## License

For authorized security testing and research purposes only.

---

**Built for EDR/AV evaluation and detection engineering. https://breachsimrange.io**
