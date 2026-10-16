# System & Network Leak Detector

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Cross Platform">
  <img src="https://img.shields.io/badge/Mode-Read--Only-green.svg" alt="Read Only">
</p>

<h3 align="center">
Enterprise-Grade Network Leak Detection & Privacy Auditing Framework
</h3>

<p align="center">
Detect DNS leaks, WebRTC exposure, routing anomalies, multicast disclosure risks, and insecure socket bindings through a unified cross-platform diagnostic engine.
</p>

<p align="center">
✅ Read-Only Operation &nbsp; • &nbsp;
✅ Cross-Platform &nbsp; • &nbsp;
✅ Privacy Focused &nbsp; • &nbsp;
✅ Zero Configuration Changes
</p>

---

## Overview

**System & Network Leak Detector** is a comprehensive network diagnostics and privacy auditing framework designed to identify information leakage pathways across modern operating systems.

The framework performs multi-layer inspection of routing behavior, DNS resolution chains, multicast exposure, WebRTC public IP disclosure, and active socket communications to help security researchers, privacy-conscious users, system administrators, and VPN users validate network integrity.

Unlike many diagnostic tools, the framework operates using a **strict read-only methodology**, ensuring that system state, network adapters, routing tables, firewall rules, and DNS settings remain untouched during analysis.

> ### 🔒 Operational Safety Guarantee
>
> This framework never modifies:
>
> - Network interfaces
> - Routing tables
> - Firewall policies
> - DNS configuration
> - VPN settings
> - Kernel networking parameters
>
> All modules perform passive inspection or temporary diagnostic probing only.

---

# 🚀 Key Features

## Layer 3 Routing & Tunnel Analysis

Perform deep inspection of system routing behavior:

- IPv4 route table auditing
- IPv6 route table auditing
- Default gateway verification
- Route metric analysis
- Multi-homed network detection
- VPN route validation
- Tunnel interface enumeration

Supported tunnel technologies include:

- WireGuard
- OpenVPN
- AmneziaVPN
- TUN/TAP adapters
- Platform-native VPN interfaces

---

## Local Network Exposure Detection

Identify services capable of unintentionally exposing host identity within local networks.

| Protocol | Port | Purpose |
|-----------|--------|----------|
| mDNS | 5353 | Multicast DNS |
| LLMNR | 5355 | Windows Name Resolution |
| NetBIOS | 137 / 138 | Legacy Host Discovery |
| SSDP | 1900 | UPnP Service Discovery |

The framework verifies:

- Active listeners
- Interface bindings
- Broadcast participation
- Multicast subscriptions

---

## WebRTC Leak Assessment

Web browsers and communication applications frequently expose network information through STUN infrastructure.

The framework:

- Executes RFC 5389 STUN binding requests
- Queries multiple public STUN endpoints
- Discovers reflexive public IP addresses
- Identifies VPN bypass conditions
- Detects unexpected WAN exposure

---

## DNS Leak Detection

Analyze DNS resolution paths and resolver consistency.

Capabilities include:

- Recursive resolver identification
- Split-horizon DNS validation
- ISP fallback detection
- Resolver mismatch analysis
- DNS path verification
- Tunnel-aware DNS auditing

---

## Socket & Process Correlation

Map active network connections directly to local processes.

Collected information includes:

- Process name
- Process ID (PID)
- Local endpoint
- Remote endpoint
- Protocol type
- Connection state
- Bound interfaces

Additional analysis:

- Cleartext HTTP traffic detection
- Unexpected outbound connections
- Application-level tunnel bypass indicators

---

## Advanced Reporting Engine

Export findings in multiple formats suitable for both interactive and automated workflows.

### HTML Dashboard

Features:

- Executive summary
- Severity indicators
- Visual audit cards
- Leak findings overview
- Browser-based analysis

### JSON Report

Ideal for:

- SIEM ingestion
- Security automation
- Continuous monitoring
- Compliance validation

### CSV Telemetry

Provides:

- Socket inventories
- Process mappings
- Endpoint relationships
- Import-ready spreadsheets

---

# 🏗 Architecture

The framework follows a modular design pattern consisting of independent diagnostic engines coordinated through a centralized orchestration layer.

---

## OSI-Oriented Diagnostic Model

```text
┌─────────────────────────────────────────────────────────────┐
│                  OSI DIAGNOSTIC ENGINE                      │
├─────────────────────────────────────────────────────────────┤
│ Layer 7 │ DNS Leak Detection • HTTP Analysis                │
│ Layer 4 │ STUN Probing • UDP Listener Auditing              │
│ Layer 3 │ Route Auditing • IPv6 Verification                │
│ Layer 2 │ Interface Discovery • Adapter Enumeration         │
└─────────────────────────────────────────────────────────────┘
```

---

## Framework Layout

```text
system_network_leak_detector.py
│
├── SystemRoutingAuditor
│
├── MulticastBroadcastAuditor
│
├── STUNWebRTCTrap
│
├── DNSLeakAuditor
│
├── SystemSocketInspector
│
└── DiagnosticReport
    │
    └── ReportExporter
        │
        ├── JSON Report
        ├── CSV Telemetry
        └── HTML Dashboard
```

---

# 🔬 Diagnostic Modules

## 1. SystemRoutingAuditor

Responsible for routing intelligence collection.

Functions:

- Interface enumeration
- Gateway discovery
- Route metric extraction
- Tunnel verification
- IPv4 path analysis
- IPv6 path analysis

---

## 2. MulticastBroadcastAuditor

Inspects exposure through local discovery protocols.

Functions:

- UDP listener collection
- Multicast service detection
- Broadcast visibility assessment
- Interface exposure mapping

---

## 3. STUNWebRTCTrap

Performs public IP discovery using STUN infrastructure.

Functions:

- STUN binding requests
- Public endpoint resolution
- Reflexive address extraction
- Tunnel bypass identification

---

## 4. DNSLeakAuditor

Evaluates resolver consistency and DNS routing integrity.

Functions:

- Resolver discovery
- Recursive path analysis
- Leakage detection
- Split-horizon identification

---

## 5. SystemSocketInspector

Performs host-level connection analysis.

Functions:

- Socket enumeration
- PID correlation
- Process mapping
- Protocol inspection
- Transport security assessment

---

## 6. ReportExporter

Generates standardized output artifacts.

Supported outputs:

- HTML Dashboard
- JSON Reports
- CSV Telemetry

---

# 📦 Installation

## Requirements

| Component | Version |
|------------|---------|
| Python | 3.8+ |
| Windows | Supported |
| Linux | Supported |
| macOS | Supported |

### Recommended Privileges

| Operating System | Recommendation |
|-----------------|---------------|
| Windows | Run as Administrator |
| Linux | Run with sudo |
| macOS | Run with sudo |

Administrative privileges improve socket-to-process correlation accuracy.

---

## Clone Repository

```bash
git clone https://github.com/shataragh/system-network-leak-detector.git

cd system-network-leak-detector
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 💻 Usage

## Windows

```powershell
python .\system_network_leak_detector.py
```

---

## Linux

```bash
sudo python3 system_network_leak_detector.py
```

---

## macOS

```bash
sudo python3 system_network_leak_detector.py
```

---

# ⚡ Quick Launch (Windows)

Run the audit and automatically open the generated dashboard:

```powershell
python .\system_network_leak_detector.py; Invoke-Item .\leak_audit_report.html
```

---

# 📊 Generated Artifacts

After execution, the framework generates the following files:

| File | Format | Description |
|--------|----------|-------------|
| `leak_audit_report.html` | HTML | Interactive visual dashboard |
| `leak_audit_report.json` | JSON | Structured machine-readable findings |
| `leak_audit_sockets.csv` | CSV | Active socket and process telemetry |

---

# 🎯 Typical Use Cases

### Privacy Auditing

- DNS leak testing
- VPN validation
- WebRTC exposure checks
- Local network privacy assessment

### Security Operations

- Endpoint security reviews
- Network posture validation
- Threat hunting support
- Security monitoring

### Research & Education

- Cybersecurity training
- Network protocol analysis
- VPN behavior testing
- Operating system networking studies

### Home Lab & Enterprise Environments

- Infrastructure validation
- Remote worker VPN auditing
- Lab network assessments
- Security baseline verification

---

# ✅ Design Principles

| Principle | Description |
|------------|-------------|
| Read-Only | Never modifies host configuration |
| Cross-Platform | Windows, Linux, and macOS support |
| Privacy-Focused | Detects unintended disclosure vectors |
| Modular | Independent diagnostic modules |
| Automation-Friendly | JSON and CSV exports |
| Human-Friendly | Interactive HTML reporting |
| Lightweight | Minimal runtime footprint |

---

# ⚠ Disclaimer

This project is intended exclusively for:

- Defensive security analysis
- Network diagnostics
- Privacy auditing
- Education
- Research

Users are solely responsible for complying with applicable laws, organizational policies, and acceptable-use requirements when operating this software.

---

# 📄 License

Distributed under the **MIT License**.

See the LICENSE file for full licensing information.

---

## Project Tagline

> **Enterprise-grade cross-platform network leak detection and privacy auditing framework for DNS, WebRTC, routing analysis, multicast exposure assessment, and socket-level visibility.**
