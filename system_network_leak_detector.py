#!/usr/bin/env python3
"""
Enterprise Architecture & System Network Leak Diagnostic Framework (Read-Only)
Covers Layer 2-7 Diagnostics: Routing Metrics, Dual-Gateway, Split-DNS, STUN, and Sockets.
Supports JSON, CSV, and Visual HTML Diagnostic Reports.
"""

import csv
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional, Set
import psutil

# -------------------------------------------------------------------
# Diagnostic Data Model & Aggregator
# -------------------------------------------------------------------
class DiagnosticReport:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.system_info = {
            "os": platform.system(),
            "release": platform.release(),
            "hostname": socket.gethostname(),
            "python_version": platform.python_version()
        }
        self.interfaces = []
        self.routes = []
        self.broadcast_listeners = []
        self.stun_results = []
        self.dns_results = {}
        self.socket_connections = []

report = DiagnosticReport()


class Logger:
    @staticmethod
    def header(title: str) -> None:
        print("\n" + "=" * 78)
        print(f"  [+] ARCHITECTURAL MODULE: {title.upper()}")
        print("=" * 78)

    @staticmethod
    def info(msg: str) -> None:
        print(f"[*] {msg}")

    @staticmethod
    def alert(msg: str, remediation_hint: Optional[str] = None) -> None:
        print(f"[!] LEAK RISK DETECTED: {msg}")
        if remediation_hint:
            print(f"    └── Architectural Note: {remediation_hint}")

    @staticmethod
    def success(msg: str) -> None:
        print(f"[✓] PASSED: {msg}")

# -------------------------------------------------------------------
# Module 1: Network Layer Architecture & Routing Table Analysis
# -------------------------------------------------------------------
class SystemRoutingAuditor:
    """Parses routing tables and adapter metrics to detect gateway bypasses."""

    TUNNEL_IFACE_KEYWORDS = [
        "tun", "tap", "wg", "wireguard", "ppp", "p2p", "openvpn", "amnezia"
    ]

    @classmethod
    def audit_routes_and_interfaces(cls) -> Dict[str, bool]:
        Logger.header("1. Interface Matrix & Route Metric Analysis")
        results = {"has_tunnel": False}

        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        active_tunnels = []
        active_physical = []

        for iface_name, addresses in interfaces.items():
            iface_stat = stats.get(iface_name)
            if not iface_stat or not iface_stat.isup:
                continue

            is_tunnel = any(kw in iface_name.lower() for kw in cls.TUNNEL_IFACE_KEYWORDS)
            ip_addrs = [addr.address for addr in addresses if addr.family in (socket.AF_INET, socket.AF_INET6)]
            
            if not ip_addrs:
                continue

            iface_entry = {
                "name": iface_name,
                "type": "Tunnel/VPN" if is_tunnel else "Physical Adapter",
                "ip_addresses": ip_addrs
            }
            report.interfaces.append(iface_entry)

            if is_tunnel:
                active_tunnels.append((iface_name, ip_addrs))
            else:
                if not iface_name.startswith("lo") and "127.0.0.1" not in ip_addrs:
                    active_physical.append((iface_name, ip_addrs))

        Logger.info(f"Active Physical Adapters: {len(active_physical)}")
        for name, ips in active_physical:
            Logger.info(f"  └── {name}: {', '.join(ips)}")

        Logger.info(f"Active Virtual Tunnel Interfaces: {len(active_tunnels)}")
        for name, ips in active_tunnels:
            Logger.info(f"  └── {name}: {', '.join(ips)}")

        if active_tunnels:
            results["has_tunnel"] = True
            Logger.success("Virtual encrypted endpoint detected.")
        else:
            Logger.info("No explicit virtual tunnel adapter detected.")

        cls._parse_routing_table()
        return results

    @staticmethod
    def _parse_routing_table() -> None:
        Logger.info("Analyzing OS kernel routing table for default route priorities (0.0.0.0/0)...")
        os_type = platform.system().lower()

        try:
            if os_type == "windows":
                output = subprocess.check_output("netstat -rn", shell=True).decode()
                default_routes = []
                for line in output.splitlines():
                    if line.strip().startswith("0.0.0.0"):
                        entry = line.strip()
                        default_routes.append(entry)
                        Logger.info(f"Route Entry: {entry}")
                        report.routes.append({"raw_entry": entry, "parsed": entry})
                
                if len(default_routes) > 1:
                    Logger.alert(
                        "Multiple default routes (0.0.0.0/0) present in routing table.",
                        remediation_hint="Dual default gateways allow packets bound to specific interfaces to bypass the VPN tunnel."
                    )

            elif os_type == "linux":
                with open("/proc/net/route", "r") as f:
                    routes = f.readlines()
                for line in routes[1:]:
                    fields = line.strip().split()
                    if len(fields) > 2 and fields[1] == "00000000":
                        entry = f"Default Route bound to interface: {fields[0]} (Metric: {fields[6]})"
                        Logger.info(entry)
                        report.routes.append({"raw_entry": line.strip(), "parsed": entry})

            elif os_type == "darwin":
                output = subprocess.check_output("netstat -nr", shell=True).decode()
                for line in output.splitlines():
                    if line.startswith("default"):
                        entry = line.strip()
                        Logger.info(f"Default Route: {entry}")
                        report.routes.append({"raw_entry": entry, "parsed": entry})
        except Exception as e:
            Logger.info(f"Unable to parse routing table directly: {e}")

# -------------------------------------------------------------------
# Module 2: Broadcast Protocol & Local Identity Audit
# -------------------------------------------------------------------
class MulticastBroadcastAuditor:
    """Detects local broadcast protocols leaking system identity over physical interfaces."""

    SENSITIVE_UDP_PORTS = {
        5353: "mDNS (Multicast DNS / Bonjour)",
        5355: "LLMNR (Link-Local Multicast Name Resolution)",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        1900: "SSDP (Simple Service Discovery Protocol)"
    }

    @classmethod
    def audit_broadcast_listeners(cls) -> None:
        Logger.header("2. Multicast & Local LAN Protocol Risk Analysis")
        Logger.info("Scanning local interface sockets for active broadcast listeners...")

        connections = psutil.net_connections(kind="udp")
        detected_leaks = 0

        for conn in connections:
            if conn.laddr and conn.laddr.port in cls.SENSITIVE_UDP_PORTS:
                port = conn.laddr.port
                proc_name = "Unknown"
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "System/Access Denied"

                remediation = f"Protocol '{cls.SENSITIVE_UDP_PORTS[port]}' is listening on {conn.laddr.ip}:{port}."
                Logger.alert(
                    f"Bound listener on {conn.laddr.ip}:{port} by process '{proc_name}' (PID: {conn.pid})",
                    remediation_hint=remediation
                )
                detected_leaks += 1

                report.broadcast_listeners.append({
                    "protocol": cls.SENSITIVE_UDP_PORTS[port],
                    "bound_ip": conn.laddr.ip,
                    "port": port,
                    "process_name": proc_name,
                    "pid": conn.pid or "-"
                })

        if detected_leaks == 0:
            Logger.success("No unencrypted local broadcast/multicast listeners detected on standard risk ports.")

# -------------------------------------------------------------------
# Module 3: WebRTC & Multi-STUN Probing Engine
# -------------------------------------------------------------------
class STUNWebRTCTrap:
    """Probes global STUN infrastructure to discover exposed reflexive candidates."""

    STUN_TARGETS = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun.cloudflare.com", 3478)
    ]

    @classmethod
    def execute_stun_probe(cls) -> Set[str]:
        Logger.header("3. Multi-Server STUN & WebRTC Candidate Trap")
        discovered_public_ips = set()

        for host, port in cls.STUN_TARGETS:
            Logger.info(f"Transmitting UDP STUN Binding request to {host}:{port}...")
            trans_id = os.urandom(12)
            stun_header = struct.pack(">HHI", 0x0001, 0, 0x2112A442) + trans_id

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)

            try:
                ip_target = socket.gethostbyname(host)
                sock.sendto(stun_header, (ip_target, port))
                data, addr = sock.recvfrom(2048)
                
                if data and len(data) >= 20:
                    Logger.success(f"STUN Binding response from {host} ({addr[0]})")
                    for idx in range(20, len(data) - 8):
                        attr_type, attr_len = struct.unpack(">HH", data[idx:idx+4])
                        if attr_type == 0x0020 and attr_len >= 8:
                            family = data[idx+5]
                            if family == 0x01:
                                xport, xip = struct.unpack(">HI", data[idx+6:idx+12])
                                ip_int = xip ^ 0x2112A442
                                mapped_ip = socket.inet_ntoa(struct.pack(">I", ip_int))
                                discovered_public_ips.add(mapped_ip)
                                Logger.info(f"  └── STUN Reflexive Candidate IP: {mapped_ip}")
                                
                                report.stun_results.append({
                                    "target_host": host,
                                    "target_port": port,
                                    "server_ip": addr[0],
                                    "candidate_ip": mapped_ip
                                })
                                break
            except socket.timeout:
                Logger.info(f"STUN Probe to {host} timed out.")
            except Exception as e:
                Logger.info(f"STUN Probe failed for {host}: {e}")
            finally:
                sock.close()

        if len(discovered_public_ips) > 1:
            Logger.alert(
                f"Multiple STUN candidate IPs detected: {discovered_public_ips}.",
                remediation_hint="Multiple public IP bindings indicate WebRTC or UDP routing split-tunnel exposure."
            )
        return discovered_public_ips

# -------------------------------------------------------------------
# Module 4: Authoritative DNS & Resolver Inspection
# -------------------------------------------------------------------
class DNSLeakAuditor:
    """Passively tests DNS resolution pathways across default resolvers."""

    @staticmethod
    def audit_dns() -> None:
        Logger.header("4. Authoritative DNS & Resolver Pathway Inspection")

        try:
            req = urllib.request.Request("https://edns.ip-api.com/json", headers={"User-Agent": "SystemLeakAuditor/4.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode())
                dns_data = data.get("dns", {})
                
                res_ip = dns_data.get("ip", "Unknown")
                res_geo = dns_data.get("geo", "Unknown")
                res_asn = dns_data.get("asn", "Unknown")

                Logger.info(f"Upstream Primary DNS Resolver IP : {res_ip}")
                Logger.info(f"Resolver ASN / Geo Location       : {res_asn} ({res_geo})")

                report.dns_results["edns_resolver_ip"] = res_ip
                report.dns_results["edns_geo_asn"] = f"{res_asn} ({res_geo})"
        except Exception as e:
            Logger.alert(f"Unable to query EDNS diagnostic endpoint: {e}")

        try:
            target_host = "whoami.akamai.net"
            Logger.info(f"Performing socket test lookup for '{target_host}'...")
            addrs = socket.getaddrinfo(target_host, 80)
            resolved_ips = list(set([item[4][0] for item in addrs]))
            Logger.info(f"  └── Endpoint resolved to: {', '.join(resolved_ips)}")
            report.dns_results["resolved_endpoints"] = resolved_ips
        except Exception as e:
            Logger.info(f"Socket resolution failed: {e}")

# -------------------------------------------------------------------
# Module 5: Transport & Socket Connection Correlation
# -------------------------------------------------------------------
class SystemSocketInspector:
    """Inspects established socket endpoints and correlates them to PIDs and processes."""

    @staticmethod
    def audit_active_sockets() -> int:
        Logger.header("5. Transport Layer Sockets & Process Correlation")

        connections = psutil.net_connections(kind="inet")
        suspicious_count = 0

        fmt = "{:<8} {:<24} {:<22} {:<22} {:<12}"
        print(fmt.format("PID", "Process Name", "Local Endpoint", "Remote Endpoint", "State"))
        print("-" * 90)

        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}"

                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name() if proc else "System/Kernel"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "Access Denied"

                is_unencrypted = (conn.raddr.port == 80)
                flag = " [HTTP CLEAR]" if is_unencrypted else ""

                if is_unencrypted:
                    suspicious_count += 1

                print(fmt.format(str(conn.pid or "-"), proc_name[:22], laddr[:21], raddr[:21], conn.status + flag))

                report.socket_connections.append({
                    "pid": conn.pid or "-",
                    "process_name": proc_name,
                    "local_endpoint": laddr,
                    "remote_endpoint": raddr,
                    "status": conn.status,
                    "is_unencrypted_http": is_unencrypted
                })

        print("-" * 90)
        return suspicious_count

# -------------------------------------------------------------------
# Report Exporters: JSON, CSV, and Visual HTML Reports
# -------------------------------------------------------------------
class ReportExporter:
    @staticmethod
    def export_json(filepath: str = "leak_audit_report.json") -> None:
        data = {
            "timestamp": report.timestamp,
            "system_info": report.system_info,
            "interfaces": report.interfaces,
            "default_routes": report.routes,
            "broadcast_listeners": report.broadcast_listeners,
            "stun_results": report.stun_results,
            "dns_results": report.dns_results,
            "socket_connections": report.socket_connections
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        Logger.info(f"JSON Diagnostic Report: {os.path.abspath(filepath)}")

    @staticmethod
    def export_csv(filepath: str = "leak_audit_sockets.csv") -> None:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Process Name", "Local Endpoint", "Remote Endpoint", "Status", "Cleartext HTTP Flag"])
            for conn in report.socket_connections:
                writer.writerow([
                    conn["pid"],
                    conn["process_name"],
                    conn["local_endpoint"],
                    conn["remote_endpoint"],
                    conn["status"],
                    conn["is_unencrypted_http"]
                ])
        Logger.info(f"CSV Socket Summary Report: {os.path.abspath(filepath)}")

    @staticmethod
    def export_html(filepath: str = "leak_audit_report.html") -> None:
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>System Network Leak Diagnostic Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        h2 {{ color: #818cf8; margin-top: 30px; }}
        .card {{ background-color: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background-color: #334155; color: #f1f5f9; }}
        .badge-alert {{ background-color: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-pass {{ background-color: #22c55e; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        pre {{ background-color: #020617; padding: 10px; border-radius: 4px; overflow-x: auto; color: #38bdf8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Leak Diagnostic Report</h1>
        <p><strong>Generated:</strong> {report.timestamp} | <strong>Host:</strong> {report.system_info['hostname']} ({report.system_info['os']} {report.system_info['release']})</p>

        <div class="card">
            <h2>1. System Interfaces & Routing</h2>
            <table>
                <tr><th>Interface Name</th><th>Type</th><th>IP Addresses</th></tr>
                {"".join([f"<tr><td>{i['name']}</td><td>{i['type']}</td><td>{', '.join(i['ip_addresses'])}</td></tr>" for i in report.interfaces])}
            </table>
        </div>

        <div class="card">
            <h2>2. Multicast & Local Broadcast Listeners</h2>
            {"<p class='badge-pass'>No risk protocol listeners detected.</p>" if not report.broadcast_listeners else ""}
            {"<table><tr><th>Protocol</th><th>Bound Endpoint</th><th>Process</th><th>PID</th></tr>" + "".join([f"<tr><td>{b['protocol']}</td><td>{b['bound_ip']}:{b['port']}</td><td>{b['process_name']}</td><td>{b['pid']}</td></tr>" for b in report.broadcast_listeners]) + "</table>" if report.broadcast_listeners else ""}
        </div>

        <div class="card">
            <h2>3. WebRTC & STUN Reflexive Candidates</h2>
            <table>
                <tr><th>STUN Server</th><th>Server IP</th><th>Reflexive Candidate IP</th></tr>
                {"".join([f"<tr><td>{s['target_host']}:{s['target_port']}</td><td>{s['server_ip']}</td><td>{s['candidate_ip']}</td></tr>" for s in report.stun_results])}
            </table>
        </div>

        <div class="card">
            <h2>4. Authoritative DNS Resolver State</h2>
            <p><strong>EDNS Upstream Resolver IP:</strong> {report.dns_results.get('edns_resolver_ip', 'N/A')}</p>
            <p><strong>Resolver Location/ASN:</strong> {report.dns_results.get('edns_geo_asn', 'N/A')}</p>
        </div>

        <div class="card">
            <h2>5. Transport Layer Socket Summary ({len(report.socket_connections)} Active Sockets)</h2>
            <table>
                <tr><th>PID</th><th>Process</th><th>Local Endpoint</th><th>Remote Endpoint</th><th>Flags</th></tr>
                {"".join([f"<tr><td>{s['pid']}</td><td>{s['process_name']}</td><td>{s['local_endpoint']}</td><td>{s['remote_endpoint']}</td><td>{'<span class=\"badge-alert\">HTTP CLEAR</span>' if s['is_unencrypted_http'] else '<span class=\"badge-pass\">OK</span>'}</td></tr>" for s in report.socket_connections[:30]])}
            </table>
            <p><em>(Showing first 30 sockets. Full connections exported to CSV.)</em></p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        Logger.info(f"Visual HTML Report Generated: {os.path.abspath(filepath)}")

# -------------------------------------------------------------------
# Diagnostic Orchestrator
# -------------------------------------------------------------------
def run_full_system_audit():
    print("\n" + "#" * 78)
    print("  ENTERPRISE SYSTEM NETWORK DIAGNOSTIC & LEAK SUITE (READ-ONLY)  ")
    print("#" * 78)

    SystemRoutingAuditor.audit_routes_and_interfaces()
    MulticastBroadcastAuditor.audit_broadcast_listeners()
    STUNWebRTCTrap.execute_stun_probe()
    DNSLeakAuditor.audit_dns()
    SystemSocketInspector.audit_active_sockets()

    # Generate output reports
    ReportExporter.export_json()
    ReportExporter.export_csv()
    ReportExporter.export_html()

    print("\n[✓] Diagnostic audit and report exports completed successfully.")

if __name__ == "__main__":
    run_full_system_audit()
