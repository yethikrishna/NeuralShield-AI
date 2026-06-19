"""
NeuralShield-AI: Threat Intelligence Port Scanner Engine
Production-grade port scanning and service detection for threat intelligence
June 2026 Implementation
"""

import socket
import threading
import time
import json
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class PortScanResult:
    host: str
    port: int
    protocol: Protocol
    status: PortStatus
    service: str
    banner: Optional[str]
    response_time_ms: float
    timestamp: str


@dataclass
class HostScanSummary:
    host: str
    ip_address: str
    total_ports_scanned: int
    open_ports: List[int]
    closed_ports: int
    filtered_ports: int
    scan_duration_seconds: float
    results: List[PortScanResult]


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4000, 4001, 4045, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 5901, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999,
    10000, 10001, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]


class ThreatIntelligencePortScanner:
    """
    Production-grade port scanner engine for threat intelligence gathering.
    Features:
    - TCP connect scanning
    - Service detection and banner grabbing
    - Concurrent scanning with thread pooling
    - Timeout and rate limiting
    - Structured result output
    """

    def __init__(
        self,
        timeout_seconds: float = 2.0,
        max_threads: int = 50,
        delay_ms: int = 0,
        grab_banners: bool = True
    ):
        self.timeout = timeout_seconds
        self.max_threads = max_threads
        self.delay_ms = delay_ms
        self.grab_banners = grab_banners
        self._scan_lock = threading.Lock()

    def _resolve_host(self, host: str) -> str:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            return host

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Attempt to grab service banner from open port."""
        try:
            sock.settimeout(1.0)
            
            # Send generic probe for common services
            if port in [80, 8080, 443, 8443]:
                sock.send(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
            elif port in [21, 22, 25, 110, 143]:
                pass  # These services send banner on connect
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200] if banner else None
        except Exception:
            return None

    def _scan_single_port(
        self,
        host: str,
        port: int,
        protocol: Protocol = Protocol.TCP
    ) -> PortScanResult:
        """Scan a single port on a host."""
        start_time = time.time()
        status = PortStatus.CLOSED
        banner = None
        service = COMMON_PORTS.get(port, "unknown")

        try:
            if protocol == Protocol.TCP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    status = PortStatus.OPEN
                    if self.grab_banners:
                        banner = self._grab_banner(sock, port)
                elif result == 11:  # EAGAIN - likely filtered
                    status = PortStatus.FILTERED
                
                sock.close()
            else:
                # UDP scanning (simplified)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                try:
                    sock.sendto(b"ping", (host, port))
                    data, _ = sock.recvfrom(1024)
                    status = PortStatus.OPEN
                except socket.timeout:
                    status = PortStatus.OPEN_FILTERED
                except Exception:
                    status = PortStatus.CLOSED
                finally:
                    sock.close()

        except socket.timeout:
            status = PortStatus.FILTERED
        except OSError as e:
            if e.errno == 13:  # Permission denied
                status = PortStatus.FILTERED
            else:
                status = PortStatus.CLOSED
        except Exception:
            status = PortStatus.CLOSED

        response_time = (time.time() - start_time) * 1000

        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        return PortScanResult(
            host=host,
            port=port,
            protocol=protocol,
            status=status,
            service=service,
            banner=banner,
            response_time_ms=round(response_time, 2),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )

    def scan_host(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        ports_range: Optional[Tuple[int, int]] = None,
        quick_scan: bool = True
    ) -> HostScanSummary:
        """
        Scan a single host with specified ports.
        
        Args:
            host: Target hostname or IP
            ports: Specific list of ports to scan
            ports_range: Tuple of (start_port, end_port)
            quick_scan: If True, scan top 100 ports
        """
        start_time = time.time()
        ip_address = self._resolve_host(host)
        
        # Determine ports to scan
        if ports:
            ports_to_scan = ports
        elif ports_range:
            ports_to_scan = list(range(ports_range[0], ports_range[1] + 1))
        elif quick_scan:
            ports_to_scan = TOP_100_PORTS
        else:
            ports_to_scan = list(COMMON_PORTS.keys())

        results: List[PortScanResult] = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_single_port, ip_address, port): port
                for port in ports_to_scan
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Scan error on port {futures[future]}: {e}")

        # Sort results by port number
        results.sort(key=lambda x: x.port)
        
        open_ports = [r.port for r in results if r.status == PortStatus.OPEN]
        closed_count = sum(1 for r in results if r.status == PortStatus.CLOSED)
        filtered_count = sum(1 for r in results if r.status in [PortStatus.FILTERED, PortStatus.OPEN_FILTERED])

        return HostScanSummary(
            host=host,
            ip_address=ip_address,
            total_ports_scanned=len(ports_to_scan),
            open_ports=open_ports,
            closed_ports=closed_count,
            filtered_ports=filtered_count,
            scan_duration_seconds=round(time.time() - start_time, 2),
            results=results
        )

    def scan_network(
        self,
        cidr: str,
        ports: Optional[List[int]] = None
    ) -> List[HostScanSummary]:
        """Scan an entire network range."""
        network = ipaddress.ip_network(cidr, strict=False)
        results = []
        
        for host in network.hosts():
            try:
                result = self.scan_host(str(host), ports=ports)
                if result.open_ports:
                    results.append(result)
            except Exception as e:
                logger.warning(f"Failed to scan {host}: {e}")
        
        return results

    def export_results_json(
        self,
        summary: HostScanSummary,
        output_file: Optional[str] = None
    ) -> str:
        """Export scan results to JSON format."""
        data = {
            "scan_summary": {
                "host": summary.host,
                "ip_address": summary.ip_address,
                "total_ports_scanned": summary.total_ports_scanned,
                "open_ports": summary.open_ports,
                "closed_ports": summary.closed_ports,
                "filtered_ports": summary.filtered_ports,
                "scan_duration_seconds": summary.scan_duration_seconds,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            },
            "detailed_results": [
                {
                    "port": r.port,
                    "protocol": r.protocol.value,
                    "status": r.status.value,
                    "service": r.service,
                    "banner": r.banner,
                    "response_time_ms": r.response_time_ms
                }
                for r in summary.results
            ]
        }
        
        json_output = json.dumps(data, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
        
        return json_output

    def generate_threat_intel_report(self, summary: HostScanSummary) -> Dict:
        """Generate threat intelligence report from scan results."""
        risky_services = ["Telnet", "FTP", "SMB", "RDP", "VNC", "Redis", "MongoDB"]
        risky_open = []
        
        for result in summary.results:
            if result.status == PortStatus.OPEN and result.service in risky_services:
                risky_open.append({
                    "port": result.port,
                    "service": result.service,
                    "risk_level": "HIGH" if result.service in ["Telnet", "FTP"] else "MEDIUM",
                    "recommendation": f"Restrict access to {result.service} on port {result.port}"
                })

        return {
            "target": summary.host,
            "ip_address": summary.ip_address,
            "attack_surface_score": min(100, len(summary.open_ports) * 10),
            "open_ports_count": len(summary.open_ports),
            "risky_services_exposed": risky_open,
            "recommendations": [
                "Close unused open ports",
                "Implement firewall rules to restrict access",
                "Consider using VPN for management services",
                "Regularly patch exposed services"
            ]
        }


def run_port_scanner_demo():
    """Run a demonstration of the port scanner engine."""
    print("=" * 60)
    print("NeuralShield-AI Threat Intelligence Port Scanner Engine")
    print("=" * 60)
    
    scanner = ThreatIntelligencePortScanner(
        timeout_seconds=1.0,
        max_threads=20,
        grab_banners=True
    )
    
    # Scan localhost as demonstration
    print(f"\n[+] Starting scan on localhost (127.0.0.1)")
    print(f"[+] Scanning top 20 common ports...")
    
    test_ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]
    result = scanner.scan_host("127.0.0.1", ports=test_ports)
    
    print(f"\n[+] Scan Complete!")
    print(f"    Host: {result.host} ({result.ip_address})")
    print(f"    Ports Scanned: {result.total_ports_scanned}")
    print(f"    Open Ports: {result.open_ports}")
    print(f"    Closed Ports: {result.closed_ports}")
    print(f"    Filtered Ports: {result.filtered_ports}")
    print(f"    Duration: {result.scan_duration_seconds}s")
    
    if result.open_ports:
        print(f"\n[+] Open Ports Details:")
        for r in result.results:
            if r.status == PortStatus.OPEN:
                print(f"    Port {r.port:5d} ({r.service:12s}) - {r.response_time_ms:6.2f}ms")
                if r.banner:
                    print(f"        Banner: {r.banner[:80]}")
    
    # Generate threat intel report
    print(f"\n[+] Threat Intelligence Report:")
    intel_report = scanner.generate_threat_intel_report(result)
    print(f"    Attack Surface Score: {intel_report['attack_surface_score']}/100")
    if intel_report['risky_services_exposed']:
        print(f"    [WARNING] Risky Services Found:")
        for risk in intel_report['risky_services_exposed']:
            print(f"        - Port {risk['port']}: {risk['service']} ({risk['risk_level']})")
    
    # Export results
    json_output = scanner.export_results_json(result, "test_results_port_scanner.json")
    print(f"\n[+] Results exported to test_results_port_scanner.json")
    
    return result


if __name__ == "__main__":
    run_port_scanner_demo()
