"""
Test suite for Threat Intelligence Network Traffic Analyzer - NeuralShield AI
Real working tests with actual test data and assertions
"""
import unittest
import time
import uuid
from neural_shield.threat_intelligence_network_traffic_analyzer_2026_june import (
    NetworkTrafficAnalyzer,
    NetworkFlow,
    TrafficAnomaly
)


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    """Real test cases for NetworkTrafficAnalyzer"""
    
    def setUp(self):
        """Set up test analyzer before each test"""
        self.analyzer = NetworkTrafficAnalyzer(window_seconds=300)
    
    def test_add_flow_basic(self):
        """Test basic flow addition works correctly"""
        flow = NetworkFlow(
            flow_id=str(uuid.uuid4()),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            bytes_in=1000,
            bytes_out=500,
            packet_count=10,
            timestamp=time.time(),
            duration=0.5
        )
        
        self.analyzer.add_flow(flow)
        
        # Verify flow was added
        self.assertEqual(len(self.analyzer.flows), 1)
        self.assertEqual(self.analyzer.flows[0].src_ip, "192.168.1.100")
    
    def test_calculate_entropy(self):
        """Test entropy calculation works correctly"""
        # Uniform distribution should have high entropy
        uniform = ["A", "B", "C", "D", "E"]
        entropy_uniform = self.analyzer.calculate_entropy(uniform)
        
        # Skewed distribution should have low entropy
        skewed = ["A", "A", "A", "A", "B"]
        entropy_skewed = self.analyzer.calculate_entropy(skewed)
        
        # Uniform should have higher entropy
        self.assertGreater(entropy_uniform, entropy_skewed)
        # Empty list should have 0 entropy
        self.assertEqual(self.analyzer.calculate_entropy([]), 0.0)
    
    def test_port_scan_detection_vertical(self):
        """Test vertical port scanning detection (many ports on single target)"""
        # Simulate port scan: single IP hitting many different ports
        scanner_ip = "10.0.0.99"
        target_ip = "192.168.1.1"
        
        for port in range(1, 30):  # 29 ports = should trigger detection
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip=scanner_ip,
                dst_ip=target_ip,
                src_port=50000 + port,
                dst_port=port,
                protocol="TCP",
                bytes_in=64,
                bytes_out=0,
                packet_count=1,
                timestamp=time.time(),
                duration=0.01
            )
            self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_port_scanning()
        
        # Should detect vertical port scan
        vertical_scans = [a for a in anomalies if a.anomaly_type == "PORT_SCAN_VERTICAL"]
        self.assertGreater(len(vertical_scans), 0)
        self.assertIn(scanner_ip, vertical_scans[0].source_ips)
        self.assertGreater(vertical_scans[0].confidence, 0.5)
    
    def test_port_scan_detection_horizontal(self):
        """Test horizontal port scanning detection (one port across many targets)"""
        scanner_ip = "10.0.0.99"
        
        # Simulate horizontal scan: single port on many IPs
        for i in range(1, 15):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip=scanner_ip,
                dst_ip=f"192.168.1.{i}",
                src_port=50000 + i,
                dst_port=22,  # Always port 22
                protocol="TCP",
                bytes_in=64,
                bytes_out=0,
                packet_count=1,
                timestamp=time.time(),
                duration=0.01
            )
            self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_port_scanning()
        
        # Should detect horizontal scan
        horizontal_scans = [a for a in anomalies if a.anomaly_type == "PORT_SCAN_HORIZONTAL"]
        self.assertGreater(len(horizontal_scans), 0)
        self.assertEqual(horizontal_scans[0].evidence["target_port"], 22)
    
    def test_whitelist_works(self):
        """Test whitelisted IPs are excluded from scanning"""
        whitelisted_ip = "192.168.1.1"
        self.analyzer.add_to_whitelist(whitelisted_ip)
        
        # Even with suspicious behavior, whitelisted IP should not trigger
        for port in range(1, 50):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip=whitelisted_ip,
                dst_ip="10.0.0.1",
                src_port=50000 + port,
                dst_port=port,
                protocol="TCP",
                bytes_in=64,
                bytes_out=0,
                packet_count=1,
                timestamp=time.time(),
                duration=0.01
            )
            self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_port_scanning()
        scanner_anomalies = [a for a in anomalies if whitelisted_ip in a.source_ips]
        
        # No anomalies from whitelisted IP
        self.assertEqual(len(scanner_anomalies), 0)
    
    def test_syn_flood_detection(self):
        """Test SYN flood detection works"""
        attacker_ip = "10.0.0.66"
        
        # Simulate SYN flood: many SYN without ACK
        for i in range(60):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip=f"10.0.0.{i}",
                dst_ip="192.168.1.100",
                src_port=40000 + i,
                dst_port=80,
                protocol="TCP",
                bytes_in=64,
                bytes_out=0,
                packet_count=1,
                timestamp=time.time(),
                duration=0.01,
                flags={"SYN"}  # SYN only, no ACK
            )
            self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_ddos_patterns()
        syn_anomalies = [a for a in anomalies if a.anomaly_type == "SYN_FLOOD_POTENTIAL"]
        
        self.assertGreater(len(syn_anomalies), 0)
    
    def test_data_exfiltration_detection(self):
        """Test large outbound data transfer detection"""
        for i in range(100):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip="192.168.1.50",
                dst_ip="1.2.3.4",  # External IP
                src_port=30000 + i,
                dst_port=443,
                protocol="TCP",
                bytes_in=1000,
                bytes_out=200_000,  # Large outbound
                packet_count=100,
                timestamp=time.time(),
                duration=1.0
            )
            self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_data_exfiltration()
        self.assertGreater(len(anomalies), 0)
    
    def test_dns_tunneling_detection_long_subdomain(self):
        """Test DNS tunneling detection via long subdomains"""
        # Very long subdomain is typical of DNS tunneling
        long_subdomain = "x" * 60 + ".example.com"
        
        flow = NetworkFlow(
            flow_id=str(uuid.uuid4()),
            src_ip="192.168.1.200",
            dst_ip="8.8.8.8",
            src_port=53000,
            dst_port=53,
            protocol="DNS",
            bytes_in=100,
            bytes_out=200,
            packet_count=1,
            timestamp=time.time(),
            duration=0.01,
            dns_query=long_subdomain
        )
        self.analyzer.add_flow(flow)
        
        anomalies = self.analyzer.detect_dns_tunneling()
        tunnel_anomalies = [a for a in anomalies if "TUNNELING" in a.anomaly_type]
        
        self.assertGreater(len(tunnel_anomalies), 0)
    
    def test_full_analyze_traffic(self):
        """Test full traffic analysis pipeline"""
        # Add normal traffic
        for i in range(10):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip=f"192.168.1.{10+i}",
                dst_ip="10.0.0.1",
                src_port=20000 + i,
                dst_port=443,
                protocol="TCP",
                bytes_in=5000,
                bytes_out=1000,
                packet_count=20,
                timestamp=time.time(),
                duration=0.5
            )
            self.analyzer.add_flow(flow)
        
        result = self.analyzer.analyze_traffic()
        
        # Verify result structure
        self.assertIn("summary", result)
        self.assertIn("anomalies", result)
        self.assertIn("total_flows", result["summary"])
        self.assertEqual(result["summary"]["total_flows"], 10)
        self.assertGreater(result["summary"]["traffic_entropy"], 0)
    
    def test_anomaly_summary(self):
        """Test anomaly summary generation"""
        # Add some anomalies via detection
        for port in range(1, 30):
            flow = NetworkFlow(
                flow_id=str(uuid.uuid4()),
                src_ip="10.0.0.99",
                dst_ip="192.168.1.1",
                src_port=50000 + port,
                dst_port=port,
                protocol="TCP",
                bytes_in=64,
                bytes_out=0,
                packet_count=1,
                timestamp=time.time(),
                duration=0.01
            )
            self.analyzer.add_flow(flow)
        
        self.analyzer.analyze_traffic()
        summary = self.analyzer.get_anomaly_summary()
        
        self.assertIn("total_anomalies", summary)
        self.assertIn("by_type", summary)
        self.assertIn("by_severity", summary)
        self.assertGreater(summary["total_anomalies"], 0)
    
    def test_ip_validation(self):
        """Test IP validation for whitelist/blacklist"""
        # Valid IPs should work
        self.assertTrue(self.analyzer.add_to_whitelist("192.168.1.1"))
        self.assertTrue(self.analyzer.add_to_blacklist("10.0.0.1"))
        
        # Invalid IPs should return False
        self.assertFalse(self.analyzer.add_to_whitelist("not-an-ip"))
        self.assertFalse(self.analyzer.add_to_blacklist("256.256.256.256"))


if __name__ == "__main__":
    # Run tests and show results
    unittest.main(verbosity=2)
