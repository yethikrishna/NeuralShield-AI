"""
Threat Intelligence Subdomain Discovery Engine - NeuralShield AI
Production-grade subdomain enumeration for attack surface mapping
"""
import re
import time
import hashlib
import secrets
from enum import Enum
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

import dns.resolver
import dns.exception


class DiscoveryStatus(Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    WILDCARD = "WILDCARD"
    RATE_LIMITED = "RATE_LIMITED"
    ERROR = "ERROR"


@dataclass
class DiscoveredSubdomain:
    subdomain: str
    status: DiscoveryStatus
    ip_addresses: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class DiscoveryResult:
    discovery_id: str
    target_domain: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    subdomains: List[DiscoveredSubdomain] = field(default_factory=list)
    total_discovered: int = 0
    active_subdomains: int = 0
    errors: List[str] = field(default_factory=list)
    wordlist_size: int = 0


class SubdomainDiscoveryEngine:
    """Production-grade Subdomain Discovery Engine for Threat Intelligence"""
    
    # Common subdomain wordlist (500+ entries)
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "pop3", "imap",
        "admin", "api", "blog", "cdn", "cpanel", "demo", "dev", "docs", "download",
        "git", "help", "img", "images", "info", "irc", "jenkins", "jira", "m",
        "media", "news", "ns1", "ns2", "ns3", "old", "panel", "portal", "prod",
        "qa", "repo", "sandbox", "shop", "site", "staging", "static", "status",
        "support", "test", "wiki", "ww1", "ww2", "ww3", "www2", "www3", "autodiscover",
        "owa", "exchange", "server", "mx", "mx1", "mx2", "mail1", "mail2", "smtp1",
        "smtp2", "relay", "gateway", "vpn", "remote", "rdp", "ssh", "secure",
        "ssl", "cert", "auth", "login", "signin", "signup", "register", "account",
        "user", "users", "profile", "dashboard", "app", "apps", "application",
        "beta", "alpha", "stage", "test1", "test2", "test3", "dev1", "dev2",
        "prod1", "prod2", "uat", "sitemap", "robots", "feed", "rss", "xmlrpc",
        "wp", "wp-admin", "wp-content", "wordpress", "drupal", "joomla", "magento",
        "shopify", "store", "cart", "checkout", "payment", "pay", "billing",
        "invoice", "crm", "erp", "hr", "hrm", "finance", "accounting", "analytics",
        "stats", "metrics", "monitor", "monitoring", "alert", "alerts", "logging",
        "logs", "backup", "backups", "archive", "storage", "cdn1", "cdn2", "assets",
        "static1", "static2", "files", "file", "downloads", "upload", "uploads",
        "video", "videos", "audio", "images1", "img1", "pic", "pics", "photo",
        "photos", "thumb", "thumbs", "cache", "temp", "tmp", "data", "database",
        "db", "db1", "db2", "sql", "mysql", "postgres", "mongodb", "redis",
        "elastic", "elasticsearch", "search", "solr", "kafka", "rabbitmq", "queue",
        "broker", "memcache", "memcached", "cache1", "cache2", "proxy", "proxies",
        "reverse-proxy", "lb", "lb1", "lb2", "loadbalancer", "balancer", "ha",
        "cluster", "node", "nodes", "worker", "workers", "master", "slave",
        "primary", "secondary", "replica", "replicas", "sync", "mirror", "mirrors",
        "dr", "failover", "backup1", "backup2", "dr1", "dr2", "bcp", "recovery",
        "api1", "api2", "api3", "graphql", "rest", "soap", "websocket", "ws",
        "wss", "socket", "sockets", "push", "notification", "notifications",
        "webhook", "webhooks", "callback", "callbacks", "oauth", "sso", "saml",
        "oidc", "identity", "idp", "auth0", "keycloak", "okta", "onelogin",
        "ping", "pingidentity", "azure", "aws", "gcp", "cloud", "cloudflare",
        "akamai", "fastly", "edge", "edge1", "edge2", "origin", "shield", "waf",
        "firewall", "security", "sec", "ids", "ips", "siem", "soc", "soc1",
        "soc2", "threat", "threats", "intel", "ti", "cti", "ioc", "iocs",
        "indicator", "indicators", "feed", "feeds", "osint", "recon", "scanner",
        "scanner1", "scanner2", "sensor", "sensors", "probe", "probes", "honeypot",
        "honeypots", "tarpit", "decoy", "decoys", "canary", "canaries", "breadcrumb",
        "breadcrumbs", "trap", "traps", "bait", "baits", "detection", "detections",
        "alerting", "response", "soar", "playbook", "playbooks", "runbook",
        "runbooks", "case", "cases", "ticket", "tickets", "incident", "incidents",
        "event", "events", "audit", "audits", "compliance", "gdpr", "hipaa",
        "pci", "pci-dss", "iso", "nist", "framework", "policy", "policies",
        "standard", "standards", "control", "controls", "risk", "risks", "vuln",
        "vulns", "vulnerability", "vulnerabilities", "patch", "patches", "update",
        "updates", "remediate", "remediation", "mitigate", "mitigation", "fix",
        "hardening", "baseline", "benchmark", "score", "scores", "rating",
        "ratings", "level", "levels", "maturity", "capability", "capabilities",
        "mfa", "2fa", "otp", "totp", "hotp", "u2f", "fido", "yubikey", "token",
        "tokens", "certificate", "certificates", "ca", "root", "intermediate",
        "letsencrypt", "acme", "pki", "x509", "tls", "ssl", "dtls", "mtls",
        "ipsec", "ike", "ikev2", "wireguard", "openvpn", "pptp", "l2tp", "s2s",
        "site-to-site", "client", "clients", "peer", "peers", "tunnel", "tunnels",
        "corp", "internal", "intranet", "extranet", "dmz", "perimeter", "border",
        "lan", "wan", "man", "vlan", "vxlan", "sdwan", "sd-wan", "net", "net1",
        "net2", "subnet", "subnets", "route", "routes", "router", "routers",
        "switch", "switches", "fw", "fw1", "fw2", "ngfw", "utm", "ids1", "ids2",
        "ips1", "ips2", "tap", "span", "mirror", "packet", "packets", "pcap",
        "pcaps", "flow", "flows", "netflow", "sflow", "ipfix", "bandwidth",
        "latency", "jitter", "packetloss", "qos", "quality", "performance",
        "speed", "throughput", "capacity", "utilization", "uptime", "availability",
        "reliability", "redundancy", "resilience", "fault-tolerance", "ha1", "ha2",
        "dr-site", "recovery-site", "bcp-site", "hot-site", "warm-site", "cold-site",
        "mobile", "mob", "app1", "app2", "ios", "android", "apk", "ipa", "mobileapp",
        "iosapp", "androidapp", "push", "apns", "fcm", "gcm", "onesignal",
        "notification1", "notification2", "inapp", "in-app", "deeplink", "deeplinks",
        "universal", "universallink", "applink", "applinks", "branch", "branchio",
        "firebase", "fabric", "crashlytics", "analytics1", "analytics2", "mixpanel",
        "amplitude", "heap", "pendo", "fullstory", "hotjar", "mouseflow", "luckyorange",
        "crazyegg", "optimizely", "ab", "a-b", "split", "experiment", "experiments",
        "feature", "features", "flag", "flags", "toggle", "toggles", "launchdarkly",
        "configcat", "unleash", "flipper", "petri", "config", "configuration",
        "settings", "env", "environment", "environments", "vars", "variables",
        "secrets", "secret", "vault", "vault1", "vault2", "hsm", "kms", "keystore",
        "truststore", "hsm1", "hsm2", "kms1", "kms2", "encrypt", "encryption",
        "crypto", "cryptography", "cipher", "ciphers", "hash", "hashes", "sign",
        "signature", "signatures", "verify", "verification", "non-repudiation",
        "integrity", "confidentiality", "authenticity", "privacy", "anonymity",
        "pseudonymity", "zero-knowledge", "zkp", "snark", "stark", "bulletproofs",
        "homomorphic", "he", "fhe", "quantum", "post-quantum", "pqc", "lattice",
        "code-based", "hash-based", "multivariate", "isogeny", "supersingular",
        "dilithium", "crystals", "falcon", "sphincs", "rainbow", "ge", "mceliece",
        "ntru", "saber", "kyber", "newhope", "frodo", "lac", "sidh", "sike",
        "bike", "hqc", "classic", "r5", "round5", "threebears", "ntruprime",
        "sntrup", "saber", "firesaber", "lightsaber", "sabers", "crystals-kyber",
        "crystals-dilithium", "nist", "standard", "standards", "fips", "fips140",
        "fips140-2", "fips140-3", "commoncriteria", "cc", "cc-eval", "cc-cert",
        "ecc", "ecdsa", "ecdh", "eddsa", "ed25519", "x25519", "curve25519",
        "secp256r1", "secp384r1", "secp521r1", "brainpool", "nistp", "rsa",
        "rsa2048", "rsa3072", "rsa4096", "dh", "dhe", "ecdhe", "forward-secrecy",
        "pfs", "perfect-forward-secrecy", "ephemeral", "session", "sessions",
        "ticket", "tickets", "session-id", "sessionid", "cookie", "cookies",
        "jwt", "jws", "jwe", "jwk", "jwks", "oauth2", "oauth2.0", "openid",
        "connect", "oidc", "id_token", "access_token", "refresh_token", "token",
        "bearer", "mac", "hmac", "sha1", "sha2", "sha256", "sha384", "sha512",
        "sha3", "sha3-256", "sha3-512", "md5", "ripemd", "whirlpool", "blake2",
        "blake2b", "blake2s", "blake3", "argon2", "argon2i", "argon2d", "argon2id",
        "pbkdf2", "bcrypt", "scrypt", "yescrypt", "makwa", "lyra2", "catena",
        "yespower", "yescrypt", "balloon", "balloon-hashing", "memory-hard",
        "cpu-hard", "gpu-hard", "asic-resistant", "fpga-resistant", "password",
        "passwords", "passphrase", "passphrases", "salt", "salts", "pepper",
        "peppers", "stretch", "stretching", "kdf", "key-derivation", "hkdf",
        "pbkdf", "scrypt", "argon2", "bcrypt", "yescrypt", "hashcat", "john",
        "hashcat64", "johntheripper", "wordlist", "wordlists", "dictionary",
        "dictionaries", "rainbow", "rainbow-tables", "lookup", "lookups", "crack",
        "cracking", "brute", "bruteforce", "brute-force", "dictionary-attack",
        "mask", "masks", "rule", "rules", "combinator", "hybrid", "prince",
        "markov", "statistical", "probabilistic", "frequency", "ngram", "ngrams",
        "levenshtein", "damerau", "hamming", "edit-distance", "similarity",
        "fuzzy", "fuzzing", "fuzzer", "fuzzers", "afl", "libfuzzer", "honggfuzz",
        "radamsa", "zzuf", "peach", "sulley", "boofuzz", "mutations", "mutation",
        "generation", "generational", "evolutionary", "genetic", "coverage",
        "code-coverage", "sanitizer", "sanitizers", "asan", "ubsan", "msan",
        "tsan", "lsan", "valgrind", "drmemory", "address-sanitizer", "memory",
        "undefined", "thread", "leak", "buffer", "overflow", "underflow",
        "heap", "stack", "use-after-free", "double-free", "uaf", "df", "oob",
        "out-of-bounds", "integer", "signed", "unsigned", "truncation", "wrap",
        "null", "null-deref", "dereference", "format-string", "printf", "scanf",
        "sql", "sqli", "sql-injection", "union", "blind", "error-based",
        "time-based", "boolean-based", "stacked", "second-order", "out-of-band",
        "oast", "dnslog", "collaborator", "burp", "burpsuite", "zap", "owasp",
        "nmap", "masscan", "unicornscan", "socat", "netcat", "nc", "ncat",
        "wireshark", "tshark", "tcpdump", "ngrep", "ettercap", "bettercap",
        "mitmproxy", "mitm", "man-in-the-middle", "sslstrip", "sslsplit",
        "hsts", "hsts-preload", "hpkp", "expect-ct", "csp", "content-security-policy",
        "x-frame-options", "x-xss-protection", "x-content-type-options",
        "referrer-policy", "feature-policy", "permissions-policy", "coop",
        "coep", "corp", "cross-origin", "cors", "sop", "same-origin", "origin",
        "iframe", "frame", "frameset", "embedding", "sandbox", "sandboxed",
        "script", "scripts", "javascript", "js", "eval", "inline", "inline-script",
        "unsafe-inline", "unsafe-eval", "strict-dynamic", "nonce", "nonces",
        "hash", "hashes", "sha256-", "sha384-", "sha512-", "report-uri",
        "report-to", "reporting", "violation", "violations", "enforce",
        "enforcement", "monitor", "monitoring", "xss", "cross-site-scripting",
        "stored", "reflected", "dom", "dom-based", "mXSS", "mutation", "uxss",
        "universal", "self-xss", "csrf", "xsrf", "cross-site-request-forgery",
        "token", "tokens", "samesite", "samesite-cookie", "strict", "lax",
        "none", "secure", "httponly", "path", "domain", "expires", "max-age",
        "session-cookie", "persistent", "persistent-cookie", "third-party",
        "first-party", "party", "tracking", "fingerprint", "fingerprinting",
        "canvas", "webgl", "audio", "fonts", "plugins", "useragent", "ua",
        "accept", "accept-language", "accept-encoding", "dnt", "do-not-track",
        "gpc", "global-privacy-control", "privacy", "gdpr", "ccpa", "lgpd",
        "pipeda", "popia", "hipaa", "coppa", "copra", "ferpa", "glba", "sox",
        "privacy-by-design", "privacy-by-default", "data-minimization",
        "purpose-limitation", "storage-limitation", "integrity", "confidentiality",
        "lawfulness", "fairness", "transparency", "legitimate-interest",
        "consent", "consent-management", "cmp", "cookie-banner", "opt-in",
        "opt-out", "withdraw", "dsar", "data-subject", "access", "rectification",
        "erasure", "right-to-be-forgotten", "rtbf", "data-portability",
        "restriction", "objection", "automated-decision-making", "profiling",
        "dpo", "data-protection-officer", "privacy-officer", "privacy-impact",
        "pia", "dpia", "data-protection-impact-assessment", "transfer",
        "international-transfer", "adequacy", "schrems", "schrems-ii", "eu-us",
        "privacy-shield", "standard-contractual-clauses", "scc", "binding-corporate-rules",
        "bcr", "code-of-conduct", "certification", "supervisory-authority",
        "sa", "dpa", "data-protection-authority", "ico", "edpb", "wp29",
        "article-29", "working-party", "enforcement", "fine", "fines", "penalty",
        "penalties", "breach", "data-breach", "notification", "72-hours",
        "incident", "incident-response", "breach-response", "notification",
        "affected", "impact", "risk-assessment", "mitigation", "remediation",
        "communication", "stakeholders", "regulators", "individuals", "public",
        "media", "pr", "crisis", "crisis-management", "forensics", "digital-forensics",
        "dfir", "digital-forensics-incident-response", "evidence", "chain-of-custody",
        "preservation", "acquisition", "analysis", "reporting", "testimony",
        "expert", "expert-witness", "court", "legal", "litigation", "discovery",
        "ediscovery", "e-discovery", "electronic-discovery", "legal-hold",
        "litigation-hold", "preservation-order", "subpoena", "warrant", "court-order"
    ]
    
    # Cloud provider patterns
    CLOUD_PATTERNS = {
        "AWS": [r"amazonaws", r"awsdns", r"cloudfront", r"s3\.", r"ec2\.", r"elb\."],
        "GCP": [r"googleusercontent", r"googleapis", r"gcp", r"cloud\.google"],
        "AZURE": [r"azure", r"microsoftonline", r"windows\.net", r"cloudapp\.net"],
        "CLOUDFLARE": [r"cloudflare", r"cfdns"],
        "AKAMAI": [r"akamai", r"akadns"],
        "FASTLY": [r"fastly", r"fastlylb"]
    }
    
    def __init__(self, timeout: float = 5.0, max_retries: int = 3,
                 rate_limit_delay: float = 0.1):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        self._dns_cache: Dict[str, Any] = {}
        self._discovery_count = 0
    
    def _generate_discovery_id(self) -> str:
        return hashlib.sha256(
            f"{datetime.now().isoformat()}{secrets.token_hex(16)}".encode()
        ).hexdigest()[:16]
    
    def _dns_query(self, domain: str, record_type: str) -> Optional[List[str]]:
        """Perform DNS query with caching and retries"""
        cache_key = f"{domain}:{record_type}"
        if cache_key in self._dns_cache:
            return self._dns_cache[cache_key]
        
        results = []
        for attempt in range(self.max_retries):
            try:
                answers = self._resolver.resolve(domain, record_type)
                results = [str(rdata) for rdata in answers]
                self._dns_cache[cache_key] = results
                return results
            except dns.resolver.NXDOMAIN:
                self._dns_cache[cache_key] = None
                return None
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self._dns_cache[cache_key] = []
                return []
            except dns.exception.Timeout:
                if attempt < self.max_retries - 1:
                    time.sleep(self.rate_limit_delay * (attempt + 1))
                    continue
                return None
            except Exception:
                return None
        
        return None
    
    def _detect_wildcard(self, domain: str) -> bool:
        """Detect wildcard DNS configuration"""
        random_subdomain = f"{secrets.token_hex(16)}.{domain}"
        result = self._dns_query(random_subdomain, "A")
        return result is not None and len(result) > 0
    
    def _detect_cloud_provider(self, subdomain: str, 
                                ips: List[str], cnames: List[str]) -> Optional[str]:
        """Detect cloud provider from IP/CNAME records"""
        all_text = " ".join(ips + cnames).lower()
        
        for provider, patterns in self.CLOUD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    return provider
        
        return None
    
    def _generate_permutations(self, base_subdomains: List[str]) -> Set[str]:
        """Generate permutations from known subdomains"""
        permutations = set()
        prefixes = ["www", "api", "dev", "staging", "test", "prod", "admin", "secure"]
        suffixes = ["1", "2", "3", "-dev", "-test", "-prod", "-stage", "-api"]
        
        for sub in base_subdomains:
            parts = sub.split(".")
            if len(parts) >= 1:
                base = parts[0]
                for prefix in prefixes:
                    permutations.add(f"{prefix}-{base}")
                    permutations.add(f"{prefix}{base}")
                for suffix in suffixes:
                    permutations.add(f"{base}{suffix}")
        
        return permutations
    
    def discover_subdomains(self, target_domain: str,
                            use_wordlist: bool = True,
                            use_permutations: bool = True,
                            max_subdomains: int = 1000) -> DiscoveryResult:
        """Main subdomain discovery method"""
        start_time = datetime.now()
        discovery_id = self._generate_discovery_id()
        
        result = DiscoveryResult(
            discovery_id=discovery_id,
            target_domain=target_domain,
            start_time=start_time,
            wordlist_size=len(self.COMMON_SUBDOMAINS)
        )
        
        discovered: Dict[str, DiscoveredSubdomain] = {}
        
        # Check for wildcard
        has_wildcard = self._detect_wildcard(target_domain)
        
        # Wordlist-based discovery
        if use_wordlist:
            for sub in self.COMMON_SUBDOMAINS[:max_subdomains]:
                if len(discovered) >= max_subdomains:
                    break
                    
                full_domain = f"{sub}.{target_domain}"
                
                a_records = self._dns_query(full_domain, "A")
                aaaa_records = self._dns_query(full_domain, "AAAA") or []
                cname_records = self._dns_query(full_domain, "CNAME") or []
                mx_records = self._dns_query(full_domain, "MX") or []
                txt_records = self._dns_query(full_domain, "TXT") or []
                ns_records = self._dns_query(full_domain, "NS") or []
                
                all_ips = (a_records or []) + aaaa_records
                
                if a_records is not None:
                    status = DiscoveryStatus.ACTIVE if len(all_ips) > 0 else DiscoveryStatus.INACTIVE
                    if has_wildcard and len(all_ips) > 0:
                        status = DiscoveryStatus.WILDCARD
                    
                    discovered[full_domain] = DiscoveredSubdomain(
                        subdomain=full_domain,
                        status=status,
                        ip_addresses=all_ips,
                        cname_records=cname_records,
                        mx_records=mx_records,
                        txt_records=txt_records,
                        ns_records=ns_records,
                        cloud_provider=self._detect_cloud_provider(full_domain, all_ips, cname_records)
                    )
                
                time.sleep(self.rate_limit_delay)
        
        # Permutation-based discovery
        if use_permutations and len(discovered) > 0:
            known_bases = [d.subdomain.replace(f".{target_domain}", "") 
                          for d in discovered.values()]
            permutations = self._generate_permutations(known_bases)
            
            for perm in permutations:
                if len(discovered) >= max_subdomains:
                    break
                    
                full_domain = f"{perm}.{target_domain}"
                if full_domain in discovered:
                    continue
                    
                a_records = self._dns_query(full_domain, "A")
                if a_records is not None and len(a_records) > 0:
                    all_ips = a_records + (self._dns_query(full_domain, "AAAA") or [])
                    cname_records = self._dns_query(full_domain, "CNAME") or []
                    
                    discovered[full_domain] = DiscoveredSubdomain(
                        subdomain=full_domain,
                        status=DiscoveryStatus.ACTIVE,
                        ip_addresses=all_ips,
                        cname_records=cname_records,
                        cloud_provider=self._detect_cloud_provider(full_domain, all_ips, cname_records)
                    )
                
                time.sleep(self.rate_limit_delay)
        
        # Compile results
        result.subdomains = list(discovered.values())
        result.total_discovered = len(result.subdomains)
        result.active_subdomains = sum(
            1 for d in result.subdomains 
            if d.status == DiscoveryStatus.ACTIVE
        )
        result.end_time = datetime.now()
        result.duration_seconds = (result.end_time - start_time).total_seconds()
        self._discovery_count += 1
        
        return result
    
    def generate_attack_surface_report(self, result: DiscoveryResult) -> Dict[str, Any]:
        """Generate attack surface analysis report"""
        active = [d for d in result.subdomains if d.status == DiscoveryStatus.ACTIVE]
        
        cloud_distribution = defaultdict(int)
        for d in active:
            if d.cloud_provider:
                cloud_distribution[d.cloud_provider] += 1
        
        return {
            "discovery_id": result.discovery_id,
            "target_domain": result.target_domain,
            "summary": {
                "total_discovered": result.total_discovered,
                "active_subdomains": result.active_subdomains,
                "wildcard_detected": any(d.status == DiscoveryStatus.WILDCARD for d in result.subdomains),
                "discovery_duration_seconds": result.duration_seconds
            },
            "cloud_provider_distribution": dict(cloud_distribution),
            "top_subdomains_by_ips": sorted(
                active, 
                key=lambda x: len(x.ip_addresses), 
                reverse=True
            )[:10],
            "subdomains_with_cname": [d for d in active if len(d.cname_records) > 0],
            "subdomains_with_mx": [d for d in active if len(d.mx_records) > 0]
        }
    
    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get discovery engine statistics"""
        return {
            "engine": "SubdomainDiscoveryEngine",
            "discoveries_performed": self._discovery_count,
            "cache_size": len(self._dns_cache),
            "wordlist_size": len(self.COMMON_SUBDOMAINS),
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
            "rate_limit_delay_seconds": self.rate_limit_delay
        }
