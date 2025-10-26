#!/usr/bin/env python3
"""
Advanced Network Security & Vulnerability Scanner
Includes OWASP Top 10 checks and comprehensive vulnerability detection

Coded By: Infinity_sec (Nir_____)


WARNING: Only use on systems you own or have explicit written permission to scan.
Unauthorized scanning is illegal and may violate laws including CFAA.
"""

import socket
import sys
import argparse
import ssl
import json
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings('ignore')

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Please install requests: pip install requests")
    sys.exit(1)

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Display enhanced ASCII art banner"""
    banner = f"""{Colors.RED}
 _    __      __          _____                                 
| |  / /_  __/ /___      / ___/_________ _____  ____  ___  _____
| | / / / / / / __ \     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
| |/ / /_/ / / / / /    ___/ / /__/ /_/ / / / / / / /  __/ /    
|___/\__,_/_/_/ /_/____/____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                  /_____/                                        
{Colors.END}
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════════╗
║          Advanced Network Security & Vulnerability Scanner                ║
║                    Coded By: Infinity_sec (Nir_____)                      ║
╚═══════════════════════════════════════════════════════════════════════════╝{Colors.END}
{Colors.YELLOW}[!] WARNING: Only use on authorized systems - Unauthorized scanning is illegal{Colors.END}
"""
    print(banner)

class VulnerabilityDatabase:
    """Database of known vulnerabilities and exploits"""
    
    # Common vulnerable service versions
    VULNERABLE_VERSIONS = {
        'Apache': {
            '2.4.49': {'cve': 'CVE-2021-41773', 'severity': 'CRITICAL', 'description': 'Path Traversal and RCE'},
            '2.4.50': {'cve': 'CVE-2021-42013', 'severity': 'CRITICAL', 'description': 'Path Traversal and RCE'},
        },
        'nginx': {
            '1.3.9-1.4.0': {'cve': 'CVE-2013-2028', 'severity': 'HIGH', 'description': 'Memory Disclosure'},
        },
        'OpenSSH': {
            '7.4': {'cve': 'CVE-2018-15473', 'severity': 'MEDIUM', 'description': 'Username Enumeration'},
            '6.6': {'cve': 'CVE-2015-5600', 'severity': 'HIGH', 'description': 'MaxAuthTries Bypass'},
        },
        'MySQL': {
            '5.7.0-5.7.23': {'cve': 'CVE-2018-3081', 'severity': 'HIGH', 'description': 'Multiple Vulnerabilities'},
        },
        'PostgreSQL': {
            '9.3-11.2': {'cve': 'CVE-2019-10164', 'severity': 'HIGH', 'description': 'Stack Buffer Overflow'},
        },
        'vsftpd': {
            '2.3.4': {'cve': 'Backdoor', 'severity': 'CRITICAL', 'description': 'Backdoor Command Execution'},
        }
    }
    
    # OWASP Top 10 2021 Categories
    OWASP_TOP_10 = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable and Outdated Components',
        'A07': 'Identification and Authentication Failures',
        'A08': 'Software and Data Integrity Failures',
        'A09': 'Security Logging and Monitoring Failures',
        'A10': 'Server-Side Request Forgery (SSRF)'
    }

class AdvancedScanner:
    def __init__(self, target, ports=None, aggressive=False):
        self.target = target
        self.ports = ports or range(1, 1025)
        self.aggressive = aggressive
        self.base_url = None
        self.results = {
            'target': target,
            'scan_time': str(datetime.now()),
            'ip_address': None,
            'open_ports': [],
            'services': {},
            'os_guess': None,
            'vulnerabilities': [],
            'owasp_findings': {},
            'risk_score': 0,
            'ssl_issues': [],
            'web_vulnerabilities': [],
            'credentials': []
        }
    
    def resolve_target(self):
        """Resolve hostname to IP"""
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip_address'] = ip
            print(f"{Colors.GREEN}[+] Target: {self.target} ({ip}){Colors.END}")
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}[-] Cannot resolve hostname: {self.target}{Colors.END}")
            sys.exit(1)
    
    def scan_port(self, port):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    def port_scan(self):
        """Multi-threaded port scanning"""
        print(f"\n{Colors.CYAN}[*] Scanning ports on {self.target}...{Colors.END}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    print(f"{Colors.GREEN}[+] Port {port} is OPEN{Colors.END}")
        
        self.results['open_ports'] = sorted(open_ports)
        return open_ports
    
    def grab_banner(self, port):
        """Advanced banner grabbing with service-specific probes"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            
            # Service-specific probes
            if port == 22:  # SSH
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [80, 443, 8080, 8443]:  # HTTP(S)
                request = f"HEAD / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                sock.send(request.encode())
                banner = sock.recv(2048).decode('utf-8', errors='ignore')
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.send(b"EHLO test\r\n")
                banner += sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 3306:  # MySQL
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            else:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.close()
            return banner.strip()
        except:
            return None
    
    def detect_service(self, port):
        """Enhanced service detection with version extraction"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
            5900: 'VNC', 1433: 'MSSQL', 11211: 'Memcached', 9200: 'Elasticsearch'
        }
        
        service_info = {
            'port': port,
            'service': common_services.get(port, 'Unknown'),
            'version': 'Unknown',
            'banner': None,
            'cpe': None
        }
        
        banner = self.grab_banner(port)
        if banner:
            service_info['banner'] = banner[:500]
            
            # Extract version information
            version_patterns = [
                r'Apache[/\s]+([\d.]+)',
                r'nginx[/\s]+([\d.]+)',
                r'OpenSSH[_\s]+([\d.]+)',
                r'MySQL[/\s]+([\d.]+)',
                r'PostgreSQL\s+([\d.]+)',
                r'Microsoft-IIS[/\s]+([\d.]+)',
                r'vsftpd\s+([\d.]+)',
                r'ProFTPD\s+([\d.]+)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    service_info['version'] = match.group(1)
                    service_name = re.search(r'([A-Za-z-]+)', pattern).group(1)
                    service_info['service'] = service_name
                    break
        
        return service_info
    
    def service_detection(self, open_ports):
        """Detect services on all open ports"""
        print(f"\n{Colors.CYAN}[*] Performing service detection...{Colors.END}")
        
        for port in open_ports:
            service_info = self.detect_service(port)
            self.results['services'][port] = service_info
            print(f"{Colors.GREEN}[+] Port {port}: {service_info['service']} {service_info['version']}{Colors.END}")
    
    def check_ssl_tls(self, port):
        """Advanced SSL/TLS security analysis"""
        print(f"\n{Colors.CYAN}[*] Analyzing SSL/TLS on port {port}...{Colors.END}")
        ssl_issues = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check SSL/TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_issues.append({
                            'type': 'Weak Protocol',
                            'severity': 'HIGH',
                            'description': f'Outdated protocol {version} enabled',
                            'owasp': 'A02',
                            'cwe': 'CWE-327'
                        })
                    
                    # Check weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                    if cipher and any(weak in cipher[0] for weak in weak_ciphers):
                        ssl_issues.append({
                            'type': 'Weak Cipher',
                            'severity': 'HIGH',
                            'description': f'Weak cipher suite: {cipher[0]}',
                            'owasp': 'A02',
                            'cwe': 'CWE-327'
                        })
                    
                    # Check certificate
                    if not cert:
                        ssl_issues.append({
                            'type': 'No Certificate',
                            'severity': 'CRITICAL',
                            'description': 'No SSL certificate found',
                            'owasp': 'A02',
                            'cwe': 'CWE-295'
                        })
                    
                    print(f"{Colors.GREEN}[+] SSL/TLS Version: {version}{Colors.END}")
                    print(f"{Colors.GREEN}[+] Cipher: {cipher[0] if cipher else 'Unknown'}{Colors.END}")
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] SSL/TLS check failed: {str(e)}{Colors.END}")
        
        self.results['ssl_issues'].extend(ssl_issues)
        return ssl_issues
    
    def check_web_vulnerabilities(self, port):
        """OWASP Top 10 web vulnerability checks"""
        print(f"\n{Colors.CYAN}[*] Checking web vulnerabilities on port {port}...{Colors.END}")
        
        protocol = 'https' if port in [443, 8443] else 'http'
        base_url = f"{protocol}://{self.target}:{port}"
        self.base_url = base_url
        
        try:
            # Test if web server is responsive
            response = requests.get(base_url, timeout=5, verify=False)
        except:
            print(f"{Colors.RED}[-] Web server not accessible on port {port}{Colors.END}")
            return
        
        # A01: Broken Access Control
        self.test_broken_access_control(base_url)
        
        # A02: Cryptographic Failures
        self.test_crypto_failures(base_url, port)
        
        # A03: Injection
        self.test_injection_vulnerabilities(base_url)
        
        # A05: Security Misconfiguration
        self.test_security_misconfiguration(base_url)
        
        # A06: Vulnerable Components
        self.test_vulnerable_components(base_url)
        
        # A07: Authentication Failures
        self.test_auth_failures(base_url)
        
        # Additional checks
        self.test_xss_vulnerabilities(base_url)
        self.test_common_files(base_url)
    
    def test_broken_access_control(self, base_url):
        """Test for broken access control (OWASP A01)"""
        print(f"{Colors.CYAN}[*] Testing Broken Access Control...{Colors.END}")
        
        # Test for directory traversal
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{base_url}/{payload}"
                response = requests.get(test_url, timeout=3, verify=False)
                
                if 'root:' in response.text or '[extensions]' in response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'Path Traversal',
                        'severity': 'CRITICAL',
                        'owasp': 'A01',
                        'cwe': 'CWE-22',
                        'url': test_url,
                        'description': 'Directory traversal vulnerability detected',
                        'evidence': response.text[:100]
                    })
                    print(f"{Colors.RED}[!] CRITICAL: Path Traversal found!{Colors.END}")
                    break
            except:
                pass
        
        # Test for exposed admin panels
        admin_paths = ['/admin', '/administrator', '/admin.php', '/wp-admin', '/phpmyadmin']
        for path in admin_paths:
            try:
                response = requests.get(base_url + path, timeout=3, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    self.results['vulnerabilities'].append({
                        'type': 'Exposed Admin Panel',
                        'severity': 'MEDIUM',
                        'owasp': 'A01',
                        'cwe': 'CWE-425',
                        'url': base_url + path,
                        'description': 'Admin panel accessible without authentication',
                    })
                    print(f"{Colors.YELLOW}[!] Admin panel found: {path}{Colors.END}")
            except:
                pass
    
    def test_crypto_failures(self, base_url, port):
        """Test for cryptographic failures (OWASP A02)"""
        print(f"{Colors.CYAN}[*] Testing Cryptographic Failures...{Colors.END}")
        
        # Check if HTTPS is available
        if port == 80:
            try:
                https_url = base_url.replace('http://', 'https://').replace(':80', ':443')
                response = requests.get(https_url, timeout=3, verify=False)
                if response.status_code >= 400:
                    self.results['vulnerabilities'].append({
                        'type': 'Missing HTTPS',
                        'severity': 'HIGH',
                        'owasp': 'A02',
                        'cwe': 'CWE-319',
                        'description': 'HTTPS not properly configured',
                    })
                    print(f"{Colors.YELLOW}[!] HTTPS not available or misconfigured{Colors.END}")
            except:
                self.results['vulnerabilities'].append({
                    'type': 'Missing HTTPS',
                    'severity': 'HIGH',
                    'owasp': 'A02',
                    'cwe': 'CWE-319',
                    'description': 'No HTTPS available',
                })
        
        # Check for SSL/TLS issues
        if port in [443, 8443]:
            self.check_ssl_tls(port)
    
    def test_injection_vulnerabilities(self, base_url):
        """Test for injection vulnerabilities (OWASP A03)"""
        print(f"{Colors.CYAN}[*] Testing Injection Vulnerabilities...{Colors.END}")
        
        # SQL Injection tests
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "1' UNION SELECT NULL--",
        ]
        
        test_params = ['id', 'user', 'username', 'email', 'search', 'q']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=3, verify=False)
                    
                    # SQL error patterns
                    sql_errors = [
                        'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                        'SQLite', 'Microsoft SQL', 'ODBC', 'mysql_query'
                    ]
                    
                    if any(error in response.text for error in sql_errors):
                        self.results['vulnerabilities'].append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'owasp': 'A03',
                            'cwe': 'CWE-89',
                            'url': test_url,
                            'description': 'Possible SQL injection vulnerability',
                            'parameter': param,
                            'payload': payload
                        })
                        print(f"{Colors.RED}[!] CRITICAL: SQL Injection found in {param}!{Colors.END}")
                        return  # Stop after first finding
                except:
                    pass
        
        # Command Injection test
        cmd_payloads = ['; ls', '| whoami', '`id`', '$(whoami)']
        for payload in cmd_payloads:
            try:
                test_url = f"{base_url}?cmd={payload}"
                response = requests.get(test_url, timeout=3, verify=False)
                
                if 'root' in response.text or 'uid=' in response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'Command Injection',
                        'severity': 'CRITICAL',
                        'owasp': 'A03',
                        'cwe': 'CWE-78',
                        'url': test_url,
                        'description': 'Command injection vulnerability detected'
                    })
                    print(f"{Colors.RED}[!] CRITICAL: Command Injection found!{Colors.END}")
                    break
            except:
                pass
    
    def test_xss_vulnerabilities(self, base_url):
        """Test for XSS vulnerabilities"""
        print(f"{Colors.CYAN}[*] Testing XSS Vulnerabilities...{Colors.END}")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert(1)</script>',
            "javascript:alert('XSS')",
            '<img src=x onerror=alert(1)>',
        ]
        
        test_params = ['q', 'search', 'query', 'name', 'comment']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    test_url = f"{base_url}?{param}={payload}"
                    response = requests.get(test_url, timeout=3, verify=False)
                    
                    if payload in response.text:
                        self.results['vulnerabilities'].append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'HIGH',
                            'owasp': 'A03',
                            'cwe': 'CWE-79',
                            'url': test_url,
                            'description': 'Reflected XSS vulnerability',
                            'parameter': param,
                            'payload': payload
                        })
                        print(f"{Colors.YELLOW}[!] HIGH: XSS found in {param}!{Colors.END}")
                        return
                except:
                    pass
    
    def test_security_misconfiguration(self, base_url):
        """Test for security misconfigurations (OWASP A05)"""
        print(f"{Colors.CYAN}[*] Testing Security Misconfigurations...{Colors.END}")
        
        try:
            response = requests.get(base_url, timeout=5, verify=False)
            headers = response.headers
            
            # Check security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME-sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not configured',
                'Content-Security-Policy': 'CSP not configured',
                'X-XSS-Protection': 'XSS protection header missing'
            }
            
            for header, issue in security_headers.items():
                if header not in headers:
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'owasp': 'A05',
                        'cwe': 'CWE-16',
                        'description': issue,
                        'header': header
                    })
                    print(f"{Colors.YELLOW}[!] Missing header: {header}{Colors.END}")
            
            # Check for server information disclosure
            if 'Server' in headers:
                self.results['vulnerabilities'].append({
                    'type': 'Information Disclosure',
                    'severity': 'LOW',
                    'owasp': 'A05',
                    'cwe': 'CWE-200',
                    'description': f'Server banner disclosed: {headers["Server"]}'
                })
            
            # Check for directory listing
            try:
                dir_response = requests.get(base_url + '/images/', timeout=3, verify=False)
                if 'Index of' in dir_response.text or 'Directory listing' in dir_response.text:
                    self.results['vulnerabilities'].append({
                        'type': 'Directory Listing',
                        'severity': 'MEDIUM',
                        'owasp': 'A05',
                        'cwe': 'CWE-548',
                        'description': 'Directory listing enabled'
                    })
                    print(f"{Colors.YELLOW}[!] Directory listing enabled{Colors.END}")
            except:
                pass
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Security misconfiguration check failed: {str(e)}{Colors.END}")
    
    def test_vulnerable_components(self, base_url):
        """Check for vulnerable components (OWASP A06)"""
        print(f"{Colors.CYAN}[*] Checking Vulnerable Components...{Colors.END}")
        
        for port, service in self.results['services'].items():
            service_name = service['service']
            version = service['version']
            
            if version != 'Unknown':
                # Check against vulnerability database
                if service_name in VulnerabilityDatabase.VULNERABLE_VERSIONS:
                    vuln_versions = VulnerabilityDatabase.VULNERABLE_VERSIONS[service_name]
                    
                    for vuln_ver, vuln_info in vuln_versions.items():
                        if version in vuln_ver or version == vuln_ver:
                            self.results['vulnerabilities'].append({
                                'type': 'Vulnerable Component',
                                'severity': vuln_info['severity'],
                                'owasp': 'A06',
                                'cwe': 'CWE-1035',
                                'service': service_name,
                                'version': version,
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description']
                            })
                            color = Colors.RED if vuln_info['severity'] == 'CRITICAL' else Colors.YELLOW
                            print(f"{color}[!] {vuln_info['severity']}: {service_name} {version} - {vuln_info['cve']}{Colors.END}")
    
    def test_auth_failures(self, base_url):
        """Test for authentication failures (OWASP A07)"""
        print(f"{Colors.CYAN}[*] Testing Authentication Mechanisms...{Colors.END}")
        
        # Test for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('administrator', 'administrator'),
            ('admin', ''),
        ]
        
        login_paths = ['/login', '/admin/login', '/wp-login.php', '/user/login']
        
        for path in login_paths:
            try:
                login_url = base_url + path
                response = requests.get(login_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    for username, password in default_creds:
                        # Don't actually attempt login to avoid account lockouts
                        self.results['vulnerabilities'].append({
                            'type': 'Default Credentials Risk',
                            'severity': 'HIGH',
                            'owasp': 'A07',
                            'cwe': 'CWE-798',
                            'url': login_url,
                            'description': 'Login page found - test for default credentials',
                            'recommendation': f'Test credentials: {username}:{password}'
                        })
                        print(f"{Colors.YELLOW}[!] Login page found: {path}{Colors.END}")
                        return
            except:
                pass
    
    def test_common_files(self, base_url):
        """Test for exposed sensitive files"""
        print(f"{Colors.CYAN}[*] Checking for sensitive files...{Colors.END}")
        
        sensitive_files = [
            '/.git/config',
            '/.env',
            '/backup.sql',
            '/phpinfo.php',
            '/server-status',
            '/config.php.bak',
            '/.htaccess',
            '/web.config',
            '/composer.json',
            '/package.json',
        ]
        
        for file_path in sensitive_files:
            try:
                response = requests.get(base_url + file_path, timeout=3, verify=False)
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'Sensitive File Exposure',
                        'severity': 'HIGH',
                        'owasp': 'A05',
                        'cwe': 'CWE-200',
                        'url': base_url + file_path,
                        'description': f'Sensitive file exposed: {file_path}'
                    })
                    print(f"{Colors.YELLOW}[!] Sensitive file found: {file_path}{Colors.END}")
            except:
                pass
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        severity_scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        
        total_score = 0
        for vuln in self.results['vulnerabilities']:
            total_score += severity_scores.get(vuln['severity'], 0)
        
        for ssl_issue in self.results['ssl_issues']:
            total_score += severity_scores.get(ssl_issue['severity'], 0)
        
        self.results['risk_score'] = min(total_score, 100)
        
        # Risk level
        if total_score >= 30:
            risk_level = "CRITICAL"
        elif total_score >= 20:
            risk_level = "HIGH"
        elif total_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        self.results['risk_level'] = risk_level
        return total_score, risk_level
    
    def categorize_owasp(self):
        """Categorize findings by OWASP Top 10"""
        owasp_summary = {}
        
        for vuln in self.results['vulnerabilities']:
            if 'owasp' in vuln:
                owasp_cat = vuln['owasp']
                if owasp_cat not in owasp_summary:
                    owasp_summary[owasp_cat] = {
                        'name': VulnerabilityDatabase.OWASP_TOP_10.get(owasp_cat, 'Unknown'),
                        'count': 0,
                        'findings': []
                    }
                owasp_summary[owasp_cat]['count'] += 1
                owasp_summary[owasp_cat]['findings'].append(vuln)
        
        self.results['owasp_findings'] = owasp_summary
    
    def generate_report(self, output_file=None):
        """Generate comprehensive security report"""
        risk_score, risk_level = self.calculate_risk_score()
        self.categorize_owasp()
        
        # Color for risk level
        risk_colors = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.YELLOW,
            'MEDIUM': Colors.BLUE,
            'LOW': Colors.GREEN
        }
        risk_color = risk_colors.get(risk_level, Colors.WHITE)
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.WHITE}ADVANCED SECURITY SCAN REPORT{Colors.END}")
        print(f"{Colors.CYAN}{'='*70}{Colors.END}")
        print(f"{Colors.WHITE}Target: {self.results['target']} ({self.results['ip_address']}){Colors.END}")
        print(f"{Colors.WHITE}Scan Date: {self.results['scan_time']}{Colors.END}")
        print(f"{Colors.WHITE}Risk Score: {risk_color}{risk_score}/100{Colors.END}")
        print(f"{Colors.WHITE}Risk Level: {risk_color}{risk_level}{Colors.END}")
        print(f"{Colors.WHITE}Open Ports: {Colors.GREEN}{len(self.results['open_ports'])}{Colors.END}")
        print(f"{Colors.WHITE}Vulnerabilities: {Colors.RED}{len(self.results['vulnerabilities'])}{Colors.END}")
        print(f"{Colors.WHITE}SSL/TLS Issues: {Colors.YELLOW}{len(self.results['ssl_issues'])}{Colors.END}")
        
        # Print vulnerability summary
        if self.results['vulnerabilities']:
            print(f"\n{Colors.BOLD}{Colors.RED}[!] VULNERABILITY SUMMARY{Colors.END}")
            severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for vuln in self.results['vulnerabilities']:
                severity_count[vuln['severity']] = severity_count.get(vuln['severity'], 0) + 1
            
            if severity_count['CRITICAL'] > 0:
                print(f"{Colors.RED}  • CRITICAL: {severity_count['CRITICAL']}{Colors.END}")
            if severity_count['HIGH'] > 0:
                print(f"{Colors.YELLOW}  • HIGH: {severity_count['HIGH']}{Colors.END}")
            if severity_count['MEDIUM'] > 0:
                print(f"{Colors.BLUE}  • MEDIUM: {severity_count['MEDIUM']}{Colors.END}")
            if severity_count['LOW'] > 0:
                print(f"{Colors.GREEN}  • LOW: {severity_count['LOW']}{Colors.END}")
        
        # Print OWASP findings
        if self.results['owasp_findings']:
            print(f"\n{Colors.BOLD}{Colors.CYAN}[*] OWASP TOP 10 FINDINGS{Colors.END}")
            for owasp_id, data in sorted(self.results['owasp_findings'].items()):
                print(f"{Colors.YELLOW}  • {owasp_id}: {data['name']} - {data['count']} findings{Colors.END}")
        
        if output_file:
            self._write_report_file(output_file, risk_score, risk_level)
            print(f"\n{Colors.GREEN}[+] Full report saved to: {output_file}{Colors.END}")
        
        print(f"{Colors.CYAN}{'='*70}{Colors.END}\n")
    
    def _write_report_file(self, output_file, risk_score, risk_level):
        """Write detailed report to file"""
        with open(output_file, 'w') as f:
            f.write("# Advanced Security Scan Report\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"**Coded By:** Infinity_sec (Nir_____)\n\n")
            f.write(f"**Target:** {self.results['target']} ({self.results['ip_address']})\n")
            f.write(f"**Scan Date:** {self.results['scan_time']}\n")
            f.write(f"**Risk Score:** {risk_score}/100\n")
            f.write(f"**Risk Level:** {risk_level}\n\n")
            
            # Open Ports
            f.write("## Open Ports\n")
            for port in self.results['open_ports']:
                service = self.results['services'].get(port, {})
                f.write(f"- Port {port}: {service.get('service', 'Unknown')} {service.get('version', '')}\n")
            f.write("\n")
            
            # Vulnerabilities
            if self.results['vulnerabilities']:
                f.write("## Vulnerabilities\n\n")
                for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                    f.write(f"### {i}. {vuln['type']}\n")
                    f.write(f"**Severity:** {vuln['severity']}\n")
                    if 'owasp' in vuln:
                        f.write(f"**OWASP:** {vuln['owasp']} - {VulnerabilityDatabase.OWASP_TOP_10.get(vuln['owasp'], '')}\n")
                    if 'cwe' in vuln:
                        f.write(f"**CWE:** {vuln['cwe']}\n")
                    f.write(f"**Description:** {vuln['description']}\n")
                    if 'url' in vuln:
                        f.write(f"**URL:** {vuln['url']}\n")
                    if 'cve' in vuln:
                        f.write(f"**CVE:** {vuln['cve']}\n")
                    f.write("\n")
            
            # SSL/TLS Issues
            if self.results['ssl_issues']:
                f.write("## SSL/TLS Issues\n\n")
                for i, issue in enumerate(self.results['ssl_issues'], 1):
                    f.write(f"### {i}. {issue['type']}\n")
                    f.write(f"**Severity:** {issue['severity']}\n")
                    f.write(f"**Description:** {issue['description']}\n\n")
            
            # OWASP Summary
            if self.results['owasp_findings']:
                f.write("## OWASP Top 10 Summary\n\n")
                for owasp_id, data in sorted(self.results['owasp_findings'].items()):
                    f.write(f"### {owasp_id}: {data['name']}\n")
                    f.write(f"**Findings:** {data['count']}\n\n")
    
    def run_full_scan(self, output_file=None):
        """Execute full vulnerability scan"""
        self.resolve_target()
        open_ports = self.port_scan()
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.END}")
            return
        
        self.service_detection(open_ports)
        
        # Check web vulnerabilities on common web ports
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
        for port in web_ports:
            self.check_web_vulnerabilities(port)
        
        # Check SSL/TLS on HTTPS ports
        ssl_ports = [p for p in open_ports if p in [443, 8443]]
        for port in ssl_ports:
            if port not in web_ports:  # Avoid duplicate checks
                self.check_ssl_tls(port)
        
        self.generate_report(output_file)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Network Security & Vulnerability Scanner by Infinity_sec',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python vuln_scanner.py -t example.com
  python vuln_scanner.py -t 192.168.1.1 -p 1-1000
  python vuln_scanner.py -t example.com -p 80,443,8080 -o report.md
  python vuln_scanner.py -t example.com --aggressive

WARNING: Only use on systems you own or have explicit permission to scan!
        '''
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,8080)', default='1-1024')
    parser.add_argument('-o', '--output', help='Output report file (markdown format)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Enable aggressive scanning')
    parser.add_argument('--no-banner', action='store_true', help='Disable banner display')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # Parse port range
    ports = []
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = range(start, end + 1)
    elif ',' in args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    else:
        ports = [int(args.ports)]
    
    # Create scanner instance
    scanner = AdvancedScanner(args.target, ports=ports, aggressive=args.aggressive)
    
    try:
        scanner.run_full_scan(output_file=args.output)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
