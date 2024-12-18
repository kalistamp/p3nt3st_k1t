#!/usr/bin/env python3
import requests
import dns.resolver
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
from datetime import datetime
import os
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PhishingInvestigator:
    def __init__(self):
        self.common_paths = [
            # Admin and Control Panels
            '/admin/', '/panel/', '/cp/', '/dashboard/',
            '/login/', '/signin/', '/auth/',
            
            # Common Directories
            '/includes/', '/tmp/', '/temp/',
            '/backup/', '/bak/', '/old/',
            '/upload/', '/uploads/', '/files/',
            
            # Archives
            'backup.zip', 'admin.zip', 'site.zip', 'login.zip',
            'phpinfo.php', '.php~', '.php.bak', '.php.old',
            
            # Configuration Files
            'config.php', 'configuration.php', 'settings.php',
            'database.php', 'connect.php', 'wp-config.php',
            'config.php.bak', 'db.php',
            
            # Common Phishing Files
            'post.php', 'send.php', 'submit.php', 'capture.php',
            'process.php', 'next.php', 'redirect.php',
            'success.php', 'thanks.php', 'verify.php',
            'confirmation.php', 'validate.php', 'check.php',
            
            # Log Files
            'log.txt', 'logs.txt', 'error_log',
            'access_log', 'debug.log', 'data.txt',
            
            # Additional Phishing Artifacts
            'result.php', 'results.php', 'store.php',
            'save.php', 'handler.php', 'process_login.php',
            'auth.php', 'authenticate.php', 'validation.php',
            'proceed.php', 'continue.php', 'processing.php',
            'account.php', 'secure.php', 'update.php'
        ]

    def check_domain(self, line):
        """Check if a domain is active and accessible"""
        try:
            # Parse log line
            domain, score, timestamp = line.strip().split('\t')
            # Resolve domain
            ip = socket.gethostbyname(domain)
            
            # Check HTTP/HTTPS
            for protocol in ['http://', 'https://']:
                try:
                    url = f"{protocol}{domain}"
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                    if r.status_code == 200:
                        # Look for suspicious content
                        suspicious_terms = ['login', 'password', 'username', 'bank', 'verify',
                                         'account', 'secure', 'update', 'confirm', 'wallet']
                        content_match = any(term in r.text.lower() for term in suspicious_terms)
                        
                        return {
                            'domain': domain,
                            'score': score,
                            'ip': ip,
                            'protocol': protocol,
                            'status': r.status_code,
                            'suspicious_content': content_match,
                            'content_length': len(r.content),
                            'timestamp': timestamp
                        }
                except:
                    continue
        except:
            pass
        return None

    def scan_domain_artifacts(self, domain_info):
        """Scan domain for suspicious files and directories"""
        findings = []
        base_domain = domain_info['domain']
        protocol = domain_info['protocol']
        base_url = f"{protocol}{base_domain}"
        
        for path in self.common_paths:
            try:
                url = urljoin(base_url, path)
                r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                # Check if found something interesting
                if r.status_code in [200, 403]:  # 403 can be interesting too
                    content_type = r.headers.get('content-type', '')
                    size = len(r.content)
                    
                    # Look for interesting content
                    suspicious = False
                    suspicious_terms = ['password', 'username', 'login', '$', 'config', 
                                     'mysql', 'database', 'admin', 'bitcoin', 'wallet']
                    if any(x in r.text.lower() for x in suspicious_terms):
                        suspicious = True
                    
                    findings.append({
                        'url': url,
                        'status': r.status_code,
                        'size': size,
                        'type': content_type,
                        'suspicious': suspicious
                    })
            except:
                continue
                
        return findings

    def investigate_domains(self, logfile):
        """Main investigation process"""
        print(f"\n[+] Starting investigation of domains from {logfile}")
        
        # Read domains from log
        with open(logfile, 'r') as f:
            domains = f.readlines()
        
        print(f"[+] Checking {len(domains)} domains for activity...")
        
        # Check domain activity
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(self.check_domain, domains))
        
        # Filter active domains
        active_domains = [r for r in results if r]
        
        # Display summary of active domains first
        print(f"\n[+] Found {len(active_domains)} active domains:")
        print("\nInitial Summary:")
        print("="*80)
        print(f"{'#':<4} {'Domain':<40} {'Score':<8} {'IP':<15} {'Content':<8}")
        print("-"*80)
        for i, domain in enumerate(active_domains, 1):
            content_indicator = "Yes" if domain.get('suspicious_content', False) else "No"
            print(f"{i:<4} {domain['domain']:<40} {domain['score']:<8} {domain['ip']:<15} {content_indicator:<8}")
        print("="*80)
        
        # Ask user if they want to proceed with detailed scanning
        input("\nPress Enter to begin detailed scanning of each domain...")
        
        # Investigate each active domain
        for i, domain in enumerate(active_domains, 1):
            print(f"\n{'='*80}")
            print(f"Scanning Domain {i}/{len(active_domains)}")
            print(f"Domain: {domain['domain']}")
            print(f"Score: {domain['score']}")
            print(f"IP: {domain['ip']}")
            print(f"Status: {domain['status']}")
            print(f"Initial Content Length: {domain['content_length']}")
            print(f"Timestamp: {domain['timestamp']}")
            
            # Scan for artifacts
            print("\nScanning for suspicious files and directories...")
            findings = self.scan_domain_artifacts(domain)
            
            if findings:
                print("\nSuspicious findings:")
                for find in findings:
                    if find['suspicious']:
                        print(f"[!] {find['url']}")
                        print(f"    Status: {find['status']}, Size: {find['size']}, Type: {find['type']}")
            else:
                print("No suspicious files found.")

def main():
    parser = argparse.ArgumentParser(description='Investigate suspicious phishing domains')
    parser.add_argument('logfile', help='Path to the suspicious domains log file')
    args = parser.parse_args()
    
    if not os.path.exists(args.logfile):
        print(f"Error: Log file {args.logfile} not found!")
        return
    
    investigator = PhishingInvestigator()
    investigator.investigate_domains(args.logfile)

if __name__ == '__main__':
    main()
