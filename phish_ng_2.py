#!/usr/bin/env python3
import re
import math
import time
import os
import json
import certstream
import tqdm
import yaml
from datetime import datetime, timedelta
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld
from confusables import unconfuse
from collections import defaultdict
import threading
import pickle

# Configuration paths
CERTSTREAM_URL = 'wss://certstream.calidog.io'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = os.path.join(BASE_DIR, f'suspicious_domains_{time.strftime("%Y-%m-%d")}.log')
SUSPICIOUS_YAML = os.path.join(BASE_DIR, 'suspicious.yaml')
EXTERNAL_YAML = os.path.join(BASE_DIR, 'external.yaml')

# Cache configuration
CACHE_DIR = '/dev/shm/phishing_catcher'  # RAM-based cache
PERSISTENT_CACHE = '/var/cache/phishing_catcher'  # Disk-based cache
CACHE_DURATION = 3600  # 1 hour cache lifetime

# Initialize progress bar
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

# Initialize caches
domain_cache = {}
cert_pattern_cache = defaultdict(int)

class CacheManager:
    def __init__(self):
        # Ensure cache directories exist
        for directory in [CACHE_DIR, PERSISTENT_CACHE]:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
        
        self.ram_cache_file = os.path.join(CACHE_DIR, 'domain_cache.pkl')
        self.disk_cache_file = os.path.join(PERSISTENT_CACHE, 'persistent_cache.pkl')
        self.load_cache()
        
        # Start cache cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def load_cache(self):
        """Load cache from disk on startup"""
        try:
            if os.path.exists(self.disk_cache_file):
                with open(self.disk_cache_file, 'rb') as f:
                    self.persistent_cache = pickle.load(f)
        except:
            self.persistent_cache = {}

    def save_cache(self):
        """Save cache to disk periodically"""
        try:
            with open(self.disk_cache_file, 'wb') as f:
                pickle.dump(self.persistent_cache, f)
        except:
            pass

    def _cleanup_loop(self):
        """Periodic cache cleanup"""
        while True:
            time.sleep(3600)  # Run every hour
            self._cleanup_cache()
            self.save_cache()

    def _cleanup_cache(self):
        """Remove expired cache entries"""
        now = time.time()
        expired = [k for k, v in domain_cache.items() if now - v['timestamp'] > CACHE_DURATION]
        for k in expired:
            domain_cache.pop(k, None)

cache_manager = CacheManager()

def analyze_keyboard_patterns(domain):
    """Detect keyboard pattern typos"""
    score = 0
    keyboard_neighbors = {
        'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'srfce',
        'e': 'wrsdf', 'f': 'dcvgr', 'g': 'fvbht', 'h': 'gbynj',
        'i': 'ujko', 'j': 'huknm', 'k': 'jm,lo', 'l': 'kop;.',
        'm': 'njk,', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol[.',
        'q': 'wa', 'r': 'edft', 's': 'awdxz', 't': 'rfgy',
        'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
        'y': 'tghu', 'z': 'asx'
    }
    
    for i in range(len(domain)-1):
        if domain[i] in keyboard_neighbors and domain[i+1] in keyboard_neighbors[domain[i]]:
            score += 15
    
    return score

def analyze_domain_patterns(domain):
    """Analyze domain for suspicious patterns"""
    score = 0
    
    # Check for repeated characters
    repeated = re.finditer(r'(.)\1{2,}', domain)
    for match in repeated:
        score += 10 * len(match.group())
    
    # Check brand names with added terms
    brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix']
    security_terms = ['secure', 'login', 'verify', 'update', 'account', 'service']
    
    domain_lower = domain.lower()
    for brand in brands:
        if brand in domain_lower:
            for term in security_terms:
                if term in domain_lower:
                    score += 25
                    if f'{brand}-{term}' in domain_lower or f'{term}-{brand}' in domain_lower:
                        score += 15
    
    # Check excessive subdomains
    subdomain_count = domain.count('.')
    if subdomain_count > 2:
        score += (subdomain_count - 2) * 20
    
    # Check for number sequences
    if re.search(r'\d{4,}', domain):
        score += 15
    
    return score

def analyze_cert_patterns(cert_data):
    """Analyze certificate patterns"""
    score = 0
    
    # Check certificate validity period
    try:
        not_before = datetime.strptime(cert_data['not_before'], '%Y-%m-%dT%H:%M:%S')
        not_after = datetime.strptime(cert_data['not_after'], '%Y-%m-%dT%H:%M:%S')
        validity_period = (not_after - not_before).days
        
        # Short validity periods are suspicious
        if validity_period < 30:
            score += 30
        elif validity_period < 90:
            score += 15
            
        # Track and score certificate patterns
        issuer = cert_data['issuer']['O']
        cert_pattern_cache[issuer] += 1
        
        # Many certs from same issuer in short time
        if cert_pattern_cache[issuer] > 100:
            score += 10
    except:
        pass
    
    return score

def entropy(string):
    """Calculate Shannon entropy of string"""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def score_domain(domain, cert_data=None):
    """Score domain for suspicious patterns"""
    score = 0
    
    # Check cache first
    cache_key = domain.lower()
    if cache_key in domain_cache:
        if time.time() - domain_cache[cache_key]['timestamp'] < CACHE_DURATION:
            return domain_cache[cache_key]['score']
    
    # Basic entropy score
    score += int(round(entropy(domain)*10))
    
    # Pattern analysis
    score += analyze_domain_patterns(domain)
    score += analyze_keyboard_patterns(domain)
    
    # Certificate analysis if available
    if cert_data:
        score += analyze_cert_patterns(cert_data)
    
    # Cache the result
    domain_cache[cache_key] = {
        'score': score,
        'timestamp': time.time()
    }
    
    return score

def callback(message, context):
    """Handle incoming certificate stream"""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        cert_data = message['data']['leaf_cert']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower(), cert_data)

            if score >= 100:
                tqdm.tqdm.write(
                    "[!] High Risk Domain: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['bold', 'underline']), score))
            elif score >= 90:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write(
                    "[!] Likely Phishing: "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 65:
                tqdm.tqdm.write(
                    "[+] Potential: "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))

            if score >= 75:
                with open(LOG_FILE, 'a') as f:
                    f.write(f"{domain}\t{score}\t{datetime.now()}\n")

if __name__ == '__main__':
    # Load configurations
    with open(SUSPICIOUS_YAML, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(EXTERNAL_YAML, 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml']:
        suspicious = external
    else:
        if external['keywords']:
            suspicious['keywords'].update(external['keywords'])
        if external['tlds']:
            suspicious['tlds'].update(external['tlds'])

    # Start certificate monitoring
    certstream.listen_for_events(callback, url=CERTSTREAM_URL)