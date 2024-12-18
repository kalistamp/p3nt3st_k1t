#!/usr/bin/env python3
import re
import math
import time
import os
import certstream
import tqdm
import yaml
import whois
from datetime import datetime, timedelta
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld
from confusables import unconfuse

# Configuration
certstream_url = 'wss://certstream.calidog.io'
log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'
suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'
external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'

# Initialize progress bar
pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

# Homograph character mappings (expanded)
homograph_chars = {
    'а': 'a', 'β': 'b', 'ϲ': 'c', 'ԁ': 'd', 'е': 'e', 'ғ': 'f', 'ɡ': 'g', 'һ': 'h',
    'і': 'i', 'ј': 'j', 'κ': 'k', 'ӏ': 'l', 'м': 'm', 'η': 'n', 'о': 'o', 'р': 'p',
    'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'ս': 'u', 'ν': 'v', 'ѡ': 'w', 'х': 'x',
    'у': 'y', 'z': 'z'
}

def check_domain_age(domain):
    """Check if domain was recently registered"""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
                
            domain_age = datetime.now() - creation_date
            return domain_age.days
    except:
        return None
    return None

def detect_homographs(domain):
    """Detect homograph attack attempts in domain"""
    score = 0
    decoded = domain.encode('idna').decode('ascii').lower()
    
    # Check for mixed scripts
    has_latin = bool(re.search(r'[a-z]', domain))
    has_cyrillic = bool(re.search(r'[а-яА-Я]', domain))
    has_greek = bool(re.search(r'[\u0370-\u03FF]', domain))
    
    if sum([has_latin, has_cyrillic, has_greek]) > 1:
        score += 50
    
    # Check for homograph character substitutions
    substitutions = 0
    for char in domain:
        if char in homograph_chars:
            substitutions += 1
            
    if substitutions > 0:
        score += (substitutions * 25)
    
    # Check for lookalike domains against common targets
    common_targets = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal']
    for target in common_targets:
        if distance(decoded, target) == 1:  # One character different
            score += 75
            break
            
    return score

def entropy(string):
    """Calculate the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def score_domain(domain):
    """Score domain for suspiciousness"""
    score = 0
    
    # Remove initial wildcard
    if domain.startswith('*.'):
        domain = domain[2:]
    
    # Check TLD
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        if res and res.tld:
            if res.tld in suspicious['tlds']:
                score += suspicious['tlds'].get(res.tld, 20)  # Default 20 points for suspicious TLD
        
        # Extract domain without TLD
        domain_without_tld = '.'.join([res.subdomain, res.domain]) if res.subdomain else res.domain
    except:
        domain_without_tld = domain

    # Check domain age if possible
    domain_age = check_domain_age(domain)
    if domain_age is not None:
        if domain_age < 30:  # Domain less than 30 days old
            score += 40
        elif domain_age < 90:  # Domain less than 90 days old
            score += 20

    # Check for homograph attacks
    score += detect_homographs(domain)
    
    # Calculate entropy score
    score += int(round(entropy(domain_without_tld)*10))
    
    # Remove confusable characters
    domain_without_tld = unconfuse(domain_without_tld)
    
    # Check keywords
    for keyword in suspicious['keywords']:
        if keyword in domain_without_tld:
            score += suspicious['keywords'][keyword]

    # Check for excessive hyphens
    if domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Check for deep nesting
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score

def callback(message, context):
    """Callback handler for certstream events"""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower())

            # Increase score for certificates from free CAs
            if "Let's Encrypt" in message['data']['leaf_cert']['issuer']['O']:
                score += 10

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
                with open(log_suspicious, 'a') as f:
                    f.write("{}\t{}\n".format(domain, score))

if __name__ == '__main__':
    # Load configuration
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])
        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    # Start listening for certificates
    certstream.listen_for_events(callback, url=certstream_url)
