

keywords:
    # Authentication & Verification - Higher weights for combinations
    'login': 35
    'log-in': 35
    'sign-in': 35
    'signin': 35
    'verify': 40
    'verification': 40
    'authenticate': 40
    'authentication': 40
    'account': 35
    'password': 35
    'credential': 35
    'confirm': 30
    'authorize': 35
    'authorization': 35
    'recovery': 35
    'unlock': 35
    'suspended': 35
    'unusual': 30
    'secure': 25

    # High-value Financial Targets
    'wallet': 40
    'crypto': 45
    'bitcoin': 50
    'eth': 45
    'metamask': 50
    'binance': 50
    'coinbase': 50
    'blockchain': 50
    'banker': 45
    'banking': 45
    'payment': 40
    'invoice': 35
    'transaction': 35
    
    # Major Brand Names (Frequently Targeted)
    'paypal': 80
    'apple': 70
    'icloud': 70
    'microsoft': 70
    'office365': 70
    'amazon': 70
    'netflix': 70
    'facebook': 65
    'instagram': 65
    'whatsapp': 65
    'twitter': 65
    'gmail': 70
    'google': 65
    'yahoo': 65
    'outlook': 65

    # Emerging Threats
    'covid': 40
    'vaccine': 40
    'tracking': 35
    'delivery': 35
    'shipment': 35
    'usps': 45
    'fedex': 45
    'dhl': 45
    'notification': 30
    'document': 30
    'share': 30
    'cloud': 30

    # Suspicious Combinations & Patterns
    'security': 35
    'alert': 35
    'update': 35
    'service': 25
    'support': 25
    'help': 20
    'desk': 20
    'customer': 25
    'online': 25
    'official': 30
    'verify-now': 45
    'update-now': 45
    'secure-verify': 45
    'auth-verify': 45
    'sign-verify': 45
    
    # Technical/URL Patterns
    'cgi-bin': 50
    'webscr': 45
    'form': 25
    'submit': 25
    'redirect': 35
    '-secure-': 35
    '-verify-': 35
    '-login-': 35
    '-auth-': 35
    
    # Domain Structure Red Flags
    '-com.': 30
    '.net-': 30
    '.org-': 30
    '.com-': 30
    '.net.': 30
    '.org.': 30
    '.com.': 30
    '.gov-': 40
    '.gov.': 40
    '-' : 15  # Suspicious number of hyphens checked in code

tlds:
    # Highest Risk (Commonly Abused)
    '.tk': 25
    '.ga': 25
    '.ml': 25
    '.cf': 25
    '.gq': 25
    '.icu': 25
    '.xyz': 20
    '.top': 20
    '.sir': 20
    '.sar': 20
    '.ru': 15
    
    # Moderate Risk
    '.cc': 15
    '.pw': 15
    '.club': 15
    '.work': 15
    '.top': 15
    '.support': 15
    '.bank': 15
    '.info': 15
    '.study': 15
    '.click': 15
    '.loan': 15
    '.download': 15
    '.racing': 15
    '.online': 15
    '.ren': 15
    '.win': 15
    '.review': 15
    '.vip': 15
    '.party': 15
    '.tech': 15
    '.science': 15
    '.business': 15
    '.mp3': 15
    '.pro': 15
    '.cr': 15

multipliers:
    # Combinations that increase score
    'login|password': 1.5
    'verify|account': 1.5
    'secure|update': 1.5
    'bank|verify': 1.75
    'wallet|crypto': 1.75
    'signin|auth': 1.5


***

suspis.yaml

    '.gb':
    '.win':
    '.review':
    '.vip':
    '.party':
    '.tech':
    '.science':
    '.business':
    '.ml':
    '.cf':
    '.tk':
    '.gq':
    '.ga':
    '.ru':
    '.mp3':
    '.xyz':
    '.sar':
    '.cr':
    '.icu':
    '.pro':
    '.top':
    '.sir':

***

***
## Nmap:

Public & Private IP - ``` ip a ``` | ``` hostename -I ```

Ping - ``` ping <DOMAIN/IP> ```

Scan Host Ports - ``` nmap -Pn <IP> ```

OS Scan - ``` nmap -O <IP> ```

Basic TCP Scan - ``` nmap -sT <IP> ```

Basic UDP Scan - ``` nmap -sU <IP> ```

Fastmode Scan - ``` nmap -F <DOMAIN/IP> ```

Version - ``` nmap -sV <DOMAIN/IP> ```

Aggressive Scan - ``` nmap -A <DOMAIN> ```

Traceroute SCan - ``` --traceroute <DOMAIN/IP> ```


255 Scan - ``` nmap 10.0.2.0/24 ```

Save Results - ``` nmap -oS saved.txt <DOMAIN/IP> ```
* * *

Port Scan - ``` nmap -p- -A -sC -Pn <IP> ``` | ``` nmap -F -Pn <IP> ```

Enum Scan - ``` nmap -sV -sC <IP> ```

Telnet Scan - ``` nmap -A -Pn -p- <IP> ```



* * * 

## Resources:

* [Hack_Tricks](https://book.hacktricks.xyz/welcome/readme) - Informative Blog
* [DORKS](https://github.com/cipher387/Dorks-collections-list/blob/main/README.md) - original dorks
* [Resources](https://github.com/birdbee44/Resources) - Tools, Articles, Manuals, Cheatsheets, etc.(502 links - 47 Categories)
* [FBI_Tools](https://github.com/danieldurnea/FBI-tools) - Tools for gathering information and actions forensic
* [Payloadd_All_Things](https://github.com/swisskyrepo/PayloadsAllTheThings) - A list of useful payloads and bypasses for Web Application Security
* [mr.d0x](https://mrd0x.com/) | [mr.d0x ~ filesec](https://filesec.io/#)  - Security Blog
* [Clone_Wars](https://github.com/gorvgoyl/clone-wars) - 100+ open-source clones and alternatives of popular sites 



## Literature:

* [All_About_Bugbounty](https://github.com/daffainfo/AllAboutBugBounty) - Collection of notes about on the most important BugBounty-related topics. Written concisely and succinctly. It can be read in one evening
* [Public_pentest_reports](https://github.com/juliocesarfort/public-pentesting-reports) - List of public penetration test report
* [Pentest_Guide](https://www.offensity.com/en/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/)
* [Sub-Domain_Enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
* [Checklist](https://gbhackers.com/web-application-penetration-testing-checklist-a-detailed-cheat-sheet/)
 

## Pentest Search Engines: [Huge_Search_Engine_List](https://github.com/edoardottt/awesome-hacker-search-engines)

* https://www.shodan.io/
* https://fullhunt.io/
* https://intelx.io/
* https://www.greynoise.io/
* https://censys.io/
* https://www.zoomeye.org/
* https://hunter.io/
* https://dnsdumpster.com/
* https://urlscan.io/
* https://wigle.net/
* https://socradar.io/
* https://haveibeenpwned.com/
* https://publicwww.com/
* https://pulsedive.com/
* https://reposify.com/
* https://phonebook.cz/
* https://redhuntlabs.com/online-ide-search
* https://securitytrails.com/
* https://www.onyphe.io/
* https://synapsint.com/
* https://ivre.rocks/
