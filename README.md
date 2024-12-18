


CVE-2024-4577_exploit.py





keywords:
    # Critical Authentication & Security
    'login': 70
    'log-in': 70
    'signin': 70
    'sign-in': 70
    'verify': 80
    'verification': 80
    'authenticate': 80
    'authentication': 80
    'password': 70
    'credential': 70
    'authorize': 70
    'secure-login': 90
    'verify-account': 90
    'auth-verify': 90
    'password-reset': 85
    'restore-access': 85
    'account-recovery': 85
    'suspended': 70
    'limited': 70
    'restricted': 70
    'unusual': 65
    'suspicious': 65

    # Financial & Cryptocurrency (Modern)
    'wallet': 85
    'metamask': 90
    'opensea': 85
    'web3': 85
    'defi': 85
    'nft': 80
    'crypto': 85
    'bitcoin': 85
    'ethereum': 85
    'binance': 85
    'coinbase': 85
    'kraken': 85
    'ledger': 85
    'trezor': 85
    'blockchain': 85
    'trustwallet': 85
    'pancakeswap': 85
    'uniswap': 85
    'airdrop': 80
    'mint': 75
    'stake': 75
    'swap': 75
    'yield': 75
    
    # Banking & Payments
    'bank': 80
    'chase': 85
    'wellsfargo': 85
    'citibank': 85
    'barclays': 85
    'santander': 85
    'hsbc': 85
    'rbс': 85
    'llоyds': 85
    'scotiabank': 85
    'wise': 80
    'revolut': 80
    'venmo': 80
    'zelle': 80
    'cashapp': 80
    'swift': 75
    'iban': 75
    'wire': 75
    'transfer': 75
    'e-transfer': 80

    # Modern Tech & Services
    'cloudflare': 85
    'protonmail': 85
    'tutanota': 85
    'signal': 80
    'telegram': 80
    'discord': 85
    'steam': 85
    'epic': 80
    'roblox': 80
    'tiktok': 80
    'onlyfans': 85
    'twitch': 80
    'zoom': 80
    'teams': 80
    'slack': 80
    'azure': 80
    'aws': 80
    'docusign': 85
    'dropbox': 80
    'wetransfer': 80

    # Delivery & Shopping
    'shipping': 75
    'delivery': 75
    'track': 70
    'order': 70
    'package': 70
    'shipment': 70
    'usps': 80
    'fedex': 80
    'dhl': 80
    'ups': 80
    'amazon': 85
    'walmart': 80
    'target': 80
    'ebay': 80
    'shop': 65
    'store': 65

    # Government & Services
    'gov': 85
    'irs': 90
    'hmrc': 90
    'taxref': 85
    'refund': 80
    'benefits': 80
    'stimulus': 85
    'payment': 80
    'relief': 75
    'grant': 75
    'medicare': 85
    'medicaid': 85
    'insurance': 80
    'claim': 75

    # Technical Patterns
    'api': 70
    'auth': 75
    'oauth': 80
    'sso': 80
    'mfa': 80
    '2fa': 80
    'webscr': 80
    'form': 65
    'portal': 70
    'access': 70
    'gateway': 70
    'cdn': 65
    'download': 70
    'upload': 70
    'redirect': 75
    'validation': 75
    'service': 65
    'support': 65
    'help': 60
    'desk': 60

    # Suspicious URL Patterns
    '-secure-': 75
    '-verify-': 75
    '-signin-': 75
    '-login-': 75
    '-auth-': 75
    '-update-': 75
    '-confirm-': 75
    '-online-': 70
    '-official-': 70
    '-support-': 70
    'my-': 65
    '-my-': 65
    'real-': 65
    '-real': 65
    'true-': 65
    '-true': 65
    
tlds:
    # Newly Observed in Phishing
    '.top': 40
    '.xyz': 40
    '.icu': 40
    '.buzz': 40
    '.shop': 35
    '.site': 35
    '.online': 35
    '.store': 35
    '.cloud': 35
    '.app': 35
    '.live': 35
    '.world': 35
    '.space': 35
    '.life': 35
    '.quest': 35
    '.homes': 35
    '.pics': 35
    '.ink': 35
    '.bond': 35
    '.fan': 35

    # Classic High-Risk
    '.tk': 45
    '.ga': 45
    '.ml': 45
    '.cf': 45
    '.gq': 45
    '.ru': 40
    '.su': 40
    '.pw': 40
    '.cc': 40
    '.biz': 35
    '.info': 35
    '.work': 35
    '.name': 35
    '.click': 35
    '.loan': 35
    '.hair': 35
    '.mom': 35
    '.party': 35
    '.rent': 35
    '.surf': 35
    
    # Emerging Markets (Often Abused)
    '.br': 30
    '.cn': 30
    '.id': 30
    '.in': 30
    '.ir': 30
    '.kr': 30
    '.mx': 30
    '.ph': 30
    '.th': 30
    '.tr': 30
    '.ua': 30
    '.vn': 30
    '.za': 30

multipliers:
    'login|verify': 2.0
    'wallet|connect': 2.0
    'bank|verify': 2.0
    'account|secure': 2.0
    'update|required': 2.0
    'credential|verify': 2.0
    'password|reset': 2.0
    'unusual|activity': 2.0
    'security|alert': 2.0
    'payment|confirm': 2.0
    'crypto|wallet': 2.0
    'nft|mint': 2.0
    'delivery|track': 1.8
    'tax|refund': 2.0
    'gov|benefit': 2.0


***
***

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
