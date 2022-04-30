
# Note: If ran as sudo Permissions will default to "Locked"

fold_one = 'Pen_kit'
os.mkdir(fold_one, mode=0o777)

list = open("Tools.txt", "w")
list.write("""
Resources:

[ Take a list of domains and probe for working http and https servers ]
[ https://github.com/tomnomnom/httprobe ]

- Short guide to get started:

https://github.com/DennisFeldbusch/CheatSheet
https://book.hacktricks.xyz/pentesting/pentesting-network#discovering-hosts

- Subdomain Enumeration:

https://github.com/projectdiscovery/subfinder
https://github.com/aboul3la/Sublist3r
https://github.com/SpiderLabs/HostHunter
https://github.com/infosec-au/altdns
https://github.com/ProjectAnte/dnsgen
https://github.com/blechschmidt/massdns
https://github.com/UnaPibaGeek/ctfr


- Monitor GitHub to search and find sensitive data :
[ Search Terms: company.com | dev | dev.company.com | company.com <API_key> | company.com <password> | api.company.com authorization ]

https://github.com/hisxo/gitGraber
https://github.com/michenriksen/gitrob
https://github.com/techgaun/github-dorks

TOP Information Gathering Tools: 

http://nibbler.silktide.com - Tool for comprehensive website analysis on more than ten different parameters

Dracnmap - https://github.com/Screetsec/Dracnmap
Xerosploit - https://github.com/LionSec/xerosploit 
RED HAWK (All In One Scanning) - https://github.com/Tuhinshubhra/RED_HAWK 
ReconSpider(For All Scaning) - https://github.com/bhavsec/reconspider 
IsItDown (Check Website Down/Up)  - https://www.isitdownrightnow.com/
Infoga - Email OSINT - https://github.com/m4ll0k/Infoga
ReconDog - https://github.com/s0md3v/ReconDog 
Striker - https://github.com/s0md3v/Striker 
SecretFinder (like API & etc) - https://github.com/m4ll0k/SecretFinder 
Find Info Using Shodan - https://github.com/m4ll0k/Shodanfy.py 
rang3r - https://github.com/floriankunushevci/rang3r 
Breacher https://github.com/s0md3v/Breacher

""")
list.close()

file = open("Man.txt", "w")
file.write("""

Subdomain Enumeration 
[ List Above ]

What Services are they using:

Do they use a WAF like CloudFront or CloudFlare ?
Do they use a CMS like Wordpress, Drupal or Joomla ?
Do they use a framework like AngularJS or CakePHP ?
Whats the version of Apache ?
Do they use template engine like Jinja2 or Smarty ?

Google Dorks:

So, if you want to find WP-Config files with cleartext DB-credentials in it, google: [ inurl:wp-config.php intext:DB_PASSWORD -stackoverflow -wpbeginner -foro -forum -topic -blog -about -docs -articles ]

site:target.com -www
site:target.com intitle:”test” -support
site:target.com ext:php | ext:html
site:subdomain.target.com
site:target.com inurl:auth
site:target.com inurl:dev

""")
file.close()

file = open("Recon_man", "w")
file.write("""

                9 OSINT-services/Steps for gathering information about a website:

1. Collect basic information about domain

[IP address lookup, whois records, dns records, ping, traceroute, NSlookup]

2. Find out what technology was used to create the site: frameworks, #javascript libraries, analytics and tracking tools, widgets, payment systems, content delivery networks etc.

[builtwith.com/]

3. Get a list of sites belonging to the same owner (having the same Yandex.Metrika and Google Analytics counter numbers, as well as other common identifiers)

[builtwith.com/relationships/]

4. Map Subdomains

[dnsdumpster.com/#domainmap]

5. Looking for email addresses associated with the domain or subdomains

[hunter.io/search | snov.io/email-finder | https://github.com/sharsil/mailcat]

6. Download documents (PDF, docx, xlsx, pptx) from the site and analyze their metadata. This way you can find the names of the organization's employees, user names in the system and emails.

[github.com/laramies/metagoofil | https://github.com/ferreiraklet/Aline]

7. Use Google Dorks to look for database dumps, office documents, log files, and potentially vulnerable pages

[dorks.faisalahmed.me]

8. Looking for old versions of the site in archives and caches of search engines (sometimes in this way you can find addresses and contact information of the owners, which are currently already hidden from the site)

[https://cipher387.github.io/quickcacheandarchivesearch/]

9. Find out the approximate geographical location of the site

[iplocation.net/ip-lookup]


""")
file.close()
