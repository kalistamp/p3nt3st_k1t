
# Note: If ran as sudo Permissions will default to "Locked"

list = open("Tools.txt", "w")
list.write("""
Resources:

[ Take a list of domains and probe for working http and https servers ]
[ https://github.com/tomnomnom/httprobe ]

- Short guide to get started:

https://github.com/DennisFeldbusch/CheatSheet

- Subdomain Enumeration:

https://github.com/projectdiscovery/subfinder
https://github.com/aboul3la/Sublist3r
https://github.com/SpiderLabs/HostHunter
https://github.com/infosec-au/altdns
https://github.com/ProjectAnte/dnsgen
https://github.com/blechschmidt/massdns



- Monitor GitHub to search and find sensitive data :
[ Search Terms: company.com | dev | dev.company.com | company.com <API_key> | company.com <password> | api.company.com authorization ]

https://github.com/hisxo/gitGraber
https://github.com/michenriksen/gitrob
https://github.com/techgaun/github-dorks



""")
list.close()

file = open("Man.txt", "w")
file.write("""
Steps:

Subdomain Enumeration 
[ List Above ]

What Services are they using:

Do they use a WAF like CloudFront or CloudFlare ?
Do they use a CMS like Wordpress, Drupal or Joomla ?
Do they use a framework like AngularJS or CakePHP ?
Whats the version of Apache ?
Do they use template engine like Jinja2 or Smarty ?

Google Dorks:

site:target.com -www
site:target.com intitle:”test” -support
site:target.com ext:php | ext:html
site:subdomain.target.com
site:target.com inurl:auth
site:target.com inurl:dev

So, if you want to find WP-Config files with cleartext DB-credentials in it - [ inurl:wp-config.php intext:DB_PASSWORD -stackoverflow -wpbeginner -foro -forum -topic -blog -about -docs -articles ]

""")
file.close()
