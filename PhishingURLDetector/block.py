from datetime import datetime
from tldextract import extract
import feature


#hostpath = "C:\Windows\System32\drivers\etc\hosts"
hostpath = "web_host.txt"
redirect = "127.0.0.1"

subdomain, domain, suffix = extract(feature.url)
domain_name = domain+"."+suffix
web_url = subdomain+"."+domain+"."+suffix


websites = [web_url,domain_name]

try:
    if datetime(datetime.now().year, datetime.now().month, datetime.now().day,0) < datetime.now() < datetime(datetime.now().year, datetime.now().month, datetime.now().day,23):
        print("Malicious Website Detected...\nProceeding to Block")
        with open(hostpath, 'r+') as file:
            content = file.read()
            for website in websites:
                if website in content:
                    pass
                else:
                    # mapping hostnames to your localhost IP address
                    file.write(redirect + " " + website + "\n")
except:
    print("error")