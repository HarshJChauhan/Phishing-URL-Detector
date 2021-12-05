from datetime import datetime
from urllib import response
from urllib.parse import urlparse
import requests
from tldextract.tldextract import extract
import urllib.request
from bs4 import BeautifulSoup
import whois
import requests
from urllib.parse import urlparse, quote, urlencode
import json
import urllib
import time
import favicon

#url = "https://www.google.com"
#url = "https://www.stackoverflow.com"
#url = "https://www.facebook.com/login"
#url = "https://analytics.google.com/analytics/web"
url = "https://en.wikipedia.org/wiki/Stack_Overflow"
#url = "https://www.youtube.com"


icons = favicon.get(url)
icon = icons[0]
if icon in icons:
    print("legit")
else:
    print("malicious")