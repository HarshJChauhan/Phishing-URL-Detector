from urllib.parse import urlparse, quote
import urllib.request
import ipaddress
import re
import requests
from datetime import datetime
import socket
from bs4 import BeautifulSoup
import ssl
from tldextract import extract
import favicon
import whois


url = "	https://allegro-order.pl-id32454099.xyz"
#url = "http://activate.facebook.fblogins.net/88adbao798283o8298398?login.asp"
#url = "https://houses.servegame.com/?checkid=a@abc"
#url = "https://komnestinis.000webhostapp.com/untuaklogin.html"
#url = "https://arsempengenharia.com/wp-admin/network/Swiss_Post.Home-page/Redsys.html"
#url = "https://www.agdkbabwicklunge.com/bericht/zuweisem/57JaKkGrTY42p7L2grh6K5/clients/login.php"

class urlfeatures:

    # Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name.
    # If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone
    # is trying to steal personal information with this URL. If the domain part of URL has IP address,
    # the value assigned to this feature is -1 (phishing) or else 1 (legitimate).
    def having_IPhaving_IP_Address():
        try:
            ipaddress.ip_address(url)
            ip = -1
        except:
            ip = 1
        return ip

    # Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar.
    # In this project, if the length of the URL is greater than or equal 54 characters then the URL classified
    # as phishing otherwise legitimate.If the length of URL >= 54 , the value assigned to this feature is
    # -1 (phishing) or else if 0 (suspicious) else 1 (legitimate).
    def URLURL_Length():
        if len(url) < 54:
            length = 1
        else:
            length = -1
        return length

    # URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length
    # and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name
    # that is short, which links to the webpage that has a long URL. If the URL is using Shortening Services, the
    # value assigned to this feature is -1 (phishing) or else 1 (legitimate).
    def Shortining_Service():
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                              r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                              r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                              r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                              r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                              r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                              r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                              r"tr\.im|link\.zip\.net"
        match = re.search(shortening_services, url)
        if match:
            return -1
        else:
            return 1

    # Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser to ignore everything
    # preceding the “@” symbol and the real address often follows the “@” symbol. If the URL has '@' symbol, the value assigned
    # to this feature is -1 (phishing) or else 1 (legitimate).
    def having_At_Symbol():

        if "@" in url:
            return -1
        else:
            return 1
            
        

    # Checks the presence of "//" in the URL. The existence of “//” within the URL path means that the user will be redirected to
    # another website. The location of the “//” in URL is computed. We find that if the URL starts with “HTTP”, that means the
    # “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.
    # If the "//" is anywhere in the URL apart from after the protocol, thee value assigned to this feature is -1 (phishing) or
    # else 1 (legitimate).
    def double_slash_redirecting():
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return -1
            else:
                return 1
        else:
            return 1

    # Checking the presence of '-' in the domain part of URL. The dash symbol is rarely used in legitimate URLs. Phishers tend to
    # add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage.
    # If the URL has '-' symbol in the domain part of the URL, the value assigned to this feature is -1 (phishing) or else 1 (legitimate).
    def Prefix_Suffix():
        if '-' in urlparse(url).netloc:
            return -1
        else:
            return 1

    # checking if the url has more than 3 subdomain. if the url has "." more than 3 times, then the value assigned to this feature is
    # -1 (phising) or elif 0 (suspicious) or else 1 (legitimate)
    def having_Sub_Domain():
        subdomain, domain, suffix = extract(url)
        if subdomain.count('.') == 0:
            return 1
        elif subdomain.count('.') == 1:
            return 0
        else:
            return -1

    # check if the URL holds a proper certificate from the trusted issuer
    # if the url has https and proper certificate then the feature is 1(legitimate), if url has https but no certificate then feature is 0(suspicous)
    # else -1 (phishing)
    def SSLfinal_State():
        try:
            # check whether it contain https or not
            if(re.search('^https',url)):
                usehttps = 1
            else:
                usehttps = 0

            # getting the certificate issuer to later compare with trusted issuer
            # getting host name
            subdomain, domain, suffix = extract(url)
            host_name = domain +"."+ suffix
            context = ssl.create_default_context()
            sct = context.wrap_socket(socket.socket(), server_hostname=host_name)
            sct.connect((host_name,443))
            certificate = sct.getpeercert()
            issuer = dict(x[0] for x in certificate['issuer'])
            certificate_auth = str(issuer['commonName'])
            certificate_auth = certificate_auth.split()
            if certificate_auth[0] == "Network" or certificate_auth == "Deutshe":
                certificate_auth = certificate_auth[0]+" "+certificate_auth[1]
            else:
                certificate_auth = certificate_auth[0]
            trusted_auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert',
                             'StartCom','Entrust','Verizon','Trustwave','Unizeto',
                             'Buypass','QuoVadis','Deutsche Telekom','Network Solutions',
                             'SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte',
                             'Doster','VeriSign']

            # getting age of certificate
            startingdate = str(certificate['notBefore'])
            endingdate = str(certificate['notAfter'])
            startingyear = int(startingdate.split()[3])
            endingyear = int(endingdate.split()[3])
            age_of_certification = endingyear - startingyear

            # checking final conditions
            if(usehttps == 1) and (certificate_auth in trusted_auth) and (age_of_certification >= 1):
                return 1
            elif(usehttps == 1) and (certificate_auth not in trusted_auth):
                return 0
            else:
                return -1
        except:
            return -1
     

    # check for how long the url's domain is registered. It also checks for the domain's creation date and expiration date
    # if the domain registration length is more then 6 years or has no date, the value assigned in feature is -1 (phishing)
    # if the domain registration length is less than 6 years, the value assigned in feature is 1 (legitimate)
    def Domain_registeration_length():
        try:
            w = whois.whois(url)
            updated = w.updated_date
            exp = w.expiration_date
            length = (exp[0]-updated).days
            if(length<=365):
                return -1
            else:
                return 1
        except:
            return -1

        
    # checks if the website has a proper icon or favicon which defines the genuinity of the website.
    # if icon is not present in website url then the feature is -1(phishing), else 1(legitimate)
    def favicon():
        try:
            icons = favicon.get(url)
            icon = icons[0]
            if icon in icons:
                return 1
            else:
                return -1
        except:
            return -1


    # checks if the https token doesn't exist on the domain part of the url as attackers tricks by doing so
    # if https token on domain part, the feature is -1(phishing), else 1(legitimate)
    def HTTPS_token():
        try:
            subdomain, domain, suffix = extract(url)
            host = subdomain+'.'+domain+'.'+suffix
            if(host.count('https')):
                return -1
            else:
                return 1
        except:
            return -1

    # examines whether the external objects contained within a webpage such as images, videos and sounds are loaded from another domain
    # if not then the feature is -1 (phishing) else 1(legitimate)
    def Request_URL():
        try:
            subDomain, domain, suffix = extract(url)
            websiteDomain = domain
            opener = urllib.request.urlopen(url).read()
            soup = BeautifulSoup(opener, 'lxml')
            imgs = soup.findAll('img', src=True)
            total = len(imgs)
            linked_to_same = 0
            avg = 0
            for image in imgs:
                subDomain, domain, suffix = extract(image['src'])
                imageDomain = domain
                if(websiteDomain==imageDomain or imageDomain==''):
                    linked_to_same = linked_to_same + 1
            vids = soup.findAll('video', src=True)
            total = total + len(vids)

            for video in vids:
                subDomain, domain, suffix = extract(video['src'])
                vidDomain = domain
                if(websiteDomain==vidDomain or vidDomain==''):
                    linked_to_same = linked_to_same + 1
            linked_outside = total-linked_to_same
            if(total!=0):
                avg = linked_outside/total
                
            if(avg<0.22):
                return 1
            else:
                return -1
        except:
            return -1

    # check if the </a><a> tags and the website have different domain names.
    def URL_of_Anchor():
        try:
            subDomain, domain, suffix = extract(url)
            websiteDomain = domain
            
            opener = urllib.request.urlopen(url).read()
            soup = BeautifulSoup(opener, 'lxml')
            anchors = soup.findAll('a', href=True)
            total = len(anchors)
            linked_to_same = 0
            avg = 0
            for anchor in anchors:
                subDomain, domain, suffix = extract(anchor['href'])
                anchorDomain = domain
                if(websiteDomain==anchorDomain or anchorDomain==''):
                    linked_to_same = linked_to_same + 1
            linked_outside = total-linked_to_same
            if(total!=0):
                avg = linked_outside/total
                
            if(avg<0.31):
                return 1
            elif(0.31<=avg<=0.67):
                return 0
            else:
                return -1
        except:
            return -1

    # Given that our investigation covers all angles likely to be used in the
    # webpage source code, we find that it is common for legitimate websites to use tags to offer metadata about the HTML document
    def Links_in_tags():
        try:
            opener = urllib.request.urlopen(url).read()
            soup = BeautifulSoup(opener, 'lxml')
            
            no_of_meta =0
            no_of_link =0
            no_of_script =0
            anchors=0
            avg =0
            for meta in soup.find_all('meta'):
                no_of_meta = no_of_meta+1
            for link in soup.find_all('link'):
                no_of_link = no_of_link +1
            for script in soup.find_all('script'):
                no_of_script = no_of_script+1
            for anchor in soup.find_all('a'):
                anchors = anchors+1
            total = no_of_meta + no_of_link + no_of_script+anchors
            tags = no_of_meta + no_of_link + no_of_script
            if(total!=0):
                avg = tags/total

            if(avg<0.25):
                return 1
            elif(0.25<=avg<=0.81):
                return 0
            else:
                return -1      
        except:        
            return -1
    

    # checks for HTTP status of the website
    def SFH():
        try:
            response = requests.get(url)
            res = response.status_code
            if res == 200 or (res <=300 and res >=308):
                return 1
            elif res>=400 and res <=500:
                return -1
            else:
                return 0
        except:
            return -1
    
    # A phisher might redirect the user’s information to his personal email. 
    # To that end, a server-side script language might be used such as “mail()” function in PHP. 
    def Submitting_to_email():
        try:
            opener = urllib.request.urlopen(url).read()
            soup = BeautifulSoup(opener, 'lxml')
            if(soup.find('mailto:')):
                return -1
            else:
                return 1
        except:
            return -1


    # checks how many times the URL website has been redirected to other website
    # if URL is redirected more than 2 times, the feature is -1(phishing), else 1(legitimate)
    def Redirect():
        try:
            response = requests.get(url)
            if response == "":
                return 0
            else:
                if len(response.history) <= 2:
                    return 1
                else:
                    return 0
        except:
            return -1
    
    # phishers use JavaScript to show fake URL on the status bar during the mouseover event
    # if the response is empty or mouseover is found, the feature is -1(phishing), else 1(legitimate)
    def on_mouseover():
        try:
            response = requests.get(url)
            if response == "":
                return 1
            else:
                if re.findall("<script>.+onmouseover.+</script>", response.text):
                    return -1
                else:
                    return 1
        except:
            return -1

    # checks if the right click is being blocked on the website.
    # If the right click event is empty or disabled on url, the feature is -1(phishing), else 1(legitimate)
    def RightClick():
        try:
            response = requests.get(url)
            if response == "":
                return 1
            else:
                if re.findall(r"event.button ?== ?2", response.text):
                    return -1
                else:
                    return 1
        except:
            return -1


    # IFrame is an HTML tag used to display an additional webpage into one that is currently shown.
    # Phishers can make use of the “iframe” tag and make it invisible
    # if Iframe is empty or response is not found, the feature is -1(phishing), else 1(legitimate)
    def Iframe():
        try:
            response = requests.get(url)
            if response.url == "":
                return -1
            else:
                if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                    return 1
                else:
                    return -1
        except:
            return -1
    
    # Most phishing websites live for a short period of time. By reviewing our dataset, 
    # we find that the minimum age of the legitimate domain is 6 months.
    def age_of_domain():
        try:
            w = whois.whois(url)
            start_date = w.creation_date
            current_date = datetime.now()
            age =(current_date-start_date).days
            if(age>=180):
                return 1
            else:
                return -1
        except:
            return -1

    # If the DNS record is empty or not found then the website is classified as -1(phishing) else 1(legitimate).
    def DNSRecord():
        try:
            domain_name = whois.whois(urlparse(url).netloc)
            if url in domain_name:
                return -1
            else:
                return 1
        except:
            return -1

    # checks if the URL is frequently visited by the users
    # if the URL is nut visited by users, it raises suspicions whether website should be trusted
    # the less the traffic, the feature is -1(phishing), elseif 0(suspicious), else 1(legitimate)
    def web_traffic():
        try:
            web = quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + web).read(), "xml").find("REACH")['RANK']
            rank = int(rank)
            if rank <= 30000:
                return 1
            elif rank >30000 and rank <=100000:
                return 0
            else:
                return -1
        except:
            return -1

    # check which rank the URL holds in Alexa page rank
    # the best rank given to the websites which are under 30000
    # if URL ranks is not below 30000, the feature is -1(phishing), else 1(legitimate)
    def Page_Rank():
        try:
            web = quote(url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + web).read(), "xml").find("REACH")['RANK']
            rank = int(rank)
            if rank <= 30000:
                return 1
            else:
                return -1
        except:
            return -1

    # This feature examines whether a website is in Google’s index or not. When a site is indexed by Google, it is displayed on search results.
    def Google_Index():
        try:
            web = requests.get("https://www.google.com/search?q="+url)
            soup = BeautifulSoup(web.text, 'html.parser')
            res = soup.select('div#main > div > div > div > a')
            if len(res) <= 2:
                return -1
            elif len(res) > 2 and len(res) < 5:
                return 0
            else:
                return 1
        except:
            return -1

    # The number of links pointing to the webpage indicates its legitimacy level, even if some links are of the same domain 
    def Links_pointing_to_page():
        try:
            web = requests.get(url)
            soup = BeautifulSoup(web.text,'lxml')
            links = soup.find_all('a',href=True)
            if len(links) <= 2:
                return -1
            elif len(links) > 2 and len(links) <= 10:
                return 0
            else:
                return 1
        except:
            return -1


 #[having_IPhaving_IP_Address,URLURL_Length,Shortining_Service,having_At_Symbol,double_slash_redirecting,Prefix_Suffix,having_Sub_Domain,
 # SSLfinal_State,Domain_registeration_length,Favicon,port,HTTPS_token,Request_URL,URL_of_Anchor,Links_in_tags,SFH,Submitting_to_email,
 # Abnormal_URL,Redirect,on_mouseover,RightClick,popUpWidnow,Iframe,age_of_domain,DNSRecord,web_traffic,Page_Rank,Google_Index,
 # Links_pointing_to_page,Statistical_report]




ls = [urlfeatures.having_IPhaving_IP_Address(),
urlfeatures.URLURL_Length(),
urlfeatures.Shortining_Service(),
urlfeatures.having_At_Symbol(),
urlfeatures.double_slash_redirecting(),
urlfeatures.Prefix_Suffix(),
urlfeatures.having_Sub_Domain(),
urlfeatures.SSLfinal_State(),
urlfeatures.Domain_registeration_length(),
urlfeatures.favicon(),
urlfeatures.HTTPS_token(),
urlfeatures.Request_URL(),
urlfeatures.URL_of_Anchor(),
urlfeatures.Links_in_tags(),
urlfeatures.SFH(),
urlfeatures.Submitting_to_email(),
urlfeatures.Redirect(),
urlfeatures.on_mouseover(),
urlfeatures.RightClick(),
urlfeatures.Iframe(),
urlfeatures.age_of_domain(),
urlfeatures.DNSRecord(),
urlfeatures.web_traffic(),
urlfeatures.Page_Rank(),
urlfeatures.Google_Index(),
urlfeatures.Links_pointing_to_page()]

print(ls)