import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
import config
from urllib.parse import urljoin
import dns.resolver
from alexa_siterank import *
import config
import requests
from bs4 import BeautifulSoup
from urllib.parse import unquote
from html import unescape
from selenium import webdriver
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class FeatureExtraction:
    features = []
    feature_labels = ['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//',
                      'PrefixSuffix-', 'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon',
                      'NonStdPort', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL',
                      'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'AbnormalURL',
                      'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
                      'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
                      'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage',
                      'StatsReport']
    def __init__(self,url):
        self.originalurl = url
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            # Set up a headless browser (you may need to download the appropriate driver)
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            driver = webdriver.Chrome(options=options)

            # Open the URL in the browser
            driver.get(url)

            # Wait until the page has fully loaded and the URL has stabilized
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )

            # Use JavaScript to get the final URL
            final_url = driver.execute_script("return window.location.href;")
            print("Final URL (Selenium):", final_url)            

            self.url = final_url

            # Set a timeout for getting the page source
            fully_rendered_html = WebDriverWait(driver, 10).until(
                lambda x: x.page_source
            )
            self.soup = BeautifulSoup(fully_rendered_html, 'html.parser')

            self.response = requests.get(self.url, timeout=15)  # Set timeout to 15 seconds
            if not self.response or not self.response .status_code == 200 or not self.response.content not in ["b''", "b' '"]:
                return None

        except Exception as e:
            print(f"Error: {e}")
            return None
        
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.query(self.domain)
        except:
            pass

        self.populate_features()


    def populate_features(self):
        for label in self.feature_labels:
            # Convert label to lowercase and replace special characters with underscores
            method_name = label.replace('@', '_').replace('//', '_').replace('-', '_')

            # Get the method using the modified name
            method = getattr(self, method_name, None)

            if method is not None and callable(method):
                self.features.append(method())


    #1
    def UsingIP(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '[0-9a-fA-F]{7}', self.url)  # Ipv6
        if match:
            print("Phishing 1")
            return -1
        else:
            return 1
        
    #2
    def LongURL(self):
        url_length = len(self.url)

        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        else:
            print("Phishing 2")
            return -1
        
    #3
    def ShortURL(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        self.url)       
        if match:
            print("Phishing 3")
            return -1
        return 1

    #4
    def Symbol_(self): 
        if '@' in self.url:
            print("Phishing 4")
            return -1  # Phishing
        else:
            return 1  # Legitimate
        
    #5
    def Redirecting_(self):
        double_slash_position = self.url.rfind('//')

        if double_slash_position > 6:
            print("Phishing 5")
            return -1  # Phishing
        else:
            return 1  # Legitimate
        
    #6
    def PrefixSuffix_(self):
        try:
            match = re.findall('\-', self.url)
            if match:
                return -1
            return 1
        except:
            return 
    #7
    def SubDomains(self):
        # Remove 'www.' if it exists
        self.urlparse = urlparse(self.url)
        self.domain = self.urlparse.netloc
        domain_without_www = self.domain.replace('www.', '')

        # Remove country-code top-level domain (ccTLD) if it exists
        parts = domain_without_www.split('.')
        if len(parts) > 1:
            ccTLD = parts[-1]
            if ccTLD.isalpha() and len(ccTLD) <= 4:  # Assuming ccTLD is alphabetical and has at most 4 characters
                domain_without_www = '.'.join(parts[:-1])

        # Count the remaining dots
        num_dots = domain_without_www.count('.')

        if num_dots <= 1:
            return 1  # Legitimate
        elif num_dots == 2:
            return 0  # Suspicious
        else:
            print("Phishing 7")
            return -1  # Phishing

    #8
    def HTTPS(self):
        # Check if the URL starts with 'https://'
        if self.url.startswith('https://') and self.originalurl.startswith('https://'):
            print("HTTPS???")
            return 1

        print("Phishing 8")
        return -1  # Phishing if not using HTTPS


    #9
    def DomainRegLen(self):
        try:
            # Assuming you have access to the domain registration information
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            age = (expiration_date.year-creation_date.year)*12 + (expiration_date.month-creation_date.month)
            print(age)

            if age <= 12:
                print("Phishing 9")
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            # Handle exceptions if the domain registration information is not available
            return 0  # Suspicious

    #10
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1


    #11 
    def NonStdPort(self):
        self.urlparse = urlparse(self.url)
        self.domain = self.urlparse.netloc
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1



    #12 
    def HTTPSDomainURL(self):
        self.urlparse = urlparse(self.url)
        self.domain = self.urlparse.netloc
        if "https" in self.domain:
            print("Phishing 12")
            return -1  # Phishing
        else:
            return 1  # Legitimate
        
    
    #13    
    def RequestURL(self):
        try:
            total_objects = 0
            external_objects = 0

            # Check for external objects in the webpage (e.g., images, videos, sounds)
            for tag in self.soup.find_all(['img', 'video', 'audio', 'source', 'script']):
                total_objects += 1
                src = tag.get('src', None)
                if src and urlparse(src).netloc != self.domain:
                    external_objects += 1


            print("total_objects", total_objects)
            # Check for external objects in the stylesheets and scripts
            for tag in self.soup.find_all(['link']):
                total_objects += 1
                href =tag.get('href', None)
                if href and urlparse(href).netloc != self.domain:
                    external_objects += 1

            # Calculate the percentage of external objects
            if total_objects > 0:
                percentage = (external_objects / total_objects) * 100

                if percentage < 22:
                    return 1  # Legitimate
                elif 22 <= percentage <= 61:
                    return 0  # Suspicious
                else:
                    print("Phishing 13")
                    return -1  # Phishing

            return 0  # Suspicious (total_objects is zero)
        except Exception as e:
            print(f"Error in RequestURL check: {e}")
            return -1  # Phishing (Error or exception)


    #14
    def AnchorURL(self):
        try:
            total_anchors = 0
            different_domain_anchors = 0
            empty_page_anchors = 0

            # Check for anchor tags in the webpage
            for tag in self.soup.find_all('a', href=True):
                total_anchors += 1
                href = tag.get('href', None)

                # Check if the anchor links to a different domain
                if href and urlparse(href).netloc != self.domain:
                    different_domain_anchors += 1

                # Check if the anchor does not link to any webpage
                if not href or href.startswith(('#', 'JavaScript:')):
                    empty_page_anchors += 1

            # Calculate the percentage of anchors linking to a different domain
            if total_anchors > 0:
                percentage = (different_domain_anchors / total_anchors) * 100

                if percentage < 31:
                    return 1  # Legitimate
                elif 31 <= percentage <= 67 or empty_page_anchors == total_anchors:
                    return 0  # Suspicious
                else:
                    print("Phishing 14")
                    return -1  # Phishing

            return 0  # Suspicious (total_anchors is zero)
        except Exception as e:
            print(f"Error in AnchorURL check: {e}")
            return -1  # Phishing (Error or exception)

    #15
    def LinksInScriptTags(self):
        print("LinksInScriptTags")
        try:
            total_tags = 0
            total_links = 0

            # Check for links in Meta, Script, and Link tags in the webpage
            for tag_name in ['meta', 'script', 'link']:
                for tag in self.soup.find_all(tag_name):
                    total_tags += 1
                    href = tag.get('href', '') if tag_name == 'link' else tag.get('content', '')

                    # Check if the link is not empty and links to the same domain
                    if href and urlparse(href).netloc == self.domain:
                        total_links += 1

            # Calculate the percentage of links in Meta, Script, and Link tags
            if total_tags > 0:
                percentage = (total_links / total_tags) * 100
                print("PERCENTAGE!!!", percentage)

                if percentage < 17:
                    return 1  # Legitimate
                elif 17 <= percentage <= 81:
                    return 0  # Suspicious
                else:
                    print("Phishing 15")
                    return -1  # Phishing

            return 0  # Suspicious (total_tags is zero)
        except Exception as e:
            print(f"Error in LinksInScriptTags check: {e}")
            return -1  # Phishing (Error or exception)


    #16
    def ServerFormHandler(self):
        try:
            # Assuming you have access to the HTML content of the webpage
            forms = self.soup.find_all('form')

            for form in forms:
                action = form.get('action', '').lower()

                # Check for "about:blank" or empty action
                if action == '' or action == 'about:blank':
                    print("Phishing 16")
                    return -1  # Phishing

                # Check if the action domain is different from the main domain
                action_domain = urlparse(action).netloc
                if action_domain != self.domain:
                    return 0  # Suspicious

            return 1  # Legitimate

        except Exception as e:
            print(f"Error in SFH check: {e}")
            return 0  # Suspicious (Error or exception)


    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soup):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            # Extract the host name from the URL
            host_name = self.urlparse.hostname
            print("HOSTNAME: ", host_name)
            # Check if the host name is not included in the URL
            if host_name not in self.url:
                print("Phishing 6")
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            return 0
        
    #19
    def WebsiteForwarding(self):
        try:
            # Assuming you have access to the HTTP response object
            if self.response:
                # Get the number of redirects
                num_redirects = len(self.response.history)

                if num_redirects <= 1:
                    return 1  # Legitimate
                elif 2 <= num_redirects < 4:
                    return 0  # Suspicious
                else:
                    print("Phishing 19")
                    return -1  # Phishing

            return 0  # Suspicious (No HTTP response available)

        except Exception as e:
            print(f"Error in WebsiteForwarding: {e}")
            return 0  # Suspicious (Error or exception)
        
    #20
    def StatusBarCust(self):
        try:
            # Assuming you have access to the HTML content of the webpage
            if self.soup:
                # Search for onMouseOver event in the source code
                onMouseOver_elements = self.soup.find_all(onmouseover=True)

                for element in onMouseOver_elements:
                    # Check if onMouseOver changes the status bar
                    if "window.status" in str(element.get('onmouseover')):
                        print("Phishing 20")
                        return -1  # Phishing

                return 1  # Legitimate

            return 0  # Suspicious (No HTML content available)

        except Exception as e:
            print(f"Error in StatusBarCust: {e}")
            return 0  # Suspicious (Error or exception)    
        
     # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            # Assuming you have access to the HTML content of the webpage
            if self.soup:
                # Search for event.button==2 condition in the source code
                disable_right_click_elements = self.soup.find_all(
                    lambda tag: tag.has_attr('oncontextmenu') and 'event.button==2' in tag['oncontextmenu']
                )

                if disable_right_click_elements:
                    print("Phishing 21")
                    return -1  # Phishing (Right click disabled)

                return 1  # Legitimate

            return 0  # Suspicious (No HTML content available)

        except Exception as e:
            print(f"Error in DisableRightClick: {e}")
            return 0  # Suspicious (Error or exception)

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            # Assuming you have access to the HTML content of the webpage
            if self.soup:
                # Search for input elements within pop-up windows
                pop_up_elements = self.soup.find_all(lambda tag: 'window.open' in str(tag))

                print("POP UP 1")

                for pop_up_element in pop_up_elements:
                    # Check if the pop-up window contains text fields (input elements)
                    print("POP UP")
                    text_fields = pop_up_element.find_all('input', {'type': 'text'})

                    if text_fields:
                        print("Phishing 22")
                        return -1  # Phishing (Pop-up window contains text fields)

                return 1  # Legitimate

            return 0  # Suspicious (No HTML content available)

        except Exception as e:
            print(f"Error in UsingPopupWindow: {e}")
            return 0  # Suspicious (Error or exception)

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            # Assuming you have access to the HTML content of the webpage
            if self.soup:
                # Search for iframe elements
                iframe_elements = self.soup.find_all('iframe')

                for iframe_element in iframe_elements:
                    # Check if the iframe has the "frameBorder" attribute set to 0 or "no"
                    frame_border = iframe_element.get('frameborder', '').lower()
                    if frame_border == '0' or frame_border == 'no':
                        print("Phishing 23")
                        return -1  # Phishing (Iframe redirection with invisible frame borders)

                return 1  # Legitimate

            return 0  # Suspicious (No HTML content available)

        except Exception as e:
            print(f"Error in IframeRedirection: {e}")
            return 0  # Suspicious (Error or exception)

    #24
    def AgeofDomain(self):
        try:
            # Assuming you have access to the domain registration information
            creation_date = self.whois_response.creation_date

            if creation_date:
                # Calculate the age of the domain in months
                age_in_months = (datetime.now() - creation_date).days / 30
                print("AGE", age_in_months)

                if age_in_months >= 6:
                    return 1  # Legitimate
                else:
                    print("Phishing 24")
                    return -1  # Phishing

            return 0  # Suspicious (No creation date available)

        except Exception as e:
            print(f"Error in AgeofDomain: {e}")
            return 0  # Suspicious (Error or exception)
        

    #25
    def DNSRecording(self):
        try:
            nameservers = dns.resolver.resolve(self.domain,'NS')
            if len(nameservers)>0:
                return 1
            else:
                print("Phishing 25")
                return -1
        except:
            return 0


    #26
    def WebsiteTraffic(self):
        api_key = config.API_KEY
        try:


            url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + self.domain

            request = requests.get(url, headers={'API-OPR':api_key})
            print("req", request)
            result = request.json()
            latest_rank = int(result['response'][0]['rank'])
            print("Latest", latest_rank)

            if latest_rank is not None and latest_rank < 10000:
                return 1  # Legitimate
            elif latest_rank is not None and latest_rank >= 10000:
                return 0  # Suspicious
            else:
                print("Phishing 26")
                return -1  # Phishing (No rank information)

        except Exception as e:
            print(f"Error in PageRank: {e}")
            return -1  # Phishing (Error or exception)
        
    #27
    def PageRank(self):
        api_key = config.API_KEY
        try:
            # Define the API endpoint and parameters
            url = 'https://openpagerank.com/api/v1.0/getPageRank'
            params = {
                'domains[]': [self.domain]
            }

            # Set your API key in the request headers
            headers = {
                'API-OPR': api_key
            }

            # Make the HTTP GET request
            response = requests.get(url, params=params, headers=headers)
            #Check if the request was successful
            if response.status_code == 200:
                data = response.json()

                # If the domain is not found then there will be no page_rank_integer
                # and an exception will be thrown - this is the expeceted behaviour
                page_rank_integer = data['response'][0]['page_rank_integer']
                #print("Page rank " , page_rank_integer)

                if page_rank_integer >= 5:
                    return 1
            print("Phishing 27")
            return -1
        except:
            print("Phishing 27")
            return -1
        
    # 28
    def GoogleIndex(self):
        google = "https://www.google.com/search?q=site:" + self.url + "&hl=en"
        response = requests.get(google, cookies={"CONSENT": "YES+1"})
        soup = BeautifulSoup(response.content, "html.parser")
        not_indexed = re.compile("did not match any documents")

        if soup(text=not_indexed):
            print("Phishing 28")
            return -1
        else:
            ##print("This page is indexed by Google.")
            return 1
        
    #29
    def LinksPointingToPage(self):
        try:

            # Find all <a> tags with an 'href' attribute
            links = self.soup.find_all('a', href=True)

            # Filter external links by checking if they have a different domain
            external_links = [link['href'] for link in links if self.domain not in link['href']]

            # Get the count of external links
            external_links_count = len(external_links)

            if external_links_count == 0:
                return 1
            elif external_links_count <= 2:
                return 0
            else:
                print("Phishing 29")
                print(external_links_count)
                return -1
        except Exception as e:
            print(f"Error fetching or parsing HTML: {e}")
            return -1
        
    # 30
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
        
    def getFeaturesList(self):
        return self.features