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
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument('--headless')
            driver = webdriver.Chrome(options=options)

            # Open the URL in the browser
            driver.get(url)

            # Wait until the page has fully loaded and the URL has stabilized
            WebDriverWait(driver, 10)

            # Detect Cloudflare challenge
            driver = self.detect_cloudflare_challenge(driver)
            if driver is None:
                return None

            # Use JavaScript to get the final URL
            final_url = driver.execute_script("return window.location.href;")

            self.url = final_url

            # Set a timeout for getting the page source
            fully_rendered_html = WebDriverWait(driver, 10).until(
                lambda x: x.page_source
            )
            self.soup = BeautifulSoup(fully_rendered_html, 'html.parser')
            driver.quit()

            self.response = requests.get(self.url, timeout=15)  # Set timeout to 15 seconds
            if not self.response or not self.response .status_code == 200 or not self.response.content not in ["b''", "b' '"]:
                return None

        except Exception as e:
            driver.quit()
            return None
        
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.query(self.domain)
        except Exception as e:
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
                
    def detect_cloudflare_challenge(self, driver):
        try:
            # Check if the Cloudflare security challenge iframe is present
            iframe_present = EC.presence_of_element_located((By.CSS_SELECTOR, "iframe[title='Widget containing a Cloudflare security challenge']"))
            WebDriverWait(driver, 3).until(iframe_present)
            
            # If the iframe is present, return None to indicate a Cloudflare security challenge
            return None
        except Exception as e:
            # If an exception occurs or the iframe is not present, continue with the normal flow
            return driver

    #1
    def UsingIP(self):
        try: 
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
                '[0-9a-fA-F]{7}', self.url)  # Ipv6
            if match:
                return -1
            else:
                return 1
        except:
            return -1
        
    #2
    def LongURL(self):
        try:
            url_length = len(self.url)
            if url_length < 54:
                return 1
            elif 54 <= url_length <= 75:
                return 0
            else:
                return -1
        except:
            return -1
            
    #3
    def ShortURL(self):
        try:
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
                return -1
            return 1
        except:
            return -1

    #4
    def Symbol_(self): 
        try:
            if '@' in self.url:
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            return -1
        
    #5
    def Redirecting_(self):
        try: 
            double_slash_position = self.url.rfind('//')
            if double_slash_position > 6:
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            return -1
        
    #6
    def PrefixSuffix_(self):
        try:
            match = re.findall('\-', self.url)
            if match:
                return -1
            return 1
        except:
            return -1
    #7
    def SubDomains(self):
        try: 
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

            if num_dots == 0:
                return 1  # Legitimate
            elif num_dots == 1:
                return 0  # Suspicious
            else:
                return -1  # Phishing
        except:
            return -1
    #8
    def HTTPS(self):
        # Check if the URL starts with 'https://'
        try: 
            if self.url.startswith('https://') and self.originalurl.startswith('https://'):
                return 1

            return -1  # Phishing if not using HTTPS
        except:
            return -1


    #9
    def DomainRegLen(self):
        try:
            # Assuming you have access to the domain registration information
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            age = (expiration_date.year-creation_date.year)*12 + (expiration_date.month-creation_date.month)

            if age <= 12:
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            # Handle exceptions if the domain registration information is not available
            return -1 # Suspicious

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
        try: 
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1


    #12 
    def HTTPSDomainURL(self):
        try: 
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            if "https" in self.domain:
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            -1
    
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
                    return -1  # Phishing

            return 0  # Suspicious (total_objects is zero)
        except Exception as e:
            return -1  # Phishing (Error or exception)


    #14
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1


            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1
        except Exception as e:
            return -1

    #15
    def LinksInScriptTags(self):
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

                if percentage < 17:
                    return 1  # Legitimate
                elif 17 <= percentage <= 81:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing

            return 0  # Suspicious (total_tags is zero)
        except Exception as e:
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
                    return -1  # Phishing

                # Check if the action domain is different from the main domain
                action_domain = urlparse(action).netloc
                if action_domain != self.domain:
                    return 0  # Suspicious

            return 1  # Legitimate

        except Exception as e:
            return -1  # Suspicious (Error or exception)


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
            # Check if the host name is not included in the URL
            if host_name not in self.url:
                return -1  # Phishing
            else:
                return 1  # Legitimate
        except:
            return -1
        
    #19
    def WebsiteForwarding(self):
        try:
            # Assuming you have access to the HTTP response object
            if self.url != self.originalurl:
                return -1
            
            if self.response:
                # Get the number of redirects
                num_redirects = len(self.response.history)

                if num_redirects <= 1:
                    return 1  # Legitimate
                elif 2 <= num_redirects < 4:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing

            return -1  # Suspicious (No HTTP response available)

        except Exception as e:
            return -1  # Suspicious (Error or exception)
        
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
                        return -1  # Phishing

                return 1  # Legitimate

            return -1  # Suspicious (No HTML content available)

        except Exception as e:
            return -1  # Suspicious (Error or exception)    
        
     # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            # Convert BeautifulSoup object to string
            html_content = str(self.soup)

            # Search for the pattern "event.button==2" in the HTML content
            pattern = re.compile(r"event.button ?== ?2", re.IGNORECASE)
            match = pattern.search(html_content)

            # If the pattern is found, right-click is disabled (Phishing)
            if match:
                return -1
            else:
                return 1  # Right-click is not disabled (Legitimate)

        except Exception as e:
            return -1  # Return False in case of an error or exception


    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_argument('--headless')
            driver = webdriver.Chrome(options=options)            
            driver.get(self.url)


            # Wait for a certain amount of time (e.g., 10 seconds) for the pop-up to appear
            WebDriverWait(driver, 20)

            # Check if there are multiple windows open
            window_handles = driver.window_handles
            if len(window_handles) > 1:

                # Switch to the pop-up window
                driver.switch_to.window(window_handles[1])

                # Check if the pop-up has text inputs
                text_inputs = driver.find_elements_by_css_selector('input[type="text"]')
                driver.quit()
                if text_inputs:
                    return -1

                return -1  # Pop-ups detected, but no text inputs found
            
            if re.findall(r"alert\(", self.response.text):
                return -1

            return 1  # No pop-ups detected
        except Exception as e:
            return -1  # Suspicious (Error or exception)

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
                        return -1  # Phishing (Iframe redirection with invisible frame borders)

                return 1  # Legitimate

            return 0  # Suspicious (No HTML content available)

        except Exception as e:
            return 0  # Suspicious (Error or exception)

    #24
    def AgeofDomain(self):
        try:
            # Assuming you have access to the domain registration information
            creation_date = self.whois_response.creation_date

            if creation_date:
                # Calculate the age of the domain in months
                age_in_months = (datetime.now() - creation_date).days / 30

                if age_in_months >= 6:
                    return 1  # Legitimate
                else:
                    return -1  # Phishing
                
            return -1
        except Exception as e:
            return -1  # Suspicious (Error or exception)
        

    #25
    def DNSRecording(self):
        try:
            self.domain = self.urlparse.netloc
            domain_without_www = self.domain.replace('www.', '')
            nameservers = dns.resolver.resolve(domain_without_www,'NS')
            if len(nameservers)>0:
                return 1
            else:
                return -1
        except Exception as e:
            return -1  # Suspicious (Error or exception)
        

    #26
    def WebsiteTraffic(self):
        api_key = config.API_KEY
        try:


            url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + self.domain

            request = requests.get(url, headers={'API-OPR':api_key})
            result = request.json()
            latest_rank = int(result['response'][0]['rank'])

            if latest_rank is not None and latest_rank < 10000:
                return 1  # Legitimate
            elif latest_rank is not None and latest_rank >= 10000:
                return -1  # Suspicious

        except Exception as e:
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

                if page_rank_integer >= 5:
                    return 1
            return -1
        except:
            return -1
        
    # 28
    def GoogleIndex(self):
        try: 
            google = "https://www.google.com/search?q=site:" + self.url + "&hl=en"
            response = requests.get(google, cookies={"CONSENT": "YES+1"})
            soup = BeautifulSoup(response.content, "html.parser")
            not_indexed = re.compile("did not match any documents")

            if soup(text=not_indexed):
                return -1
            else:
                return 1
        except:
            return -1
        
    #29
    def LinksPointingToPage(self):
        try:
            # Find all <a> tags with an 'href' attribute
            links = self.soup.find_all('a', href=True)

            # Get the domain of the current URL
            current_domain = urlparse(self.url).netloc

            # Filter links pointing to the same domain
            same_domain_links = [link['href'] for link in links if urlparse(link['href']).netloc == current_domain]

            # Get the count of links pointing to the same domain
            same_domain_links_count = len(same_domain_links)

            if same_domain_links_count == 0:
                return -1  # Phishing
            elif 0 < same_domain_links_count <= 2:
                return 0  # Suspicious
            else:
                return 1  # Legitimate
        except Exception as e:
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
            return -1
        
    def getFeaturesList(self):
        return self.features