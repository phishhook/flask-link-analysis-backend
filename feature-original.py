import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.query(self.domain)
        except:
            pass

        self.extract_features()

    def extract_features(self):
        # 1. NumDots
        self.features.append(self.NumDots())

        # 2. SubdomainLevel
        self.features.append(self.SubdomainLevel())

        # 3. PathLevel
        self.features.append(self.PathLevel())

        # 4. UrlLength
        self.features.append(self.UrlLength())

        # 5. NumDash
        self.features.append(self.NumDash())

        # 6. NumDashInHostname
        self.features.append(self.NumDashInHostname())

        # 7. AtSymbol
        self.features.append(self.AtSymbol())

        # 8. TildeSymbol
        self.features.append(self.TildeSymbol())

        # 9. NumUnderscore
        self.features.append(self.NumUnderscore())

        # 10. NumPercent
        self.features.append(self.NumPercent())

        # 11. NumQueryComponents
        self.features.append(self.NumQueryComponents())

        # 12. NumAmpersand
        self.features.append(self.NumAmpersand())

        # 13. NumHash
        self.features.append(self.NumHash())

        # 14. NumNumericChars
        self.features.append(self.NumNumericChars())

        # 15. NoHttps
        self.features.append(self.NoHttps())

        # 16. RandomString
        self.features.append(self.RandomString())

        # 17. IpAddress
        self.features.append(self.IpAddress())

        # 18. DomainInSubdomains
        self.features.append(self.DomainInSubdomains())

        # 19. DomainInPaths
        self.features.append(self.DomainInPaths())

        # 20. HttpsInHostname
        self.features.append(self.HttpsInHostname())

        # 21. HostnameLength
        self.features.append(self.HostnameLength())

        # 22. PathLength
        self.features.append(self.PathLength())

        # 23. QueryLength
        self.features.append(self.QueryLength())

        # 24. DoubleSlashInPath
        self.features.append(self.DoubleSlashInPath())

        # 25. NumSensitiveWords
        self.features.append(self.NumSensitiveWords())

        # 26. EmbeddedBrandName
        self.features.append(self.EmbeddedBrandName())

        # 27. PctExtHyperlinks
        self.features.append(self.PctExtHyperlinks())

        # 28. PctExtResourceUrls
        self.features.append(self.PctExtResourceUrls())

        # 29. ExtFavicon
        self.features.append(self.ExtFavicon())

        # 30. InsecureForms
        self.features.append(self.InsecureForms())

        # 31. RelativeFormAction
        self.features.append(self.RelativeFormAction())

        # 32. ExtFormAction
        self.features.append(self.ExtFormAction())

        # 33. AbnormalFormAction
        self.features.append(self.AbnormalFormAction())

        # 34. PctNullSelfRedirectHyperlinks
        self.features.append(self.PctNullSelfRedirectHyperlinks())

        # 35. FrequentDomainNameMismatch
        self.features.append(self.FrequentDomainNameMismatch())

        # 36. FakeLinkInStatusBar
        self.features.append(self.FakeLinkInStatusBar())

        # 37. RightClickDisabled
        self.features.append(self.RightClickDisabled())

        # 38. PopUpWindow
        self.features.append(self.PopUpWindow())

        # 39. SubmitInfoToEmail
        self.features.append(self.SubmitInfoToEmail())

        # 40. IframeOrFrame
        self.features.append(self.IframeOrFrame())

        # 41. MissingTitle
        self.features.append(self.MissingTitle())

        # 42. ImagesOnlyInForm
        self.features.append(self.ImagesOnlyInForm())

        # 43. SubdomainLevelRT
        self.features.append(self.SubdomainLevelRT())

        # 44. UrlLengthRT
        self.features.append(self.UrlLengthRT())

        # 45. PctExtResourceUrlsRT
        self.features.append(self.PctExtResourceUrlsRT())

        # 46. AbnormalExtFormActionR
        self.features.append(self.AbnormalExtFormActionR())

        # 47. ExtMetaScriptLinkRT
        self.features.append(self.ExtMetaScriptLinkRT())

        # 48. PctExtNullSelfRedirectHyperlinksRT
        self.features.append(self.PctExtNullSelfRedirectHyperlinksRT())

        # 1. NumDots
    def NumDots(self):
        try:
            return self.url.count('.')
        except:
            return 1

    # 2. SubdomainLevel
    def SubdomainLevel(self):
        try:
            subdomains = self.urlparse.netloc.split('.')
            return len(subdomains) - 2  # Subtract 2 to exclude the main domain and top-level domain
        except:
            return 0

    # 3. PathLevel
    def PathLevel(self):
        try:
            path = self.urlparse.path
            return path.count('/')
        except:
            return 0

    # 4. UrlLength
    def UrlLength(self):
        try:
            return len(self.url)
        except:
            return 0

    # 5. NumDash
    def NumDash(self):
        try:
            return self.url.count('-')
        except:
            return 0

    # 6. NumDashInHostname
    def NumDashInHostname(self):
        try:
            return self.urlparse.netloc.count('-')
        except:
            return 0

    # 7. AtSymbol
    def AtSymbol(self):
        try:
            if '@' in self.urlparse.netloc:
                return 1
            return 0
        except:
            return 0

    # 8. TildeSymbol
    def TildeSymbol(self):
        try:
            if '~' in self.urlparse.netloc:
                return 1
            return 0
        except:
            return 0

    # 9. NumUnderscore
    def NumUnderscore(self):
        try:
            return self.url.count('_')
        except:
            return 0

    # 10. NumPercent
    def NumPercent(self):
        try:
            return self.url.count('%')
        except:
            return 0

    # 11. NumQueryComponents
    def NumQueryComponents(self):
        try:
            query = self.urlparse.query
            components = query.split('&')
            return len(components)
        except:
            return 0

    # 12. NumAmpersand
    def NumAmpersand(self):
        try:
            return self.url.count('&')
        except:
            return 0

    # 13. NumHash
    def NumHash(self):
        try:
            return self.url.count('#')
        except:
            return 0

    # 14. NumNumericChars
    def NumNumericChars(self):
        try:
            return sum(c.isdigit() for c in self.url)
        except:
            return 0

    # 15. NoHttps
    def NoHttps(self):
        try:
            if self.urlparse.scheme == 'https':
                return 0
            return 1
        except:
            return 1

    # 16. RandomString
    def RandomString(self):
        try:
            url = self.url

            # Define a regular expression pattern to match random strings
            random_string_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

            # Search for random strings in the URL
            if re.search(random_string_pattern, url):
                return 1  # Random strings are found
            else:
                return 0  # No random strings found

        except:
            return -1

    # 17. IpAddress
    def IpAddress(self):
        try:
            ipaddress.ip_address(self.urlparse.netloc)
            return -1
        except:
            return 1

    # 18. DomainInSubdomains
    def DomainInSubdomains(self):
        try:
            if self.domain in self.urlparse.netloc:
                return -1
            return 1
        except:
            return -1

    # 19. DomainInPaths
    def DomainInPaths(self):
        try:
            if self.domain in self.urlparse.path:
                return -1
            return 1
        except:
            return -1

    # 20. HttpsInHostname
    def HttpsInHostname(self):
        try:
            if 'https' in self.urlparse.netloc:
                return -1
            return 1
        except:
            return -1

    # 21. HostnameLength
    def HostnameLength(self):
        try:
            return len(self.urlparse.netloc)
        except:
            return -1

    # 22. PathLength
    def PathLength(self):
        try:
            return len(self.urlparse.path)
        except:
            return -1

    # 23. QueryLength
    def QueryLength(self):
        try:
            return len(self.urlparse.query)
        except:
            return -1

    # 24. DoubleSlashInPath
    def DoubleSlashInPath(self):
        try:
            if '//' in self.urlparse.path:
                return -1
            return 1
        except:
            return -1

    # 25. NumSensitiveWords
    def NumSensitiveWords(self):
        try:
            # Implement your logic to detect sensitive words here
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 26. EmbeddedBrandName
    def EmbeddedBrandName(self):
        try:
            # Implement your logic to detect embedded brand names here
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 27. PctExtHyperlinks
    def PctExtHyperlinks(self):
        try:
            # Implement your logic to calculate the percentage of external hyperlinks here
            # Return -1 if certain conditions are met, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 28. PctExtResourceUrls
    def PctExtResourceUrls(self):
        try:
            # Implement your logic to calculate the percentage of external resource URLs here
            # Return -1 if certain conditions are met, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 29. ExtFavicon
    def ExtFavicon(self):
        try:
            # Implement your logic to detect the presence of an external favicon
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 30. InsecureForms
    def InsecureForms(self):
        try:
            for form in self.soup.find_all('form', action=True):
                if not form['action'].startswith('https://') and not form['action'].startswith('data:'):
                    return -1
            return 1
        except:
            return -1

    # 31. RelativeFormAction
    def RelativeFormAction(self):
        try:
            for form in self.soup.find_all('form', action=True):
                if not form['action'].startswith('http://') and not form['action'].startswith('https://'):
                    return -1
            return 1
        except:
            return -1

    # 32. ExtFormAction
    def ExtFormAction(self):
        try:
            for form in self.soup.find_all('form', action=True):
                if form['action'].startswith('http://') or form['action'].startswith('https://'):
                    return -1
            return 1
        except:
            return -1

    # 33. AbnormalFormAction
    def AbnormalFormAction(self):
        try:
            for form in self.soup.find_all('form', action=True):
                action_url = form['action'].lower()
                if 'javascript:' in action_url or 'data:' in action_url or 'mailto:' in action_url:
                    return -1
            return 1
        except:
            return -1

    # 34. PctNullSelfRedirectHyperlinks
    def PctNullSelfRedirectHyperlinks(self):
        try:
            # Implement your logic to calculate the percentage of null self-redirect hyperlinks
            # Return -1 if certain conditions are met, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 35. FrequentDomainNameMismatch
    def FrequentDomainNameMismatch(self):
        try:
            # Implement your logic to detect frequent domain name mismatches
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 36. FakeLinkInStatusBar
    def FakeLinkInStatusBar(self):
        try:
            # Implement your logic to detect fake links in the status bar
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 37. RightClickDisabled
    def RightClickDisabled(self):
        try:
            # Implement your logic to detect right-click disabled on the webpage
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 38. PopUpWindow
    def PopUpWindow(self):
        try:
            # Implement your logic to detect the presence of pop-up windows
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 39. SubmitInfoToEmail
    def SubmitInfoToEmail(self):
        try:
            # Implement your logic to detect the submission of information to an email
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 40. IframeOrFrame
    def IframeOrFrame(self):
        try:
            # Implement your logic to detect iframes or frames
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 41. MissingTitle
    def MissingTitle(self):
        try:
            title = self.soup.find('title')
            if not title or not title.string:
                return -1
            return 1
        except:
            return -1

    # 42. ImagesOnlyInForm
    def ImagesOnlyInForm(self):
        try:
            # Implement your logic to detect if images are only found within forms
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 43. SubdomainLevelRT
    def SubdomainLevelRT(self):
        try:
            # Implement your logic to detect a change in subdomain level
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 44. UrlLengthRT
    def UrlLengthRT(self):
        try:
            # Implement your logic to detect a change in URL length
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 45. PctExtResourceUrlsRT
    def PctExtResourceUrlsRT(self):
        try:
            # Implement your logic to detect a change in the percentage of external resource URLs
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 46. AbnormalExtFormActionR
    def AbnormalExtFormActionR(self):
        try:
            # Implement your logic to detect abnormal external form actions
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 47. ExtMetaScriptLinkRT
    def ExtMetaScriptLinkRT(self):
        try:
            # Implement your logic to detect a change in the number of external meta, script, and link tags
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1

    # 48. PctExtNullSelfRedirectHyperlinksRT
    def PctExtNullSelfRedirectHyperlinksRT(self):
        try:
            # Implement your logic to detect a change in the percentage of external null self-redirect hyperlinks
            # Return -1 if detected, 1 otherwise
            return -1  # Placeholder, implement your logic
        except:
            return -1


    # Implement other feature extraction methods using a similar structure

    def getFeaturesList(self):
        return self.features
