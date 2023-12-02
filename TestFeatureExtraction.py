import unittest
from unittest.mock import Mock, create_autospec, patch
from urllib.parse import urlparse
from feature2 import FeatureExtraction
from bs4 import BeautifulSoup
from selenium.webdriver.remote.webelement import WebElement
from datetime import datetime, timedelta



class TestFeatureExtraction(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass


    def test_UsingIP_false(self):
        feature_extraction = FeatureExtraction("https://www.wisc.edu/")
        result = feature_extraction.UsingIP()
        self.assertEqual(result, 1)  


    def test_UsingIP_true(self):
        feature_extraction = FeatureExtraction("http://125.98.3.123/fake.html")
        result = feature_extraction.UsingIP()
        self.assertEqual(result, -1)  


    def test_LongURL_Short(self):
        # Test case for a short URL
        feature_extraction = FeatureExtraction("http://example.com")
        result = feature_extraction.LongURL()
        self.assertEqual(result, 1)

    def test_LongURL_Medium(self):
        # Test case for a medium-length URL
        medium_length_url = "http://example.com/" + "a" * 56  # Adjust the length as needed
        feature_extraction = FeatureExtraction(medium_length_url)
        result = feature_extraction.LongURL()
        self.assertEqual(result, 0)

    def test_LongURL_Long(self):
        # Test case for a long URL
        long_url = "http://example.com/" + "a" * 80  # Adjust the length as needed
        feature_extraction = FeatureExtraction(long_url)
        result = feature_extraction.LongURL()
        self.assertEqual(result, -1)

    def test_ShortURL_NotShort(self):
        # Test case for a URL that is not considered short
        feature_extraction = FeatureExtraction("http://example.com")
        result = feature_extraction.ShortURL()
        self.assertEqual(result, 1)


    def test_ShortURL_OtherShort(self):
        # Test case for another type of short URL
        other_short_url = "http://bit.ly/19DXSk4/"  # Replace with an actual short URL
        feature_extraction = FeatureExtraction(other_short_url)
        result = feature_extraction.ShortURL()
        self.assertEqual(result, -1)

    def test_Symbol_NoSymbol(self):
        # Test case for a URL without the '@' symbol
        feature_extraction = FeatureExtraction("http://example.com")
        result = feature_extraction.Symbol_()
        self.assertEqual(result, 1)

    def test_Symbol_WithSymbol(self):
        # Test case for a URL with the '@' symbol
        phishing_url = "http://example@phishing.com"  # Replace with an actual phishing URL
        feature_extraction = FeatureExtraction(phishing_url)
        result = feature_extraction.Symbol_()
        self.assertEqual(result, -1)

    def test_Redirecting_NoRedirect(self):
        # Test case for a URL without excessive double slashes
        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.Redirecting_()
        self.assertEqual(result, 1)

    def test_Redirecting_WithRedirect(self):
        # Test case for a URL with excessive double slashes
        phishing_url = "http://example.com/path//to//phishing"  # Replace with an actual phishing URL
        feature_extraction = FeatureExtraction(phishing_url)
        result = feature_extraction.Redirecting_()
        self.assertEqual(result, -1)

    def test_PrefixSuffix_NoDash(self):
        # Test case for a URL without a dash in the domain
        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.PrefixSuffix_()
        self.assertEqual(result, 1)

    def test_PrefixSuffix_WithDash(self):
        # Test case for a URL with a dash in the domain
        phishing_url = "http://phishing-example.com"  # Replace with an actual phishing URL
        feature_extraction = FeatureExtraction(phishing_url)
        result = feature_extraction.PrefixSuffix_()
        self.assertEqual(result, -1)

    def test_SubDomains_Legitimate(self):
        # Test case for a legitimate URL with one subdomain
        legitimate_url = "http://phishing-example.com"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.SubDomains()
        self.assertEqual(result, 1)

    def test_SubDomains_Suspicious(self):
        # Test case for a suspicious URL with two subdomains
        suspicious_url = "http://sub1.sub2.example.com"
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.SubDomains()
        self.assertEqual(result, 0)

    def test_SubDomains_Phishing(self):
        # Test case for a phishing URL with more than two subdomains
        phishing_url = "http://sub1.sub2.sub3.example.com"  # Replace with an actual phishing URL
        feature_extraction = FeatureExtraction(phishing_url)
        result = feature_extraction.SubDomains()
        self.assertEqual(result, -1)
    
    def test_HTTPS_test_Legitimate(self):
        legitimate_url = "https://phishing-example.com"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.HTTPS()
        self.assertEqual(result, 1)

    def test_HTTPS_test_Phishing(self):
        suspicious_url = "http://phishing-example.com"
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.HTTPS()
        self.assertEqual(result, -1)

    def test_DomainRegLen_test_Legitimate(self):
        legitimate_url = "https://www.wisc.edu/"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.DomainRegLen()
        self.assertEqual(result, 1)

    def test_DomainRegLen_test_Phishing(self):
        suspicious_url = "https://meta-community.link/meta-community-standard"
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.DomainRegLen()
        self.assertEqual(result, -1)

    def test_Favicon_test_Legitimate(self):
        legitimate_url = "https://www.wisc.edu/"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.Favicon()
        self.assertEqual(result, 1)

    def test_Favicon_test_Phishing(self):
        suspicious_url = "https://meta-community.link/meta-community-standard"
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.Favicon()
        ##self.assertEqual(result, -1)

    def test_NonStdPort_test_Legitimate(self):
        legitimate_url = "https://www.wisc.edu/"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.NonStdPort()
        self.assertEqual(result, 1)

    def test_NonStdPort_test_Phishing(self):
        suspicious_url = "https://9955344.vip:8989"
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.NonStdPort()
        self.assertEqual(result, -1)


    def test_HTTPSDomainURL_test_Legitimate(self):
        legitimate_url = "https://www.wisc.edu/"
        feature_extraction = FeatureExtraction(legitimate_url)
        result = feature_extraction.HTTPSDomainURL()
        self.assertEqual(result, 1)

    def test_HTTPSDomainURL_test_Phishing(self):
        suspicious_url = "http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/."
        feature_extraction = FeatureExtraction(suspicious_url)
        result = feature_extraction.HTTPSDomainURL()
        self.assertEqual(result, -1)

    def test_RequestURL_Legitimate(self):
        # Simulate a webpage with 10 total objects, 2 external objects (20%)

        # Test case for a URL without a dash in the domain
        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Mock the find_all method
        # Test case for a URL without a dash in the domain
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='img', get=lambda x, _: 'http://example.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://example.com/image2.jpg' if x == 'src' else ''),
                Mock(name='video', get=lambda x, _: 'http://example.com/video.mp4' if x == 'src' else ''),
                Mock(name='audio', get=lambda x, _: 'http://example.com/audio.mp3' if x == 'src' else ''),
                Mock(name='source', get=lambda x, _: 'http://example.com/source.mp3' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://example.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image2.jpg' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://external.com/script.js' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://example.com/script.js' if x == 'src' else '')
            ],
            [
                Mock(name='link', get=lambda x, _: 'http://example.com/stylesheet.css' if x == 'href' else ''),
            ]
        ]
        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.RequestURL()
            
        self.assertEqual(result, 1)

    def test_RequestURL_Suspicious(self):
        # Simulate a webpage with 10 total objects, 3 external objects (30%)

        # Test case for a URL without a dash in the domain
        suspicious_url = "http://example.com"
        feature_extraction = FeatureExtraction(suspicious_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()


        # Test case for a URL without a dash in the domain
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='img', get=lambda x, _: 'http://example.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://example.com/image2.jpg' if x == 'src' else ''),
                Mock(name='video', get=lambda x, _: 'http://example.com/video.mp4' if x == 'src' else ''),
                Mock(name='audio', get=lambda x, _: 'http://example.com/audio.mp3' if x == 'src' else ''),
                Mock(name='source', get=lambda x, _: 'http://example.com/source.mp3' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image2.jpg' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://external.com/script.js' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://example.com/script.js' if x == 'src' else '')
            ],
            [
                Mock(name='link', get=lambda x, _: 'http://example.com/stylesheet.css' if x == 'href' else ''),
            ]
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.RequestURL()
            
        self.assertEqual(result, 0)

    def test_RequestURL_Phishing(self):
        # Simulate a webpage with 10 total objects, 7 external objects (70%)

        # Test case for a URL without a dash in the domain
        phishing_url = "http://example.com"
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()


        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='img', get=lambda x, _: 'http://example.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image2.jpg' if x == 'src' else ''),
                Mock(name='video', get=lambda x, _: 'http://external.com/video.mp4' if x == 'src' else ''),
                Mock(name='audio', get=lambda x, _: 'http://external.com/audio.mp3' if x == 'src' else ''),
                Mock(name='source', get=lambda x, _: 'http://external.com/source.mp3' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image1.jpg' if x == 'src' else ''),
                Mock(name='img', get=lambda x, _: 'http://external.com/image2.jpg' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://external.com/script.js' if x == 'src' else ''),
                Mock(name='script', get=lambda x, _: 'http://example.com/script.js' if x == 'src' else '')
            ],
            [
                Mock(name='link', get=lambda x, _: 'http://example.com/stylesheet.css' if x == 'href' else ''),
            ]
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.RequestURL()
            
        self.assertEqual(result, -1)

    def test_AnchorURL_Legitimate(self):
        # Simulate a webpage with 10 total anchors, 2 linking to a different domain (20%)

        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a URL without a dash in the domain
        feature_extraction.soup.find_all.return_value = [
            Mock(name='a', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page2' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page3' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page4' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page5' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page6' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page7' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page8' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page9' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: '' if x == 'href' else ''),  # Empty anchor
        ]


        result = feature_extraction.AnchorURL()
        self.assertEqual(result, 1)  # Legitimate


    def test_AnchorURL_Suspicious(self):
        # Simulate a webpage with 10 total anchors, 4 linking to a different domain (40%)

        suspicious_url = "http://example.com"
        feature_extraction = FeatureExtraction(suspicious_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a URL without a dash in the domain
        feature_extraction.soup.find_all.return_value = [
            Mock(name='a', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page2' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page3' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page4' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page5' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page6' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page7' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page8' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page9' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: '' if x == 'href' else ''),  # Empty anchor
        ]


        result = feature_extraction.AnchorURL()
        self.assertEqual(result, 0)  # Legitimate
    

    def test_AnchorURL_Phishing(self):
        # Simulate a webpage with 10 total anchors, 7 linking to a different domain (70%)

        phishing_url = "http://example.com"
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a URL without a dash in the domain
        feature_extraction.soup.find_all.return_value = [
            Mock(name='a', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://example.com/page2' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page3' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page4' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page5' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page6' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page7' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page8' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: 'http://external.com/page9' if x == 'href' else ''),
            Mock(name='a', get=lambda x, _: '' if x == 'href' else ''),  # Empty anchor
        ]


        result = feature_extraction.AnchorURL()
        self.assertEqual(result, -1)  # Legitimate


    def test_LinksInScriptTags_Legitimate(self):
        # Simulate a webpage with 10 total tags, 1 link in Script tags (20%)

        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Mock the find_all method
        # Mock the find_all method
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
            ],
            [
                Mock(name='script', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='script', get=lambda x, _: '' if x == 'content' else ''),
            ],
            [
                Mock(name='link', get=lambda x, _: '' if x == 'href' else ''),  
                Mock(name='link', get=lambda x, _: '' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: '' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                

            ]
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.LinksInScriptTags()

        self.assertEqual(result, 1)  # Legitimate
    
    def test_LinksInScriptTags_Suspicious(self):
        # Simulate a webpage with 10 total tags, 6 link in Script tags (60%)

        suspicious_url = "http://example.com"
        feature_extraction = FeatureExtraction(suspicious_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Mock the find_all method
        # Mock the find_all method
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
            ],
            [
                Mock(name='script', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
                Mock(name='script', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
            ],
            [
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),  
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                

            ]
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.LinksInScriptTags()

        self.assertEqual(result, 0)  # Legitimate


    def test_LinksInScriptTags_Phishing(self):
        # Simulate a webpage with 10 total tags, 9 link in Script tags (90%)

        phishing_url = "http://example.com"
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Mock the find_all method
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='meta', get=lambda x, _: '' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
                Mock(name='meta', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
            ],
            [
                Mock(name='script', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
                Mock(name='script', get=lambda x, _: 'http://example.com/page1' if x == 'content' else ''),
            ],
            [
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),  
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                
                Mock(name='link', get=lambda x, _: 'http://example.com/page1' if x == 'href' else ''),                

            ]
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.LinksInScriptTags()

        self.assertEqual(result, -1)  

    def test_ServerFormHandler_Legitimate(self):

        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a legitimate form
        feature_extraction.soup.find_all.return_value = [
            Mock(name='form', get=lambda x, _: 'http://example.com/form_handler' if x == 'action' else ''),
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.ServerFormHandler()

        self.assertEqual(result, 1)  # Legitimate

    def test_ServerFormHandler_Suspicious(self):

        # Empty form

        suspicious_url = "http://example.com"
        feature_extraction = FeatureExtraction(suspicious_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a legitimate form
        feature_extraction.soup.find_all.return_value = [
            Mock(name='form', get=lambda x, _: 'http://malicious.com/form_handler' if x == 'action' else ''),
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.ServerFormHandler()

        self.assertEqual(result, 0)  # Legitimate

    def test_ServerFormHandler_Phishing(self):

        # Empty form

        phishing_url = "http://example.com"
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for a legitimate form
        feature_extraction.soup.find_all.return_value = [
            Mock(name='form', get=lambda x, _: '' if x == 'action' else ''),
        ]


        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.ServerFormHandler()

        self.assertEqual(result, -1)  # Legitimate

    def test_InfoEmail_Legitimate(self):

        legitimate_url = "http://example.com"
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for an email found in the content
        feature_extraction.soup.find_all.return_value = []
        result = feature_extraction.InfoEmail()


        self.assertEqual(result, -1)


    def test_InfoEmail_Phishing(self):

        phishing_url = "http://example.com"
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.domain = "example.com"
        feature_extraction.soup = Mock()

        # Test case for an email found in the content
        feature_extraction.soup.find_all.return_value = [Mock(name='tag', text='Contact us at mail@example.com')]
        result = feature_extraction.InfoEmail()


        self.assertEqual(result, -1)


    def test_AbnormalURL_Legitimate(self):
        # Test case for matching responses

        legitimate_url = "http://example.com"
        
        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(legitimate_url)

        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.AbnormalURL()


        self.assertEqual(result, -1)
        self.assertEqual(result, 1)


    def test_AbnormalURL_Phishing(self):
        # Test case for non matching responses

        phishing_url = "http://example.com"
        
        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(phishing_url)

        feature_extraction.url = "http://phishing.com"

        # Mock urlparse for the external objects
        with unittest.mock.patch('urllib.parse.urlparse', side_effect=urlparse):
            result = feature_extraction.AbnormalURL()


        self.assertEqual(result, -1)


    def test_WebsiteForwarding_Legitimate(self):
        # Test case for matching responses
        legitimate_url = "http://example.com"
        
        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.response.history = [1]

        # Mock urlparse for the external objects
        result = feature_extraction.WebsiteForwarding()


        self.assertEqual(result, 1)

    def test_WebsiteForwarding_Phishing(self):
        # Test case for matching responses
        legitimate_url = "http://example.com"
        
        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(legitimate_url)

        feature_extraction.response.history = [1,2,3,4]

        # Mock urlparse for the external objects
        result = feature_extraction.WebsiteForwarding()


        self.assertEqual(result, -1)
        
    def test_StatusBarCust_Legitimate(self):
        # Test case for matching responses
        legitimate_url = "http://example.com"


        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(legitimate_url)
        feature_extraction.soup = Mock()


        # Mock the find_all method
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='div', get=lambda x: ' ' if x == 'onmouseover' else '')
            ]
        ]
        

        # Mock urlparse for the external objects
        result = feature_extraction.StatusBarCust()


        self.assertEqual(result, 1)


    def test_StatusBarCust_Suspicious(self):
        # Test case for matching responses
        legitimate_url = "http://example.com"


        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(legitimate_url)
        feature_extraction.soup = None


        # Mock urlparse for the external objects
        result = feature_extraction.StatusBarCust()


        self.assertEqual(result, 0)


    def test_StatusBarCust_Phishing(self):
        # Test case for matching responses
        phishing_url = "http://example.com"


        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(phishing_url)
        feature_extraction.soup = Mock()


        # Mock the find_all method
        feature_extraction.soup.find_all.side_effect = [
            [
                Mock(name='div', get=lambda x: 'window.status=\'Phishing\';' if x == 'onmouseover' else '')
            ]
        ]
        

        # Mock urlparse for the external objects
        result = feature_extraction.StatusBarCust()


        self.assertEqual(result, -1)


    def test_DisableRightClick_Phishing(self):
        # Test case for matching responses
        phishing_url = "http://example.com"


        # Mock urlparse for the external objects
        feature_extraction = FeatureExtraction(phishing_url)

        html_content = """<h1 style="color:green"> 
                            GeeksforGeeks 
                        </h1> 
                        <h2>Mouse click event</h2> 
                        <button onclick="click(event)">Click me</button> 
                        <p id="demo"></p> 
                        <script> 
                            document.onmousedown = click 
                            
                            // click function called 
                            function click(event) { 
                                
                                // Condition to disable left click 
                                if (event.button == 2) { 
                                        document.getElementById("demo").innerHTML= "Right click not allowed" 
                                } 
                            } 
                        </script>"""
        
        feature_extraction.soup = BeautifulSoup(html_content, 'html.parser')

        # Call DisableRightClick method
        result = feature_extraction.DisableRightClick()

        self.assertEqual(result, -1)

    def test_UsingPopupWindow_Phishing(self):

        # Test case for pop-ups with text inputs
        feature_extraction = FeatureExtraction("http://example.com")

        with patch('selenium.webdriver.Chrome') as mock_chrome:
            mock_driver = mock_chrome.return_value
            mock_driver.window_handles = ['main_window', 'popup_window']
            mock_driver.switch_to.window.return_value = None

            # Mocking WebElement for text inputs
            mock_text_input = Mock(spec=WebElement)
            mock_driver.find_elements_by_css_selector.return_value = [mock_text_input]

            result = feature_extraction.UsingPopupWindow()

        self.assertEqual(result, -1)

    def test_UsingPopupWindow_Phishing(self):

        # Test case for pop-ups with text inputs
        feature_extraction = FeatureExtraction("http://example.com")

        with patch('selenium.webdriver.Chrome') as mock_chrome:
            mock_driver = mock_chrome.return_value
            mock_driver.window_handles = ['main_window', 'popup_window']
            mock_driver.switch_to.window.return_value = None

            # Mocking WebElement for text inputs
            mock_text_input = Mock(spec=WebElement)
            mock_driver.find_elements_by_css_selector.return_value = [mock_text_input]

            result = feature_extraction.UsingPopupWindow()

        self.assertEqual(result, -1)


    def test_UsingPopupWindow_Legitimate(self):
        # Test case for no pop-ups
        feature_extraction = FeatureExtraction("http://example.com")

        with patch('selenium.webdriver.Chrome') as mock_chrome:
            mock_driver = mock_chrome.return_value
            mock_driver.window_handles = ['main_window']

            result = feature_extraction.UsingPopupWindow()

        self.assertEqual(result, 1)

    def test_UsingPopupWindow_Suspicious(self):
        # Test case for an exception during execution
        feature_extraction = FeatureExtraction("http://example.com")

        with patch('selenium.webdriver.Chrome') as mock_chrome:
            mock_chrome.side_effect = Exception("Test exception")

            result = feature_extraction.UsingPopupWindow()

        self.assertEqual(result, 0)  # Suspicious (Error or exception)

    def test_IframeRedirection_Phishing(self):
        # Test case for phishing iframe with invisible frame borders
        feature_extraction = FeatureExtraction("http://example.com")

        html_content = """<html><body><iframe src="http://example.com" frameborder="0"></iframe></body></html>"""
        
        feature_extraction.soup = BeautifulSoup(html_content, 'html.parser')


        result = feature_extraction.IframeRedirection()
        self.assertEqual(result, -1)


    def test_IframeRedirection_Legitimate(self):
        # Test case for phishing iframe with invisible frame borders
        feature_extraction = FeatureExtraction("http://example.com")

        html_content = """<html><body><iframe src="http://example.com"></iframe></body></html>"""
        
        feature_extraction.soup = BeautifulSoup(html_content, 'html.parser')


        result = feature_extraction.IframeRedirection()
        self.assertEqual(result, 1)

    def test_IframeRedirection_Suspicious(self):
        # Test case for phishing iframe with invisible frame borders
        feature_extraction = FeatureExtraction("http://example.com")

        html_content = None
        
        feature_extraction.soup = html_content


        result = feature_extraction.IframeRedirection()
        self.assertEqual(result, 0)


    def test_AgeofDomain_Legitimate(self):
        # Test case for a legitimate domain with an age greater than 6 months
        feature_extraction = FeatureExtraction("http://example.com")

        whois_response = Mock(creation_date=datetime.now() - timedelta(days=210))
        feature_extraction.whois_response = whois_response
        result = feature_extraction.AgeofDomain()
        self.assertEqual(result, 1)


    def test_AgeofDomain_Phishing(self):
        # Test case for a legitimate domain with an age greater than 6 months
        feature_extraction = FeatureExtraction("http://example.com")

        whois_response = Mock(creation_date=datetime.now() - timedelta(days=30))
        feature_extraction.whois_response = whois_response
        result = feature_extraction.AgeofDomain()
        self.assertEqual(result, -1)


    def test_AgeofDomain_Suspicious(self):
        # Test case for a legitimate domain with an age greater than 6 months
        feature_extraction = FeatureExtraction("http://example.com")

        whois_response = Mock(side_effect=Exception('Simulated error'))
        feature_extraction.whois_response = whois_response
        result = feature_extraction.AgeofDomain()
        self.assertEqual(result, 0)


    def test_DNSRecording_Legitimate(self):
        feature_extraction = FeatureExtraction("http://example.com")

        result = feature_extraction.DNSRecording()
        self.assertEqual(result, 1)
        


    def test_DNSRecording_Phishing(self):
        feature_extraction = FeatureExtraction("http://3t0xsjjehns3-1322632174.cos.na-toronto.myqcloud.com/3t0xsjjehns3.html")

        result = feature_extraction.DNSRecording()
        self.assertEqual(result, -1)
        

    def test_WebsiteTraffic_Legitimate(self):
        feature_extraction = FeatureExtraction("http://example.com")

        result = feature_extraction.WebsiteTraffic()
        self.assertEqual(result, 1)


    def test_WebsiteTraffic_Phishing(self):
        feature_extraction = FeatureExtraction("https://toffeeshare.com/")

        result = feature_extraction.WebsiteTraffic()
        self.assertEqual(result, 1)

    def test_PageRank_Legitimate(self):
        feature_extraction = FeatureExtraction("http://example.com")

        result = feature_extraction.PageRank()
        self.assertEqual(result, 1)

    def test_PageRank_Phishing(self):
        feature_extraction = FeatureExtraction("https://toffeeshare.com/")

        result = feature_extraction.PageRank()
        self.assertEqual(result, -1)

    def test_GoogleIndex_Legitimate(self):
        feature_extraction = FeatureExtraction("http://example.com")

        result = feature_extraction.GoogleIndex()
        self.assertEqual(result, 1)

    def test_GoogleIndex_Phishing(self):
        feature_extraction = FeatureExtraction("http://000m8ih.wcomhost.com/mama/23a2c/index_2.html")

        result = feature_extraction.GoogleIndex()
        self.assertEqual(result, -1)


    def test_LinksPointingToPage_Phishing(self):
        # Arrange
        feature_extraction = FeatureExtraction("http://example.com")

        feature_extraction.soup = Mock()

        feature_extraction.soup.find_all.return_value = [
            Mock(href="http://external.com"),
            Mock(href="http://external.com"),
            Mock(href="http://external.com")
        ]

        # Act
        result = feature_extraction.LinksPointingToPage()

        # Assert
        self.assertEqual(result, -1)  # Legitimate

    def test_StatsReport_Phishing(self):
        # Test case for a phishing IP address match
        feature_extraction = FeatureExtraction("http://example.com")
        feature_extraction.domain = "phishing-ip.com"
        result = feature_extraction.StatsReport()
        self.assertEqual(result, -1)

    def test_StatsReport_Legitimate(self):
        # Test case for a phishing IP address match
        feature_extraction = FeatureExtraction("http://example.com")
        result = feature_extraction.StatsReport()
        self.assertEqual(result, 1)


if __name__ == '__main__':
    unittest.main()
