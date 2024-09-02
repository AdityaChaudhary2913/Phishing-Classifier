import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import socket
from urllib.parse import urlparse

class ExtractFeatures:
    def __init__(self) -> None:
        self.features = list()
    
    def extract_features(self, url: str) -> list:
        parsed_url = urlparse(url)

        # 1. Check if IP address is in URL
        try:
            if socket.gethostbyname(parsed_url.hostname):
                self.features.append(1)
        except socket.error:
            self.features.append(-1)

        # 2. URL Length
        if len(url) < 54:
            self.features.append(-1)
        elif 54 <= len(url) <= 75:
            self.features.append(0)
        else:
            self.features.append(1)

        # 3. URL Shortening Service
        short_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
        if any(service in url for service in short_services):
            self.features.append(-1)
        else:
            self.features.append(1)

        # 4. Having @ symbol
        self.features.append(1 if '@' in url else -1)

        # 5. Double slash redirecting
        position = url.rfind("//")
        if position > 7:
            self.features.append(-1)
        else:
            self.features.append(1)

        # 6. Prefix-Suffix
        self.features.append(-1 if '-' in parsed_url.netloc else 1)

        # 7. Having Sub Domain
        subdomains = parsed_url.hostname.split('.')
        print()
        if len(subdomains) > 3:
            self.features.append(1)
        elif len(subdomains) == 3:
            self.features.append(0)
        else:
            self.features.append(-1)

        # 8. SSL final state
        try:
            response = requests.get(url, timeout=10)
            if response.history:
                self.features.append(-1)
            elif 'https' in response.url:
                self.features.append(1)
            else:
                self.features.append(0)
        except:
            self.features.append(-1)

        # 9. Domain registration length
        try:
            domain_info = whois.whois(url)
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if (expiration_date - datetime.now()).days >= 365:
                self.features.append(1)
            else:
                self.features.append(-1)
        except:
            self.features.append(-1)

        # 10. Favicon
        try:
            response = requests.get(url + '/favicon.ico', timeout=10)
            favicon_url = urlparse(response.url)
            domain = urlparse(url).netloc
            self.features.append(1 if favicon_url.netloc == domain else -1)
        except:
            self.features.append(-1)

        # 11. Port
        # Standard web port check
        self.features.append(1 if parsed_url.scheme == 'http' or parsed_url.scheme == 'https' else -1)

        # 12. HTTPS token in the domain part
        self.features.append(-1 if 'https' in parsed_url.netloc else 1)

        # 13. Request URL
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            external_links = [link for link in soup.find_all('a', href=True) if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc]
            self.features.append(1 if len(external_links) > 5 else -1)
        except:
            self.features.append(-1)

        # 14. URL of Anchor
        try:
            total_links = soup.find_all('a', href=True)
            if not total_links:
                self.features.append(1)
            else:
                external_links = [link for link in total_links if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc]
                percentage = len(external_links) / len(total_links)
                self.features.append(-1 if percentage > 0.67 else 1)
        except:
            self.features.append(-1)

        # 15. Links in tags
        try:
            total_tags = soup.find_all(['link', 'script'], href=True) + soup.find_all(['link', 'script'], src=True)
            external_tags = [tag for tag in total_tags if urlparse(tag.get('href', tag.get('src', ''))).netloc and urlparse(tag.get('href', tag.get('src', ''))).netloc != urlparse(url).netloc]
            percentage = len(external_tags) / len(total_tags) if total_tags else 0
            self.features.append(-1 if percentage > 0.22 else 1)
        except:
            self.features.append(-1)

        # 16. SFH
        self.features.append(1)

        # 17. Submitting to email
        self.features.append(1)

        # 18. Abnormal URL
        try:
            self.features.append(-1 if parsed_url.netloc != urlparse(requests.get(url).url).netloc else 1)
        except:
            self.features.append(-1)

        # 19. Redirect
        try:
            self.features.append(1 if len(response.history) > 1 else 0)
        except:
            self.features.append(0)

        # 20. on_mouseover
        try:
            mouse_overs = soup.find_all(onmouseover=True)
            self.features.append(-1 if any("window.status" in mo['onmouseover'] for mo in mouse_overs) else 1)
        except:
            self.features.append(1)

        # 21. RightClick
        try:
            if 'event.button==2' in response.text or 'contextmenu' in response.text:
                self.features.append(-1)
            else:
                self.features.append(1)
        except:
            self.features.append(1)

        # 22. popUpWidnow
        try:
            if "window.open(" in response.text:
                self.features.append(-1)
            else:
                self.features.append(1)
        except:
            self.features.append(1)

        # 23. Iframe
        try:
            iframes = soup.find_all('iframe', style=lambda value: value and 'display:none' in value)
            self.features.append(-1 if iframes else 1)
        except:
            self.features.append(-1)

        # 24. Age of Domain
        try:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if (datetime.now() - creation_date).days > 180:
                self.features.append(1)
            else:
                self.features.append(-1)
        except:
            self.features.append(-1)

        # 25. DNSRecord
        try:
            socket.gethostbyname(parsed_url.netloc)
            self.features.append(1)
        except socket.error:
            self.features.append(-1)

        # 26. Web Traffic
        if len(url) > 20 and not url.startswith('http'):
            self.features.append(-1)
        else:
            self.features.append(1)

        # 27. Page Rank
        if '-' in urlparse(url).netloc or len(url) > 100:
            self.features.append(-1)
        else:
            self.features.append(1)

        # 28. Google Index
        if urlparse(url).scheme == 'https' and '.' in urlparse(url).netloc:
            self.features.append(-1)
        else:
            self.features.append(1)

        # 29. Links pointing to page
        try:
            links = soup.find_all('a', href=True)
            internal_links = [link for link in links if urlparse(link['href']).netloc == urlparse(url).netloc]
            self.features.append(1 if len(internal_links) > 10 else -1)
        except:
            self.features.append(-1)

        # 30. Statistical report
        try:
            size = len(response.text)
            self.features.append(1 if size > 20000 else -1 ) # Assuming larger pages might have more content and thus, more reporting.
        except:
            self.features.append(-1)

        # Return the complete list of self.features
        return self.features