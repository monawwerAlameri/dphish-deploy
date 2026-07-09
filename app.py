# D-PHISH - Phishing URL Detection System
# Flask Application with Authentication & Machine Learning

print("📦 Importing Flask modules...")
from flask import Flask, request, render_template, redirect, url_for, session, flash
from functools import wraps
print("📦 Importing numpy and pickle...")
import numpy as np
import pickle
import logging
import sys
import os
from datetime import datetime, timedelta
print("📦 Importing database and auth modules...")
from database import get_db
from auth import AuthManager
from enhanced_detection import heuristic_phishing_detection, is_likely_phishing
print("✅ All imports successful!")

# Setup
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Enhanced Logging - Console + File
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('phishing_detection.log')
    ]
)
logger = logging.getLogger(__name__)

# Load ML Model
try:
    model_path = os.path.join('pickle', 'model.pkl')
    with open(model_path, 'rb') as file:
        model = pickle.load(file)
    logger.info("✅ ML model loaded successfully")
    print("✅ ML model loaded successfully")
except Exception as e:
    logger.error(f"❌ Error loading model: {e}")
    print(f"❌ Error loading model: {e}")
    model = None

# Import ML feature extraction libraries
from urllib.parse import urlparse
import ipaddress, re, urllib.request
from bs4 import BeautifulSoup
import socket, requests, whois
from dateutil.parser import parse as date_parse
import dns.resolver
from tldextract import extract
from collections import Counter
import json, ssl, tldextract
import warnings

# Suppress deprecation warnings from BeautifulSoup
warnings.filterwarnings('ignore', category=DeprecationWarning)

# ML Feature Extraction Functions (API-Free Version)
def get_full_hostname(url):
    """Extract full hostname including subdomains from URL"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        if re.match(r"^www.", hostname):
            hostname = hostname.replace("www.", "")
        return hostname
    except:
        return ""

def extract_domain(url):
    """Extract base domain from URL (without subdomain)"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        extracted = extract(domain)
        full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain == "vercel" and extracted.suffix == "app":
            return full_domain.strip(".")
        return f"{extracted.domain}.{extracted.suffix}"
    except:
        return ""

def having_ip_address(url):
    """Check if URL contains IP address instead of domain"""
    try:
        domain = extract_domain(url)
        match = re.search(r'\d+\.\d+\.\d+\.\d+', domain)
        return 1 if match else -1
    except:
        return 0

def URL_Length(url):
    """Analyze URL length (longer URLs are often phishing)"""
    try:
        if len(url) < 54:
            return -1
        elif len(url) >= 54 and len(url) <= 75:
            return 0
        else:
            return 1
    except:
        return 0

def isShortUrl(url):
    """Check if URL uses a URL shortening service"""
    try:
        domain = extract_domain(url)
        short_domains = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
                         'shorte.st', 'go2l.ink', 'x.co', 'cli.gs', 'yfrog.com', 
                         'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 
                         'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 
                         'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 
                         'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 
                         'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt', 
                         'qr.ae', 'adf.ly', 'cur.lv', 'ity.im', 'q.gs', 'po.st', 'bc.vc', 
                         'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 
                         'yourls.org', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 
                         'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 
                         'link.zip.net', 'short.gy', 'shorturl.at', 't.ly', 'rb.gy']
        for short_domain in short_domains:
            if domain.endswith(short_domain):
                return 1
        return -1
    except:
        return 0

def symbol(url):
    """Check for @ symbol in URL (often used in phishing)"""
    try:
        return 1 if re.findall("@", url) else -1
    except:
        return 0

def redirection(url):
    """Check for double slash redirects"""
    try:
        parsed_url = urlparse(url)
        protocol = parsed_url.scheme.lower()
        pos = url.rfind('//')
        if (protocol == "http" and pos > 6) or (protocol == "https" and pos > 7):
            return 1
        else:
            return -1
    except:
        return 0

def prefixSuffix(url):
    """Check for dashes in domain (often used in phishing)"""
    try:
        # Check full hostname including subdomains for dashes
        hostname = get_full_hostname(url)
        return 1 if '-' in hostname else -1
    except:
        return 0

def SubDomains(url):
    """Count number of subdomains"""
    try:
        # Check full hostname to count all dots
        hostname = get_full_hostname(url)
        # Count dots in the hostname
        num_dots = hostname.count('.')
        # Normal domains have 1 dot (example.com)
        # Subdomains add more dots (sub.example.com = 2 dots)
        if num_dots <= 1:
            return -1  # Safe - no subdomain or single subdomain
        elif num_dots == 2:
            return 0   # Neutral - one subdomain
        else:
            return 1   # Suspicious - multiple subdomains
    except:
        return 0

def SSLfinal_State(url):
    """Check SSL certificate validity"""
    try:
        use_https = 1 if url.startswith('https') else -1
        domain = extract_domain(url)
        
        # Try to get SSL certificate
        context = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.settimeout(5)
                ssock.connect((domain, 443))
                certificate = ssock.getpeercert()
        
        if 'issuer' in certificate:
            issuer = dict(x[0] for x in certificate['issuer'])
            certificate_auth = str(issuer.get('commonName', '')).split()[0]
        else:
            certificate_auth = ''
        
        # List of trusted certificate authorities
        trusted_auth = ['Comodo', 'Symantec', 'AlphaSSL', 'GoDaddy', 'Amazon', 'GlobalSign', 
                       'DigiCert', 'StartCom', 'Entrust', 'Verizon', 'Trustwave', 'Unizeto', 
                       'Buypass', 'QuoVadis', 'Deutsche Telekom', 'Network Solutions', 
                       'SwissSign', 'IdenTrust', 'Secom', 'TWCA', 'GeoTrust', 'Thawte', 
                       'Doster', 'Verisign', 'VeriSign', "Let's Encrypt", 'GTS', 'SSL.com', 
                       'RapidSSL', 'Sectigo', 'Starfield', 'eNom', 'Namecheap', '1&1 IONOS', 
                       'Hostinger', 'A2 Hosting', 'Bluehost', 'DreamHost', 'GreenGeeks', 
                       'InMotion Hosting', 'InterServer', 'Liquid Web', 'Media Temple', 
                       'MilesWeb', 'Nexcess', 'SiteGround', 'WP Engine', 'Cloudflare', 'ZeroSSL']
        
        starting_date = datetime.strptime(certificate['notBefore'], "%b %d %H:%M:%S %Y %Z")
        ending_date = datetime.strptime(certificate['notAfter'], "%b %d %H:%M:%S %Y %Z")
        num_days = (ending_date - starting_date).days
        
        if use_https == 1 and certificate_auth in trusted_auth and num_days >= 83:
            return -1
        
        elif use_https == 1 and certificate_auth not in trusted_auth:
            return 0
        else:
            return 1
    except:
        return 1

def domain_registration_length(domain_name):
    """Check domain registration length"""
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(expiration_date, str):
                expiration_date = expiration_date.lstrip(': ').strip()
                try:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(creation_date, str):
                creation_date = creation_date.lstrip(': ').strip()
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        
        ageofdomain = abs((expiration_date - creation_date).days) if expiration_date and creation_date else 0
        return 1 if ageofdomain < 367 else -1
    except:
        return 0

def Favicon(response, url):
    """Check if favicon is loaded from same domain"""
    try:
        if response == "":
            return 1
        soup = BeautifulSoup(response.text, 'html.parser')
        parsed_urll = urlparse(url)
        for head in soup.find_all('head'):
            for link in head.find_all('link', href=True):
                parsed_link = urlparse(link['href'])
                if parsed_link.netloc == url or parsed_link.path == parsed_urll.path:
                    return -1
        return 1
    except:
        return 1

def check_port(url):
    """Check for suspicious ports (API-free version with heuristics)"""
    try:
        parsed = urlparse(url)
        if parsed.port:
            # Common legitimate ports
            if parsed.port in [80, 443, 8080, 8443]:
                return -1
            # Suspicious ports
            elif parsed.port in [21, 22, 23, 445, 1433, 1521, 3306, 3389]:
                return 1
            else:
                return 0
        return -1  # No port specified, assume safe
    except:
        return 0

def httpsDomain(url):
    """Check if domain name contains 'https'"""
    try:
        domain = extract_domain(url)
        return 1 if 'https' in domain else -1
    except:
        return 0

def too_deep_url(url):
    """Check URL depth (too many slashes)"""
    try:
        slashes = -2
        for i in url:
            if i == '/':
                slashes += 1
        return 1 if slashes > 5 else -1
    except:
        return 0

def request_url(response, url):
    """Check percentage of external resources"""
    try:
        if response == "":
            return 1
        
        Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", 
                      "#whatever", "#content", "javascript::void(0)", "javascript::void(0);", 
                      "javascript::;", "javascript"]
        
        hostname = urlparse(url).netloc
        domain = tldextract.extract(url).domain
        
        Media = {'internals': [], 'externals': [], 'null': []}
        soup = BeautifulSoup(response.content, 'html.parser', from_encoding='iso-8859-1')
        
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
                if not img['src'].startswith('http'):
                    if not img['src'].startswith('/'):
                        Media['internals'].append(hostname + '/' + img['src'])
                    elif img['src'] in Null_format:
                        Media['null'].append(img['src'])
                    else:
                        Media['internals'].append(hostname + img['src'])
            else:
                Media['externals'].append(img['src'])
        
        total = len(Media['internals']) + len(Media['externals'])
        externals = len(Media['externals'])
        percentile = (externals / float(total) * 100) if total > 0 else 0
        
        if percentile < 22:
            return -1
        elif percentile >= 22 and percentile < 61:
            return 0
        else:
            return 1
    except:
        return 0

def url_of_anchor(response, url):
    """Check anchor tags linking to different domains"""
    try:
        if response == "":
            return 1
        
        extracted_main = extract(url)
        websiteDomain = extracted_main.domain
        content = response.text
        soup = BeautifulSoup(content, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        
        for anchor in anchors:
            try:
                extracted_anchor = extract(anchor['href'])
                anchorDomain = extracted_anchor.domain
                if websiteDomain == anchorDomain or anchorDomain == '':
                    linked_to_same += 1
            except:
                continue
        
        linked_outside = total - linked_to_same
        avg = linked_outside / total if total != 0 else 0
        
        if avg < 0.31:
            return -1
        elif 0.31 <= avg <= 0.67:
            return 0
        else:
            return 1
    except:
        return 0

def LinksInTags(response, url):
    """Check links in meta/script tags"""
    try:
        if response == "":
            return 1
        
        soup = BeautifulSoup(response.content, 'html.parser')
        success = 0
        total = 0
        
        for link in soup.find_all('link', href=True):
            href = link['href']
            total += 1
            if href and (url in href or href.startswith('/') or len(href.split('.')) == 1):
                success += 1
        
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            total += 1
            if src and (url in src or src.startswith('/') or len(src.split('.')) == 1):
                success += 1
        
        if total > 0:
            percentage = (success / total) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        else:
            return 0
    except:
        return 0

def ServerFormHandler(response, url):
    """Check if forms submit to external domains"""
    try:
        if response == "":
            return 1
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        if len(soup.find_all('form', action=True)) == 0:
            return 0
        else:
            domain = urlparse(url).netloc
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return 0
                elif url not in form['action'] and domain not in form['action']:
                    return 1
            return -1
    except:
        return 0

def email_submit(opener, url):
    """Check for mailto links in page"""
    try:
        if opener == "":
            return 1
        soup = BeautifulSoup(opener, 'lxml')
        if soup.find('a', href=lambda href: href and href.startswith('mailto:')):
            return 1
        else:
            return -1
    except:
        return 0

def abnormal_url(domain_names, url):
    """Check if URL matches registered domain"""
    try:
        domain = extract_domain(url)
        registered_domain = domain_names.domain_name
        
        if registered_domain is None:
            return 1
        
        if isinstance(registered_domain, list):
            registered_domain = ' '.join(registered_domain)
        
        if domain.lower() in registered_domain.lower():
            return -1
        else:
            return 1
    except:
        return 1

def StatusBarCust(response):
    """Check for status bar customization"""
    try:
        if response == "":
            return 1
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        elements = soup.find_all(attrs={'onmouseover': True})
        return 1 if len(elements) > 0 else -1
    except:
        return 0

def rightClick(opener):
    """Check if right-click is disabled"""
    try:
        if opener == "":
            return 1
        
        soup = BeautifulSoup(opener, 'lxml')
        s = str(soup)
        if (re.search("contextmenu", s) and re.search("preventDefault()", s)):
            return 1
        else:
            return -1
    except:
        return 0

def UsingPopupWindow(response):
    """Check for popup windows/alerts"""
    try:
        if response == "":
            return 1
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        s = str(soup)
        return 1 if re.search("alert", s) else -1
    except:
        return 0

def IframeRedirection(response):
    """Check for iframe usage"""
    try:
        if response == "":
            return 1
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        s = str(soup)
        if (re.search("iframe", s) or re.search("frameBorder()", s)):
            return 1
        else:
            return -1
    except:
        return 0

def domainAge(domain_name):
    """Check domain age from WHOIS data"""
    try:
        today = datetime.today()
        expiration_date = domain_name.expiration_date
        
        if expiration_date:
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(expiration_date, str):
                expiration_date = expiration_date.lstrip(': ').strip()
                try:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        
        registration_length = abs((expiration_date - today).days) if expiration_date else 0
        return 1 if registration_length <= 180 else -1
    except:
        return 0

def check_dns_record(url):
    """Check if domain has DNS record"""
    try:
        domain = extract_domain(url)
        dns.resolver.resolve(domain, 'A')
        return -1
    except:
        return 1

def WebsiteTraffic(url):
    """Estimate website traffic (API-free heuristic)"""
    try:
        domain = extract_domain(url)
        # Simple heuristic: check if domain is accessible
        response = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return -1 if response.status_code == 200 else 1
    except:
        return 0

def page_rank(url):
    """Estimate page rank (API-free heuristic based on domain characteristics)"""
    try:
        domain = extract_domain(url)
        
        # Well-known popular domains get -1 (good)
        popular_domains = ['google', 'facebook', 'twitter', 'instagram', 'linkedin', 
                          'youtube', 'amazon', 'microsoft', 'apple', 'github', 
                          'stackoverflow', 'wikipedia', 'reddit', 'netflix', 'paypal']
        
        for pop_domain in popular_domains:
            if pop_domain in domain.lower():
                return -1
        
        # Very short domains or suspicious patterns
        if len(domain) < 5 or domain.count('-') > 2:
            return 1
        
        # Default to neutral
        return 0
    except:
        return 1

def googleIndex(url):
    """Check if site appears to be indexed (API-free heuristic)"""
    try:
        domain = extract_domain(url)
        
        # Try to access the domain
        response = requests.get(f"https://{domain}", timeout=5)
        
        # If site is accessible and has content, likely indexed
        if response.status_code == 200 and len(response.content) > 1000:
            return -1
        else:
            return 1
    except:
        return 0

def LinksPointingToPage(response):
    """Count number of links pointing to the page"""
    try:
        if response == "":
            return 1
        
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        found_urls = Counter([link["href"] for link in soup.find_all("a", href=lambda href: href and not href.startswith("#"))])
        count = len(found_urls)
        
        if count > 2:
            return -1
        if 0 < count <= 2:
            return 0
        else:
            return 1
    except:
        return 0

def featureExtraction(url):
    """Extract all features from URL - API-FREE VERSION"""
    features = []
    
    # Feature 1: Having IP Address
    features.append(having_ip_address(url))
    
    # Feature 2: URL Length
    features.append(URL_Length(url))
    
    # Feature 3: Shortening Service
    features.append(isShortUrl(url))
    
    # Feature 4: Having @ Symbol
    features.append(symbol(url))
    
    # Feature 5: Double Slash Redirecting
    features.append(redirection(url))
    
    # Feature 6: Prefix Suffix
    features.append(prefixSuffix(url))
    
    # Feature 7: Sub Domains
    features.append(SubDomains(url))
    
    # Feature 8: SSL Final State
    features.append(SSLfinal_State(url))
    
    # Feature 9: Domain Registration Length
    dns_flag = 0
    try:
        domain_names = whois.whois(extract_domain(url))
    except:
        dns_flag = 1
        domain_names = None
    
    features.append(1 if dns_flag == 1 else domain_registration_length(domain_names))
    
    # Get HTTP response for remaining features
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
    except:
        response = ""
    
    # Feature 10: Favicon
    features.append(Favicon(response, url))
    
    # Feature 11: Port (API-FREE)
    features.append(check_port(url))
    
    # Feature 12: HTTPS Domain
    features.append(httpsDomain(url))
    
    # Feature 13: Too Deep URL
    features.append(too_deep_url(url))
    
    # Feature 14: Request URL
    features.append(request_url(response, url))
    
    # Feature 15: URL of Anchor
    features.append(url_of_anchor(response, url))
    
    # Feature 16: Links in Tags
    features.append(LinksInTags(response, url))
    
    # Feature 17: Server Form Handler
    features.append(ServerFormHandler(response, url))
    
    # Get page content
    try:
        opener = urllib.request.urlopen(url, timeout=10).read()
    except:
        opener = ""
    
    # Feature 18: Email Submit
    features.append(email_submit(opener, url))
    
    # Feature 19: Abnormal URL
    features.append(1 if dns_flag == 1 else abnormal_url(domain_names, url))
    
    # Feature 20: Status Bar Customization
    features.append(StatusBarCust(response))
    
    # Feature 21: Right Click
    features.append(rightClick(opener))
    
    # Feature 22: Popup Window
    features.append(UsingPopupWindow(response))
    
    # Feature 23: Iframe Redirection
    features.append(IframeRedirection(response))
    
    # Feature 24: Domain Age
    features.append(1 if dns_flag == 1 else domainAge(domain_names))
    
    # Feature 25: DNS Record
    features.append(check_dns_record(url))
    
    # Feature 26: Website Traffic (API-FREE)
    features.append(WebsiteTraffic(url))
    
    # Feature 27: Page Rank (API-FREE)
    features.append(page_rank(url))
    
    # Feature 28: Google Index (API-FREE)
    features.append(googleIndex(url))
    
    # Feature 29: Links Pointing to Page
    features.append(LinksPointingToPage(response))
    
    return features

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes - Authentication
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        print(f"\n{'='*70}")
        print(f"📝 SIGNUP ATTEMPT")
        print(f"Full Name: {full_name}")
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"{'='*70}")
        logger.info(f"📝 Signup attempt - Username: {username}, Email: {email}")
        
        success, message, user_id = AuthManager.register_user(username, email, full_name, password, confirm_password)
        if success:
            print(f"✅ SIGNUP SUCCESS")
            print(f"New User ID: {user_id}")
            print(f"Username: {username}")
            print(f"{'='*70}\n")
            logger.info(f"✅ Signup successful - New user ID: {user_id}, Username: {username}")
            
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            print(f"❌ SIGNUP FAILED: {message}")
            print(f"{'='*70}\n")
            logger.warning(f"❌ Signup failed - Username: {username} - {message}")
            flash(message, 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"\n{'='*70}")
        print(f"🔐 LOGIN ATTEMPT")
        print(f"Username: {username}")
        print(f"{'='*70}")
        logger.info(f"🔐 Login attempt for user: {username}")
        
        success, message, user = AuthManager.login_user(username, password)
        if success:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session.permanent = True
            
            print(f"✅ LOGIN SUCCESS")
            print(f"User ID: {user['id']}")
            print(f"Username: {username}")
            print(f"{'='*70}\n")
            logger.info(f"✅ Login successful for user: {username} (ID: {user['id']})")
            
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            print(f"❌ LOGIN FAILED: {message}")
            print(f"{'='*70}\n")
            logger.warning(f"❌ Login failed for user: {username} - {message}")
            flash(message, 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id', 'Unknown')
    
    print(f"\n{'='*70}")
    print(f"🚪 LOGOUT")
    print(f"Username: {username}")
    print(f"User ID: {user_id}")
    print(f"{'='*70}\n")
    logger.info(f"🚪 User {username} (ID: {user_id}) logged out")
    
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# Routes - Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    stats = db.get_statistics(user_id)
    recent_checks = db.get_user_checks(user_id, limit=5)
    
    print(f"\n{'='*70}")
    print(f"📊 DASHBOARD ACCESSED")
    print(f"User: {user.get('username') if user else 'Unknown'}")
    if stats:
        print(f"Total Checks: {stats.get('total_checks', 0)}")
        print(f"Phishing Detected: {stats.get('phishing_detected', 0)}")
        print(f"Legitimate: {stats.get('legitimate_detected', 0)}")
    print(f"{'='*70}\n")
    logger.info(f"📊 Dashboard accessed by user: {user.get('username') if user else 'Unknown'} (ID: {user_id})")
    
    return render_template('dashboard.html', user=user, stats=stats, recent_checks=recent_checks)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            
            print(f"\n{'='*70}")
            print(f"👤 PROFILE UPDATE")
            print(f"User ID: {user_id}")
            print(f"New Name: {full_name}")
            print(f"New Email: {email}")
            print(f"{'='*70}")
            logger.info(f"👤 Profile update for user {user_id} - Name: {full_name}, Email: {email}")
            
            success, message = AuthManager.update_profile(user_id, full_name, email)
            if success:
                print(f"✅ PROFILE UPDATE SUCCESS")
                print(f"{'='*70}\n")
                logger.info(f"✅ Profile updated successfully for user {user_id}")
                flash(message, 'success')
                user = db.get_user_by_id(user_id)
            else:
                print(f"❌ PROFILE UPDATE FAILED: {message}")
                print(f"{'='*70}\n")
                logger.warning(f"❌ Profile update failed for user {user_id}: {message}")
                flash(message, 'danger')
                
        elif action == 'change_password':
            old_password = request.form.get('old_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            print(f"\n{'='*70}")
            print(f"🔑 PASSWORD CHANGE ATTEMPT")
            print(f"User ID: {user_id}")
            print(f"{'='*70}")
            logger.info(f"🔑 Password change attempt for user {user_id}")
            
            success, message = AuthManager.change_password(user_id, old_password, new_password, confirm_password)
            if success:
                print(f"✅ PASSWORD CHANGE SUCCESS")
                print(f"{'='*70}\n")
                logger.info(f"✅ Password changed successfully for user {user_id}")
            else:
                print(f"❌ PASSWORD CHANGE FAILED: {message}")
                print(f"{'='*70}\n")
                logger.warning(f"❌ Password change failed for user {user_id}: {message}")
            flash(message, 'success' if success else 'danger')
            
    return render_template('profile.html', user=user)

@app.route('/history')
@login_required
def history():
    db = get_db()
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    checks = db.get_user_checks_all(user_id)
    
    print(f"\n{'='*70}")
    print(f"📋 HISTORY PAGE ACCESSED")
    print(f"User: {user.get('username') if user else 'Unknown'}")
    print(f"Total Records: {len(checks) if checks else 0}")
    print(f"{'='*70}\n")
    logger.info(f"📋 User {user_id} accessed history - Found {len(checks) if checks else 0} records")
    
    return render_template('history.html', user=user, checks=checks)

@app.route('/saved-urls')
@login_required
def saved_urls():
    db = get_db()
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    saved = db.get_saved_urls(user_id)
    
    print(f"\n{'='*70}")
    print(f"📌 SAVED URLs PAGE ACCESSED")
    print(f"User: {user.get('username') if user else 'Unknown'}")
    print(f"Total Saved URLs: {len(saved) if saved else 0}")
    print(f"{'='*70}\n")
    logger.info(f"📌 Saved URLs accessed by user {user_id} - Found {len(saved) if saved else 0} saved URLs")
    
    return render_template('saved_urls.html', user=user, saved_urls=saved)

@app.route('/delete-saved-url/<int:url_id>', methods=['POST'])
@login_required
def delete_saved_url(url_id):
    db = get_db()
    db.delete_saved_url(url_id)
    flash('URL removed from saved list', 'success')
    return redirect(url_for('saved_urls'))

# Routes - Main & Info Pages
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Require login for URL checking
        if 'user_id' not in session:
            flash('Please login to check URLs', 'danger')
            return redirect(url_for('login'))
        
        url = request.form.get('url', '')
        
        if not url or not url.strip():
            flash('Please enter a valid URL', 'danger')
            return render_template('index.html', xx=-1)
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"\n{'='*70}")
        print(f"🔍 URL ANALYSIS STARTED")
        print(f"URL: {url}")
        print(f"{'='*70}")
        logger.info(f"🔍 URL Analysis started for: {url}")
        
        try:
            # Step 1: Heuristic Analysis (Fast, no network required)
            heuristic_report = heuristic_phishing_detection(url)
            print(f"🔍 Heuristic Analysis: {heuristic_report['verdict']}")
            if heuristic_report['reasons']:
                print(f"   Reasons: {', '.join(heuristic_report['reasons'][:3])}")
            print(f"   Confidence: {heuristic_report['confidence']*100:.2f}%")
            
            # Step 2: ML Model Analysis
            features = featureExtraction(url)
            features = np.array(features).reshape(1, -1)
            
            if model:
                prediction = model.predict(features)
                phishing_prob_all = model.predict_proba(features)
                ml_phishing_prob = phishing_prob_all[0, 1]
                ml_result = "Phishing" if prediction[0] == 1 else "Legitimate"
                ml_confidence = ml_phishing_prob if prediction[0] == 1 else 1 - ml_phishing_prob
                print(f"🤖 ML Model Analysis: {ml_result}")
                print(f"   Confidence: {ml_confidence*100:.2f}%")
            else:
                ml_phishing_prob = 0.5
                ml_result = "Unknown"
                ml_confidence = 0.5
            
            # Step 3: Combine both analyses for final verdict
            # If heuristic detects phishing with high confidence, override ML
            if heuristic_report['is_phishing'] and heuristic_report['confidence'] >= 0.7:
                result = "Phishing"
                confidence = heuristic_report['confidence']
                phishing_prob = heuristic_report['confidence']
                print(f"\n🎯 FINAL VERDICT: PHISHING (Heuristic Override)")
                print(f"   Primary Detection: Heuristic Analysis")
            # If both agree it's phishing
            elif heuristic_report['is_phishing'] and ml_result == "Phishing":
                result = "Phishing"
                confidence = max(heuristic_report['confidence'], ml_confidence)
                phishing_prob = confidence
                print(f"\n🎯 FINAL VERDICT: PHISHING (Both Methods Agree)")
            # If heuristic is suspicious (0.4-0.7) and ML says phishing
            elif heuristic_report['confidence'] >= 0.4 and ml_result == "Phishing":
                result = "Phishing"
                confidence = (heuristic_report['confidence'] + ml_confidence) / 2
                phishing_prob = confidence
                print(f"\n🎯 FINAL VERDICT: PHISHING (Combined Analysis)")
            # Use ML result if heuristic doesn't find issues
            else:
                result = ml_result
                confidence = ml_confidence
                phishing_prob = ml_phishing_prob
                print(f"\n🎯 FINAL VERDICT: {result.upper()} (ML Analysis)")
            
            if result == "Phishing":
                print(f"⚠️  RESULT: PHISHING DETECTED")
                logger.warning(f"⚠️  PHISHING DETECTED: {url} - Confidence: {confidence*100:.2f}%")
                if heuristic_report['reasons']:
                    print(f"⚠️  Indicators: {', '.join(heuristic_report['reasons'])}")
            else:
                print(f"✅ RESULT: LEGITIMATE WEBSITE")
                logger.info(f"✅ SAFE URL: {url} - Confidence: {confidence*100:.2f}%")
            print(f"Final Confidence: {confidence*100:.2f}%")
            print(f"{'='*70}\n")
            
            if 'user_id' in session:
                db = get_db()
                user_id = session.get('user_id')
                db.insert_url_check(user_id, url, result, confidence, {'features': features.tolist()})
            
            logger.info(f"URL checked: {url} - Result: {result}")
            return render_template('index.html', xx=round(phishing_prob, 4), url=url, result=result, confidence=round(confidence, 4))
            
        except Exception as e:
            logger.error(f"❌ Error checking URL: {e}")
            print(f"❌ ERROR: {str(e)}")
            print(f"{'='*70}\n")
            flash(f'Error checking URL: {str(e)}', 'danger')
            return render_template('index.html', xx=-1)
            
    return render_template('index.html', xx=-1)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        logger.info(f"Contact form submitted: {name} ({email})")
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    try:
        print("\n" + "="*70)
        print("🚀 D-PHISH - PHISHING DETECTION APPLICATION")
        print("="*70)
        
        db = get_db()
        logger.info("Application started")
        print("✅ Database connected successfully!")
        print("✅ All systems operational!")
        print("="*70 + "\n")
        
        # Get network information
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        port = int(os.environ.get('PORT', 5000))
        
        print(f"📡 Network Information:")
        print(f"   🖥️  Hostname: {hostname}")
        print(f"   🌐 Local IP: {local_ip}")
        print(f"   🔗 Server: http://localhost:{port}")
        print(f"   🔗 Server: http://127.0.0.1:{port}")
        print(f"   🔗 Network: http://{local_ip}:{port}")
        print("="*70 + "\n")
        
        # Run Flask server (debug only when explicitly enabled)
        debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
        app.run(host='0.0.0.0', port=port, debug=debug, use_reloader=False)
        
    except Exception as e:
        logger.error(f"Application startup error: {e}")
        print(f"❌ Startup Error: {e}")
        exit(1)
