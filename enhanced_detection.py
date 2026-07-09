"""
Enhanced Phishing Detection with Heuristic Analysis
This module provides additional heuristic-based detection for phishing URLs
"""

import re
from urllib.parse import urlparse
import tldextract
from phishing_blocklist import check_blocklist, check_suspicious_patterns

# Known brand names that are commonly impersonated
BRAND_NAMES = [
    'paypal', 'amazon', 'ebay', 'google', 'microsoft', 'apple', 'facebook',
    'instagram', 'twitter', 'linkedin', 'netflix', 'spotify', 'adobe',
    'dropbox', 'github', 'gitlab', 'steam', 'roblox', 'minecraft',
    'trezor', 'ledger', 'metamask', 'coinbase', 'binance', 'kraken',
    'blockchain', 'wallet', 'bank', 'chase', 'wellsfargo', 'citibank',
    'usbank', 'bofa', 'hsbc', 'barclays', 'santander', 'visa', 'mastercard',
    'americanexpress', 'discover', 'venmo', 'cashapp', 'zelle', 'whatsapp',
    'telegram', 'signal', 'discord', 'slack', 'zoom', 'skype', 'yahoo',
    'outlook', 'icloud', 'onedrive', 'gdrive', 'drive', 'login', 'signin',
    'verify', 'secure', 'account', 'update', 'confirm', 'auth', 'support'
]

# Whitelist of legitimate top domains (to avoid false positives)
WHITELIST_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'gstatic.com',
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in',
    'facebook.com', 'fb.com', 'messenger.com', 'instagram.com',
    'twitter.com', 'x.com',
    'linkedin.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com',
    'apple.com', 'icloud.com', 'me.com', 'mac.com',
    'paypal.com', 'paypal.me',
    'netflix.com',
    'ebay.com',
    'yahoo.com',
    'wikipedia.org', 'wikimedia.org',
    'github.com', 'gitlab.com',
    'stackoverflow.com', 'stackexchange.com',
    'reddit.com',
    'whatsapp.com',
    'zoom.us',
    'dropbox.com',
    'adobe.com',
    'spotify.com',
    'twitch.tv',
}

# Legitimate domains for these brands
LEGITIMATE_DOMAINS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in'],
    'google': ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com', 'googleapis.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'msn.com'],
    'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
    'trezor': ['trezor.io'],
    'ledger': ['ledger.com'],
    'metamask': ['metamask.io'],
    'coinbase': ['coinbase.com'],
    'binance': ['binance.com', 'binance.us']
}

# Suspicious TLDs
SUSPICIOUS_TLDS = [
    'xyz', 'top', 'work', 'click', 'link', 'loan', 'win', 'bid', 'racing',
    'accountant', 'science', 'cricket', 'gq', 'ml', 'cf', 'ga', 'tk',
    'men', 'stream', 'download', 'party', 'trade', 'webcam', 'faith',
    'date', 'review', 'country', 'kim', 'uno', 'rocks', 'club', 'cn',
    'ru', 'pw', 'cc', 'ws', 'info', 'biz'
]

# Financial/Banking keywords (high risk if combined with suspicious patterns)
FINANCIAL_KEYWORDS = [
    'bank', 'card', 'credit', 'debit', 'pay', 'payment', 'wallet', 'account',
    'sbi', 'smbc', 'chase', 'citi', 'hsbc', 'barclays', 'santander',
    'visa', 'mastercard', 'amex', 'discover', 'venmo', 'cashapp', 'zelle',
    'paypal', 'stripe', 'square', 'transfer', 'wire', 'swift', 'iban'
]

# Suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'update', 'confirm', 'secure', 'login', 'signin',
    'banking', 'suspended', 'locked', 'restore', 'recover', 'reset',
    'validation', 'authenticate', 'wallet', 'support', 'helpdesk',
    'billing', 'payment', 'refund', 'prize', 'winner', 'claim'
]

def analyze_brand_impersonation(url):
    """
    Detect potential brand impersonation in URL
    Returns (is_suspicious, confidence, reason)
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        ext = tldextract.extract(url)
        
        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        suffix = ext.suffix.lower()
        full_domain = f"{domain}.{suffix}"
        
        # Check for brand names in subdomain or domain
        for brand in BRAND_NAMES:
            # Brand in subdomain but not in legitimate domain
            if brand in subdomain or brand in domain:
                # Check if it's a legitimate domain for this brand
                if brand in LEGITIMATE_DOMAINS:
                    if full_domain not in LEGITIMATE_DOMAINS[brand]:
                        return True, 0.95, f"Brand '{brand}' found in URL but domain is not legitimate"
                else:
                    # Brand found but not in our whitelist of legitimate domains
                    # Check if the full domain contains the brand (e.g., facebook.com is OK)
                    if not (domain == brand):
                        return True, 0.85, f"Suspicious use of brand name '{brand}'"
        
        # Check for multiple brands (very suspicious)
        brands_found = [b for b in BRAND_NAMES if b in hostname]
        if len(brands_found) >= 2:
            return True, 0.98, f"Multiple brand names found: {brands_found}"
        
        return False, 0.0, "No brand impersonation detected"
    except:
        return False, 0.0, "Analysis error"

def calculate_domain_entropy(domain):
    """Calculate Shannon entropy of domain name to detect random strings"""
    import math
    from collections import Counter
    
    if not domain:
        return 0
    
    # Calculate character frequency
    counter = Counter(domain)
    length = len(domain)
    
    # Calculate entropy
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def has_random_patterns(text):
    """Detect random/gibberish strings in domain"""
    # Check for consecutive consonants (common in random strings)
    consonant_pattern = re.search(r'[bcdfghjklmnpqrstvwxyz]{4,}', text.lower())
    if consonant_pattern:
        return True
    
    # Check for very few vowels
    vowels = len(re.findall(r'[aeiou]', text.lower()))
    consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]', text.lower()))
    
    if len(text) > 6 and vowels > 0:
        vowel_ratio = vowels / len(text)
        if vowel_ratio < 0.15:  # Less than 15% vowels
            return True
    
    return False

def analyze_url_patterns(url):
    """
    Analyze URL for suspicious patterns
    Returns (is_suspicious, confidence, reasons[])
    """
    reasons = []
    max_confidence = 0.0
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        path = parsed.path.lower()
        ext = tldextract.extract(url)
        
        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        suffix = ext.suffix.lower()
        
        # 1. Excessive hyphens (common in phishing)
        hyphen_count = hostname.count('-')
        if hyphen_count >= 3:
            reasons.append(f"Excessive hyphens in domain ({hyphen_count})")
            max_confidence = max(max_confidence, 0.8)
        elif hyphen_count >= 2:
            reasons.append(f"Multiple hyphens in domain ({hyphen_count})")
            max_confidence = max(max_confidence, 0.6)
        
        # 2. Suspicious TLD
        if suffix in SUSPICIOUS_TLDS:
            reasons.append(f"Suspicious TLD: .{suffix}")
            max_confidence = max(max_confidence, 0.7)
        
        # 3. Subdomain depth (too many levels)
        subdomain_parts = subdomain.split('.') if subdomain else []
        if len(subdomain_parts) >= 3:
            reasons.append(f"Deep subdomain structure ({len(subdomain_parts)} levels)")
            max_confidence = max(max_confidence, 0.75)
        
        # 4. Suspicious keywords
        suspicious_words = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname or kw in path]
        if len(suspicious_words) >= 2:
            reasons.append(f"Multiple suspicious keywords: {suspicious_words}")
            max_confidence = max(max_confidence, 0.85)
        elif len(suspicious_words) == 1:
            reasons.append(f"Suspicious keyword: {suspicious_words[0]}")
            max_confidence = max(max_confidence, 0.5)
        
        # 5. Numbers in domain (common in phishing)
        if re.search(r'\d{2,}', domain):
            reasons.append("Multiple digits in domain name")
            max_confidence = max(max_confidence, 0.6)
        
        # 6. IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
            reasons.append("IP address used instead of domain")
            max_confidence = max(max_confidence, 0.95)
        
        # 7. Homograph attack (Unicode lookalike characters only)
        # Only check for actual Unicode lookalikes, not normal ASCII characters
        suspicious_chars = re.findall(r'[àáâãäåèéêëìíîïòóôõöùúûüýÿ]', hostname)
        if len(suspicious_chars) >= 2:
            reasons.append("Possible homograph attack (Unicode lookalike characters)")
            max_confidence = max(max_confidence, 0.7)
        
        # 8. Very long domain
        if len(hostname) > 50:
            reasons.append(f"Unusually long hostname ({len(hostname)} chars)")
            max_confidence = max(max_confidence, 0.65)
        
        # 9. @ symbol in URL (URL obfuscation)
        if '@' in url:
            reasons.append("@ symbol in URL (obfuscation technique)")
            max_confidence = max(max_confidence, 0.9)
        
        # 10. Port number (unusual for normal websites)
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            reasons.append(f"Unusual port number: {parsed.port}")
            max_confidence = max(max_confidence, 0.7)
        
        # 11. Random/gibberish domain detection
        if has_random_patterns(domain):
            reasons.append(f"Random/gibberish domain name: {domain}")
            max_confidence = max(max_confidence, 0.75)
        
        # 12. High entropy domain (random characters)
        entropy = calculate_domain_entropy(domain)
        if len(domain) > 5 and entropy > 3.5:
            reasons.append(f"High entropy domain (random characters)")
            max_confidence = max(max_confidence, 0.7)
        
        # 13. Financial keywords combined with suspicious patterns
        financial_kw = [kw for kw in FINANCIAL_KEYWORDS if kw in hostname]
        if financial_kw:
            # If financial keyword found, check for other suspicious signs
            if hyphen_count >= 1 or suffix in SUSPICIOUS_TLDS or has_random_patterns(domain):
                reasons.append(f"Financial keyword with suspicious patterns: {financial_kw}")
                max_confidence = max(max_confidence, 0.85)
        
        # 14. Very short domain with numbers (often phishing)
        if len(domain) <= 6 and re.search(r'\d', domain):
            reasons.append(f"Short domain with numbers: {domain}")
            max_confidence = max(max_confidence, 0.65)
        
        # 15. Subdomain contains suspicious patterns
        if subdomain and has_random_patterns(subdomain):
            reasons.append(f"Random/gibberish subdomain: {subdomain}")
            max_confidence = max(max_confidence, 0.7)
        
        return len(reasons) > 0, max_confidence, reasons
    except:
        return False, 0.0, []

def heuristic_phishing_detection(url):
    """
    Main heuristic detection function
    Returns: (is_phishing, confidence, detailed_report)
    """
    report = {
        'url': url,
        'is_phishing': False,
        'confidence': 0.0,
        'reasons': [],
        'brand_impersonation': None,
        'suspicious_patterns': [],
        'blocklist_match': False,
        'whitelisted': False
    }
    
    try:
        # Parse URL
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        
        # Extract domain
        ext = tldextract.extract(url)
        full_domain = f"{ext.domain}.{ext.suffix}".lower()
        
        # Step 1: Check blocklist FIRST (highest priority - overrides whitelist)
        is_blocked, block_reason = check_blocklist(url, hostname)
        if is_blocked:
            report['blocklist_match'] = True
            report['is_phishing'] = True
            report['confidence'] = 1.0  # 100% confidence for blocklist matches
            report['reasons'].append(f"⛔ {block_reason}")
            report['verdict'] = 'PHISHING'
            return report
        
        # Step 2: Check whitelist (to avoid false positives on known legitimate sites)
        if full_domain in WHITELIST_DOMAINS or hostname in WHITELIST_DOMAINS:
            report['whitelisted'] = True
            report['verdict'] = 'LIKELY SAFE'
            return report
        
        # Step 3: Check suspicious patterns
        is_susp_pattern, pattern_conf, pattern_reason = check_suspicious_patterns(hostname)
        if is_susp_pattern:
            report['is_phishing'] = True
            report['confidence'] = max(report['confidence'], pattern_conf)
            report['reasons'].append(pattern_reason)
        
        # Step 4: Check brand impersonation
        is_brand_attack, brand_conf, brand_reason = analyze_brand_impersonation(url)
        if is_brand_attack:
            report['brand_impersonation'] = {
                'detected': True,
                'confidence': brand_conf,
                'reason': brand_reason
            }
            report['is_phishing'] = True
            report['confidence'] = max(report['confidence'], brand_conf)
            report['reasons'].append(brand_reason)
        
        # Check URL patterns
        has_patterns, pattern_conf, pattern_reasons = analyze_url_patterns(url)
        if has_patterns:
            report['suspicious_patterns'] = pattern_reasons
            report['is_phishing'] = True
            report['confidence'] = max(report['confidence'], pattern_conf)
            report['reasons'].extend(pattern_reasons)
        
        # Final verdict based on combined analysis
        if report['confidence'] >= 0.7:
            report['verdict'] = 'PHISHING'
        elif report['confidence'] >= 0.4:
            report['verdict'] = 'SUSPICIOUS'
        else:
            report['verdict'] = 'LIKELY SAFE'
        
        return report
    except Exception as e:
        report['error'] = str(e)
        return report

# Quick check function for integration
def is_likely_phishing(url, threshold=0.6):
    """
    Quick check if URL is likely phishing
    Returns: (bool, confidence)
    """
    report = heuristic_phishing_detection(url)
    return report['is_phishing'] and report['confidence'] >= threshold, report['confidence']
