"""
Phishing URL Blocklist and Reputation System
This module maintains a list of known phishing domains
"""

# Known phishing domains (from real phishing databases)
KNOWN_PHISHING_DOMAINS = {
    'choixdescreneaux.com',
    'choisislecreneau.com',
    'cambiasso.s3.eu-north-1.amazonaws.com',
    'santaeulaliaonline.com',
    'sbisec-jp.wx99h.com',
    'sbisec-co.sctghny.cn',
    'smbc-card.vxdzvl.com',
    'smbc-card.youzjk.com',
    'smbcvpass.xyz',
    'smbcyberadvisor.com',
    'wx99h.com',
    'sctghny.cn',
    'vxdzvl.com',
    'youzjk.com'
}

# Suspicious patterns that should trigger warnings
SUSPICIOUS_DOMAIN_PATTERNS = [
    # French delivery/scheduling phishing patterns
    r'.*choix.*creneau.*',
    r'.*rendez.*vous.*',
    r'.*livraison.*',
    r'.*tracking.*colis.*',
    
    # Banking/Financial phishing patterns
    r'.*bank.*login.*',
    r'.*secure.*account.*',
    r'.*verify.*payment.*',
    r'.*card.*update.*',
    
    # Generic phishing patterns
    r'.*account.*verify.*',
    r'.*suspended.*account.*',
    r'.*confirm.*identity.*',
]

def check_blocklist(url, hostname):
    """
    Check if URL or hostname is in blocklist
    Returns: (is_blocked, reason)
    """
    import tldextract
    
    # Extract domain
    ext = tldextract.extract(url)
    full_domain = f"{ext.domain}.{ext.suffix}".lower()
    hostname_lower = hostname.lower()
    
    # Check exact match
    if full_domain in KNOWN_PHISHING_DOMAINS or hostname_lower in KNOWN_PHISHING_DOMAINS:
        return True, f"Domain '{full_domain}' is in phishing blocklist"
    
    # Check if subdomain + domain matches
    if hostname_lower in KNOWN_PHISHING_DOMAINS:
        return True, f"Hostname '{hostname_lower}' is in phishing blocklist"
    
    return False, ""

def check_suspicious_patterns(hostname):
    """
    Check if hostname matches suspicious patterns
    Returns: (is_suspicious, confidence, reason)
    """
    import re
    
    hostname_lower = hostname.lower()
    
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.match(pattern, hostname_lower):
            return True, 0.75, f"Matches suspicious pattern: {pattern}"
    
    return False, 0.0, ""
