import re
from urllib.parse import urlparse

# --- Regular Expressions (Regex) for IOC Extraction ---
# \b means "word boundary" (start or end of a word)
# \d{1,3} means "1 to 3 digits"
# IP Regex: Looks for 4 groups of numbers separated by dots (e.g., 192.168.1.1)
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# URL Regex: Looks for http or https, followed by characters that make up a URL
URL_REGEX = r'https?://[^\s<>"]+|www\.[^\s<>"]+'

# Email Regex: Looks for characters, an @ symbol, and a domain
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Keywords that attackers often use in phishing links
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'password', 'secure', 'bank', 'account']

def extract_iocs(text):
    """
    Scans text for IPs, URLs, and Email addresses using Regex.
    Returns a dictionary of unique IOCs.
    """
    if not text:
        return {"ips": [], "urls": [], "emails": []}
        
    # We use set() to automatically remove duplicates
    ips = set(re.findall(IP_REGEX, text))
    urls = set(re.findall(URL_REGEX, text))
    emails = set(re.findall(EMAIL_REGEX, text))
    
    return {
        "ips": list(ips),
        "urls": list(urls),
        "emails": list(emails)
    }

def analyze_url(url):
    """
    Performs basic security checks on a single URL.
    Returns a list of suspicious reasons, or an empty list if it looks okay.
    """
    reasons = []
    
    # Parse the URL to get just the domain part (e.g., gets 'www.google.com' from 'https://www.google.com/search')
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except Exception:
        domain = ""
        reasons.append("Malformed URL structure")
        
    # Check 1: Is the domain actually a raw IP address?
    # Attackers use IPs because domains can be quickly blacklisted and taken down.
    if re.match(IP_REGEX, domain):
        reasons.append(f"Uses raw IP address ({domain}) instead of a domain name")
        
    # Check 2: Suspicious Keywords in the URL
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        
    # Check 3: Too many subdomains
    # Example: login.chase.com.verification.bad-site.com
    # Splitting by '.' gives us the parts of the domain.
    if domain:
        parts = domain.split('.')
        # If there are 4 or more parts, and it's not just an IP address, flag it.
        if len(parts) >= 4 and not re.match(IP_REGEX, domain):
            reasons.append(f"Unusually high number of subdomains ({len(parts)} parts)")
            
    return reasons

def analyze_all_iocs(parsed_data):
    """
    Extracts IOCs from both the plain text and HTML bodies,
    combines them, and analyzes the URLs for threats.
    """
    plain_text = parsed_data.get("body_plain", "")
    html_text = parsed_data.get("body_html", "")
    
    # Combine text for easier searching
    combined_text = plain_text + " " + html_text
    
    extracted = extract_iocs(combined_text)
    
    # Analyze the URLs
    analyzed_urls = []
    for url in extracted["urls"]:
        suspicious_reasons = analyze_url(url)
        analyzed_urls.append({
            "url": url,
            "is_suspicious": len(suspicious_reasons) > 0,
            "reasons": suspicious_reasons
        })
        
    return {
        "ips": extracted["ips"],
        "emails": extracted["emails"],
        "analyzed_urls": analyzed_urls
    }
