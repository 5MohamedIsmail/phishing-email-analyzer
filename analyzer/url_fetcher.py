import requests
from urllib.parse import urlparse

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB in bytes
TRUSTED_DOMAINS = ["raw.githubusercontent.com"]

def format_github_url(url):
    """
    If the URL is a standard GitHub blob link, convert it to the raw format.
    Example: https://github.com/user/repo/blob/main/file.eml -> https://raw.githubusercontent.com/user/repo/main/file.eml
    """
    if url.startswith("https://github.com/") and "/blob/" in url:
        url = url.replace("https://github.com/", "https://raw.githubusercontent.com/")
        url = url.replace("/blob/", "/", 1)
    return url

def fetch_eml(url):
    """
    Fetches the .eml file from the given URL.
    Returns a dict with 'bytes', 'error', and 'warning' keys.
    """
    result = {"bytes": None, "error": None, "warning": None}
    
    # 1. Enforce HTTPS
    if not url.startswith("https://"):
        result["error"] = "Only HTTPS URLs are permitted for security reasons."
        return result
        
    # 2. Format GitHub URLs
    url = format_github_url(url)
    
    # 3. Check Domain Trust
    try:
        domain = urlparse(url).netloc
        if domain not in TRUSTED_DOMAINS:
            result["warning"] = f"Untrusted domain ({domain}). Proceed with caution, as this file was fetched from an unverified source."
    except Exception:
        result["error"] = "Invalid URL format."
        return result
        
    # 4. Stream Download & Enforce Size Limit
    file_data = bytearray()
    try:
        with requests.get(url, stream=True, timeout=10) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    file_data.extend(chunk)
                    if len(file_data) > MAX_FILE_SIZE:
                        result["error"] = "File size exceeds the 5MB limit. Aborting fetch to prevent memory exhaustion."
                        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"Failed to fetch file: {str(e)}"
        return result
        
    # 5. Basic Content Validation
    # We decode the first 2KB to check for standard email headers.
    content_snippet = file_data[:2048].decode('utf-8', errors='ignore').lower()
    
    # Very basic heuristic to check if it looks like an email.
    if "from:" not in content_snippet and "date:" not in content_snippet and "return-path:" not in content_snippet and "received:" not in content_snippet:
        result["error"] = "The fetched content does not appear to be a valid email (missing standard headers like 'From:', 'Date:', or 'Received:')."
        return result
        
    result["bytes"] = bytes(file_data)
    return result
