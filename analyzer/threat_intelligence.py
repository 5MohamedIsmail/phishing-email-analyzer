from analyzer import virustotal_client

# Simple in-memory cache for the session. 
# Key: IOC string, Value: Enriched dictionary
_ioc_cache = {}

def enrich_iocs(ioc_data, api_key=None):
    """
    Takes the raw extracted IOCs and queries external Threat Intelligence (VirusTotal).
    Uses an in-memory cache to prevent duplicate queries for the same IOC.
    
    Returns a list of enriched IOC dictionaries.
    """
    enriched_results = []
    
    # 1. Enrich IPs
    # We use set() to ensure we only process unique IPs from the list
    for ip in set(ioc_data.get("ips", [])):
        if ip in _ioc_cache:
            enriched_results.append(_ioc_cache[ip])
            continue
            
        result = virustotal_client.check_ip(ip, api_key)
        # Only cache and append if it didn't error (e.g., missing API key)
        if "error" not in result:
            _ioc_cache[ip] = result
            enriched_results.append(result)
        else:
            # If there's an error, we can return it or just log it. We'll append it so the UI can show the error.
            enriched_results.append({"ioc": ip, "type": "ip", "error": result["error"]})
            
    # 2. Enrich URLs
    # Extract the raw URLs from the analyzed_urls list
    urls = [url_obj["url"] for url_obj in ioc_data.get("analyzed_urls", [])]
    
    for url in set(urls):
        if url in _ioc_cache:
            enriched_results.append(_ioc_cache[url])
            continue
            
        result = virustotal_client.check_url(url, api_key)
        if "error" not in result:
            _ioc_cache[url] = result
            enriched_results.append(result)
        else:
            enriched_results.append({"ioc": url, "type": "url", "error": result["error"]})
            
    # Emails and Hashes are skipped for now per the requirements.
            
    return enriched_results
