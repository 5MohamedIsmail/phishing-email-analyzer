import os
import requests
import base64
from dotenv import load_dotenv

# Load environment variables (like VIRUSTOTAL_API_KEY) from .env file
load_dotenv()

VT_API_URL = "https://www.virustotal.com/api/v3"

def get_vt_api_key(session_key=None):
    """
    Retrieves the VirusTotal API key.
    Prioritizes the session key (from Streamlit UI) over the .env file.
    """
    if session_key:
        return session_key
    return os.environ.get("VIRUSTOTAL_API_KEY")

def _make_vt_request(endpoint, api_key):
    """
    Helper function to make requests to the VirusTotal API.
    Handles the headers and basic error checking.
    """
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    url = f"{VT_API_URL}{endpoint}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        # Return the JSON response, or an error dictionary if it fails
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            # 404 means the indicator is not in VT's database yet.
            # We add a 'data' key so it bypasses the strict error checks 
            # and gets parsed as 'undetected'.
            return {"data": None, "error": "Not Found (404)"}
        else:
            return {"error": f"API Error: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def _parse_vt_response(vt_data, ioc_value, ioc_type):
    """
    Parses the standard VirusTotal response to extract the verdict stats.
    """
    # If the API call failed or the IOC isn't known to VT yet
    if "error" in vt_data or "data" not in vt_data:
        return _format_standard_output(ioc_value, ioc_type, 0, 0, 0, 0, "undetected")

    try:
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        # Verdict Logic per SOC requirements
        verdict = "clean"
        if malicious >= 5:
            verdict = "malicious"
        elif suspicious > 0 or malicious > 0:
            # If malicious is > 0 but < 5, we flag as suspicious
            verdict = "suspicious"
            
        return _format_standard_output(ioc_value, ioc_type, malicious, suspicious, harmless, undetected, verdict)
    except KeyError:
        return _format_standard_output(ioc_value, ioc_type, 0, 0, 0, 0, "undetected")

def _format_standard_output(ioc, ioc_type, malicious, suspicious, harmless, undetected, verdict):
    """
    Returns the standard IOC dictionary format required by the Threat Intel layer.
    """
    return {
        "ioc": ioc,
        "type": ioc_type,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "verdict": verdict,
        "source": "virustotal"
    }

# --- Exported Functions ---

def check_ip(ip, api_key=None):
    """Checks an IP address against VirusTotal."""
    key = get_vt_api_key(api_key)
    if not key:
        return {"error": "Missing API Key"}
    
    endpoint = f"/ip_addresses/{ip}"
    data = _make_vt_request(endpoint, key)
    # Check if we got an error before parsing
    if "error" in data and not "data" in data:
         return {"error": data["error"]}
         
    return _parse_vt_response(data, ip, "ip")

def check_domain(domain, api_key=None):
    """Checks a domain against VirusTotal."""
    key = get_vt_api_key(api_key)
    if not key:
        return {"error": "Missing API Key"}
        
    endpoint = f"/domains/{domain}"
    data = _make_vt_request(endpoint, key)
    if "error" in data and not "data" in data:
         return {"error": data["error"]}
         
    return _parse_vt_response(data, domain, "domain")

def check_url(url, api_key=None):
    """
    Checks a URL against VirusTotal.
    Crucial Fix: VT v3 requires the URL to be URL-safe Base64 encoded WITHOUT padding (=).
    """
    key = get_vt_api_key(api_key)
    if not key:
        return {"error": "Missing API Key"}
        
    # URL-safe Base64 encode the URL, decode to string, and remove padding '='
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    endpoint = f"/urls/{encoded_url}"
    data = _make_vt_request(endpoint, key)
    if "error" in data and not "data" in data:
         return {"error": data["error"]}
         
    return _parse_vt_response(data, url, "url")
