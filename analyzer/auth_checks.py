import re

def parse_auth_header(auth_header):
    """
    Parses the Authentication-Results header to find SPF, DKIM, and DMARC results.
    We use simple string matching because different mail servers (Gmail, Outlook) 
    format this header slightly differently.
    """
    results = {
        "SPF": "Not Found",
        "DKIM": "Not Found",
        "DMARC": "Not Found"
    }
    
    if not auth_header or auth_header == "Not Found":
        return results
        
    # Convert to lowercase to make searching easier
    auth_header_lower = auth_header.lower()
    
    # Check SPF
    if "spf=pass" in auth_header_lower:
        results["SPF"] = "Pass"
    elif "spf=fail" in auth_header_lower or "spf=softfail" in auth_header_lower:
        results["SPF"] = "Fail"
        
    # Check DKIM
    if "dkim=pass" in auth_header_lower:
        results["DKIM"] = "Pass"
    elif "dkim=fail" in auth_header_lower:
        results["DKIM"] = "Fail"
        
    # Check DMARC
    if "dmarc=pass" in auth_header_lower:
        results["DMARC"] = "Pass"
    elif "dmarc=fail" in auth_header_lower:
        results["DMARC"] = "Fail"

    return results

def extract_email_address(header_value):
    """
    Helper function to extract just the email address from a header.
    Often headers look like: "John Doe <john.doe@example.com>"
    We just want the "john.doe@example.com" part to do comparisons.
    """
    if not header_value or header_value == "Not Found":
        return None
        
    # Regular expression to find text between < and >
    match = re.search(r'<([^>]+)>', header_value)
    if match:
        return match.group(1).lower().strip()
    
    # If there are no brackets, assume the whole string is the email address
    return header_value.lower().strip()

def analyze_headers(parsed_data):
    """
    Performs security checks on the headers extracted from the email.
    Returns authentication results and any detected anomalies.
    """
    raw_message = parsed_data["raw_message"]
    
    # Get the Authentication-Results header. It might be missing.
    auth_header = raw_message.get("Authentication-Results", "Not Found")
    auth_results = parse_auth_header(auth_header)
    
    anomalies = []
    
    # Extract the clean email addresses for comparison
    from_address = extract_email_address(parsed_data.get("From"))
    reply_to = extract_email_address(parsed_data.get("Reply-To"))
    return_path = extract_email_address(parsed_data.get("Return-Path"))
    
    # Check for From / Reply-To mismatch
    if from_address and reply_to:
        if from_address != reply_to:
            anomalies.append({
                "type": "Reply-To Mismatch",
                "description": f"The From address ({from_address}) does not match the Reply-To address ({reply_to}). This is a common tactic where attackers spoof the sender but want your reply to go to them."
            })
            
    # Check for From / Return-Path mismatch
    if from_address and return_path:
        if from_address != return_path:
            anomalies.append({
                "type": "Return-Path Mismatch",
                "description": f"The From address ({from_address}) does not match the Return-Path ({return_path}). This means if the email bounces, the error goes to a different server. Often indicates spoofing."
            })
            
    return {
        "auth_results": auth_results,
        "anomalies": anomalies,
        "raw_auth_header": auth_header
    }
