def calculate_risk(auth_data, ioc_data, enriched_iocs=None):
    """
    Calculates a risk score based on the findings from header analysis and IOC extraction.
    If enriched_iocs (from Threat Intelligence) are provided, they significantly impact the score.
    Returns the score, severity level, reasons, and recommendations.
    """
    score = 0
    reasons = []
    recommendations = []
    
    # 1. Analyze Authentication Results
    auth_results = auth_data.get("auth_results", {})
    if auth_results.get("SPF") == "Fail":
        score += 20
        reasons.append("SPF check failed (sender IP not authorized).")
    if auth_results.get("DKIM") == "Fail":
        score += 20
        reasons.append("DKIM check failed (email signature invalid/tampered).")
    if auth_results.get("DMARC") == "Fail":
        score += 20
        reasons.append("DMARC check failed.")
        
    # 2. Analyze Header Anomalies
    for anomaly in auth_data.get("anomalies", []):
        if anomaly["type"] == "Reply-To Mismatch":
            score += 15
            reasons.append("Reply-To address differs from the From address.")
        if anomaly["type"] == "Return-Path Mismatch":
            score += 15
            reasons.append("Return-Path address differs from the From address.")
            
    # 3. Analyze URLs
    suspicious_url_count = 0
    for url_obj in ioc_data.get("analyzed_urls", []):
        if url_obj["is_suspicious"]:
            suspicious_url_count += 1
            
    if suspicious_url_count > 0:
        score += 20
        reasons.append(f"Found {suspicious_url_count} suspicious URL(s) in the body.")
        recommendations.append("Do NOT click any links in the email.")
        recommendations.append("Block the suspicious domains/IPs on your firewall.")
        
    # 4. Analyze Enriched Threat Intelligence (VirusTotal)
    if enriched_iocs:
        vt_malicious_count = 0
        vt_suspicious_count = 0
        for ioc in enriched_iocs:
            if ioc.get("verdict") == "malicious":
                vt_malicious_count += 1
            elif ioc.get("verdict") == "suspicious":
                vt_suspicious_count += 1
                
        if vt_malicious_count > 0:
            # We add +40 per malicious indicator, but cap the total score effect if needed
            score += (40 * vt_malicious_count) 
            reasons.append(f"Threat Intel: Found {vt_malicious_count} MALICIOUS indicator(s).")
            if "Block the suspicious domains/IPs on your firewall." not in recommendations:
                recommendations.append("Block the malicious domains/IPs on your firewall/proxy immediately.")
                
        if vt_suspicious_count > 0:
            score += (20 * vt_suspicious_count) 
            reasons.append(f"Threat Intel: Found {vt_suspicious_count} SUSPICIOUS indicator(s).")
            
    # 5. Multi-indicator Bonus
    if len(reasons) >= 3:
        score += 10
        reasons.append("Multiple indicators of compromise detected (+10 points).")
        
    # Determine Severity
    if score <= 25:
        severity = "Low"
    elif score <= 50:
        severity = "Medium"
    elif score <= 75:
        severity = "High"
    else:
        severity = "Critical"
        
    # Base recommendations
    if severity in ["High", "Critical"]:
        recommendations.append("Report this email to the security team immediately.")
        recommendations.append("Delete the email from your inbox.")
    elif severity == "Medium":
        recommendations.append("Proceed with caution. Verify the sender out-of-band (e.g., via phone call).")
    else:
        recommendations.append("No major threats detected, but always remain vigilant.")
        
    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
        "recommendations": recommendations
    }
