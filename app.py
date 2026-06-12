import streamlit as st
from analyzer.parser import parse_email
from analyzer.auth_checks import analyze_headers
from analyzer.ioc_extractor import analyze_all_iocs
from analyzer.risk_scorer import calculate_risk
from analyzer.threat_intelligence import enrich_iocs
from analyzer.url_fetcher import fetch_eml

def main():
    st.set_page_config(page_title="Phishing Email Analyzer", page_icon="📧", layout="wide")
    
    # --- Sidebar Configuration ---
    with st.sidebar:
        st.header("⚙️ Configuration")
        vt_api_key = st.text_input("VirusTotal API Key (Optional)", type="password", help="Overrides the .env file. Required for Threat Intelligence enrichment.")
        st.warning("ℹ️ **Quota Note:** The public VirusTotal API has strict rate limits (4 requests/minute, 500/day). Use it judiciously!")
    
    st.title("📧 Phishing Email Analyzer")
    st.markdown("""
    Welcome to the **Phishing Email Analyzer**! This tool is designed to help you learn how SOC analysts investigate suspicious emails.
    Upload a `.eml` file below to begin the analysis.
    """)

    # --- File Input Section ---
    st.header("1. File Input")
    
    file_bytes = None
    input_source_name = None
    
    tab_upload, tab_url = st.tabs(["Upload Local File", "Fetch from URL"])
    
    with tab_upload:
        uploaded_file = st.file_uploader("Upload a suspicious email (.eml)", type=["eml"])
        if uploaded_file is not None:
            # If a local file is uploaded, clear any fetched URL state
            st.session_state.fetched_file_bytes = None
            st.session_state.fetched_url = None
            
            st.success("File uploaded successfully!")
            file_bytes = uploaded_file.getvalue()
            input_source_name = uploaded_file.name
            
    with tab_url:
        st.markdown("Fetch a `.eml` file directly from a URL (e.g., a GitHub repository).")
        eml_url = st.text_input("URL to .eml file (HTTPS only)")
        
        if st.button("Fetch & Analyze"):
            if not eml_url:
                st.error("Please enter a URL.")
            else:
                with st.spinner("Fetching file into memory..."):
                    fetch_result = fetch_eml(eml_url)
                    if fetch_result.get("error"):
                        st.error(fetch_result["error"])
                    else:
                        if fetch_result.get("warning"):
                            st.warning(fetch_result["warning"])
                        st.success("File fetched successfully!")
                        st.session_state.fetched_file_bytes = fetch_result["bytes"]
                        st.session_state.fetched_url = eml_url
                        
        if st.session_state.get("fetched_file_bytes") and not file_bytes:
            # If we fetched a file and aren't overriding it with a local upload
            file_bytes = st.session_state.fetched_file_bytes
            input_source_name = st.session_state.fetched_url

    if file_bytes is not None:
        # Reset TI state if a new file is uploaded or fetched
        if "last_file" not in st.session_state or st.session_state.last_file != input_source_name:
            st.session_state.last_file = input_source_name
            st.session_state.enriched_iocs = None
        
        # --- Run Backend Analysis ---
        parsed_data = parse_email(file_bytes)
        auth_data = analyze_headers(parsed_data)
        ioc_data = analyze_all_iocs(parsed_data)
        
        # Calculate risk (will use enriched_iocs if they exist in session state)
        risk_data = calculate_risk(auth_data, ioc_data, st.session_state.get("enriched_iocs"))
        
        # --- Executive Summary Section (BLUF) ---
        st.header("Executive Summary")
        
        severity_color = "green"
        if risk_data['severity'] == "Medium":
            severity_color = "orange"
        elif risk_data['severity'] in ["High", "Critical"]:
            severity_color = "red"
            
        st.markdown(f"### Verdict: **<span style='color:{severity_color}'>{risk_data['severity']} Risk</span>** (Score: {risk_data['score']})", unsafe_allow_html=True)
        
        col_reasons, col_recs = st.columns(2)
        with col_reasons:
            st.subheader("Reasons for Score")
            if risk_data['reasons']:
                for reason in risk_data['reasons']:
                    st.markdown(f"- {reason}")
            else:
                st.success("No suspicious indicators found.")
                
        with col_recs:
            st.subheader("Recommendations")
            for rec in risk_data['recommendations']:
                st.markdown(f"- {rec}")
                
        st.divider()
        
        # --- Email Details Section ---
        st.header("2. Email Details")
        
        # Display the parsed headers using columns for a clean look
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**From:** `{parsed_data.get('From')}`")
            st.markdown(f"**To:** `{parsed_data.get('To')}`")
            st.markdown(f"**Subject:** {parsed_data.get('Subject')}")
        with col2:
            st.markdown(f"**Date:** {parsed_data.get('Date')}")
            st.markdown(f"**Reply-To:** `{parsed_data.get('Reply-To')}`")
            st.markdown(f"**Return-Path:** `{parsed_data.get('Return-Path')}`")
        
        with st.expander("💡 Learning Note: Reply-To & Return-Path vs From"):
            st.markdown("""
            * **From**: The visible sender. Attackers frequently spoof this to look like your boss or a legitimate company.
            * **Reply-To**: If an attacker spoofs the `From` address, they need the victim's reply to go to an inbox they control. They achieve this by setting a different `Reply-To` address.
            * **Return-Path**: This is where automated "bounce" messages are sent. A mismatch here compared to the `From` address can be a strong indicator of spoofing or spam.
            """)
            
        # --- Email Body Section ---
        st.header("3. Email Body Analysis")
        
        tab1, tab2 = st.tabs(["Plain Text", "HTML Source"])
        
        with tab1:
            if parsed_data.get("body_plain"):
                st.text_area("Plain Text Content", value=parsed_data.get("body_plain"), height=300, disabled=True)
            else:
                st.info("No plain text body found in this email.")
                
        with tab2:
            if parsed_data.get("body_html"):
                # For SOC analysis, viewing raw HTML source is safer and allows inspection of hidden links.
                st.text_area("HTML Source Code", value=parsed_data.get("body_html"), height=300, disabled=True)
            else:
                st.info("No HTML body found in this email.")
                
        with st.expander("💡 Learning Note: Plain Text vs HTML"):
            st.markdown("""
            * Emails are often sent as `multipart/alternative`, containing both a Plain Text and an HTML version.
            * **Why check both?** Attackers sometimes put clean text in the Plain Text version to trick spam filters, while hiding malicious links in the HTML version that the victim actually sees.
            """)
            
        # --- Header & Authentication Analysis Section ---
        st.header("4. Header Authentication Analysis")
        
        auth_results = auth_data["auth_results"]
        anomalies = auth_data["anomalies"]
        
        # Display Authentication Results
        st.subheader("Authentication Checks")
        col_spf, col_dkim, col_dmarc = st.columns(3)
        
        def format_auth_result(result):
            if result == "Pass":
                return "✅ Pass"
            elif result == "Fail":
                return "❌ Fail"
            return "❓ Not Found"
            
        with col_spf:
            st.markdown(f"**SPF:** {format_auth_result(auth_results['SPF'])}")
        with col_dkim:
            st.markdown(f"**DKIM:** {format_auth_result(auth_results['DKIM'])}")
        with col_dmarc:
            st.markdown(f"**DMARC:** {format_auth_result(auth_results['DMARC'])}")
            
        with st.expander("💡 Learning Note: SPF, DKIM, and DMARC"):
            st.markdown("""
            * **SPF (Sender Policy Framework)**: A list of IP addresses allowed to send emails on behalf of a domain. If the sender's IP isn't on the list, SPF fails.
            * **DKIM (DomainKeys Identified Mail)**: A cryptographic signature attached to the email. If the email was tampered with in transit, the signature breaks and DKIM fails.
            * **DMARC**: A policy that ties SPF and DKIM together. It tells the receiving server what to do if an email fails these checks (e.g., reject it or mark as spam).
            """)
            
        # Display Anomalies
        st.subheader("Header Anomalies")
        if anomalies:
            for anomaly in anomalies:
                st.warning(f"**{anomaly['type']}**: {anomaly['description']}")
        else:
            st.success("No obvious header anomalies detected (From, Reply-To, and Return-Path align).")
            
        # --- IOC Extraction Section ---
        st.header("5. Indicator of Compromise (IOC) Extraction")
        
        # Display IPs and Emails
        col_ip, col_email = st.columns(2)
        with col_ip:
            st.subheader("Extracted IP Addresses")
            if ioc_data["ips"]:
                for ip in ioc_data["ips"]:
                    st.code(ip)
            else:
                st.info("No IP addresses found in the body.")
                
        with col_email:
            st.subheader("Extracted Email Addresses")
            if ioc_data["emails"]:
                for email in ioc_data["emails"]:
                    st.code(email)
            else:
                st.info("No email addresses found in the body.")
                
        # Display URLs
        st.subheader("Extracted URLs & Local Analysis")
        if ioc_data["analyzed_urls"]:
            for url_obj in ioc_data["analyzed_urls"]:
                if url_obj["is_suspicious"]:
                    st.error(f"🔗 **{url_obj['url']}**")
                    for reason in url_obj["reasons"]:
                        st.markdown(f"- 🚩 {reason}")
                else:
                    st.success(f"🔗 **{url_obj['url']}** (No obvious local threats detected)")
        else:
            st.info("No URLs found in the body.")
            
        with st.expander("💡 Learning Note: IOCs and URL Analysis"):
            st.markdown("""
            * **IOCs (Indicators of Compromise)**: Artifacts like IPs, Domains, and URLs that identify potentially malicious activity.
            * **Why check for subdomains?** Attackers often register a random domain (`attacker.com`) and create long subdomains to fool users into thinking it's legitimate: `secure.login.bank.com.attacker.com`.
            """)
            
        # --- Threat Intelligence Section ---
        st.header("6. Threat Intelligence Enrichment")
        st.markdown("Query external Threat Intelligence providers (like VirusTotal) for the extracted URLs and IPs to get real-world reputation data.")
        
        def handle_ti_check():
            st.session_state.enriched_iocs = enrich_iocs(ioc_data, api_key=vt_api_key)
            
        st.button("🔍 Run Threat Intelligence Check", on_click=handle_ti_check)
                
        # Display TI Results if available
        if st.session_state.get("enriched_iocs") is not None:
            st.subheader("VirusTotal Results")
            if len(st.session_state.enriched_iocs) == 0:
                st.info("No unique IPs or URLs found in the email to check against VirusTotal.")
            else:
                for item in st.session_state.enriched_iocs:
                    if "error" in item:
                        st.error(f"⚠️ **{item['ioc']}** ({item['type']}): {item['error']}")
                    else:
                        verdict = item['verdict']
                        stats_str = f"Malicious: {item['malicious']} | Suspicious: {item['suspicious']} | Harmless: {item['harmless']} | Undetected: {item['undetected']}"
                        
                        if verdict == "malicious":
                            st.error(f"🚨 **{item['ioc']}** ({item['type']}) - **{verdict.upper()}**\n\n*{stats_str}*")
                        elif verdict == "suspicious":
                            st.warning(f"⚠️ **{item['ioc']}** ({item['type']}) - **{verdict.upper()}**\n\n*{stats_str}*")
                        else:
                            st.success(f"✅ **{item['ioc']}** ({item['type']}) - **{verdict.upper()}**\n\n*{stats_str}*")

if __name__ == "__main__":
    main()
