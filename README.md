# Phishing Email Analyzer

A professional, fully-featured cybersecurity tool designed to help Security Operations Center (SOC) analysts, security researchers, and students safely investigate suspicious `.eml` files.

## 🛡️ Why This Project Was Built
Analyzing malicious emails manually is dangerous and time-consuming. SOC analysts typically have to manually extract headers, identify spoofing attempts, parse out hidden URLs from HTML bodies, and query threat intelligence platforms without accidentally clicking malicious links. 

This project automates that entire workflow in a clean, terminal-inspired dashboard—keeping all processing strictly in-memory without saving malicious files to your hard drive.

## ✨ Key Features
*   **Dual Input Methods**: Safely upload a local `.eml` file or fetch it directly from an HTTPS URL (such as a GitHub raw blob).
*   **Authentication Checking**: Automatically validates SPF, DKIM, and DMARC alignments, flagging any spoofing anomalies between `From`, `Reply-To`, and `Return-Path` headers.
*   **Safe HTML Extraction**: Dissects `multipart/alternative` boundaries to safely display the underlying HTML source code so you can hunt for hidden tracking pixels and deceptive links.
*   **Automated IOC Extraction**: Uses regex to pull out all unique IP addresses, Email Addresses, and URLs embedded in the email body.
*   **Local Risk Scoring**: Applies a proprietary heuristic scoring algorithm to classify the email risk severity (Clean, Low, Medium, High, Critical) based on missing authentication, suspicious URL patterns, and mismatched sender headers.
*   **Threat Intelligence Enrichment**: Integrates directly with the VirusTotal v3 API to look up the global reputation of extracted URLs and IP addresses, updating the overall risk score dynamically.

## 🛠️ Tech Stack
*   **Python 3** (Core logic and parsing)
*   **Streamlit** (Frontend Dashboard UI)
*   **Requests** (HTTP and API Interactions)
*   **Python-Dotenv** (Environment variable management)
*   **VirusTotal API** (External Threat Intelligence)

## 📁 Project Structure
```text
Phishing Email Analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── auth_checks.py          # Validates SPF, DKIM, DMARC, and header anomalies
│   ├── ioc_extractor.py        # Extracts IPs, URLs, and Emails from text/html bodies
│   ├── parser.py               # Dissects raw .eml bytes into readable components
│   ├── risk_scorer.py          # Calculates the local and enriched threat risk score
│   ├── threat_intelligence.py  # Caching and integration layer for Threat Intel
│   ├── url_fetcher.py          # Securely fetches remote .eml files into memory
│   └── virustotal_client.py    # Direct client for the VirusTotal v3 API
├── assets/
│   └── screenshots/            # UI placeholders for documentation
├── app.py                      # Main Streamlit application and UI
├── requirements.txt            # Python dependencies
└── .env                        # Secure configuration (not committed)
```

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/phishing-email-analyzer.git
   cd phishing-email-analyzer
   ```

2. **Create a virtual environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **(Optional) Setup Threat Intelligence:**
   To enable Threat Intelligence enrichment, you need a free VirusTotal API key.
   * Create a `.env` file in the root directory.
   * Add your key: `VIRUSTOTAL_API_KEY=your_key_here`
   * *Alternatively, you can securely paste your key into the app's sidebar during runtime.*

## 💻 How to Run Locally

Run the Streamlit application using the following command:

```bash
python -m streamlit run app.py
```
The dashboard will open automatically in your default web browser at `http://localhost:8501`.

## 📸 Screenshots

*(Placeholders for future screenshots)*

### Executive Summary & Risk Score
![Risk Score](assets/screenshots/risk-score.png)

### Email Header Analysis
![Header Analysis](assets/screenshots/header-analysis.png)

### Extracted Indicators of Compromise
![IOC Results](assets/screenshots/ioc-results.png)

### VirusTotal Enrichment
![VirusTotal Results](assets/screenshots/virustotal-results.png)

## 🔮 Future Improvements
*   **Attachment Sandboxing**: Add parsing and hashing for `.zip`, `.pdf`, and `.docx` attachments to analyze malware signatures.
*   **Extended Threat Intel**: Support for AbuseIPDB and AlienVault OTX.
*   **Export to PDF**: Generate printable incident response reports directly from the dashboard.

## 📄 License
This project is licensed under the MIT License. See the `LICENSE` file for details.
