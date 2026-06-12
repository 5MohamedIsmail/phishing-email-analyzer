# Phishing Email Analyzer

This project simulates a SOC-style phishing email analysis workflow for educational and portfolio purposes. Designed to replicate real-world cybersecurity investigation techniques, the application provides a safe, fully in-memory environment to analyze suspicious `.eml` files without relying on automated enterprise black-boxes.

## 🌐 Live Demo
* **Read the full project breakdown:** [https://5mohamedismail.github.io](https://5mohamedismail.github.io)
* **Live App:** *(Deployment link coming soon)*

## 🧠 Why I Built This
In modern Security Operations Centers (SOCs), analyzing malicious emails requires piecing together disparate data points—from header manipulation to hidden HTML links. I built this tool to simulate a real security analysis workflow and gain hands-on experience with threat intelligence enrichment, IOC extraction, and risk-based decision making.

## 🏗️ Architecture & System Design
```text
Email Upload → Parser → IOC Extractor → Threat Intelligence → Risk Engine → UI Dashboard
```

## 🔍 SOC Analyst Workflow Simulation
This tool replicates the cognitive workflow of a security analyst investigating an incident:
1. Receive suspicious email (`.eml`) safely into memory.
2. Parse email headers, plain text, and HTML bodies.
3. Extract Indicators of Compromise (IOCs) such as IPs, URLs, and domains.
4. Enrich IOCs using Threat Intelligence (VirusTotal).
5. Analyze authentication results (SPF, DKIM, DMARC) to detect spoofing.
6. Calculate a risk score based on rule anomalies and intelligence hits.
7. Generate a final verdict (Low / Medium / High / Critical) with actionable recommendations.

## 💡 Engineering Learning Outcomes
Developing this system strengthened my understanding of key security engineering concepts:
* **Email Authentication Analysis:** Verifying SPF, DKIM, and DMARC alignments to spot sophisticated spoofing techniques.
* **IOC Extraction Techniques:** Using complex Regex and structured parsing to safely strip malicious indicators from multipart payloads.
* **Threat Intelligence Integration:** Automating global reputation lookups using the VirusTotal API.
* **Risk-Based Decision Making:** Building a heuristic scoring engine that weighs multiple risk factors simultaneously.
* **SOC Workflow Simulation:** Adopting an investigation mindset to present data like a SIEM dashboard.
* **API Resiliency:** Handling rate limits and graceful failure states for external integrations.

## ✨ Key Features
* **Dual Input Processing:** Safely ingest a local `.eml` file or fetch one directly from an HTTPS URL (such as a GitHub raw blob).
* **Authentication Checking:** Automatically checks if the SPF, DKIM, and DMARC records pass, fail, or exhibit anomalies.
* **Safe HTML Viewing:** Safely view the raw HTML of an email to hunt for hidden links or tracking pixels.
* **IOC Extraction:** Pulls out all unique IP addresses, email addresses, and URLs from the email body.
* **Risk Scoring Engine:** Applies a dynamic scoring system to rate the email's risk severity.
* **Threat Intelligence:** Uses the VirusTotal API to look up the reputation of extracted URLs and IPs dynamically.

## 🛠️ Tech Stack
* **Backend:** Python (Email parsing, IOC extraction, Risk scoring engine)
* **UI:** Streamlit (Dashboard and interactive presentation)
* **Threat Intelligence:** VirusTotal API
* **Security Concepts:** SPF, DKIM, DMARC analysis, Incident Triage
* **Data Handling:** Regex-based IOC extraction, secure in-memory file parsing

## 📁 Project Structure
```text
Phishing Email Analyzer/
├── analyzer/
│   ├── auth_checks.py          # Validates SPF, DKIM, DMARC anomalies
│   ├── ioc_extractor.py        # Extracts IPs, URLs, and Emails via Regex
│   ├── parser.py               # Parses raw .eml bytes into structured data
│   ├── risk_scorer.py          # Calculates the threat risk score
│   ├── threat_intelligence.py  # Caching and enrichment layer for Threat Intel
│   ├── url_fetcher.py          # Fetches remote .eml files safely into memory
│   └── virustotal_client.py    # VirusTotal API client integration
├── assets/
│   └── screenshots/            # UI screenshots for documentation
├── app.py                      # Main Streamlit application
└── requirements.txt            # Python dependencies
```

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/phishing-email-analyzer.git
   cd phishing-email-analyzer
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 💻 How to Run Locally

Run the application using the following command:
```bash
python -m streamlit run app.py
```
The SOC dashboard will open automatically in your browser at `http://localhost:8501`.

## 🛡️ Optional VirusTotal Setup

To enable the Threat Intelligence checks, you'll need a free VirusTotal API key.
1. Create a `.env` file in the root folder.
2. Add your key like this: `VIRUSTOTAL_API_KEY=your_key_here`
*(You can also paste the key securely into the app's sidebar during runtime.)*

## 📸 Screenshots

*(Add your screenshots to the `assets/screenshots/` folder to display them here)*

**Home Page & File Upload**
![Home Page](assets/screenshots/home-page.png)

**Executive Summary & Risk Score**
![Risk Score](assets/screenshots/risk-score.png)

**Email Details & Header Analysis**
![Header Analysis](assets/screenshots/header-analysis.png)

**Extracted IOCs**
![IOC Results](assets/screenshots/ioc-results.png)

**VirusTotal Enrichment**
![VirusTotal Results](assets/screenshots/virustotal-results.png)

## 🔮 Future Improvements
* Parse and analyze `.zip` and `.pdf` attachments.
* Add support for additional threat intelligence sources like AbuseIPDB and AlienVault OTX.
* Generate exportable PDF incident response reports.

## 📄 License
This project is licensed under the MIT License.
