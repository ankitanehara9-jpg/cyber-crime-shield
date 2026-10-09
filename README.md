# Cyber Crime Shield (Anti-Fraud & Phishing Detection System)

An automated full-stack cyber intelligence tool designed to detect phishing links, malicious SMS text patterns, and deceptive UPI impersonation handles in real-time.

## Key Features
- **Phishing URL Engine:** Detects suspicious TLDs, keyword spoofing, and raw IP hosting.
- **UPI Fraud Detection:** Identifies deceptive keywords (`nodal`, `refund`, `support`) and disposable account patterns.
- **Automated Police Dossier:** Formats legal evidence reports tailored for the National Cyber Crime Reporting Portal (1930).
- **Evidence Database:** Logs scan timestamps, risk vectors, and confidence scores via SQLite.

## Tech Stack
- **Backend:** Python, FastAPI, Uvicorn, Pydantic
- **Data & Parsing:** tldextract, Regex, SQLite3
- **Frontend:** HTML5, CSS3, Modern JavaScript Fetch API
