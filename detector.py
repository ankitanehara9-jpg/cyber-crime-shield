import re
import datetime
import tldextract

SUSPICIOUS_KEYWORDS = [
    "kyc", "pan", "electricity", "bill", "refund", "lottery",
    "apk", "login", "secure", "bonus", "free", "gift", "update"
]

SUSPICIOUS_TLDS = ["top", "xyz", "live", "tk", "ml", "ga", "cf", "gq", "click"]

# Scammer UPI IDs aksar fake banking/support handles bna kar aati hain
SUSPICIOUS_UPI_HANDLES = ["support", "refund", "helpline", "nodal", "customercare", "reward", "lottery"]

def generate_police_complaint(target_evidence: str, reasons: list, message: str, fraud_type: str) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reasons_str = "\n".join([f"- {r}" for r in reasons])
    
    draft = f"""--- FORMAL CYBER FRAUD EVIDENCE REPORT ---
Incident Date & Time: {timestamp}
Suspected Fraud Mechanism: {fraud_type}

Incident Details:
Deceptive message received:
"{message}"

Technical Evidence Collected:
Identified Fraud Marker: {target_evidence}
Technical Risk Flags:
{reasons_str}

Requested Action:
Kindly blacklist the destination entity (Domain/UPI beneficiary) and freeze the associated banking node under the Information Technology Act.
------------------------------------------"""
    return draft

def scan_text_and_url(text: str) -> dict:
    risk_score = 0
    flags = []
    evidence_target = ""
    fraud_type = "Generic Cyber Fraud"

    # 1. URL Detection
    url_pattern = r'https?://[^\s]+'
    found_urls = re.findall(url_pattern, text)

    # 2. UPI ID Detection (e.g. username@bank)
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
    found_upis = re.findall(upi_pattern, text)

    if found_urls:
        fraud_type = "Phishing / Fake Link Scam"
        target_url = found_urls[0]
        evidence_target = target_url
        extracted = tldextract.extract(target_url)
        domain_name = extracted.domain.lower()
        suffix = extracted.suffix.lower()

        if suffix in SUSPICIOUS_TLDS:
            risk_score += 40
            flags.append(f"Suspicious Top-Level Domain (.{suffix}) detect hui.")

        for word in SUSPICIOUS_KEYWORDS:
            if word in domain_name:
                risk_score += 35
                flags.append(f"Domain me phishing keyword mila: '{word}'")
                break

        if "-" in domain_name or any(char.isdigit() for char in domain_name):
            risk_score += 20
            flags.append("Domain name me numbers ya unusual hyphens hain.")

        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, target_url):
            risk_score += 50
            flags.append("Direct IP address based URL hai (Malicious server risk).")

    elif found_upis:
        fraud_type = "Financial Fraud / Impersonation UPI Mule"
        target_upi = found_upis[0]
        evidence_target = f"UPI ID: {target_upi}"
        username, bank_handle = target_upi.split("@")

        for handle in SUSPICIOUS_UPI_HANDLES:
            if handle in username.lower():
                risk_score += 65
                flags.append(f"UPI ID me deceptive impersonation term mila: '{handle}'")

        if any(char.isdigit() for char in username) and len(username) > 8:
            risk_score += 25
            flags.append("Disposable/Random numeric pattern in UPI identifier.")

    else:
        return {
            "status": "Safe",
            "risk_score": "0%",
            "verdict": "NO RISKS FOUND",
            "flags": ["Message me koi suspicious link ya UPI ID nahi mila."],
            "complaint_draft": None
        }

    risk_score = min(risk_score, 100)
    complaint_draft = None

    if risk_score >= 60:
        verdict = "DANGER / HIGH FRAUD RISK"
        complaint_draft = generate_police_complaint(evidence_target, flags, text, fraud_type)
    elif risk_score >= 30:
        verdict = "SUSPICIOUS / BE CAREFUL"
    else:
        verdict = "LIKELY SAFE"

    return {
        "evidence_target": evidence_target,
        "risk_score": f"{risk_score}%",
        "verdict": verdict,
        "flags": flags,
        "complaint_draft": complaint_draft
    }
