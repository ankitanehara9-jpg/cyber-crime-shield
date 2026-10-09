from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from detector import scan_text_and_url
from database import init_db, log_scan, get_recent_scans

app = FastAPI(title="Cyber Crime Shield")

init_db()

class FraudCheckRequest(BaseModel):
    message_content: str

@app.post("/scan-fraud")
def scan_fraud(data: FraudCheckRequest):
    result = scan_text_and_url(data.message_content)
    log_scan(
        result.get("evidence_target"),
        result.get("risk_score"),
        result.get("verdict"),
        data.message_content
    )
    return result

@app.get("/recent-scans")
def fetch_recent():
    scans = get_recent_scans()
    return [{"timestamp": s[0], "target": s[1], "score": s[2], "verdict": s[3], "excerpt": s[4]} for s in scans]

@app.get("/", response_class=HTMLResponse)
def home_ui():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cyber Crime Shield | Anti-Fraud Detection</title>
        <style>
            * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
            body { background: #0f172a; color: #f8fafc; display: flex; justify-content: center; padding: 40px 16px; margin: 0; }
            .container { max-width: 720px; width: 100%; background: #1e293b; padding: 32px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            h1 { font-size: 24px; margin-bottom: 8px; color: #38bdf8; }
            p.subtitle { color: #94a3b8; font-size: 14px; margin-top: 0; margin-bottom: 24px; }
            textarea { width: 100%; height: 100px; padding: 14px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 14px; resize: vertical; outline: none; }
            textarea:focus { border-color: #38bdf8; }
            button.main-btn { margin-top: 14px; width: 100%; padding: 12px; font-size: 15px; font-weight: 600; background: #0284c7; color: #fff; border: none; border-radius: 8px; cursor: pointer; transition: 0.2s; }
            button.main-btn:hover { background: #0369a1; }
            .result-card { margin-top: 24px; padding: 20px; border-radius: 8px; background: #0f172a; display: none; }
            .score-badge { display: inline-block; padding: 6px 12px; border-radius: 6px; font-weight: bold; margin-bottom: 12px; }
            .danger { background: #ef4444; color: #fff; }
            .warning { background: #f59e0b; color: #fff; }
            .safe { background: #22c55e; color: #fff; }
            ul { margin: 10px 0; padding-left: 20px; color: #cbd5e1; font-size: 14px; }
            pre { background: #1e293b; padding: 14px; border-radius: 6px; color: #e2e8f0; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
            .copy-btn { background: #334155; color: #38bdf8; border: 1px solid #475569; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; margin-bottom: 8px; }
            .copy-btn:hover { background: #475569; }
            .history-table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
            .history-table th, .history-table td { padding: 10px; border-bottom: 1px solid #334155; text-align: left; }
            .history-table th { color: #94a3b8; font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cyber Crime Shield</h1>
            <p class="subtitle">Suspicious SMS, WhatsApp link, ya fake UPI ID scan karein.</p>
            <textarea id="messageInput" placeholder="Message, fraud link, ya scam UPI ID yahan paste karein..."></textarea>
            <button class="main-btn" onclick="scanFraud()">Scan Now</button>

            <div id="resultCard" class="result-card">
                <div id="badge" class="score-badge"></div>
                <div id="flagsSection"></div>
                <div id="draftSection" style="margin-top: 16px; display: none;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: #38bdf8; font-size: 13px;">Auto-Generated Police Dossier:</strong>
                        <button class="copy-btn" id="copyBtn" onclick="copyReport()">Copy Dossier</button>
                    </div>
                    <pre id="draftText"></pre>
                </div>
            </div>

            <div style="margin-top: 36px;">
                <h3 style="color: #cbd5e1; font-size: 16px; margin-bottom: 8px;">Recent Threat Log (Live Evidence Database)</h3>
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Target Marker</th>
                            <th>Risk</th>
                        </tr>
                    </thead>
                    <tbody id="historyBody"></tbody>
                </table>
            </div>
        </div>

        <script>
            async function loadHistory() {
                const res = await fetch('/recent-scans');
                const data = await res.json();
                const tbody = document.getElementById('historyBody');
                tbody.innerHTML = data.map(item => `
                    <tr>
                        <td style="color: #94a3b8;">${item.timestamp}</td>
                        <td style="color: #e2e8f0; word-break: break-all;">${item.target}</td>
                        <td><span style="color: ${parseInt(item.score) >= 60 ? '#ef4444' : '#22c55e'}; font-weight: bold;">${item.score}</span></td>
                    </tr>
                `).join('');
            }

            async function scanFraud() {
                const text = document.getElementById('messageInput').value.trim();
                if (!text) return alert("Pehle koi message, link ya UPI ID enter karein.");

                const res = await fetch('/scan-fraud', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message_content: text })
                });
                const data = await res.json();

                const card = document.getElementById('resultCard');
                const badge = document.getElementById('badge');
                const flagsSec = document.getElementById('flagsSection');
                const draftSec = document.getElementById('draftSection');
                const draftText = document.getElementById('draftText');

                card.style.display = 'block';
                badge.innerText = `${data.verdict} (Risk: ${data.risk_score})`;

                if (parseInt(data.risk_score) >= 60) {
                    badge.className = "score-badge danger";
                } else if (parseInt(data.risk_score) >= 30) {
                    badge.className = "score-badge warning";
                } else {
                    badge.className = "score-badge safe";
                }

                if (data.flags && data.flags.length > 0) {
                    flagsSec.innerHTML = "<strong>Detected Risks:</strong><ul>" + data.flags.map(f => `<li>${f}</li>`).join('') + "</ul>";
                } else {
                    flagsSec.innerHTML = "<p style='color: #22c55e;'>Koi high risk flag detect nahi hua.</p>";
                }

                if (data.complaint_draft) {
                    draftSec.style.display = 'block';
                    draftText.innerText = data.complaint_draft;
                } else {
                    draftSec.style.display = 'none';
                }

                loadHistory();
            }

            function copyReport() {
                const text = document.getElementById('draftText').innerText;
                navigator.clipboard.writeText(text).then(() => {
                    const btn = document.getElementById('copyBtn');
                    btn.innerText = "Copied!";
                    btn.style.color = "#22c55e";
                    setTimeout(() => {
                        btn.innerText = "Copy Dossier";
                        btn.style.color = "#38bdf8";
                    }, 2000);
                });
            }

            loadHistory();
        </script>
    </body>
    </html>
    """
