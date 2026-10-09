from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from detector import analyze_text
from database import init_db, log_threat, get_recent_threats

app = FastAPI(title="Cyber Crime Shield API")

init_db()

class ScanRequest(BaseModel):
    text: str

@app.post("/scan")
def scan_text(request: ScanRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
    
    analysis = analyze_text(request.text)
    
    target_marker = "General Text Threat"
    if analysis.get("extracted_urls"):
        target_marker = analysis["extracted_urls"][0]
    elif analysis.get("extracted_upis"):
        target_marker = analysis["extracted_upis"][0]
        
    log_threat(
        input_text=request.text,
        target_marker=target_marker,
        risk_score=analysis["risk_score"],
        risk_factors=analysis["risk_factors"],
        dossier=analysis.get("police_dossier", "")
    )
    
    return analysis

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cyber Crime Shield</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; display: flex; justify-content: center; }
            .container { max-width: 600px; width: 100%; background: #1e293b; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
            h2 { color: #38bdf8; margin-top: 0; }
            p { color: #94a3b8; font-size: 14px; }
            textarea { width: 100%; height: 100px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; color: #fff; padding: 10px; font-size: 14px; box-sizing: border-box; resize: vertical; }
            button { width: 100%; background: #0284c7; color: white; border: none; padding: 12px; font-size: 16px; font-weight: bold; border-radius: 8px; cursor: pointer; margin-top: 15px; }
            button:hover { background: #0369a1; }
            .privacy-badge { display: flex; align-items: center; justify-content: center; gap: 8px; font-size: 12px; color: #10b981; margin-top: 10px; }
            .result-card { margin-top: 20px; padding: 15px; border-radius: 8px; display: none; }
            .danger { background: #450a0a; border: 1px solid #ef4444; }
            .safe { background: #064e3b; border: 1px solid #10b981; }
            .score-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 14px; margin-bottom: 10px; }
            .score-danger { background: #ef4444; color: #fff; }
            .score-safe { background: #10b981; color: #fff; }
            .dossier-box { background: #0f172a; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; white-space: pre-wrap; margin-top: 10px; border: 1px solid #334155; }
            .copy-btn { background: #334155; color: #f8fafc; font-size: 12px; padding: 6px 12px; width: auto; float: right; margin-top: -5px; }
            .copy-btn:hover { background: #475569; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Cyber Crime Shield</h2>
            <p>Suspicious SMS, WhatsApp link, ya fake UPI ID paste karke scan karein.</p>
            <textarea id="inputText" placeholder="Message, fraud link, ya scam UPI ID yahan paste karein..."></textarea>
            <button onclick="scanNow()">Scan Now</button>
            <div class="privacy-badge">🔒 End-to-End Private: Aapka personal input kisi ke sath publicly share nahi hota.</div>

            <div id="resultCard" class="result-card">
                <span id="scoreBadge" class="score-badge"></span>
                <ul id="riskList" style="padding-left: 20px; font-size: 14px; margin-bottom: 15px;"></ul>
                
                <div id="dossierContainer" style="display:none; margin-top: 15px;">
                    <button class="copy-btn" onclick="copyDossier()">Copy Dossier</button>
                    <span style="font-weight: bold; font-size: 13px; color: #38bdf8;">Auto-Generated Police Dossier:</span>
                    <div id="dossierText" class="dossier-box"></div>
                </div>
            </div>
        </div>

        <script>
            async function scanNow() {
                const text = document.getElementById("inputText").value;
                if (!text.trim()) return alert("Pehle koi text ya link paste karein.");

                const res = await fetch("/scan", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ text })
                });
                const data = await res.json();

                const card = document.getElementById("resultCard");
                const badge = document.getElementById("scoreBadge");
                const list = document.getElementById("riskList");
                const dossierContainer = document.getElementById("dossierContainer");
                const dossierText = document.getElementById("dossierText");

                card.style.display = "block";
                list.innerHTML = "";

                if (data.risk_score >= 40) {
                    card.className = "result-card danger";
                    badge.className = "score-badge score-danger";
                    badge.innerText = `DANGER / HIGH FRAUD RISK (Risk: ${data.risk_score}%)`;
                    data.risk_factors.forEach(rf => {
                        const li = document.createElement("li");
                        li.innerText = rf;
                        list.appendChild(li);
                    });
                    if (data.police_dossier) {
                        dossierContainer.style.display = "block";
                        dossierText.innerText = data.police_dossier;
                    }
                } else {
                    card.className = "result-card safe";
                    badge.className = "score-badge score-safe";
                    badge.innerText = `LIKELY SAFE (Risk: ${data.risk_score}%)`;
                    list.innerHTML = "<li style='list-style: none; margin-left: -20px; color: #6ee7b7;'>Koi high risk flag detect nahi hua.</li>";
                    dossierContainer.style.display = "none";
                }
            }

            function copyDossier() {
                const text = document.getElementById("dossierText").innerText;
                navigator.clipboard.writeText(text);
                alert("Police Dossier copied to clipboard!");
            }
        </script>
    </body>
    </html>
    """
