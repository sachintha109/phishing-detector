from flask import Flask, request, render_template_string
import requests
import time
from datetime import datetime


app = Flask(__name__)

API_KEY = "1013b5b38842fe3a243c3ad8d94d6c087bfaec379116a427aa0a5d26008d9a2a"


def check_url(url):

    if not url.startswith("http"):
        return "Invalid URL"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return "❌ Error submitting URL"

    analysis_id = response.json()["data"]["id"]

    for _ in range(20):

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        data = report.json()["data"]["attributes"]

        if data["status"] == "completed":

            stats = data["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            score = min(100, malicious * 15 + suspicious * 5)

            # ✅ YOUR CUSTOM LOGIC (CORRECT PLACE)
            if "login" in url and malicious > 0:
                return f"⚠️ High Risk Login Page | Risk Score: {score}/100"

            if malicious >= 3:
                return f"Phishing Detected | Risk Score: {score}/100"
            elif malicious > 0 or suspicious > 1:
                return f"Suspicious | Risk Score: {score}/100"
            else:
                return f"Safe | Risk Score: {score}/100"

        time.sleep(2)

    return "⚠️ Scan timed out, try again"
    
    if not url.startswith("http"):
        return "Invalid URL"
    
    if "login" in url and malicious > 0:
        return "⚠️ High Risk Login Page"

@app.route("/", methods=["GET", "POST"])
def home():
    result = ""
    scan_time=""
    if request.method == "POST":
        url = request.form["url"]
        result = check_url(url)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ✅ THIS MUST HAVE 1 TAB (or 4 spaces)
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection System</title>

    <style>
        body {
            margin: 0;
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a, #020617);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .container {
            background: rgba(30, 41, 59, 0.95);
            padding: 40px;
            border-radius: 15px;
            width: 400px;
            text-align: center;
            box-shadow: 0 0 25px rgba(0,0,0,0.6);
            transition: 0.3s ease;        
        }

       .container:hover {
           transform: scale(1.02);
        }
                                  
        h2 {
            margin-bottom: 20px;
        }

        input {
            width: 90%;
            padding: 12px;
            border-radius: 8px;
            border: none;
            outline: none;
            margin-bottom: 15px;
            font-size: 14px;
        }

        button {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            background: #22c55e;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }

        button:hover {
            background: #16a34a;
            transform: scale(1.05);
            transform: translateY(-2px);
        }

        .result {
            margin-top: 20px;
            font-size: 18px;
            font-weight: bold;
        }

        .safe { color: #22c55e; }
        .danger { color: #ef4444; }
        .warn { color: #facc15; }
    </style>
</head>

<body>

<div class="container">
    <h2>🔐 Phishing Detection System</h2>
    <p style="opacity:0.7;">
    Real-time URL security analysis using VirusTotal API
</p>

    <form method="POST">
        <input type="text" name="url" placeholder="Enter URL to scan..." required>
        <br>
       <button type="submit" onclick="this.innerText='Scanning...'">
    Scan URL
</button>
    </form>

   <div class="result-box">
    {% if "Safe" in result %}
        <div class="safe-box">✅ {{ result }}</div>
    {% elif "Phishing" in result %}
        <div class="danger-box">❌ {{ result }}</div>
    {% elif "Suspicious" in result %}
        <div class="warn-box">⚠️ {{ result }}</div>
    {% endif %}
</div>
                                  
{% if scan_time %}
<p style="margin-top:10px; opacity:0.7; text-align:center;">
    Scan Time: {{ scan_time }}
</p>    
{% endif %}


<p style="margin-top:20px; font-size:12px; opacity:0.5;">
     Developed by Sachintha Kularathne | Final Year Project
</p>
</div> 

</body>
</html>
""", result=result, scan_time=scan_time)

if __name__ == "__main__":
    app.run(debug=True)    