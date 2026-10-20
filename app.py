from flask import Flask, request, jsonify, render_template_string
import requests

app = Flask(__name__)

# ==========================================
# الـ API Keys الخاصة بك
# ==========================================
VT_API_KEY = "4317be5918e4f0a2937e6e92b1cf0fef957801789d3255db50f4be76cbb65325"
ABUSE_API_KEY = "10a7135ca0f7cd34d63796276b2ce70193b9223ddedd19605b53ba28fa6cf98aa57cab8fc8b85464"
# لو مش معاك X-Force حالياً، سيبهم فاضيين عادي
XFORCE_API_KEY = ""
XFORCE_API_PASSWORD = ""

# واجهة الموقع
HTML_PAGE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>IP Reputation Checker</title>
    <style>
        body { font-family: Arial; background: #1e1e2f; color: #fff; text-align: center; padding-top: 50px; }
        .box { background: #27293d; padding: 25px; border-radius: 10px; display: inline-block; width: 450px; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }
        input, button { padding: 12px; margin: 10px 0; width: 90%; border-radius: 5px; border: none; font-size: 16px; }
        input { background: #1e1e2f; color: #fff; border: 1px solid #444; text-align: center; }
        button { background: #e14eca; color: white; cursor: pointer; font-weight: bold; }
        button:hover { background: #be35a7; }
        .results { text-align: right; background: #1e1e2f; padding: 15px; margin-top: 15px; border-radius: 5px; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="box">
        <h2>فحص سمعة الـ IP</h2>
        <input type="text" id="ipInput" placeholder="أدخل الـ IP هنا (مثال: 8.8.8.8)">
        <br>
        <button onclick="checkIP()">فحص الآن</button>
        <div class="results" id="res" style="display:none;">
            <p id="vt"><b>VirusTotal:</b> جاري الفحص...</p>
            <p id="abuse"><b>AbuseIPDB:</b> جاري الفحص...</p>
            <p id="xforce"><b>IBM X-Force:</b> جاري الفحص...</p>
        </div>
    </div>

    <script>
        async function checkIP() {
            const ip = document.getElementById('ipInput').value.trim();
            if(!ip) return alert('أدخل IP لو سمحت');
            
            document.getElementById('res').style.display = 'block';
            document.getElementById('vt').innerHTML = '<b>VirusTotal:</b> جاري الفحص...';
            document.getElementById('abuse').innerHTML = '<b>AbuseIPDB:</b> جاري الفحص...';
            document.getElementById('xforce').innerHTML = '<b>IBM X-Force:</b> جاري الفحص...';

            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ip: ip})
                });
                const data = await response.json();

                document.getElementById('vt').innerHTML = '<b>VirusTotal:</b> ' + data.vt;
                document.getElementById('abuse').innerHTML = '<b>AbuseIPDB:</b> ' + data.abuse;
                document.getElementById('xforce').innerHTML = '<b>IBM X-Force:</b> ' + data.xforce;
            } catch (err) {
                alert('حدث خطأ في الاتصال');
            }
        }
    </script>
</body>
</html>
"""

# فحص VirusTotal
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            return f"Malicious: {malicious} | Suspicious: {suspicious}"
        return f"Error: Status {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

# فحص AbuseIPDB
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            return f"Abuse Confidence Score: {score}%"
        return f"Error: Status {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

# فحص IBM X-Force (اختياري لو مفتاحه مش موجود)
def check_xforce(ip):
    if not XFORCE_API_KEY:
        return "لم يتم إدخال مفتاح IBM X-Force"
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
    try:
        response = requests.get(url, auth=(XFORCE_API_KEY, XFORCE_API_PASSWORD))
        if response.status_code == 200:
            score = response.json().get('score', 'N/A')
            return f"Score: {score}"
        return f"Error: Status {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/')
def home():
    return render_template_string(HTML_PAGE)

@app.route('/check', methods=['POST'])
def check():
    ip = request.json.get('ip')
    
    vt_result = check_virustotal(ip)
    abuse_result = check_abuseipdb(ip)
    xforce_result = check_xforce(ip)
    
    return jsonify({
        'vt': vt_result,
        'abuse': abuse_result,
        'xforce': xforce_result
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)