import os
import requests
import google.generativeai as genai

# 1. إعداد المفتاح
API_KEY = "AQ.Ab8RN6KEsdKhmfEdeZMO-M8rwbaWxqFdk1oEENRc_m2-PKCsfw"
genai.configure(api_key=API_KEY)

# 2. استخدام النموذج القوي المتاح بحسابك (gemini-2.5-flash)
model = genai.GenerativeModel("gemini-2.5-flash")

# 3. دالة فحص الـ Headers للموقع الهدف
def scan_website_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return dict(response.headers)
    except Exception as e:
        return f"Error scanning URL: {str(e)}"

# 4. تنفيذ الفحص والتحليل
target_url = "https://example.com"
print(f"[*] Scanning {target_url} ...")

scan_results = scan_website_headers(target_url)

prompt = f"""
You are a Senior DevSecOps & Cloud Architect AI Agent.
Analyze the following HTTP headers for security risks on {target_url}:
{scan_results}

Identify missing security headers (such as HSTS, CSP, X-Frame-Options) and potential vulnerabilities.
Provide a clean summary with severity levels (High, Medium, Low) and quick fix recommendations.
"""

print("[*] Analyzing security results with Gemini AI Agent...\n")

response = model.generate_content(prompt)

print("=== SECURITY ANALYSIS REPORT ===")
print(response.text)