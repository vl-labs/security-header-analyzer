from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against HTTPS downgrade attacks.",
    "Content-Security-Policy": "Helps prevent XSS and code injection.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "X-Content-Type-Options": "Prevents MIME type sniffing.",
    "Referrer-Policy": "Controls how much referrer info is shared.",
    "Permissions-Policy": "Restricts browser features like camera, mic, GPS."
}

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def analyze_site(url):
    url = normalize_url(url)
    parsed = urlparse(url)

    if not parsed.netloc:
        return None, "Invalid URL."

    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        return None, f"Could not connect: {e}"

    headers = response.headers
    results = []

    final_url = response.url
    uses_https = final_url.startswith("https://")

    results.append({
        "name": "HTTPS",
        "present": uses_https,
        "value": final_url,
        "description": "Site should load over HTTPS."
    })

    for header, description in SECURITY_HEADERS.items():
        results.append({
            "name": header,
            "present": header in headers,
            "value": headers.get(header, "Missing"),
            "description": description
        })

    server_header = headers.get("Server", "")
    results.append({
        "name": "Server Header Exposure",
        "present": not bool(server_header),
        "value": server_header if server_header else "Not exposed",
        "description": "Server header can reveal backend technology."
    })

    score = sum(1 for item in results if item["present"])
    total = len(results)

    return {
        "url": url,
        "final_url": final_url,
        "score": score,
        "total": total,
        "results": results
    }, None

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "")
        report, error = analyze_site(url)

    return render_template("index.html", report=report, error=error)

@app.route("/health")
def health():
    return {"status": "running"}

if __name__ == "__main__":
    app.run(debug=True)