"""
SSRF Vulnerable Flask Application - FOR EDUCATION ONLY

This app is intentionally vulnerable to Server-Side Request Forgery (SSRF).
Deploy only in isolated lab environments. Never use in production.

Endpoints:
  /         - Index page
  /health   - Health check (ALB target group)
  /info     - Server metadata
  /fetch    - SSRF vulnerable endpoint
"""

from flask import Flask, request, jsonify
import requests
import socket

app = Flask(__name__)


@app.route("/")
def index():
    return """
    <h1>Security Lab - Vulnerable App</h1>
    <p>Endpoints:</p>
    <ul>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/info">/info</a> - Server info</li>
        <li>/fetch?url=... - SSRF vulnerable endpoint</li>
    </ul>
    <hr>
    <p style="color:red"><strong>WARNING:</strong> This app is intentionally
    vulnerable. For educational use only.</p>
    """


@app.route("/health")
def health():
    return jsonify(status="ok"), 200


@app.route("/info")
def info():
    return jsonify(
        hostname=socket.gethostname(),
        private_ip=socket.gethostbyname(socket.gethostname()),
    )


@app.route("/fetch")
def fetch():
    """SSRF VULNERABLE ENDPOINT - FOR EDUCATION ONLY"""
    url = request.args.get("url", "")
    if not url:
        return "Usage: /fetch?url=http://example.com", 400
    try:
        resp = requests.get(url, timeout=5)
        return resp.text
    except Exception as e:
        return str(e), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
