#!/bin/bash
set -euo pipefail

# Install dependencies
dnf install -y python3 python3-pip
pip3 install flask requests

# Create vulnerable app
cat > /opt/app.py << 'PYEOF'
from flask import Flask, request, jsonify
import requests
import socket
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Security Lab - Vulnerable App</h1>
    <p>Endpoints:</p>
    <ul>
        <li><a href="/health">/health</a> - Health check</li>
        <li><a href="/info">/info</a> - Server info</li>
        <li>/fetch?url=... - SSRF vulnerable endpoint</li>
    </ul>
    '''

@app.route('/health')
def health():
    return jsonify(status='ok'), 200

@app.route('/info')
def info():
    return jsonify(
        hostname=socket.gethostname(),
        private_ip=socket.gethostbyname(socket.gethostname()),
    )

@app.route('/fetch')
def fetch():
    """SSRF VULNERABLE ENDPOINT - FOR EDUCATION ONLY"""
    url = request.args.get('url', '')
    if not url:
        return 'Usage: /fetch?url=http://example.com', 400
    try:
        resp = requests.get(url, timeout=5)
        return resp.text
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=${app_port})
PYEOF

# Create systemd service
cat > /etc/systemd/system/vulnapp.service << 'SVCEOF'
[Unit]
Description=Vulnerable Lab App
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable vulnapp
systemctl start vulnapp
