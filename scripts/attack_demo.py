import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

cases = [
    {
        "name": "BOLA / IDOR",
        "method": "GET",
        "path": "/api/users/1002",
        "user_id": "1001",
        "role": "user",
        "token": "demo-token",
        "client_type": "human",
        "source_ip": "10.0.0.8",
        "body": {},
    },
    {
        "name": "AI agent sensitive transfer",
        "method": "POST",
        "path": "/api/transfer",
        "user_id": "1001",
        "role": "user",
        "token": "demo-token",
        "client_type": "ai-agent",
        "source_ip": "10.0.0.9",
        "body": {"amount": 50000, "currency": "INR", "recipient": "demo"},
    },
    {
        "name": "SSRF",
        "method": "POST",
        "path": "/api/fetch",
        "user_id": "1001",
        "role": "user",
        "token": "demo-token",
        "client_type": "human",
        "source_ip": "10.0.0.10",
        "body": {"url": "http://169.254.169.254/latest/meta-data/"},
    },
]

for case in cases:
    payload = json.dumps(case).encode()
    req = urllib.request.Request(
        BASE + "/api/gateway/analyze",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        result = json.load(resp)
    print(f"\n[{case['name']}] {result['risk_score']}/100 -> {result['decision']}")
    for f in result["findings"]:
        print(f"  - {f['code']}: {f['title']}")
    time.sleep(0.25)
