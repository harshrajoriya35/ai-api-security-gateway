# AI API Security Gateway

This project adds a runtime security layer in front of APIs and autonomous AI agents. It analyzes requests, assigns a risk score, explains the decision, and returns **ALLOW**, **CHALLENGE**, or **BLOCK**.

> **Scope:** This repository is a safe local demonstration. The upstream endpoints are simulated and the gateway uses deterministic rules/heuristics so the project works without paid APIs or external services.

## Why this project

Modern API attacks often involve authorization abuse, abnormal request behavior, SSRF, stolen credentials, sensitive data leakage, and automated clients. AI agents add another dimension because an agent can call tools/APIs autonomously. The prototype focuses on runtime controls rather than only static scanning.

## Features

- **BOLA / IDOR detection** – blocks attempts to access another user's object.
- **Broken Function Level Authorization** – detects low-privilege users calling admin/sensitive functions.
- **AI-agent action control** – raises a challenge/block for sensitive AI-initiated operations and destructive actions.
- **API abuse detection** – rolling request-volume and burst detection.
- **SSRF protection** – blocks common localhost, loopback and cloud metadata destinations.
- **Sensitive-data detection** – flags credential-like secrets in request bodies.
- **Risk scoring** – combines multiple findings into a 0–100 risk score.
- **Runtime decision** – ALLOW / CHALLENGE / BLOCK.
- **Security-event dashboard** – live metrics and recent findings.
- **Demo attack presets** – BOLA, AI transfer and SSRF.
- **Automated tests** – pytest coverage for the main security controls.
- **Docker support** – one-command local deployment.

## Architecture

```text
                    ┌─────────────────────┐
                    │ Client / AI Agent    │
                    └──────────┬──────────┘
                               │ API request
                               ▼
                    ┌─────────────────────┐
                    │ AI API Security      │
                    │ Gateway              │
                    ├─────────────────────┤
                    │ Authentication       │
                    │ Authorization        │
                    │ BOLA/BFLA           │
                    │ Behavior analysis    │
                    │ AI-agent policy      │
                    │ SSRF checks          │
                    │ Data checks          │
                    └──────────┬──────────┘
                               │
                         Risk score 0–100
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
              ALLOW        CHALLENGE       BLOCK
                 │             │             │
                 └─────────────┼─────────────┘
                               ▼
                        Protected API
```

## Tech stack

- Python 3.11+
- FastAPI
- Pydantic
- Uvicorn
- Vanilla HTML/CSS/JavaScript dashboard
- pytest
- Docker

No database and no paid model/API key are required for the prototype.

## Quick start — Windows / Linux / macOS

### 1. Clone

```bash
git clone https://github.com/YOUR-USERNAME/ai-api-security-gateway.git
cd ai-api-security-gateway
```

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Windows CMD**

```cmd
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Start the gateway

```bash
uvicorn app.main:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/health

## Run with Docker

```bash
docker compose up --build
```

Then open http://127.0.0.1:8000

Stop:

```bash
docker compose down
```

## How to operate the demo

### Demo 1 — BOLA / IDOR

In the dashboard click **Demo BOLA**, then **Analyze request**.

It sends roughly:

```json
{
  "method": "GET",
  "path": "/api/users/1002",
  "user_id": "1001",
  "role": "user",
  "token": "demo-token",
  "client_type": "human"
}
```

Expected result:

```text
96-ish / 100 — BLOCK
BOLA detected
```

The exact score can vary as runtime behavior findings accumulate.

### Demo 2 — AI-agent transfer

Click **Demo AI transfer**.

The gateway sees an autonomous client trying to perform a sensitive transfer and returns a high-risk result. In this prototype, the policy is designed to prevent autonomous high-impact actions from silently passing through.

### Demo 3 — SSRF

Click **Demo SSRF**.

Expected result:

```text
CRITICAL
SSRF detected
BLOCK
```

### Demo 4 — Safe request

Set:

```text
GET /api/users/1001
User ID: 1001
Role: user
Client: human
```

Expected result:

```text
ALLOW
```

## CLI attack demonstration

With the server running:

```bash
python scripts/attack_demo.py
```

It runs safe, local simulated attack scenarios against the gateway and prints the resulting decisions.

## API examples

### Analyze a request

```bash
curl -X POST http://127.0.0.1:8000/api/gateway/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "method":"GET",
    "path":"/api/users/1002",
    "user_id":"1001",
    "role":"user",
    "token":"demo-token",
    "client_type":"human",
    "source_ip":"192.0.2.10",
    "body":{}
  }'
```

### Metrics

```bash
curl http://127.0.0.1:8000/api/metrics
```

### Events

```bash
curl http://127.0.0.1:8000/api/events
```

## Risk model

The prototype is intentionally transparent:

| Signal | Example score |
|---|---:|
| Missing authentication | +25 |
| Suspicious/compromised token | +35 |
| BOLA | +75 |
| Broken function authorization | +70 |
| SSRF | +65 |
| API abuse | +55 |
| Request burst | +25 |
| AI sensitive action | +50 |
| AI destructive action | +50 |
| Sensitive secret in body | +40 |

Decision thresholds:

- **0–49:** ALLOW
- **50–79:** CHALLENGE
- **80–100:** BLOCK

These values are for the hackathon prototype, not production security policy.

## Demo upstream API

The repository includes intentionally simplified upstream routes to make demonstrations easy:

- `GET /api/users/{user_id}`
- `POST /api/transfer`
- `POST /api/fetch`

They are **simulation endpoints**. Do not expose them to the public Internet.

## Testing

Run:

```bash
pytest -q
```

Expected: all tests pass.

## Suggested hackathon demo flow (2–3 minutes)

1. Open the dashboard.
2. Show a normal request → **ALLOW**.
3. Change the object ID → **BOLA → BLOCK**.
4. Switch client type to **AI agent** and select transfer → **CHALLENGE/BLOCK**.
5. Use SSRF preset → **BLOCK**.
6. Point to the event log and risk score.
7. Explain that the gateway is a runtime security layer between autonomous clients and sensitive APIs.

## What makes it extensible

For a production version, replace the in-memory runtime state and demo upstream service with:

- Redis or Kafka for distributed event/rate state
- PostgreSQL/ClickHouse for security analytics
- Envoy/Nginx/API gateway integration
- OIDC/JWT introspection
- OpenTelemetry telemetry
- API inventory/discovery
- ML anomaly detection
- SIEM/SOAR integrations
- policy-as-code for AI-agent permissions
- human approval workflows for high-impact agent actions

## Security / ethics

This project is intended for defensive development and authorized local testing. The demo attack scenarios target only the simulated endpoints shipped in this repository. Do not use the tool against systems you do not own or have explicit authorization to test.

## References

- OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API Security project: https://owasp.org/API-Security/
- Akamai API security research: https://www.akamai.com/
- Salt Security State of API Security: https://salt.security/
- Wallarm API ThreatStats: https://www.wallarm.com/

## License

MIT — see `LICENSE`.

Credit:- Harsh Rajoriya(Team Leader), Chetan dewda(member), Rohit Rathore(member)
         1st Year Btech IOT students at PIEMR
