from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from .config import settings
from .models import GatewayRequest, ApiEvent
from .risk_engine import engine
from .state import state

BASE_DIR = Path(__file__).resolve().parent.parent
app = FastAPI(title=settings.app_name, version=settings.version)

DEMO_USERS = {
    "1001": {"name": "Alice", "email": "alice@example.com", "role": "user"},
    "1002": {"name": "Bob", "email": "bob@example.com", "role": "user"},
    "1003": {"name": "Carol", "email": "carol@example.com", "role": "manager"},
}

class DemoProxyRequest(BaseModel):
    method: str = "GET"
    path: str
    user_id: str | None = None
    role: str = "user"
    token: str | None = "demo-token"
    client_type: str = "human"
    source_ip: str = "127.0.0.1"
    body: dict[str, Any] | None = None

@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": settings.app_name, "version": settings.version}

@app.post("/api/gateway/analyze")
def analyze(req: GatewayRequest):
    result = engine.analyze(req)
    event = ApiEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_id=result.request_id,
        method=req.method.upper(),
        path=req.path,
        user_id=req.user_id,
        role=req.role,
        client_type=req.client_type,
        source_ip=req.source_ip,
        risk_score=result.risk_score,
        decision=result.decision,
        finding_codes=[f.code for f in result.findings],
    )
    state.add_event(event)
    return result

@app.post("/api/gateway/proxy")
def proxy(req: DemoProxyRequest):
    gateway_req = GatewayRequest(**req.model_dump())
    result = engine.analyze(gateway_req)
    event = ApiEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        request_id=result.request_id,
        method=req.method.upper(),
        path=req.path,
        user_id=req.user_id,
        role=req.role,
        client_type=req.client_type,
        source_ip=req.source_ip,
        risk_score=result.risk_score,
        decision=result.decision,
        finding_codes=[f.code for f in result.findings],
    )
    state.add_event(event)
    if result.decision == "BLOCK":
        raise HTTPException(status_code=403, detail=result.model_dump())
    return {"gateway": result.model_dump(), "upstream": demo_upstream(req)}

@app.get("/api/events")
def events(limit: int = 50):
    return {"events": [e.model_dump() for e in state.recent_events(max(1, min(limit, 200)))]}

@app.get("/api/metrics")
def metrics():
    events = state.recent_events(200)
    return {
        "total_events": len(events),
        "blocked": sum(e.decision == "BLOCK" for e in events),
        "challenged": sum(e.decision == "CHALLENGE" for e in events),
        "allowed": sum(e.decision == "ALLOW" for e in events),
        "avg_risk": round(sum(e.risk_score for e in events) / len(events), 1) if events else 0,
        "top_findings": {
            code: sum(code in e.finding_codes for e in events)
            for code in sorted({c for e in events for c in e.finding_codes})
        },
    }

@app.get("/api/users/{user_id}")
def demo_user(user_id: str):
    """Intentionally insecure upstream endpoint used only for local demonstrations.
    The gateway should sit in front of it and prevent unauthorized object access.
    """
    user = DEMO_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user_id, **user}

@app.post("/api/transfer")
def demo_transfer(payload: dict[str, Any]):
    return {"status": "simulated", "message": "Demo transfer accepted by upstream", "payload": payload}

@app.post("/api/fetch")
def demo_fetch(payload: dict[str, Any]):
    return {"status": "simulated", "fetched": payload.get("url")}

def demo_upstream(req: DemoProxyRequest):
    if req.path.startswith("/api/users/"):
        user_id = req.path.rstrip("/").split("/")[-1]
        return {"service": "demo-users", **DEMO_USERS.get(user_id, {"error": "not found"})}
    if req.path == "/api/transfer":
        return {"service": "demo-payments", "status": "simulated", "amount": (req.body or {}).get("amount")}
    if req.path == "/api/fetch":
        return {"service": "demo-fetcher", "status": "simulated", "url": (req.body or {}).get("url")}
    return {"service": "demo-upstream", "path": req.path, "status": "simulated"}
