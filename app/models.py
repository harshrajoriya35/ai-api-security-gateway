from typing import Any, Literal
from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "CHALLENGE", "BLOCK"]

class GatewayRequest(BaseModel):
    method: str = "GET"
    path: str
    user_id: str | None = None
    role: str = "user"
    token: str | None = None
    client_type: str = "human"
    source_ip: str = "127.0.0.1"
    body: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)

class Finding(BaseModel):
    code: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    score: int
    title: str
    detail: str
    remediation: str

class AnalysisResult(BaseModel):
    request_id: str
    risk_score: int
    decision: Decision
    findings: list[Finding]
    explanation: str
    policy: dict[str, Any]

class ApiEvent(BaseModel):
    timestamp: str
    request_id: str
    method: str
    path: str
    user_id: str | None
    role: str
    client_type: str
    source_ip: str
    risk_score: int
    decision: Decision
    finding_codes: list[str]
