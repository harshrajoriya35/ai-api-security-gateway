import re
import uuid
from typing import Any
from .config import settings
from .models import GatewayRequest, Finding, AnalysisResult
from .state import state

SENSITIVE_PATHS = {
    "/api/transfer": {"min_role": "admin", "ai_requires_approval": True},
    "/api/admin": {"min_role": "admin", "ai_requires_approval": True},
    "/api/users": {"min_role": "user", "ai_requires_approval": False},
}
ROLE_RANK = {"guest": 0, "user": 1, "manager": 2, "admin": 3}

PATH_RE = re.compile(r"^/api/([^/]+)/(\d+)(?:/.*)?$")
PRIVATE_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254")

class RiskEngine:
    """Deterministic security engine suitable for an offline hackathon demo."""

    def analyze(self, req: GatewayRequest) -> AnalysisResult:
        request_id = str(uuid.uuid4())[:8]
        findings: list[Finding] = []
        score = 0

        if not req.token:
            findings.append(Finding(
                code="AUTH_MISSING", severity="HIGH", score=25,
                title="Missing authentication token",
                detail="The request has no bearer/session token.",
                remediation="Require authenticated access for protected API endpoints.",
            ))
            score += 25
        elif req.token.startswith("stolen-"):
            findings.append(Finding(
                code="TOKEN_ANOMALY", severity="HIGH", score=35,
                title="Suspicious token pattern",
                detail="Demo token is marked as compromised/stolen.",
                remediation="Revoke the token and require re-authentication.",
            ))
            score += 35

        bola = self._check_bola(req)
        if bola:
            findings.append(bola)
            score += bola.score

        authz = self._check_function_authorization(req)
        if authz:
            findings.append(authz)
            score += authz.score

        ssrf = self._check_ssrf(req)
        if ssrf:
            findings.append(ssrf)
            score += ssrf.score

        behavior = self._check_behavior(req)
        if behavior:
            findings.append(behavior)
            score += behavior.score

        ai = self._check_ai_agent_policy(req)
        if ai:
            findings.append(ai)
            score += ai.score

        data = self._check_sensitive_body(req)
        if data:
            findings.append(data)
            score += data.score

        score = min(100, score)
        decision = "ALLOW"
        if score >= settings.risk_block_threshold:
            decision = "BLOCK"
        elif score >= settings.risk_challenge_threshold:
            decision = "CHALLENGE"

        explanation = self._explain(req, findings, score, decision)
        policy = {
            "block_threshold": settings.risk_block_threshold,
            "challenge_threshold": settings.risk_challenge_threshold,
            "mode": "hybrid-rule-risk-engine",
        }
        return AnalysisResult(
            request_id=request_id,
            risk_score=score,
            decision=decision,
            findings=findings,
            explanation=explanation,
            policy=policy,
        )

    def _check_bola(self, req: GatewayRequest):
        if not req.user_id or req.method.upper() not in {"GET", "PUT", "PATCH", "DELETE"}:
            return None
        m = PATH_RE.match(req.path)
        if not m:
            return None
        requested_id = m.group(2)
        if requested_id != str(req.user_id):
            return Finding(
                code="BOLA",
                severity="CRITICAL",
                score=75,
                title="Broken Object Level Authorization (BOLA)",
                detail=f"Authenticated user {req.user_id} requested object {requested_id}.",
                remediation="Verify object ownership or permission server-side before returning the object.",
            )
        return None

    def _check_function_authorization(self, req: GatewayRequest):
        rule = SENSITIVE_PATHS.get(req.path)
        if not rule:
            return None
        required = rule["min_role"]
        if ROLE_RANK.get(req.role, 0) < ROLE_RANK[required]:
            return Finding(
                code="BFLA",
                severity="CRITICAL",
                score=70,
                title="Broken Function Level Authorization",
                detail=f"Role '{req.role}' attempted endpoint requiring '{required}'.",
                remediation="Enforce server-side role/function authorization on every sensitive route.",
            )
        return None

    def _check_ssrf(self, req: GatewayRequest):
        body = req.body or {}
        url = str(body.get("url", ""))
        lowered = url.lower()
        if any(host in lowered for host in PRIVATE_HOSTS) or "file://" in lowered:
            return Finding(
                code="SSRF",
                severity="CRITICAL",
                score=65,
                title="Potential SSRF target",
                detail=f"Request contains a URL pointing to a local/internal resource: {url}",
                remediation="Allowlist destinations and block private, loopback and metadata addresses.",
            )
        return None

    def _check_behavior(self, req: GatewayRequest):
        state.record_request(req.source_ip, req.user_id)
        ip_count, user_count = state.counts(req.source_ip, req.user_id)
        if ip_count > settings.rate_limit or user_count > settings.rate_limit:
            return Finding(
                code="API_ABUSE",
                severity="HIGH",
                score=55,
                title="Abnormal API request volume",
                detail=f"Observed {max(ip_count, user_count)} requests from the same actor in the last {settings.rate_window_seconds}s.",
                remediation="Apply adaptive rate limiting, bot controls and step-up authentication.",
            )
        if ip_count > settings.burst_limit:
            return Finding(
                code="BURST",
                severity="MEDIUM",
                score=25,
                title="Unusual request burst",
                detail=f"Observed {ip_count} requests from source {req.source_ip} within the rolling window.",
                remediation="Throttle bursts and investigate whether automation is expected.",
            )
        return None

    def _check_ai_agent_policy(self, req: GatewayRequest):
        if req.client_type.lower() != "ai-agent":
            return None
        rule = SENSITIVE_PATHS.get(req.path)
        if rule and rule.get("ai_requires_approval"):
            return Finding(
                code="AI_SENSITIVE_ACTION",
                severity="HIGH",
                score=50,
                title="High-risk AI-agent action",
                detail="An autonomous AI agent is attempting a sensitive business operation.",
                remediation="Require human approval, narrow tool permissions and log the action before execution.",
            )
        dangerous = {"DELETE", "PATCH"}
        if req.method.upper() in dangerous:
            return Finding(
                code="AI_DESTRUCTIVE_ACTION",
                severity="HIGH",
                score=50,
                title="Potentially destructive AI-agent action",
                detail=f"AI agent requested {req.method.upper()} on {req.path}.",
                remediation="Use least-privilege tools and require explicit approval for destructive actions.",
            )
        return None

    def _check_sensitive_body(self, req: GatewayRequest):
        body_text = str(req.body or {})
        patterns = [r"sk-[A-Za-z0-9_-]{8,}", r"AKIA[0-9A-Z]{12,}", r"password\s*[:=]", r"otp\s*[:=]"]
        if any(re.search(p, body_text, flags=re.I) for p in patterns):
            return Finding(
                code="SENSITIVE_DATA",
                severity="HIGH",
                score=40,
                title="Sensitive data in request",
                detail="The request body appears to contain a credential or authentication secret.",
                remediation="Redact secrets and prevent sensitive fields from crossing trust boundaries.",
            )
        return None

    def _explain(self, req, findings, score, decision):
        if not findings:
            return f"Request appears low-risk. No policy violations detected. Risk {score}/100 → {decision}."
        primary = ", ".join(f.title for f in findings[:3])
        return f"Detected {len(findings)} security signal(s): {primary}. Combined risk is {score}/100, so the gateway will {decision.lower()} this request."

engine = RiskEngine()
