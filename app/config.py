from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    app_name: str = "AI API Security Gateway"
    version: str = "1.0.0"
    risk_block_threshold: int = 80
    risk_challenge_threshold: int = 50
    rate_window_seconds: int = 60
    rate_limit: int = 60
    burst_limit: int = 15

settings = Settings()
