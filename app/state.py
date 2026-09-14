from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from .models import ApiEvent
from .config import settings

class RuntimeState:
    def __init__(self):
        self.lock = Lock()
        self.events: list[ApiEvent] = []
        self.requests_by_ip: dict[str, deque[datetime]] = defaultdict(deque)
        self.requests_by_user: dict[str, deque[datetime]] = defaultdict(deque)

    def record_request(self, ip: str, user: str | None):
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - settings.rate_window_seconds
        with self.lock:
            for bucket in (self.requests_by_ip[ip], self.requests_by_user[user or "anonymous"]):
                bucket.append(now)
                while bucket and bucket[0].timestamp() < cutoff:
                    bucket.popleft()

    def counts(self, ip: str, user: str | None):
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - settings.rate_window_seconds
        with self.lock:
            for bucket in (self.requests_by_ip[ip], self.requests_by_user[user or "anonymous"]):
                while bucket and bucket[0].timestamp() < cutoff:
                    bucket.popleft()
            return len(self.requests_by_ip[ip]), len(self.requests_by_user[user or "anonymous"])

    def add_event(self, event: ApiEvent):
        with self.lock:
            self.events.insert(0, event)
            self.events = self.events[:200]

    def recent_events(self, limit=50):
        with self.lock:
            return self.events[:limit]

state = RuntimeState()
