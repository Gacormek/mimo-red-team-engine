"""Metrics collector for Red Team Engine."""
import time
from collections import defaultdict


class MetricsCollector:
    def __init__(self):
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.start_time = time.time()

    def increment(self, name: str, value: int = 1):
        self.counters[name] += value

    def set_gauge(self, name: str, value: float):
        self.gauges[name] = value

    def get_all(self) -> dict:
        return {
            "uptime_seconds": round(time.time() - self.start_time),
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
        }


metrics = MetricsCollector()
