"""Brain Engine: traffic intelligence, endpoint intelligence, and alert generation."""

from __future__ import annotations

import json
import time

import redis.asyncio as aioredis
import structlog

log = structlog.get_logger(__name__)


class IPIntelligence:
    def __init__(self, ip: str):
        self.ip = ip
        self.request_count = 0
        self.blocked_count = 0
        self.unique_paths: set[str] = set()
        self.flags_seen: list[str] = []
        self.first_seen = time.time()
        self.last_seen = time.time()

    def update(self, event: dict) -> None:
        self.request_count += 1
        self.last_seen = time.time()
        path = event.get("path", "")
        if path:
            self.unique_paths.add(path)
        if event.get("verdict") == "BLOCKED":
            self.blocked_count += 1
        flags = event.get("flags", [])
        if flags:
            if isinstance(flags, str):
                self.flags_seen.extend(flags.split(","))
            elif isinstance(flags, list):
                self.flags_seen.extend(flags)

    def is_enumerating(self) -> bool:
        return len(self.unique_paths) > 15 and self.request_count > 20

    def is_auth_probing(self) -> bool:
        return self.flags_seen.count("missing_auth") >= 5

    def threat_level(self) -> str:
        score = 0
        score += min(self.blocked_count * 2, 20)
        score += min(len(self.unique_paths), 15)
        if self.is_enumerating():
            score += 25
        if self.is_auth_probing():
            score += 20
        if score >= 40:
            return "CRITICAL"
        if score >= 20:
            return "HIGH"
        if score >= 10:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "request_count": self.request_count,
            "blocked_count": self.blocked_count,
            "unique_paths": len(self.unique_paths),
            "is_enumerating": self.is_enumerating(),
            "is_auth_probing": self.is_auth_probing(),
            "threat_level": self.threat_level(),
            "flags_summary": list(set(self.flags_seen))[:10],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class BrainEngine:
    def __init__(self):
        self.ip_intel: dict[str, IPIntelligence] = {}
        self.path_hit_counts: dict[str, int] = {}
        self.events_processed = 0
        self.alerts_emitted = 0

    async def process_event(self, r: aioredis.Redis, event: dict) -> None:
        self.events_processed += 1
        ip = event.get("source_ip", "unknown")
        path = event.get("path", "")

        if ip not in self.ip_intel:
            self.ip_intel[ip] = IPIntelligence(ip)
        intel = self.ip_intel[ip]
        intel.update(event)
        self.path_hit_counts[path] = self.path_hit_counts.get(path, 0) + 1

        await r.hset("brain:ip_intel", ip, json.dumps(intel.to_dict()))

        if intel.threat_level() in ("CRITICAL", "HIGH") and intel.request_count % 10 == 0:
            alert = {
                "type": "ip_threat_alert",
                "ts": str(time.time()),
                "ip": ip,
                "threat_level": intel.threat_level(),
                "reason": (
                    "path_enumeration" if intel.is_enumerating()
                    else "auth_probing" if intel.is_auth_probing()
                    else "high_block_rate"
                ),
                "stats": json.dumps(intel.to_dict()),
            }
            try:
                from eventbus.redis_bus import publish_alert_event, event_bus_mode

                before_mode = event_bus_mode()
                await publish_alert_event(alert)
                after_mode = event_bus_mode()
                if before_mode == "stream" and after_mode == "list":
                    log.warning("redis_streams_not_supported", fallback="list")
            except Exception as e:
                log.error("alerts_publish_failed", exc=str(e))
            self.alerts_emitted += 1
            log.warning("ip_threat_alert", ip=ip, level=intel.threat_level(), paths=len(intel.unique_paths), blocked=intel.blocked_count)

        if self.events_processed % 100 == 0:
            log.info("brain_engine_stats", processed=self.events_processed, alerts=self.alerts_emitted, tracked_ips=len(self.ip_intel))

    async def persist_summary(self, r: aioredis.Redis) -> None:
        summary = {
            "events_processed": self.events_processed,
            "tracked_ips": len(self.ip_intel),
            "alerts_emitted": self.alerts_emitted,
            "critical_ips": [ip for ip, intel in self.ip_intel.items() if intel.threat_level() == "CRITICAL"],
            "top_paths": sorted(self.path_hit_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "last_updated": time.time(),
        }
        await r.set("brain:summary", json.dumps(summary))
