"""In-memory dynamic rule registry shared across middleware and admin endpoints."""

from __future__ import annotations

from typing import Any, Dict

# Keyed by a caller-supplied rule_id (string).
# Each entry:
#   {
#       "type":   "Blocklist" | "Brownout" | "Deprecation",
#       "target": "<source_ip>" | "<url_path_prefix>",
#       "meta":   {}   # optional free-form metadata
#   }
RULE_REGISTRY: Dict[str, Dict[str, Any]] = {}
