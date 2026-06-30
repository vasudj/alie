"""Compatibility wrapper for the refactored gateway middleware (moved to scripts/)."""

from gateway.middleware import CorrelationIDMiddleware, RequestLoggingMiddleware, SecurityHeadersMiddleware
