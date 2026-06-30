"""Compatibility wrapper for the refactored gateway proxy handler (moved to scripts/)."""

from gateway.proxy import close_http_client, get_http_client, handle_request, resolve_backend
