"""
Middleware for error handling and logging.
VULNERABLE: Legacy error handlers expose stack traces and sensitive information.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException
import traceback
import logging
import os
from typing import Callable
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Error handling middleware.
    VULNERABLE: Exposes database errors, stack traces, and file paths in legacy mode
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> any:
        try:
            response = await call_next(request)
            return response
        
        except HTTPException as http_exc:
            # Standard HTTP exceptions
            return JSONResponse(
                status_code=http_exc.status_code,
                content={"detail": http_exc.detail}
            )
        
        except Exception as exc:
            # VULNERABLE: Check if this is a legacy endpoint
            is_legacy = "/api/v1/" in request.url.path or "/legacy/" in request.url.path
            is_internal = "/internal/" in request.url.path
            
            if is_legacy or is_internal:
                # VULNERABLE: Expose full error details for legacy endpoints
                error_response = {
                    "error": str(exc),
                    "code": 500,
                    "details": traceback.format_exc(),  # VULNERABLE: Stack trace
                    "database_error": str(exc) if "database" in str(type(exc)).lower() else None,
                    "file_path": os.path.abspath(__file__) if is_internal else None,
                    "request_path": request.url.path,
                    "query_params": dict(request.query_params) if request.query_params else None,
                }
                logger.error(f"Legacy endpoint error: {exc}", exc_info=True)
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content=error_response
                )
            else:
                # Secure error response for v2 endpoints
                logger.error(f"Internal server error: {exc}", exc_info=True)
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": "Internal server error"}
                )


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log all requests to audit trail.
    VULNERABLE: Some endpoints log sensitive data
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> any:
        # Skip certain endpoints
        skip_paths = ["/docs", "/openapi.json", "/redoc"]
        if any(request.url.path.startswith(p) for p in skip_paths):
            return await call_next(request)
        
        # VULNERABLE: Log everything including sensitive paths
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
        
        # VULNERABLE: Log auth headers for debugging (security risk)
        if "/legacy/" in request.url.path or "/internal/" in request.url.path:
            auth_header = request.headers.get("authorization", "")
            if auth_header:
                audit_entry["auth_header"] = auth_header[:50] + "..."
        
        response = await call_next(request)
        audit_entry["status_code"] = response.status_code
        
        logger.info(f"Request audit: {json.dumps(audit_entry)}")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    VULNERABLE: Rate limiting is incomplete and can be bypassed
    Only checks certain endpoints, not comprehensive coverage
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.request_counts = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> any:
        # VULNERABLE: Only rate limit /api/v2/ endpoints, not legacy
        if "/api/v1/" in request.url.path:
            # Legacy endpoints have NO rate limiting
            return await call_next(request)
        
        # VULNERABLE: Rate limiting by IP only, easily spoofed
        client_ip = request.client.host if request.client else "unknown"
        
        # VULNERABLE: Very high rate limit (almost no protection)
        max_requests = 10000  # Should be much lower
        time_window = 60
        
        key = f"{client_ip}:{request.url.path}"
        # Simplified rate limiting (real implementation would use Redis)
        
        return await call_next(request)
