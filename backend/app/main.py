"""
Main FastAPI application for banking backend.
Initializes routers, middleware, and database.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
import sys
from datetime import datetime

# Ensure top-level package imports work even if started from the app directory.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import database
from app.db.database import init_db

# Import routers
from app.api.v2_api import router as v2_router
from app.legacy.v1_api import router as v1_router
from app.admin.admin_api import router as admin_router
from app.internal.internal_api import router as internal_router
from trapnet.bait_api import router as bait_router

# Import middleware
from app.middleware.error_handler import ErrorHandlingMiddleware, AuditLoggingMiddleware, RateLimitMiddleware

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Banking Backend API",
    description="Enterprise-grade banking API with legacy modules",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# ==================== MIDDLEWARE ====================

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # VULNERABLE: Allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(AuditLoggingMiddleware)
app.add_middleware(RateLimitMiddleware)


# ==================== STARTUP EVENTS ====================

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized")
    
    # Log startup info
    logger.info(f"Banking Backend started at {datetime.utcnow()}")
    logger.info("Endpoints:")
    logger.info("  - v2 (Modern/Secure): /api/v2/...")
    logger.info("  - v1 (Legacy): /api/v1/...")
    logger.info("  - Admin: /api/admin/...")
    logger.info("  - Internal: /api/internal/...")
    logger.info("  - Docs: /api/docs")


# ==================== ROUTE REGISTRATION ====================

# Register routers
app.include_router(v2_router)
app.include_router(v1_router)
app.include_router(admin_router)
app.include_router(internal_router)
app.include_router(bait_router)


# ==================== ROOT ENDPOINTS ====================

@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "name": "Banking Backend",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "api_v2_secure": "/api/v2",
            "api_v1_legacy": "/api/v1",
            "admin": "/api/admin",
            "internal": "/api/internal",
            "documentation": "/api/docs"
        },
        "modules": {
            "authentication": "JWT-based",
            "database": "SQLAlchemy with SQLite/PostgreSQL",
            "security": "Mixed (modern secure + legacy vulnerable)"
        },
        "features": [
            "Account Management",
            "Transactions",
            "Card Services",
            "Loan Management",
            "KYC Verification",
            "Fraud Detection",
            "Admin Dashboard",
            "Internal Reporting"
        ]
    }


@app.get("/api/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }


# ==================== ERROR HANDLERS ====================

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# ==================== DEPRECATED ENDPOINTS ====================

@app.get("/api/v0/legacy-endpoint")
def legacy_v0_endpoint():
    """
    VULNERABLE: Very old API endpoint
    - Still active but not documented
    - No authentication
    - Could be deprecated zombie
    """
    return {
        "status": "deprecated",
        "message": "This API version is deprecated",
        "current_version": "v2"
    }


@app.get("/api/beta/experimental")
def beta_experimental():
    """
    VULNERABLE: Beta endpoint that's still active
    - Might have been forgotten
    - No proper security
    - Could expose experimental features
    """
    return {
        "status": "beta",
        "features": ["experimental_auth", "test_transfers"],
        "warning": "This API may change without notice"
    }


# ==================== SWAGGER/OPENAPI CUSTOMIZATION ====================

def get_openapi_schema():
    """Customize OpenAPI schema."""
    if not app.openapi_schema:
        app.openapi_schema = {
            "openapi": "3.0.0",
            "info": {
                "title": "Banking Backend API",
                "version": "2.0.0",
            },
            "paths": {},
        }
    return app.openapi_schema


app.openapi = get_openapi_schema


# ==================== DEBUG ROUTES (Accidentally exposed) ====================

@app.get("/api/debug/config")
def debug_config():
    """
    Debug endpoint - system configuration information.
    VULNERABLE: Exposes all settings
    """
    from app.utils.config import settings, LEGACY_CONFIGS
    
    return {
        "debug_enabled": True,
        "api_version": "2.0.0"
    }


@app.get("/api/debug/routes")
def debug_routes():
    """
    Debug endpoint - available API routes.
    VULNERABLE: Lists all endpoints without authentication
    """
    routes = []
    for route in app.routes:
        routes.append({
            "path": route.path,
            "methods": route.methods if hasattr(route, 'methods') else []
        })
    
    return {
        "total_routes": len(routes),
        "routes": routes[:20]  # Return limited set
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
