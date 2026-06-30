# Banking Backend API - Enterprise Edition

A realistic, production-style banking backend built with FastAPI for security scanning, threat detection, and penetration testing demonstrations.

**Status: Contains intentional security vulnerabilities for ALIE scanner testing**

## Overview

This backend simulates 5+ years of banking infrastructure development with:

- **Modern Secure APIs (v2)** - Enterprise-grade implementations
- **Legacy Vulnerable APIs (v1)** - Real technical debt and security issues
- **Internal Endpoints** - Accidentally exposed microservice integrations
- **Admin Dashboard** - Powerful but insecure administration tools
- **Realistic Technical Debt** - TODO comments, partial refactors, inconsistent standards

## Security Vulnerability Types (By Design)

The codebase intentionally includes these vulnerability patterns for ALIE detection:

### 1. **Broken Authentication**
- `/api/v1/auth/login-legacy` - Compares plaintext passwords
- `/api/v1/debug/user/{user_id}` - No authentication required
- `/api/v1/auth/check-email` - User enumeration vulnerability

### 2. **Missing Rate Limiting**
- `/api/v1/otp/request` - Unlimited OTP requests
- `/api/v1/password/reset` - Brute force enabled
- `/api/v1/quick-pay` - No throttling

### 3. **Hardcoded Secrets**
- `app/utils/config.py` - Hardcoded API keys and credentials
- `LEGACY_CONFIGS` - Hardcoded database and JWT keys
- Environment variable fallbacks with insecure defaults

### 4. **SQL Injection**
- `/api/v1/export/search?query=...` - Direct SQL concatenation
- `/api/v1/export/user-data` - F-string SQL building
- `/api/admin/users/list` - Admin search with injection
- `/api/internal/reports/daily-summary` - Date-based injection

### 5. **Verbose Error Leakage**
- `/api/v1/legacy/error-test` - Full stack traces exposed
- Error middleware shows database details in legacy endpoints
- File paths and SQL queries returned in responses

### 6. **Mass Assignment**
- `/api/v1/account/update` - Accepts arbitrary fields
- `/api/v1/user/update` - Users can set `is_admin`, `balance`, `role`
- `UserUpdateRaw` schema with `extra="allow"`

### 7. **Insecure Internal HTTP Calls**
- `NotificationService` - Uses HTTP to internal services
- `FraudService` - HTTP instead of HTTPS
- Hardcoded internal tokens passed in headers
- All service URLs configurable but default to HTTP

### 8. **Zombie APIs**
- `/api/v1/beta/quick-balance/` - Active but undocumented
- `/api/v0/legacy-endpoint` - Still returns data
- `/api/v1/legacy/csv-export` - Forgotten endpoint
- Multiple deprecated endpoints still functional

## Project Structure

```
backend/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── api/
│   │   └── v2_api.py          # Modern secure endpoints
│   ├── legacy/
│   │   └── v1_api.py          # Legacy vulnerable endpoints
│   ├── internal/
│   │   └── internal_api.py    # Internal/microservice endpoints
│   ├── admin/
│   │   └── admin_api.py       # Admin dashboard endpoints
│   ├── auth/
│   │   └── jwt_handler.py     # JWT and authentication
│   ├── db/
│   │   └── database.py        # Database setup
│   ├── models/
│   │   ├── database.py        # SQLAlchemy ORM models
│   │   └── schemas.py         # Pydantic schemas
│   ├── middleware/
│   │   └── error_handler.py   # Error handling and logging
│   ├── services/
│   │   └── service.py         # Business logic
│   ├── utils/
│   │   └── config.py          # Configuration management
│   └── scripts/
│       └── populate_db.py     # Sample data generation
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Container image
├── docker-compose.yml         # Multi-container setup
├── .env.example              # Environment template
└── README.md                 # This file
```

## Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 12+ (or SQLite for development)
- Docker & Docker Compose (optional)

### Local Setup

1. **Clone and install dependencies**

```bash
cd backend-alie
pip install -r requirements.txt
```

2. **Configure environment**

```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Initialize database with sample data**

```bash
python -m app.scripts.populate_db
```

4. **Run the application**

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- API: `http://localhost:8000`
- Documentation: `http://localhost:8000/api/docs`
- OpenAPI Schema: `http://localhost:8000/api/openapi.json`

### Docker Setup

```bash
# Build and run with Docker Compose
docker-compose up --build

# Access the API
curl http://localhost:8000/api/health
```

## API Endpoints

### Secure v2 Endpoints (Use These)

```
POST   /api/v2/auth/register          - Create user account
POST   /api/v2/auth/login             - Authenticate user
GET    /api/v2/accounts/balance       - Get account balance
GET    /api/v2/accounts/{id}          - Get account details
POST   /api/v2/transfers/send         - Send transfer
POST   /api/v2/kyc/upload             - Upload KYC document
GET    /api/v2/transactions           - List transactions
POST   /api/v2/cards/block            - Block credit card
GET    /api/v2/health                 - Health check
```

### Legacy v1 Endpoints (VULNERABLE)

```
POST   /api/v1/auth/login-legacy             - [VULN] No rate limit, weak auth
GET    /api/v1/auth/check-email              - [VULN] User enumeration
GET    /api/v1/debug/user/{id}               - [VULN] No auth, exposes hash
GET    /api/v1/export/search?query=...       - [VULN] SQL injection
POST   /api/v1/export/user-data              - [VULN] SQL injection
GET    /api/v1/admin/users/search            - [VULN] SQL injection
POST   /api/v1/account/update                - [VULN] Mass assignment
POST   /api/v1/user/update                   - [VULN] Mass assignment
POST   /api/v1/otp/request                   - [VULN] No rate limit
POST   /api/v1/password/reset                - [VULN] No rate limit
POST   /api/v1/quick-pay                     - [VULN] Multiple issues
GET    /api/v1/internal/system/status        - [VULN] Exposed endpoint
GET    /api/v1/internal/accounts/all         - [VULN] Lists all accounts
GET    /api/v1/legacy/error-test             - [VULN] Error stack traces
GET    /api/v1/beta/quick-balance/{id}       - [VULN] Zombie endpoint
POST   /api/v1/legacy/csv-export             - [VULN] SQL injection
```

### Admin Endpoints

```
POST   /api/admin/login                      - Admin login
GET    /api/admin/dashboard                  - System dashboard
GET    /api/admin/users/list                 - [VULN] List all users
POST   /api/admin/accounts/balance-adjust    - [VULN] Direct balance modification
GET    /api/admin/db/query                   - [VULN] Execute arbitrary SQL
GET    /api/admin/config/view                - [VULN] Expose all secrets
```

### Internal Endpoints

```
POST   /api/internal/billing/create-invoice         - [VULN] HTTP call
POST   /api/internal/fraud/check-transaction        - [VULN] HTTP call
POST   /api/internal/notifications/send             - [VULN] HTTP call
GET    /api/internal/employees/list                 - [VULN] No auth
GET    /api/internal/employees/{id}/credentials    - [VULN] Exposes passwords
GET    /api/internal/reports/daily-summary         - [VULN] SQL injection
POST   /api/internal/reports/export-data           - [VULN] SQL injection
GET    /api/internal/health/detailed                - [VULN] System info exposed
```

## Test Users

Pre-populated sample data:

```
Email: john.doe@example.com
Password: password123
Role: Customer

Email: admin@bank.local
Password: password123
Role: Admin
```

## Sample Requests

### Login

```bash
curl -X POST http://localhost:8000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "password123"
  }'
```

### Get Account Balance

```bash
curl -X GET http://localhost:8000/api/v2/accounts/balance \
  -H "Authorization: Bearer {token}"
```

### Vulnerable SQL Injection Example

```bash
# Search transactions with SQL injection payload
curl "http://localhost:8000/api/v1/export/search?query=test' OR '1'='1"
```

## Security Scanning

This backend is designed for security scanning tools like ALIE (Semgrep-based scanner):

### Expected Detections

The codebase should trigger:

- ✓ Hardcoded credentials/API keys
- ✓ SQL injection patterns (raw queries, f-strings)
- ✓ Missing authentication on sensitive endpoints
- ✓ Verbose error handling exposing internals
- ✓ Insecure HTTP calls to services
- ✓ Mass assignment vulnerabilities
- ✓ Zombie/deprecated endpoints
- ✓ Weak rate limiting

### Running Semgrep

```bash
# Scan this codebase
semgrep --config=p/security-audit --json app/ > results.json

# Or use ALIE
alie scan .
```

## Database Schema

### Users Table
- Stores user accounts with authentication data
- Includes `is_admin` flag and internal role fields
- Contains password hashes (often exposed in vulnerabilities)

### Accounts Table
- Bank accounts owned by users
- Tracks balance and status
- Includes overdraft limits

### Transactions Table
- Transaction history with amounts and statuses
- References source/destination accounts
- Stores transaction metadata

### Cards Table
- Credit/debit card information
- Links to accounts
- Includes card limits and block status

### KYC Documents Table
- Know-Your-Customer verification documents
- Tracks verification status
- Links to users

### Audit Logs Table
- Action tracking for security analysis
- Records user actions and IP addresses
- Can be manipulated by admins (vulnerability)

## Configuration

### Security Settings

```python
# app/utils/config.py

# VULNERABLE: Hardcoded defaults
SECRET_KEY = "super-secret-key-for-jwt-tokens-2019"
STRIPE_SECRET_KEY = "your_stripe_secret_key"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Service URLs - VULNERABLE: HTTP by default
BILLING_SERVICE_URL = "http://billing-service:8001"
FRAUD_SERVICE_URL = "http://fraud-service:8002"
```

### Environment Variables

See `.env.example` for all configurable options.

## Middleware

### Error Handling
- Legacy endpoints: Expose stack traces and database errors
- Modern endpoints: Sanitized error responses
- Middleware: Logs all requests including sensitive data

### Rate Limiting
- v2 endpoints: Basic rate limiting (incomplete)
- v1 endpoints: No rate limiting
- Easy to bypass

### Audit Logging
- Logs all requests with parameters
- Can include authentication headers (vulnerability)
- Audit logs can be deleted by admins

## Maintenance Notes

### TODO Comments (Technical Debt)

```python
# TODO: Remove after migration to env vars
LEGACY_CONFIGS = {...}

# TODO: Replace raw SQL later
def search_transactions():...

# FIXME: Implement proper rate limiting
@app.middleware...

# Temporary internal endpoint
@router.get("/internal/...")

# Legacy support for old mobile clients
@router.post("/api/v1/...")
```

### Known Issues

This codebase intentionally contains:

1. **Mixed coding standards** - Some modules use ORM, others raw SQL
2. **Incomplete security** - Some endpoints protected, others not
3. **Forgotten endpoints** - Beta/legacy APIs still active
4. **Hardcoded values** - For "backward compatibility"
5. **Verbose responses** - Legacy error handling

## Performance Characteristics

- SQLite (dev): ~50-100 req/sec
- PostgreSQL (prod): ~1000+ req/sec
- Database queries: Unoptimized in v1 APIs
- No connection pooling in legacy modules
- N+1 query problems in some endpoints

## Limitations

- SQLite database (single file)
- No actual payment processing
- Mock fraud detection service
- Sample data only
- No real encryption for card data
- Admin operations are not fully audited

## License

This code is provided as-is for security testing and educational purposes.

## Support & Disclaimer

**This is intentionally vulnerable code for security research and testing.**

Do not use in production. Do not expose to the internet.

For security scanner testing, ALIE detection verification, and penetration testing demonstrations only.

## Change Log

### Version 2.0.0
- Rewrite with mixed secure/vulnerable implementations
- Added internal endpoints
- Comprehensive vulnerability patterns
- Docker support
- Sample data generation

### Version 1.0.0
- Initial release
- Basic banking APIs
- SQLAlchemy models
- JWT authentication
