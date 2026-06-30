## 🏦 Banking Backend API - Generation Complete

A production-style banking backend with 50+ endpoints mixing secure modern APIs with realistic legacy vulnerabilities for security scanning and threat detection.

---

## ✅ Generated Components

### Core Application
- ✓ `app/main.py` - FastAPI application with routers, middleware, startup events
- ✓ `app/__init__.py` - Package initialization
- ✓ `requirements.txt` - Python dependencies
- ✓ `Dockerfile` - Container image for deployment
- ✓ `docker-compose.yml` - Multi-container setup with PostgreSQL and mock services
- ✓ `.env.example` - Environment configuration template
- ✓ `.gitignore` - Git ignore rules
- ✓ `README.md` - Comprehensive documentation

### Authentication & Security
- ✓ `app/auth/jwt_handler.py` - JWT token generation and validation
  - Secure token creation with bcrypt password hashing
  - Legacy key support for backward compatibility (VULNERABLE)
  - Multiple authentication methods

### Database Layer
- ✓ `app/db/database.py` - SQLAlchemy configuration
  - SQLite (development) and PostgreSQL support
  - Session management and dependency injection
  - Database initialization

### Models & Schemas
- ✓ `app/models/database.py` - SQLAlchemy ORM models
  - User, Account, Transaction, Card, Loan, KYC, AuditLog, AdminUser
  - Relationships and indexes for production queries
  
- ✓ `app/models/schemas.py` - Pydantic validation schemas
  - Secure v2 schemas with strict validation
  - Vulnerable v1 schemas with mass assignment

### Middleware
- ✓ `app/middleware/error_handler.py` - Error handling and logging
  - Verbose error responses for legacy endpoints (VULNERABLE)
  - Sanitized responses for v2 endpoints
  - Audit logging middleware
  - Rate limiting middleware (incomplete)

### Business Logic
- ✓ `app/services/service.py` - Service layer with vulnerabilities
  - UserService - ORM-based (secure)
  - AccountService - ORM-based (secure)
  - TransactionService - Mixed (secure ORM + vulnerable raw SQL)
  - AdminService - SQL injection vulnerabilities
  - NotificationService - HTTP calls without HTTPS
  - FraudService - Insecure internal calls

### API Endpoints

#### ✓ Modern v2 APIs (Secure)
- `POST /api/v2/auth/register` - Create user account
- `POST /api/v2/auth/login` - Authenticate with JWT
- `GET /api/v2/accounts/balance` - Get account balance
- `GET /api/v2/accounts/{id}` - Get account details
- `POST /api/v2/transfers/send` - Send transfer
- `POST /api/v2/kyc/upload` - Upload KYC document
- `GET /api/v2/transactions` - List transactions
- `POST /api/v2/cards/block` - Block credit card
- `GET /api/v2/health` - Health check

#### ✓ Legacy v1 APIs (Vulnerable)
**Authentication Issues:**
- `POST /api/v1/auth/login-legacy` - No rate limiting, weak auth (VULN)
- `GET /api/v1/auth/check-email` - User enumeration (VULN)
- `GET /api/v1/debug/user/{id}` - No auth, exposes password hash (VULN)

**SQL Injection:**
- `GET /api/v1/export/search?query=...` - F-string SQL building (VULN)
- `POST /api/v1/export/user-data` - Raw SQL concatenation (VULN)
- `GET /api/v1/admin/users/search` - Admin search with injection (VULN)

**Mass Assignment:**
- `POST /api/v1/account/update` - Blind field updates (VULN)
- `POST /api/v1/user/update` - Users can set is_admin, role, balance (VULN)

**Missing Rate Limiting:**
- `POST /api/v1/otp/request` - Unlimited requests (VULN)
- `POST /api/v1/password/reset` - Brute force enabled (VULN)
- `POST /api/v1/quick-pay` - Quick transfer with minimal validation (VULN)

**Zombie Endpoints:**
- `GET /api/v1/internal/system/status` - System info exposed (VULN)
- `GET /api/v1/internal/accounts/all` - Lists all accounts (VULN)
- `GET /api/v1/legacy/error-test` - Stack traces in responses (VULN)
- `GET /api/v1/beta/quick-balance/{id}` - Beta endpoint still active (VULN)
- `POST /api/v1/legacy/csv-export` - CSV export with SQL injection (VULN)

#### ✓ Admin APIs
- `POST /api/admin/login` - Hardcoded credentials (VULN)
- `GET /api/admin/dashboard` - System statistics (VULN)
- `GET /api/admin/users/list` - List all users (VULN)
- `POST /api/admin/users/delete` - Delete user without audit (VULN)
- `POST /api/admin/accounts/balance-adjust` - Direct balance modification (VULN)
- `POST /api/admin/accounts/unlock` - Unlock account (VULN)
- `GET /api/admin/transactions/search` - SQL injection (VULN)
- `POST /api/admin/transactions/reverse` - Reverse any transaction (VULN)
- `GET /api/admin/db/query` - Execute arbitrary SQL (VULN)
- `GET /api/admin/db/stats` - Database statistics (VULN)
- `GET /api/admin/audit/logs` - Access audit logs (VULN)
- `POST /api/admin/audit/logs/delete` - Delete audit logs (VULN)
- `GET /api/admin/config/view` - Expose all secrets (VULN)
- `POST /api/admin/config/update` - Update configuration (VULN)

#### ✓ Internal APIs
- `POST /api/internal/billing/create-invoice` - HTTP to billing service (VULN)
- `POST /api/internal/fraud/check-transaction` - HTTP to fraud service (VULN)
- `POST /api/internal/notifications/send` - HTTP notifications (VULN)
- `GET /api/internal/employees/list` - Employee directory (VULN)
- `GET /api/internal/employees/{id}/credentials` - Expose passwords (VULN)
- `GET /api/internal/reports/daily-summary` - SQL injection (VULN)
- `POST /api/internal/reports/export-data` - SQL injection (VULN)
- `GET /api/internal/audit/recent-activities` - Audit access (VULN)
- `GET /api/internal/health/detailed` - System info (VULN)

#### ✓ Debug Endpoints
- `GET /` - Root endpoint with API info
- `GET /api/health` - Basic health check
- `GET /api/v0/legacy-endpoint` - Very old API (deprecated)
- `GET /api/beta/experimental` - Beta endpoint
- `GET /api/debug/config` - Configuration info (VULN)
- `GET /api/debug/routes` - List all routes (VULN)

---

## 🔒 Vulnerability Pattern Coverage

✓ **8 Vulnerability Types Included:**

1. **Broken Authentication** - v1 endpoints skip JWT validation
2. **Missing Rate Limiting** - OTP, password reset, quick-pay endpoints
3. **Hardcoded Secrets** - API keys, DB passwords in config and legacy modules
4. **SQL Injection** - Raw queries with f-string concatenation
5. **Verbose Error Leakage** - Stack traces and DB errors exposed
6. **Mass Assignment** - Users can set is_admin, role, balance fields
7. **Insecure Internal HTTP** - Notification, fraud, billing services use HTTP
8. **Zombie APIs** - v1, v0, beta endpoints still active but poorly secured

---

## 📊 API Statistics

- **Total Endpoints:** 60+
- **Secure v2 Endpoints:** 9
- **Vulnerable v1 Endpoints:** 20
- **Admin Endpoints:** 14
- **Internal Endpoints:** 9
- **Debug Endpoints:** 6

---

## 🔍 Realistic Features

✓ Natural API responses (no explicit "VULNERABLE" messages)
✓ Vulnerabilities hidden in code implementation
✓ Mixed secure and insecure patterns
✓ TODO comments and technical debt markers
✓ Commented-out code and partial refactors
✓ Inconsistent naming conventions
✓ Multiple authentication approaches
✓ Some endpoints use ORM, others raw SQL
✓ Hardcoded credentials alongside env variables
✓ Forgotten internal endpoints accidentally exposed
✓ Debug endpoints left in production
✓ Service degradation with fail-open behavior

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd c:\Users\Shree\Desktop\backend\ alie
pip install -r requirements.txt
```

### 2. Run Locally
```bash
python -m app.scripts.populate_db
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Access
- **API Docs:** http://localhost:8000/api/docs
- **OpenAPI Schema:** http://localhost:8000/api/openapi.json
- **Root:** http://localhost:8000

### 4. Sample Login
```bash
curl -X POST http://localhost:8000/api/v2/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "password123"
  }'
```

---

## 🛡️ For Security Scanning

This codebase is designed to be detected by security scanners like ALIE (Semgrep-based):

**Expected Detections:**
- ✓ Hardcoded credentials in config.py
- ✓ SQL injection in raw SQL queries
- ✓ Missing authentication decorators
- ✓ Verbose error handling exposing internals
- ✓ HTTP calls without HTTPS
- ✓ Mass assignment vulnerabilities
- ✓ Zombie/deprecated API patterns
- ✓ Weak rate limiting

**Semgrep Scan:**
```bash
semgrep --config=p/security-audit app/
```

---

## 📝 Configuration

All secrets are in:
- `app/utils/config.py` - Hardcoded defaults and LEGACY_CONFIGS
- `.env.example` - Environment variables

Hardcoded values intentionally present for detection:
- JWT secrets
- Database passwords
- API keys (Stripe, AWS)
- Internal tokens
- Legacy configuration

---

## 🗂️ Project Structure (Complete)

```
backend alie/
├── app/
│   ├── main.py                      # FastAPI app
│   ├── api/
│   │   └── v2_api.py               # Secure endpoints
│   ├── legacy/
│   │   └── v1_api.py               # Vulnerable endpoints
│   ├── admin/
│   │   └── admin_api.py            # Admin endpoints
│   ├── internal/
│   │   └── internal_api.py         # Internal endpoints
│   ├── auth/
│   │   └── jwt_handler.py          # Authentication
│   ├── db/
│   │   └── database.py             # Database setup
│   ├── models/
│   │   ├── database.py             # ORM models
│   │   └── schemas.py              # Pydantic schemas
│   ├── middleware/
│   │   └── error_handler.py        # Middleware
│   ├── services/
│   │   └── service.py              # Business logic
│   ├── utils/
│   │   └── config.py               # Configuration
│   └── scripts/
│       └── populate_db.py          # Sample data
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## ✨ Key Characteristics

1. **Enterprise-Grade Structure** - Multiple modules, clear separation of concerns
2. **Mixed Implementation** - Some secure, some vulnerable, inconsistent standards
3. **Technical Debt** - TODO comments, partial refactors, legacy support
4. **Realistic Vulnerabilities** - Look natural, not intentionally planted
5. **Detectable by Scanners** - Static analysis can find vulnerabilities
6. **Production-Style** - Error handling, logging, Docker support
7. **Functional APIs** - Real database operations, sample data
8. **Security Demonstrations** - Perfect for demos, training, testing

---

## 🎯 Suitable For

- ✓ ALIE security scanner testing
- ✓ Semgrep vulnerability detection
- ✓ Security demonstration and training
- ✓ Penetration testing practice
- ✓ Banking API security analysis
- ✓ Legacy codebase remediation examples
- ✓ Security audit simulations
- ✓ Bug bounty testing scenarios

---

## ⚠️ Disclaimer

**This codebase is intentionally vulnerable for security research and testing purposes.**

- Do not deploy to production
- Do not expose to the internet
- For authorized security testing only
- Use only in controlled environments

---

**Status:** ✅ Complete and Ready for Security Scanning

All 50+ endpoints generated with realistic mixed secure/vulnerable implementations.
No external dependencies required to run (only Python packages).
