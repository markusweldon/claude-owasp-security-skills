---
name: owasp-api
description: Apply OWASP API Security Top 10:2023 standards when designing or reviewing REST, GraphQL, gRPC, or WebSocket APIs. Covers BOLA/IDOR, broken auth, excessive data exposure, unrestricted resource consumption, SSRF, and improper inventory management.
when_to_use: Use when building or reviewing API endpoints, REST or GraphQL services, microservices, API gateways, or any HTTP/WebSocket interface. Also use when someone asks about API authorization, rate limiting, object-level access control, API versioning security, or SSRF prevention.
---

# OWASP API Security Top 10:2023

## Quick Reference

| # | Risk | Key Mitigation |
|---|------|----------------|
| API1 | Broken Object Level Authorization | Validate user owns the requested object on every call |
| API2 | Broken Authentication | Strong tokens, short expiry, rotate secrets, no credentials in URLs |
| API3 | Broken Object Property Level Authorization | Return only fields the caller is authorized to see/write |
| API4 | Unrestricted Resource Consumption | Rate limit per user/key, cap request size and result count |
| API5 | Broken Function Level Authorization | Separate admin vs user endpoints; test with low-priv token |
| API6 | Unrestricted Access to Sensitive Business Flows | Bot detection, CAPTCHA, workflow rate limiting |
| API7 | Server Side Request Forgery (SSRF) | Validate/allowlist URLs, block internal ranges, disable redirects |
| API8 | Security Misconfiguration | Disable debug, remove unused methods, enforce TLS, set CORS tightly |
| API9 | Improper Inventory Management | Maintain API catalog, deprecate old versions, no shadow APIs |
| API10 | Unsafe Consumption of APIs | Treat third-party API responses as untrusted input |

---

## API Security Checklist

### Object & Property Authorization (API1, API3)
- [ ] Every endpoint verifies the authenticated user owns/can access the requested object (BOLA)
- [ ] Response serializers use an explicit allowlist of fields — never auto-serialize full DB row
- [ ] Write operations validate which fields the caller may update (mass assignment prevention)
- [ ] Indirect object references (UUIDs not sequential IDs) preferred to reduce enumeration

### Authentication (API2)
- [ ] Tokens signed and verified server-side (RS256/ES256 for JWT, not HS256 with weak secret)
- [ ] Short-lived access tokens (≤15 min); refresh tokens rotated on use
- [ ] No credentials, tokens, or API keys in query strings or logs
- [ ] API keys hashed in storage (not plaintext)
- [ ] Revocation mechanism exists (token blocklist or short TTL)

### Resource Consumption & Business Logic (API4, API6)
- [ ] Per-user and per-key rate limits on all endpoints
- [ ] Request payload size limits enforced (body, file upload, batch size)
- [ ] Pagination enforced with max `limit` cap; no unbounded `?limit=999999`
- [ ] Expensive operations (exports, bulk ops) are async + queued, not synchronous
- [ ] Critical business flows (checkout, password reset, OTP) have anti-automation controls

### Function Level Authorization (API5)
- [ ] Admin and management endpoints are on a separate path prefix or service
- [ ] HTTP method restrictions enforced (e.g., `PUT`/`DELETE` require elevated role)
- [ ] Horizontal privilege escalation tested with a low-privilege token against admin paths

### SSRF Prevention (API7)
```python
# UNSAFE — attacker can reach internal metadata endpoints
@app.post("/fetch")
def fetch(url: str):
    return requests.get(url).text

# SAFE — validate scheme and block internal ranges
# DNS rebinding risk: check and request use two separate DNS lookups.
# In production use `ssrf_filter` (pip install ssrf-filter) to pin DNS resolution.
import ipaddress, socket, urllib.parse

ALLOWED_SCHEMES = {"https"}
BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS metadata
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]

def safe_fetch(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Scheme not allowed")
    # Resolve all addresses (handles round-robin / multi-homed hosts)
    try:
        addrs = {r[4][0] for r in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        raise ValueError("Could not resolve hostname")
    for addr in addrs:
        if any(ipaddress.ip_address(addr) in r for r in BLOCKED_RANGES):
            raise ValueError("Internal IP not allowed")
    # Production: replace the line below with ssrf_filter to pin DNS
    # from ssrf_filter import ssrf_filter; return ssrf_filter(url).text
    return requests.get(url, allow_redirects=False, timeout=5).text
```

### Security Misconfiguration (API8)
```yaml
# Checklist for API deployment
- TLS 1.2+ enforced; HTTP redirects to HTTPS
- CORS: explicit origin allowlist, not "*" for credentialed requests
- Unused HTTP methods disabled (OPTIONS/TRACE removed in prod)
- Security headers set: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options
- Debug endpoints (/debug, /metrics, /actuator) blocked in prod or auth-gated
- Error responses: never expose stack traces, DB errors, or internal paths
```

### Mass Assignment (API3)
```javascript
// UNSAFE — binds all request body fields to model
app.put('/users/:id', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, req.body);
});

// SAFE — explicit field allowlist
app.put('/users/:id', async (req, res) => {
  const allowed = ['name', 'email', 'bio'];
  const update = Object.fromEntries(
    Object.entries(req.body).filter(([k]) => allowed.includes(k))
  );
  await User.findByIdAndUpdate(req.params.id, update);
});
```

### Rate Limiting (API4)
```python
# SAFE — tiered rate limiting
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: g.user_id)

@app.post("/api/export")
@limiter.limit("5/hour")          # per-user hourly cap
@limiter.limit("2/minute")        # per-user burst cap
def export_data():
    queue_export_job(g.user_id)
    return {"status": "queued"}, 202
```

### Unsafe Third-Party API Consumption (API10)
```python
# UNSAFE — trusts external API response blindly
data = requests.get("https://partner-api.example.com/user").json()
db.update_user(user_id, **data)  # potential mass assignment + injection

# SAFE — validate schema and sanitize
schema = {"name": str, "email": str}
data = requests.get("https://partner-api.example.com/user", timeout=5).json()
validated = {k: schema[k](v) for k, v in data.items() if k in schema}
db.update_user(user_id, **validated)
```

---

## GraphQL-Specific Risks

```graphql
# UNSAFE — no depth/complexity limit; DoS via deeply nested query
query {
  user { posts { comments { author { posts { comments { ... } } } } } }
}
```

**GraphQL hardening checklist:**
- [ ] Query depth limit enforced (e.g., max 5 levels)
- [ ] Query complexity scoring + budget per request
- [ ] Introspection disabled in production
- [ ] Mutations require explicit authorization per field
- [ ] Batch query limits (prevents N+1 DoS)

---

## API Inventory & Versioning (API9)

- [ ] All API versions are documented in a central catalog (OpenAPI/Swagger)
- [ ] Deprecated versions have a sunset date and are actively monitored
- [ ] Shadow APIs (undocumented internal endpoints) discovered via traffic analysis
- [ ] Third-party integrations inventoried; unused ones removed
- [ ] API versioning strategy enforced — old versions retired within defined SLA

---

## JWT Security Checklist

- [ ] `alg: none` rejected server-side
- [ ] Algorithm pinned to RS256/ES256 — never trust `alg` header from token
- [ ] `aud` (audience) and `iss` (issuer) claims validated
- [ ] `exp` (expiry) validated and enforced
- [ ] Token not stored in `localStorage` (use `httpOnly` cookie)
- [ ] Sensitive data not stored in JWT payload (it's base64, not encrypted)

```python
# SAFE JWT validation (PyJWT)
import jwt
payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"],           # pin algorithm — never ["RS256", "none"]
    audience="https://api.example.com",
    issuer="https://auth.example.com",
)
```
