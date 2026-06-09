---
name: owasp-web
description: Apply OWASP Top 10:2025 and ASVS 5.0 security standards when writing or reviewing web application code. Covers broken access control, injection, cryptographic failures, auth weaknesses, and 20+ language-specific security pitfalls.
when_to_use: Use when reviewing code for security vulnerabilities, implementing authentication or authorization, handling user input, storing passwords or secrets, designing server-side logic, or when someone asks about web application security, secure coding, or vulnerability prevention.
---

# OWASP Web Security (Top 10:2025 + ASVS 5.0)

## Quick Reference: OWASP Top 10:2025

| # | Vulnerability | Key Prevention |
|---|---------------|----------------|
| A01 | Broken Access Control | Deny by default, enforce server-side, verify ownership |
| A02 | Security Misconfiguration | Harden configs, disable defaults, minimize features |
| A03 | Supply Chain Failures | Lock versions, verify integrity, audit dependencies |
| A04 | Cryptographic Failures | TLS 1.2+, AES-256-GCM, Argon2/bcrypt for passwords |
| A05 | Injection | Parameterized queries, input validation, safe APIs |
| A06 | Insecure Design | Threat model, rate limit, design security controls |
| A07 | Auth Failures | MFA, check breached passwords, secure sessions |
| A08 | Integrity Failures | Sign packages, SRI for CDN, safe serialization |
| A09 | Logging Failures | Log security events, structured format, alerting |
| A10 | Exception Handling | Fail-closed, hide internals, log with context |

## Security Code Review Checklist

### Input Handling
- [ ] All user input validated server-side
- [ ] Parameterized queries (never string concatenation)
- [ ] Input length limits enforced
- [ ] Allowlist validation preferred over denylist

### Authentication & Sessions
- [ ] Passwords hashed with Argon2/bcrypt (not MD5/SHA1)
- [ ] Session tokens have 128+ bits entropy
- [ ] Sessions invalidated on logout
- [ ] MFA available for sensitive operations
- [ ] Passwords checked against breach lists (HIBP)

### Access Control
- [ ] Check for framework-level auth middleware before flagging missing per-route auth
- [ ] Authorization checked on every request server-side
- [ ] Object ownership verified (IDOR prevention)
- [ ] Deny by default policy enforced
- [ ] Privilege escalation paths reviewed

### Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] TLS 1.2+ for all data in transit
- [ ] No sensitive data in URLs or logs
- [ ] Secrets in environment/vault (not hardcoded)

### Error Handling
- [ ] No stack traces exposed to users
- [ ] Fail-closed on errors (deny, not allow)
- [ ] All exceptions logged with context + correlation ID
- [ ] Consistent error responses (prevents enumeration)

## Secure Code Patterns

### SQL Injection
```python
# UNSAFE
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Command Injection
```python
# UNSAFE
os.system(f"convert {filename} output.png")
# SAFE
subprocess.run(["convert", filename, "output.png"], shell=False)
```

### Password Storage
```python
# UNSAFE
hashlib.md5(password.encode()).hexdigest()
# SAFE
from argon2 import PasswordHasher
PasswordHasher().hash(password)
```

### Access Control
```python
# UNSAFE — no authorization check
@app.route('/api/user/<user_id>')
def get_user(user_id):
    return db.get_user(user_id)

# SAFE — authorization enforced
@app.route('/api/user/<user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    return db.get_user(user_id)
```

### Fail-Closed Error Handling
```python
# UNSAFE — fail-open
def check_permission(user, resource):
    try:
        return auth_service.check(user, resource)
    except Exception:
        return True  # DANGEROUS

# SAFE — fail-closed
def check_permission(user, resource):
    try:
        return auth_service.check(user, resource)
    except Exception as e:
        logger.error(f"Auth check failed: {e}")
        return False
```

### Secure Error Response
```python
# UNSAFE — leaks internals
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500

# SAFE
@app.errorhandler(Exception)
def handle_error(e):
    error_id = uuid.uuid4()
    logger.exception(f"Error {error_id}: {e}")
    return {"error": "An error occurred", "id": str(error_id)}, 500
```

## ASVS 5.0 Verification Levels

| Level | Requirement |
|-------|-------------|
| **L1** | Passwords ≥12 chars, breach-list check, rate limiting, session tokens 128+ bits, HTTPS everywhere |
| **L2** | All L1 + MFA for sensitive ops, crypto key management, comprehensive security logging, input validation |
| **L3** | All L2 + HSM for keys, threat modeling docs, advanced monitoring, pen testing validation |

**New in ASVS 5.0:** V15 (OAuth/OIDC), V16 (Self-Contained Tokens/JWT), V17 (WebSockets)

## Language-Specific Security Pitfalls

### JavaScript / TypeScript
```javascript
// UNSAFE: prototype pollution
Object.assign(target, userInput)
// SAFE: null prototype
Object.assign(Object.create(null), validated)
```
**Watch:** `eval()`, `innerHTML`, `document.write()`, `__proto__`, prototype chain manipulation

### Python
```python
# UNSAFE: pickle RCE
pickle.loads(user_data)
# SAFE
json.loads(user_data)
```
**Watch:** `pickle`, `eval()`, `exec()`, `os.system()`, `subprocess(shell=True)`

### Java
```java
// UNSAFE: arbitrary deserialization RCE
Object obj = new ObjectInputStream(userStream).readObject();
// SAFE
mapper.readValue(json, SafeClass.class);
```
**Watch:** `ObjectInputStream`, `Runtime.exec()`, XML parsers without XXE protection, JNDI lookups

### C#
```csharp
// UNSAFE: BinaryFormatter RCE
object obj = new BinaryFormatter().Deserialize(stream);
// SAFE
var obj = JsonSerializer.Deserialize<SafeType>(json);
```
**Watch:** `BinaryFormatter`, `JavaScriptSerializer`, `TypeNameHandling.All`, raw SQL strings

### PHP
```php
// UNSAFE: type juggling in auth
if ($password == $stored_hash) { ... }
// SAFE
if (hash_equals($stored_hash, $password)) { ... }
```
**Watch:** `==` vs `===`, `include/require` with user input, `unserialize()`, `preg_replace /e`

### Go
```go
// UNSAFE: race condition
go func() { counter++ }()
// SAFE
atomic.AddInt64(&counter, 1)
```
**Watch:** goroutine data races, `template.HTML()`, `unsafe` package, unchecked slice access

### Ruby
```ruby
# UNSAFE: YAML RCE
YAML.load(user_input)
# SAFE
YAML.safe_load(user_input)
```
**Watch:** `Marshal.load`, `eval`, `send` with user input, `.permit!` (Rails)

### Rust
```rust
// UNSAFE: integer overflow in release builds
let y = x + 1; // wraps to 0 silently!
// SAFE
let y = x.checked_add(1).unwrap_or(255);
```
**Watch:** `unsafe` blocks, FFI calls, `.unwrap()` on untrusted input

### C / C++
```c
// UNSAFE: buffer overflow
char buf[10]; strcpy(buf, userInput);
// SAFE
strncpy(buf, userInput, sizeof(buf) - 1);
// UNSAFE: format string
printf(userInput);
// SAFE
printf("%s", userInput);
```
**Watch:** `strcpy`, `sprintf`, `gets`, pointer arithmetic, manual memory management

### Shell (Bash)
```bash
# UNSAFE: unquoted variables + eval
rm $user_file; eval "$user_command"
# SAFE
rm "$user_file"  # never eval user input
```
**Watch:** unquoted variables, backticks, `$(...)` with user input, missing `set -euo pipefail`

### SQL
```sql
-- UNSAFE
"SELECT * FROM users WHERE id = " + userId
-- SAFE: always use prepared statements / parameterized queries
```
**Watch:** dynamic SQL, `EXECUTE IMMEDIATE`, stored procedures with dynamic queries

> For Python, Kotlin, Swift, Dart, Scala, R, Perl, Lua, Elixir, PowerShell — see `docs/language-security-reference.md`

## Deep Security Analysis Mindset

When reviewing any language think like a security researcher:
1. **Memory model** — managed vs manual; GC pauses exploitable?
2. **Type system** — weak typing = type confusion; coercion exploits
3. **Serialization** — every language has its pickle/Marshal equivalent; all are dangerous
4. **Concurrency** — race conditions, TOCTOU, atomicity failures
5. **FFI boundaries** — native interop is where type safety breaks down
6. **Standard library CVEs** — research historic CVEs for the specific stdlib
7. **Package ecosystem** — typosquatting, dependency confusion, malicious packages
8. **Build system** — Makefile/gradle/npm script injection during builds
9. **Debug vs release** — different behavior (Rust overflow, C++ assertions)
10. **Error handling** — how does it fail? Silently? With stack traces? Fail-open?
