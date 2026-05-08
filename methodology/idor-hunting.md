# Methodology: IDOR Hunting

**Difficulty:** Easy-Medium | **Avg Bounty:** $500-$5,000 | **Competition:** Low-Medium

## Why IDOR?

IDOR (Insecure Direct Object Reference) is the **#1 easiest entry point** for bug bounty:
- No special tools needed — just a browser + Burp
- Appears in almost every app with user-specific resources
- High acceptance rate on HackerOne/Bugcrowd
- Automated scanners can't find it (requires logic understanding)

## Attack Surface

Any endpoint that references a user-owned resource:
```
GET /api/users/123/orders
GET /api/invoices/INV-2024-0042
GET /api/documents/doc_abc123
POST /api/v1/account/settings   (body: {"user_id": "victim@email.com"})
GET /download?file=user_123_report.pdf
```

## Step-by-Step

### 1. Map User-Specific Endpoints
```
Register 2 accounts (A and B).
Use account A, capture every request in Burp.
Look for any parameter that references:
  - Numeric IDs (user_id=123)
  - UUIDs (order_id=550e8400-e29b-41d4-a716-446655440000)
  - Email/username references
  - File paths or document names
  - Encoded tokens (base64 user data)
```

### 2. Swap IDs Between Accounts
```
For each endpoint found:
1. Note the request as Account A
2. Change the ID to Account B's ID
3. Send the request
4. If you get Account B's data → IDOR confirmed

Also try:
- Remove the ID parameter entirely
- Set ID to 0 or null
- Use array: user_id[]=123&user_id[]=456
- Wildcard: user_id=*
```

### 3. Common Bypasses
```
# If they use UUID and you only have your own:
- Check if UUID appears in other API responses
- Check if user profile exposes their UUID
- Check if the app leaks IDs in HTML source

# If they check ownership server-side:
- Try different HTTP methods (GET vs POST vs PUT vs DELETE)
- Try adding X-Original-URL or X-Forwarded-For headers
- Try URL encoding: %31%32%33 instead of 123
- Try path traversal: /api/users/../other_users/456/data

# If numeric but sequential:
- Just increment/decrement — most common IDOR
- Try negative: user_id=-1
- Try zero: user_id=0
```

### 4. IDOR in Different Contexts

**REST APIs:**
```
GET /api/v2/users/{id}/profile
PATCH /api/v2/users/{id}/email
DELETE /api/v2/users/{id}
```

**GraphQL:**
```graphql
query {
  user(id: "VICTIM_ID") {
    email
    orders { amount }
  }
}
```

**File Downloads:**
```
GET /api/files/report_2024_USERID.pdf
GET /export?user_id=123&format=csv
```

**Admin Functions:**
```
GET /admin/users/123/settings     (normal user accessing admin endpoint)
POST /api/admin/delete-user  {"id": 456}
```

### 5. Automation

```bash
# Find endpoints with numeric IDs
cat endpoints.txt | grep -E '[?&](id|user|account|order|doc|file|invoice)=[0-9]+' > idor_candidates.txt

# ffuf IDOR test (change FUZZ to sequential IDs)
ffuf -u "https://target.com/api/users/FUZZ/profile" -w <(seq 1 1000) -mc 200 -fc 403,404
```

## Real-World Patterns

| App Type | Common IDOR Points |
|----------|--------------------|
| E-commerce | Orders, invoices, addresses, wishlists |
| SaaS | Workspaces, projects, documents, billing |
| Healthcare | Patient records, appointments, prescriptions |
| Finance | Transactions, accounts, statements |
| Social | Messages, profiles, connections, posts |

## Report Template

**Title:** Insecure Direct Object Reference in [Endpoint] allows unauthorized access to [resource]

**Severity:** High (if PII exposed) / Medium (if non-sensitive data)

**Steps to Reproduce:**
1. Login as Account A, navigate to [URL]
2. Intercept request, note parameter [param]=[A's ID]
3. Change value to Account B's ID
4. Observe Account B's data returned

**Impact:** An authenticated attacker can access any user's [data type] by iterating through IDs.

**Remediation:** Implement server-side authorization checks. Verify the authenticated user owns the requested resource.
