# CLAUDE.md — OWASP Luxora CTF Project

> **Project**: Vulnerable e-commerce CTF platform with 25 intentional OWASP vulnerabilities
> **Stack**: Node.js + Express + PostgreSQL + EJS

---

## CORE PRINCIPLES

**Investigate First** — Read the file before answering. Never rely on memory. Mark unverified items as `[NEEDS VERIFICATION]`.

**Pre-Work** — Before touching code: (1) trace the full call chain, (2) list all affected files, (3) write a checklist, (4) get approval.

**Scope** — Modify only what was requested. No "while I'm at it" changes. No preemptive code.

**Anti-Hallucination** — Never reference unconfirmed functions/files/variables. Banned: "probably", "should work", "I think", "likely". Say "I don't know" when unsure.

**Completion** — Nothing is done until tests pass. Declare completion with: tests run, pass/fail count, side-effect review, changed files list.

**Project-Specific** — DO NOT fix vulnerabilities — they are intentional. Preserve 100% vulnerability behavior.

---

## MODULIZATION PROTOCOL

> Smallest unit first · One thing at a time · Fully independent steps · Divide and conquer

### Hard Constraints

| NEVER | ALWAYS |
|---|---|
| Modulize the entire system at once | Full project survey before starting |
| Start without a written plan | Pick exactly one most-urgent thing |
| Leave old + new code coexisting | Write plan first, check off as you go |
| Change behavior while modulizing | Zero Backward Compatibility — delete old code |
| Declare complete via grep/pattern match | Zero Behavioral Change — 100% behavior preserved |
| Declare migration done without tests | 100% tests pass after each step |

---

## CHECKLIST EXECUTION RULE

> **Before checking off ANY item — run the full survey flow below.**
> Every single checkbox requires completing this flow first. No exceptions.

```
FULL SURVEY FLOW (required before each checkbox):
  □ Re-read all relevant files from scratch — no assumptions from prior steps
  □ Re-trace entry points → data flow → exit points, all branches
  □ Re-verify inter-module dependencies and dynamic registrations
  □ Confirm no side effects introduced by the previous step
  □ Run tests — confirm 100% pass
  → Only after all above: check off the item and proceed
```

---

## MODULIZATION STEPS

### STEP 1 — Pre-Work Survey
```
□ Enumerate all entry points (API / Event / Cron / CLI / DI)
□ Trace data flow — entry to exit, every branch
□ Map inter-module dependencies — micro to macro
□ Identify dynamic registrations (Registry / Event Emitter / DI / string dispatch)
□ Confirm public API list from all barrel/entry-point files
□ Full understanding confirmed — thoroughly
```

### STEP 2 — Target Selection
```
□ Select exactly one thing most urgently needed for cohesion/extensibility
□ State the reason: "Why this, why now?" (one sentence)
```

### STEP 3 — Write a Plan (task/<n>.md)
```
□ As-Is: file locations, dependencies, current problems
□ To-Be: new module boundaries, file/folder layout
□ Migration steps: numbered, sequential, each independently testable
□ Rollback plan
```

### STEP 4 — Execute
```
□ [FULL SURVEY FLOW] → Step 1
□ [FULL SURVEY FLOW] → Step 2
□ [FULL SURVEY FLOW] → Step N ...
  - Run tests after each step — stop if any fail
  - Delete old code immediately after replacement is verified
  - No behavior changes — modulization only
```

### STEP 5 — Post-Work Survey
```
□ [FULL SURVEY FLOW] → final pass
□ No dead code, orphaned imports, or duplicate logic
□ Documentation and barrel files updated
```

---

## CHECKLIST FORMAT

```markdown
## Task: <description>

### Pre-Work
- [ ] [FULL SURVEY FLOW] Read all relevant files
- [ ] Impact analysis complete
- [ ] Approved by user

### Execution
- [ ] [FULL SURVEY FLOW] Step 1 — <description>
- [ ] [FULL SURVEY FLOW] Step 2 — <description>

### Completion
- [ ] [FULL SURVEY FLOW] Final verification
- [ ] Tests: <command> → X passed / Y failed
- [ ] Side effects reviewed
- [ ] Changed files: <list>
```

---

## PROJECT STRUCTURE

```
app/
├── server.js              # Main Express server (1990 lines → being modularized)
├── routes/                # Route modules (Phase 1 complete)
│   ├── index.js           # Route aggregator
│   └── info.js            # Info/static routes (7 routes)
├── views/                 # EJS templates (23 files)
├── flags/                 # CTF flags (25 files)
├── secrets/               # Exposed credentials (intentional)
├── uploads/               # File upload directory
└── public/                # Static files

task/
└── 001-route-extraction.md   # Phase 1 plan (complete)
```

---

## ROUTES BY DOMAIN

### Extracted (routes/info.js)
- `GET /dev-notes` — Developer notes
- `GET /api-docs` — API documentation
- `GET /robots.txt` — Robots file
- `GET /sitemap.xml` — Sitemap
- `GET /.well-known/security.txt` — Security info
- `GET /backup` — Backup directory
- `GET /.git/config` — Git config

### Remaining in server.js (73+ routes)
- Auth: `/login`, `/register`, `/account`, `/profile/:id`, `/logout`
- Products: `/products`, `/category/:name`, `/new-arrivals`, `/sale`
- Orders: `/track-order`, `/checkout`
- Admin: `/admin`, `/admin/login`
- Injection: `/search`, `/ldap`, `/xpath`, `/ping`, `/dns`, `/file`
- SSRF: `/image`, `/fetch`, `/proxy`
- XSS: `/search-xss`, `/comments`, `/dom-xss`
- RCE: `/cmd`, `/webshell`, `/shell`
- File: `/upload`, `/download`, `/read-file`
- And 50+ more...

---

## VULNERABILITY CATEGORIES (25 CTF Flags)

| # | Category | Example Route | Flag File |
|---|----------|---------------|-----------|
| 1 | SQL Injection | `/login`, `/search` | flag_sqli.txt |
| 2 | XSS | `/comments`, `/search-xss` | flag_xss.txt |
| 3 | SSRF | `/image`, `/fetch`, `/proxy` | flag_ssrf.txt |
| 4 | Command Injection | `/ping`, `/dns`, `/cmd` | flag_rce.txt |
| 5 | Path Traversal | `/download`, `/read-file` | flag_lfi.txt |
| 6 | IDOR | `/profile/:id` | flag_idor.txt |
| 7 | XXE | `/xml` | flag_xxe.txt |
| 8 | SSTI | `/template` | flag_ssti.txt |
| 9 | LDAP Injection | `/ldap` | flag_ldap.txt |
| 10 | XPath Injection | `/xpath` | flag_xpath.txt |
| 11 | NoSQL Injection | `POST /search` | flag_nosqli.txt |
| 12 | Prototype Pollution | `POST /merge` | flag_prototype.txt |
| 13 | Deserialization | `POST /deserialize` | flag_deser.txt |
| 14 | Open Redirect | `/redirect` | flag_redirect.txt |
| 15 | File Upload | `POST /upload` | flag_upload.txt |
| 16 | RFI | `/rfi-challenge` | flag_rfi.txt |
| 17 | Web Shell | `POST /webshell` | flag_revshell.txt |
| 18 | JWT Weakness | `/jwt` | (crypto) |
| 19 | CORS Misconfig | `/api/data` | (config) |
| 20 | Session Fixation | `/session` | (auth) |
| 21 | Brute Force | `POST /brute` | flag_brute.txt |
| 22 | Host Header | `POST /reset-password` | flag_host.txt |
| 23 | CSRF | `/account/password` | (auth) |
| 24 | Admin Bypass | `/admin` | flag_admin.txt |
| 25 | Reversing | `/admin/shell-auth.js` | flag_reversing.txt |

---

## REFACTORING PHASES

### Phase 1: Info Routes ✅ COMPLETE
- Extracted 7 static routes to `routes/info.js`
- Created `routes/index.js` aggregator
- Deleted old routes from `server.js`
- Reduced `server.js` from 2115 → 1990 lines

### Phase 2: Auth Routes (Planned)
- Routes: `/login`, `/register`, `/account`, `/profile/:id`, `/logout`
- Requires: Database layer extraction first

### Phase 3: Product Routes (Planned)
- Routes: `/products`, `/category/:name`, `/new-arrivals`, `/sale`
- Requires: Database layer extraction first

### Future: Database Layer
- Create `db/` directory with repository pattern
- Extract inline SQL queries from routes
- Centralize `pool` management

---

## QUICK COMMANDS

```bash
# Syntax check
node --check server.js
node --check routes/index.js
node --check routes/info.js

# Verify route module
node -e "const r = require('./routes/info'); console.log(r.stack.length, 'routes')"

# Count lines
wc -l server.js routes/*.js

# Find route definitions
grep -n "^app\.\(get\|post\|put\)" server.js
```

---

## DATABASE SCHEMA

```sql
users (id, username, password, email, ssn, credit_card, role, reset_token, security_question, api_key)
comments (id, author, content, created_at)
products (id, name, price, image_url, category, description, stock, badge, original_price, data)
secrets (id, name, value)
```

---

## NOTES

- **DO NOT** fix vulnerabilities during refactoring
- **DO NOT** add validation, sanitization, or security improvements
- **ONLY** move code to improve structure and maintainability
- Preserve all CTF flag behaviors exactly
