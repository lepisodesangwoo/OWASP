/**
 * Server-Side Layer Routes
 * 14 flags across 5 server-side types
 */

const express = require('express');
const router = express.Router();
const axios = require('axios');
const _ = require('lodash');
const path = require('path');
const fs = require('fs');

const FLAGS_DIR = path.join(__dirname, '..', 'flags', 'server');

const getFlag = (subdir, filename) => {
  const flagPath = path.join(FLAGS_DIR, subdir, filename);
  if (fs.existsSync(flagPath)) {
    return fs.readFileSync(flagPath, 'utf8').trim();
  }
  return `FLAG{${subdir.toUpperCase()}_${filename.replace('.txt', '').toUpperCase()}_NOT_FOUND}`;
};

// ============================================
// SSRF (4 tiers)
// ============================================

router.get('/ssrf/bronze', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.json({
      endpoint: '/ssrf/bronze',
      hint: 'Fetch any URL from server',
      example: '?url=http://127.0.0.1:8080/internal'
    });
  }

  // VULN: No URL validation
  try {
    const response = await axios.get(url);
    const flagContent = getFlag('ssrf', 'ssrf_bronze.txt');
    return res.json({
      success: true,
      message: 'SSRF successful!',
      data: response.data,
      flag: flagContent
    });
  } catch (err) {
    res.json({ error: err.message, url });
  }
});

router.get('/ssrf/silver', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.json({
      endpoint: '/ssrf/silver',
      hint: 'Access cloud metadata',
      target: 'http://169.254.169.254/latest/meta-data/'
    });
  }

  // VULN: Can access internal/metadata
  if (url.includes('169.254.169.254') || url.includes('metadata') || url.includes('127.0.0.1')) {
    const flagContent = getFlag('ssrf', 'ssrf_silver.txt');
    return res.json({
      success: true,
      message: 'Cloud metadata accessed!',
      metadata: {
        amiId: 'ami-12345678',
        instanceId: 'i-abcdef12',
        iamRole: 'admin-role'
      },
      flag: flagContent
    });
  }

  try {
    const response = await axios.get(url);
    res.json({ data: response.data });
  } catch (err) {
    res.json({ error: err.message });
  }
});

router.get('/ssrf/gold', async (req, res) => {
  const { target } = req.query;

  if (!target) {
    return res.json({
      endpoint: '/ssrf/gold',
      hint: 'DNS rebinding attack',
      explanation: 'First resolve to allowed IP, then to 127.0.0.1'
    });
  }

  // VULN: DNS rebinding simulation
  if (target.includes('rebind') || target.includes('attacker')) {
    const flagContent = getFlag('ssrf', 'ssrf_gold.txt');
    return res.json({
      success: true,
      message: 'DNS rebinding SSRF successful!',
      resolvedTo: '127.0.0.1 (after initial allowed IP)',
      internalData: 'Sensitive internal data',
      flag: flagContent
    });
  }

  res.json({ target: target, message: 'URL validated' });
});

router.get('/ssrf/platinum', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.json({
      endpoint: '/ssrf/platinum',
      hint: 'Protocol smuggling: gopher://, dict://',
      example: '?url=gopher://127.0.0.1:6379/_INFO'
    });
  }

  // VULN: Protocol smuggling
  if (url.startsWith('gopher://') || url.startsWith('dict://') || url.startsWith('file://')) {
    const flagContent = getFlag('ssrf', 'ssrf_platinum.txt');
    return res.json({
      success: true,
      message: 'Protocol smuggling SSRF!',
      protocol: url.split(':')[0],
      result: 'Redis/Memcached internal service accessed',
      flag: flagContent
    });
  }

  res.json({ url: url, message: 'Only HTTP allowed' });
});

// ============================================
// PROTOTYPE POLLUTION (3 tiers)
// ============================================

router.post('/proto/bronze', (req, res) => {
  const { config } = req.body;

  if (!config) {
    return res.json({
      endpoint: 'POST /proto/bronze',
      hint: 'Pollute Object.prototype',
      example: '{"__proto__":{"admin":true}}'
    });
  }

  // VULN: Deep merge with prototype pollution
  const target = {};
  try {
    _.merge(target, config);

    if ({}.admin === true || config.__proto__) {
      const flagContent = getFlag('proto_pollute', 'proto_pollute_bronze.txt');
      return res.json({
        success: true,
        message: 'Prototype pollution achieved!',
        polluted: true,
        flag: flagContent
      });
    }

    res.json({ config: target });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/proto/silver', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.json({
      endpoint: 'POST /proto/silver',
      hint: 'RCE via prototype pollution chain',
      chain: 'pollute shellPath -> trigger exec'
    });
  }

  // VULN: Prototype pollution to RCE
  if (data.__proto__ || data.constructor?.prototype) {
    const flagContent = getFlag('proto_pollute', 'proto_pollute_silver.txt');
    return res.json({
      success: true,
      message: 'Prototype pollution RCE chain!',
      executed: 'spawn child_process with polluted shell',
      flag: flagContent
    });
  }

  res.json({ data: data });
});

router.post('/proto/gold', (req, res) => {
  const { payload } = req.body;

  if (!payload) {
    return res.json({
      endpoint: 'POST /proto/gold',
      hint: 'Bypass safe merge with special properties',
      bypass: 'constructor.prototype, __proto__ alternatives'
    });
  }

  // VULN: Safe mode bypass
  const blocked = ['__proto__'];
  const dataStr = JSON.stringify(payload);

  if (!blocked.some(b => dataStr.includes(b)) && payload.constructor?.prototype) {
    const flagContent = getFlag('proto_pollute', 'proto_pollute_gold.txt');
    return res.json({
      success: true,
      message: 'Safe mode bypass via constructor.prototype!',
      flag: flagContent
    });
  }

  res.json({ payload: payload, safe: true });
});

// ============================================
// RACE CONDITION (3 tiers)
// ============================================

const balances = new Map([['user1', 100], ['user2', 50]]);
const coupons = new Map([['SAVE10', { used: false, value: 10 }]]);

router.post('/race/bronze', async (req, res) => {
  const { account, amount } = req.body;

  if (!account) {
    return res.json({
      endpoint: 'POST /race/bronze',
      hint: 'TOCTOU in balance check',
      accounts: ['user1', 'user2']
    });
  }

  // VULN: Time-of-check to time-of-use
  const balance = balances.get(account) || 0;

  // Simulate delay between check and use
  await new Promise(r => setTimeout(r, 100));

  if (amount > balance) {
    return res.status(400).json({ error: 'Insufficient funds', balance });
  }

  // VULN: Race allows multiple withdrawals
  balances.set(account, balance - amount);

  if (balances.get(account) < 0) {
    const flagContent = getFlag('race', 'race_bronze.txt');
    return res.json({
      success: true,
      message: 'TOCTOU race condition exploited!',
      balance: balances.get(account),
      flag: flagContent
    });
  }

  res.json({ account, balance: balances.get(account), withdrawn: amount });
});

router.post('/race/silver', async (req, res) => {
  const { coupon } = req.body;

  if (!coupon) {
    return res.json({
      endpoint: 'POST /race/silver',
      hint: 'Race coupon usage',
      coupons: ['SAVE10']
    });
  }

  const couponData = coupons.get(coupon);

  if (!couponData) {
    return res.status(404).json({ error: 'Coupon not found' });
  }

  // VULN: Check and use are not atomic
  if (couponData.used) {
    return res.status(400).json({ error: 'Coupon already used' });
  }

  await new Promise(r => setTimeout(r, 50));

  // Race: multiple requests can pass the check
  couponData.used = true;
  coupons.set(coupon, couponData);

  // Check if coupon was used multiple times
  if (req.headers['x-race'] === 'true') {
    const flagContent = getFlag('race', 'race_silver.txt');
    return res.json({
      success: true,
      message: 'Coupon race condition exploited!',
      discount: couponData.value,
      flag: flagContent
    });
  }

  res.json({ message: 'Coupon applied', discount: couponData.value });
});

router.post('/race/gold', async (req, res) => {
  const { from, to, amount } = req.body;

  if (!from || !to) {
    return res.json({
      endpoint: 'POST /race/gold',
      hint: 'Race balance transfer',
      accounts: ['user1', 'user2']
    });
  }

  // VULN: Non-atomic transfer
  const fromBalance = balances.get(from) || 0;
  const toBalance = balances.get(to) || 0;

  if (fromBalance < amount) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }

  await new Promise(r => setTimeout(r, 100));

  // Race allows negative balance
  balances.set(from, fromBalance - amount);
  balances.set(to, toBalance + amount);

  if (balances.get(from) < 0) {
    const flagContent = getFlag('race', 'race_gold.txt');
    return res.json({
      success: true,
      message: 'Transfer race condition exploited!',
      from: { account: from, balance: balances.get(from) },
      to: { account: to, balance: balances.get(to) },
      flag: flagContent
    });
  }

  res.json({
    from: { account: from, balance: balances.get(from) },
    to: { account: to, balance: balances.get(to) }
  });
});

// ============================================
// HTTP REQUEST SMUGGLING (2 tiers)
// ============================================

router.post('/smuggle/bronze', (req, res) => {
  const { body } = req;

  if (!body || Object.keys(body).length === 0) {
    return res.json({
      endpoint: 'POST /smuggle/bronze',
      hint: 'CL.TE smuggling',
      explanation: 'Front-end uses Content-Length, back-end uses Transfer-Encoding'
    });
  }

  // VULN: CL.TE desync
  const cl = req.headers['content-length'];
  const te = req.headers['transfer-encoding'];

  if (cl && te) {
    const flagContent = getFlag('smuggle', 'smuggle_bronze.txt');
    return res.json({
      success: true,
      message: 'CL.TE request smuggling detected!',
      contentLength: cl,
      transferEncoding: te,
      flag: flagContent
    });
  }

  res.json({ body: body, message: 'Request processed' });
});

router.post('/smuggle/silver', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.json({
      endpoint: 'POST /smuggle/silver',
      hint: 'TE.CL smuggling',
      explanation: 'Front-end uses Transfer-Encoding, back-end uses Content-Length'
    });
  }

  // VULN: TE.CL desync
  const te = req.headers['transfer-encoding'];

  if (te && te.includes('chunked')) {
    const flagContent = getFlag('smuggle', 'smuggle_silver.txt');
    return res.json({
      success: true,
      message: 'TE.CL request smuggling detected!',
      transferEncoding: te,
      nextRequest: 'Smuggled request processed by backend',
      flag: flagContent
    });
  }

  res.json({ data: data });
});

// ============================================
// CACHE POISONING (2 tiers)
// ============================================

router.get('/cache/bronze', (req, res) => {
  const { lang } = req.query;

  // VULN: Unkeyed header affects cache
  const xForwardedHost = req.headers['x-forwarded-host'];

  if (xForwardedHost) {
    const flagContent = getFlag('cache', 'cache_bronze.txt');
    return res.json({
      success: true,
      message: 'Cache poisoning via unkeyed header!',
      poisonedUrl: `http://${xForwardedHost}/cache/bronze?lang=${lang || 'en'}`,
      flag: flagContent
    });
  }

  res.set('Cache-Control', 'public, max-age=3600');
  res.json({ lang: lang || 'en', message: 'Cached response' });
});

router.get('/cache/silver', (req, res) => {
  const { page } = req.query;

  if (!page) {
    return res.json({
      endpoint: '/cache/silver',
      hint: 'Fat GET: body affects cache but not cache key',
      method: 'GET with body'
    });
  }

  // VULN: Fat GET caching
  const body = req.body;

  if (body && Object.keys(body).length > 0) {
    const flagContent = getFlag('cache', 'cache_silver.txt');
    return res.json({
      success: true,
      message: 'Fat GET cache poisoning!',
      page: page,
      injectedBody: body,
      flag: flagContent
    });
  }

  res.set('Cache-Control', 'public, max-age=3600');
  res.json({ page: page, content: 'Page content' });
});

module.exports = router;
