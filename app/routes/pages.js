/**
 * Page Routes
 *
 * Static page routes for checkout, about, and contact pages.
 *
 * VULNERABILITIES (INTENTIONAL - DO NOT FIX):
 * - Credit card data logged in plaintext (POST /checkout)
 * - User input logged without sanitization
 */

const express = require('express');
const router = express.Router();

// ==========================================
// CHECKOUT PAGES
// ==========================================

// Checkout page
router.get('/checkout', (req, res) => {
  res.render('checkout', { title: 'Checkout - LUXORA' });
});

// Checkout handler - VULN: Credit card data logged
router.post('/checkout', (req, res) => {
  // VULN: Credit card data logged
  const { cardNumber, expiry, cvv, name } = req.body;
  console.log('Payment received:', { cardNumber, expiry, cvv, name });

  res.redirect('/checkout/success');
});

// Checkout success page
router.get('/checkout/success', (req, res) => {
  res.render('checkout-success', { title: 'Order Confirmed - LUXORA' });
});

// ==========================================
// STATIC PAGES
// ==========================================

// About Page
router.get('/about', (req, res) => {
  res.render('about', { title: 'About Us - LUXORA' });
});

// Contact Page (GET only - POST has DB dependency, stays in server.js)
router.get('/contact', (req, res) => {
  const sent = req.query.sent || null;
  res.render('contact', { title: 'Contact Us - LUXORA', sent });
});

module.exports = router;
