/**
 * Route Aggregator
 * Mounts all route modules
 */

const express = require('express');
const router = express.Router();

// Import route modules
const infoRoutes = require('./info');
const adminRoutes = require('./admin');
const pageRoutes = require('./pages');

// Mount routes
router.use('/', infoRoutes);
router.use('/', adminRoutes);
router.use('/', pageRoutes);

module.exports = router;
