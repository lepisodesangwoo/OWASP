/**
 * Route Aggregator
 * Mounts all route modules
 */

const express = require('express');
const router = express.Router();

// Import route modules
const infoRoutes = require('./info');
const adminRoutes = require('./admin');

// Mount routes
router.use('/', infoRoutes);
router.use('/', adminRoutes);

module.exports = router;
