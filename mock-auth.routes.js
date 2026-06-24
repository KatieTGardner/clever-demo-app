// src/routes/mock-auth.routes.js
const express = require('express');
const router = express.Router();

router.get('/login', (req, res) => {
  // Fake logged-in user for MCP/local testing
  req.session.user = {
    email: 'mock-admin@example.com',
    role: 'district_admin',
    name: 'Mock Admin'
  };
  res.redirect('/dashboard');
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;
