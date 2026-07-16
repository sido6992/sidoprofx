// routes.js — central place to mount every API router.
// Keeping this separate from server.js means adding a new route group
// (e.g. trade history persistence, bot config storage) is a one-line change.
const express = require('express');
const authRouter = require('./auth');

const router = express.Router();

router.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

router.use('/auth', authRouter);

module.exports = router;
