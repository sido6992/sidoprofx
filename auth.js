// auth.js — OAuth endpoints consumed by frontend/app.js
const express = require('express');
const { exchangeCodeForToken, refreshAccessToken } = require('./deriv');

const router = express.Router();

/**
 * POST /api/auth/token
 * body: { code, verifier, redirect_uri }
 * Exchanges a PKCE authorization code for an access token and
 * returns it to the browser as JSON.
 */
router.post('/token', async (req, res) => {
  const { code, verifier, redirect_uri } = req.body || {};

  if (!code || !verifier || !redirect_uri) {
    return res.status(400).json({ error: 'code, verifier and redirect_uri are all required' });
  }

  try {
    const tokenData = await exchangeCodeForToken({
      code,
      verifier,
      redirectUri: redirect_uri
    });
    res.json(tokenData);
  } catch (err) {
    console.error('Token exchange failed:', err.message);
    res.status(err.status || 502).json({ error: err.message });
  }
});

/**
 * POST /api/auth/refresh
 * body: { refresh_token }
 * Exchanges a refresh token for a new access token.
 */
router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body || {};

  if (!refresh_token) {
    return res.status(400).json({ error: 'refresh_token is required' });
  }

  try {
    const tokenData = await refreshAccessToken(refresh_token);
    res.json(tokenData);
  } catch (err) {
    console.error('Token refresh failed:', err.message);
    res.status(err.status || 502).json({ error: err.message });
  }
});

module.exports = router;
             
