// deriv.js — thin wrapper around Deriv's OAuth2 endpoints.
// Keeping this isolated from auth.js/routes.js makes it easy to swap in
// mocked responses during testing, or add token refresh / revoke later.

const DERIV_TOKEN_URL = process.env.DERIV_TOKEN_URL || 'https://auth.deriv.com/oauth2/token';

/**
 * Exchange an OAuth2 authorization code (+ PKCE verifier) for an access token.
 * This runs server-side so:
 *   1. the browser never needs Deriv's app secret (if your app has one)
 *   2. we avoid CORS issues calling Deriv's token endpoint from the browser
 *
 * @param {Object} params
 * @param {string} params.code          - authorization code from the redirect
 * @param {string} params.verifier      - PKCE code_verifier generated client-side
 * @param {string} params.redirectUri   - must match the one used in the auth request
 * @returns {Promise<Object>}           - Deriv's token response (access_token, expires_in, ...)
 */
async function exchangeCodeForToken({ code, verifier, redirectUri }) {
  const body = new URLSearchParams({
    grant_type:    'authorization_code',
    code,
    code_verifier: verifier,
    redirect_uri:  redirectUri,
    client_id:     process.env.DERIV_APP_ID
  });

  // Only include the app secret if one is configured — PKCE public clients
  // often don't have (or need) one.
  if (process.env.DERIV_APP_SECRET) {
    body.append('client_secret', process.env.DERIV_APP_SECRET);
  }

  const res = await fetch(DERIV_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = data.error_description || data.error || `Deriv token endpoint returned ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }

  return data;
}

/**
 * Exchange a refresh token for a new access token.
 * @param {string} refreshToken
 */
async function refreshAccessToken(refreshToken) {
  const body = new URLSearchParams({
    grant_type:    'refresh_token',
    refresh_token: refreshToken,
    client_id:     process.env.DERIV_APP_ID
  });

  if (process.env.DERIV_APP_SECRET) {
    body.append('client_secret', process.env.DERIV_APP_SECRET);
  }

  const res = await fetch(DERIV_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = data.error_description || data.error || `Deriv token endpoint returned ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }

  return data;
}

module.exports = { exchangeCodeForToken, refreshAccessToken };
