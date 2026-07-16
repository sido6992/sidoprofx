/* ═══════════════════════════════════════════
   CONFIG — EDIT THIS BLOCK FOR YOUR DEPLOYMENT
   Only public, non-secret values belong here.
   The token exchange itself happens on the
   backend (see backend/auth.js) so no app
   secret is ever shipped to the browser.
═══════════════════════════════════════════ */
const CONFIG = {
  // Your Deriv App ID (registered on app.deriv.com)
  APP_ID: '33CMCtugHowMoinRyyCTS',

  // Deriv OAuth2 endpoints (confirmed from developers.deriv.com/docs/intro/oauth)
  AUTH_URL: 'https://auth.deriv.com/oauth2/auth',

  // ⚠️ MUST exactly match the redirect URI registered for this App ID
  // on app.deriv.com (including trailing slash / no trailing slash —
  // they must be byte-identical). This page acts as its own OAuth
  // callback receiver — Deriv redirects back here with ?code&state,
  // and app.js exchanges that code for a token via the backend.
  REDIRECT_URI: window.location.origin + window.location.pathname,

  // Requested permission scopes
  // ⚠️ Must exactly match the scopes approved for this App ID on the
  // Deriv dashboard (app.deriv.com / developers.deriv.com → your app).
  SCOPE: 'trade account_manage',

  // Deriv WebSocket endpoint for trading after auth
  WS_URL: 'wss://ws.derivws.com/websockets/v3',

  // Your backend API base URL (see backend/server.js).
  // The backend proxies the OAuth code→token exchange so the browser
  // never needs Deriv's app secret and never hits CORS issues.
  // Point this at your local dev server or your deployed Render URL.
  BACKEND_URL: 'http://localhost:4000'
};
