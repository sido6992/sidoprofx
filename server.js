// server.js — backend entrypoint.
// Responsible only for the OAuth code→token proxy (and any future API
// routes). Actual trading happens over a direct wss:// connection from
// the browser straight to Deriv, same as before — this backend never
// sits in the middle of that socket.
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const routes = require('./routes');

const app = express();
const PORT = process.env.PORT || 10000;

// Only allow the configured frontend origin (falls back to '*' for local dev)
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());

app.use('/api', routes);

app.get('/', (req, res) => {
  res.send('Deriv Bot backend is running. See /api/health.');
});

app.listen(PORT, () => {
  console.log(`Deriv Bot backend listening on port ${PORT}`);
});
