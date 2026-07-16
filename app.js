/* ═══════════════════════════════════════════
   PKCE HELPERS (Proof Key for Code Exchange)
   Config values now live in config.js (loaded
   before this file — see index.html)
═══════════════════════════════════════════ */
function pkceRandomString(len = 64) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(v => charset[v % charset.length]).join('');
}

function base64URLEncode(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function pkceCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64URLEncode(digest);
}

/* ═══════════════════════════════════════════
   STATE
═══════════════════════════════════════════ */
const STATE = {
  connected: false,
  balance: 0,
  currency: 'USD',
  loginId: '',
  botRunning: false,
  wins: 0, losses: 0,
  dayProfit: 0,
  stakeVal: 1.00,
  durVal: 5,
  multiVal: 2.0,
  maxTVal: 100,
  mstakeVal: 1.00,
  mdurVal: 3,
  botTrades: 0,
  botProfit: 0,
  botWins: 0,
  chartType: 'candle',
  chartTF: '1T',
  trades: [],
  ws: null,
  appId: CONFIG.APP_ID,
  accessToken: '',
  tokenExpiry: 0,
  chartData: [],
  botInterval: null,
  signalInterval: null,
  tickerInterval: null,
  indInterval: null
};

/* ═══════════════════════════════════════════
   NAVIGATION
═══════════════════════════════════════════ */
function showPage(id, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('pg-'+id).classList.add('active');
  btn.classList.add('active');
  if(id === 'chart') initChart();
  if(id === 'markets') renderMarkets('all');
  if(id === 'dash') renderSignals();
}

/* ═══════════════════════════════════════════
   BOT TABS
═══════════════════════════════════════════ */
function switchBotTab(tab, el) {
  ['run','free','build','import'].forEach(t => {
    document.getElementById('botTab-'+t).classList.toggle('hidden', t !== tab);
  });
  el.closest('.tab-bar').querySelectorAll('.tab-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  if(tab === 'free') renderFreeBots();
}

function switchImportTab(tab, el) {
  ['xml','html','paste'].forEach(t => {
    document.getElementById('importTab-'+t).classList.toggle('hidden', t !== tab);
  });
  el.closest('.tab-bar').querySelectorAll('.tab-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
}

/* ═══════════════════════════════════════════
   STEPPERS
═══════════════════════════════════════════ */
function changeVal(key, delta) {
  if(key === 'stake') {
    STATE.stakeVal = Math.max(0.35, +(STATE.stakeVal + delta).toFixed(2));
    document.getElementById('stakeVal').textContent = STATE.stakeVal.toFixed(2);
  } else if(key === 'dur') {
    STATE.durVal = Math.max(1, STATE.durVal + delta);
    document.getElementById('durVal').textContent = STATE.durVal;
  } else if(key === 'multi') {
    STATE.multiVal = Math.max(1.1, +(STATE.multiVal + delta).toFixed(1));
    document.getElementById('multiVal').textContent = STATE.multiVal.toFixed(1)+'×';
  } else if(key === 'maxT') {
    STATE.maxTVal = Math.max(1, STATE.maxTVal + delta);
    document.getElementById('maxTVal').textContent = STATE.maxTVal;
  } else if(key === 'mstake') {
    STATE.mstakeVal = Math.max(0.35, +(STATE.mstakeVal + delta).toFixed(2));
    document.getElementById('mstakeVal').textContent = STATE.mstakeVal.toFixed(2);
  } else if(key === 'mdur') {
    STATE.mdurVal = Math.max(1, STATE.mdurVal + delta);
    document.getElementById('mdurVal').textContent = STATE.mdurVal;
  }
}

/* ═══════════════════════════════════════════
   CONNECT — OAuth2 + PKCE, token exchange via backend
   Flow:
   1. connectDeriv() redirects → auth.deriv.com with PKCE params
      (redirect_uri points back at this same page)
   2. Deriv redirects back here with ?code=...&state=...
   3. On load, app.js finds ?code, verifies state, and POSTs
      { code, verifier, redirect_uri } to the backend
   4. Backend (backend/auth.js + backend/deriv.js) exchanges the
      code for an access_token with Deriv's token endpoint and
      returns it as JSON — this keeps any app secret + CORS
      concerns off the browser
   5. app.js opens wss:// and sends authorize with that token
═══════════════════════════════════════════ */

function setConnectBtnLoading(loading) {
  const btn = document.getElementById('loginBtn');
  if (!btn) return;
  btn.disabled      = loading;
  btn.style.opacity = loading ? '.6' : '1';
  btn.textContent   = loading ? '🔄 Connecting…' : '🔐 Log In with Deriv';
}

function clearSession() {
  ['db_access_token','db_token_expiry','db_pkce_verifier',
   'db_pkce_state','db_oauth_error','db_account_id',
   'db_refresh_token'
  ].forEach(k => sessionStorage.removeItem(k));
  STATE.accessToken = '';
  STATE.tokenExpiry = 0;
}

/* ── Step 1: Kick off PKCE login ── */
async function connectDeriv() {
  setConnectBtnLoading(true);
  try {
    const verifier  = pkceRandomString(64);
    const challenge = await pkceCodeChallenge(verifier);
    const state     = pkceRandomString(24);
    sessionStorage.setItem('db_pkce_verifier', verifier);
    sessionStorage.setItem('db_pkce_state',    state);
    const params = new URLSearchParams({
      response_type:         'code',
      client_id:             CONFIG.APP_ID,
      redirect_uri:          CONFIG.REDIRECT_URI,
      scope:                 CONFIG.SCOPE,
      state:                 state,
      code_challenge:        challenge,
      code_challenge_method: 'S256'
    });
    window.location.href = CONFIG.AUTH_URL + '?' + params.toString();
  } catch (err) {
    setConnectBtnLoading(false);
    showToast('❌ Could not start login: ' + err.message);
  }
}

/* ── Step 2-4 now happen in callback.html, which:
      - receives ?code&state from Deriv
      - verifies state against the verifier stashed in sessionStorage
      - POSTs { code, verifier, redirect_uri } to the backend
      - stores the returned access_token/expiry/refresh_token in
        sessionStorage
      - redirects back here to index.html
   All this function needs to do is surface an error if callback.html
   left one behind, and otherwise fall through to tryRestoreSession()
   which will find the token callback.html just stored. ── */
function consumeOAuthError() {
  const err = sessionStorage.getItem('db_oauth_error');
  if (!err) return false;
  sessionStorage.removeItem('db_oauth_error');
  setConnectBtnLoading(false);
  showToast('❌ ' + err);
  return true;
}

/* ── Session restore on page refresh (token still cached client-side) ── */
async function tryRestoreSession() {
  const token  = sessionStorage.getItem('db_access_token');
  const expiry = +(sessionStorage.getItem('db_token_expiry') || 0);
  if (!token || Date.now() >= expiry) return false;
  STATE.accessToken = token;
  STATE.tokenExpiry = expiry;
  openTradingSocket(CONFIG.WS_URL + '?app_id=' + CONFIG.APP_ID, token, 'restored');
  return true;
}

/* ══════════════════════════════════════════
   SHARED WEBSOCKET — all paths converge here
══════════════════════════════════════════ */
function openTradingSocket(wsTarget, token, mode) {
  if (STATE.ws) { try { STATE.ws.close(); } catch(e){} STATE.ws = null; }
  setConnectBtnLoading(true);
  showToast('🔄 Opening trading session…');
  let settled = false;
  try {
    const ws = new WebSocket(wsTarget);
    STATE.ws = ws;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      setConnectBtnLoading(false);
      showToast('❌ Connection timed out. Please log in again.');
      try { ws.close(); } catch(e){}
    }, 14000);
    ws.onopen = () => {
      ws.send(JSON.stringify({ authorize: token }));
    };
    ws.onmessage = (evt) => {
      let data;
      try { data = JSON.parse(evt.data); } catch(e) { return; }
      if (data.msg_type === 'authorize' && data.authorize) {
        settled = true;
        clearTimeout(timer);
        const acc = data.authorize;
        if (acc.is_virtual) {
          setConnectBtnLoading(false);
          showToast('🚫 Demo account blocked. Please use a Real Money account.');
          clearSession();
          try { ws.close(); } catch(e){}
          return;
        }
        STATE.connected = true;
        STATE.balance   = acc.balance;
        STATE.currency  = acc.currency;
        STATE.loginId   = acc.loginid;
        setConnectBtnLoading(false);
        onConnected(acc);
        ws.send(JSON.stringify({ balance: 1, subscribe: 1 }));
      } else if (data.msg_type === 'balance' && data.balance) {
        STATE.balance = data.balance.balance;
        updateBalanceUI();
      } else if (data.error) {
        settled = true;
        clearTimeout(timer);
        setConnectBtnLoading(false);
        showToast('❌ ' + (data.error.message || 'Authorization failed.') + ' Please log in again.');
        clearSession();
        try { ws.close(); } catch(e){}
      }
    };
    ws.onerror = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      setConnectBtnLoading(false);
      showToast('❌ WebSocket error. Check your network and log in again.');
    };
    ws.onclose = () => {
      if (STATE.connected) {
        STATE.connected = false;
        updateConnStatus();
        showToast('🔌 Disconnected from Deriv');
      } else if (!settled) {
        settled = true;
        clearTimeout(timer);
        setConnectBtnLoading(false);
        showToast('❌ Connection closed before authorizing. Please log in again.');
        clearSession();
      }
      setConnectBtnLoading(false);
    };
  } catch (err) {
    setConnectBtnLoading(false);
    showToast('❌ WebSocket error: ' + err.message);
  }
}

function onConnected(acc) {
  updateConnStatus();
  updateBalanceUI();
  document.getElementById('connectedInfo').style.display = 'block';
  document.getElementById('connInfoBody').innerHTML = `
    <strong style="color:var(--text-1)">Account:</strong> ${acc.loginid}<br>
    <strong style="color:var(--text-1)">Type:</strong>
      <span style="color:var(--accent-3)">✅ Real Money Account</span><br>
    <strong style="color:var(--text-1)">Auth:</strong>
      <span style="color:var(--accent-1)">🔐 OAuth2 + PKCE</span><br>
    <strong style="color:var(--text-1)">Balance:</strong>
      ${acc.currency} ${(+acc.balance).toFixed(2)}<br>
    <strong style="color:var(--text-1)">Name:</strong> ${acc.fullname || 'User'}`;
  document.getElementById('connectNotif').style.display = 'none';
  showToast('✅ Connected! ' + acc.currency + ' ' + (+acc.balance).toFixed(2));
  startTickerUpdates();
  renderSignals();
  startIndicatorUpdates();
}

function disconnectDeriv() {
  if (STATE.ws) { try { STATE.ws.close(); } catch(e){} STATE.ws = null; }
  STATE.connected = false;
  STATE.balance   = 0;
  clearSession();
  clearInterval(STATE.botInterval);
  clearInterval(STATE.tickerInterval);
  clearInterval(STATE.indInterval);
  if (STATE.botRunning) {
    STATE.botRunning = false;
    const btn  = document.getElementById('startStopBtn');
    const txt  = document.getElementById('startStopTxt');
    const ring = document.getElementById('pulseRing');
    if (btn)  btn.classList.remove('running');
    if (txt)  txt.textContent = '▶  START BOT';
    if (ring) ring.style.display = 'none';
  }
  updateConnStatus();
  updateBalanceUI();
  document.getElementById('connectedInfo').style.display = 'none';
  document.getElementById('connectNotif').style.display = '';
  showToast('🔌 Disconnected');
}

function updateConnStatus() {
  document.getElementById('connDot').classList.toggle('live', STATE.connected);
  document.getElementById('connLabel').textContent = STATE.connected ? 'Live' : 'Offline';
}

function updateBalanceUI() {
  const fmt = v => (+v || 0).toLocaleString('en-US',
    { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  document.getElementById('balAmount').textContent   = '$' + fmt(STATE.balance);
  document.getElementById('balCurrency').textContent = STATE.currency || 'USD';
  document.getElementById('accountId').textContent   = STATE.loginId  || 'Not connected';
  document.getElementById('topBal').textContent      = '$' + fmt(STATE.balance);
  const dp   = STATE.dayProfit || 0;
  const chip = document.getElementById('dayPL');
  chip.textContent = (dp >= 0 ? '+' : '') + '$' + fmt(Math.abs(dp));
  chip.className   = 'pl-chip ' + (dp >= 0 ? 'win' : 'loss');
  const total = STATE.wins + STATE.losses;
  const wr    = total > 0 ? Math.round(STATE.wins / total * 100) : 0;
  document.getElementById('winCount').textContent  = STATE.wins  || 0;
  document.getElementById('lossCount').textContent = STATE.losses || 0;
  document.getElementById('winRate').textContent   = wr + '%';
}


/* ═══════════════════════════════════════════
   BOT
═══════════════════════════════════════════ */
function toggleBot() {
  if(!STATE.connected) { showToast('⚠️ Connect account first!'); showPage('connect', document.querySelectorAll('.nav-btn')[4]); return; }
  STATE.botRunning = !STATE.botRunning;
  const btn = document.getElementById('startStopBtn');
  const txt = document.getElementById('startStopTxt');
  const ring = document.getElementById('pulseRing');
  if(STATE.botRunning) {
    btn.classList.add('running');
    txt.textContent = '⏹  STOP BOT';
    ring.style.display = '';
    showToast('🤖 Bot started!');
    STATE.botTrades = 0; STATE.botProfit = 0; STATE.botWins = 0;
    STATE.botInterval = setInterval(simulateBotTrade, 3500+Math.random()*4000);
    simulateBotTrade();
  } else {
    btn.classList.remove('running');
    txt.textContent = '▶  START BOT';
    ring.style.display = 'none';
    clearInterval(STATE.botInterval);
    showToast('⏹ Bot stopped. P/L: $'+STATE.botProfit.toFixed(2));
  }
}

function simulateBotTrade() {
  if(!STATE.botRunning) return;
  const stake = STATE.stakeVal;
  const win = Math.random() > 0.43;
  const payout = win ? stake * 0.87 : -stake;
  if(win) { STATE.wins++; STATE.botWins++; }
  else { STATE.losses++; }
  STATE.botTrades++;
  STATE.dayProfit += payout;
  STATE.botProfit += payout;
  STATE.balance = Math.max(0, STATE.balance + payout);
  updateBalanceUI();
  updateBotStats();

  const mkt = document.getElementById('botMarket').value.split(' ').slice(0,2).join(' ');
  const dir = Math.random() > 0.5 ? '📈 RISE' : '📉 FALL';
  addTradeToHistory({
    time: new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),
    market: mkt, dir, stake, payout, win
  });
}

function updateBotStats() {
  document.getElementById('liveTradeCount').textContent = STATE.botTrades;
  const p = STATE.botProfit;
  const el = document.getElementById('liveProfit');
  el.textContent = (p >= 0 ? '+' : '')+'$'+Math.abs(p).toFixed(2);
  el.className = 'bst-val '+(p >= 0 ? 'positive' : 'negative');
  const wr = STATE.botTrades > 0 ? Math.round(STATE.botWins/STATE.botTrades*100) : 0;
  document.getElementById('liveWin').textContent = wr+'%';
}

function addTradeToHistory(t) {
  STATE.trades.unshift(t);
  if(STATE.trades.length > 30) STATE.trades.pop();
  const h = document.getElementById('tradeHistory');
  h.innerHTML = STATE.trades.slice(0,10).map(t =>
    `<div class="history-row">
      <div class="hr-time">${t.time}</div>
      <div class="hr-market">${t.market}</div>
      <div class="hr-dir" style="color:${t.win ? 'var(--accent-3)' : 'var(--accent-5)'}">${t.dir}</div>
      <div class="hr-stake">$${t.stake.toFixed(2)}</div>
      <div><span class="pl-chip ${t.win ? 'win' : 'loss'}">${t.win ? '+' : ''}$${t.payout.toFixed(2)}</span></div>
    </div>`
  ).join('');
}

/* ═══════════════════════════════════════════
   MANUAL TRADE
═══════════════════════════════════════════ */
function placeManualTrade(dir) {
  if(!STATE.connected) { showToast('⚠️ Connect account first!'); return; }
  const stake = STATE.mstakeVal;
  const win = Math.random() > 0.43;
  const payout = win ? stake * 0.87 : -stake;
  if(win) STATE.wins++; else STATE.losses++;
  STATE.dayProfit += payout;
  STATE.balance = Math.max(0, STATE.balance + payout);
  updateBalanceUI();
  const icons = {RISE:'📈',FALL:'📉',EVEN:'♾️',ODD:'🔢'};
  showToast((win ? '✅ WIN' : '❌ LOSS') + ' ' + icons[dir] + ' ' + dir + ' → $'+Math.abs(payout).toFixed(2));
  addTradeToHistory({
    time: new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}),
    market: 'Manual', dir: icons[dir]+' '+dir, stake, payout, win
  });
}

/* ═══════════════════════════════════════════
   AI SIGNALS
═══════════════════════════════════════════ */
const sigMarkets = [
  {id:'v75',name:'Volatility 75 Index',cat:'vol'},
  {id:'v10',name:'Volatility 10 Index',cat:'vol'},
  {id:'v100',name:'Volatility 100 (1s)',cat:'vol'},
  {id:'b1k',name:'Boom 1000',cat:'bc'},
  {id:'c5',name:'Crash 500',cat:'bc'},
  {id:'dig',name:'Digits Even/Odd',cat:'dig'},
  {id:'eurusd',name:'EUR/USD',cat:'fx'},
  {id:'us500',name:'US 500',cat:'idx'},
];

// Live signal state per market — populated by generateSignalSet()
let sigState = {};

const REASON_BANK_BULL = [
  'Strong upward momentum with rising volume',
  'Bullish trend confirmed across multiple timeframes',
  'Price broke above key resistance level',
  'RSI showing bullish divergence with strength',
  'EMA crossover signaling upward continuation',
  'Consistent higher highs forming on recent ticks'
];
const REASON_BANK_BEAR = [
  'Strong downward pressure building',
  'Bearish trend confirmed across multiple timeframes',
  'Price rejected at resistance, reversing down',
  'RSI showing bearish divergence',
  'EMA crossover signaling downward continuation',
  'Consistent lower lows forming on recent ticks'
];
const REASON_BANK_NEUTRAL = [
  'Choppy price action — waiting for clearer setup',
  'Conflicting signals across timeframes',
  'Low volatility, range-bound conditions'
];

function generateSignalSet() {
  const next = {};
  sigMarkets.forEach(m => {
    const roll = Math.random();
    const type = roll > 0.52 ? 'bull' : (roll > 0.12 ? 'bear' : 'neutral');
    const conf = type === 'neutral'
      ? Math.floor(Math.random()*20+45)
      : Math.floor(Math.random()*30+65);
    const reasons = type === 'bull' ? REASON_BANK_BULL : type === 'bear' ? REASON_BANK_BEAR : REASON_BANK_NEUTRAL;
    next[m.id] = {
      type,
      conf,
      dir: type === 'bull' ? 'RISE ▲' : type === 'bear' ? 'FALL ▼' : 'HOLD —',
      reason: reasons[Math.floor(Math.random()*reasons.length)]
    };
  });
  return next;
}

function getBestMarket() {
  let best = null;
  sigMarkets.forEach(m => {
    const s = sigState[m.id];
    if (!s || s.type === 'neutral') return;
    if (!best || s.conf > sigState[best.id].conf) best = m;
  });
  return best;
}

function renderSignals() {
  sigState = generateSignalSet();
  paintSignals();
  document.getElementById('sigUpdate').textContent = 'Updated '+new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  // Auto-refresh signals every 7s
  if(!STATE.signalInterval) {
    STATE.signalInterval = setInterval(() => {
      if(document.getElementById('pg-dash').classList.contains('active')) updateSignals();
    }, 7000);
  }
}

function updateSignals() {
  sigState = generateSignalSet();
  paintSignals();
  document.getElementById('sigUpdate').textContent = 'Updated '+new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function paintSignals() {
  const grid = document.getElementById('signalGrid');
  const bestMkt = getBestMarket();

  grid.innerHTML = sigMarkets.map(m => {
    const s = sigState[m.id];
    const isTop = bestMkt && bestMkt.id === m.id;
    return `<div class="signal-item ${s.type}${isTop ? ' top-pick' : ''}">
      ${isTop ? '<div class="top-pick-tag">⭐ TOP PICK</div>' : ''}
      <div class="sig-market">${m.name}</div>
      <div class="sig-dir ${s.type}">${s.dir}</div>
      <div class="sig-conf">${s.conf}% conf</div>
      <span class="sig-badge ${s.type}">${s.type==='bull'?'BUY':s.type==='bear'?'SELL':'WAIT'}</span>
      <div class="sig-bar ${s.type==='bear'?'bear':''}" style="width:${s.conf}%"></div>
    </div>`;
  }).join('');

  paintBestMarketCard(bestMkt);
}

function paintBestMarketCard(bestMkt) {
  const nameEl = document.getElementById('bmName');
  const reasonEl = document.getElementById('bmReason');
  const confEl = document.getElementById('bmConf');
  const actionEl = document.getElementById('bmAction');
  if (!bestMkt) {
    nameEl.textContent = 'No strong setup right now';
    reasonEl.textContent = 'All markets are showing mixed or weak signals — sit tight';
    confEl.textContent = '—';
    actionEl.textContent = '⏳ Wait for a clearer setup';
    actionEl.style.color = 'var(--accent-4)';
    return;
  }
  const s = sigState[bestMkt.id];
  nameEl.textContent = bestMkt.name;
  reasonEl.textContent = s.reason;
  confEl.textContent = s.conf + '%';
  const bull = s.type === 'bull';
  actionEl.textContent = (bull ? '📈 Suggested: BUY / RISE' : '📉 Suggested: SELL / FALL') + ' · ' + s.dir;
  actionEl.style.color = bull ? 'var(--accent-3)' : 'var(--accent-5)';
}

function manualRefreshSignals() {
  const btn = document.getElementById('refreshSigBtn');
  const icon = document.getElementById('refreshIcon');
  if (btn) btn.disabled = true;
  if (icon) icon.classList.add('spinning');
  showToast('🔄 Scanning all markets…');
  setTimeout(() => {
    updateSignals();
    if (icon) icon.classList.remove('spinning');
    if (btn) btn.disabled = false;
    const best = getBestMarket();
    showToast(best ? '🏆 Best market: '+best.name+' ('+sigState[best.id].conf+'% conf)' : '⏳ No strong setup found right now');
  }, 550);
}

/* ═══════════════════════════════════════════
   TICKER
═══════════════════════════════════════════ */
const tickerBases = {v75:1045.23,v10:254.87,b1k:8823.45,c5:1234.56,eurusd:1.08432};

function startTickerUpdates() {
  updateTicker();
  STATE.tickerInterval = setInterval(updateTicker, 1200);
}

function updateTicker() {
  const fmt = (v,d=2) => v.toFixed(d);
  const jit = (v,p) => v * (1 + (Math.random()-.5)*p);
  const ids = ['v75','v10','b1k','c5','eurusd'];
  const keys = ['t-v75','t-v10','t-b1k','t-c5','t-eurusd'];
  ids.forEach((id,i) => {
    tickerBases[id] = jit(tickerBases[id], id==='eurusd'?.0003:.0005);
    const el = document.getElementById(keys[i]);
    if(el) el.textContent = id==='eurusd' ? fmt(tickerBases[id],5) : fmt(tickerBases[id]);
  });
}

/* ═══════════════════════════════════════════
   INDICATORS
═══════════════════════════════════════════ */
function startIndicatorUpdates() {
  updateIndicators();
  STATE.indInterval = setInterval(updateIndicators, 3000);
}

function updateIndicators() {
  const rsi = +(40+Math.random()*30).toFixed(1);
  const macd = +((Math.random()-.5)*0.5).toFixed(4);
  const ema = +(tickerBases.v75 * (1+(Math.random()-.5)*.001)).toFixed(2);
  const bb = Math.random() > .6 ? 'Upper' : Math.random() > .5 ? 'Lower' : 'Mid';
  const stoch = +(20+Math.random()*60).toFixed(1);
  const atr = +(2+Math.random()*5).toFixed(2);

  setInd('rsi', rsi, rsi < 30 ? 'Oversold 🔥' : rsi > 70 ? 'Overbought ❄' : 'Neutral', rsi, 100, 'var(--accent-4)');
  setInd('macd', macd, macd > 0 ? 'Bullish ▲' : 'Bearish ▼', Math.abs(macd)*200, 100, macd>0?'var(--accent-3)':'var(--accent-5)');
  setInd('ema', ema, 'Price EMA', 60, 100, 'var(--accent-1)');
  setInd('bb', bb, bb==='Lower' ? 'Buy Zone' : (bb==='Upper' ? 'Sell Zone' : 'Wait'), 50, 100, 'var(--accent-6)');
  setInd('stoch', stoch, stoch<20?'Oversold':stoch>80?'Overbought':'Neutral', stoch, 100, 'var(--accent-2)');
  setInd('atr', atr, 'Volatility', atr*10, 100, '#F97316');
}

function setInd(id, val, sig, barPct, max, color) {
  const el = document.getElementById('ind-'+id);
  const sig_el = document.getElementById('ind-'+id+'-sig');
  const bar = document.getElementById('ind-'+id+'-bar');
  if(el) el.textContent = val;
  if(sig_el) { sig_el.textContent = sig; sig_el.style.color = color; }
  if(bar) { bar.style.width = Math.min(100,Math.max(2,barPct))+'%'; bar.style.background = color; }
}

/* ═══════════════════════════════════════════
   CHART
═══════════════════════════════════════════ */
let chartAnimFrame;
function initChart() {
  generateChartData();
  drawChart();
}

function generateChartData() {
  let price = 1045;
  STATE.chartData = [];
  for(let i=0;i<60;i++){
    const o = price;
    const h = o + Math.random()*4;
    const l = o - Math.random()*4;
    const c = l + Math.random()*(h-l);
    STATE.chartData.push({o,h,l,c});
    price = c;
  }
}

function drawChart() {
  const canvas = document.getElementById('chartCanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 220 * dpr;
  ctx.scale(dpr, dpr);
  const W = rect.width, H = 220;
  const pad = {t:16, b:24, l:8, r:50};
  const data = STATE.chartData;
  const n = data.length;
  const minP = Math.min(...data.map(d=>d.l));
  const maxP = Math.max(...data.map(d=>d.h));
  const rng = maxP - minP || 1;
  const toY = v => pad.t + (1-(v-minP)/rng)*(H-pad.t-pad.b);
  const colW = (W-pad.l-pad.r)/n;

  // Background
  ctx.fillStyle = '#0D1525';
  if (ctx.roundRect) {
    ctx.beginPath();
    ctx.roundRect(0,0,W,H,12);
    ctx.fill();
  } else {
    ctx.fillRect(0,0,W,H);
  }

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,.05)';
  ctx.lineWidth = 1;
  for(let i=0;i<=4;i++){
    const y = pad.t + (H-pad.t-pad.b)/4*i;
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(W-pad.r,y); ctx.stroke();
    const val = maxP - rng/4*i;
    ctx.fillStyle = '#475569'; ctx.font = '10px JetBrains Mono'; ctx.textAlign='right';
    ctx.fillText(val.toFixed(2), W-4, y+4);
  }

  if(STATE.chartType === 'line' || STATE.chartType === 'tick') {
    // Line/area chart
    ctx.beginPath();
    data.forEach((d,i) => {
      const x = pad.l + (i+.5)*colW;
      const y = toY(d.c);
      i===0 ? ctx.moveTo(x,y) : ctx.lineTo(x,y);
    });
    ctx.strokeStyle = '#00E5FF';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    // Area fill
    const last = data[data.length-1];
    ctx.lineTo(pad.l+(n-.5)*colW, H-pad.b);
    ctx.lineTo(pad.l+.5*colW, H-pad.b);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0,pad.t,0,H-pad.b);
    grad.addColorStop(0,'rgba(0,229,255,.25)');
    grad.addColorStop(1,'rgba(0,229,255,.0)');
    ctx.fillStyle = grad;
    ctx.fill();
    // Dots
    if(STATE.chartType === 'tick') {
      data.forEach((d,i) => {
        const x = pad.l+(i+.5)*colW;
        const y = toY(d.c);
        ctx.beginPath(); ctx.arc(x,y,2,0,Math.PI*2);
        ctx.fillStyle='#00E5FF'; ctx.fill();
      });
    }
  } else {
    // Candles
    data.forEach((d,i) => {
      const x = pad.l + i*colW;
      const cw = Math.max(2, colW*.65);
      const cx = x + (colW-cw)/2;
      const bull = d.c >= d.o;
      ctx.fillStyle = bull ? '#10B981' : '#EF4444';
      ctx.strokeStyle = bull ? '#10B981' : '#EF4444';
      ctx.lineWidth = 1;
      // Wick
      ctx.beginPath();
      ctx.moveTo(cx+cw/2, toY(d.h));
      ctx.lineTo(cx+cw/2, toY(d.l));
      ctx.stroke();
      // Body
      const bodyTop = toY(Math.max(d.o,d.c));
      const bodyH = Math.max(1,Math.abs(toY(d.o)-toY(d.c)));
      ctx.fillRect(cx, bodyTop, cw, bodyH);
    });
  }

  // Last price line
  const lastC = data[data.length-1].c;
  const lastY = toY(lastC);
  ctx.setLineDash([4,4]);
  ctx.strokeStyle = 'rgba(0,229,255,.4)';
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(pad.l,lastY); ctx.lineTo(W-pad.r,lastY); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = '#00E5FF';
  ctx.font = 'bold 10px JetBrains Mono';
  ctx.textAlign = 'right';
  ctx.fillText(lastC.toFixed(2), W-4, lastY-3);
}

function setChartType(type, btn) {
  STATE.chartType = type;
  document.querySelectorAll('.chart-toolbar .chart-btn').forEach((b,i)=>{ if(i<3) b.classList.remove('active'); });
  btn.classList.add('active');
  initChart();
}

function setChartTF(tf, btn) {
  STATE.chartTF = tf;
  document.querySelectorAll('.chart-toolbar:nth-child(2) .chart-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  generateChartData();
  drawChart();
}

// Live chart tick
setInterval(() => {
  if(STATE.connected && document.getElementById('pg-chart').classList.contains('active')) {
    const last = STATE.chartData[STATE.chartData.length-1];
    const c = last.c * (1+(Math.random()-.5)*.001);
    STATE.chartData.push({o:last.c, h:Math.max(last.c,c)+Math.random()*.5, l:Math.min(last.c,c)-Math.random()*.5, c});
    if(STATE.chartData.length > 80) STATE.chartData.shift();
    drawChart();
  }
}, 1500);

/* ═══════════════════════════════════════════
   MARKETS
═══════════════════════════════════════════ */
const ALL_MARKETS = [
  {id:'v10',name:'Volatility 10',sub:'Synthetic',cat:'vol',icon:'📊',color:'#00E5FF'},
  {id:'v25',name:'Volatility 25',sub:'Synthetic',cat:'vol',icon:'📊',color:'#7C3AED'},
  {id:'v50',name:'Volatility 50',sub:'Synthetic',cat:'vol',icon:'📊',color:'#F59E0B'},
  {id:'v75',name:'Volatility 75',sub:'Synthetic',cat:'vol',icon:'📊',color:'#10B981'},
  {id:'v100',name:'Volatility 100',sub:'Synthetic',cat:'vol',icon:'📊',color:'#EF4444'},
  {id:'v101s',name:'Volatility 10 (1s)',sub:'1s Candle',cat:'vol',icon:'⚡',color:'#00E5FF'},
  {id:'v251s',name:'Volatility 25 (1s)',sub:'1s Candle',cat:'vol',icon:'⚡',color:'#7C3AED'},
  {id:'v501s',name:'Volatility 50 (1s)',sub:'1s Candle',cat:'vol',icon:'⚡',color:'#F59E0B'},
  {id:'v751s',name:'Volatility 75 (1s)',sub:'1s Candle',cat:'vol',icon:'⚡',color:'#10B981'},
  {id:'v1001s',name:'Volatility 100 (1s)',sub:'1s Candle',cat:'vol',icon:'⚡',color:'#EF4444'},
  {id:'b300',name:'Boom 300',sub:'Boom/Crash',cat:'bc',icon:'🚀',color:'#10B981'},
  {id:'b500',name:'Boom 500',sub:'Boom/Crash',cat:'bc',icon:'🚀',color:'#34D399'},
  {id:'b1k',name:'Boom 1000',sub:'Boom/Crash',cat:'bc',icon:'🚀',color:'#6EE7B7'},
  {id:'c300',name:'Crash 300',sub:'Boom/Crash',cat:'bc',icon:'💥',color:'#EF4444'},
  {id:'c500',name:'Crash 500',sub:'Boom/Crash',cat:'bc',icon:'💥',color:'#F87171'},
  {id:'c1k',name:'Crash 1000',sub:'Boom/Crash',cat:'bc',icon:'💥',color:'#FCA5A5'},
  {id:'deo',name:'Digits Even/Odd',sub:'Digits',cat:'dig',icon:'🔢',color:'#EC4899'},
  {id:'dou',name:'Digits Over/Under',sub:'Digits',cat:'dig',icon:'🔢',color:'#F472B6'},
  {id:'dm',name:'Digits Matches',sub:'Digits',cat:'dig',icon:'🎯',color:'#A78BFA'},
  {id:'dd',name:'Digits Differs',sub:'Digits',cat:'dig',icon:'🎯',color:'#C4B5FD'},
  {id:'av10',name:'Accumulators V10',sub:'Accumulators',cat:'acc',icon:'📈',color:'#F97316'},
  {id:'av25',name:'Accumulators V25',sub:'Accumulators',cat:'acc',icon:'📈',color:'#FB923C'},
  {id:'av75',name:'Accumulators V75',sub:'Accumulators',cat:'acc',icon:'📈',color:'#FDBA74'},
  {id:'eurusd',name:'EUR/USD',sub:'Forex',cat:'fx',icon:'💱',color:'#3B82F6'},
  {id:'gbpusd',name:'GBP/USD',sub:'Forex',cat:'fx',icon:'💱',color:'#60A5FA'},
  {id:'usdjpy',name:'USD/JPY',sub:'Forex',cat:'fx',icon:'💱',color:'#93C5FD'},
  {id:'audusd',name:'AUD/USD',sub:'Forex',cat:'fx',icon:'💱',color:'#BFDBFE'},
  {id:'us30',name:'US 30 (Wall St)',sub:'Index',cat:'idx',icon:'🏦',color:'#FBBF24'},
  {id:'us500',name:'US 500 (S&P)',sub:'Index',cat:'idx',icon:'🏦',color:'#FCD34D'},
  {id:'jp225',name:'JP 225 (Nikkei)',sub:'Index',cat:'idx',icon:'🏦',color:'#FDE68A'},
  {id:'uk100',name:'UK 100 (FTSE)',sub:'Index',cat:'idx',icon:'🏦',color:'#FEF3C7'},
];

let mktPrices = {};
ALL_MARKETS.forEach(m => {
  mktPrices[m.id] = {
    p: 100+Math.random()*2000,
    chg: (Math.random()-.5)*2
  };
});
setInterval(() => {
  ALL_MARKETS.forEach(m => {
    mktPrices[m.id].p *= (1+(Math.random()-.5)*.0008);
    mktPrices[m.id].chg = (Math.random()-.5)*3;
  });
  if(document.getElementById('pg-markets').classList.contains('active')) {
    const active = document.querySelector('.mktab.active');
    const cat = active ? active.getAttribute('data-cat') || 'all' : 'all';
  }
}, 2000);

function filterMarket(cat, el) {
  document.querySelectorAll('.mktab').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  el.setAttribute('data-cat', cat);
  renderMarkets(cat);
}

function renderMarkets(cat) {
  const list = cat === 'all' ? ALL_MARKETS : ALL_MARKETS.filter(m => m.cat === cat);
  const container = document.getElementById('marketList');
  container.innerHTML = list.map(m => {
    const p = mktPrices[m.id];
    const bull = p.chg >= 0;
    return `<div class="market-item" onclick="selectMarket('${m.id}')">
      <div class="mkt-icon" style="color:${m.color}">${m.icon}</div>
      <div class="mkt-info">
        <div class="mkt-name">${m.name}</div>
        <div class="mkt-sub">${m.sub}</div>
      </div>
      <div class="mkt-price">
        <div class="mkt-val">${p.p.toFixed(2)}</div>
        <div class="mkt-chg" style="color:${bull?'var(--accent-3)':'var(--accent-5)'}">${bull?'+':''}${p.chg.toFixed(2)}%</div>
      </div>
    </div>`;
  }).join('');
}

function selectMarket(id) {
  const m = ALL_MARKETS.find(x => x.id === id);
  if(m) showToast('📊 '+m.name+' selected');
}

/* ═══════════════════════════════════════════
   FREE BOTS
═══════════════════════════════════════════ */
const FREE_BOTS = [
  {name:'Digit Even/Odd Master',icon:'🎯',desc:'Trades even/odd digits with smart martingale recovery',wr:'71%',profit:'+$124',trades:'2.1K',tags:['Digits','Martingale','Safe'],color:'#EC4899'},
  {name:'V75 Trend Rider',icon:'🏄',desc:'Follows EMA crossover signals on Volatility 75',wr:'67%',profit:'+$89',trades:'1.4K',tags:['V75','EMA','Trend'],color:'#10B981'},
  {name:'Boom 1000 Spiker',icon:'🚀',desc:'Buys Rise on Boom 1000 after 3 consecutive falls',wr:'63%',profit:'+$67',trades:'890',tags:['Boom','Counter','Mid-risk'],color:'#F59E0B'},
  {name:'Crash Scalper Pro',icon:'💥',desc:'Short-duration fall trades on Crash indices',wr:'69%',profit:'+$103',trades:'1.8K',tags:['Crash','Scalp','Active'],color:'#EF4444'},
  {name:'Safe Accumulator',icon:'🛡️',desc:'Low-risk accumulator strategy with 1% growth rate',wr:'82%',profit:'+$45',trades:'670',tags:['Accumulator','Safe','Low-risk'],color:'#7C3AED'},
  {name:'Forex Swing Bot',icon:'💱',desc:'EUR/USD swing trades based on RSI+MACD confluence',wr:'58%',profit:'+$31',trades:'420',tags:['Forex','RSI','MACD'],color:'#3B82F6'},
];

function renderFreeBots() {
  document.getElementById('freeBotList').innerHTML = FREE_BOTS.map((b,i) =>
    `<div class="bot-card">
      <div class="bot-header">
        <div class="bot-ico" style="color:${b.color}">${b.icon}</div>
        <div class="bot-meta">
          <div class="bot-name">${b.name}</div>
          <div class="bot-desc">${b.desc}</div>
        </div>
      </div>
      <div class="bot-stats">
        <div class="bot-stat-item"><div class="bst-label">Win Rate</div><div class="bst-val positive">${b.wr}</div></div>
        <div class="bot-stat-item"><div class="bst-label">Profit (30d)</div><div class="bst-val positive">${b.profit}</div></div>
        <div class="bot-stat-item"><div class="bst-label">Trades</div><div class="bst-val">${b.trades}</div></div>
      </div>
      <div class="tag-list">${b.tags.map(t=>`<span class="tag">${t}</span>`).join('')}</div>
      <div class="row">
        <button class="btn btn-ghost col btn-sm" onclick="showToast('👁 Previewing ${b.name}')">Preview</button>
        <button class="btn btn-primary col btn-sm" onclick="loadFreeBot(${i})">▶ Use Bot</button>
      </div>
    </div>`
  ).join('');
}

function loadFreeBot(i) {
  const b = FREE_BOTS[i];
  switchBotTab('run', document.querySelector('#botTabBar .tab-item'));
  showToast('✅ '+b.name+' loaded!');
}

/* ═══════════════════════════════════════════
   FILE IMPORT
═══════════════════════════════════════════ */
function handleFileImport(input, type) {
  const file = input.files[0];
  if(file) showToast('📥 '+file.name+' imported!');
}

/* ═══════════════════════════════════════════
   TOAST
═══════════════════════════════════════════ */
let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2800);
}

/* ═══════════════════════════════════════════
   INIT
═══════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  renderSignals();
  renderMarkets('all');
  window.addEventListener('resize', () => {
    if (document.getElementById('pg-chart').classList.contains('active')) drawChart();
  });
  document.getElementById('connectNotif').style.display = '';
  setInterval(() => {
    if (document.getElementById('pg-dash').classList.contains('active')) updateSignals();
  }, 8000);

  // On load, try to restore a connection in priority order:
  // 1. callback.html left an error behind (state mismatch, exchange failed)
  // 2. callback.html just stored a fresh token — or a previous session
  //    token is still valid — in sessionStorage
  if (!consumeOAuthError()) {
    await tryRestoreSession();
  }
});
