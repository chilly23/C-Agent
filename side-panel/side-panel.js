/**
 * AgentGuard Side Panel Script
 * Handles: Agent execution, Security scanning, Audit logging
 */

// ── STATE ────────────────────────────────────────────────────────
let port = null;
let isRunning = false;
let stepCount = 0;
let auditChain = [];      // cryptographic audit entries
let fullLog = [];         // all log events ever
let taskHistory = [];     // completed tasks

// ── CONNECT TO BACKGROUND ────────────────────────────────────────
function connectToBackground() {
  try {
    port = chrome.runtime.connect({ name: 'side-panel-connection' });
    port.onMessage.addListener(handleBackgroundMessage);
    port.onDisconnect.addListener(() => {
      port = null;
      if (isRunning) {
        addLog('warn', 'Background disconnected');
        setStatus('idle');
      }
      // Reconnect after a short delay
      setTimeout(connectToBackground, 1000);
    });
  } catch (e) {
    setTimeout(connectToBackground, 2000);
  }
}

function sendToBackground(msg) {
  if (port) {
    try { port.postMessage(msg); } catch (e) { connectToBackground(); }
  }
}

// ── MESSAGE HANDLER ──────────────────────────────────────────────
function handleBackgroundMessage(msg) {
  if (!msg) return;
  const { type, state, actor, data, error } = msg;

  // Handle event stream from executor
  if (state && actor && data) {
    const details = data.details || '';
    const step = data.step || 0;

    switch (state) {
      case 'task.start':
        stepCount = 0;
        updateStepCounter(0);
        addLog('info', `[TASK START] ${details}`);
        recordAudit('TASK_START', details);
        break;
      case 'task.ok':
        setStatus('done');
        addLog('success', `[DONE] ${details}`);
        recordAudit('TASK_OK', details);
        addToHistory(currentTask, 'success');
        isRunning = false;
        toggleRunBtn(false);
        break;
      case 'task.fail':
        setStatus('error');
        addLog('error', `[FAIL] ${details}`);
        recordAudit('TASK_FAIL', details);
        addToHistory(currentTask, 'fail');
        isRunning = false;
        toggleRunBtn(false);
        break;
      case 'task.cancel':
        setStatus('idle');
        addLog('warn', `[CANCELLED] ${details}`);
        recordAudit('TASK_CANCEL', details);
        isRunning = false;
        toggleRunBtn(false);
        break;
      case 'task.pause':
        setStatus('idle');
        addLog('warn', '[PAUSED]');
        break;
      case 'step.start':
        stepCount = step + 1;
        updateStepCounter(stepCount);
        addLog('info', `[${actor.toUpperCase()}] ${details}`);
        break;
      case 'step.ok':
        addLog('action', `[${actor.toUpperCase()}] ✓ ${details}`);
        recordAudit(`${actor.toUpperCase()}_STEP_OK`, details, step);
        break;
      case 'step.fail':
        addLog('error', `[${actor.toUpperCase()}] ✗ ${details}`);
        break;
      case 'act.start':
        addLog('info', `  → ${details}`);
        break;
      case 'act.ok':
        addLog('action', `  ✓ ${details}`);
        recordAudit('ACT_OK', details, step);
        break;
      case 'act.fail':
        addLog('error', `  ✗ ${details}`);
        break;
    }
    return;
  }

  if (type === 'error') {
    addLog('error', `[ERROR] ${error || 'Unknown error'}`);
    setStatus('error');
    isRunning = false;
    toggleRunBtn(false);
    return;
  }
  if (type === 'heartbeat_ack') return;
  if (type === 'success') return;

  if (type === 'security_scan_result') {
    renderSecurityResults(msg.result);
    return;
  }
}

// ── CURRENT TASK TRACKER ─────────────────────────────────────────
let currentTask = '';

// ── RUN / STOP ───────────────────────────────────────────────────
document.getElementById('btn-run').addEventListener('click', async () => {
  const task = document.getElementById('task-input').value.trim();
  if (!task) {
    addLog('warn', '// no task entered');
    return;
  }

  // Get active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    addLog('error', '// no active tab found');
    return;
  }

  // Check if settings are configured
  const settings = await loadSettings();
  if (!settings.apiKey) {
    addLog('warn', '// no API key configured — go to 06 VERIFY → settings');
    switchPanel('verify');
    return;
  }

  currentTask = task;
  isRunning = true;
  stepCount = 0;
  toggleRunBtn(true);
  setStatus('running');
  clearLog();
  addLog('info', `// task: ${task}`);
  addLog('info', `// using model: ${settings.model || 'claude-sonnet-4-6'}`);

  const taskId = `task_${Date.now()}`;
  sendToBackground({
    type: 'new_task',
    task,
    taskId,
    tabId: tab.id,
    settings,
  });
});

document.getElementById('btn-stop').addEventListener('click', () => {
  if (!isRunning) return;
  sendToBackground({ type: 'cancel_task' });
  addLog('warn', '// stop requested');
});

document.getElementById('btn-view-audit').addEventListener('click', () => {
  switchPanel('verify');
});

// ── QUICK ACTIONS ────────────────────────────────────────────────
document.getElementById('btn-goto').addEventListener('click', async () => {
  const url = document.getElementById('quick-url').value.trim();
  if (!url) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    await chrome.tabs.update(tab.id, { url: url.startsWith('http') ? url : 'https://' + url });
    addLog('action', `// navigating to ${url}`);
  }
});

document.getElementById('btn-search').addEventListener('click', async () => {
  const q = document.getElementById('quick-search').value.trim();
  if (!q) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    await chrome.tabs.update(tab.id, { url: `https://www.google.com/search?q=${encodeURIComponent(q)}` });
    addLog('action', `// searching: ${q}`);
  }
});

// ── SECURITY SCAN ────────────────────────────────────────────────
document.getElementById('btn-scan').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) { addLog('error', '// no active tab'); return; }

  addLog('security', `// scanning: ${tab.url}`);
  resetSecurityUI();

  // Run local analysis
  const result = await analyzePageSecurity(tab);
  renderSecurityResults(result);
  recordAudit('SECURITY_SCAN', `Scanned ${tab.url}`, 0);
});

async function analyzePageSecurity(tab) {
  const url = tab.url || '';
  const result = {
    url,
    protocol: '',
    domain: '',
    ssl: false,
    hsts: false,
    csp: false,
    phishing: {
      lookalike: 0,
      homoglyph: false,
      keywords: [],
      redirectChain: 0,
    },
    zeroClick: [],
    promptInjection: [],
    overallRisk: 'unknown',
  };

  try {
    const parsedUrl = new URL(url);
    result.protocol = parsedUrl.protocol;
    result.domain = parsedUrl.hostname;
    result.ssl = parsedUrl.protocol === 'https:';

    // Phishing checks
    result.phishing.lookalike = calcLookalikeScore(parsedUrl.hostname);
    result.phishing.homoglyph = hasHomoglyphs(parsedUrl.hostname);
    result.phishing.keywords = findPhishingKeywords(parsedUrl.hostname + parsedUrl.pathname);

    // Check for zero-click patterns via content script
    try {
      const [scanResult] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: domSecurityScan,
      });
      if (scanResult?.result) {
        const r = scanResult.result;
        result.zeroClick = r.zeroClick || [];
        result.promptInjection = r.promptInjection || [];
        result.hsts = r.hsts || false;
        result.csp = r.csp || false;
      }
    } catch (_) {
      // scripting not available on this page
    }

    // Overall risk scoring
    let riskScore = 0;
    if (!result.ssl) riskScore += 30;
    if (result.phishing.lookalike > 0.6) riskScore += 25;
    if (result.phishing.homoglyph) riskScore += 20;
    if (result.phishing.keywords.length > 2) riskScore += 15;
    if (result.zeroClick.length > 0) riskScore += result.zeroClick.length * 10;
    if (result.promptInjection.length > 0) riskScore += result.promptInjection.length * 8;

    result.overallRisk = riskScore >= 50 ? 'danger' : riskScore >= 20 ? 'warn' : 'safe';
  } catch (e) {
    result.overallRisk = 'unknown';
  }

  return result;
}

// Injected into page via executeScript
function domSecurityScan() {
  const result = { zeroClick: [], promptInjection: [], hsts: false, csp: false };

  // Check meta tags for CSP
  const metas = document.querySelectorAll('meta[http-equiv]');
  for (const m of metas) {
    const he = m.getAttribute('http-equiv') || '';
    if (he.toLowerCase() === 'content-security-policy') result.csp = true;
  }

  // Zero-click patterns: auto-executing scripts, hidden iframes, auto-redirect
  const scripts = document.querySelectorAll('script');
  const ZERO_CLICK_PATTERNS = [
    { pattern: /document\.location\s*=/, label: 'Auto-redirect via JS', severity: 'high' },
    { pattern: /window\.location\.replace/, label: 'Forced redirect', severity: 'high' },
    { pattern: /eval\s*\(/, label: 'eval() usage', severity: 'med' },
    { pattern: /document\.write\s*\(/, label: 'document.write', severity: 'med' },
    { pattern: /new\s+Function\s*\(/, label: 'Dynamic function creation', severity: 'high' },
    { pattern: /fetch\(.*credentials/, label: 'Credential fetch', severity: 'high' },
    { pattern: /XMLHttpRequest.*withCredentials/, label: 'XHR with credentials', severity: 'med' },
  ];

  const scriptTexts = [];
  for (const s of scripts) {
    if (s.textContent) scriptTexts.push(s.textContent);
  }
  const allScripts = scriptTexts.join('\n');

  for (const p of ZERO_CLICK_PATTERNS) {
    if (p.pattern.test(allScripts)) {
      result.zeroClick.push({ label: p.label, severity: p.severity });
    }
  }

  // Hidden iframes (potential clickjacking / drive-by)
  const iframes = document.querySelectorAll('iframe');
  for (const iframe of iframes) {
    const style = window.getComputedStyle(iframe);
    const w = parseInt(style.width) || 0;
    const h = parseInt(style.height) || 0;
    if ((w <= 1 && h <= 1) || style.opacity === '0' || style.display === 'none') {
      result.zeroClick.push({ label: 'Hidden iframe detected', severity: 'high' });
      break;
    }
  }

  // Prompt injection patterns in visible text
  const bodyText = document.body?.innerText || '';
  const PI_PATTERNS = [
    { pattern: /ignore\s+(previous|all)\s+instructions/i, label: 'Task override attempt' },
    { pattern: /your\s+(new\s+)?task\s+is/i, label: 'Task injection' },
    { pattern: /system\s+prompt/i, label: 'System prompt reference' },
    { pattern: /\[INST\]|\[\/INST\]/i, label: 'LLM instruction tags' },
    { pattern: /<\|system\|>/i, label: 'System role injection' },
    { pattern: /act\s+as\s+a\s+(different|new)\s+(AI|assistant|model)/i, label: 'Role impersonation' },
    { pattern: /disregard\s+(safety|guidelines|rules)/i, label: 'Safety bypass attempt' },
  ];
  for (const p of PI_PATTERNS) {
    if (p.pattern.test(bodyText)) {
      result.promptInjection.push({ label: p.label, severity: 'high' });
    }
  }

  return result;
}

function calcLookalikeScore(domain) {
  const POPULAR = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix',
    'twitter', 'instagram', 'linkedin', 'youtube', 'github', 'reddit', 'wikipedia', 'bankofamerica',
    'chase', 'wellsfargo', 'citibank', 'gmail', 'outlook'];
  const clean = domain.toLowerCase().replace(/^www\./, '').split('.')[0];
  let maxSim = 0;
  for (const p of POPULAR) {
    const sim = stringSimilarity(clean, p);
    if (sim > maxSim) maxSim = sim;
  }
  // If exact match, it's legit
  if (POPULAR.includes(clean)) return 0;
  return maxSim;
}

function stringSimilarity(a, b) {
  const longer = a.length > b.length ? a : b;
  const shorter = a.length > b.length ? b : a;
  if (longer.length === 0) return 1;
  const dist = editDistance(longer, shorter);
  return (longer.length - dist) / longer.length;
}

function editDistance(s, t) {
  const m = s.length, n = t.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0));
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    dp[i][j] = s[i-1] === t[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function hasHomoglyphs(domain) {
  // Common homoglyph characters
  return /[0oOlI1|расеохАСЕОХ]/u.test(domain) && domain.length > 4;
}

function findPhishingKeywords(urlPath) {
  const KEYWORDS = ['login', 'signin', 'secure', 'verify', 'account', 'update', 'confirm',
    'banking', 'password', 'credential', 'wallet', 'crypto', 'urgent', 'suspended'];
  return KEYWORDS.filter(k => urlPath.toLowerCase().includes(k));
}

function renderSecurityResults(result) {
  if (!result) return;

  // Protocol & domain
  setText('sec-protocol', result.protocol || '—');
  setText('sec-domain', result.domain || '—');

  const sslEl = document.getElementById('sec-ssl');
  sslEl.textContent = result.ssl ? 'VALID ✓' : 'NONE ✗';
  sslEl.className = 'sec-val ' + (result.ssl ? 'ok' : 'bad');

  const hstsEl = document.getElementById('sec-hsts');
  hstsEl.textContent = result.hsts ? 'ENABLED ✓' : 'NOT SET';
  hstsEl.className = 'sec-val ' + (result.hsts ? 'ok' : 'warn');

  const cspEl = document.getElementById('sec-csp');
  cspEl.textContent = result.csp ? 'PRESENT ✓' : 'MISSING ✗';
  cspEl.className = 'sec-val ' + (result.csp ? 'ok' : 'warn');

  // Phishing
  const ls = result.phishing?.lookalike || 0;
  const lsEl = document.getElementById('phish-lookalike');
  lsEl.textContent = `${(ls * 100).toFixed(0)}% similarity`;
  lsEl.className = 'sec-val ' + (ls > 0.6 ? 'bad' : ls > 0.3 ? 'warn' : 'ok');

  const homoEl = document.getElementById('phish-homo');
  homoEl.textContent = result.phishing?.homoglyph ? 'DETECTED ✗' : 'CLEAN ✓';
  homoEl.className = 'sec-val ' + (result.phishing?.homoglyph ? 'bad' : 'ok');

  const kw = result.phishing?.keywords || [];
  const kwEl = document.getElementById('phish-keywords');
  kwEl.textContent = kw.length ? kw.join(', ') : 'NONE ✓';
  kwEl.className = 'sec-val ' + (kw.length > 2 ? 'bad' : kw.length > 0 ? 'warn' : 'ok');

  const rdEl = document.getElementById('phish-redirect');
  rdEl.textContent = '—';
  rdEl.className = 'sec-val';

  setText('phish-age', '—');

  // Zero-click threats
  const zcList = document.getElementById('zc-threats-list');
  const zcBadge = document.getElementById('zc-badge');
  const zc = result.zeroClick || [];
  if (zc.length === 0) {
    zcList.innerHTML = '<div style="padding:8px;font-size:10px;color:var(--green)">✓ NO ZERO-CLICK THREATS DETECTED</div>';
    setBadge(zcBadge, 'safe', 'CLEAN');
  } else {
    zcList.innerHTML = zc.map(t => `
      <div class="threat-item ${t.severity}">
        <div class="audit-action">${t.label}</div>
        <div class="threat-type">${t.severity.toUpperCase()} SEVERITY</div>
      </div>`).join('');
    setBadge(zcBadge, zc.some(t => t.severity === 'high') ? 'danger' : 'warn',
      zc.some(t => t.severity === 'high') ? 'DANGER' : 'WARN');
    addLog('security', `[SECURITY] ${zc.length} zero-click threat(s) detected`);
  }

  // Prompt injection
  const piList = document.getElementById('pi-threats-list');
  const piBadge = document.getElementById('pi-badge');
  const pi = result.promptInjection || [];
  if (pi.length === 0) {
    piList.innerHTML = '<div style="padding:8px;font-size:10px;color:var(--green)">✓ NO PROMPT INJECTION DETECTED</div>';
    setBadge(piBadge, 'safe', 'CLEAN');
  } else {
    piList.innerHTML = pi.map(t => `
      <div class="threat-item high">
        <div class="audit-action">${t.label}</div>
        <div class="threat-type">HIGH SEVERITY</div>
      </div>`).join('');
    setBadge(piBadge, 'danger', 'DANGER');
    addLog('security', `[SECURITY] ${pi.length} prompt injection pattern(s) found`);
  }

  // Overall page badge
  const pageBadge = document.getElementById('page-sec-badge');
  const r = result.overallRisk || 'unknown';
  setBadge(pageBadge,
    r === 'safe' ? 'safe' : r === 'warn' ? 'warn' : r === 'danger' ? 'danger' : 'unknown',
    r.toUpperCase());
  const phishBadge = document.getElementById('phish-badge');
  const phishRisk = (ls > 0.6 || result.phishing?.homoglyph || kw.length > 2) ? 'danger' :
                    (ls > 0.3 || kw.length > 0) ? 'warn' : 'safe';
  setBadge(phishBadge, phishRisk, phishRisk.toUpperCase());

  addLog('security', `// scan complete — risk: ${r.toUpperCase()}`);
}

function resetSecurityUI() {
  ['sec-protocol','sec-domain','sec-ssl','sec-hsts','sec-csp',
   'phish-age','phish-lookalike','phish-homo','phish-keywords','phish-redirect'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.textContent = '...'; el.className = 'sec-val'; }
  });
  document.getElementById('zc-threats-list').innerHTML = '<div class="empty-state" style="padding:10px">// scanning...</div>';
  document.getElementById('pi-threats-list').innerHTML = '<div class="empty-state" style="padding:10px">// scanning...</div>';
  ['page-sec-badge','phish-badge','zc-badge','pi-badge'].forEach(id => setBadge(document.getElementById(id), 'unknown', '...'));
}

// ── AUDIT LOG ────────────────────────────────────────────────────
async function recordAudit(action, details, step = 0) {
  const prev = auditChain.length > 0 ? auditChain[auditChain.length - 1].hash : '0'.repeat(64);
  const payload = `${Date.now()}|${action}|${details}|${step}|${prev}`;
  const hash = await sha256(payload);
  const entry = { ts: Date.now(), action, details: details.slice(0, 100), step, hash, prev };
  auditChain.push(entry);
  renderAuditEntry(entry);
}

async function sha256(message) {
  try {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (_) {
    return Math.random().toString(16).slice(2).padEnd(64, '0');
  }
}

function renderAuditEntry(entry) {
  const list = document.getElementById('audit-log-list');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const el = document.createElement('div');
  el.className = 'audit-entry';
  el.innerHTML = `
    <div style="display:flex;justify-content:space-between">
      <span class="audit-action">${entry.action}</span>
      <span class="audit-time">${new Date(entry.ts).toLocaleTimeString()}</span>
    </div>
    <div style="color:var(--text-dim);font-size:10px;margin:2px 0">${entry.details}</div>
    <div class="audit-hash">HASH: ${entry.hash}</div>
    <div class="audit-hash">PREV: ${entry.prev}</div>
  `;
  list.appendChild(el);
  list.scrollTop = list.scrollHeight;
}

// ── TASK HISTORY ─────────────────────────────────────────────────
function addToHistory(task, status) {
  taskHistory.push({ task, status, ts: Date.now() });
  renderTaskHistory();
  saveToStorage();
}

function renderTaskHistory() {
  const list = document.getElementById('task-history-list');
  if (taskHistory.length === 0) {
    list.innerHTML = '<div class="empty-state">// no tasks yet</div>';
    return;
  }
  list.innerHTML = [...taskHistory].reverse().slice(0, 20).map(h => `
    <div class="hist-item">
      <div class="hist-item-hdr">
        <span class="hist-task">${h.task}</span>
        <span class="hist-time">${new Date(h.ts).toLocaleTimeString()}</span>
      </div>
    </div>
  `).join('');
}

// ── LOG HELPERS ──────────────────────────────────────────────────
function addLog(type, msg) {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const entry = { type, msg, ts };
  fullLog.push(entry);

  // Live log (agent panel)
  appendLogEntry(document.getElementById('log-container'), entry);
  // Full log panel
  appendLogEntry(document.getElementById('full-log-container'), entry);
}

function appendLogEntry(container, entry) {
  if (!container) return;
  const empty = container.querySelector('.empty-state');
  if (empty) empty.remove();

  const el = document.createElement('div');
  el.className = `log-entry ${entry.type}`;
  el.innerHTML = `<span class="log-ts">[${entry.ts}]</span>${escHtml(entry.msg)}`;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;

  // Keep only last 200 entries in DOM
  const entries = container.querySelectorAll('.log-entry');
  if (entries.length > 200) entries[0].remove();
}

function clearLog() {
  const c = document.getElementById('log-container');
  c.innerHTML = '<div class="empty-state">// awaiting task input</div>';
}

document.getElementById('btn-clear-log').addEventListener('click', clearLog);
document.getElementById('btn-clear-all-log').addEventListener('click', () => {
  fullLog = [];
  document.getElementById('full-log-container').innerHTML = '<div class="empty-state">// no events</div>';
});

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── STATUS ───────────────────────────────────────────────────────
function setStatus(state) {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  dot.className = 'status-dot ' + state;
  const labels = { idle: 'IDLE — READY', running: 'RUNNING...', done: 'TASK COMPLETE', error: 'ERROR' };
  text.textContent = labels[state] || state.toUpperCase();
}

function updateStepCounter(n) {
  document.getElementById('step-counter').textContent = `STEP ${n}`;
}

function toggleRunBtn(running) {
  const btn = document.getElementById('btn-run');
  btn.disabled = running;
  if (running) {
    btn.innerHTML = '<span class="spinner"></span>RUNNING...';
  } else {
    btn.innerHTML = '▶ RUN AGENT';
  }
}

// ── NAV TABS ─────────────────────────────────────────────────────
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    switchPanel(tab.dataset.panel);
  });
});

function switchPanel(panelName) {
  // map panel names to IDs
  const panelMap = {
    agent: 'panel-agent',
    interact: 'panel-interact',
    secure: 'panel-secure',
    automate: 'panel-automate',
    log: 'panel-log',
    verify: 'panel-verify',
  };
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));

  const panelId = panelMap[panelName];
  if (panelId) document.getElementById(panelId)?.classList.add('active');

  const tab = document.querySelector(`[data-panel="${panelName}"]`);
  if (tab) tab.classList.add('active');

  if (panelName === 'interact') updatePageStateInfo();
}

// ── PAGE STATE ───────────────────────────────────────────────────
async function updatePageStateInfo() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
      setText('cur-url', tab.url || '—');
      setText('cur-title', tab.title || '—');
    }
  } catch (_) {}
}

// ── SETTINGS ─────────────────────────────────────────────────────
async function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get(['agentguard_settings'], r => {
      resolve(r.agentguard_settings || {
        apiKey: '',
        provider: 'anthropic',
        model: 'claude-sonnet-4-6',
        maxSteps: 30,
        useVision: false,
      });
    });
  });
}

async function saveToStorage() {
  chrome.storage.local.set({ agentguard_task_history: taskHistory });
}

async function loadFromStorage() {
  return new Promise(resolve => {
    chrome.storage.local.get(['agentguard_task_history'], r => {
      if (r.agentguard_task_history) {
        taskHistory = r.agentguard_task_history;
        renderTaskHistory();
      }
      resolve();
    });
  });
}

// ── UTIL ─────────────────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBadge(el, cls, text) {
  if (!el) return;
  el.className = `badge ${cls}`;
  el.textContent = text;
}

// ── HEARTBEAT ────────────────────────────────────────────────────
setInterval(() => {
  if (port) sendToBackground({ type: 'heartbeat' });
}, 10000);

// ── INIT ─────────────────────────────────────────────────────────
(async () => {
  connectToBackground();
  await loadFromStorage();
  // Update page info periodically
  chrome.tabs.onActivated.addListener(updatePageStateInfo);
  chrome.tabs.onUpdated.addListener((_, info) => {
    if (info.status === 'complete') updatePageStateInfo();
  });
  addLog('info', '// agentguard initialized');
  addLog('info', '// ready for task input');
})();
