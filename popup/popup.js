/**
 * AgentGuard Popup Script
 * Chrome 109 / MV3 compatible - no sidePanel API used
 */

// ── STATE ──────────────────────────────────────────────────────────────────
let port = null;
let isRunning = false;
let stepCount = 0;
let auditChain = [];
let taskHistory = [];
let agentMemory = '';
let currentTask = '';
let fullLogEntries = [];

// ── BACKGROUND CONNECTION ──────────────────────────────────────────────────
function connectBg() {
  try {
    port = chrome.runtime.connect({ name: 'side-panel-connection' });
    port.onMessage.addListener(onBgMessage);
    port.onDisconnect.addListener(() => {
      port = null;
      if (isRunning) { setStatus('error'); isRunning = false; setRunning(false); }
    });
  } catch (e) {}
}

function sendBg(msg) {
  if (!port) connectBg();
  if (port) try { port.postMessage(msg); } catch (e) { connectBg(); }
}

// ── BACKGROUND MESSAGES ───────────────────────────────────────────────────
function onBgMessage(msg) {
  if (!msg) return;
  const { type, state, actor, data, error } = msg;

  if (state && actor && data) {
    const det = data.details || '';
    const step = data.step || 0;
    switch (state) {
      case 'task.start':
        stepCount = 0; updateStep(0);
        addLog('info', `[TASK START]`);
        auditRecord('TASK_START', det);
        break;
      case 'task.ok':
        setStatus('done'); addLog('success', `[DONE] ${det}`);
        auditRecord('TASK_OK', det);
        saveHistory(currentTask, 'ok');
        isRunning = false; setRunning(false);
        break;
      case 'task.fail':
        setStatus('error'); addLog('error', `[FAIL] ${det}`);
        auditRecord('TASK_FAIL', det);
        saveHistory(currentTask, 'fail');
        isRunning = false; setRunning(false);
        break;
      case 'task.cancel':
        setStatus('idle'); addLog('warn', `[CANCELLED]`);
        isRunning = false; setRunning(false);
        break;
      case 'step.start':
        stepCount = step + 1; updateStep(stepCount);
        addLog('info', `[${(actor||'').toUpperCase()}] ${det}`);
        break;
      case 'step.ok':
        addLog('action', `[${(actor||'').toUpperCase()}] ✓ ${det}`);
        auditRecord(`${(actor||'').toUpperCase()}_OK`, det, step);
        break;
      case 'step.fail':
        addLog('error', `[${(actor||'').toUpperCase()}] ✗ ${det}`);
        break;
      case 'act.start':
        addLog('info', `  → ${det}`);
        break;
      case 'act.ok':
        addLog('action', `  ✓ ${det}`);
        auditRecord('ACT_OK', det, step);
        break;
      case 'act.fail':
        addLog('error', `  ✗ ${det}`);
        break;
    }
    // Update memory display
    if (data.memory) {
      agentMemory = data.memory;
      el('mem-display').textContent = agentMemory;
    }
    return;
  }
  if (type === 'error') {
    addLog('error', `[ERROR] ${error}`);
    setStatus('error'); isRunning = false; setRunning(false);
  }
  if (type === 'heartbeat_ack') return;
}

// ── RUN / STOP ─────────────────────────────────────────────────────────────
el('btn-run').addEventListener('click', async () => {
  const task = el('task-input').value.trim();
  if (!task) { addLog('warn', '// no task entered'); return; }

  const s = await loadSettings();
  if (!s.apiKey) {
    addLog('warn', '// no API key — go to 06 VERIFY and paste your key');
    switchTo('verify'); return;
  }

  currentTask = task;
  isRunning = true; stepCount = 0;
  setRunning(true); setStatus('running');
  clearLiveLog();
  addLog('info', `// task: ${task}`);
  addLog('info', `// provider: ${s.provider} / model: ${s.model}`);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  sendBg({ type: 'new_task', task, taskId: `t_${Date.now()}`, tabId: tab?.id, settings: s });
});

el('btn-stop').addEventListener('click', () => {
  if (!isRunning) return;
  sendBg({ type: 'cancel_task' });
  addLog('warn', '// stop requested');
});

el('btn-goto-audit').addEventListener('click', () => switchTo('verify'));

// ── INTERACT PANEL ─────────────────────────────────────────────────────────
el('btn-goto-url').addEventListener('click', async () => {
  const u = el('quick-url').value.trim();
  if (!u) return;
  const url = u.startsWith('http') ? u : 'https://' + u;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) { chrome.tabs.update(tab.id, { url }); addLog('action', `// → ${url}`); }
});

el('btn-do-search').addEventListener('click', async () => {
  const q = el('quick-search').value.trim();
  if (!q) return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    chrome.tabs.update(tab.id, { url: `https://www.google.com/search?q=${encodeURIComponent(q)}` });
    addLog('action', `// searching: ${q}`);
  }
});

// ── SECURITY SCAN ──────────────────────────────────────────────────────────
el('btn-scan').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) { addLog('error', '// no active tab'); return; }
  resetSecUI();
  addLog('sec', `// scanning: ${tab.url}`);
  const r = await runSecScan(tab);
  renderSec(r);
  auditRecord('SECURITY_SCAN', `Scanned ${tab.url}`);
});

async function runSecScan(tab) {
  const url = tab.url || '';
  const r = {
    url, proto: '', domain: '', ssl: false, csp: false,
    phish: { look: 0, homo: false, kw: [] },
    zeroClick: [], promptInj: [], risk: 'unknown',
  };
  try {
    const u = new URL(url);
    r.proto = u.protocol;
    r.domain = u.hostname;
    r.ssl = u.protocol === 'https:';
    r.phish.look = lookalike(u.hostname);
    r.phish.homo = homoglyph(u.hostname);
    r.phish.kw = phishKw(u.hostname + u.pathname);

    try {
      const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: domScan });
      if (res?.result) {
        r.zeroClick = res.result.zc || [];
        r.promptInj = res.result.pi || [];
        r.csp = res.result.csp || false;
      }
    } catch (_) {}

    let score = 0;
    if (!r.ssl) score += 30;
    if (r.phish.look > 0.6) score += 25;
    if (r.phish.homo) score += 18;
    if (r.phish.kw.length > 2) score += 15;
    score += r.zeroClick.length * 10;
    score += r.promptInj.length * 8;
    r.risk = score >= 50 ? 'danger' : score >= 18 ? 'warn' : 'safe';
  } catch (_) {}
  return r;
}

function domScan() {
  const out = { csp: false, zc: [], pi: [] };

  for (const m of document.querySelectorAll('meta[http-equiv]')) {
    if ((m.getAttribute('http-equiv') || '').toLowerCase() === 'content-security-policy') out.csp = true;
  }

  let allJs = '';
  for (const s of document.querySelectorAll('script')) allJs += (s.textContent || '') + '\n';

  const ZC = [
    { re: /document\.location\s*=/, label: 'Auto-redirect', sev: 'high' },
    { re: /window\.location\.replace/, label: 'Forced redirect', sev: 'high' },
    { re: /eval\s*\(/, label: 'eval() usage', sev: 'med' },
    { re: /document\.write\s*\(/, label: 'document.write()', sev: 'med' },
    { re: /new\s+Function\s*\(/, label: 'Dynamic Function', sev: 'high' },
    { re: /fetch\(.*credentials/, label: 'Credential fetch', sev: 'high' },
  ];
  for (const z of ZC) if (z.re.test(allJs)) out.zc.push({ label: z.label, sev: z.sev });

  for (const iframe of document.querySelectorAll('iframe')) {
    const st = window.getComputedStyle(iframe);
    const w = parseInt(st.width) || 0, h = parseInt(st.height) || 0;
    if ((w < 2 && h < 2) || st.opacity === '0' || st.display === 'none')
      out.zc.push({ label: 'Hidden iframe', sev: 'high' });
  }

  const body = document.body?.innerText || '';
  const PI = [
    { re: /ignore\s+(previous|all)\s+instructions/i, label: 'Task override attempt' },
    { re: /your\s+(new\s+)?task\s+is/i, label: 'Task injection' },
    { re: /system\s+prompt/i, label: 'System prompt ref' },
    { re: /act\s+as\s+(a\s+)?(different|new)\s+(AI|assistant)/i, label: 'Role impersonation' },
    { re: /disregard\s+(safety|guidelines|rules)/i, label: 'Safety bypass' },
    { re: /\[INST\]|\[\/INST\]/i, label: 'LLM instruction tags' },
  ];
  for (const p of PI) if (p.re.test(body)) out.pi.push({ label: p.label });
  return out;
}

function lookalike(domain) {
  const BRANDS = ['google','facebook','amazon','microsoft','apple','paypal','netflix',
    'twitter','instagram','linkedin','youtube','github','gmail','outlook','chase','paypal'];
  const clean = domain.toLowerCase().replace(/^www\./, '').split('.')[0];
  if (BRANDS.includes(clean)) return 0;
  let max = 0;
  for (const b of BRANDS) { const s = sim(clean, b); if (s > max) max = s; }
  return max;
}
function sim(a, b) {
  if (!a || !b) return 0;
  const l = a.length > b.length ? a : b, s = a.length > b.length ? b : a;
  if (!l.length) return 1;
  return (l.length - ed(l, s)) / l.length;
}
function ed(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({length:m+1}, (_,i) => Array.from({length:n+1}, (_,j) => i===0?j:j===0?i:0));
  for (let i=1;i<=m;i++) for(let j=1;j<=n;j++)
    d[i][j] = a[i-1]===b[j-1] ? d[i-1][j-1] : 1+Math.min(d[i-1][j],d[i][j-1],d[i-1][j-1]);
  return d[m][n];
}
function homoglyph(domain) {
  return /[0oO1lI]/.test(domain) && domain.includes('-') && domain.length > 6;
}
function phishKw(path) {
  return ['login','signin','verify','account','update','confirm','banking','password',
    'credential','wallet','suspended','urgent'].filter(k => path.toLowerCase().includes(k));
}

function renderSec(r) {
  setText('s-proto', r.proto || '—');
  setText('s-domain', r.domain || '—');
  setKV('s-ssl', r.ssl ? 'HTTPS ✓' : 'HTTP ✗', r.ssl ? 'ok' : 'bad');
  setKV('s-csp', r.csp ? 'PRESENT ✓' : 'MISSING', r.csp ? 'ok' : 'warn');

  const ls = r.phish?.look || 0;
  setKV('s-look', `${(ls*100).toFixed(0)}% similarity`, ls > 0.6 ? 'bad' : ls > 0.3 ? 'warn' : 'ok');
  setKV('s-homo', r.phish?.homo ? 'DETECTED ✗' : 'CLEAN ✓', r.phish?.homo ? 'bad' : 'ok');
  const kw = r.phish?.kw || [];
  setKV('s-kw', kw.length ? kw.join(', ') : 'NONE ✓', kw.length > 2 ? 'bad' : kw.length ? 'warn' : 'ok');

  const zcEl = el('zc-list'), zcB = el('b-zc');
  const zc = r.zeroClick || [];
  if (!zc.length) { zcEl.innerHTML = '<div style="padding:6px;font-size:10px;color:var(--green)">✓ NONE DETECTED</div>'; setBadge(zcB,'safe','CLEAN'); }
  else {
    zcEl.innerHTML = zc.map(t=>`<div class="threat ${t.sev}"><div>${t.label}</div><div class="threat-type">${t.sev.toUpperCase()}</div></div>`).join('');
    setBadge(zcB, zc.some(t=>t.sev==='high')?'danger':'warn', 'THREATS');
    addLog('sec', `[SEC] ${zc.length} zero-click threat(s)`);
  }

  const piEl = el('pi-list'), piB = el('b-pi');
  const pi = r.promptInj || [];
  if (!pi.length) { piEl.innerHTML = '<div style="padding:6px;font-size:10px;color:var(--green)">✓ NONE DETECTED</div>'; setBadge(piB,'safe','CLEAN'); }
  else {
    piEl.innerHTML = pi.map(p=>`<div class="threat high"><div>${p.label}</div><div class="threat-type">HIGH</div></div>`).join('');
    setBadge(piB, 'danger', 'DANGER');
    addLog('sec', `[SEC] ${pi.length} injection pattern(s)`);
  }

  setBadge(el('b-page'), r.risk === 'safe' ? 'safe' : r.risk === 'warn' ? 'warn' : r.risk === 'danger' ? 'danger' : 'unknown', (r.risk||'?').toUpperCase());
  const phishRisk = (ls > 0.6 || r.phish?.homo || kw.length > 2) ? 'danger' : (ls > 0.3 || kw.length) ? 'warn' : 'safe';
  setBadge(el('b-phish'), phishRisk, phishRisk.toUpperCase());
  addLog('sec', `// scan done — risk: ${(r.risk||'?').toUpperCase()}`);
}

function resetSecUI() {
  ['s-proto','s-domain','s-ssl','s-csp','s-look','s-homo','s-kw'].forEach(id => { const e = el(id); if(e) { e.textContent='...'; e.className='kv-val'; } });
  el('zc-list').innerHTML = '<div class="empty" style="padding:6px">// scanning...</div>';
  el('pi-list').innerHTML = '<div class="empty" style="padding:6px">// scanning...</div>';
  ['b-page','b-phish','b-zc','b-pi'].forEach(id => setBadge(el(id),'','...'));
}

// ── AUDIT LOG ─────────────────────────────────────────────────────────────
async function auditRecord(action, details, step = 0) {
  const prev = auditChain.length ? auditChain[auditChain.length-1].hash : '0'.repeat(64);
  const payload = `${Date.now()}|${action}|${details}|${step}|${prev}`;
  const hash = await sha256(payload);
  const entry = { ts: Date.now(), action, details: (details||'').slice(0,90), step, hash, prev };
  auditChain.push(entry);
  renderAuditEntry(entry);
  persistAudit();
}

async function sha256(msg) {
  try {
    const buf = new TextEncoder().encode(msg);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  } catch (_) { return Math.random().toString(16).slice(2).padEnd(64,'0'); }
}

function renderAuditEntry(e) {
  const list = el('audit-list');
  const emp = list.querySelector('.empty');
  if (emp) emp.remove();
  const d = document.createElement('div');
  d.className = 'aentry';
  d.innerHTML = `<div class="aentry-top"><span class="aaction">${e.action}</span><span class="atime">${new Date(e.ts).toLocaleTimeString()}</span></div>
<div class="adetail">${esc(e.details)}</div>
<div class="ahash">H: ${e.hash}</div>`;
  list.appendChild(d);
  list.scrollTop = list.scrollHeight;
}

// ── HISTORY ───────────────────────────────────────────────────────────────
function saveHistory(task, status) {
  taskHistory.push({ task, status, ts: Date.now() });
  renderHistory();
  chrome.storage.local.set({ ag_history: taskHistory });
}

function renderHistory() {
  const list = el('hist-list');
  if (!taskHistory.length) { list.innerHTML = '<div class="empty">// no tasks yet</div>'; return; }
  list.innerHTML = [...taskHistory].reverse().slice(0,30).map(h => `
    <div class="hitem">
      <div class="hitem-hdr">
        <span class="htask">${esc(h.task)}</span>
        <span class="htime">${new Date(h.ts).toLocaleTimeString()}</span>
        <span class="hstatus ${h.status==='ok'?'ok':'fail'}">${h.status==='ok'?'OK':'FAIL'}</span>
      </div>
    </div>`).join('');
}

el('btn-clr-hist').addEventListener('click', () => {
  taskHistory = [];
  el('hist-list').innerHTML = '<div class="empty">// no tasks yet</div>';
  chrome.storage.local.remove('ag_history');
});

// ── FULL LOG ──────────────────────────────────────────────────────────────
el('btn-clr-fulllog').addEventListener('click', () => {
  fullLogEntries = [];
  el('fulllog-box').innerHTML = '<div class="empty">// no events</div>';
});

// ── SETTINGS ──────────────────────────────────────────────────────────────
el('cfg-steps').addEventListener('input', e => {
  el('cfg-steps-val').textContent = e.target.value;
  el('cfg-steps-lbl').textContent = e.target.value;
});

el('btn-save').addEventListener('click', () => {
  const s = {
    provider: el('cfg-provider').value,
    apiKey: el('cfg-key').value,
    model: el('cfg-model').value,
    maxSteps: parseInt(el('cfg-steps').value),
  };
  chrome.storage.local.set({ ag_settings: s }, () => {
    const m = el('saved-msg'); m.classList.add('show');
    setTimeout(() => m.classList.remove('show'), 2500);
  });
});

async function loadSettings() {
  return new Promise(res => {
    chrome.storage.local.get(['ag_settings'], r => {
      res(r.ag_settings || { provider:'anthropic', apiKey:'', model:'claude-sonnet-4-6', maxSteps:30 });
    });
  });
}

function applySettings(s) {
  if (!s) return;
  if (s.provider) el('cfg-provider').value = s.provider;
  if (s.apiKey) el('cfg-key').value = s.apiKey;
  if (s.model) el('cfg-model').value = s.model;
  if (s.maxSteps) {
    el('cfg-steps').value = s.maxSteps;
    el('cfg-steps-val').textContent = s.maxSteps;
    el('cfg-steps-lbl').textContent = s.maxSteps;
  }
}

function persistAudit() {
  chrome.storage.local.set({ ag_audit: auditChain.slice(-100) });
}

// ── TABS ──────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => switchTo(t.dataset.p)));

function switchTo(name) {
  const map = { agent:'p-agent', interact:'p-interact', secure:'p-secure', automate:'p-automate', log:'p-log', verify:'p-verify' };
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  const pid = map[name];
  if (pid) el(pid)?.classList.add('active');
  document.querySelector(`[data-p="${name}"]`)?.classList.add('active');
  if (name === 'interact') updatePageInfo();
}

async function updatePageInfo() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) { setText('pg-url', (tab.url||'').slice(0,55)); setText('pg-title', (tab.title||'').slice(0,55)); }
  } catch (_) {}
}

// ── LOG HELPERS ───────────────────────────────────────────────────────────
function addLog(type, msg) {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const entry = { type, msg, ts };
  fullLogEntries.push(entry);
  appendTo(el('log-box'), entry);
  appendTo(el('fulllog-box'), entry);
}

function appendTo(container, entry) {
  if (!container) return;
  const emp = container.querySelector('.empty'); if (emp) emp.remove();
  const d = document.createElement('div');
  d.className = `le ${entry.type}`;
  d.innerHTML = `<span class="ts">[${entry.ts}]</span>${esc(entry.msg)}`;
  container.appendChild(d);
  container.scrollTop = container.scrollHeight;
  const all = container.querySelectorAll('.le');
  if (all.length > 200) all[0].remove();
}

function clearLiveLog() {
  el('log-box').innerHTML = '<div class="empty">// awaiting task input</div>';
}

el('btn-clrlog').addEventListener('click', clearLiveLog);

// ── STATUS ────────────────────────────────────────────────────────────────
function setStatus(s) {
  const dot = el('sdot'), txt = el('stext');
  dot.className = `dot ${s}`;
  txt.textContent = { idle:'IDLE — READY', running:'RUNNING...', done:'TASK COMPLETE', error:'ERROR' }[s] || s.toUpperCase();
}
function updateStep(n) { el('stepc').textContent = `STEP ${n}`; }
function setRunning(r) {
  const b = el('btn-run');
  b.disabled = r;
  b.innerHTML = r ? '<span class="spin"></span>RUNNING...' : '▶ RUN AGENT';
}

// ── UTILS ──────────────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function setText(id, v) { const e = el(id); if(e) e.textContent = v; }
function setKV(id, v, cls) { const e = el(id); if(e) { e.textContent = v; e.className = `kv-val ${cls||''}`; } }
function setBadge(e, cls, txt) { if(!e) return; e.className = `badge ${cls}`; e.textContent = txt; }
function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ── HEARTBEAT ─────────────────────────────────────────────────────────────
setInterval(() => { if (port) sendBg({ type: 'heartbeat' }); }, 10000);

// ── INIT ──────────────────────────────────────────────────────────────────
(async () => {
  connectBg();

  // Load saved data
  chrome.storage.local.get(['ag_settings','ag_history','ag_audit'], r => {
    if (r.ag_settings) applySettings(r.ag_settings);
    if (r.ag_history) { taskHistory = r.ag_history; renderHistory(); }
    if (r.ag_audit) {
      auditChain = r.ag_audit;
      auditChain.forEach(e => renderAuditEntry(e));
    }
  });

  // Auto-update page info
  chrome.tabs.onActivated?.addListener(updatePageInfo);
  chrome.tabs.onUpdated?.addListener((_, info) => { if (info.status === 'complete') updatePageInfo(); });

  addLog('info', '// agentguard v1.0 — chrome 109 compatible');
  addLog('info', '// go to 06 VERIFY to configure your API key');
})();
