// AgentGuard content script — indexes interactive elements for agent use
(function() {
  if (window.__agentguard_loaded) return;
  window.__agentguard_loaded = true;

  function index() {
    const sel = 'a,button,input,textarea,select,[role="button"],[role="link"],[onclick]';
    let i = 0;
    for (const el of document.querySelectorAll(sel)) {
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) el.setAttribute('data-ag-idx', i++);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', index);
  else index();

  chrome.runtime.onMessage.addListener((msg, _, respond) => {
    if (msg.type === 'reindex') { index(); respond({ ok: true }); }
    return true;
  });
})();
