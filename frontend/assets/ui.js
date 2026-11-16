/* UI primitives — DOM helpers, escaping, tables, toasts. No framework, no build step. */
const UI = (() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const esc = (v) => String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  let toastTimer = null;
  function toast(msg, kind) {
    const el = $('#toast');
    el.textContent = msg;
    el.className = 'toast ' + (kind || '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add('hidden'), kind === 'err' ? 6500 : 3600);
  }

  function table(el, cols, rows, opts = {}) {
    if (!rows || !rows.length) {
      el.innerHTML = `<div class="empty">${esc(opts.empty || 'No records.')}</div>`;
      return;
    }
    const head = cols.map(c => `<th>${esc(c.label)}</th>`).join('');
    const body = rows.map(r => {
      const tds = cols.map(c => {
        const raw = typeof c.get === 'function' ? c.get(r) : r[c.key];
        const html = c.html ? raw : esc(raw);
        return `<td class="${c.mono ? 'mono' : ''}">${html == null ? '' : html}</td>`;
      }).join('');
      const rowAttr = opts.rowAttr ? opts.rowAttr(r) : '';
      return `<tr ${rowAttr}>${tds}</tr>`;
    }).join('');
    el.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  }

  function kv(el, pairs, opts) {
    // Everything is escaped unless the caller explicitly asks for raw markup.
    // The old "a value starting with < is trusted HTML" rule turned any echoed
    // target string into live markup; the callers never needed it.
    const raw = !!(opts && opts.html);
    el.innerHTML = pairs.map(([k, v]) =>
      `<div class="k">${esc(k)}</div><div class="v">${raw ? (v == null ? '' : v) : esc(v)}</div>`
    ).join('');
  }

  function bars(el, counts, order) {
    const keys = order || Object.keys(counts);
    const max = Math.max(1, ...keys.map(k => counts[k] || 0));
    el.innerHTML = keys.map(k => {
      const n = counts[k] || 0;
      const pct = Math.round((n / max) * 100);
      return `<div class="bar-row"><span class="t">${esc(k)}</span>
        <span class="bar-track"><span class="bar-fill ${esc(k)}" style="width:${pct}%"></span></span>
        <span>${n}</span></div>`;
    }).join('');
  }

  const sevClass = (s) => ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'info';

  function findingCard(f) {
    const sev = sevClass(f.severity);
    const ev = (f.evidence || []).filter(e => e && typeof e === 'object');
    const evHtml = ev.slice(0, 4).map(e => {
      const head = e.command ? `<div class="muted small">$ ${esc(e.command)}</div>` :
        (e.summary ? `<div class="muted small">${esc(e.summary)}</div>` : '');
      const out = e.stdout ? `<pre>${esc(String(e.stdout).slice(0, 1600))}</pre>` : '';
      return head + out;
    }).join('');
    const meta = [
      f.asset ? `asset: ${esc(f.asset)}` : '',
      f.cvss_score != null ? `CVSS ${esc(f.cvss_score)}` : '',
      (f.cwe && f.cwe.length) ? esc(f.cwe.join(', ')) : '',
      f.check_id ? `check ${esc(f.check_id)}` : '',
    ].filter(Boolean).map(x => `<span>${x}</span>`).join('');
    const rem = f.remediation ? `<div class="finding-meta"><span>remediation: ${esc(f.remediation)}</span></div>` : '';
    return `<div class="finding ${sev}">
      <div class="finding-head">
        <span class="pill ${sev}">${esc(f.severity)}</span>
        <span class="pill src ${esc(f.evidence_source)}">${esc(f.evidence_source)}</span>
        <span class="finding-title">${esc(f.title)}</span>
      </div>
      <div class="finding-body">${esc(f.description || '')}</div>
      ${meta ? `<div class="finding-meta">${meta}</div>` : ''}
      ${rem}
      ${evHtml}
    </div>`;
  }

  function stopBadge(active) {
    const b = $('#stop-badge');
    if (active) b.classList.remove('hidden'); else b.classList.add('hidden');
  }

  function badge(el, text, cls) {
    el.textContent = text;
    el.className = 'badge ' + (cls || '');
  }

  return { $, $$, esc, toast, table, kv, bars, findingCard, stopBadge, badge, sevClass };
})();
