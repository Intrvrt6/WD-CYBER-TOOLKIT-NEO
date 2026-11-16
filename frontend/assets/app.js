/* WD CYBER TOOLKIT NEO — application controller. */
(() => {
  const { $, $$, esc, toast, table, kv, bars, findingCard, stopBadge, badge } = UI;
  const S = { templates: [], modules: [], runs: [], caps: null, currentJob: null, pollTimer: null, lastAssessment: null };

  /* --------------------------------------------------------------- gate -- */
  function gateMsg(id, text, ok) {
    const el = $(id);
    el.textContent = text || '';
    el.className = 'gate-msg' + (ok ? ' ok' : '');
  }

  $('#stage1-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    gateMsg('#g1-msg', '');
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    try {
      const r = await WD.stage1($('#g-user').value.trim(), $('#g-pass').value, $('#g-short').value.trim());
      WD.setToken(r.token);
      WD.state.stage = 1; WD.state.user = r.user;
      $('#stage1-form').classList.add('hidden');
      $('#stage2-form').classList.remove('hidden');
      gateMsg('#g2-msg', 'Stage 1 accepted for ' + r.user.username + '. Enter the stage-2 PIN.', true);
      $('#g-pin').focus();
    } catch (err) {
      gateMsg('#g1-msg', err.message);
    } finally { btn.disabled = false; }
  });

  $('#stage2-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    gateMsg('#g2-msg', '');
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    try {
      const r = await WD.stage2($('#g-pin').value.trim());
      WD.state.stage = r.stage; WD.state.user = r.user;
      stopBadge(!!(r.emergency_stop && r.emergency_stop.active));
      await enterShell();
    } catch (err) {
      gateMsg('#g2-msg', err.message);
    } finally { btn.disabled = false; }
  });

  $('#g-back').addEventListener('click', () => {
    $('#stage2-form').classList.add('hidden');
    $('#stage1-form').classList.remove('hidden');
    WD.setToken('');
    gateMsg('#g2-msg', '');
  });

  async function enterShell() {
    $('#gate').classList.add('hidden');
    $('#shell').classList.remove('hidden');
    badge($('#session-badge'), 'STAGE ' + WD.state.stage);
    try { S.me = await WD.me(); } catch { S.me = null; }
    if (S.me && S.me.user && S.me.user.must_change_password) {
      toast('Bootstrap password in use — rotate it in Account before executing tests.', 'warn');
    }
    await Promise.all([loadTemplates(), loadModules(), loadCaps()]);
    await refreshAll();
    switchView('dashboard');
  }

  /* --------------------------------------------------------------- nav --- */
  function switchView(name) {
    $$('.view').forEach(v => v.classList.add('hidden'));
    const v = $('#view-' + name);
    if (v) v.classList.remove('hidden');
    $$('#nav button').forEach(b => b.classList.toggle('active', b.dataset.view === name));
    $('#nav').classList.remove('open');
    const loaders = { dashboard: refreshAll, modules: renderModules, scope: loadScope,
      runs: loadRuns, findings: prepFindings, reports: prepReports, audit: loadAudit,
      caps: renderCaps, artax: initArtax, integrations: initIntegrations,
      account: renderAccount };
    if (loaders[name]) loaders[name]().catch(e => toast(e.message, 'err'));
  }
  $$('#nav button').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
  $('#nav-toggle').addEventListener('click', () => $('#nav').classList.toggle('open'));

  /* ----------------------------------------------------------- dashboard -- */
  async function refreshAll() {
    const [stats, stop] = await Promise.all([WD.stats(), WD.stopState()]);
    stopBadge(!!stop.active);
    $('#dash-ts').textContent = new Date().toLocaleString();
    const sev = stats.findings_by_severity || {};
    $('#kpis').innerHTML = [
      ['assessments', stats.assessments, 'acc'],
      ['findings', stats.findings, ''],
      ['critical', sev.critical || 0, 'bad'],
      ['high', sev.high || 0, 'bad'],
      ['medium', sev.medium || 0, 'warn'],
      ['avg risk', stats.avg_risk == null ? '–' : stats.avg_risk, ''],
      ['audit events', stats.audit_events, ''],
    ].map(([l, v, c]) => `<div class="kpi ${c}"><div class="v">${esc(v)}</div><div class="l">${l}</div></div>`).join('');
    bars($('#sev-chart'), sev, ['critical', 'high', 'medium', 'low', 'info']);
    const h = await WD.health();
    const reg = (h.engines && h.engines.registered) || [];
    const failed = (h.engines && h.engines.failed) || {};
    kv($('#platform-state'), [
      ['instance', h.instance + ' v' + h.version],
      ['database', String(h.database || '').split('/').pop()],
      ['emergency stop', stop.active ? `<span style="color:#fca5a5">ACTIVE (gen ${stop.generation})</span>` : `<span style="color:#22c55e">clear</span>`],
      ['engines loaded', reg.length + ' / ' + (reg.length + Object.keys(failed).length)],
      ['engines', reg.join(', ') || 'none'],
      ['unavailable', Object.entries(failed).map(([k, v]) => k).join(', ') || '–'],
    ]);
    table($('#recent-runs'), [
      { label: 'name', key: 'name' },
      { label: 'module', key: 'module' },
      { label: 'mode', key: 'mode' },
      { label: 'status', key: 'status' },
      { label: 'risk', get: r => r.risk == null ? '–' : r.risk },
      { label: 'created', get: r => fmtTs(r.created_at) },
    ], stats.recent || [], { empty: 'No assessments yet. Create one from “New Assessment”.' });
    S.lastAssessment = (stats.recent && stats.recent[0] && stats.recent[0].id) || S.lastAssessment;
  }

  function fmtTs(s) {
    if (!s) return '–';
    try { return new Date(s).toLocaleString(); } catch { return s; }
  }

  /* -------------------------------------------------------------- modules -- */
  async function loadModules() { S.modules = (await WD.modules()).modules || []; }
  async function renderModules() {
    if (!S.modules.length) await loadModules();
    const loaded = S.modules.map(m => m.module);
    const cards = S.modules.map(m => `<div class="card module-card">
      <div class="modid">${esc(m.module.toUpperCase())}</div>
      <h3 style="margin:6px 0 6px">${esc(m.title)}</h3>
      <div class="muted small">${esc(m.description)}</div>
      <div class="chips">${(m.checks || []).map(c => `<span class="chip${c.active ? '' : ' off'}" title="${esc(c.title)}">${esc(c.id)}</span>`).join('')}</div>
    </div>`).join('');
    $('#modules-grid').innerHTML = cards || '<div class="empty">No engine modules registered.</div>';
    if (!loaded.length) $('#modules-grid').innerHTML = '<div class="empty">Engines are still loading.</div>';
  }

  /* ---------------------------------------------------------------- scope -- */
  async function loadScope() {
    const r = await WD.scope();
    table($('#scope-list'), [
      { label: 'target', key: 'target', mono: true },
      { label: 'type', key: 'target_type' },
      { label: 'description', get: s => s.description || '–' },
      { label: 'by', key: 'created_by' },
      { label: 'active', get: s => s.active ? 'yes' : 'no' },
      { label: '', get: s => `<button class="btn sm ghost" data-del-scope="${esc(s.id)}">REMOVE</button>`, html: true },
    ], r.scope || [], { empty: 'Scope registry is empty — add the targets you are authorized to test.' });
    $$('[data-del-scope]').forEach(b => b.addEventListener('click', async () => {
      try { await WD.delScope(b.dataset.delScope); toast('Scope entry removed', 'ok'); await loadScope(); }
      catch (e) { toast(e.message, 'err'); }
    }));
  }
  $('#scope-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await WD.addScope($('#scope-target').value.trim(), $('#scope-desc').value.trim());
      toast('Added ' + r.target + ' (' + r.target_type + ')', 'ok');
      $('#scope-target').value = ''; $('#scope-desc').value = '';
      await loadScope();
    } catch (err) { toast(err.message, 'err'); }
  });

  /* --------------------------------------------------------- assessment -- */
  async function loadTemplates() {
    S.templates = (await WD.templates()).templates || [];
    $('#a-template').innerHTML = S.templates.map(t =>
      `<option value="${esc(t.id)}">${esc(t.name)} — ${esc(t.module)}</option>`).join('');
    renderTemplateDetail();
  }
  function currentTemplate() { return S.templates.find(t => t.id === $('#a-template').value); }
  function renderTemplateDetail() {
    const t = currentTemplate();
    if (!t) return;
    $('#a-mode').value = t.mode_default || 'live';
    $('#a-intensity').innerHTML = (t.intensity_options || ['normal']).map(i => `<option>${esc(i)}</option>`).join('');
    kv($('#tpl-detail'), [
      ['module', t.module],
      ['scope types', (t.scope_types || []).join(', ') || 'any'],
      ['requires authorization', t.requires_authorization ? 'yes' : 'no'],
      ['checks', (t.checklist || []).length],
      ['standards', (t.standards || []).join(', ') || '–'],
      ['safety', Object.entries(t.safety || {}).map(([k, v]) => k + '=' + v).join(', ') || '–'],
    ]);
  }
  $('#a-template').addEventListener('change', renderTemplateDetail);

  function parseTargets() {
    return $('#a-targets').value.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
  }

  $('#btn-preflight').addEventListener('click', async () => {
    const targets = parseTargets();
    if (!targets.length) return toast('Enter at least one target', 'err');
    const t = currentTemplate();
    try {
      const v = await WD.validate(targets);
      const rows = [
        ['all in scope', v.all_in_scope ? 'YES' : 'NO'],
        ['scope entries', v.scope_size],
        ...v.results.map(r => [r.target, r.in_scope ? 'in scope (' + (r.matched_scope || '') + ')' : 'OUT OF SCOPE']),
      ];
      kv($('#preflight'), rows);
      kv($('#preflight'), rows.concat([
        ['preflight steps', (t.preflight || []).map(p => p.id).join(', ') || '–'],
        ['mode', $('#a-mode').value],
        ['intensity', $('#a-intensity').value],
      ]));
      gateMsg('#assess-msg', v.all_in_scope ? '' : 'Some targets are outside the registered scope.', v.all_in_scope);
    } catch (e) { toast(e.message, 'err'); }
  });

  $('#btn-create-run').addEventListener('click', async () => {
    const targets = parseTargets();
    if (!targets.length) return toast('Enter at least one target', 'err');
    let params = {};
    try { params = JSON.parse($('#a-params').value || '{}'); }
    catch { return toast('Extra params must be valid JSON', 'err'); }
    const btn = $('#btn-create-run');
    btn.disabled = true;
    gateMsg('#assess-msg', 'Authorizing and creating assessment…', true);
    try {
      const authz = await WD.authorize(targets, Number($('#a-ttl').value) || 60, $('#a-note').value.trim());
      const a = await WD.createAssessment({
        template: currentTemplate().id, targets, mode: $('#a-mode').value,
        intensity: $('#a-intensity').value, params,
      });
      if (!a.status || a.status === 'preflight_failed') {
        gateMsg('#assess-msg', 'Preflight failed: ' + JSON.stringify((a.preflight || {}).checks || []), false);
        btn.disabled = false;
        return;
      }
      gateMsg('#assess-msg', 'Assessment ' + a.id.slice(0, 8) + ' authorized. Starting execution…', true);
      const run = await WD.run(a.id, authz.id);
      S.lastAssessment = a.id;
      watchJob(run.job_id, a.id);
    } catch (err) {
      gateMsg('#assess-msg', err.message, false);
    } finally { btn.disabled = false; }
  });

  function watchJob(jobId, assessmentId) {
    $('#job-card').classList.remove('hidden');
    $('#job-log').textContent = '';
    $('#job-bar').style.width = '0%';
    clearInterval(S.pollTimer);
    let seen = 0;
    S.pollTimer = setInterval(async () => {
      try {
        const j = await WD.job(jobId);
        $('#job-bar').style.width = (j.progress || 0) + '%';
        $('#job-meta').innerHTML = `job <code>${esc(j.id.slice(0, 8))}</code> · ${esc(j.status)} · ${j.progress || 0}%` +
          (j.error ? ` · <span style="color:#fca5a5">${esc(j.error)}</span>` : '');
        const log = j.log || [];
        if (log.length > seen) {
          $('#job-log').textContent += log.slice(seen).map(l =>
            `[${(l.at || '').slice(11, 19)}] ${l.level || 'info'}: ${l.message}`).join('\n') + '\n';
          $('#job-log').scrollTop = $('#job-log').scrollHeight;
          seen = log.length;
        }
        if (['completed', 'failed', 'aborted'].includes(j.status)) {
          clearInterval(S.pollTimer);
          toast('Assessment ' + j.status + (j.error ? ': ' + j.error : ''), j.status === 'completed' ? 'ok' : 'err');
          await refreshAll();
          await openRun(assessmentId);
        }
      } catch (e) { clearInterval(S.pollTimer); toast(e.message, 'err'); }
    }, 1800);
  }

  /* ----------------------------------------------------------------- runs -- */
  async function loadRuns() {
    const r = await WD.assessments();
    S.runs = r.assessments || [];
    table($('#runs-list'), [
      { label: 'name', get: a => `<a href="#" data-open-run="${esc(a.id)}">${esc(a.name)}</a>`, html: true },
      { label: 'module', key: 'module' },
      { label: 'mode', key: 'mode' },
      { label: 'intensity', key: 'intensity' },
      { label: 'status', key: 'status' },
      { label: 'risk', get: a => a.risk_score == null ? '–' : a.risk_score },
      { label: 'findings', get: a => (a.summary && a.summary.findings) || 0 },
      { label: 'created', get: a => fmtTs(a.created_at) },
    ], S.runs, { empty: 'No assessments recorded yet.' });
    $$('[data-open-run]').forEach(a => a.addEventListener('click', (e) => {
      e.preventDefault(); openRun(a.dataset.openRun);
    }));

    const opts = S.runs.map(a => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.status)})</option>`).join('');
    $('#f-run').innerHTML = opts; $('#r-run').innerHTML = opts;
  }

  async function openRun(id) {
    const a = await WD.assessment(id);
    S.lastAssessment = id;
    $('#run-detail').classList.remove('hidden');
    $('#run-detail-title').textContent = a.name;
    const s = a.summary || {};
    const body = $('#run-detail-body');
    body.innerHTML = `
      <div class="kv small">
        ${[['id', a.id], ['template', a.template], ['module', a.module], ['mode', a.mode],
           ['intensity', a.intensity], ['status', a.status], ['operator', a.operator],
           ['risk', a.risk_score == null ? '–' : a.risk_score],
           ['targets', (a.targets || []).join(', ')],
           ['duration', (s.duration_s || '–') + 's'],
           ['checks reported', (s.checks_reported || []).length + ' / ' + (s.checks_expected || []).length],
           ['by source', JSON.stringify(s.by_source || {})],
           ['by severity', JSON.stringify(s.by_severity || {})],
           ['artifacts', (a.artifacts || []).length]].map(([k, v]) =>
          `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join('')}
      </div>
      <div class="row-actions">
        <button class="btn sm" id="rd-findings">VIEW FINDINGS</button>
        <button class="btn sm" id="rd-report">OPEN REPORT</button>
      </div>
      <div id="rd-list" style="margin-top:12px"></div>`;
    $('#rd-findings').addEventListener('click', () => { switchView('findings'); $('#f-run').value = id; loadFindings(id); });
    $('#rd-report').addEventListener('click', () => { switchView('reports'); $('#r-run').value = id; previewReport(); });
    const list = $('#rd-list');
    list.innerHTML = (a.findings || []).length
      ? (a.findings || []).map(findingCard).join('')
      : '<div class="empty">No findings recorded for this assessment.</div>';
    $('#run-detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  $('#btn-refresh-runs').addEventListener('click', () => loadRuns().catch(e => toast(e.message, 'err')));

  /* ------------------------------------------------------------- findings -- */
  async function prepFindings() { await loadRuns(); if (!$('#f-run').value && S.lastAssessment) $('#f-run').value = S.lastAssessment; }
  async function loadFindings(id) {
    id = id || $('#f-run').value;
    if (!id) return toast('Select an assessment', 'err');
    const r = await WD.findings(id);
    const sev = $('#f-sev').value;
    const rows = (r.findings || []).filter(f => !sev || f.severity === sev);
    $('#findings-scope').textContent = rows.length + ' finding(s) · ' + id.slice(0, 8);
    $('#findings-list').innerHTML = rows.length
      ? rows.map(findingCard).join('')
      : '<div class="card"><div class="empty">No findings for this filter.</div></div>';
  }
  $('#btn-load-findings').addEventListener('click', () => loadFindings().catch(e => toast(e.message, 'err')));
  $('#f-sev').addEventListener('change', () => loadFindings().catch(e => toast(e.message, 'err')));

  /* -------------------------------------------------------------- reports -- */
  async function prepReports() { await loadRuns(); if (!$('#r-run').value && S.lastAssessment) $('#r-run').value = S.lastAssessment; }
  async function previewReport() {
    const id = $('#r-run').value;
    if (!id) return toast('Select an assessment', 'err');
    const fmt = $('#r-fmt').value === 'pdf' ? 'md' : $('#r-fmt').value;
    const lang = $('#r-lang').value;
    const res = await fetch(WD.reportUrl(id, fmt, lang), {
      headers: { authorization: 'Bearer ' + WD.token() },
    });
    const text = await res.text();
    if (!res.ok) return toast('Report failed: ' + text.slice(0, 200), 'err');
    $('#report-preview').textContent = text;
    gateMsg('#report-msg', 'Preview generated (' + fmt.toUpperCase() + '/' + lang.toUpperCase() + '), ' + text.length + ' chars.', true);
  }
  $('#btn-report').addEventListener('click', async () => {
    try {
      const id = $('#r-run').value;
      if (!id) return toast('Select an assessment', 'err');
      const fmt = $('#r-fmt').value, lang = $('#r-lang').value;
      const res = await fetch(WD.reportUrl(id, fmt, lang), { headers: { authorization: 'Bearer ' + WD.token() } });
      if (!res.ok) throw new Error('report failed: ' + (await res.text()).slice(0, 200));
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      gateMsg('#report-msg', fmt.toUpperCase() + ' / ' + lang.toUpperCase() + ' generated (' + blob.size + ' bytes).', true);
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#btn-report-save').addEventListener('click', async () => {
    try {
      const id = $('#r-run').value;
      if (!id) return toast('Select an assessment', 'err');
      const res = await WD.call('/api/assessments/' + id + '/report/save?fmt=' + $('#r-fmt').value + '&lang=' + $('#r-lang').value, { method: 'POST' });
      gateMsg('#report-msg', 'Saved to ' + res.path + ' (' + res.size + ' bytes)', true);
      toast('Report saved to disk', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
  $('#r-run').addEventListener('change', () => previewReport().catch(() => {}));

  /* ---------------------------------------------------------------- audit -- */
  async function loadAudit() {
    const r = await WD.audit(150);
    table($('#audit-list'), [
      { label: 'seq', key: 'seq' },
      { label: 'ts', get: e => fmtTs(e.ts) },
      { label: 'actor', key: 'actor' },
      { label: 'action', key: 'action', mono: true },
      { label: 'target', get: e => (e.target || '–').slice(0, 42) },
      { label: 'hash', get: e => `<code>${esc((e.hash || '').slice(0, 14))}…</code>`, html: true },
    ], r.events || [], { empty: 'No audit events.' });
  }
  async function verifyAudit() {
    const v = await WD.auditVerify();
    kv($('#audit-verify'), [
      ['chain valid', v.valid ? 'YES' : 'NO — TAMPERED'],
      ['events', v.events == null ? '–' : v.events],
      ['head hash', v.head || '–'],
      ['broken at', v.broken_at == null ? '–' : v.broken_at],
      ['reason', v.reason || '–'],
    ]);
    toast(v.valid ? 'Audit chain verified' : 'AUDIT CHAIN BROKEN at seq ' + v.broken_at, v.valid ? 'ok' : 'err');
  }
  $('#btn-audit-verify').addEventListener('click', () => verifyAudit().catch(e => toast(e.message, 'err')));

  /* ----------------------------------------------------------------- caps -- */
  async function loadCaps() {
    try { S.caps = await WD.caps(); } catch { S.caps = null; }
  }
  function renderCaps() {
    const c = S.caps;
    if (!c) return;
    const cli = Object.entries(c.cli_tools || {})
      .map(([name, v]) => ({ name, present: v.present, version: v.version, path: v.path }))
      .sort((a, b) => (b.present ? 1 : 0) - (a.present ? 1 : 0) || a.name.localeCompare(b.name));
    table($('#caps-cli'), [
      { label: 'tool', key: 'name', mono: true },
      { label: 'present', get: r => r.present
          ? '<span style="color:#22c55e">yes</span>'
          : '<span style="color:#ef4444">missing</span>', html: true },
      { label: 'version / path', get: r => (r.version || r.path || '–').slice(0, 58) },
    ], cli, { empty: 'No CLI tools detected.' });
    const py = Object.entries(c.python_modules || {});
    table($('#caps-py'), [
      { label: 'module', key: 'name' },
      { label: 'present', get: r => r.present ? `<span style="color:#22c55e">yes</span>` : `<span style="color:#ef4444">missing</span>`, html: true },
      { label: 'package', key: 'pkg' },
      { label: 'version', get: r => (r.version || '–').slice(0, 30) },
    ], py.map(([k, v]) => ({ name: k, pkg: v.package, present: v.present, version: v.version })), { empty: 'None.' });
    $('#caps-host').textContent = JSON.stringify({
      host: c.host, interfaces: c.interfaces, can: c.can, usb: c.usb, raw_socket: c.raw_socket,
    }, null, 2);
  }
  $('#btn-refresh-caps').addEventListener('click', async () => { await loadCaps(); renderCaps(); toast('Capabilities re-detected', 'ok'); });

  /* ---------------------------------------------------------- integrations -- */
  async function initIntegrations() {
    const [cat, st] = await Promise.all([WD.integrations(), WD.integrationsStatus()]);
    const status = st.status || {};
    $('#int-grid').innerHTML = (cat.integrations || []).map(i => {
      const s = status[i.id] || {};
      const ok = !!s.available;
      const detail = ok
        ? (s.version ? esc(String(s.version).slice(0, 60)) : (s.base_url || s.dir || 'ready'))
        : esc(s.reason || 'not probed');
      return `<div class="card module-card">
        <div class="modid">${esc(i.id.toUpperCase())}</div>
        <h3 style="margin:6px 0">${esc(i.name)}</h3>
        <div class="muted small">${esc(i.role)}</div>
        <div class="chips">
          <span class="chip">${esc(i.license)}</span>
          <span class="chip">${esc(i.revision.slice(0, 10))}</span>
          <span class="chip">${ok ? 'AVAILABLE' : 'NOT AVAILABLE'}</span>
        </div>
        <div class="muted small" style="margin-top:8px">${detail}</div>
        <div class="muted small" style="margin-top:6px">
          <a href="${esc(i.upstream)}" target="_blank" rel="noopener">${esc(i.upstream)}</a>
        </div>
      </div>`;
    }).join('') || '<div class="empty">No integrations registered.</div>';

    // vendored templates table
    const nt = (cat.integrations || []).find(i => i.id === 'nuclei_templates');
    const tstatus = status['nuclei_templates'] || {};
    $('#int-templates').innerHTML = nt && tstatus.available
      ? `<div class="muted small">${tstatus.count} template(s) in <code>${esc(tstatus.dir || '')}</code> `
        + `— upstream ${esc(nt.upstream)} (${esc(nt.license)})</div>`
      : '<div class="empty">Vendored nuclei templates not found.</div>';
  }

  async function katanaCrawl() {
    const url = $('#int-crawl-url').value.trim();
    if (!url) return toast('Enter a URL to crawl', 'err');
    const msg = $('#int-crawl-msg');
    msg.className = 'gate-msg';
    msg.textContent = 'Crawling ' + url + ' …';
    const btn = $('#int-crawl-go');
    btn.disabled = true;
    try {
      const r = await WD.katanaCrawl(url, $('#int-crawl-depth').value, $('#int-crawl-secs').value);
      const rows = (r.endpoints || []).map(e => ({ ...e }));
      UI.table($('#int-crawl-out'), [
        { label: 'method', key: 'method' },
        { label: 'url', key: 'url', mono: true },
        { label: 'source', get: e => e.source || '–' },
        { label: 'status', get: e => e.status == null ? '–' : e.status },
      ], rows, { empty: 'Crawl returned no endpoints.' });
      msg.className = 'gate-msg ok';
      msg.textContent = 'katana found ' + r.count + ' endpoint(s) in depth ' + r.depth + ' (rc=' + r.returncode + ').';
    } catch (e) {
      msg.className = 'gate-msg';
      msg.textContent = e.message;
    } finally { btn.disabled = false; }
  }

  $('#int-reload').addEventListener('click', () => initIntegrations().catch(e => toast(e.message, 'err')));
  $('#int-crawl-go').addEventListener('click', () => katanaCrawl());

  /* ---------------------------------------------------------------- artax -- */
  const AX = { ready: false, mode: '', history: [] };

  async function initArtax() {
    try {
      const st = await WD.artaxStatus();
      AX.mode = st.mode;
      const label = st.mode === 'endpoint'
        ? 'MODEL · ' + (st.model || 'endpoint')
        : (st.mode === 'local' ? 'LOCAL ANALYST (no model endpoint)' : 'DISABLED');
      UI.badge($('#artax-mode'), label, st.mode === 'disabled' ? 'stop' : '');
      $('#artax-hint').innerHTML = st.mode === 'endpoint'
        ? 'Model-backed reasoning via the configured endpoint — answers are grounded in recorded evidence only.'
        : 'No model endpoint configured: Artax runs a <strong>deterministic evidence-only analyst</strong> '
          + '(not an LLM). Set <code>WD_ARTAX_BASE_URL</code> to enable model-backed reasoning.';
    } catch (e) {
      UI.badge($('#artax-mode'), 'unavailable', 'stop');
    }
    await loadRuns();
    const opts = ['<option value="">platform (no assessment)</option>']
      .concat(S.runs.map(a => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.status)})</option>`));
    $('#artax-run').innerHTML = opts.join('');
    if (S.lastAssessment) $('#artax-run').value = S.lastAssessment;
    AX.ready = true;
  }

  function artaxRender() {
    const el = $('#artax-thread');
    if (!AX.history.length) {
      el.innerHTML = '<div class="empty">No questions yet. Pick an assessment and ask Artax.</div>';
      return;
    }
    el.innerHTML = AX.history.map(m => {
      const who = m.role === 'user' ? 'OPERATOR' : 'ARTAX';
      const meta = m.role === 'assistant' && m.parser
        ? `<span class="pill src ${m.parser === 'endpoint' ? '' : 'lab'}">${esc(m.parser)}</span>` : '';
      return `<div class="ax-msg ${m.role}">
        <div class="ax-who">${who} ${meta}</div>
        <div class="ax-body">${esc(m.content)}</div>
      </div>`;
    }).join('');
    el.scrollTop = el.scrollHeight;
  }

  function artaxPush(role, content, parser) {
    AX.history.push({ role, content, parser });
    artaxRender();
  }

  async function artaxAsk() {
    const q = $('#artax-q').value.trim();
    if (!q) return toast('Type a question first', 'err');
    const id = $('#artax-run').value || null;
    const scope = id ? 'auto' : 'platform';
    artaxPush('user', q);
    $('#artax-q').value = '';
    const btn = $('#artax-ask');
    btn.disabled = true;
    const msg = $('#artax-msg');
    msg.className = 'gate-msg';
    msg.textContent = 'Artax is analysing the recorded evidence…';
    try {
      const r = await WD.artaxAsk(q, id, scope,
        AX.history.slice(-9).map(m => ({ role: m.role, content: m.content })));
      artaxPush('assistant', r.answer, r.parser);
      msg.className = 'gate-msg ok';
      msg.textContent = 'Answered in ' + r.mode + ' mode (' + r.parser + '), scope: ' + r.scope + '.';
    } catch (e) {
      msg.className = 'gate-msg';
      msg.textContent = e.message;
      toast(e.message, 'err');
    } finally { btn.disabled = false; }
  }

  async function artaxRunPreset() {
    const preset = $('#artax-preset').value;
    if (!preset) return;
    const id = $('#artax-run').value || null;
    artaxPush('user', 'preset: ' + preset);
    const msg = $('#artax-msg');
    msg.className = 'gate-msg';
    msg.textContent = 'Running preset…';
    try {
      const r = await WD.artaxPreset(preset, id);
      artaxPush('assistant', r.answer, r.parser);
      msg.className = 'gate-msg ok';
      msg.textContent = 'Preset ' + preset + ' answered (' + r.parser + ', scope: ' + r.scope + ').';
    } catch (e) {
      msg.className = 'gate-msg';
      msg.textContent = e.message;
    } finally { $('#artax-preset').value = ''; }
  }

  $('#artax-ask').addEventListener('click', () => artaxAsk());
  $('#artax-preset').addEventListener('change', () => artaxRunPreset());
  $('#artax-clear').addEventListener('click', () => {
    AX.history = []; artaxRender();
    $('#artax-msg').textContent = '';
  });
  $('#artax-reload').addEventListener('click', () => initArtax().catch(e => toast(e.message, 'err')));
  $('#artax-q').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); artaxAsk(); }
  });

  /* -------------------------------------------------------- stop / logout -- */
  /* ------------------------------------------------------------ account -- */
  function renderAccount() {
    const u = (S.me && S.me.user) || {};
    $('#acct-who').textContent = (u.username || '') + (u.role ? ' · ' + u.role : '') +
      (u.must_change_password ? ' · rotation pending' : '');
    $('#acct-rotate-warning').style.display = u.must_change_password ? '' : 'none';
    $('#pw-msg').textContent = '';
    $('#pin-msg').textContent = '';
  }

  async function refreshMe() {
    S.me = await WD.me();
    $('.badge').classList.remove('hidden');
    return S.me;
  }

  $('#btn-account').addEventListener('click', () => switchView('account'));

  $('#pw-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const msg = $('#pw-msg');
    const oldPw = $('#pw-old').value, a = $('#pw-new').value, b = $('#pw-new2').value;
    if (a !== b) { msg.textContent = 'New passwords do not match.'; msg.className = 'gate-msg err'; return; }
    if (a.length < 12) { msg.textContent = 'Minimum 12 characters.'; msg.className = 'gate-msg err'; return; }
    try {
      await WD.changePassword(oldPw, a);
      $('#pw-old').value = $('#pw-new').value = $('#pw-new2').value = '';
      msg.textContent = 'Password updated. Authorizing and execution are now unlocked.';
      msg.className = 'gate-msg ok';
      toast('Password updated', 'ok');
      await refreshMe();
      renderAccount();
    } catch (e) {
      msg.textContent = e.message; msg.className = 'gate-msg err';
    }
  });

  $('#pin-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const msg = $('#pin-msg');
    try {
      await WD.changePin($('#pin-pass').value, $('#pin-new').value);
      $('#pin-pass').value = $('#pin-new').value = '';
      msg.textContent = 'Stage-2 PIN updated.';
      msg.className = 'gate-msg ok';
      toast('PIN updated', 'ok');
    } catch (e) {
      msg.textContent = e.message; msg.className = 'gate-msg err';
    }
  });

    $('#btn-stop-all').addEventListener('click', async () => {
    if (!confirm('EMERGENCY STOP will abort running assessments, kill managed subprocesses, revoke authorizations and require fresh authentication. Continue?')) return;
    try {
      const r = await WD.stop('operator pressed emergency stop');
      stopBadge(true);
      toast('Emergency stop active: ' + r.jobs_aborted + ' job(s), ' + r.assessments_aborted + ' assessment(s) aborted', 'ok');
      await refreshAll().catch(() => {});
    } catch (e) { toast(e.message, 'err'); }
  });

  $('#btn-logout').addEventListener('click', async () => {
    try { await WD.logout(); } catch {}
    WD.setToken('');
    clearInterval(S.pollTimer);
    location.reload();
  });

  /* ------------------------------------------------------------- bootstrap -- */
  async function boot() {
    const h = await fetch('/api/health').then(r => r.json()).catch(() => null);
    $('#gate-health').textContent = h
      ? `${h.instance} v${h.version} · ${((h.engines && h.engines.registered) || []).length} engines · db ok`
      : 'platform unreachable';
    if (WD.token()) {
      try {
        const me = await WD.me();
        WD.state.stage = me.stage; WD.state.user = me.user;
        if (me.stage >= 2) { stopBadge(!!(me.emergency_stop && me.emergency_stop.active)); return enterShell(); }
        if (me.stage === 1) {
          $('#stage1-form').classList.add('hidden');
          $('#stage2-form').classList.remove('hidden');
          return;
        }
      } catch { WD.setToken(''); }
    }
  }

  // expose for the emergency-stop clear button in the console if needed
  window.WDNEO = { WD, S, refreshAll, switchView };
  boot();
})();
