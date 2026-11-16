/* API client — thin, typed-ish wrapper over the WD NEO REST API. */
const WD = (() => {
  const KEY = 'wd_neo_token';
  const state = { token: localStorage.getItem(KEY) || '', stage: 0, user: null };

  function setToken(t) {
    state.token = t || '';
    if (t) localStorage.setItem(KEY, t); else localStorage.removeItem(KEY);
  }

  async function call(path, opts = {}) {
    const o = { method: opts.method || 'GET', headers: {} };
    if (state.token) o.headers['authorization'] = 'Bearer ' + state.token;
    if (opts.body !== undefined) {
      o.headers['content-type'] = 'application/json';
      o.body = JSON.stringify(opts.body);
    }
    const res = await fetch(path, o);
    const ctype = res.headers.get('content-type') || '';
    let payload = null;
    if (ctype.includes('application/json')) {
      payload = await res.json().catch(() => null);
    } else {
      payload = await res.text();
    }
    if (!res.ok) {
      const d = payload && payload.detail;
      let msg = typeof d === 'string' ? d : (d && (d.message || d.code)) || res.statusText;
      if (Array.isArray(d)) msg = d.map(x => x.msg || JSON.stringify(x)).join('; ');
      const err = new Error(msg || ('HTTP ' + res.status));
      err.status = res.status;
      err.payload = payload;
      throw err;
    }
    return payload;
  }

  return {
    state, setToken, call,
    token: () => state.token,
    stage1: (username, password, shortcut) => call('/api/auth/stage1', { method: 'POST', body: { username, password, shortcut } }),
    stage2: (pin) => call('/api/auth/stage2', { method: 'POST', body: { pin } }),
    me: () => call('/api/auth/me'),
    logout: () => call('/api/auth/logout', { method: 'POST' }),
    health: () => call('/api/health'),
    caps: () => call('/api/capabilities'),
    modules: () => call('/api/modules'),
    stats: () => call('/api/stats'),
    scope: () => call('/api/scope'),
    addScope: (target, description) => call('/api/scope', { method: 'POST', body: { target, description } }),
    delScope: (id) => call('/api/scope/' + id, { method: 'DELETE' }),
    validate: (targets) => call('/api/scope/validate', { method: 'POST', body: { targets } }),
    templates: () => call('/api/templates'),
    authorize: (targets, ttl, note) => call('/api/authorizations', { method: 'POST', body: { targets, ttl_minutes: ttl, note, intended_test: note } }),
    createAssessment: (b) => call('/api/assessments', { method: 'POST', body: b }),
    assessments: () => call('/api/assessments'),
    assessment: (id) => call('/api/assessments/' + id),
    run: (id, authz) => call('/api/assessments/' + id + '/run', { method: 'POST', body: { authz_id: authz, confirm: true } }),
    job: (id) => call('/api/jobs/' + id),
    findings: (id) => call('/api/assessments/' + id + '/findings'),
    audit: (limit) => call('/api/audit?limit=' + (limit || 200)),
    auditVerify: () => call('/api/audit/verify'),
    stopState: () => call('/api/emergency-stop'),
    stop: (reason) => call('/api/emergency-stop', { method: 'POST', body: { reason: reason || 'operator emergency stop' } }),
    clearStop: () => call('/api/emergency-stop/clear', { method: 'POST' }),
    reportUrl: (id, fmt, lang) => '/api/assessments/' + id + '/report?fmt=' + fmt + '&lang=' + lang,
    artaxStatus: () => call('/api/artax/status'),
    artaxAsk: (question, assessmentId, scope, history) => call('/api/artax/ask', {
      method: 'POST',
      body: { question, assessment_id: assessmentId || null, scope: scope || 'auto', history: history || [] },
    }),
    integrations: () => call('/api/integrations'),
    integrationsStatus: () => call('/api/integrations/status'),
    katanaCrawl: (url, depth, secs) => call('/api/integrations/katana/crawl', {
      method: 'POST', body: { url, depth: Number(depth), duration_s: Number(secs) } }),
    artaxPreset: (presetId, assessmentId) => call('/api/artax/preset/' + presetId +
      (assessmentId ? '?assessment_id=' + encodeURIComponent(assessmentId) : ''), { method: 'POST' }),
  };
})();
