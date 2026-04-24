// Shared helpers for audit renderers (tech, redirect, geo, accessibility).
// Removes duplicated status localization, checks table rendering, meta grid,
// priority checklist, and fetch endpoints that each audit used to reimplement.

function localizeAuditStatus(status, prefix) {
  const safe = String(status || '').trim().toLowerCase();
  if (safe === 'pass') return t(`${prefix}_status_pass`);
  if (safe === 'fail') return t(`${prefix}_status_fail`);
  return t(`${prefix}_status_warn`);
}

function renderAuditMetaGrid(container, rows) {
  if (!container) return;
  const body = rows.map(({ label, value }) => `
    <div class="audit-meta-row">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value || '-')}</dd>
    </div>
  `).join('');
  container.className = 'audit-meta';
  container.innerHTML = `<dl class="audit-meta-grid">${body}</dl>`;
}

function renderAuditKpis(container, entries) {
  if (!container) return;
  container.innerHTML = entries.map(({ label, value }) => `
    <div class="tech-kpi">
      <b>${escapeHtml(String(value))}</b>
      <span>${escapeHtml(label)}</span>
    </div>
  `).join('');
}

function renderAuditChecksTable(container, checks, opts) {
  if (!container) return;
  const { prefix, localizeLabel, emptyKey, titleKey } = opts;
  if (!checks.length) {
    container.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t(emptyKey))}</div>`;
    return;
  }
  const rows = checks.map((check) => {
    const status = String(check.status || 'warn').toLowerCase();
    const value = String(check.value || '-');
    const label = localizeLabel(check.key);
    const statusLabel = localizeAuditStatus(status, prefix);
    return `
      <tr>
        <td>${escapeHtml(label)}</td>
        <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
        <td>${escapeHtml(value)}</td>
      </tr>
    `;
  }).join('');
  container.innerHTML = `
    <div class="tech-checks-head">${escapeHtml(t(titleKey))}</div>
    <div class="tech-checks-table-wrap">
      <table class="tech-checks-table">
        <thead>
          <tr>
            <th>${escapeHtml(t(`${prefix}_col_check`))}</th>
            <th>${escapeHtml(t(`${prefix}_col_status`))}</th>
            <th>${escapeHtml(t(`${prefix}_col_value`))}</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderPriorityChecklist(checklist, recommendations, localizer, prefix) {
  const buckets = checklist && typeof checklist === 'object' ? checklist : {};
  const high = Array.isArray(buckets.high) ? buckets.high : [];
  const medium = Array.isArray(buckets.medium) ? buckets.medium : [];
  const low = Array.isArray(buckets.low) ? buckets.low : [];
  const fallback = Array.isArray(recommendations) ? recommendations : [];

  if (!high.length && !medium.length && !low.length) {
    if (!fallback.length) {
      return `<div class="mesh-actions-empty">${escapeHtml(t(`${prefix}_recos_empty`))}</div>`;
    }
    const items = fallback.map((key) => `<li>${escapeHtml(localizer(key))}</li>`).join('');
    return `<ul class="tech-recos-list">${items}</ul>`;
  }

  const renderBucket = (title, keys, className) => {
    if (!keys.length) return '';
    const items = keys.map((key) => `<li>${escapeHtml(localizer(key))}</li>`).join('');
    return `
      <div class="tech-checklist-block ${className}">
        <div class="tech-checklist-title">${escapeHtml(title)}</div>
        <ul class="tech-recos-list">${items}</ul>
      </div>
    `;
  };

  return `
    <div class="tech-checklist-grid">
      ${renderBucket(t(`${prefix}_recos_priority_high`), high, 'high')}
      ${renderBucket(t(`${prefix}_recos_priority_medium`), medium, 'medium')}
      ${renderBucket(t(`${prefix}_recos_priority_low`), low, 'low')}
    </div>
  `;
}

function buildLabelLookup(map) {
  return (key) => {
    const safe = String(key || '').trim().toLowerCase();
    const i18nKey = map[safe];
    return i18nKey ? t(i18nKey) : safe;
  };
}

async function runAuditEndpoint(url, payload, keys) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await parseApiJsonResponse(res, keys.invalidJson, keys.badGateway);
  if (!res.ok) throw new Error(data.error || t(keys.error));
  return data;
}

async function runTechAudit(payload) {
  return runAuditEndpoint('tech_audit.php', payload, {
    invalidJson: 'tech_api_invalid_json',
    badGateway: 'tech_api_bad_gateway',
    error: 'tech_api_error',
  });
}

async function runRedirectAudit(payload) {
  return runAuditEndpoint('tech_audit.php', payload, {
    invalidJson: 'redirect_api_invalid_json',
    badGateway: 'redirect_api_bad_gateway',
    error: 'redirect_api_error',
  });
}

async function runGeoAudit(payload) {
  return runAuditEndpoint('geo_audit.php', payload, {
    invalidJson: 'geo_api_invalid_json',
    badGateway: 'geo_api_bad_gateway',
    error: 'geo_api_error',
  });
}

async function runAccessibilityAudit(payload) {
  return runAuditEndpoint('accessibility_audit.php', payload, {
    invalidJson: 'accessibility_api_invalid_json',
    badGateway: 'accessibility_api_bad_gateway',
    error: 'accessibility_api_error',
  });
}

async function loadSharedMesh(meshId) {
  const res = await fetch(`mesh_result.php?mesh_id=${encodeURIComponent(meshId)}`, { cache: 'no-store' });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || t('mesh_api_error'));
  return data;
}
