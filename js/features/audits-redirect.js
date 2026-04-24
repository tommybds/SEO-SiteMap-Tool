// Redirect audit: chain visualization, scoring, renderer.

const localizeRedirectCheckLabel = buildLabelLookup({
  redirect_check_final_2xx: 'redirect_check_final_2xx',
  redirect_check_hop_count: 'redirect_check_hop_count',
  redirect_check_final_https: 'redirect_check_final_https',
  redirect_check_chain_https: 'redirect_check_chain_https',
  redirect_check_temporary_hops: 'redirect_check_temporary_hops',
  redirect_check_has_redirect: 'redirect_check_has_redirect',
  redirect_check_primary_redirect: 'redirect_check_primary_redirect',
});

const localizeRedirectRecommendation = buildLabelLookup({
  redirect_reco_fix_final_status: 'redirect_reco_fix_final_status',
  redirect_reco_reduce_hops: 'redirect_reco_reduce_hops',
  redirect_reco_enforce_https: 'redirect_reco_enforce_https',
  redirect_reco_use_301: 'redirect_reco_use_301',
});

function buildRedirectChainHtml(chain) {
  const rows = Array.isArray(chain) ? chain : [];
  if (!rows.length) return `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`;
  return rows.slice(0, 12).map((step, index) => {
    const url = String(step.url || '');
    const status = Number(step.status || 0);
    const nextStep = rows[index + 1] || null;
    const nextUrl = String(nextStep && nextStep.url ? nextStep.url : '').trim();
    const locationPart = nextUrl ? ` → ${buildFullUrlLink(nextUrl)}` : '';
    return `${index + 1}. ${buildFullUrlLink(url)} · ${escapeHtml(String(status || '-'))}${locationPart}`;
  }).join('<br>');
}

function formatPrimaryRedirect(code) {
  const statusCode = Number(code || 0);
  if (!statusCode) return t('redirect_primary_none');
  if (statusCode === 301 || statusCode === 308) {
    return `${statusCode} (${t('redirect_primary_permanent')})`;
  }
  if (statusCode === 302 || statusCode === 307) {
    return `${statusCode} (${t('redirect_primary_temporary')})`;
  }
  return String(statusCode);
}

function localizeRedirectStepTitle(statusCode, isFinalStep) {
  const code = Number(statusCode || 0);
  if (code === 301 || code === 308) return t('redirect_step_permanent', { code });
  if (code === 302 || code === 303 || code === 307) return t('redirect_step_temporary', { code });
  if (code >= 200 && code < 300 && isFinalStep) return t('redirect_step_direct', { code });
  if (code >= 200 && code < 300) return t('redirect_step_ok', { code });
  if (code >= 400) return t('redirect_step_error', { code });
  return t('redirect_step_status', { code: code || '-' });
}

function redirectStepTone(statusCode, isFinalStep) {
  const code = Number(statusCode || 0);
  if (code === 301 || code === 308) return 'permanent';
  if (code === 302 || code === 303 || code === 307) return 'temporary';
  if (code >= 200 && code < 300 && isFinalStep) return 'success';
  if (code >= 400) return 'error';
  return 'neutral';
}

function buildRedirectHeadline(primaryRedirectCode, statusCode, redirectCount) {
  const primary = Number(primaryRedirectCode || 0);
  if (primary === 301 || primary === 308) {
    return t('redirect_headline_permanent', { code: primary });
  }
  if (primary === 302 || primary === 303 || primary === 307) {
    return t('redirect_headline_temporary', { code: primary });
  }
  if (Number(redirectCount || 0) === 0 && statusCode >= 200 && statusCode < 300) {
    return t('redirect_headline_direct', { code: statusCode });
  }
  return t('redirect_headline_generic');
}

function buildRedirectFlowHtml(chain) {
  const rows = Array.isArray(chain) ? chain : [];
  if (!rows.length) {
    return `<div class="mesh-actions-empty">${escapeHtml(t('redirect_flow_empty'))}</div>`;
  }

  return rows.slice(0, 12).map((step, index, arr) => {
    const isFinalStep = index === arr.length - 1;
    const currentUrl = String(step && step.url ? step.url : '');
    const statusCode = Number(step && step.status ? step.status : 0);
    const statusLabel = localizeRedirectStepTitle(statusCode, isFinalStep);
    const tone = redirectStepTone(statusCode, isFinalStep);
    const nextStep = !isFinalStep ? arr[index + 1] : null;
    const nextUrl = String(nextStep && nextStep.url ? nextStep.url : '');

    return `
      <article class="redirect-flow-step">
        <div class="redirect-flow-row">
          <div class="redirect-flow-url">${buildFullUrlLink(currentUrl)}</div>
          <div class="redirect-flow-status">
            <span class="redirect-http-badge ${escapeHtml(tone)}">${escapeHtml(String(statusCode || '-'))}</span>
            <span class="redirect-flow-label">${escapeHtml(statusLabel)}</span>
          </div>
        </div>
        ${nextUrl ? `<div class="redirect-flow-next"><span>${escapeHtml(t('redirect_flow_to'))}:</span> ${buildFullUrlLink(nextUrl)}</div>` : ''}
      </article>
      ${isFinalStep ? '' : '<div class="redirect-flow-arrow" aria-hidden="true">↓</div>'}
    `;
  }).join('');
}

function computeRedirectChecks(ctx) {
  const checks = [];
  const push = (key, status, value) => checks.push({ key, status, value });
  push('redirect_check_final_2xx', (ctx.statusCode >= 200 && ctx.statusCode < 300) ? 'pass' : 'fail', String(ctx.statusCode));
  push(
    'redirect_check_hop_count',
    ctx.redirectCount <= 1 ? 'pass' : (ctx.redirectCount <= 2 ? 'warn' : 'fail'),
    String(ctx.redirectCount),
  );
  push('redirect_check_final_https', ctx.finalHttps ? 'pass' : 'fail', ctx.finalHttps ? 'https' : 'http');
  push('redirect_check_chain_https', ctx.chainHttpsOnly ? 'pass' : 'fail', ctx.chainHttpsOnly ? t('opt_yes') : t('opt_no'));
  push(
    'redirect_check_temporary_hops',
    ctx.temporaryHopCount === 0 ? 'pass' : 'warn',
    String(ctx.temporaryHopCount),
  );
  push(
    'redirect_check_has_redirect',
    ctx.redirectCount >= 1 ? 'pass' : 'warn',
    ctx.redirectCount >= 1 ? t('opt_yes') : t('opt_no'),
  );
  push(
    'redirect_check_primary_redirect',
    (ctx.primaryRedirectCode === 301 || ctx.primaryRedirectCode === 308) ? 'pass' : 'warn',
    ctx.primaryRedirectLabel,
  );
  return checks;
}

const REDIRECT_WEIGHTS = {
  redirect_check_final_2xx: 25,
  redirect_check_hop_count: 25,
  redirect_check_final_https: 20,
  redirect_check_chain_https: 20,
  redirect_check_temporary_hops: 5,
  redirect_check_has_redirect: 5,
};
const REDIRECT_STATUS_FACTOR = { pass: 1, warn: 0.5, fail: 0 };

function computeRedirectScore(checks) {
  let scoreRaw = 0;
  checks.forEach((check) => {
    const weight = Number(REDIRECT_WEIGHTS[String(check.key || '')] || 0);
    const factor = Number(REDIRECT_STATUS_FACTOR[String(check.status || 'warn').toLowerCase()] ?? 0.5);
    scoreRaw += weight * factor;
  });
  return Math.max(0, Math.min(100, Math.round(scoreRaw)));
}

function computeRedirectRecommendations(ctx) {
  const recos = [];
  const push = (key) => { if (!recos.includes(key)) recos.push(key); };
  if (!(ctx.statusCode >= 200 && ctx.statusCode < 300)) push('redirect_reco_fix_final_status');
  if (ctx.redirectCount > 1) push('redirect_reco_reduce_hops');
  if (!ctx.finalHttps || !ctx.chainHttpsOnly) push('redirect_reco_enforce_https');
  if (ctx.temporaryHopCount > 0) push('redirect_reco_use_301');
  return recos;
}

function renderRedirect(audit) {
  if (!hasRedirectMode) return;
  latestRedirectPayload = audit;
  redirectCard.style.display = currentMode === 'redirect' ? 'block' : 'none';

  const statusCode = Number(audit.status_code || 0);
  const responseMs = Number(audit.response_time_ms || 0);
  const finalUrl = String(audit.final_url || '');
  const requestedUrl = String(audit.url || '');
  const contentType = String(audit.content_type || '-');
  const redirectCount = Number(audit.redirect_count || 0);
  const redirectChain = Array.isArray(audit.redirect_chain) ? audit.redirect_chain : [];
  const finalHttps = finalUrl.toLowerCase().startsWith('https://');
  const chainHttpsOnly = redirectChain.every((step) => !!step && !!step.https);
  const primaryRedirectStep = redirectChain.find((step) => {
    const code = Number(step && step.status ? step.status : 0);
    return code >= 300 && code < 400;
  }) || null;
  const primaryRedirectCode = Number(primaryRedirectStep && primaryRedirectStep.status ? primaryRedirectStep.status : 0);
  const primaryRedirectLabel = formatPrimaryRedirect(primaryRedirectCode);
  const temporaryHopCount = redirectChain.slice(0, -1).filter((step) => {
    const code = Number(step && step.status ? step.status : 0);
    return code === 302 || code === 307;
  }).length;

  const ctx = {
    statusCode, redirectCount, finalHttps, chainHttpsOnly,
    temporaryHopCount, primaryRedirectCode, primaryRedirectLabel,
  };
  const checks = computeRedirectChecks(ctx);
  const score = computeRedirectScore(checks);
  const recommendations = computeRedirectRecommendations(ctx);

  if (redirectFlow) {
    redirectFlow.innerHTML = `
      <div class="redirect-flow-head">
        <strong>${escapeHtml(buildRedirectHeadline(primaryRedirectCode, statusCode, redirectCount))}</strong>
        <span>${escapeHtml(t('redirect_flow_summary', { hops: redirectCount, final_status: statusCode }))}</span>
      </div>
      <div class="redirect-flow-chain">${buildRedirectFlowHtml(redirectChain)}</div>
    `;
  }

  renderAuditMetaGrid(redirectStatusBox, [
    { label: t('redirect_status_url'), value: requestedUrl },
    { label: t('redirect_status_final_url'), value: finalUrl },
    { label: t('redirect_status_primary_redirect'), value: primaryRedirectLabel },
    { label: t('redirect_status_http'), value: String(statusCode) },
    { label: t('redirect_status_response_time'), value: `${responseMs} ms` },
    { label: t('redirect_status_content_type'), value: contentType },
    { label: t('redirect_status_redirects'), value: String(redirectCount) },
  ]);

  renderAuditKpis(redirectKpis, [
    { label: t('redirect_kpi_score'), value: score },
    { label: t('redirect_kpi_hops'), value: redirectCount },
    { label: t('redirect_kpi_primary_redirect'), value: primaryRedirectLabel },
    { label: t('redirect_kpi_final_status'), value: statusCode || 0 },
    { label: t('redirect_kpi_final_https'), value: finalHttps ? t('opt_yes') : t('opt_no') },
    { label: t('redirect_kpi_chain_https'), value: chainHttpsOnly ? t('opt_yes') : t('opt_no') },
    { label: t('redirect_kpi_temporary_hops'), value: temporaryHopCount },
  ]);

  renderAuditChecksTable(redirectChecks, checks, {
    prefix: 'redirect',
    localizeLabel: localizeRedirectCheckLabel,
    emptyKey: 'redirect_checks_empty',
    titleKey: 'redirect_checks_title',
  });

  const recosHtml = recommendations.length
    ? `<ul class="tech-recos-list">${recommendations.map((key) => `<li>${escapeHtml(localizeRedirectRecommendation(key))}</li>`).join('')}</ul>`
    : `<div class="mesh-actions-empty">${escapeHtml(t('redirect_recos_empty'))}</div>`;

  redirectRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('redirect_recos_title'))}</div>
    ${recosHtml}
    <div class="tech-details-grid">
      <div><strong>${escapeHtml(t('redirect_detail_chain'))}</strong><br>${buildRedirectChainHtml(redirectChain)}</div>
      <div><strong>${escapeHtml(t('redirect_detail_chain_https'))}</strong><br>${chainHttpsOnly ? escapeHtml(t('opt_yes')) : escapeHtml(t('opt_no'))}</div>
      <div><strong>${escapeHtml(t('redirect_detail_temporary_hops'))}</strong><br>${escapeHtml(String(temporaryHopCount))}</div>
    </div>
  `;
  renderActionPlan();
}
