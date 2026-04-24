// Security headers audit: labels, recommendations, renderer.

const localizeSecurityCheckLabel = buildLabelLookup({
  https: 'security_check_https',
  http_to_https_redirect: 'security_check_http_redirect',
  hsts: 'security_check_hsts',
  hsts_subdomains: 'security_check_hsts_subdomains',
  hsts_preload: 'security_check_hsts_preload',
  csp: 'security_check_csp',
  csp_no_unsafe: 'security_check_csp_unsafe',
  frame_protection: 'security_check_frame_protection',
  content_type_options: 'security_check_content_type_options',
  referrer_policy: 'security_check_referrer_policy',
  permissions_policy: 'security_check_permissions_policy',
  server_info_leak: 'security_check_server_leak',
  mixed_content: 'security_check_mixed_content',
  xss_protection_deprecated: 'security_check_xss_deprecated',
  cookies_secure: 'security_check_cookies',
});

const localizeSecurityRecommendation = buildLabelLookup({
  security_reco_https: 'security_reco_https',
  security_reco_http_redirect: 'security_reco_http_redirect',
  security_reco_hsts: 'security_reco_hsts',
  security_reco_hsts_subdomains: 'security_reco_hsts_subdomains',
  security_reco_hsts_preload: 'security_reco_hsts_preload',
  security_reco_csp: 'security_reco_csp',
  security_reco_csp_unsafe: 'security_reco_csp_unsafe',
  security_reco_frame_protection: 'security_reco_frame_protection',
  security_reco_content_type_options: 'security_reco_content_type_options',
  security_reco_referrer_policy: 'security_reco_referrer_policy',
  security_reco_permissions_policy: 'security_reco_permissions_policy',
  security_reco_server_leak: 'security_reco_server_leak',
  security_reco_mixed_content: 'security_reco_mixed_content',
  security_reco_xss_deprecated: 'security_reco_xss_deprecated',
  security_reco_cookies: 'security_reco_cookies',
});

async function runSecurityAudit(payload) {
  return runAuditEndpoint('security_audit.php', payload, {
    invalidJson: 'security_api_invalid_json',
    badGateway: 'security_api_bad_gateway',
    error: 'security_api_error',
  });
}

function renderSecurity(audit) {
  if (!hasSecurityMode) return;
  latestSecurityPayload = audit;
  securityCard.style.display = currentMode === 'security' ? 'block' : 'none';

  const statusCode = Number(audit.status_code || 0);
  const responseMs = Number(audit.response_time_ms || 0);
  const finalUrl = String(audit.final_url || '');
  const requestedUrl = String(audit.url || '');
  const redirects = Number(audit.redirect_count || 0);
  const score = Number(audit.score || 0);
  const kpis = audit && typeof audit.kpis === 'object' ? audit.kpis : {};
  const checks = Array.isArray(audit.checks) ? audit.checks : [];
  const recommendations = Array.isArray(audit.recommendations) ? audit.recommendations : [];
  const checklist = audit && typeof audit.checklist === 'object' ? audit.checklist : {};
  const metrics = audit && typeof audit.metrics === 'object' ? audit.metrics : {};
  const mixedUrls = Array.isArray(metrics.mixed_content_urls) ? metrics.mixed_content_urls : [];

  renderAuditMetaGrid(securityStatusBox, [
    { label: t('security_status_url'), value: requestedUrl },
    { label: t('security_status_final_url'), value: finalUrl },
    { label: t('security_status_http'), value: String(statusCode) },
    { label: t('security_status_response_time'), value: `${responseMs} ms` },
    { label: t('security_status_redirects'), value: String(redirects) },
  ]);

  renderAuditKpis(securityKpis, [
    { label: t('security_kpi_score'), value: score },
    { label: t('security_kpi_pass'), value: Number(kpis.checks_pass || 0) },
    { label: t('security_kpi_warn'), value: Number(kpis.checks_warn || 0) },
    { label: t('security_kpi_fail'), value: Number(kpis.checks_fail || 0) },
    { label: t('security_kpi_mixed'), value: Number(kpis.mixed_content_count || 0) },
  ]);

  renderAuditChecksTable(securityChecks, checks, {
    prefix: 'security',
    localizeLabel: localizeSecurityCheckLabel,
    emptyKey: 'security_checks_empty',
    titleKey: 'security_checks_title',
  });

  let extraDetails = '';
  if (mixedUrls.length > 0) {
    const urlItems = mixedUrls.slice(0, 10).map((u) => `<li><code>${escapeHtml(u)}</code></li>`).join('');
    extraDetails = `<div class="tech-details-grid"><div><strong>${escapeHtml(t('security_detail_mixed_urls'))}</strong><ul class="tech-recos-list">${urlItems}</ul></div></div>`;
  }

  securityRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('security_recos_title'))}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeSecurityRecommendation, 'security')}
    ${extraDetails}
  `;
  renderActionPlan();
}
