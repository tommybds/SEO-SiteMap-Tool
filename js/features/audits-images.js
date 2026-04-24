// Images audit: labels, recommendations, renderer.

const localizeImagesCheckLabel = buildLabelLookup({
  img_presence: 'images_check_presence',
  img_alt_coverage: 'images_check_alt',
  img_dimensions: 'images_check_dimensions',
  img_lazy_loading: 'images_check_lazy',
  img_modern_format: 'images_check_modern_format',
  img_responsive: 'images_check_responsive',
});

const localizeImagesRecommendation = buildLabelLookup({
  images_reco_alt: 'images_reco_alt',
  images_reco_dimensions: 'images_reco_dimensions',
  images_reco_lazy: 'images_reco_lazy',
  images_reco_modern_format: 'images_reco_modern_format',
  images_reco_responsive: 'images_reco_responsive',
  images_reco_presence: 'images_reco_presence',
});

async function runImagesAudit(payload) {
  return runAuditEndpoint('images_audit.php', payload, {
    invalidJson: 'images_api_invalid_json',
    badGateway: 'images_api_bad_gateway',
    error: 'images_api_error',
  });
}

function renderImages(audit) {
  if (!hasImagesMode) return;
  latestImagesPayload = audit;
  imagesCard.style.display = currentMode === 'images' ? 'block' : 'none';

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
  const formats = metrics && typeof metrics.formats === 'object' ? metrics.formats : {};
  const sampleAlt = Array.isArray(metrics.sample_missing_alt) ? metrics.sample_missing_alt : [];
  const sampleDims = Array.isArray(metrics.sample_missing_dims) ? metrics.sample_missing_dims : [];

  renderAuditMetaGrid(imagesStatusBox, [
    { label: t('images_status_url'), value: requestedUrl },
    { label: t('images_status_final_url'), value: finalUrl },
    { label: t('images_status_http'), value: String(statusCode) },
    { label: t('images_status_response_time'), value: `${responseMs} ms` },
    { label: t('images_status_redirects'), value: String(redirects) },
  ]);

  renderAuditKpis(imagesKpis, [
    { label: t('images_kpi_score'), value: score },
    { label: t('images_kpi_total'), value: Number(kpis.total_images || 0) },
    { label: t('images_kpi_without_alt'), value: Number(kpis.without_alt || 0) },
    { label: t('images_kpi_without_dimensions'), value: Number(kpis.without_dimensions || 0) },
    { label: t('images_kpi_modern_format'), value: `${Number(kpis.modern_format_pct || 0)}%` },
  ]);

  renderAuditChecksTable(imagesChecks, checks, {
    prefix: 'images',
    localizeLabel: localizeImagesCheckLabel,
    emptyKey: 'images_checks_empty',
    titleKey: 'images_checks_title',
  });

  const formatRow = Object.entries(formats)
    .filter(([, v]) => Number(v) > 0)
    .map(([k, v]) => `<span class="tech-check-badge">${escapeHtml(k)}: ${escapeHtml(String(v))}</span>`)
    .join(' ');

  let extras = '';
  if (formatRow) {
    extras += `<div class="tech-details-grid"><div><strong>${escapeHtml(t('images_detail_formats'))}</strong><br>${formatRow}</div></div>`;
  }
  if (sampleAlt.length > 0) {
    const items = sampleAlt.slice(0, 5).map((u) => `<li><code>${escapeHtml(u || '(empty src)')}</code></li>`).join('');
    extras += `<div class="tech-details-grid"><div><strong>${escapeHtml(t('images_detail_sample_missing_alt'))}</strong><ul class="tech-recos-list">${items}</ul></div></div>`;
  }
  if (sampleDims.length > 0) {
    const items = sampleDims.slice(0, 5).map((u) => `<li><code>${escapeHtml(u || '(empty src)')}</code></li>`).join('');
    extras += `<div class="tech-details-grid"><div><strong>${escapeHtml(t('images_detail_sample_missing_dims'))}</strong><ul class="tech-recos-list">${items}</ul></div></div>`;
  }

  imagesRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('images_recos_title'))}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeImagesRecommendation, 'images')}
    ${extras}
  `;
  renderActionPlan();
}
