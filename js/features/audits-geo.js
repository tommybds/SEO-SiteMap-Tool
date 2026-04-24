// GEO audit: labels, recommendations, renderer.

const localizeGeoCheckLabel = buildLabelLookup({
  geo_http_status_2xx: 'geo_http_status_2xx',
  geo_html_content_type: 'geo_html_content_type',
  geo_indexable: 'geo_indexable',
  geo_structured_data: 'geo_structured_data',
  geo_organization_entity: 'geo_organization_entity',
  geo_author_signal: 'geo_author_signal',
  geo_date_metadata: 'geo_date_metadata',
  geo_freshness: 'geo_freshness',
  geo_qa_format: 'geo_qa_format',
  geo_faq_markup: 'geo_faq_markup',
  geo_content_depth: 'geo_content_depth',
  geo_internal_links: 'geo_internal_links',
  geo_citations_external: 'geo_citations_external',
  geo_list_table_blocks: 'geo_list_table_blocks',
});

const localizeGeoRecommendation = buildLabelLookup({
  geo_reco_add_structured_data: 'geo_reco_add_structured_data',
  geo_reco_add_organization_entity: 'geo_reco_add_organization_entity',
  geo_reco_add_author_signals: 'geo_reco_add_author_signals',
  geo_reco_add_dates: 'geo_reco_add_dates',
  geo_reco_refresh_content: 'geo_reco_refresh_content',
  geo_reco_improve_qa_format: 'geo_reco_improve_qa_format',
  geo_reco_add_faq_markup: 'geo_reco_add_faq_markup',
  geo_reco_deepen_content: 'geo_reco_deepen_content',
  geo_reco_improve_internal_links: 'geo_reco_improve_internal_links',
  geo_reco_add_external_citations: 'geo_reco_add_external_citations',
});

function renderGeo(audit) {
  if (!hasGeoMode) return;
  latestGeoPayload = audit;
  geoCard.style.display = currentMode === 'geo' ? 'block' : 'none';

  const statusCode = Number(audit.status_code || 0);
  const responseMs = Number(audit.response_time_ms || 0);
  const finalUrl = String(audit.final_url || '');
  const requestedUrl = String(audit.url || '');
  const contentType = String(audit.content_type || '-');
  const redirects = Number(audit.redirect_count || 0);
  const score = Number(audit.score || 0);
  const indexable = !!audit.indexable;
  const counts = audit && audit.counts ? audit.counts : {};
  const checks = Array.isArray(audit.checks) ? audit.checks : [];
  const recommendations = Array.isArray(audit.recommendations) ? audit.recommendations : [];
  const checklist = audit && typeof audit.checklist === 'object' ? audit.checklist : {};
  const metrics = audit && typeof audit.metrics === 'object' ? audit.metrics : {};
  const structuredTypes = Array.isArray(metrics.structured_types) ? metrics.structured_types : [];
  const publishedDate = String(metrics.published_date || '').trim();
  const modifiedDate = String(metrics.modified_date || '').trim();
  const freshnessRaw = metrics.freshness_days;
  const freshnessDays = freshnessRaw === null || typeof freshnessRaw === 'undefined' || String(freshnessRaw).trim() === ''
    ? null
    : Number(freshnessRaw);
  const freshnessText = Number.isFinite(freshnessDays)
    ? `${freshnessDays}d`
    : t('geo_detail_freshness_unknown');

  renderAuditMetaGrid(geoStatusBox, [
    { label: t('geo_status_url'), value: requestedUrl },
    { label: t('geo_status_final_url'), value: finalUrl },
    { label: t('geo_status_http'), value: String(statusCode) },
    { label: t('geo_status_response_time'), value: `${responseMs} ms` },
    { label: t('geo_status_content_type'), value: contentType },
    { label: t('geo_status_redirects'), value: String(redirects) },
  ]);

  renderAuditKpis(geoKpis, [
    { label: t('geo_kpi_score'), value: score },
    { label: t('geo_kpi_pass'), value: Number(counts.pass || 0) },
    { label: t('geo_kpi_warn'), value: Number(counts.warn || 0) },
    { label: t('geo_kpi_fail'), value: Number(counts.fail || 0) },
    { label: t('geo_kpi_indexable'), value: indexable ? t('opt_yes') : t('opt_no') },
    { label: t('geo_kpi_freshness'), value: freshnessText },
  ]);

  renderAuditChecksTable(geoChecks, checks, {
    prefix: 'geo',
    localizeLabel: localizeGeoCheckLabel,
    emptyKey: 'geo_checks_empty',
    titleKey: 'geo_checks_title',
  });

  const datesValue = [publishedDate, modifiedDate].filter(Boolean).join(' / ');
  const detailsRows = [
    `<div><strong>${escapeHtml(t('geo_detail_structured_types'))}</strong><br>${structuredTypes.length ? escapeHtml(structuredTypes.slice(0, 8).join(', ')) : `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_dates'))}</strong><br>${datesValue ? escapeHtml(datesValue) : `<span class="muted">-</span>`}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_freshness'))}</strong><br>${escapeHtml(freshnessText)}</div>`,
  ].join('');

  geoRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('geo_recos_title'))}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeGeoRecommendation, 'geo')}
    <div class="tech-details-grid">${detailsRows}</div>
  `;
  renderActionPlan();
}
