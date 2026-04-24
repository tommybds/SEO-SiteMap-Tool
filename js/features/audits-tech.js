// Tech audit: labels, recommendations, renderer.

const localizeTechCheckLabel = buildLabelLookup({
  http_status_200: 'tech_check_http_status_200',
  https: 'tech_check_https',
  redirect_chain_length: 'tech_check_redirect_chain_length',
  redirect_chain_https: 'tech_check_redirect_chain_https',
  html_content_type: 'tech_check_html_content_type',
  indexable: 'tech_check_indexable',
  effective_indexability_conflict: 'tech_check_effective_indexability_conflict',
  title_present: 'tech_check_title_present',
  title_length: 'tech_check_title_length',
  meta_description_present: 'tech_check_meta_description_present',
  meta_description_length: 'tech_check_meta_description_length',
  h1_single: 'tech_check_h1_single',
  canonical_present: 'tech_check_canonical_present',
  canonical_count_single: 'tech_check_canonical_count_single',
  canonical_self_domain: 'tech_check_canonical_self_domain',
  canonical_target_status: 'tech_check_canonical_target_status',
  canonical_target_indexable: 'tech_check_canonical_target_indexable',
  robots_meta_noindex: 'tech_check_robots_meta_noindex',
  x_robots_noindex: 'tech_check_x_robots_noindex',
  hreflang_consistency: 'tech_check_hreflang_consistency',
  og_core: 'tech_check_og_core',
  og_image_fetchable: 'tech_check_og_image_fetchable',
  twitter_core: 'tech_check_twitter_core',
  twitter_image_present: 'tech_check_twitter_image_present',
  jsonld_present: 'tech_check_jsonld_present',
  jsonld_valid: 'tech_check_jsonld_valid',
  jsonld_has_type: 'tech_check_jsonld_has_type',
  viewport_present: 'tech_check_viewport_present',
  internal_links_count: 'tech_check_internal_links_count',
  robots_txt_accessible: 'tech_check_robots_txt_accessible',
  robots_txt_blocks_url: 'tech_check_robots_txt_blocks_url',
});

const localizeTechRecommendation = buildLabelLookup({
  fix_http_status: 'tech_reco_fix_http_status',
  enforce_https: 'tech_reco_enforce_https',
  reduce_redirect_hops: 'tech_reco_reduce_redirect_hops',
  fix_redirect_chain_https: 'tech_reco_fix_redirect_chain_https',
  serve_html_content: 'tech_reco_serve_html_content',
  remove_noindex: 'tech_reco_remove_noindex',
  allow_in_robots: 'tech_reco_allow_in_robots',
  add_title: 'tech_reco_add_title',
  optimize_title_length: 'tech_reco_optimize_title_length',
  add_meta_description: 'tech_reco_add_meta_description',
  optimize_meta_description: 'tech_reco_optimize_meta_description',
  add_h1: 'tech_reco_add_h1',
  keep_single_h1: 'tech_reco_keep_single_h1',
  add_canonical: 'tech_reco_add_canonical',
  fix_canonical_domain: 'tech_reco_fix_canonical_domain',
  fix_canonical_target_status: 'tech_reco_fix_canonical_target_status',
  fix_canonical_target_indexability: 'tech_reco_fix_canonical_target_indexability',
  unify_canonical_single: 'tech_reco_unify_canonical_single',
  fix_hreflang_consistency: 'tech_reco_fix_hreflang_consistency',
  complete_open_graph: 'tech_reco_complete_open_graph',
  fix_og_image: 'tech_reco_fix_og_image',
  complete_twitter_card: 'tech_reco_complete_twitter_card',
  add_twitter_image: 'tech_reco_add_twitter_image',
  add_structured_data: 'tech_reco_add_structured_data',
  fix_jsonld_syntax: 'tech_reco_fix_jsonld_syntax',
  add_jsonld_type: 'tech_reco_add_jsonld_type',
  add_viewport: 'tech_reco_add_viewport',
  enrich_internal_links: 'tech_reco_enrich_internal_links',
  restore_robots_txt: 'tech_reco_restore_robots_txt',
  unblock_url_in_robots: 'tech_reco_unblock_url_in_robots',
});

function buildTechRedirectChainHtml(chain) {
  const rows = Array.isArray(chain) ? chain : [];
  if (!rows.length) return `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`;
  return rows.slice(0, 8).map((step, index) => {
    const url = String(step.url || '');
    const status = Number(step.status || 0);
    return `${index + 1}. ${buildMeshUrlLink(url)} · ${escapeHtml(String(status || '-'))}`;
  }).join('<br>');
}

function renderTech(audit) {
  if (!hasTechMode) return;
  latestTechPayload = audit;
  techCard.style.display = currentMode === 'tech' ? 'block' : 'none';

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
  const redirectChain = Array.isArray(audit.redirect_chain) ? audit.redirect_chain : [];
  const canonicalTarget = metrics && typeof metrics.canonical_target === 'object' ? metrics.canonical_target : {};
  const jsonLdTypes = Array.isArray(metrics.json_ld_types) ? metrics.json_ld_types : [];
  const canonicalTargetStatus = Number(canonicalTarget.status_code || 0);
  const canonicalTargetIndexable = canonicalTarget.present
    ? ((canonicalTarget.is_2xx && !canonicalTarget.noindex) ? t('opt_yes') : t('opt_no'))
    : '-';
  const effectiveConflict = !!metrics.effective_indexability_conflict;

  renderAuditMetaGrid(techStatusBox, [
    { label: t('tech_status_url'), value: requestedUrl },
    { label: t('tech_status_final_url'), value: finalUrl },
    { label: t('tech_status_http'), value: String(statusCode) },
    { label: t('tech_status_response_time'), value: `${responseMs} ms` },
    { label: t('tech_status_content_type'), value: contentType },
    { label: t('tech_status_redirects'), value: String(redirects) },
  ]);

  renderAuditKpis(techKpis, [
    { label: t('tech_kpi_score'), value: score },
    { label: t('tech_kpi_pass'), value: Number(counts.pass || 0) },
    { label: t('tech_kpi_warn'), value: Number(counts.warn || 0) },
    { label: t('tech_kpi_fail'), value: Number(counts.fail || 0) },
    { label: t('tech_kpi_indexable'), value: indexable ? t('opt_yes') : t('opt_no') },
    { label: t('tech_kpi_redirect_hops'), value: redirects },
    { label: t('tech_kpi_conflict'), value: effectiveConflict ? t('opt_yes') : t('opt_no') },
  ]);

  renderAuditChecksTable(techChecks, checks, {
    prefix: 'tech',
    localizeLabel: localizeTechCheckLabel,
    emptyKey: 'tech_checks_empty',
    titleKey: 'tech_checks_title',
  });

  const detailsRows = [
    `<div><strong>${escapeHtml(t('tech_detail_redirect_chain'))}</strong><br>${buildTechRedirectChainHtml(redirectChain)}</div>`,
    `<div><strong>${escapeHtml(t('tech_detail_canonical_target'))}</strong><br>${canonicalTarget && canonicalTarget.present && canonicalTarget.url ? `${buildMeshUrlLink(canonicalTarget.url)} · ${escapeHtml(String(canonicalTargetStatus || '-'))} · ${escapeHtml(canonicalTargetIndexable)}` : `<span class="muted">-</span>`}</div>`,
    `<div><strong>${escapeHtml(t('tech_detail_jsonld_types'))}</strong><br>${jsonLdTypes.length ? escapeHtml(jsonLdTypes.slice(0, 8).join(', ')) : `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`}</div>`,
  ].join('');

  techRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('tech_recos_title'))}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeTechRecommendation, 'tech')}
    <div class="tech-details-grid">${detailsRows}</div>
  `;
  renderActionPlan();
}
