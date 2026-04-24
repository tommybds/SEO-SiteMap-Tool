// Accessibility audit: labels, recommendations, renderer (with hero score).

const localizeAccessibilityCheckLabel = buildLabelLookup({
  a11y_http_status_2xx: 'a11y_http_status_2xx',
  a11y_html_lang_present: 'a11y_html_lang_present',
  a11y_title_present: 'a11y_title_present',
  a11y_viewport_present: 'a11y_viewport_present',
  a11y_main_landmark: 'a11y_main_landmark',
  a11y_skip_link: 'a11y_skip_link',
  a11y_image_alt_coverage: 'a11y_image_alt_coverage',
  a11y_form_labels: 'a11y_form_labels',
  a11y_button_names: 'a11y_button_names',
  a11y_link_names: 'a11y_link_names',
  a11y_iframe_titles: 'a11y_iframe_titles',
  a11y_accessibility_page: 'a11y_accessibility_page',
  a11y_accessibility_statement: 'a11y_accessibility_statement',
  a11y_accessibility_plan: 'a11y_accessibility_plan',
  a11y_accessibility_multiyear: 'a11y_accessibility_multiyear',
  a11y_accessibility_status_mention: 'a11y_accessibility_status_mention',
});

const localizeAccessibilityRecommendation = buildLabelLookup({
  a11y_reco_fix_http_status: 'a11y_reco_fix_http_status',
  a11y_reco_add_lang: 'a11y_reco_add_lang',
  a11y_reco_add_title: 'a11y_reco_add_title',
  a11y_reco_add_main_landmark: 'a11y_reco_add_main_landmark',
  a11y_reco_add_skip_link: 'a11y_reco_add_skip_link',
  a11y_reco_fix_image_alts: 'a11y_reco_fix_image_alts',
  a11y_reco_fix_form_labels: 'a11y_reco_fix_form_labels',
  a11y_reco_fix_button_names: 'a11y_reco_fix_button_names',
  a11y_reco_fix_link_names: 'a11y_reco_fix_link_names',
  a11y_reco_fix_iframe_titles: 'a11y_reco_fix_iframe_titles',
  a11y_reco_publish_accessibility_page: 'a11y_reco_publish_accessibility_page',
  a11y_reco_publish_statement: 'a11y_reco_publish_statement',
  a11y_reco_publish_multiyear: 'a11y_reco_publish_multiyear',
  a11y_reco_publish_plan: 'a11y_reco_publish_plan',
  a11y_reco_add_status_mention: 'a11y_reco_add_status_mention',
});

function renderAccessibility(audit) {
  if (!hasAccessibilityMode) return;
  latestAccessibilityPayload = audit;
  accessibilityCard.style.display = currentMode === 'accessibility' ? 'block' : 'none';

  const statusCode = Number(audit.status_code || 0);
  const responseMs = Number(audit.response_time_ms || 0);
  const finalUrl = String(audit.final_url || '');
  const requestedUrl = String(audit.url || '');
  const contentType = String(audit.content_type || '-');
  const redirects = Number(audit.redirect_count || 0);
  const score = Number(audit.score || 0);
  const counts = audit && audit.counts ? audit.counts : {};
  const checks = Array.isArray(audit.checks) ? audit.checks : [];
  const recommendations = Array.isArray(audit.recommendations) ? audit.recommendations : [];
  const checklist = audit && typeof audit.checklist === 'object' ? audit.checklist : {};
  const metrics = audit && typeof audit.metrics === 'object' ? audit.metrics : {};
  const referenceStandard = String(metrics.reference_standard || 'rgaa4').toLowerCase() === 'rgaa5' ? 'rgaa5' : 'rgaa4';
  const referenceStandardLabel = referenceStandard === 'rgaa5' ? t('accessibility_standard_rgaa5') : t('accessibility_standard_rgaa4');
  const imageTotal = Number(metrics.image_total || 0);
  const imageMissingAlt = Number(metrics.image_missing_alt || 0);
  const formControlTotal = Number(metrics.form_control_total || 0);
  const unlabeledFormControls = Number(metrics.unlabeled_form_controls || 0);
  const linkTotal = Number(metrics.link_total || 0);
  const unnamedLinks = Number(metrics.unnamed_links || 0);
  const accessibilitySignals = Number(metrics.accessibility_signals || 0);

  renderAuditMetaGrid(accessibilityStatusBox, [
    { label: t('accessibility_status_url'), value: requestedUrl },
    { label: t('accessibility_status_final_url'), value: finalUrl },
    { label: t('accessibility_status_standard'), value: referenceStandardLabel },
    { label: t('accessibility_status_http'), value: String(statusCode) },
    { label: t('accessibility_status_response_time'), value: `${responseMs} ms` },
    { label: t('accessibility_status_content_type'), value: contentType },
    { label: t('accessibility_status_redirects'), value: String(redirects) },
  ]);

  const scoreValue = Math.max(0, Math.min(100, score));
  const scoreTier = scoreValue >= 80 ? 'good' : scoreValue >= 50 ? 'warn' : 'bad';
  const passCount = Number(counts.pass || 0);
  const warnCount = Number(counts.warn || 0);
  const failCount = Number(counts.fail || 0);

  const signalsRows = [
    { label: t('accessibility_kpi_images_without_alt'), value: `${imageMissingAlt}/${imageTotal}` },
    { label: t('accessibility_kpi_unlabeled_controls'), value: `${unlabeledFormControls}/${formControlTotal}` },
    { label: t('accessibility_kpi_unnamed_links'), value: `${unnamedLinks}/${linkTotal}` },
    { label: t('accessibility_kpi_legal_signals'), value: String(accessibilitySignals) },
  ].map((entry) => `
    <div class="a11y-signal-card">
      <b>${escapeHtml(entry.value)}</b>
      <span>${escapeHtml(entry.label)}</span>
    </div>
  `).join('');

  accessibilityKpis.className = 'a11y-metrics';
  accessibilityKpis.innerHTML = `
    <div class="a11y-score-card ${scoreTier}">
      <div class="a11y-score-headline">
        <span class="a11y-score-label">${escapeHtml(t('accessibility_kpi_score'))}</span>
        <div class="a11y-score-value-row">
          <span class="a11y-score-value">${escapeHtml(String(scoreValue))}</span>
          <span class="a11y-score-suffix">/ 100</span>
        </div>
      </div>
      <div class="a11y-score-breakdown">
        <span class="a11y-pill pass"><b>${passCount}</b> ${escapeHtml(t('accessibility_kpi_pass'))}</span>
        <span class="a11y-pill warn"><b>${warnCount}</b> ${escapeHtml(t('accessibility_kpi_warn'))}</span>
        <span class="a11y-pill fail"><b>${failCount}</b> ${escapeHtml(t('accessibility_kpi_fail'))}</span>
      </div>
    </div>
    <div class="a11y-signals-block">
      <div class="a11y-signals-title">${escapeHtml(t('accessibility_signals_title'))}</div>
      <div class="a11y-signals-grid">${signalsRows}</div>
    </div>
  `;

  renderAuditChecksTable(accessibilityChecks, checks, {
    prefix: 'accessibility',
    localizeLabel: localizeAccessibilityCheckLabel,
    emptyKey: 'accessibility_checks_empty',
    titleKey: 'accessibility_checks_title',
  });

  const referenceStandardDetail = referenceStandard === 'rgaa5'
    ? t('accessibility_detail_reference_standard_value_rgaa5')
    : t('accessibility_detail_reference_standard_value');
  const automationWarning = referenceStandard === 'rgaa5'
    ? t('accessibility_automation_warning_rgaa5')
    : t('accessibility_automation_warning');

  const detailsRows = [
    `<div><strong>${escapeHtml(t('accessibility_detail_reference_standard'))}</strong><br>${escapeHtml(referenceStandardDetail)}</div>`,
    `<div><strong>${escapeHtml(t('accessibility_detail_legal_scope'))}</strong><br>${escapeHtml(t('accessibility_detail_legal_scope_value'))}</div>`,
    `<div><strong>${escapeHtml(t('accessibility_detail_required_publication'))}</strong><br>${escapeHtml(t('accessibility_detail_required_publication_value'))}</div>`,
  ].join('');

  accessibilityRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('accessibility_recos_title'))}</div>
    <div class="muted" style="margin-bottom:10px;">${escapeHtml(automationWarning)}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeAccessibilityRecommendation, 'accessibility')}
    <div class="tech-details-grid">${detailsRows}</div>
  `;
  renderActionPlan();
}
