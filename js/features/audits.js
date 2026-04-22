// Auto-split from app.js
function localizeTechCheckLabel(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeTechRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
        align_indexability_signals: 'tech_reco_align_indexability_signals',
        add_open_graph: 'tech_reco_add_open_graph',
        fix_og_image: 'tech_reco_fix_og_image',
        add_twitter_tags: 'tech_reco_add_twitter_tags',
        add_twitter_image: 'tech_reco_add_twitter_image',
        add_jsonld: 'tech_reco_add_jsonld',
        fix_jsonld_validity: 'tech_reco_fix_jsonld_validity',
        add_jsonld_type: 'tech_reco_add_jsonld_type',
        add_x_default_hreflang: 'tech_reco_add_x_default_hreflang',
        add_viewport: 'tech_reco_add_viewport',
        publish_robots_txt: 'tech_reco_publish_robots_txt',
        improve_internal_links: 'tech_reco_improve_internal_links',
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeTechCheckStatus(status) {
      const safe = String(status || '').trim().toLowerCase();
      if (safe === 'pass') return t('tech_status_pass');
      if (safe === 'fail') return t('tech_status_fail');
      return t('tech_status_warn');
    }

    function buildTechRedirectChainHtml(chain) {
      const rows = Array.isArray(chain) ? chain : [];
      if (!rows.length) return `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`;
      return rows.slice(0, 8).map((step, index) => {
        const url = String(step.url || '');
        const status = Number(step.status || 0);
        const prefix = `${index + 1}. `;
        return `${prefix}${buildMeshUrlLink(url)} · ${escapeHtml(String(status || '-'))}`;
      }).join('<br>');
    }

    function renderTechChecklist(checklist, recommendations) {
      const buckets = checklist && typeof checklist === 'object' ? checklist : {};
      const high = Array.isArray(buckets.high) ? buckets.high : [];
      const medium = Array.isArray(buckets.medium) ? buckets.medium : [];
      const low = Array.isArray(buckets.low) ? buckets.low : [];
      const fallback = Array.isArray(recommendations) ? recommendations : [];

      if (!high.length && !medium.length && !low.length) {
        if (!fallback.length) {
          return `<div class="mesh-actions-empty">${escapeHtml(t('tech_recos_empty'))}</div>`;
        }
        const items = fallback.map((key) => `<li>${escapeHtml(localizeTechRecommendation(key))}</li>`).join('');
        return `<ul class="tech-recos-list">${items}</ul>`;
      }

      const renderBucket = (title, keys, className) => {
        if (!keys.length) return '';
        const items = keys.map((key) => `<li>${escapeHtml(localizeTechRecommendation(key))}</li>`).join('');
        return `
          <div class="tech-checklist-block ${className}">
            <div class="tech-checklist-title">${escapeHtml(title)}</div>
            <ul class="tech-recos-list">${items}</ul>
          </div>
        `;
      };

      return `
        <div class="tech-checklist-grid">
          ${renderBucket(t('tech_recos_priority_high'), high, 'high')}
          ${renderBucket(t('tech_recos_priority_medium'), medium, 'medium')}
          ${renderBucket(t('tech_recos_priority_low'), low, 'low')}
        </div>
      `;
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

      techStatusBox.textContent = [
        `${t('tech_status_url')}: ${requestedUrl}`,
        `${t('tech_status_final_url')}: ${finalUrl}`,
        `${t('tech_status_http')}: ${statusCode}`,
        `${t('tech_status_response_time')}: ${responseMs} ms`,
        `${t('tech_status_content_type')}: ${contentType}`,
        `${t('tech_status_redirects')}: ${redirects}`,
      ].join('\n');

      techKpis.innerHTML = '';
      [
        { label: t('tech_kpi_score'), value: String(score) },
        { label: t('tech_kpi_pass'), value: String(Number(counts.pass || 0)) },
        { label: t('tech_kpi_warn'), value: String(Number(counts.warn || 0)) },
        { label: t('tech_kpi_fail'), value: String(Number(counts.fail || 0)) },
        { label: t('tech_kpi_indexable'), value: indexable ? t('opt_yes') : t('opt_no') },
        { label: t('tech_kpi_redirect_hops'), value: String(redirects) },
        { label: t('tech_kpi_conflict'), value: effectiveConflict ? t('opt_yes') : t('opt_no') },
      ].forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'tech-kpi';
        card.innerHTML = `<b>${escapeHtml(entry.value)}</b><span>${escapeHtml(entry.label)}</span>`;
        techKpis.appendChild(card);
      });

      if (!checks.length) {
        techChecks.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('tech_checks_empty'))}</div>`;
      } else {
        const rows = checks.map((check) => {
          const status = String(check.status || 'warn').toLowerCase();
          const value = String(check.value || '-');
          const label = localizeTechCheckLabel(check.key);
          const statusLabel = localizeTechCheckStatus(status);
          return `
            <tr>
              <td>${escapeHtml(label)}</td>
              <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
              <td>${escapeHtml(value)}</td>
            </tr>
          `;
        }).join('');

        techChecks.innerHTML = `
          <div class="tech-checks-head">${escapeHtml(t('tech_checks_title'))}</div>
          <div class="tech-checks-table-wrap">
            <table class="tech-checks-table">
              <thead>
                <tr>
                  <th>${escapeHtml(t('tech_col_check'))}</th>
                  <th>${escapeHtml(t('tech_col_status'))}</th>
                  <th>${escapeHtml(t('tech_col_value'))}</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        `;
      }

      const detailsRows = [
        `<div><strong>${escapeHtml(t('tech_detail_redirect_chain'))}</strong><br>${buildTechRedirectChainHtml(redirectChain)}</div>`,
        `<div><strong>${escapeHtml(t('tech_detail_canonical_target'))}</strong><br>${canonicalTarget && canonicalTarget.present && canonicalTarget.url ? `${buildMeshUrlLink(canonicalTarget.url)} · ${escapeHtml(String(canonicalTargetStatus || '-'))} · ${escapeHtml(canonicalTargetIndexable)}` : `<span class="muted">-</span>`}</div>`,
        `<div><strong>${escapeHtml(t('tech_detail_jsonld_types'))}</strong><br>${jsonLdTypes.length ? escapeHtml(jsonLdTypes.slice(0, 8).join(', ')) : `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`}</div>`,
      ].join('');
      techRecos.innerHTML = `
        <div class="tech-recos-head">${escapeHtml(t('tech_recos_title'))}</div>
        ${renderTechChecklist(checklist, recommendations)}
        <div class="tech-details-grid">${detailsRows}</div>
      `;
      renderActionPlan();
    }

    function localizeRedirectCheckLabel(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
        redirect_check_final_2xx: 'redirect_check_final_2xx',
        redirect_check_hop_count: 'redirect_check_hop_count',
        redirect_check_final_https: 'redirect_check_final_https',
        redirect_check_chain_https: 'redirect_check_chain_https',
        redirect_check_temporary_hops: 'redirect_check_temporary_hops',
        redirect_check_has_redirect: 'redirect_check_has_redirect',
        redirect_check_primary_redirect: 'redirect_check_primary_redirect',
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeRedirectRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
        redirect_reco_fix_final_status: 'redirect_reco_fix_final_status',
        redirect_reco_reduce_hops: 'redirect_reco_reduce_hops',
        redirect_reco_enforce_https: 'redirect_reco_enforce_https',
        redirect_reco_use_301: 'redirect_reco_use_301',
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeRedirectCheckStatus(status) {
      const safe = String(status || '').trim().toLowerCase();
      if (safe === 'pass') return t('redirect_status_pass');
      if (safe === 'fail') return t('redirect_status_fail');
      return t('redirect_status_warn');
    }

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

      const checks = [];
      const addCheck = (key, status, value) => checks.push({ key, status, value });
      addCheck('redirect_check_final_2xx', (statusCode >= 200 && statusCode < 300) ? 'pass' : 'fail', String(statusCode));
      addCheck(
        'redirect_check_hop_count',
        redirectCount <= 1 ? 'pass' : (redirectCount <= 2 ? 'warn' : 'fail'),
        String(redirectCount)
      );
      addCheck('redirect_check_final_https', finalHttps ? 'pass' : 'fail', finalHttps ? 'https' : 'http');
      addCheck('redirect_check_chain_https', chainHttpsOnly ? 'pass' : 'fail', chainHttpsOnly ? t('opt_yes') : t('opt_no'));
      addCheck(
        'redirect_check_temporary_hops',
        temporaryHopCount === 0 ? 'pass' : 'warn',
        String(temporaryHopCount)
      );
      addCheck(
        'redirect_check_has_redirect',
        redirectCount >= 1 ? 'pass' : 'warn',
        redirectCount >= 1 ? t('opt_yes') : t('opt_no')
      );
      addCheck(
        'redirect_check_primary_redirect',
        (primaryRedirectCode === 301 || primaryRedirectCode === 308) ? 'pass' : 'warn',
        primaryRedirectLabel
      );

      const counts = { pass: 0, warn: 0, fail: 0 };
      checks.forEach((check) => {
        const safe = String(check.status || 'warn').toLowerCase();
        if (safe === 'pass' || safe === 'warn' || safe === 'fail') counts[safe]++;
      });
      const weights = {
        redirect_check_final_2xx: 25,
        redirect_check_hop_count: 25,
        redirect_check_final_https: 20,
        redirect_check_chain_https: 20,
        redirect_check_temporary_hops: 5,
        redirect_check_has_redirect: 5,
      };
      const factor = { pass: 1, warn: 0.5, fail: 0 };
      let scoreRaw = 0;
      checks.forEach((check) => {
        const key = String(check.key || '');
        const status = String(check.status || 'warn').toLowerCase();
        scoreRaw += Number(weights[key] || 0) * Number(factor[status] ?? 0.5);
      });
      const score = Math.max(0, Math.min(100, Math.round(scoreRaw)));

      const recommendations = [];
      const pushReco = (key) => {
        if (!recommendations.includes(key)) recommendations.push(key);
      };
      if (!(statusCode >= 200 && statusCode < 300)) pushReco('redirect_reco_fix_final_status');
      if (redirectCount > 1) pushReco('redirect_reco_reduce_hops');
      if (!finalHttps || !chainHttpsOnly) pushReco('redirect_reco_enforce_https');
      if (temporaryHopCount > 0) pushReco('redirect_reco_use_301');

      if (redirectFlow) {
        redirectFlow.innerHTML = `
          <div class="redirect-flow-head">
            <strong>${escapeHtml(buildRedirectHeadline(primaryRedirectCode, statusCode, redirectCount))}</strong>
            <span>${escapeHtml(t('redirect_flow_summary', { hops: redirectCount, final_status: statusCode }))}</span>
          </div>
          <div class="redirect-flow-chain">${buildRedirectFlowHtml(redirectChain)}</div>
        `;
      }

      redirectStatusBox.textContent = [
        `${t('redirect_status_url')}: ${requestedUrl}`,
        `${t('redirect_status_final_url')}: ${finalUrl}`,
        `${t('redirect_status_primary_redirect')}: ${primaryRedirectLabel}`,
        `${t('redirect_status_http')}: ${statusCode}`,
        `${t('redirect_status_response_time')}: ${responseMs} ms`,
        `${t('redirect_status_content_type')}: ${contentType}`,
        `${t('redirect_status_redirects')}: ${redirectCount}`,
      ].join('\n');

      redirectKpis.innerHTML = '';
      [
        { label: t('redirect_kpi_score'), value: String(score) },
        { label: t('redirect_kpi_hops'), value: String(redirectCount) },
        { label: t('redirect_kpi_primary_redirect'), value: primaryRedirectLabel },
        { label: t('redirect_kpi_final_status'), value: String(statusCode || 0) },
        { label: t('redirect_kpi_final_https'), value: finalHttps ? t('opt_yes') : t('opt_no') },
        { label: t('redirect_kpi_chain_https'), value: chainHttpsOnly ? t('opt_yes') : t('opt_no') },
        { label: t('redirect_kpi_temporary_hops'), value: String(temporaryHopCount) },
      ].forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'tech-kpi';
        card.innerHTML = `<b>${escapeHtml(entry.value)}</b><span>${escapeHtml(entry.label)}</span>`;
        redirectKpis.appendChild(card);
      });

      if (!checks.length) {
        redirectChecks.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('redirect_checks_empty'))}</div>`;
      } else {
        const rows = checks.map((check) => {
          const status = String(check.status || 'warn').toLowerCase();
          const value = String(check.value || '-');
          const label = localizeRedirectCheckLabel(check.key);
          const statusLabel = localizeRedirectCheckStatus(status);
          return `
            <tr>
              <td>${escapeHtml(label)}</td>
              <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
              <td>${escapeHtml(value)}</td>
            </tr>
          `;
        }).join('');
        redirectChecks.innerHTML = `
          <div class="tech-checks-head">${escapeHtml(t('redirect_checks_title'))}</div>
          <div class="tech-checks-table-wrap">
            <table class="tech-checks-table">
              <thead>
                <tr>
                  <th>${escapeHtml(t('redirect_col_check'))}</th>
                  <th>${escapeHtml(t('redirect_col_status'))}</th>
                  <th>${escapeHtml(t('redirect_col_value'))}</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        `;
      }

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

    function localizeGeoCheckLabel(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeGeoRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeGeoCheckStatus(status) {
      const safe = String(status || '').trim().toLowerCase();
      if (safe === 'pass') return t('geo_status_pass');
      if (safe === 'fail') return t('geo_status_fail');
      return t('geo_status_warn');
    }

    function renderGeoChecklist(checklist, recommendations) {
      const buckets = checklist && typeof checklist === 'object' ? checklist : {};
      const high = Array.isArray(buckets.high) ? buckets.high : [];
      const medium = Array.isArray(buckets.medium) ? buckets.medium : [];
      const low = Array.isArray(buckets.low) ? buckets.low : [];
      const fallback = Array.isArray(recommendations) ? recommendations : [];

      if (!high.length && !medium.length && !low.length) {
        if (!fallback.length) {
          return `<div class="mesh-actions-empty">${escapeHtml(t('geo_recos_empty'))}</div>`;
        }
        const items = fallback.map((key) => `<li>${escapeHtml(localizeGeoRecommendation(key))}</li>`).join('');
        return `<ul class="tech-recos-list">${items}</ul>`;
      }

      const renderBucket = (title, keys, className) => {
        if (!keys.length) return '';
        const items = keys.map((key) => `<li>${escapeHtml(localizeGeoCheckLabel(key))}</li>`).join('');
        return `
          <div class="tech-checklist-block ${className}">
            <div class="tech-checklist-title">${escapeHtml(title)}</div>
            <ul class="tech-recos-list">${items}</ul>
          </div>
        `;
      };

      return `
        <div class="tech-checklist-grid">
          ${renderBucket(t('geo_recos_priority_high'), high, 'high')}
          ${renderBucket(t('geo_recos_priority_medium'), medium, 'medium')}
          ${renderBucket(t('geo_recos_priority_low'), low, 'low')}
        </div>
      `;
    }

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

      geoStatusBox.textContent = [
        `${t('geo_status_url')}: ${requestedUrl}`,
        `${t('geo_status_final_url')}: ${finalUrl}`,
        `${t('geo_status_http')}: ${statusCode}`,
        `${t('geo_status_response_time')}: ${responseMs} ms`,
        `${t('geo_status_content_type')}: ${contentType}`,
        `${t('geo_status_redirects')}: ${redirects}`,
      ].join('\n');

      geoKpis.innerHTML = '';
      [
        { label: t('geo_kpi_score'), value: String(score) },
        { label: t('geo_kpi_pass'), value: String(Number(counts.pass || 0)) },
        { label: t('geo_kpi_warn'), value: String(Number(counts.warn || 0)) },
        { label: t('geo_kpi_fail'), value: String(Number(counts.fail || 0)) },
        { label: t('geo_kpi_indexable'), value: indexable ? t('opt_yes') : t('opt_no') },
        { label: t('geo_kpi_freshness'), value: freshnessText },
      ].forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'tech-kpi';
        card.innerHTML = `<b>${escapeHtml(entry.value)}</b><span>${escapeHtml(entry.label)}</span>`;
        geoKpis.appendChild(card);
      });

      if (!checks.length) {
        geoChecks.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('geo_checks_empty'))}</div>`;
      } else {
        const rows = checks.map((check) => {
          const status = String(check.status || 'warn').toLowerCase();
          const value = String(check.value || '-');
          const label = localizeGeoCheckLabel(check.key);
          const statusLabel = localizeGeoCheckStatus(status);
          return `
            <tr>
              <td>${escapeHtml(label)}</td>
              <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
              <td>${escapeHtml(value)}</td>
            </tr>
          `;
        }).join('');

        geoChecks.innerHTML = `
          <div class="tech-checks-head">${escapeHtml(t('geo_checks_title'))}</div>
          <div class="tech-checks-table-wrap">
            <table class="tech-checks-table">
              <thead>
                <tr>
                  <th>${escapeHtml(t('geo_col_check'))}</th>
                  <th>${escapeHtml(t('geo_col_status'))}</th>
                  <th>${escapeHtml(t('geo_col_value'))}</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        `;
      }

      const datesValue = [publishedDate, modifiedDate].filter(Boolean).join(' / ');
      const detailsRows = [
        `<div><strong>${escapeHtml(t('geo_detail_structured_types'))}</strong><br>${structuredTypes.length ? escapeHtml(structuredTypes.slice(0, 8).join(', ')) : `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`}</div>`,
        `<div><strong>${escapeHtml(t('geo_detail_dates'))}</strong><br>${datesValue ? escapeHtml(datesValue) : `<span class="muted">-</span>`}</div>`,
        `<div><strong>${escapeHtml(t('geo_detail_freshness'))}</strong><br>${escapeHtml(freshnessText)}</div>`,
      ].join('');

      geoRecos.innerHTML = `
        <div class="tech-recos-head">${escapeHtml(t('geo_recos_title'))}</div>
        ${renderGeoChecklist(checklist, recommendations)}
        <div class="tech-details-grid">${detailsRows}</div>
      `;
      renderActionPlan();
    }

    function localizeAccessibilityCheckLabel(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeAccessibilityRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      const map = {
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
      };
      const i18nKey = map[safe];
      return i18nKey ? t(i18nKey) : safe;
    }

    function localizeAccessibilityCheckStatus(status) {
      const safe = String(status || '').trim().toLowerCase();
      if (safe === 'pass') return t('accessibility_status_pass');
      if (safe === 'fail') return t('accessibility_status_fail');
      return t('accessibility_status_warn');
    }

    function renderAccessibilityChecklist(checklist, recommendations) {
      const buckets = checklist && typeof checklist === 'object' ? checklist : {};
      const high = Array.isArray(buckets.high) ? buckets.high : [];
      const medium = Array.isArray(buckets.medium) ? buckets.medium : [];
      const low = Array.isArray(buckets.low) ? buckets.low : [];
      const fallback = Array.isArray(recommendations) ? recommendations : [];

      if (!high.length && !medium.length && !low.length) {
        if (!fallback.length) {
          return `<div class="mesh-actions-empty">${escapeHtml(t('accessibility_recos_empty'))}</div>`;
        }
        const items = fallback.map((key) => `<li>${escapeHtml(localizeAccessibilityRecommendation(key))}</li>`).join('');
        return `<ul class="tech-recos-list">${items}</ul>`;
      }

      const renderBucket = (title, keys, className) => {
        if (!keys.length) return '';
        const items = keys.map((key) => `<li>${escapeHtml(localizeAccessibilityRecommendation(key))}</li>`).join('');
        return `
          <div class="tech-checklist-block ${className}">
            <div class="tech-checklist-title">${escapeHtml(title)}</div>
            <ul class="tech-recos-list">${items}</ul>
          </div>
        `;
      };

      return `
        <div class="tech-checklist-grid">
          ${renderBucket(t('accessibility_recos_priority_high'), high, 'high')}
          ${renderBucket(t('accessibility_recos_priority_medium'), medium, 'medium')}
          ${renderBucket(t('accessibility_recos_priority_low'), low, 'low')}
        </div>
      `;
    }

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

      accessibilityStatusBox.textContent = [
        `${t('accessibility_status_url')}: ${requestedUrl}`,
        `${t('accessibility_status_final_url')}: ${finalUrl}`,
        `${t('accessibility_status_standard')}: ${referenceStandardLabel}`,
        `${t('accessibility_status_http')}: ${statusCode}`,
        `${t('accessibility_status_response_time')}: ${responseMs} ms`,
        `${t('accessibility_status_content_type')}: ${contentType}`,
        `${t('accessibility_status_redirects')}: ${redirects}`,
      ].join('\n');

      accessibilityKpis.innerHTML = '';
      [
        { label: t('accessibility_kpi_score'), value: String(score) },
        { label: t('accessibility_kpi_pass'), value: String(Number(counts.pass || 0)) },
        { label: t('accessibility_kpi_warn'), value: String(Number(counts.warn || 0)) },
        { label: t('accessibility_kpi_fail'), value: String(Number(counts.fail || 0)) },
        { label: t('accessibility_kpi_images_without_alt'), value: `${imageMissingAlt}/${imageTotal}` },
        { label: t('accessibility_kpi_unlabeled_controls'), value: `${unlabeledFormControls}/${formControlTotal}` },
        { label: t('accessibility_kpi_unnamed_links'), value: `${unnamedLinks}/${linkTotal}` },
        { label: t('accessibility_kpi_legal_signals'), value: String(accessibilitySignals) },
      ].forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'tech-kpi';
        card.innerHTML = `<b>${escapeHtml(entry.value)}</b><span>${escapeHtml(entry.label)}</span>`;
        accessibilityKpis.appendChild(card);
      });

      if (!checks.length) {
        accessibilityChecks.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('accessibility_checks_empty'))}</div>`;
      } else {
        const rows = checks.map((check) => {
          const status = String(check.status || 'warn').toLowerCase();
          const value = String(check.value || '-');
          const label = localizeAccessibilityCheckLabel(check.key);
          const statusLabel = localizeAccessibilityCheckStatus(status);
          return `
            <tr>
              <td>${escapeHtml(label)}</td>
              <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
              <td>${escapeHtml(value)}</td>
            </tr>
          `;
        }).join('');

        accessibilityChecks.innerHTML = `
          <div class="tech-checks-head">${escapeHtml(t('accessibility_checks_title'))}</div>
          <div class="tech-checks-table-wrap">
            <table class="tech-checks-table">
              <thead>
                <tr>
                  <th>${escapeHtml(t('accessibility_col_check'))}</th>
                  <th>${escapeHtml(t('accessibility_col_status'))}</th>
                  <th>${escapeHtml(t('accessibility_col_value'))}</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        `;
      }

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
        ${renderAccessibilityChecklist(checklist, recommendations)}
        <div class="tech-details-grid">${detailsRows}</div>
      `;
      renderActionPlan();
    }

    async function runAccessibilityAudit(payload) {
      const res = await fetch('accessibility_audit.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await parseApiJsonResponse(res, 'accessibility_api_invalid_json', 'accessibility_api_bad_gateway');
      if (!res.ok) throw new Error(data.error || t('accessibility_api_error'));
      return data;
    }

async function runTechAudit(payload) {
      const res = await fetch('tech_audit.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await parseApiJsonResponse(res, 'tech_api_invalid_json', 'tech_api_bad_gateway');
      if (!res.ok) throw new Error(data.error || t('tech_api_error'));
      return data;
    }

    async function runRedirectAudit(payload) {
      const res = await fetch('tech_audit.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await parseApiJsonResponse(res, 'redirect_api_invalid_json', 'redirect_api_bad_gateway');
      if (!res.ok) throw new Error(data.error || t('redirect_api_error'));
      return data;
    }

    async function runGeoAudit(payload) {
      const res = await fetch('geo_audit.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await parseApiJsonResponse(res, 'geo_api_invalid_json', 'geo_api_bad_gateway');
      if (!res.ok) throw new Error(data.error || t('geo_api_error'));
      return data;
    }

    async function loadSharedMesh(meshId) {
      const res = await fetch(`mesh_result.php?mesh_id=${encodeURIComponent(meshId)}`, { cache: 'no-store' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || t('mesh_api_error'));
      return data;
    }
