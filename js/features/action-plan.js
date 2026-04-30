// Auto-split from app.js
function normalizeActionPlanPriority(priority) {
      const raw = String(priority || '').trim().toLowerCase();
      if (raw === 'critical' || raw === 'high' || raw === 'medium' || raw === 'low') return raw;
      if (raw === 'none') return 'low';
      return 'medium';
    }

    function actionPlanPriorityWeight(priority) {
      const safe = normalizeActionPlanPriority(priority);
      if (safe === 'critical') return 4;
      if (safe === 'high') return 3;
      if (safe === 'medium') return 2;
      return 1;
    }

    function normalizeActionPlanEffort(effort) {
      const raw = String(effort || '').trim().toLowerCase();
      if (raw === 'low' || raw === 'medium' || raw === 'high') return raw;
      return 'medium';
    }

    function actionPlanEffortWeight(effort) {
      const safe = normalizeActionPlanEffort(effort);
      if (safe === 'low') return 0;
      if (safe === 'medium') return 1;
      return 2;
    }

    function localizeActionPlanPriority(priority) {
      const safe = normalizeActionPlanPriority(priority);
      if (safe === 'critical') return t('insights_priority_critical');
      if (safe === 'high') return t('insights_priority_high');
      if (safe === 'medium') return t('insights_priority_medium');
      return t('insights_priority_low');
    }

    function actionPlanPriorityBadgeClass(priority) {
      const safe = normalizeActionPlanPriority(priority);
      if (safe === 'critical') return 'csv-badge-crit';
      if (safe === 'high') return 'csv-badge-high';
      if (safe === 'medium') return 'csv-badge-medium';
      return 'csv-badge-low';
    }

    function localizeActionPlanOwner(owner) {
      const safe = String(owner || '').trim().toLowerCase();
      if (safe === 'dev') return t('action_plan_owner_dev');
      if (safe === 'content') return t('action_plan_owner_content');
      return t('action_plan_owner_seo');
    }

    function localizeActionPlanSource(source) {
      const safe = String(source || '').trim().toLowerCase();
      if (safe === 'mesh') return t('mode_mesh');
      if (safe === 'tech') return t('mode_tech');
      if (safe === 'redirect') return t('mode_redirect');
      if (safe === 'accessibility') return t('mode_accessibility');
      if (safe === 'geo') return t('mode_geo');
      if (safe === 'security') return t('mode_security');
      if (safe === 'images') return t('mode_images');
      return t('mode_sitemap');
    }

    function localizeActionPlanEffort(effort) {
      const safe = normalizeActionPlanEffort(effort);
      if (safe === 'low') return t('action_plan_effort_low');
      if (safe === 'high') return t('action_plan_effort_high');
      return t('action_plan_effort_medium');
    }

    function createActionPlanFinding(finding) {
      const title = String(finding && finding.title ? finding.title : '').trim();
      if (!title) return null;
      return {
        source: String(finding.source || 'sitemap').trim().toLowerCase(),
        owner: String(finding.owner || 'seo').trim().toLowerCase(),
        priority: normalizeActionPlanPriority(finding.priority),
        effort: normalizeActionPlanEffort(finding.effort),
        title,
        detail: String(finding.detail || '').trim(),
        entity: String(finding.entity || '').trim(),
        quickWin: !!finding.quickWin,
      };
    }

    function scoreActionPlanFinding(finding) {
      return (actionPlanPriorityWeight(finding.priority) * 100)
        + (finding.quickWin ? 20 : 0)
        - (actionPlanEffortWeight(finding.effort) * 10);
    }

    function sortActionPlanFindings(findings) {
      return findings.sort((a, b) => {
        const scoreDiff = scoreActionPlanFinding(b) - scoreActionPlanFinding(a);
        if (scoreDiff !== 0) return scoreDiff;
        return a.title.localeCompare(b.title, currentLang);
      });
    }

    function classifySitemapAction(actionKey, count) {
      const safe = String(actionKey || '').trim().toLowerCase();
      const total = Number(count || 0);
      if (safe === 'fix_non_200_in_sitemap') return { owner: 'dev', priority: total > 10 ? 'high' : 'medium', effort: 'medium', quickWin: false };
      if (safe === 'fix_robots_blocked_in_sitemap') return { owner: 'seo', priority: 'high', effort: 'medium', quickWin: false };
      if (safe === 'fix_noindex_in_sitemap') return { owner: 'seo', priority: 'high', effort: 'low', quickWin: true };
      if (safe === 'fix_cross_domain_canonicals') return { owner: 'dev', priority: 'high', effort: 'medium', quickWin: false };
      if (safe === 'add_x_default_hreflang') return { owner: 'seo', priority: 'medium', effort: 'low', quickWin: true };
      return { owner: 'seo', priority: 'high', effort: 'medium', quickWin: false };
    }

    function classifyTechRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      if (safe === 'add_title' || safe === 'optimize_title_length' || safe === 'add_meta_description' || safe === 'optimize_meta_description' || safe === 'add_h1') {
        return { owner: 'content', effort: 'low', quickWin: true };
      }
      if (safe === 'keep_single_h1' || safe === 'add_open_graph' || safe === 'add_twitter_tags' || safe === 'add_twitter_image') {
        return { owner: 'content', effort: 'medium', quickWin: true };
      }
      if (safe === 'add_viewport' || safe === 'add_jsonld' || safe === 'fix_jsonld_validity' || safe === 'add_jsonld_type'
        || safe === 'fix_http_status' || safe === 'enforce_https' || safe === 'reduce_redirect_hops'
        || safe === 'fix_redirect_chain_https' || safe === 'serve_html_content' || safe === 'allow_in_robots'
        || safe === 'add_canonical' || safe === 'fix_canonical_domain' || safe === 'fix_canonical_target_status'
        || safe === 'fix_canonical_target_indexability' || safe === 'publish_robots_txt') {
        return { owner: 'dev', effort: 'medium', quickWin: false };
      }
      return { owner: 'seo', effort: 'medium', quickWin: false };
    }

    function classifyGeoRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      if (safe === 'geo_reco_add_canonical' || safe === 'geo_reco_add_open_graph'
        || safe === 'geo_reco_add_twitter_card' || safe === 'geo_reco_fix_h1'
        || safe === 'geo_reco_add_heading_anchors') {
        return { owner: 'dev', effort: 'low', quickWin: true };
      }
      if (safe === 'geo_reco_add_llms_txt' || safe === 'geo_reco_unblock_ai_crawlers') {
        return { owner: 'dev', effort: 'low', quickWin: true };
      }
      if (safe === 'geo_reco_add_structured_data' || safe === 'geo_reco_add_faq_markup'
        || safe === 'geo_reco_fix_jsonld') {
        return { owner: 'dev', effort: 'medium', quickWin: false };
      }
      if (safe === 'geo_reco_add_dates' || safe === 'geo_reco_refresh_content' || safe === 'geo_reco_improve_qa_format'
        || safe === 'geo_reco_deepen_content' || safe === 'geo_reco_add_external_citations'
        || safe === 'geo_reco_add_author_signals') {
        return { owner: 'content', effort: 'medium', quickWin: false };
      }
      return { owner: 'seo', effort: 'medium', quickWin: false };
    }

    function classifySecurityRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      if (safe === 'security_reco_https' || safe === 'security_reco_http_redirect' || safe === 'security_reco_mixed_content') {
        return { owner: 'dev', effort: 'medium', quickWin: false };
      }
      if (safe === 'security_reco_hsts' || safe === 'security_reco_csp' || safe === 'security_reco_csp_unsafe'
        || safe === 'security_reco_frame_protection' || safe === 'security_reco_content_type_options'
        || safe === 'security_reco_referrer_policy' || safe === 'security_reco_permissions_policy'
        || safe === 'security_reco_server_leak' || safe === 'security_reco_cookies') {
        return { owner: 'dev', effort: 'low', quickWin: true };
      }
      return { owner: 'dev', effort: 'low', quickWin: true };
    }

    function collectSecurityActionPlanFindings() {
      if (typeof latestSecurityPayload === 'undefined' || !latestSecurityPayload || typeof latestSecurityPayload !== 'object') return [];
      const checklist = latestSecurityPayload.checklist && typeof latestSecurityPayload.checklist === 'object' ? latestSecurityPayload.checklist : {};
      const buckets = [
        { priority: 'high', keys: Array.isArray(checklist.high) ? checklist.high : [] },
        { priority: 'medium', keys: Array.isArray(checklist.medium) ? checklist.medium : [] },
        { priority: 'low', keys: Array.isArray(checklist.low) ? checklist.low : [] },
      ];
      const entity = String(latestSecurityPayload.final_url || latestSecurityPayload.url || '').trim();
      const findings = [];
      buckets.forEach((bucket) => {
        bucket.keys.slice(0, 4).forEach((key) => {
          const meta = classifySecurityRecommendation(key);
          const finding = createActionPlanFinding({
            source: 'security',
            owner: meta.owner,
            priority: bucket.priority,
            effort: meta.effort,
            quickWin: meta.quickWin,
            title: (typeof localizeSecurityRecommendation === 'function') ? localizeSecurityRecommendation(key) : String(key),
            entity,
          });
          if (finding) findings.push(finding);
        });
      });
      return findings;
    }

    function classifyImagesRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      if (safe === 'images_reco_alt') return { owner: 'content', effort: 'low', quickWin: true };
      if (safe === 'images_reco_dimensions' || safe === 'images_reco_lazy' || safe === 'images_reco_responsive') {
        return { owner: 'dev', effort: 'medium', quickWin: false };
      }
      if (safe === 'images_reco_modern_format') return { owner: 'dev', effort: 'high', quickWin: false };
      return { owner: 'dev', effort: 'low', quickWin: true };
    }

    function collectImagesActionPlanFindings() {
      if (typeof latestImagesPayload === 'undefined' || !latestImagesPayload || typeof latestImagesPayload !== 'object') return [];
      const checklist = latestImagesPayload.checklist && typeof latestImagesPayload.checklist === 'object' ? latestImagesPayload.checklist : {};
      const buckets = [
        { priority: 'high', keys: Array.isArray(checklist.high) ? checklist.high : [] },
        { priority: 'medium', keys: Array.isArray(checklist.medium) ? checklist.medium : [] },
        { priority: 'low', keys: Array.isArray(checklist.low) ? checklist.low : [] },
      ];
      const entity = String(latestImagesPayload.final_url || latestImagesPayload.url || '').trim();
      const findings = [];
      buckets.forEach((bucket) => {
        bucket.keys.slice(0, 4).forEach((key) => {
          const meta = classifyImagesRecommendation(key);
          const finding = createActionPlanFinding({
            source: 'images',
            owner: meta.owner,
            priority: bucket.priority,
            effort: meta.effort,
            quickWin: meta.quickWin,
            title: (typeof localizeImagesRecommendation === 'function') ? localizeImagesRecommendation(key) : String(key),
            entity,
          });
          if (finding) findings.push(finding);
        });
      });
      return findings;
    }

    function classifyAccessibilityRecommendation(key) {
      const safe = String(key || '').trim().toLowerCase();
      if (safe === 'a11y_reco_fix_image_alts' || safe === 'a11y_reco_fix_form_labels' || safe === 'a11y_reco_fix_button_names'
        || safe === 'a11y_reco_fix_link_names' || safe === 'a11y_reco_fix_iframe_titles' || safe === 'a11y_reco_add_main_landmark'
        || safe === 'a11y_reco_add_skip_link' || safe === 'a11y_reco_add_lang') {
        return { owner: 'dev', effort: 'medium', quickWin: false };
      }
      if (safe === 'a11y_reco_publish_accessibility_page' || safe === 'a11y_reco_publish_statement'
        || safe === 'a11y_reco_publish_multiyear' || safe === 'a11y_reco_publish_plan'
        || safe === 'a11y_reco_add_status_mention') {
        return { owner: 'seo', effort: 'low', quickWin: true };
      }
      return { owner: 'content', effort: 'medium', quickWin: false };
    }

    function collectSitemapActionPlanFindings() {
      if (!latestStatusPayload || typeof latestStatusPayload !== 'object') return [];
      const findings = [];
      const insights = latestStatusPayload.insights && typeof latestStatusPayload.insights === 'object' ? latestStatusPayload.insights : {};
      const domainOverview = insights.domain_overview && typeof insights.domain_overview === 'object' ? insights.domain_overview : {};
      const actions = Array.isArray(domainOverview.actions) ? domainOverview.actions : [];
      actions.slice(0, 6).forEach((action) => {
        const meta = classifySitemapAction(action.action_key, action.count);
        const finding = createActionPlanFinding({
          source: 'sitemap',
          owner: meta.owner,
          priority: meta.priority,
          effort: meta.effort,
          quickWin: meta.quickWin,
          title: t('domain_action_item', {
            label: localizeDomainAction(action.action_key),
            count: Number(action.count || 0),
          }),
          entity: latestStatusPayload.sitemap || '',
        });
        if (finding) findings.push(finding);
      });

      const rows = previewDataset
        .filter((row) => String(row.issues || '').trim())
        .slice()
        .sort((a, b) => Number(b.priority_score || 0) - Number(a.priority_score || 0))
        .slice(0, 3);
      rows.forEach((row) => {
        const issue = String(row.issues || '').split('|').map((part) => part.trim()).filter(Boolean)[0] || t('insights_top_issues');
        const finding = createActionPlanFinding({
          source: 'sitemap',
          owner: 'seo',
          priority: row.priority_level || 'medium',
          effort: 'medium',
          quickWin: Number(row.priority_score || 0) >= 70,
          title: issue,
          detail: row.final_url && row.final_url !== row.url ? row.final_url : '',
          entity: String(row.url || row.final_url || '').trim(),
        });
        if (finding) findings.push(finding);
      });
      return findings;
    }

    function collectMeshActionPlanFindings() {
      if (!latestMeshPayload || typeof latestMeshPayload !== 'object') return [];
      const actionable = latestMeshPayload.actionable && typeof latestMeshPayload.actionable === 'object' ? latestMeshPayload.actionable : {};
      const recommendations = Array.isArray(actionable.recommendations) ? actionable.recommendations : [];
      return recommendations.slice(0, 8).map((item) => createActionPlanFinding({
        source: 'mesh',
        owner: String(item.issue_type || '').toLowerCase() === 'hreflang_missing_reciprocal' ? 'seo' : 'content',
        priority: item.priority || 'medium',
        effort: String(item.issue_type || '').toLowerCase() === 'template_only_inbound' ? 'high' : 'medium',
        quickWin: String(item.priority || '').toLowerCase() !== 'low',
        title: localizeMeshIssue(item.issue_type),
        detail: String(item.target_url || '').trim(),
        entity: String(item.target_url || '').trim(),
      })).filter(Boolean);
    }

    function collectTechActionPlanFindings() {
      if (!latestTechPayload || typeof latestTechPayload !== 'object') return [];
      const checklist = latestTechPayload.checklist && typeof latestTechPayload.checklist === 'object' ? latestTechPayload.checklist : {};
      const buckets = [
        { priority: 'high', keys: Array.isArray(checklist.high) ? checklist.high : [] },
        { priority: 'medium', keys: Array.isArray(checklist.medium) ? checklist.medium : [] },
        { priority: 'low', keys: Array.isArray(checklist.low) ? checklist.low : [] },
      ];
      const entity = String(latestTechPayload.final_url || latestTechPayload.url || '').trim();
      const findings = [];
      buckets.forEach((bucket) => {
        bucket.keys.slice(0, 4).forEach((key) => {
          const meta = classifyTechRecommendation(key);
          const finding = createActionPlanFinding({
            source: 'tech',
            owner: meta.owner,
            priority: bucket.priority,
            effort: meta.effort,
            quickWin: meta.quickWin,
            title: localizeTechRecommendation(key),
            entity,
          });
          if (finding) findings.push(finding);
        });
      });
      return findings;
    }

    function collectRedirectActionPlanFindings() {
      if (!latestRedirectPayload || typeof latestRedirectPayload !== 'object') return [];
      const findings = [];
      const audit = latestRedirectPayload;
      const statusCode = Number(audit.status_code || 0);
      const redirectChain = Array.isArray(audit.redirect_chain) ? audit.redirect_chain : [];
      const redirectCount = Number(audit.redirect_count || 0);
      const finalUrl = String(audit.final_url || audit.url || '').trim();
      const finalHttps = finalUrl.toLowerCase().startsWith('https://');
      const chainHttpsOnly = redirectChain.every((step) => !!step && !!step.https);
      const temporaryHopCount = redirectChain.slice(0, -1).filter((step) => {
        const code = Number(step && step.status ? step.status : 0);
        return code === 302 || code === 307;
      }).length;
      const recommendations = [];
      if (!(statusCode >= 200 && statusCode < 300)) recommendations.push({ key: 'redirect_reco_fix_final_status', priority: 'high', effort: 'medium', quickWin: false });
      if (redirectCount > 1) recommendations.push({ key: 'redirect_reco_reduce_hops', priority: 'high', effort: 'medium', quickWin: false });
      if (!finalHttps || !chainHttpsOnly) recommendations.push({ key: 'redirect_reco_enforce_https', priority: 'high', effort: 'medium', quickWin: false });
      if (temporaryHopCount > 0) recommendations.push({ key: 'redirect_reco_use_301', priority: 'medium', effort: 'low', quickWin: true });
      recommendations.forEach((item) => {
        const finding = createActionPlanFinding({
          source: 'redirect',
          owner: 'dev',
          priority: item.priority,
          effort: item.effort,
          quickWin: item.quickWin,
          title: localizeRedirectRecommendation(item.key),
          entity: finalUrl,
        });
        if (finding) findings.push(finding);
      });
      return findings;
    }

    function collectGeoActionPlanFindings() {
      if (!latestGeoPayload || typeof latestGeoPayload !== 'object') return [];
      const checklist = latestGeoPayload.checklist && typeof latestGeoPayload.checklist === 'object' ? latestGeoPayload.checklist : {};
      const buckets = [
        { priority: 'high', keys: Array.isArray(checklist.high) ? checklist.high : [] },
        { priority: 'medium', keys: Array.isArray(checklist.medium) ? checklist.medium : [] },
        { priority: 'low', keys: Array.isArray(checklist.low) ? checklist.low : [] },
      ];
      const entity = String(latestGeoPayload.final_url || latestGeoPayload.url || '').trim();
      const findings = [];
      buckets.forEach((bucket) => {
        bucket.keys.slice(0, 4).forEach((key) => {
          const i18nKey = String(key || '').toLowerCase().startsWith('geo_reco_') ? key : '';
          const meta = classifyGeoRecommendation(i18nKey || key);
          const title = i18nKey ? t(i18nKey) : localizeGeoCheckLabel(key);
          const finding = createActionPlanFinding({
            source: 'geo',
            owner: meta.owner,
            priority: bucket.priority,
            effort: meta.effort,
            quickWin: meta.quickWin,
            title,
            entity,
          });
          if (finding) findings.push(finding);
        });
      });
      return findings;
    }

    function collectAccessibilityActionPlanFindings() {
      if (!latestAccessibilityPayload || typeof latestAccessibilityPayload !== 'object') return [];
      const checklist = latestAccessibilityPayload.checklist && typeof latestAccessibilityPayload.checklist === 'object'
        ? latestAccessibilityPayload.checklist
        : {};
      const buckets = [
        { priority: 'high', keys: Array.isArray(checklist.high) ? checklist.high : [] },
        { priority: 'medium', keys: Array.isArray(checklist.medium) ? checklist.medium : [] },
        { priority: 'low', keys: Array.isArray(checklist.low) ? checklist.low : [] },
      ];
      const entity = String(latestAccessibilityPayload.final_url || latestAccessibilityPayload.url || '').trim();
      const findings = [];
      buckets.forEach((bucket) => {
        bucket.keys.slice(0, 4).forEach((key) => {
          const meta = classifyAccessibilityRecommendation(key);
          const finding = createActionPlanFinding({
            source: 'accessibility',
            owner: meta.owner,
            priority: bucket.priority,
            effort: meta.effort,
            quickWin: meta.quickWin,
            title: localizeAccessibilityRecommendation(key),
            entity,
          });
          if (finding) findings.push(finding);
        });
      });
      return findings;
    }

    function buildActionPlanPayload() {
      const findings = sortActionPlanFindings([
        ...collectSitemapActionPlanFindings(),
        ...collectMeshActionPlanFindings(),
        ...collectTechActionPlanFindings(),
        ...collectRedirectActionPlanFindings(),
        ...collectAccessibilityActionPlanFindings(),
        ...collectGeoActionPlanFindings(),
        ...collectSecurityActionPlanFindings(),
        ...collectImagesActionPlanFindings(),
      ]);

      const counts = {
        owners: {},
        sources: {},
      };
      findings.forEach((finding) => {
        counts.owners[finding.owner] = Number(counts.owners[finding.owner] || 0) + 1;
        counts.sources[finding.source] = Number(counts.sources[finding.source] || 0) + 1;
      });

      return {
        findings,
        quickWins: findings.filter((finding) => finding.quickWin).length,
        sourceCount: Object.keys(counts.sources).length,
        ownerCount: Object.keys(counts.owners).length,
        counts,
      };
    }

    function renderActionPlanCountList(container, title, counts, formatter) {
      container.innerHTML = '';
      const heading = document.createElement('strong');
      heading.className = 'action-plan-box-title';
      heading.textContent = title;
      container.appendChild(heading);

      const entries = Object.entries(counts || {}).sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0));
      if (!entries.length) {
        const empty = document.createElement('div');
        empty.className = 'action-plan-empty';
        empty.textContent = t('action_plan_empty_text');
        container.appendChild(empty);
        return;
      }

      const list = document.createElement('ul');
      list.className = 'action-plan-count-list';
      entries.forEach(([key, value]) => {
        const item = document.createElement('li');
        item.className = 'action-plan-count-item';
        item.innerHTML = `<span>${escapeHtml(formatter(key))}</span><strong>${escapeHtml(String(Number(value || 0)))}</strong>`;
        list.appendChild(item);
      });
      container.appendChild(list);
    }

    function renderActionPlanFindingList(container, title, findings, emptyText) {
      container.innerHTML = '';
      const heading = document.createElement('strong');
      heading.className = 'action-plan-box-title';
      heading.textContent = title;
      container.appendChild(heading);

      if (!findings.length) {
        const empty = document.createElement('div');
        empty.className = 'action-plan-empty';
        empty.textContent = emptyText;
        container.appendChild(empty);
        return;
      }

      const stack = document.createElement('div');
      stack.className = 'action-plan-stack';
      findings.forEach((finding) => {
        const item = document.createElement('article');
        item.className = 'action-plan-item';
        const entityText = finding.entity ? t('action_plan_entity', { entity: finding.entity }) : '';
        const detailText = [finding.detail, entityText].filter(Boolean).join(' · ');
        item.innerHTML = `
          <div class="action-plan-item-head">
            <div class="action-plan-item-title">${escapeHtml(finding.title)}</div>
            <span class="csv-badge ${escapeHtml(actionPlanPriorityBadgeClass(finding.priority))}">${escapeHtml(localizeActionPlanPriority(finding.priority))}</span>
          </div>
          <div class="action-plan-item-meta">${escapeHtml(localizeActionPlanSource(finding.source))} · ${escapeHtml(localizeActionPlanOwner(finding.owner))} · ${escapeHtml(localizeActionPlanEffort(finding.effort))}</div>
          ${detailText ? `<div class="action-plan-item-detail">${escapeHtml(detailText)}</div>` : ''}
        `;
        stack.appendChild(item);
      });
      container.appendChild(stack);
    }

    function renderActionPlan() {
      if (!actionPlanCard) return;
      latestActionPlanPayload = buildActionPlanPayload();
      const payload = latestActionPlanPayload;
      const findings = Array.isArray(payload.findings) ? payload.findings : [];

      actionPlanCard.style.display = findings.length ? 'block' : 'none';
      if (!findings.length) return;

      actionPlanStatus.textContent = t('action_plan_status_ready', {
        count: findings.length,
        sources: Object.keys(payload.counts.sources || {}).map((key) => localizeActionPlanSource(key)).join(', '),
      });

      actionPlanKpis.innerHTML = '';
      [
        { label: t('action_plan_kpi_findings'), value: String(findings.length) },
        { label: t('action_plan_kpi_quick_wins'), value: String(Number(payload.quickWins || 0)) },
        { label: t('action_plan_kpi_sources'), value: String(Number(payload.sourceCount || 0)) },
        { label: t('action_plan_kpi_owners'), value: String(Number(payload.ownerCount || 0)) },
      ].forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'tech-kpi';
        card.innerHTML = `<b>${escapeHtml(entry.value)}</b><span>${escapeHtml(entry.label)}</span>`;
        actionPlanKpis.appendChild(card);
      });

      renderActionPlanFindingList(actionPlanNow, t('action_plan_now_title'), findings.slice(0, 5), t('action_plan_empty_text'));
      renderActionPlanCountList(actionPlanOwners, t('action_plan_by_owner_title'), payload.counts.owners, localizeActionPlanOwner);
      renderActionPlanCountList(actionPlanSources, t('action_plan_by_source_title'), payload.counts.sources, localizeActionPlanSource);
      renderActionPlanFindingList(actionPlanBacklog, t('action_plan_backlog_title'), findings.slice(5, 13), t('action_plan_backlog_empty'));
    }

    (function setupActionPlanToggle() {
      if (!actionPlanToggle || !actionPlanCard || !actionPlanBody) return;
      const STORAGE_KEY = "action_plan_collapsed";
      const apply = (collapsed) => {
        actionPlanCard.dataset.collapsed = collapsed ? "true" : "false";
        actionPlanBody.style.display = collapsed ? "none" : "";
        actionPlanToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
      };
      let initial = false;
      try { initial = localStorage.getItem(STORAGE_KEY) === "1"; } catch (_) {}
      apply(initial);
      actionPlanToggle.addEventListener("click", () => {
        const next = actionPlanCard.dataset.collapsed !== "true";
        apply(next);
        try { localStorage.setItem(STORAGE_KEY, next ? "1" : "0"); } catch (_) {}
      });
    })();
