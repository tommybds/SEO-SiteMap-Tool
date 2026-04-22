// Auto-split from app.js
function t(key, vars = {}) {
      const dict = I18N[currentLang] || I18N.fr;
      let text = dict[key] ?? I18N.fr[key] ?? key;
      Object.keys(vars).forEach((name) => {
        text = text.replaceAll(`{${name}}`, String(vars[name]));
      });
      return text;
    }

    function detectInitialLang() {
      const paramLang = (new URLSearchParams(window.location.search).get('lang') || '').toLowerCase();
      if (paramLang === 'fr' || paramLang === 'en') return paramLang;
      return navigator.language && navigator.language.toLowerCase().startsWith('en') ? 'en' : 'fr';
    }

    function localizeStatus(status) {
      const raw = String(status || '').toLowerCase();
      if (raw === 'queued') return t('status_queued');
      if (raw === 'running') return t('status_running');
      if (raw === 'completed') return t('status_completed_value');
      if (raw === 'failed') return t('status_failed');
      return t('status_unknown');
    }

    function localizeMeshJobStatus(status) {
      const raw = String(status || '').toLowerCase();
      if (raw === 'queued') return t('mesh_job_status_queued');
      if (raw === 'running') return t('mesh_job_status_running');
      if (raw === 'completed') return t('mesh_job_status_completed');
      if (raw === 'failed') return t('mesh_job_status_failed');
      return t('status_unknown');
    }

    function localizeMeshProgressStage(stage) {
      const raw = String(stage || '').toLowerCase();
      if (raw === 'queued') return t('mesh_progress_stage_queued');
      if (raw === 'preparing') return t('mesh_progress_stage_preparing');
      if (raw === 'discovering_sitemaps') return t('mesh_progress_stage_discovering');
      if (raw === 'scanning') return t('mesh_progress_stage_scanning');
      if (raw === 'finalizing') return t('mesh_progress_stage_finalizing');
      if (raw === 'completed') return t('mesh_progress_stage_completed');
      if (raw === 'failed') return t('mesh_progress_stage_failed');
      return raw || t('status_unknown');
    }

    function getModeHelpText(mode = currentMode) {
      if (mode === 'tech') return t('mode_help_tech');
      if (mode === 'redirect') return t('mode_help_redirect');
      if (mode === 'accessibility') return t('mode_help_accessibility');
      if (mode === 'geo') return t('mode_help_geo');
      if (mode === 'action-plan') return t('mode_help_action_plan');
      return t('mode_help');
    }

    function applyTranslations() {
      document.documentElement.lang = currentLang;
      document.title = t('page_title');
      if (metaDescriptionTag) {
        metaDescriptionTag.setAttribute('content', t('meta_description'));
      }
      appTitle.textContent = t('app_title');
      appSubtitle.textContent = t('app_subtitle');
      modeSitemapBtn.textContent = t('mode_sitemap');
      modeMeshBtn.textContent = t('mode_mesh');
      if (modeTechBtn) modeTechBtn.textContent = t('mode_tech');
      if (modeRedirectBtn) modeRedirectBtn.textContent = t('mode_redirect');
      if (modeAccessibilityBtn) modeAccessibilityBtn.textContent = t('mode_accessibility');
      if (modeGeoBtn) modeGeoBtn.textContent = t('mode_geo');
      if (modeActionPlanBtn) modeActionPlanBtn.textContent = t('mode_action_plan');
      modeHelp.textContent = getModeHelpText();
      labelSitemap.textContent = t('label_sitemap');
      labelMaxUrls.textContent = t('label_max_urls');
      labelWorkers.textContent = t('label_workers');
      labelTimeout.textContent = t('label_timeout');
      labelSkipRobotsText.textContent = t('label_skip_robots');
      labelMeshStartUrl.textContent = t('label_mesh_start_url');
      labelMeshMaxPages.textContent = t('label_mesh_max_pages');
      labelMeshTimeout.textContent = t('label_mesh_timeout');
      if (labelTechUrl) labelTechUrl.textContent = t('label_tech_url');
      if (labelTechTimeout) labelTechTimeout.textContent = t('label_timeout');
      if (labelRedirectUrl) labelRedirectUrl.textContent = t('label_redirect_url');
      if (labelRedirectTimeout) labelRedirectTimeout.textContent = t('label_redirect_timeout');
      if (labelAccessibilityUrl) labelAccessibilityUrl.textContent = t('label_accessibility_url');
      if (labelAccessibilityStandard) labelAccessibilityStandard.textContent = t('label_accessibility_standard');
      if (accessibilityStandardInput) {
        const rgaa4Option = accessibilityStandardInput.querySelector('option[value="rgaa4"]');
        const rgaa5Option = accessibilityStandardInput.querySelector('option[value="rgaa5"]');
        if (rgaa4Option) rgaa4Option.textContent = t('accessibility_standard_rgaa4');
        if (rgaa5Option) rgaa5Option.textContent = t('accessibility_standard_rgaa5');
      }
      if (labelAccessibilityTimeout) labelAccessibilityTimeout.textContent = t('label_accessibility_timeout');
      if (labelGeoUrl) labelGeoUrl.textContent = t('label_geo_url');
      if (labelGeoTimeout) labelGeoTimeout.textContent = t('label_geo_timeout');
      jobSectionTitle.textContent = t('job_section_title');
      meshSectionTitle.textContent = t('mesh_section_title');
      if (techSectionTitle) techSectionTitle.textContent = t('tech_section_title');
      if (redirectSectionTitle) redirectSectionTitle.textContent = t('redirect_section_title');
      if (accessibilitySectionTitle) accessibilitySectionTitle.textContent = t('accessibility_section_title');
      if (geoSectionTitle) geoSectionTitle.textContent = t('geo_section_title');
      if (actionPlanSectionTitle) actionPlanSectionTitle.textContent = t('action_plan_section_title');
      if (actionPlanIntro) actionPlanIntro.textContent = t('action_plan_intro');
      if (redirectTechDetailsSummary) redirectTechDetailsSummary.textContent = t('redirect_details_summary');
      shareMeshBtn.textContent = t('share_mesh_btn');
      if (meshToggleGraphBtn) {
        meshToggleGraphBtn.textContent = meshGraphVisible ? t('mesh_graph_hide') : t('mesh_graph_show');
      }
      meshResetFocusBtn.textContent = t('mesh_reset_focus');
      meshResetViewBtn.textContent = t('mesh_reset_view');
      downloadLink.textContent = t('download_csv');
      conflictsDownloadLink.textContent = t('download_conflicts');
      shareReportBtn.textContent = t('copy_share_url');
      kpiTotalLabel.textContent = t('kpi_total');
      kpiOkLabel.textContent = t('kpi_ok');
      kpiKoLabel.textContent = t('kpi_ko');
      insightsTitle.textContent = t('insights_title');
      logsSummary.textContent = t('logs_summary');
      previewTitle.textContent = t('preview_title');
      filterIssueLabel.textContent = t('filter_issue_label');
      filterIssue.placeholder = t('filter_issue_placeholder');
      filterHttpLabel.textContent = t('filter_http_label');
      filterIndexableLabel.textContent = t('filter_indexable_label');
      filterPriorityLabel.textContent = t('filter_priority_label');
      filterStatus.querySelector('option[value="all"]').textContent = t('opt_all');
      filterStatus.querySelector('option[value="not-200"]').textContent = t('opt_not_200');
      filterIndexable.querySelector('option[value="all"]').textContent = t('opt_all');
      filterIndexable.querySelector('option[value="true"]').textContent = t('opt_yes');
      filterIndexable.querySelector('option[value="false"]').textContent = t('opt_no');
      filterPriority.querySelector('option[value="all"]').textContent = t('opt_all_f');
      filterPriority.querySelector('option[value="critical"]').textContent = t('opt_critical');
      filterPriority.querySelector('option[value="high"]').textContent = t('opt_high');
      filterPriority.querySelector('option[value="medium"]').textContent = t('opt_medium');
      filterPriority.querySelector('option[value="low"]').textContent = t('opt_low');
      filterPriority.querySelector('option[value="none"]').textContent = t('opt_none');
      resetFiltersBtn.textContent = t('reset_filters_btn');
      footerCreditPrefix.textContent = t('footer_credit_prefix');
      langFrBtn.classList.toggle('active', currentLang === 'fr');
      langEnBtn.classList.toggle('active', currentLang === 'en');
      modeSitemapBtn.classList.toggle('active', currentMode === 'sitemap');
      modeMeshBtn.classList.toggle('active', currentMode === 'mesh');
      if (modeTechBtn) modeTechBtn.classList.toggle('active', currentMode === 'tech');
      if (modeRedirectBtn) modeRedirectBtn.classList.toggle('active', currentMode === 'redirect');
      if (modeAccessibilityBtn) modeAccessibilityBtn.classList.toggle('active', currentMode === 'accessibility');
      if (modeGeoBtn) modeGeoBtn.classList.toggle('active', currentMode === 'geo');
      if (modeActionPlanBtn) modeActionPlanBtn.classList.toggle('active', currentMode === 'action-plan');
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');
      if (modeTechBtn) modeTechBtn.setAttribute('aria-selected', currentMode === 'tech' ? 'true' : 'false');
      if (modeRedirectBtn) modeRedirectBtn.setAttribute('aria-selected', currentMode === 'redirect' ? 'true' : 'false');
      if (modeAccessibilityBtn) modeAccessibilityBtn.setAttribute('aria-selected', currentMode === 'accessibility' ? 'true' : 'false');
      if (modeGeoBtn) modeGeoBtn.setAttribute('aria-selected', currentMode === 'geo' ? 'true' : 'false');
      if (modeActionPlanBtn) modeActionPlanBtn.setAttribute('aria-selected', currentMode === 'action-plan' ? 'true' : 'false');
      setRunningState(runBtn.disabled);
      setMeshRunningState(meshRunBtn.disabled);
      if (techRunBtn) setTechRunningState(techRunBtn.disabled);
      if (redirectRunBtn) setRedirectRunningState(redirectRunBtn.disabled);
      if (accessibilityRunBtn) setAccessibilityRunningState(accessibilityRunBtn.disabled);
      if (geoRunBtn) setGeoRunningState(geoRunBtn.disabled);
      if (latestStatusPayload) {
        renderStatus(latestStatusPayload);
      } else if (!logTail.textContent.trim()) {
        logTail.textContent = t('no_logs_yet');
      }
      if (latestMeshPayload) {
        renderMesh(latestMeshPayload);
      } else {
        meshInteractionHint.textContent = t('mesh_graph_collapsed_hint');
      }
      if (latestTechPayload) {
        renderTech(latestTechPayload);
      }
      if (latestRedirectPayload) {
        renderRedirect(latestRedirectPayload);
      }
      if (latestAccessibilityPayload) {
        renderAccessibility(latestAccessibilityPayload);
      }
      if (latestGeoPayload) {
        renderGeo(latestGeoPayload);
      }
      if (actionPlanCard) {
        renderActionPlan();
      }
      applyPreviewFilters();
    }

    function setLang(lang, syncUrl = true) {
      if (lang !== 'fr' && lang !== 'en') return;
      currentLang = lang;
      applyTranslations();
      if (syncUrl) {
        const url = new URL(window.location.href);
        url.searchParams.set('lang', currentLang);
        url.searchParams.set('mode', currentMode);
        window.history.replaceState({}, '', url.toString());
      }
    }

    function detectInitialMode() {
      const mode = (new URLSearchParams(window.location.search).get('mode') || '').toLowerCase();
      if (mode === 'mesh') return 'mesh';
      if (mode === 'tech') return 'tech';
      if (mode === 'redirect') return 'redirect';
      if (mode === 'accessibility') return 'accessibility';
      if (mode === 'geo') return 'geo';
      if (mode === 'action-plan') return 'action-plan';
      return 'sitemap';
    }

    function setMeshRunningState(running) {
      meshRunBtn.disabled = running;
      meshRunBtn.textContent = running ? t('mesh_run_btn_running') : t('mesh_run_btn_idle');
    }

    function setTechRunningState(running) {
      if (!techRunBtn) return;
      techRunBtn.disabled = running;
      techRunBtn.textContent = running ? t('tech_run_btn_running') : t('tech_run_btn_idle');
    }

    function setRedirectRunningState(running) {
      if (!redirectRunBtn) return;
      redirectRunBtn.disabled = running;
      redirectRunBtn.textContent = running ? t('redirect_run_btn_running') : t('redirect_run_btn_idle');
    }

    function setAccessibilityRunningState(running) {
      if (!accessibilityRunBtn) return;
      accessibilityRunBtn.disabled = running;
      accessibilityRunBtn.textContent = running ? t('accessibility_run_btn_running') : t('accessibility_run_btn_idle');
    }

    function setGeoRunningState(running) {
      if (!geoRunBtn) return;
      geoRunBtn.disabled = running;
      geoRunBtn.textContent = running ? t('geo_run_btn_running') : t('geo_run_btn_idle');
    }

    function applyMeshGraphVisibility() {
      const wrap = meshGraph ? meshGraph.closest('.mesh-graph-wrap') : null;
      const visible = !!meshGraphVisible;
      if (wrap) {
        wrap.style.display = visible ? 'block' : 'none';
      }
      if (meshToggleGraphBtn) {
        meshToggleGraphBtn.textContent = visible ? t('mesh_graph_hide') : t('mesh_graph_show');
      }
      meshResetFocusBtn.style.display = visible ? 'inline-flex' : 'none';
      meshResetViewBtn.style.display = visible ? 'inline-flex' : 'none';
      if (!latestMeshPayload) {
        meshInteractionHint.textContent = t('mesh_graph_collapsed_hint');
        return;
      }
      meshInteractionHint.textContent = visible
        ? (String(meshInteractionHint.dataset.idleHint || '').trim() || t('mesh_interaction_hint_idle'))
        : t('mesh_graph_collapsed_hint');
    }

    function keepActiveModeButtonVisible() {
      const activeModeBtn = [modeSitemapBtn, modeMeshBtn, modeTechBtn, modeRedirectBtn, modeAccessibilityBtn, modeGeoBtn, modeActionPlanBtn]
        .find((btn) => btn && btn.classList.contains('active'));
      if (!activeModeBtn || typeof activeModeBtn.scrollIntoView !== 'function') return;
      activeModeBtn.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }

    function setMode(mode, syncUrl = true) {
      currentMode = mode === 'mesh' || mode === 'tech' || mode === 'redirect' || mode === 'accessibility' || mode === 'geo' || mode === 'action-plan' ? mode : 'sitemap';
      if (currentMode === 'tech' && !hasTechMode) {
        currentMode = 'sitemap';
      }
      if (currentMode === 'redirect' && !hasRedirectMode) {
        currentMode = 'sitemap';
      }
      if (currentMode === 'accessibility' && !hasAccessibilityMode) {
        currentMode = 'sitemap';
      }
      if (currentMode === 'geo' && !hasGeoMode) {
        currentMode = 'sitemap';
      }
      sitemapModePanel.style.display = currentMode === 'sitemap' ? 'block' : 'none';
      meshModePanel.style.display = currentMode === 'mesh' ? 'block' : 'none';
      if (techModePanel) techModePanel.style.display = currentMode === 'tech' ? 'block' : 'none';
      if (redirectModePanel) redirectModePanel.style.display = currentMode === 'redirect' ? 'block' : 'none';
      if (accessibilityModePanel) accessibilityModePanel.style.display = currentMode === 'accessibility' ? 'block' : 'none';
      if (geoModePanel) geoModePanel.style.display = currentMode === 'geo' ? 'block' : 'none';
      if (actionPlanModePanel) actionPlanModePanel.style.display = currentMode === 'action-plan' ? 'block' : 'none';
      resultCard.style.display = currentMode === 'sitemap' && sitemapHasOutput ? 'block' : 'none';
      previewCard.style.display = currentMode === 'sitemap' && previewLoadedFor ? 'block' : 'none';
      meshCard.style.display = currentMode === 'mesh' && !!latestMeshPayload ? 'block' : 'none';
      if (techCard) techCard.style.display = currentMode === 'tech' && !!latestTechPayload ? 'block' : 'none';
      if (redirectCard) redirectCard.style.display = currentMode === 'redirect' && !!latestRedirectPayload ? 'block' : 'none';
      if (accessibilityCard) accessibilityCard.style.display = currentMode === 'accessibility' && !!latestAccessibilityPayload ? 'block' : 'none';
      if (geoCard) geoCard.style.display = currentMode === 'geo' && !!latestGeoPayload ? 'block' : 'none';
      if (actionPlanCard) actionPlanCard.style.display = currentMode === 'action-plan' ? 'block' : 'none';
      modeSitemapBtn.classList.toggle('active', currentMode === 'sitemap');
      modeMeshBtn.classList.toggle('active', currentMode === 'mesh');
      if (modeTechBtn) modeTechBtn.classList.toggle('active', currentMode === 'tech');
      if (modeRedirectBtn) modeRedirectBtn.classList.toggle('active', currentMode === 'redirect');
      if (modeAccessibilityBtn) modeAccessibilityBtn.classList.toggle('active', currentMode === 'accessibility');
      if (modeGeoBtn) modeGeoBtn.classList.toggle('active', currentMode === 'geo');
      if (modeActionPlanBtn) modeActionPlanBtn.classList.toggle('active', currentMode === 'action-plan');
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');
      if (modeTechBtn) modeTechBtn.setAttribute('aria-selected', currentMode === 'tech' ? 'true' : 'false');
      if (modeRedirectBtn) modeRedirectBtn.setAttribute('aria-selected', currentMode === 'redirect' ? 'true' : 'false');
      if (modeAccessibilityBtn) modeAccessibilityBtn.setAttribute('aria-selected', currentMode === 'accessibility' ? 'true' : 'false');
      if (modeGeoBtn) modeGeoBtn.setAttribute('aria-selected', currentMode === 'geo' ? 'true' : 'false');
      if (modeActionPlanBtn) modeActionPlanBtn.setAttribute('aria-selected', currentMode === 'action-plan' ? 'true' : 'false');
      modeHelp.textContent = getModeHelpText();
      if (currentMode === 'mesh') {
        applyMeshGraphVisibility();
      }

      if (syncUrl) {
        const url = new URL(window.location.href);
        url.searchParams.set('mode', currentMode);
        url.searchParams.set('lang', currentLang);
        window.history.replaceState({}, '', url.toString());
      }

      keepActiveModeButtonVisible();
    }

    function inferSiteRootFromUrl(value) {
      try {
        const u = new URL(String(value || '').trim());
        return `${u.protocol}//${u.host}/`;
      } catch (_err) {
        return '';
      }
    }

    function ensureUrlWithScheme(value) {
      const raw = String(value || '').trim();
      if (!raw) return '';
      if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) return raw;
      if (raw.startsWith('//')) return `https:${raw}`;
      if (raw.startsWith('/')) return raw;
      return `https://${raw}`;
    }

    function normalizeUrlInputValue(inputEl) {
      if (!inputEl || typeof inputEl.value !== 'string') return '';
      const normalized = ensureUrlWithScheme(inputEl.value);
      if (normalized && normalized !== inputEl.value) {
        inputEl.value = normalized;
      }
      return String(inputEl.value || '').trim();
    }

    function syncMeshUrlFromSitemap(inputSitemap) {
      const normalizedSitemap = ensureUrlWithScheme(inputSitemap);
      const root = inferSiteRootFromUrl(normalizedSitemap);
      if (!root) return;
      if (techUrlInput && !techUrlInput.value.trim()) {
        techUrlInput.value = root;
      }
      if (redirectUrlInput && !redirectUrlInput.value.trim()) {
        redirectUrlInput.value = root;
      }
      if (accessibilityUrlInput && !accessibilityUrlInput.value.trim()) {
        accessibilityUrlInput.value = root;
      }
      if (geoUrlInput && !geoUrlInput.value.trim()) {
        geoUrlInput.value = root;
      }
      if (!meshStartUrl.value.trim()) {
        meshStartUrl.value = root;
      } else {
        const currentRoot = inferSiteRootFromUrl(meshStartUrl.value);
        if (!currentRoot) {
          meshStartUrl.value = root;
        }
      }
    }

    function normalizeMeshStartUrl(value) {
      const raw = String(value || '').trim();
      if (!raw) return '';
      try {
        const u = new URL(raw);
        const path = String(u.pathname || '').toLowerCase();
        if (path.endsWith('.xml') && path.includes('sitemap')) {
          return `${u.protocol}//${u.host}/`;
        }
      } catch (_err) {
        return raw;
      }
      return raw;
    }

    function isValidJobId(value) {
      return /^[a-f0-9]{20}$/i.test(String(value || '').trim());
    }

    function buildShareUrl(jobId) {
      const url = new URL(window.location.href);
      url.searchParams.set('job_id', jobId);
      url.searchParams.delete('mesh_id');
      url.searchParams.set('lang', currentLang);
      url.searchParams.set('mode', 'sitemap');
      return url.toString();
    }

    function buildMeshShareUrl(meshId) {
      const url = new URL(window.location.href);
      url.searchParams.set('mesh_id', meshId);
      url.searchParams.delete('job_id');
      url.searchParams.set('lang', currentLang);
      url.searchParams.set('mode', 'mesh');
      return url.toString();
    }

    function setShareFeedback(message, isError = false) {
      if (!message) {
        shareFeedback.style.display = 'none';
        shareFeedback.textContent = '';
        shareFeedback.style.color = '';
        return;
      }
      shareFeedback.style.display = 'block';
      shareFeedback.textContent = message;
      shareFeedback.style.color = isError ? '#b91c1c' : '';
    }

    function updateShareTarget(jobId, syncAddressBar = true) {
      if (!isValidJobId(jobId)) {
        shareReportBtn.style.display = 'none';
        shareReportBtn.dataset.shareUrl = '';
        return;
      }

      const shareUrl = buildShareUrl(jobId);
      shareReportBtn.dataset.shareUrl = shareUrl;
      shareReportBtn.style.display = 'inline-block';

      if (syncAddressBar) {
        const url = new URL(window.location.href);
        url.searchParams.set('job_id', jobId);
        url.searchParams.delete('mesh_id');
        url.searchParams.set('lang', currentLang);
        url.searchParams.set('mode', 'sitemap');
        window.history.replaceState({}, '', url.toString());
      }
    }

    function setShareMeshFeedback(message, isError = false) {
      if (!message) {
        shareMeshFeedback.style.display = 'none';
        shareMeshFeedback.textContent = '';
        shareMeshFeedback.style.color = '';
        return;
      }
      shareMeshFeedback.style.display = 'block';
      shareMeshFeedback.textContent = message;
      shareMeshFeedback.style.color = isError ? '#b91c1c' : '';
    }

    function updateMeshShareTarget(meshId, syncAddressBar = true) {
      if (!isValidJobId(meshId)) {
        shareMeshBtn.style.display = 'none';
        shareMeshBtn.dataset.shareUrl = '';
        return;
      }

      const shareUrl = buildMeshShareUrl(meshId);
      shareMeshBtn.dataset.shareUrl = shareUrl;
      shareMeshBtn.style.display = 'inline-block';

      if (syncAddressBar) {
        const url = new URL(window.location.href);
        url.searchParams.set('mesh_id', meshId);
        url.searchParams.delete('job_id');
        url.searchParams.set('lang', currentLang);
        url.searchParams.set('mode', 'mesh');
        window.history.replaceState({}, '', url.toString());
      }
    }

    async function copyTextToClipboard(text) {
      const value = String(text || '');
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        return;
      }
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.setAttribute('readonly', 'readonly');
      ta.style.position = 'fixed';
      ta.style.top = '-1000px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    function setRunningState(running) {
      runBtn.disabled = running;
      runBtn.textContent = running ? t('run_btn_running') : t('run_btn_idle');
    }

async function parseApiJsonResponse(res, nonJsonErrorKey, badGatewayKey) {
      const raw = await res.text();
      try {
        return JSON.parse(raw);
      } catch (_err) {
        const compact = String(raw || '').replace(/\s+/g, ' ').trim();
        const snippet = compact ? compact.slice(0, 140) : '';
        if (!res.ok) {
          throw new Error(t(badGatewayKey, { status: res.status, snippet }));
        }
        throw new Error(t(nonJsonErrorKey, { status: res.status, snippet }));
      }
    }
