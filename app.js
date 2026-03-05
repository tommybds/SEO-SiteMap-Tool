    const form = document.getElementById('audit-form');
    const runBtn = document.getElementById('run-btn');
    const formError = document.getElementById('form-error');
    const modeSitemapBtn = document.getElementById('mode-sitemap-btn');
    const modeMeshBtn = document.getElementById('mode-mesh-btn');
    const modeTechBtn = document.getElementById('mode-tech-btn');
    const modeRedirectBtn = document.getElementById('mode-redirect-btn');
    const modeGeoBtn = document.getElementById('mode-geo-btn');
    const modeHelp = document.getElementById('mode-help');
    const sitemapModePanel = document.getElementById('sitemap-mode-panel');
    const meshModePanel = document.getElementById('mesh-mode-panel');
    const techModePanel = document.getElementById('tech-mode-panel');
    const redirectModePanel = document.getElementById('redirect-mode-panel');
    const geoModePanel = document.getElementById('geo-mode-panel');
    const meshForm = document.getElementById('mesh-form');
    const meshRunBtn = document.getElementById('mesh-run-btn');
    const meshFormError = document.getElementById('mesh-form-error');
    const meshStartUrl = document.getElementById('mesh_start_url');
    const meshMaxPages = document.getElementById('mesh_max_pages');
    const meshTimeout = document.getElementById('mesh_timeout');
    const techForm = document.getElementById('tech-form');
    const techRunBtn = document.getElementById('tech-run-btn');
    const techFormError = document.getElementById('tech-form-error');
    const techUrlInput = document.getElementById('tech_url');
    const techTimeoutInput = document.getElementById('tech_timeout');
    const redirectForm = document.getElementById('redirect-form');
    const redirectRunBtn = document.getElementById('redirect-run-btn');
    const redirectFormError = document.getElementById('redirect-form-error');
    const redirectUrlInput = document.getElementById('redirect_url');
    const redirectTimeoutInput = document.getElementById('redirect_timeout');
    const geoForm = document.getElementById('geo-form');
    const geoRunBtn = document.getElementById('geo-run-btn');
    const geoFormError = document.getElementById('geo-form-error');
    const geoUrlInput = document.getElementById('geo_url');
    const geoTimeoutInput = document.getElementById('geo_timeout');
    const resultCard = document.getElementById('result-card');
    const meshCard = document.getElementById('mesh-card');
    const techCard = document.getElementById('tech-card');
    const redirectCard = document.getElementById('redirect-card');
    const geoCard = document.getElementById('geo-card');
    const meshSectionTitle = document.getElementById('mesh-section-title');
    const techSectionTitle = document.getElementById('tech-section-title');
    const redirectSectionTitle = document.getElementById('redirect-section-title');
    const geoSectionTitle = document.getElementById('geo-section-title');
    const meshStatusBox = document.getElementById('mesh-status-box');
    const techStatusBox = document.getElementById('tech-status-box');
    const redirectStatusBox = document.getElementById('redirect-status-box');
    const geoStatusBox = document.getElementById('geo-status-box');
    const meshInteractionHint = document.getElementById('mesh-interaction-hint');
    const shareMeshBtn = document.getElementById('share-mesh-btn');
    const shareMeshFeedback = document.getElementById('share-mesh-feedback');
    const meshToggleGraphBtn = document.getElementById('mesh-toggle-graph-btn');
    const meshResetFocusBtn = document.getElementById('mesh-reset-focus-btn');
    const meshResetViewBtn = document.getElementById('mesh-reset-view-btn');
    const meshGraph = document.getElementById('mesh-graph');
    const meshHoverTooltip = document.getElementById('mesh-hover-tooltip');
    const meshMeta = document.getElementById('mesh-meta');
    const meshKpis = document.getElementById('mesh-kpis');
    const meshWarnings = document.getElementById('mesh-warnings');
    const meshActions = document.getElementById('mesh-actions');
    const meshOpportunities = document.getElementById('mesh-opportunities');
    const meshSummary = document.getElementById('mesh-summary');
    const meshErrors = document.getElementById('mesh-errors');
    const techKpis = document.getElementById('tech-kpis');
    const techChecks = document.getElementById('tech-checks');
    const techRecos = document.getElementById('tech-recos');
    const redirectKpis = document.getElementById('redirect-kpis');
    const redirectChecks = document.getElementById('redirect-checks');
    const redirectRecos = document.getElementById('redirect-recos');
    const geoKpis = document.getElementById('geo-kpis');
    const geoChecks = document.getElementById('geo-checks');
    const geoRecos = document.getElementById('geo-recos');
    const statusBox = document.getElementById('status-box');
    const logTail = document.getElementById('log-tail');
    const runError = document.getElementById('run-error');
    const downloadLink = document.getElementById('download-link');
    const conflictsDownloadLink = document.getElementById('conflicts-download-link');
    const shareReportBtn = document.getElementById('share-report-btn');
    const shareFeedback = document.getElementById('share-feedback');
    const summary = document.getElementById('summary');
    const kpiTotal = document.getElementById('kpi-total');
    const kpiOk = document.getElementById('kpi-ok');
    const kpiKo = document.getElementById('kpi-ko');
    const insightsBox = document.getElementById('insights-box');
    const insightsList = document.getElementById('insights-list');
    const topIssuesBox = document.getElementById('top-issues-box');
    const domainOverviewBox = document.getElementById('domain-overview-box');
    const previewCard = document.getElementById('preview-card');
    const previewMeta = document.getElementById('preview-meta');
    const previewError = document.getElementById('preview-error');
    const tableWrap = document.getElementById('table-wrap');
    const diffBox = document.getElementById('diff-box');
    const historyBox = document.getElementById('history-box');
    const filterIssue = document.getElementById('filter-issue');
    const filterStatus = document.getElementById('filter-status');
    const filterIndexable = document.getElementById('filter-indexable');
    const filterPriority = document.getElementById('filter-priority');
    const resetFiltersBtn = document.getElementById('reset-filters-btn');
    const langFrBtn = document.getElementById('lang-fr-btn');
    const langEnBtn = document.getElementById('lang-en-btn');
    const metaDescriptionTag = document.getElementById('meta-description');
    const appTitle = document.getElementById('app-title');
    const appSubtitle = document.getElementById('app-subtitle');
    const labelSitemap = document.getElementById('label-sitemap');
    const labelMaxUrls = document.getElementById('label-max-urls');
    const labelWorkers = document.getElementById('label-workers');
    const labelTimeout = document.getElementById('label-timeout');
    const labelSkipRobotsText = document.getElementById('label-skip-robots-text');
    const labelMeshStartUrl = document.getElementById('label-mesh-start-url');
    const labelMeshMaxPages = document.getElementById('label-mesh-max-pages');
    const labelMeshTimeout = document.getElementById('label-mesh-timeout');
    const labelTechUrl = document.getElementById('label-tech-url');
    const labelTechTimeout = document.getElementById('label-tech-timeout');
    const labelRedirectUrl = document.getElementById('label-redirect-url');
    const labelRedirectTimeout = document.getElementById('label-redirect-timeout');
    const labelGeoUrl = document.getElementById('label-geo-url');
    const labelGeoTimeout = document.getElementById('label-geo-timeout');
    const jobSectionTitle = document.getElementById('job-section-title');
    const kpiTotalLabel = document.getElementById('kpi-total-label');
    const kpiOkLabel = document.getElementById('kpi-ok-label');
    const kpiKoLabel = document.getElementById('kpi-ko-label');
    const insightsTitle = document.getElementById('insights-title');
    const logsSummary = document.getElementById('logs-summary');
    const previewTitle = document.getElementById('preview-title');
    const filterIssueLabel = document.getElementById('filter-issue-label');
    const filterHttpLabel = document.getElementById('filter-http-label');
    const filterIndexableLabel = document.getElementById('filter-indexable-label');
    const filterPriorityLabel = document.getElementById('filter-priority-label');
    const footerCreditPrefix = document.getElementById('footer-credit-prefix');
    const hasTechMode = Boolean(modeTechBtn && techModePanel && techForm && techRunBtn && techCard);
    const hasRedirectMode = Boolean(modeRedirectBtn && redirectModePanel && redirectForm && redirectRunBtn && redirectCard);
    const hasGeoMode = Boolean(modeGeoBtn && geoModePanel && geoForm && geoRunBtn && geoCard);

    let pollTimer = null;
    let meshPollTimer = null;
    let previewLoadedFor = null;
    let previewDataset = [];
    let previewHeaders = [];
    let previewTotalRows = 0;
    let previewTruncated = false;
    let currentSort = { key: 'priority_score', direction: 'desc' };
    let latestStatusPayload = null;
    let currentLang = 'fr';
    let currentMode = 'sitemap';
    let sitemapHasOutput = false;
    let latestMeshPayload = null;
    let latestTechPayload = null;
    let latestRedirectPayload = null;
    let latestGeoPayload = null;
    let meshGraphController = null;
    let meshClearSelection = null;
    let meshResetView = null;
    let meshOpportunityState = {
      sortKey: 'impact_score',
      direction: 'desc',
      quickWinsOnly: false,
      contextualOnly: false,
      minConfidence: 0,
    };
    let meshGraphVisible = false;

    const I18N = window.SEO_TOOL_I18N || { fr: {}, en: {} };

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
      if (modeGeoBtn) modeGeoBtn.textContent = t('mode_geo');
      modeHelp.textContent = currentMode === 'tech'
        ? t('mode_help_tech')
        : (currentMode === 'redirect'
          ? t('mode_help_redirect')
          : (currentMode === 'geo' ? t('mode_help_geo') : t('mode_help')));
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
      if (labelGeoUrl) labelGeoUrl.textContent = t('label_geo_url');
      if (labelGeoTimeout) labelGeoTimeout.textContent = t('label_geo_timeout');
      jobSectionTitle.textContent = t('job_section_title');
      meshSectionTitle.textContent = t('mesh_section_title');
      if (techSectionTitle) techSectionTitle.textContent = t('tech_section_title');
      if (redirectSectionTitle) redirectSectionTitle.textContent = t('redirect_section_title');
      if (geoSectionTitle) geoSectionTitle.textContent = t('geo_section_title');
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
      if (modeGeoBtn) modeGeoBtn.classList.toggle('active', currentMode === 'geo');
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');
      if (modeTechBtn) modeTechBtn.setAttribute('aria-selected', currentMode === 'tech' ? 'true' : 'false');
      if (modeRedirectBtn) modeRedirectBtn.setAttribute('aria-selected', currentMode === 'redirect' ? 'true' : 'false');
      if (modeGeoBtn) modeGeoBtn.setAttribute('aria-selected', currentMode === 'geo' ? 'true' : 'false');
      setRunningState(runBtn.disabled);
      setMeshRunningState(meshRunBtn.disabled);
      if (techRunBtn) setTechRunningState(techRunBtn.disabled);
      if (redirectRunBtn) setRedirectRunningState(redirectRunBtn.disabled);
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
      if (latestGeoPayload) {
        renderGeo(latestGeoPayload);
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
      if (mode === 'geo') return 'geo';
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

    function setMode(mode, syncUrl = true) {
      currentMode = mode === 'mesh' || mode === 'tech' || mode === 'redirect' || mode === 'geo' ? mode : 'sitemap';
      if (currentMode === 'tech' && !hasTechMode) {
        currentMode = 'sitemap';
      }
      if (currentMode === 'redirect' && !hasRedirectMode) {
        currentMode = 'sitemap';
      }
      if (currentMode === 'geo' && !hasGeoMode) {
        currentMode = 'sitemap';
      }
      sitemapModePanel.style.display = currentMode === 'sitemap' ? 'block' : 'none';
      meshModePanel.style.display = currentMode === 'mesh' ? 'block' : 'none';
      if (techModePanel) techModePanel.style.display = currentMode === 'tech' ? 'block' : 'none';
      if (redirectModePanel) redirectModePanel.style.display = currentMode === 'redirect' ? 'block' : 'none';
      if (geoModePanel) geoModePanel.style.display = currentMode === 'geo' ? 'block' : 'none';
      resultCard.style.display = currentMode === 'sitemap' && sitemapHasOutput ? 'block' : 'none';
      previewCard.style.display = currentMode === 'sitemap' && previewLoadedFor ? 'block' : 'none';
      meshCard.style.display = currentMode === 'mesh' && !!latestMeshPayload ? 'block' : 'none';
      if (techCard) techCard.style.display = currentMode === 'tech' && !!latestTechPayload ? 'block' : 'none';
      if (redirectCard) redirectCard.style.display = currentMode === 'redirect' && !!latestRedirectPayload ? 'block' : 'none';
      if (geoCard) geoCard.style.display = currentMode === 'geo' && !!latestGeoPayload ? 'block' : 'none';
      modeSitemapBtn.classList.toggle('active', currentMode === 'sitemap');
      modeMeshBtn.classList.toggle('active', currentMode === 'mesh');
      if (modeTechBtn) modeTechBtn.classList.toggle('active', currentMode === 'tech');
      if (modeRedirectBtn) modeRedirectBtn.classList.toggle('active', currentMode === 'redirect');
      if (modeGeoBtn) modeGeoBtn.classList.toggle('active', currentMode === 'geo');
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');
      if (modeTechBtn) modeTechBtn.setAttribute('aria-selected', currentMode === 'tech' ? 'true' : 'false');
      if (modeRedirectBtn) modeRedirectBtn.setAttribute('aria-selected', currentMode === 'redirect' ? 'true' : 'false');
      if (modeGeoBtn) modeGeoBtn.setAttribute('aria-selected', currentMode === 'geo' ? 'true' : 'false');
      modeHelp.textContent = currentMode === 'tech'
        ? t('mode_help_tech')
        : (currentMode === 'redirect'
          ? t('mode_help_redirect')
          : (currentMode === 'geo' ? t('mode_help_geo') : t('mode_help')));
      if (currentMode === 'mesh') {
        applyMeshGraphVisibility();
      }

      if (syncUrl) {
        const url = new URL(window.location.href);
        url.searchParams.set('mode', currentMode);
        url.searchParams.set('lang', currentLang);
        window.history.replaceState({}, '', url.toString());
      }
    }

    function inferSiteRootFromUrl(value) {
      try {
        const u = new URL(String(value || '').trim());
        return `${u.protocol}//${u.host}/`;
      } catch (_err) {
        return '';
      }
    }

    function syncMeshUrlFromSitemap(inputSitemap) {
      const root = inferSiteRootFromUrl(inputSitemap);
      if (!root) return;
      if (techUrlInput && !techUrlInput.value.trim()) {
        techUrlInput.value = root;
      }
      if (redirectUrlInput && !redirectUrlInput.value.trim()) {
        redirectUrlInput.value = root;
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

    function clearPreview() {
      previewLoadedFor = null;
      previewCard.style.display = 'none';
      previewMeta.textContent = '';
      previewError.textContent = '';
      tableWrap.textContent = '';
      previewDataset = [];
      previewHeaders = [];
      previewTotalRows = 0;
      previewTruncated = false;
      currentSort = { key: 'priority_score', direction: 'desc' };
    }

    function clearInsights() {
      insightsBox.style.display = 'none';
      insightsList.innerHTML = '';
      topIssuesBox.innerHTML = '';
      domainOverviewBox.innerHTML = '';
    }

    function normalizeText(value) {
      return String(value || '').trim().toLowerCase();
    }

    function updateInsightPriorityChipStates() {
      const activePriority = normalizeText(filterPriority.value);
      const activeIssue = normalizeText(filterIssue.value);
      const chips = insightsList.querySelectorAll('.insight-chip.insight-chip-clickable');
      chips.forEach((chip) => {
        const priorityFilter = normalizeText(chip.getAttribute('data-priority-filter') || '');
        const isConflictsChip = chip.getAttribute('data-conflicts-filter') === '1';
        let isActive = false;

        if (priorityFilter) {
          isActive = activePriority === priorityFilter;
        } else if (isConflictsChip) {
          isActive = activeIssue.includes('conflit') || activeIssue.includes('conflict');
        }

        chip.classList.toggle('is-active', isActive);
        chip.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      });
    }

    function applyPriorityFilterFromInsight(priorityValue) {
      const target = normalizeText(priorityValue);
      if (!target) return;

      const current = normalizeText(filterPriority.value);
      filterPriority.value = current === target ? 'all' : target;
      applyPreviewFilters();
      updateInsightPriorityChipStates();

      if (previewCard && previewCard.style.display !== 'none') {
        previewCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      filterPriority.focus();
    }

    function applyConflictsFilterFromInsight() {
      const conflictNeedle = currentLang === 'en' ? 'conflict' : 'conflit';
      const currentIssue = normalizeText(filterIssue.value);
      filterIssue.value = currentIssue.includes('conflit') || currentIssue.includes('conflict') ? '' : conflictNeedle;
      applyPreviewFilters();
      updateInsightPriorityChipStates();
      updateInsightIssueTagStates();

      if (previewCard && previewCard.style.display !== 'none') {
        previewCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      filterIssue.focus();
      filterIssue.select();
    }

    function updateInsightIssueTagStates() {
      const activeNeedle = normalizeText(filterIssue.value);
      const tags = topIssuesBox.querySelectorAll('.issue-tag.issue-tag-clickable[data-issue-filter]');
      tags.forEach((tag) => {
        const issueLabel = normalizeText(tag.getAttribute('data-issue-filter') || '');
        const isActive = !!activeNeedle && issueLabel === activeNeedle;
        tag.classList.toggle('is-active', isActive);
        tag.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      });
    }

    function applyIssueFilterFromInsight(issueLabel) {
      const label = String(issueLabel || '').trim();
      if (!label) return;

      const current = normalizeText(filterIssue.value);
      const next = normalizeText(label);
      filterIssue.value = current === next ? '' : label;

      applyPreviewFilters();
      updateInsightIssueTagStates();

      if (previewCard && previewCard.style.display !== 'none') {
        previewCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      filterIssue.focus();
      filterIssue.select();
    }

    function renderDiff(payload) {
      const scanDiff = payload.scan_diff;
      if (!scanDiff || !scanDiff.diff) {
        diffBox.style.display = 'none';
        diffBox.innerHTML = '';
        return;
      }

      const d = scanDiff.diff;
      const metrics = [
        { label: t('diff_new_issue_urls'), value: Number(d.new_issue_urls || 0) },
        { label: t('diff_resolved_issue_urls'), value: Number(d.resolved_issue_urls || 0) },
        { label: t('diff_changed_issue_urls'), value: Number(d.changed_issue_urls || 0) },
        { label: t('diff_added_urls'), value: Number(d.added_urls || 0) },
        { label: t('diff_removed_urls'), value: Number(d.removed_urls || 0) }
      ];

      diffBox.style.display = 'block';
      diffBox.innerHTML = '';

      const title = document.createElement('strong');
      title.className = 'diff-title';
      title.textContent = t('diff_title', { job_id: scanDiff.previous_job_id || 'N/A' });
      diffBox.appendChild(title);

      const grid = document.createElement('div');
      grid.className = 'diff-grid';

      metrics.forEach((metric) => {
        const item = document.createElement('div');
        item.className = 'diff-item';

        const label = document.createElement('span');
        label.className = 'diff-item-label';
        label.textContent = metric.label;

        const value = document.createElement('span');
        value.className = 'diff-item-value';
        value.textContent = String(metric.value);

        item.appendChild(label);
        item.appendChild(value);
        grid.appendChild(item);
      });

      diffBox.appendChild(grid);
    }

    function renderHistory(payload) {
      const runs = Array.isArray(payload.recent_runs) ? payload.recent_runs : [];
      if (!runs.length) {
        historyBox.textContent = '';
        return;
      }

      historyBox.innerHTML = '';
      const title = document.createElement('strong');
      title.textContent = t('history_title');
      const list = document.createElement('ul');
      list.className = 'history-list';

      runs.slice(0, 8).forEach((run) => {
        const li = document.createElement('li');
        const sum = run.summary || {};
        li.textContent = t('history_item', {
          job_id: run.job_id || '',
          date: run.completed_at || run.created_at || '',
          total: sum.total || 0,
          issues: sum.with_issues || 0
        });
        list.appendChild(li);
      });

      historyBox.appendChild(title);
      historyBox.appendChild(list);
    }

    function renderInsights(payload) {
      const insights = payload.insights || null;
      if (!insights) {
        clearInsights();
        return;
      }

      const p = insights.priority_counts || {};
      const topIssues = Array.isArray(insights.top_issues) ? insights.top_issues : [];
      const topConflictReasons = Array.isArray(insights.top_conflict_reasons) ? insights.top_conflict_reasons : [];

      insightsBox.style.display = 'block';
      insightsList.innerHTML = '';
      topIssuesBox.innerHTML = '';

      const priorityItems = [
        { label: t('insights_priority_critical'), key: 'critical', className: 'insight-chip-critical' },
        { label: t('insights_priority_high'), key: 'high', className: 'insight-chip-high' },
        { label: t('insights_priority_medium'), key: 'medium', className: 'insight-chip-medium' },
        { label: t('insights_priority_low'), key: 'low', className: 'insight-chip-low' },
        { label: t('insights_priority_none'), key: 'none', className: 'insight-chip-none' }
      ];

      priorityItems.forEach((item) => {
        const li = document.createElement('li');
        li.className = `insight-chip ${item.className}`;
        li.classList.add('insight-chip-clickable');
        li.setAttribute('role', 'button');
        li.setAttribute('tabindex', '0');
        li.setAttribute('aria-pressed', 'false');
        li.setAttribute('data-priority-filter', item.key);
        li.title = t('insights_priority_filter_cta', { priority: item.label });
        li.addEventListener('click', () => applyPriorityFilterFromInsight(item.key));
        li.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            applyPriorityFilterFromInsight(item.key);
          }
        });

        const label = document.createElement('span');
        label.className = 'insight-chip-label';
        label.textContent = item.label;

        const value = document.createElement('span');
        value.className = 'insight-chip-value';
        value.textContent = String(Number(p[item.key] || 0));

        li.appendChild(label);
        li.appendChild(value);
        insightsList.appendChild(li);
      });

      const conflictsLi = document.createElement('li');
      conflictsLi.className = 'insight-chip insight-chip-conflicts';
      conflictsLi.classList.add('insight-chip-clickable');
      conflictsLi.setAttribute('role', 'button');
      conflictsLi.setAttribute('tabindex', '0');
      conflictsLi.setAttribute('aria-pressed', 'false');
      conflictsLi.setAttribute('data-conflicts-filter', '1');
      conflictsLi.title = t('insights_conflicts_filter_cta');
      conflictsLi.addEventListener('click', () => applyConflictsFilterFromInsight());
      conflictsLi.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          applyConflictsFilterFromInsight();
        }
      });
      const conflictsLabel = document.createElement('span');
      conflictsLabel.className = 'insight-chip-label';
      conflictsLabel.textContent = t('insights_conflicts_label');
      const conflictsValue = document.createElement('span');
      conflictsValue.className = 'insight-chip-value';
      conflictsValue.textContent = String(Number(insights.conflicts_count || 0));
      conflictsLi.appendChild(conflictsLabel);
      conflictsLi.appendChild(conflictsValue);
      insightsList.appendChild(conflictsLi);

      function normalizeInsightLabel(label) {
        const raw = String(label || 'N/A').trim();
        const normalized = raw.replace(/\s*\((?:\d+[^)]*)\)\s*$/i, '').trim();
        return normalized || raw;
      }

      function groupSimilarRows(rows, textKey) {
        const grouped = new Map();

        rows.forEach((row) => {
          const original = String(row[textKey] || 'N/A').trim();
          const normalized = normalizeInsightLabel(original);
          const count = Number(row.count || 0);
          const existing = grouped.get(normalized);

          if (existing) {
            existing.count += count;
            if (!existing.variants.includes(original)) {
              existing.variants.push(original);
            }
          } else {
            grouped.set(normalized, {
              label: normalized,
              count,
              variants: [original]
            });
          }
        });

        return Array.from(grouped.values()).sort((a, b) => {
          if (b.count !== a.count) return b.count - a.count;
          return a.label.localeCompare(b.label, currentLang);
        });
      }

      function appendTagGroup(title, rows, textKey, groupSimilar = false, makeClickable = false) {
        if (!rows.length) return;

        const displayRows = groupSimilar ? groupSimilarRows(rows, textKey) : rows.map((row) => ({
          label: String(row[textKey] || 'N/A'),
          count: Number(row.count || 0),
          variants: [String(row[textKey] || 'N/A')]
        }));

        if (!displayRows.length) return;

        const group = document.createElement('div');
        group.className = 'insight-group';

        const heading = document.createElement('div');
        heading.className = 'insight-group-title';
        heading.textContent = title;
        group.appendChild(heading);

        const tags = document.createElement('div');
        tags.className = 'issue-tags';

        displayRows.slice(0, 10).forEach((row) => {
          const tag = document.createElement('span');
          tag.className = 'issue-tag';
          if (makeClickable) {
            const issueFilter = String(row.label || '').trim();
            if (issueFilter) {
              tag.classList.add('issue-tag-clickable');
              tag.setAttribute('role', 'button');
              tag.setAttribute('tabindex', '0');
              tag.setAttribute('data-issue-filter', issueFilter);
              tag.setAttribute('aria-pressed', 'false');
              tag.title = t('insights_issue_filter_cta', { issue: issueFilter });
              tag.addEventListener('click', () => applyIssueFilterFromInsight(issueFilter));
              tag.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  applyIssueFilterFromInsight(issueFilter);
                }
              });
            }
          }

          const text = document.createElement('span');
          text.textContent = row.label;
          text.title = row.variants.join(' · ');

          const count = document.createElement('b');
          count.textContent = String(Number(row.count || 0));

          tag.appendChild(text);
          tag.appendChild(count);
          tags.appendChild(tag);
        });

        group.appendChild(tags);
        topIssuesBox.appendChild(group);
      }

      appendTagGroup(t('insights_top_issues'), topIssues, 'issue', true, true);
      appendTagGroup(t('insights_top_conflict_reasons'), topConflictReasons, 'reason');
      if (!topIssuesBox.children.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = t('insights_empty');
        topIssuesBox.appendChild(empty);
      }
      renderDomainOverview(insights.domain_overview || null);
      updateInsightIssueTagStates();
      updateInsightPriorityChipStates();
    }

    function localizeDomainAction(actionKey) {
      const key = String(actionKey || '').trim().toLowerCase();
      if (key === 'fix_sitemap_indexation_conflicts') return t('domain_action_fix_sitemap_indexation_conflicts');
      if (key === 'fix_non_200_in_sitemap') return t('domain_action_fix_non_200_in_sitemap');
      if (key === 'fix_robots_blocked_in_sitemap') return t('domain_action_fix_robots_blocked_in_sitemap');
      if (key === 'fix_noindex_in_sitemap') return t('domain_action_fix_noindex_in_sitemap');
      if (key === 'fix_cross_domain_canonicals') return t('domain_action_fix_cross_domain_canonicals');
      if (key === 'add_x_default_hreflang') return t('domain_action_add_x_default_hreflang');
      return key || '-';
    }

    function renderDomainOverview(domain) {
      domainOverviewBox.innerHTML = '';
      if (!domain || typeof domain !== 'object') return;

      const totals = domain.totals && typeof domain.totals === 'object' ? domain.totals : {};
      const rates = domain.rates && typeof domain.rates === 'object' ? domain.rates : {};
      const sections = Array.isArray(domain.top_sections) ? domain.top_sections : [];
      const actions = Array.isArray(domain.actions) ? domain.actions : [];

      const title = document.createElement('div');
      title.className = 'domain-overview-title';
      title.textContent = t('domain_overview_title');

      const kpis = document.createElement('div');
      kpis.className = 'domain-kpis';
      const kpiEntries = [
        { value: `${Number(rates.indexable_pct || 0).toFixed(1)}%`, label: t('domain_kpi_indexable_pct') },
        { value: String(Number(totals.non_200 || 0)), label: t('domain_kpi_non_200') },
        { value: String(Number(totals.conflicts || 0)), label: t('domain_kpi_conflicts') },
        { value: String(Number(totals.robots_blocked || 0)), label: t('domain_kpi_robots_blocked') },
        { value: String(Number(totals.noindex || 0)), label: t('domain_kpi_noindex') },
        { value: String(Number(totals.canonical_cross_domain || 0)), label: t('domain_kpi_canonical_cross_domain') },
      ];
      kpiEntries.forEach((entry) => {
        const el = document.createElement('div');
        el.className = 'domain-kpi';
        el.innerHTML = `<span class="domain-kpi-value">${escapeHtml(entry.value)}</span><span class="domain-kpi-label">${escapeHtml(entry.label)}</span>`;
        kpis.appendChild(el);
      });

      const grid = document.createElement('div');
      grid.className = 'domain-grid';

      const sectionsBox = document.createElement('div');
      sectionsBox.className = 'domain-box';
      const sectionsTitle = document.createElement('strong');
      sectionsTitle.className = 'domain-box-title';
      sectionsTitle.textContent = t('domain_sections_title');
      sectionsBox.appendChild(sectionsTitle);

      if (!sections.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = t('domain_sections_empty');
        sectionsBox.appendChild(empty);
      } else {
        const rows = sections.slice(0, 6).map((row) => `
          <tr>
            <td>${escapeHtml(String(row.section || '/'))}</td>
            <td>${escapeHtml(String(Number(row.urls || 0)))}</td>
            <td>${escapeHtml(String(Number(row.with_issues || 0)))}</td>
            <td>${escapeHtml(`${Number(row.issue_rate || 0).toFixed(1)}%`)}</td>
            <td title="${escapeHtml(String(row.top_issue || ''))}">${escapeHtml(String(row.top_issue || '-'))}</td>
          </tr>
        `).join('');

        sectionsBox.innerHTML += `
          <table class="domain-table">
            <thead>
              <tr>
                <th>${escapeHtml(t('domain_col_section'))}</th>
                <th>${escapeHtml(t('domain_col_urls'))}</th>
                <th>${escapeHtml(t('domain_col_issues'))}</th>
                <th>${escapeHtml(t('domain_col_issue_rate'))}</th>
                <th>${escapeHtml(t('domain_col_top_issue'))}</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        `;
      }

      const actionsBox = document.createElement('div');
      actionsBox.className = 'domain-box';
      const actionsTitle = document.createElement('strong');
      actionsTitle.className = 'domain-box-title';
      actionsTitle.textContent = t('domain_actions_title');
      actionsBox.appendChild(actionsTitle);

      if (!actions.length) {
        const empty = document.createElement('div');
        empty.className = 'muted';
        empty.textContent = t('domain_actions_empty');
        actionsBox.appendChild(empty);
      } else {
        const list = document.createElement('ul');
        list.className = 'domain-actions';
        actions.slice(0, 6).forEach((action) => {
          const count = Number(action.count || 0);
          const label = localizeDomainAction(action.action_key);
          const li = document.createElement('li');
          li.textContent = t('domain_action_item', { label, count });
          list.appendChild(li);
        });
        actionsBox.appendChild(list);
      }

      grid.appendChild(sectionsBox);
      grid.appendChild(actionsBox);

      domainOverviewBox.appendChild(title);
      domainOverviewBox.appendChild(kpis);
      domainOverviewBox.appendChild(grid);
    }

    function renderStatus(payload) {
      latestStatusPayload = payload;
      sitemapHasOutput = true;
      const parts = [
        `${t('status_job')}: ${payload.job_id}`,
        `${t('status_status')}: ${localizeStatus(payload.status)}`,
        payload.sitemap ? `${t('status_sitemap')}: ${payload.sitemap}` : '',
        payload.started_at ? `${t('status_started')}: ${payload.started_at}` : '',
        payload.completed_at ? `${t('status_completed')}: ${payload.completed_at}` : ''
      ].filter(Boolean);
      statusBox.textContent = parts.join('\n');
      updateShareTarget(payload.job_id);
      syncMeshUrlFromSitemap(payload.sitemap || '');

      const logLines = Array.isArray(payload.log_tail) ? payload.log_tail : [];
      logTail.textContent = logLines.length ? logLines.join('\n') : t('no_logs_yet');

      if (payload.status === 'completed') {
        const total = Number(payload.summary?.total || 0);
        const withIssues = Number(payload.summary?.with_issues || 0);
        const withoutIssues = Number(payload.summary?.without_issues || 0);
        summary.style.display = 'grid';
        kpiTotal.textContent = String(total);
        kpiOk.textContent = String(withoutIssues);
        kpiKo.textContent = String(withIssues);
      }

      if (payload.report_exists) {
        downloadLink.style.display = 'inline-block';
        downloadLink.href = payload.download_url;
      }
      if (payload.conflicts_report_exists) {
        conflictsDownloadLink.style.display = 'inline-block';
        conflictsDownloadLink.href = payload.conflicts_download_url;
      } else {
        conflictsDownloadLink.style.display = 'none';
      }

      renderInsights(payload);
      renderDiff(payload);
      renderHistory(payload);
    }

    function abbreviatePath(url) {
      try {
        const u = new URL(String(url || ''));
        const path = u.pathname || '/';
        if (path.length <= 42) return path;
        return `${path.slice(0, 39)}...`;
      } catch (_err) {
        const raw = String(url || '');
        return raw.length <= 42 ? raw : `${raw.slice(0, 39)}...`;
      }
    }

    function localizeMeshSeedMode(mode) {
      const raw = String(mode || '').toLowerCase();
      if (raw === 'sitemap_start') return t('mesh_seed_sitemap_start');
      if (raw === 'crawl_plus_sitemap_discovery') return t('mesh_seed_discovery');
      return t('mesh_seed_crawl_only');
    }

    function localizeMeshPriority(priority) {
      const raw = String(priority || '').toLowerCase();
      if (raw === 'high') return t('mesh_priority_high');
      if (raw === 'medium') return t('mesh_priority_medium');
      if (raw === 'low') return t('mesh_priority_low');
      return t('mesh_priority_low');
    }

    function localizeMeshIssue(issueType) {
      const raw = String(issueType || '').toLowerCase();
      if (raw === 'orphan_no_inbound') return t('mesh_issue_orphan_no_inbound');
      if (raw === 'dead_end_no_outbound') return t('mesh_issue_dead_end_no_outbound');
      if (raw === 'deep_weak_inbound') return t('mesh_issue_deep_weak_inbound');
      if (raw === 'template_only_inbound') return t('mesh_issue_template_only_inbound');
      if (raw === 'orphan_hreflang_only') return t('mesh_issue_orphan_hreflang_only');
      if (raw === 'hreflang_missing_reciprocal') return t('mesh_issue_hreflang_missing_reciprocal');
      return raw || '-';
    }

    function localizeMeshLinkContext(context) {
      const raw = String(context || '').toLowerCase();
      if (raw === 'menu') return t('mesh_context_menu');
      if (raw === 'footer') return t('mesh_context_footer');
      if (raw === 'breadcrumb') return t('mesh_context_breadcrumb');
      return t('mesh_context_content');
    }

    function localizeMeshSectionRelevance(value) {
      const raw = String(value || '').toLowerCase();
      if (raw === 'same_section') return t('mesh_section_same_section');
      if (raw === 'same_segment') return t('mesh_section_same_segment');
      return t('mesh_section_cross_section');
    }

    function localizeMeshConfidenceLevel(value) {
      const raw = String(value || '').toLowerCase();
      if (raw === 'high') return t('mesh_confidence_high');
      if (raw === 'medium') return t('mesh_confidence_medium');
      return t('mesh_confidence_low');
    }

    function formatMeshDepth(value) {
      if (Number.isInteger(value) && value >= 0) return String(value);
      return t('mesh_depth_unknown');
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function buildMeshUrlLink(url, label = '') {
      const safeUrl = escapeHtml(url);
      const safeLabel = escapeHtml(label || abbreviatePath(url));
      return `<a class="mesh-link" href="${safeUrl}" target="_blank" rel="noopener noreferrer" title="${safeUrl}">${safeLabel}</a>`;
    }

    function buildMeshSummaryList(rows, rowRenderer) {
      if (!rows.length) {
        return `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`;
      }
      const items = rows.slice(0, 8).map((row) => `<li>${rowRenderer(row)}</li>`).join('');
      return `<ul class="mesh-link-list">${items}</ul>`;
    }

    function buildMeshTreeText(mesh) {
      const nodes = Array.isArray(mesh.nodes) ? mesh.nodes : [];
      if (!nodes.length) return t('mesh_tree_empty');
      const reachableNodes = nodes.filter((node) => Number.isInteger(node && node.depth));
      const unreachableNodes = nodes.filter((node) => !Number.isInteger(node && node.depth));
      const treeNodes = reachableNodes.length ? reachableNodes : nodes;

      const normalizePath = (rawPath) => {
        const raw = String(rawPath || '').trim();
        if (!raw) return '/';
        const noHash = raw.split('#', 1)[0];
        const noQuery = noHash.split('?', 1)[0];
        let clean = noQuery.replace(/\/{2,}/g, '/');
        if (!clean.startsWith('/')) clean = `/${clean}`;
        if (!clean) clean = '/';
        if (clean.length > 1 && !clean.endsWith('/')) clean = `${clean}/`;
        return clean || '/';
      };
      const startPath = (() => {
        try {
          const rawStart = String(mesh && mesh.start_url ? mesh.start_url : '');
          if (!rawStart) return '/';
          const parsed = new URL(rawStart);
          return normalizePath(parsed.pathname || '/');
        } catch (_err) {
          return '/';
        }
      })();

      const nodeScore = (node) => Number(node?.inbound || 0) + Number(node?.outbound || 0);
      const toPath = (node) => {
        if (node && node.path) return normalizePath(node.path);
        try {
          const parsed = new URL(String(node?.url || ''));
          return normalizePath(parsed.pathname || '/');
        } catch (_err) {
          return '/';
        }
      };
      const pathLabel = (path, node) => {
        const inbound = Number(node?.inbound || 0);
        const outbound = Number(node?.outbound || 0);
        return `${path} (in:${inbound} out:${outbound})`;
      };

      const nodeByPath = new Map();
      treeNodes.forEach((node) => {
        if (!node || !node.url) return;
        const path = toPath(node);
        const existing = nodeByPath.get(path);
        if (!existing || nodeScore(node) > nodeScore(existing)) {
          nodeByPath.set(path, node);
        }
      });

      const root = {
        segment: '',
        path: '/',
        node: nodeByPath.get('/') || null,
        children: new Map(),
        branchWeight: 0,
      };

      const pickBestNode = (current, next) => {
        if (!current) return next;
        if (!next) return current;
        return nodeScore(next) > nodeScore(current) ? next : current;
      };

      treeNodes.forEach((node) => {
        if (!node || !node.url) return;
        const path = toPath(node);
        const parts = path === '/' ? [] : path.slice(1, -1).split('/').filter(Boolean);
        let cursor = root;
        let currentPath = '';
        parts.forEach((part) => {
          currentPath += `/${part}`;
          const childPath = `${currentPath}/`;
          if (!cursor.children.has(part)) {
            cursor.children.set(part, {
              segment: part,
              path: childPath,
              node: null,
              children: new Map(),
              branchWeight: 0,
            });
          }
          cursor = cursor.children.get(part);
        });
        cursor.node = pickBestNode(cursor.node, node);
      });

      const computeWeights = (branch) => {
        let weight = branch.node ? 1 : 0;
        branch.children.forEach((child) => {
          weight += computeWeights(child);
        });
        branch.branchWeight = weight;
        return weight;
      };
      computeWeights(root);
      const getBranchByPath = (fullPath) => {
        if (fullPath === '/') return root;
        const parts = fullPath.slice(1, -1).split('/').filter(Boolean);
        let cursor = root;
        for (const part of parts) {
          const next = cursor.children.get(part);
          if (!next) return null;
          cursor = next;
        }
        return cursor;
      };

      const sortChildren = (branch) => [...branch.children.values()].sort((a, b) => {
        if (a.branchWeight !== b.branchWeight) return b.branchWeight - a.branchWeight;
        const scoreA = nodeScore(a.node);
        const scoreB = nodeScore(b.node);
        if (scoreA !== scoreB) return scoreB - scoreA;
        return String(a.segment).localeCompare(String(b.segment), undefined, { sensitivity: 'base' });
      });

      const MAX_DEPTH = 6;
      const MAX_BRANCH_CHILDREN = 12;
      const MAX_LINES = 220;
      const startBranch = getBranchByPath(startPath) || root;
      const startLabel = startBranch.node ? pathLabel(startBranch.path, startBranch.node) : startBranch.path;
      const lines = [startLabel];

      const walk = (branch, prefix, depth) => {
        if (depth >= MAX_DEPTH || lines.length >= MAX_LINES) return;
        const children = sortChildren(branch);
        if (!children.length) return;

        const visible = children.slice(0, MAX_BRANCH_CHILDREN);
        visible.forEach((child, idx) => {
          if (lines.length >= MAX_LINES) return;
          const isLast = idx === visible.length - 1;
          const connector = isLast ? '└─ ' : '├─ ';
          const label = child.node ? pathLabel(child.path, child.node) : child.path;
          lines.push(`${prefix}${connector}${label}`);
          const nextPrefix = prefix + (isLast ? '   ' : '│  ');
          walk(child, nextPrefix, depth + 1);
        });

        if (children.length > visible.length && lines.length < MAX_LINES) {
          lines.push(`${prefix}└─ … +${children.length - visible.length}`);
        }
      };

      walk(startBranch, '', 0);

      const unreachable = unreachableNodes
        .filter((node) => node && node.url)
        .sort((a, b) => nodeScore(b) - nodeScore(a))
        .slice(0, 8);

      if (unreachable.length && lines.length < MAX_LINES) {
        lines.push('');
        lines.push(t('mesh_tree_unreachable_title'));
        unreachable.forEach((node) => {
          lines.push(`- ${pathLabel(toPath(node), node)}`);
        });
      }

      return lines.join('\n');
    }

    function renderMeshKpis(mesh) {
      const kpis = mesh && mesh.actionable && mesh.actionable.kpis ? mesh.actionable.kpis : {};
      const entries = [
        { label: t('mesh_kpi_avg_links'), value: Number(kpis.avg_links_per_page || 0).toFixed(2) },
        { label: t('mesh_kpi_orphans'), value: String(Number(kpis.orphan_pages || 0)) },
        { label: t('mesh_kpi_dead_ends'), value: String(Number(kpis.dead_end_pages || 0)) },
        { label: t('mesh_kpi_weak_inbound'), value: String(Number(kpis.weak_inbound_pages || 0)) },
        { label: t('mesh_kpi_unreachable'), value: String(Number(kpis.unreachable_from_start || 0)) },
        { label: t('mesh_kpi_hreflang_pages'), value: String(Number(kpis.hreflang_pages || 0)) },
        { label: t('mesh_kpi_hreflang_non_reciprocal'), value: String(Number(kpis.hreflang_non_reciprocal || 0)) },
        { label: t('mesh_kpi_template_dominant_targets'), value: String(Number(kpis.template_dominant_targets || 0)) },
        { label: t('mesh_kpi_template_only_inbound'), value: String(Number(kpis.template_only_inbound_pages || 0)) },
        { label: t('mesh_kpi_quick_wins'), value: String(Number(kpis.quick_wins || 0)) },
        { label: t('mesh_kpi_contextual_opportunities'), value: String(Number(kpis.contextual_opportunities || 0)) },
      ];

      meshKpis.innerHTML = '';
      entries.forEach((entry) => {
        const card = document.createElement('div');
        card.className = 'mesh-kpi';
        card.innerHTML = `<b>${entry.value}</b><span>${entry.label}</span>`;
        meshKpis.appendChild(card);
      });
    }

    function renderMeshWarnings(mesh) {
      const rendering = mesh && mesh.rendering_signals ? mesh.rendering_signals : {};
      const hreflang = mesh && mesh.hreflang ? mesh.hreflang : {};
      const linkContexts = mesh && mesh.link_context_summary ? mesh.link_context_summary : {};
      const kpis = mesh && mesh.actionable && mesh.actionable.kpis ? mesh.actionable.kpis : {};
      const warnings = [];

      if (rendering.js_app_suspected) {
        warnings.push(`${t('mesh_render_warning', { count: Number(rendering.js_like_pages_count || 0) })}\n${t('mesh_render_warning_hint')}`);
      }
      if (Number(hreflang.non_reciprocal_count || 0) > 0) {
        warnings.push(t('mesh_hreflang_warning_non_reciprocal', { count: Number(hreflang.non_reciprocal_count || 0) }));
      }
      if (Number(hreflang.orphan_hreflang_only_count || 0) > 0) {
        warnings.push(t('mesh_hreflang_warning_orphan_only', { count: Number(hreflang.orphan_hreflang_only_count || 0) }));
      }
      if (Number(hreflang.missing_x_default_count || 0) > 0) {
        warnings.push(t('mesh_hreflang_warning_x_default', { count: Number(hreflang.missing_x_default_count || 0) }));
      }
      if (Number(hreflang.invalid_entries || 0) > 0) {
        warnings.push(t('mesh_hreflang_warning_invalid', { count: Number(hreflang.invalid_entries || 0) }));
      }
      if (Number(linkContexts.template_dominant_targets || 0) > 0) {
        warnings.push(t('mesh_template_warning', { count: Number(linkContexts.template_dominant_targets || 0) }));
      }
      if (Number(kpis.template_only_inbound_pages || 0) > 0) {
        warnings.push(t('mesh_template_only_warning', { count: Number(kpis.template_only_inbound_pages || 0) }));
      }
      if (mesh && mesh.runtime_limited) {
        warnings.push(t('mesh_runtime_limited', { seconds: Math.max(1, Math.round(Number(mesh.runtime_budget_ms || 0) / 1000)) }));
      }
      const templateEdges = Number(linkContexts.menu || 0) + Number(linkContexts.footer || 0) + Number(linkContexts.breadcrumb || 0);
      const contentEdges = Number(linkContexts.content || 0);
      if (templateEdges > contentEdges && templateEdges >= 12) {
        warnings.push(t('mesh_context_warning_template_heavy'));
      }

      meshWarnings.innerHTML = '';
      warnings.forEach((text) => {
        const el = document.createElement('div');
        el.className = 'mesh-warning';
        el.textContent = text;
        meshWarnings.appendChild(el);
      });
    }

    function renderMeshActions(mesh) {
      const actionable = mesh && mesh.actionable ? mesh.actionable : {};
      const recommendations = Array.isArray(actionable.recommendations) ? actionable.recommendations : [];

      const title = t('mesh_actions_title');
      if (!recommendations.length) {
        meshActions.innerHTML = `<div class="mesh-actions-head">${title}</div><div class="mesh-actions-empty">${t('mesh_actions_empty')}</div>`;
        return;
      }

      const rows = recommendations.slice(0, 16).map((item) => {
        const priorityRaw = String(item.priority || 'low').toLowerCase();
        const priorityLabel = localizeMeshPriority(priorityRaw);
        const issueLabel = localizeMeshIssue(item.issue_type);
        let metricLabel = t('mesh_metric_format', {
          inbound: Number(item.current_inbound || 0),
          outbound: Number(item.current_outbound || 0),
          depth: formatMeshDepth(item.depth),
        });
        if (String(item.issue_type || '').toLowerCase() === 'orphan_hreflang_only') {
          metricLabel = t('mesh_metric_hreflang_orphan', {
            inbound: Number(item.current_inbound || 0),
            hreflang_inbound: Number(item.current_hreflang_inbound || 0),
            depth: formatMeshDepth(item.depth),
          });
        } else if (String(item.issue_type || '').toLowerCase() === 'hreflang_missing_reciprocal') {
          metricLabel = t('mesh_metric_hreflang_reciprocal', {
            hreflang: String(item.hreflang || '-'),
            inbound: Number(item.current_inbound || 0),
            outbound: Number(item.current_outbound || 0),
            depth: formatMeshDepth(item.depth),
          });
        }
        const sources = Array.isArray(item.suggested_sources) ? item.suggested_sources : [];
        const sourcesHtml = sources.length
          ? `<div class="mesh-sources">${sources.map((source) => `<a class="mesh-source mesh-link" href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(source.url)}">${escapeHtml(abbreviatePath(source.url))}</a>`).join('')}</div>`
          : `<span class="muted">${escapeHtml(t('mesh_sources_none'))}</span>`;

        return `
          <tr>
            <td><span class="mesh-priority ${escapeHtml(priorityRaw)}">${escapeHtml(priorityLabel)}</span></td>
            <td>${buildMeshUrlLink(item.target_url)}</td>
            <td>${escapeHtml(issueLabel)}</td>
            <td>${escapeHtml(metricLabel)}</td>
            <td>${sourcesHtml}</td>
          </tr>
        `;
      }).join('');

      meshActions.innerHTML = `
        <div class="mesh-actions-head">${title}</div>
        <div class="mesh-actions-table-wrap">
          <table class="mesh-actions-table">
            <thead>
              <tr>
                <th>${t('mesh_actions_col_priority')}</th>
                <th>${t('mesh_actions_col_target')}</th>
                <th>${t('mesh_actions_col_issue')}</th>
                <th>${t('mesh_actions_col_metrics')}</th>
                <th>${t('mesh_actions_col_sources')}</th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      `;
    }

    function sortMeshOpportunities(rows, sortKey, direction) {
      const key = String(sortKey || 'impact_score');
      const factor = direction === 'asc' ? 1 : -1;
      const asValue = (row) => {
        const value = row[key];
        if (typeof value === 'boolean') return value ? 1 : 0;
        const num = Number(value);
        if (!Number.isNaN(num)) return num;
        return String(value || '').toLowerCase();
      };
      rows.sort((a, b) => {
        const av = asValue(a);
        const bv = asValue(b);
        if (av === bv) return 0;
        return av > bv ? factor : -factor;
      });
    }

    function csvEscape(value) {
      const raw = String(value ?? '');
      if (raw.includes('"') || raw.includes(',') || raw.includes('\n')) {
        return `"${raw.replaceAll('"', '""')}"`;
      }
      return raw;
    }

    function downloadMeshOpportunitiesCsv(rows) {
      const headers = [
        'source_url',
        'source_context',
        'source_cluster',
        'target_url',
        'issue_type',
        'priority',
        'recommended_anchor',
        'impact_score',
        'effort_score',
        'confidence_score',
        'confidence_level',
        'section_relevance',
        'same_section',
        'same_locale',
        'target_content_inbound',
        'target_template_inbound',
        'quick_win',
      ];
      const lines = [headers.join(',')];
      rows.forEach((row) => {
        const values = [
          row.source_url,
          row.source_context,
          row.source_cluster,
          row.target_url,
          row.issue_type,
          row.priority,
          row.recommended_anchor,
          row.impact_score,
          row.effort_score,
          row.confidence_score,
          row.confidence_level,
          row.section_relevance,
          row.same_section ? '1' : '0',
          row.same_locale ? '1' : '0',
          row.target_content_inbound,
          row.target_template_inbound,
          row.quick_win ? '1' : '0',
        ];
        lines.push(values.map(csvEscape).join(','));
      });

      const blob = new Blob([`\uFEFF${lines.join('\n')}`], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const now = new Date();
      const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;
      link.download = `mesh-opportunities-${stamp}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }

    function renderMeshOpportunities(mesh) {
      const actionable = mesh && mesh.actionable ? mesh.actionable : {};
      const allRows = Array.isArray(actionable.opportunities) ? actionable.opportunities : [];
      const quickWinsCount = Number(actionable.opportunities_quick_wins || 0);
      const contextualCount = Number(actionable.opportunities_contextual || 0);

      meshOpportunities.innerHTML = '';
      const wrapper = document.createElement('div');
      wrapper.className = 'mesh-opps-wrap';

      const head = document.createElement('div');
      head.className = 'mesh-opps-head';
      head.innerHTML = `<strong>${escapeHtml(t('mesh_opps_title'))}</strong>`;

      const actions = document.createElement('div');
      actions.className = 'mesh-opps-actions';
      const quickBtn = document.createElement('button');
      quickBtn.type = 'button';
      quickBtn.className = 'mesh-control-btn';
      quickBtn.textContent = meshOpportunityState.quickWinsOnly
        ? t('mesh_opps_show_all')
        : t('mesh_opps_quick_wins_only', { count: quickWinsCount });
      quickBtn.addEventListener('click', () => {
        meshOpportunityState.quickWinsOnly = !meshOpportunityState.quickWinsOnly;
        renderMeshOpportunities(mesh);
      });

      const contextualBtn = document.createElement('button');
      contextualBtn.type = 'button';
      contextualBtn.className = 'mesh-control-btn';
      contextualBtn.textContent = meshOpportunityState.contextualOnly
        ? t('mesh_opps_contextual_off')
        : t('mesh_opps_contextual_only', { count: contextualCount });
      contextualBtn.addEventListener('click', () => {
        meshOpportunityState.contextualOnly = !meshOpportunityState.contextualOnly;
        renderMeshOpportunities(mesh);
      });

      const confidenceSelect = document.createElement('select');
      confidenceSelect.className = 'mesh-opps-select';
      [
        { value: '0', label: t('mesh_opps_confidence_all') },
        { value: '55', label: t('mesh_opps_confidence_55') },
        { value: '75', label: t('mesh_opps_confidence_75') },
      ].forEach((opt) => {
        const option = document.createElement('option');
        option.value = opt.value;
        option.textContent = opt.label;
        if (Number(meshOpportunityState.minConfidence || 0) === Number(opt.value)) {
          option.selected = true;
        }
        confidenceSelect.appendChild(option);
      });
      confidenceSelect.addEventListener('change', () => {
        meshOpportunityState.minConfidence = Number(confidenceSelect.value || 0);
        renderMeshOpportunities(mesh);
      });

      const resetBtn = document.createElement('button');
      resetBtn.type = 'button';
      resetBtn.className = 'mesh-control-btn';
      resetBtn.textContent = t('mesh_opps_reset_filters');
      resetBtn.addEventListener('click', () => {
        meshOpportunityState.quickWinsOnly = false;
        meshOpportunityState.contextualOnly = false;
        meshOpportunityState.minConfidence = 0;
        renderMeshOpportunities(mesh);
      });

      const exportBtn = document.createElement('button');
      exportBtn.type = 'button';
      exportBtn.className = 'mesh-control-btn';
      exportBtn.textContent = t('mesh_opps_export');
      actions.appendChild(quickBtn);
      actions.appendChild(contextualBtn);
      actions.appendChild(confidenceSelect);
      actions.appendChild(resetBtn);
      actions.appendChild(exportBtn);
      head.appendChild(actions);
      wrapper.appendChild(head);

      if (!allRows.length) {
        const empty = document.createElement('div');
        empty.className = 'mesh-actions-empty';
        empty.textContent = t('mesh_opps_empty');
        wrapper.appendChild(empty);
        meshOpportunities.appendChild(wrapper);
        return;
      }

      const filteredRows = allRows.filter((row) => {
        if (meshOpportunityState.quickWinsOnly && !row.quick_win) return false;
        if (meshOpportunityState.contextualOnly) {
          const context = String(row.source_context || '').toLowerCase();
          if (context !== 'content' && context !== 'breadcrumb') return false;
        }
        if (Number(meshOpportunityState.minConfidence || 0) > 0) {
          const confidence = Number(row.confidence_score || 0);
          if (confidence < Number(meshOpportunityState.minConfidence || 0)) return false;
        }
        return true;
      });
      sortMeshOpportunities(filteredRows, meshOpportunityState.sortKey, meshOpportunityState.direction);

      const meta = document.createElement('div');
      meta.className = 'muted mesh-opps-meta';
      meta.textContent = t('mesh_opps_meta', {
        total: Number(allRows.length),
        shown: Number(filteredRows.length),
        quick_wins: quickWinsCount,
      });
      wrapper.appendChild(meta);

      exportBtn.addEventListener('click', () => {
        downloadMeshOpportunitiesCsv(filteredRows);
      });

      const tableWrap = document.createElement('div');
      tableWrap.className = 'mesh-opps-table-wrap';
      const table = document.createElement('table');
      table.className = 'mesh-opps-table';

      const columns = [
        { key: 'source_url', label: t('mesh_opps_col_source') },
        { key: 'target_url', label: t('mesh_opps_col_target') },
        { key: 'recommended_anchor', label: t('mesh_opps_col_anchor') },
        { key: 'impact_score', label: t('mesh_opps_col_impact') },
        { key: 'effort_score', label: t('mesh_opps_col_effort') },
        { key: 'confidence_score', label: t('mesh_opps_col_confidence') },
        { key: 'section_relevance', label: t('mesh_opps_col_relevance') },
        { key: 'source_context', label: t('mesh_opps_col_context') },
        { key: 'priority', label: t('mesh_opps_col_priority') },
        { key: 'issue_type', label: t('mesh_opps_col_issue') },
      ];

      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      columns.forEach((column) => {
        const th = document.createElement('th');
        th.textContent = column.label;
        th.title = column.key;
        if (meshOpportunityState.sortKey === column.key) {
          th.classList.add(meshOpportunityState.direction === 'asc' ? 'sort-asc' : 'sort-desc');
        }
        th.addEventListener('click', () => {
          if (meshOpportunityState.sortKey === column.key) {
            meshOpportunityState.direction = meshOpportunityState.direction === 'asc' ? 'desc' : 'asc';
          } else {
            meshOpportunityState.sortKey = column.key;
            meshOpportunityState.direction = (column.key === 'impact_score' || column.key === 'confidence_score') ? 'desc' : 'asc';
          }
          renderMeshOpportunities(mesh);
        });
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      filteredRows.slice(0, 180).forEach((row) => {
        const tr = document.createElement('tr');
        const sourceLink = buildMeshUrlLink(row.source_url);
        const targetLink = buildMeshUrlLink(row.target_url);
        const contextLabel = localizeMeshLinkContext(row.source_context);
        const priorityLabel = localizeMeshPriority(row.priority);
        const issueLabel = localizeMeshIssue(row.issue_type);
        const impact = Number(row.impact_score || 0);
        const effort = Number(row.effort_score || 0);
        const confidence = Number(row.confidence_score || 0);
        const confidenceLevel = localizeMeshConfidenceLevel(row.confidence_level || 'low');
        const relevanceLabel = localizeMeshSectionRelevance(row.section_relevance || '');
        const anchor = String(row.recommended_anchor || '');

        const cells = [
          sourceLink,
          targetLink,
          escapeHtml(anchor || '-'),
          `<span class="mesh-opp-score impact">${escapeHtml(String(impact))}</span>`,
          `<span class="mesh-opp-score effort">${escapeHtml(String(effort))}</span>`,
          `<span class="mesh-opp-score confidence ${escapeHtml(String(row.confidence_level || 'low').toLowerCase())}" title="${escapeHtml(confidenceLevel)}">${escapeHtml(String(confidence))}</span>`,
          escapeHtml(relevanceLabel),
          escapeHtml(contextLabel),
          `<span class="mesh-priority ${escapeHtml(String(row.priority || 'low').toLowerCase())}">${escapeHtml(priorityLabel)}</span>`,
          escapeHtml(issueLabel),
        ];

        cells.forEach((content) => {
          const td = document.createElement('td');
          td.innerHTML = content;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      tableWrap.appendChild(table);
      wrapper.appendChild(tableWrap);

      meshOpportunities.appendChild(wrapper);
    }

    function renderMeshGraph(nodes, edges) {
      meshGraph.innerHTML = '';
      if (meshGraphController) {
        meshGraphController.abort();
        meshGraphController = null;
      }
      meshClearSelection = null;
      meshResetView = null;
      meshResetFocusBtn.disabled = true;

      const graphWrap = meshGraph.closest('.mesh-graph-wrap');
      const hideHoverTooltip = () => {
        if (!meshHoverTooltip) return;
        meshHoverTooltip.style.display = 'none';
        meshHoverTooltip.textContent = '';
      };
      const moveHoverTooltip = (clientX, clientY) => {
        if (!meshHoverTooltip || !graphWrap) return;
        const rect = graphWrap.getBoundingClientRect();
        const maxX = graphWrap.scrollWidth - meshHoverTooltip.offsetWidth - 8;
        const maxY = graphWrap.scrollHeight - meshHoverTooltip.offsetHeight - 8;
        const x = Math.max(8, Math.min(maxX, (clientX - rect.left) + graphWrap.scrollLeft + 14));
        const y = Math.max(8, Math.min(maxY, (clientY - rect.top) + graphWrap.scrollTop + 14));
        meshHoverTooltip.style.left = `${x}px`;
        meshHoverTooltip.style.top = `${y}px`;
      };
      const showHoverTooltip = (text, clientX, clientY) => {
        if (!meshHoverTooltip || !graphWrap) return;
        meshHoverTooltip.textContent = String(text || '');
        meshHoverTooltip.style.display = 'block';
        moveHoverTooltip(clientX, clientY);
      };
      hideHoverTooltip();

      const width = 960;
      const height = 500;
      meshGraph.setAttribute('viewBox', `0 0 ${width} ${height}`);

      if (!nodes.length || !edges.length) {
        hideHoverTooltip();
        meshResetViewBtn.disabled = true;
        meshInteractionHint.textContent = meshGraphVisible ? t('mesh_graph_empty') : t('mesh_graph_collapsed_hint');
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', String(width / 2));
        text.setAttribute('y', String(height / 2));
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', '#64748b');
        text.setAttribute('font-size', '14');
        text.textContent = t('mesh_graph_empty');
        meshGraph.appendChild(text);
        return;
      }

      meshResetViewBtn.disabled = false;

      const score = (node) => Number(node.inbound || 0) + Number(node.outbound || 0);
      const sorted = [...nodes].sort((a, b) => score(b) - score(a));
      sorted.sort((a, b) => {
        if (a.is_start) return -1;
        if (b.is_start) return 1;
        return score(b) - score(a);
      });

      const nodeDataByUrl = new Map(sorted.map((node) => [node.url, node]));

      const centerX = width / 2;
      const centerY = height / 2;
      const maxRing = Math.max(1, Math.ceil((sorted.length - 1) / 20));
      const baseRadius = Math.min(width, height) * 0.17;
      const ringStep = Math.min(width, height) * 0.11;

      const pos = new Map();
      sorted.forEach((node, idx) => {
        if (idx === 0) {
          pos.set(node.url, { x: centerX, y: centerY });
          return;
        }
        const ringIndex = Math.floor((idx - 1) / 20) + 1;
        const slot = (idx - 1) % 20;
        const slotsInRing = Math.min(20, sorted.length - 1 - (ringIndex - 1) * 20);
        const angle = (Math.PI * 2 * slot) / Math.max(1, slotsInRing);
        const radius = baseRadius + ringStep * Math.min(maxRing, ringIndex);
        pos.set(node.url, {
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
        });
      });

      const edgePriority = (edge) => {
        const sourceNode = nodeDataByUrl.get(edge.source) || {};
        const targetNode = nodeDataByUrl.get(edge.target) || {};
        const context = String(edge.context || '').toLowerCase();
        const sourceDepth = Number(sourceNode.depth);
        const targetDepth = Number(targetNode.depth);
        let scoreValue = Number(edge.weight || 1);

        if (context === 'content') scoreValue += 4;
        else if (context === 'breadcrumb') scoreValue += 2;
        else if (context === 'menu') scoreValue -= 1;
        else if (context === 'footer') scoreValue -= 2;

        if (sourceNode.is_start || targetNode.is_start) scoreValue += 3;
        if (Number.isInteger(sourceDepth) && Number.isInteger(targetDepth) && targetDepth === sourceDepth + 1) {
          scoreValue += 2;
        }

        scoreValue += (score(sourceNode) + score(targetNode)) / 30;
        return scoreValue;
      };
      const allRenderableEdges = [...edges].filter((edge) => pos.has(edge.source) && pos.has(edge.target));
      const edgeBudget = sorted.length > 60 ? 420 : (sorted.length > 35 ? 650 : 1000);
      const primaryEdges = [...allRenderableEdges]
        .sort((a, b) => edgePriority(b) - edgePriority(a))
        .slice(0, edgeBudget);
      const primaryEdgeKeys = new Set(primaryEdges.map((edge) => `${String(edge.source)}=>${String(edge.target)}`));
      const hiddenEdgesCount = Math.max(0, allRenderableEdges.length - primaryEdges.length);
      const composeIdleHint = () => {
        let hint = t('mesh_interaction_hint_idle');
        if (hiddenEdgesCount > 0) {
          hint += ` ${t('mesh_graph_simplified', { shown: primaryEdges.length, total: allRenderableEdges.length })}`;
        }
        return hint;
      };
      meshInteractionHint.dataset.idleHint = composeIdleHint();
      if (meshGraphVisible) {
        meshInteractionHint.textContent = meshInteractionHint.dataset.idleHint;
      } else {
        meshInteractionHint.textContent = t('mesh_graph_collapsed_hint');
      }
      const nodeRadiusByUrl = new Map();
      sorted.forEach((node) => {
        const s = score(node);
        const radius = node.is_start ? 10 : Math.max(4, Math.min(10, 4 + s * 0.3));
        nodeRadiusByUrl.set(node.url, radius);
      });
      const neighbors = new Map();
      sorted.forEach((node) => neighbors.set(node.url, new Set()));
      allRenderableEdges.forEach((edge) => {
        if (!neighbors.has(edge.source) || !neighbors.has(edge.target)) return;
        neighbors.get(edge.source).add(edge.target);
        neighbors.get(edge.target).add(edge.source);
      });

      const viewport = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      const background = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      background.setAttribute('x', '0');
      background.setAttribute('y', '0');
      background.setAttribute('width', String(width));
      background.setAttribute('height', String(height));
      background.setAttribute('fill', 'transparent');
      viewport.appendChild(background);

      const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
      const buildArrowMarker = (id, color) => {
        const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
        marker.setAttribute('id', id);
        marker.setAttribute('markerWidth', '7');
        marker.setAttribute('markerHeight', '7');
        marker.setAttribute('refX', '6');
        marker.setAttribute('refY', '3.5');
        marker.setAttribute('orient', 'auto');
        marker.setAttribute('markerUnits', 'strokeWidth');

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', 'M0,0 L0,7 L7,3.5 z');
        path.setAttribute('fill', color);
        marker.appendChild(path);
        defs.appendChild(marker);
      };
      buildArrowMarker('mesh-arrow-default', '#94a3b8');
      buildArrowMarker('mesh-arrow-out', '#2563eb');
      buildArrowMarker('mesh-arrow-in', '#ea580c');
      buildArrowMarker('mesh-arrow-muted', '#cbd5e1');
      meshGraph.appendChild(defs);

      const edgeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      const nodeLayer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      viewport.appendChild(edgeLayer);
      viewport.appendChild(nodeLayer);
      meshGraph.appendChild(viewport);

      const edgeEls = [];
      const nodeEls = new Map();

      allRenderableEdges.forEach((edge) => {
        const from = pos.get(edge.source);
        const to = pos.get(edge.target);
        if (!from || !to) return;
        const edgeKey = `${String(edge.source)}=>${String(edge.target)}`;
        const isPrimary = primaryEdgeKeys.has(edgeKey);
        const sourceRadius = Number(nodeRadiusByUrl.get(edge.source) || 4);
        const targetRadius = Number(nodeRadiusByUrl.get(edge.target) || 4);
        const dx = to.x - from.x;
        const dy = to.y - from.y;
        const len = Math.hypot(dx, dy) || 1;
        const ux = dx / len;
        const uy = dy / len;
        const x1 = from.x + ux * (sourceRadius + 1.5);
        const y1 = from.y + uy * (sourceRadius + 1.5);
        const x2 = to.x - ux * (targetRadius + 4);
        const y2 = to.y - uy * (targetRadius + 4);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', String(x1));
        line.setAttribute('y1', String(y1));
        line.setAttribute('x2', String(x2));
        line.setAttribute('y2', String(y2));
        line.setAttribute('stroke', isPrimary ? '#94a3b8' : '#cbd5e1');
        line.setAttribute('stroke-opacity', isPrimary ? '0.35' : '0.04');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('marker-end', isPrimary ? 'url(#mesh-arrow-default)' : 'url(#mesh-arrow-muted)');
        edgeLayer.appendChild(line);
        edgeEls.push({ el: line, source: edge.source, target: edge.target, primary: isPrimary });
      });

      const setEdgeStyle = (item, stroke, opacity, widthValue, markerId) => {
        item.el.setAttribute('stroke', stroke);
        item.el.setAttribute('stroke-opacity', String(opacity));
        item.el.setAttribute('stroke-width', String(widthValue));
        item.el.setAttribute('marker-end', `url(#${markerId})`);
      };

      sorted.forEach((node) => {
        const point = pos.get(node.url);
        if (!point) return;
        const radius = Number(nodeRadiusByUrl.get(node.url) || 4);
        const fill = node.is_start ? '#0f766e' : (node.inbound > 0 ? '#1d4ed8' : '#94a3b8');

        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', String(point.x));
        circle.setAttribute('cy', String(point.y));
        circle.setAttribute('r', String(radius));
        circle.setAttribute('fill', fill);
        circle.setAttribute('fill-opacity', node.is_start ? '1' : '0.92');
        circle.setAttribute('stroke', '#ffffff');
        circle.setAttribute('stroke-width', '1.2');
        circle.setAttribute('tabindex', '0');
        circle.setAttribute('role', 'button');
        circle.style.cursor = 'pointer';
        circle.dataset.nodeUrl = node.url;
        circle.dataset.baseRadius = String(radius);
        circle.dataset.baseFill = fill;

        const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
        title.textContent = `${node.url}\nin:${node.inbound} out:${node.outbound}`;
        circle.appendChild(title);
        nodeLayer.appendChild(circle);
        nodeEls.set(node.url, circle);
      });

      const restoreDefaultStyles = () => {
        edgeEls.forEach((item) => {
          if (item.primary) {
            setEdgeStyle(item, '#94a3b8', 0.35, 1, 'mesh-arrow-default');
          } else {
            setEdgeStyle(item, '#cbd5e1', 0.04, 1, 'mesh-arrow-muted');
          }
        });
        nodeEls.forEach((circle, url) => {
          const node = nodeDataByUrl.get(url);
          const radius = Number(circle.dataset.baseRadius || '4');
          circle.setAttribute('r', String(radius));
          circle.setAttribute('fill', String(circle.dataset.baseFill || '#1d4ed8'));
          circle.setAttribute('stroke', '#ffffff');
          circle.setAttribute('stroke-width', '1.2');
          circle.setAttribute('opacity', '1');
          circle.setAttribute('fill-opacity', node && node.is_start ? '1' : '0.92');
        });
      };

      let selectedUrl = '';
      const setSelection = (url) => {
        selectedUrl = String(url || '');
        if (!selectedUrl || !nodeDataByUrl.has(selectedUrl)) {
          restoreDefaultStyles();
          meshResetFocusBtn.disabled = true;
          meshInteractionHint.textContent = meshGraphVisible
            ? (String(meshInteractionHint.dataset.idleHint || '').trim() || composeIdleHint())
            : t('mesh_graph_collapsed_hint');
          return;
        }

        const focusedNode = nodeDataByUrl.get(selectedUrl);
        const neighborhood = new Set([selectedUrl, ...(neighbors.get(selectedUrl) || [])]);
        meshResetFocusBtn.disabled = false;
        meshInteractionHint.textContent = meshGraphVisible ? t('mesh_interaction_hint_active', {
          path: abbreviatePath(selectedUrl),
          inbound: Number(focusedNode.inbound || 0),
          outbound: Number(focusedNode.outbound || 0),
        }) : t('mesh_graph_collapsed_hint');

        edgeEls.forEach((item) => {
          const isOutgoing = item.source === selectedUrl;
          const isIncoming = item.target === selectedUrl;
          const neighborhoodEdge = neighborhood.has(item.source) && neighborhood.has(item.target);
          if (isOutgoing) {
            setEdgeStyle(item, '#2563eb', 0.92, 1.8, 'mesh-arrow-out');
          } else if (isIncoming) {
            setEdgeStyle(item, '#ea580c', 0.92, 1.8, 'mesh-arrow-in');
          } else if (neighborhoodEdge) {
            const opacity = item.primary ? 0.28 : 0.2;
            setEdgeStyle(item, '#94a3b8', opacity, 1.1, 'mesh-arrow-default');
          } else {
            if (item.primary) {
              setEdgeStyle(item, '#cbd5e1', 0.08, 1, 'mesh-arrow-muted');
            } else {
              setEdgeStyle(item, '#cbd5e1', 0.02, 1, 'mesh-arrow-muted');
            }
          }
        });

        nodeEls.forEach((circle, urlKey) => {
          const node = nodeDataByUrl.get(urlKey);
          const radius = Number(circle.dataset.baseRadius || '4');
          const isSelected = urlKey === selectedUrl;
          const isNear = neighborhood.has(urlKey);

          circle.setAttribute('opacity', isNear ? '1' : '0.14');
          circle.setAttribute('r', String(isSelected ? Math.min(14, radius + 2.5) : radius));
          circle.setAttribute('stroke', isSelected ? '#f97316' : '#ffffff');
          circle.setAttribute('stroke-width', isSelected ? '2.2' : '1.2');
          circle.setAttribute('fill-opacity', node && node.is_start ? '1' : '0.92');
        });
      };

      const controller = new AbortController();
      meshGraphController = controller;
      const signal = controller.signal;

      nodeEls.forEach((circle, url) => {
        const toggleFocus = () => setSelection(selectedUrl === url ? '' : url);
        circle.addEventListener('click', (event) => {
          event.stopPropagation();
          toggleFocus();
        }, { signal });
        circle.addEventListener('pointerenter', (event) => {
          showHoverTooltip(url, event.clientX, event.clientY);
        }, { signal });
        circle.addEventListener('pointermove', (event) => {
          moveHoverTooltip(event.clientX, event.clientY);
        }, { signal });
        circle.addEventListener('pointerleave', () => {
          hideHoverTooltip();
        }, { signal });
        circle.addEventListener('pointercancel', () => {
          hideHoverTooltip();
        }, { signal });
        circle.addEventListener('focus', () => {
          if (!graphWrap) return;
          const rect = graphWrap.getBoundingClientRect();
          showHoverTooltip(url, rect.left + 24, rect.top + 24);
        }, { signal });
        circle.addEventListener('blur', () => {
          hideHoverTooltip();
        }, { signal });
        circle.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggleFocus();
          }
        }, { signal });
      });
      meshGraph.addEventListener('click', (event) => {
        if (event.target && event.target.dataset && event.target.dataset.nodeUrl) return;
        setSelection('');
        hideHoverTooltip();
      }, { signal });

      const state = { x: 0, y: 0, k: 1 };
      const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
      const applyTransform = () => {
        viewport.setAttribute('transform', `translate(${state.x} ${state.y}) scale(${state.k})`);
      };

      let isDragging = false;
      let dragX = 0;
      let dragY = 0;

      const startDrag = (event) => {
        if (event.button !== 0) return;
        if (event.target && event.target.dataset && event.target.dataset.nodeUrl) return;
        isDragging = true;
        hideHoverTooltip();
        dragX = event.clientX;
        dragY = event.clientY;
        meshGraph.classList.add('is-dragging');
      };

      const moveDrag = (event) => {
        if (!isDragging) return;
        state.x += event.clientX - dragX;
        state.y += event.clientY - dragY;
        dragX = event.clientX;
        dragY = event.clientY;
        applyTransform();
      };

      const stopDrag = () => {
        if (!isDragging) return;
        isDragging = false;
        meshGraph.classList.remove('is-dragging');
      };

      const zoom = (event) => {
        event.preventDefault();
        const ctm = meshGraph.getScreenCTM();
        if (!ctm) return;

        const point = meshGraph.createSVGPoint();
        point.x = event.clientX;
        point.y = event.clientY;
        const graphPoint = point.matrixTransform(ctm.inverse());

        const factor = event.deltaY < 0 ? 1.1 : 0.9;
        const nextScale = clamp(state.k * factor, 0.5, 4.5);
        if (nextScale === state.k) return;

        const worldX = (graphPoint.x - state.x) / state.k;
        const worldY = (graphPoint.y - state.y) / state.k;

        state.k = nextScale;
        state.x = graphPoint.x - worldX * state.k;
        state.y = graphPoint.y - worldY * state.k;
        applyTransform();
      };

      meshGraph.addEventListener('pointerdown', startDrag, { signal });
      window.addEventListener('pointermove', moveDrag, { signal });
      window.addEventListener('pointerup', stopDrag, { signal });
      window.addEventListener('pointercancel', stopDrag, { signal });
      meshGraph.addEventListener('wheel', zoom, { signal, passive: false });

      meshClearSelection = () => setSelection('');
      meshResetView = () => {
        state.x = 0;
        state.y = 0;
        state.k = 1;
        applyTransform();
      };
      setSelection('');
      applyTransform();
    }

    function renderMesh(mesh) {
      latestMeshPayload = mesh;
      meshCard.style.display = currentMode === 'mesh' ? 'block' : 'none';

      const pages = Number(mesh.pages_scanned || 0);
      const edges = Number(mesh.edges_count || 0);
      const elapsed = Number(mesh.elapsed_ms || 0);
      const seedNote = localizeMeshSeedMode(mesh.seed_mode);

      meshStatusBox.textContent = t('mesh_done');
      meshMeta.textContent = `${t('mesh_meta', { pages, edges, elapsed })} · ${seedNote}`;
      updateMeshShareTarget(String(mesh.mesh_id || ''), false);
      setShareMeshFeedback('');
      renderMeshKpis(mesh);
      renderMeshWarnings(mesh);
      renderMeshActions(mesh);
      renderMeshOpportunities(mesh);

      const hubs = Array.isArray(mesh.top_hubs) ? mesh.top_hubs : [];
      const orphans = Array.isArray(mesh.orphan_candidates) ? mesh.orphan_candidates : [];
      const errors = Array.isArray(mesh.fetch_errors) ? mesh.fetch_errors : [];
      const hreflang = mesh && mesh.hreflang ? mesh.hreflang : {};
      const hreflangNonReciprocal = Array.isArray(hreflang.non_reciprocal_samples) ? hreflang.non_reciprocal_samples : [];
      const hreflangMissingDefault = Array.isArray(hreflang.missing_x_default_samples) ? hreflang.missing_x_default_samples : [];

      const hubsHtml = buildMeshSummaryList(hubs, (row) =>
        `${buildMeshUrlLink(row.url)} · in:${Number(row.inbound || 0)} out:${Number(row.outbound || 0)}`
      );
      const orphanHtml = buildMeshSummaryList(orphans, (row) =>
        `${buildMeshUrlLink(row.url)} · out:${Number(row.outbound || 0)}`
      );
      const errorsHtml = buildMeshSummaryList(errors, (row) =>
        `${buildMeshUrlLink(row.url)} · ${escapeHtml(String(row.error || ''))}`
      );
      const hreflangRows = [];
      hreflangNonReciprocal.slice(0, 4).forEach((row) => {
        hreflangRows.push({
          type: 'non_reciprocal',
          from_url: String(row.from_url || ''),
          to_url: String(row.to_url || ''),
          hreflang: String(row.hreflang || ''),
        });
      });
      hreflangMissingDefault.slice(0, 4).forEach((row) => {
        hreflangRows.push({
          type: 'missing_x_default',
          url: String(row.url || ''),
        });
      });
      const hreflangHtml = buildMeshSummaryList(hreflangRows, (row) => {
        if (row.type === 'non_reciprocal') {
          return `${buildMeshUrlLink(row.from_url)} → ${buildMeshUrlLink(row.to_url)} · ${escapeHtml(String(row.hreflang || '-'))}`;
        }
        return `${buildMeshUrlLink(row.url)} · ${escapeHtml(t('mesh_hreflang_missing_x_default_short'))}`;
      });
      const treeText = buildMeshTreeText(mesh);

      meshSummary.innerHTML = '';
      [
        { title: t('mesh_summary_hubs'), valueHtml: hubsHtml },
        { title: t('mesh_summary_orphans'), valueHtml: orphanHtml },
        { title: t('mesh_summary_hreflang'), valueHtml: hreflangHtml },
        { title: t('mesh_summary_errors'), valueHtml: errorsHtml },
        { title: t('mesh_summary_tree'), valueHtml: `<pre class="mesh-tree-text">${escapeHtml(treeText)}</pre>`, className: 'mesh-box-tree' },
      ].forEach((box) => {
        const el = document.createElement('div');
        el.className = `mesh-box ${String(box.className || '').trim()}`.trim();
        el.innerHTML = `<strong class="mesh-box-title">${escapeHtml(box.title)}</strong>${box.valueHtml}`;
        meshSummary.appendChild(el);
      });

      meshErrors.textContent = '';
      renderMeshGraph(Array.isArray(mesh.nodes) ? mesh.nodes : [], Array.isArray(mesh.edges) ? mesh.edges : []);
      applyMeshGraphVisibility();
    }

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
        const location = String(step.location || '').trim();
        const locationPart = location ? ` → ${escapeHtml(location)}` : '';
        return `${index + 1}. ${buildMeshUrlLink(url)} · ${escapeHtml(String(status || '-'))}${locationPart}`;
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
    }

    function parseSortableValue(value) {
      const raw = String(value ?? '').trim();
      if (raw === '') return '';
      const num = Number(raw);
      if (!Number.isNaN(num)) return num;
      return raw.toLowerCase();
    }

    function sortRows(rows, key, direction) {
      const factor = direction === 'asc' ? 1 : -1;
      rows.sort((a, b) => {
        const av = parseSortableValue(a[key]);
        const bv = parseSortableValue(b[key]);
        if (av === bv) return 0;
        return av > bv ? factor : -factor;
      });
    }

    function prettifyHeader(header) {
      const map = {
        url: 'URL',
        final_url: t('header_final_url'),
        status: 'HTTP',
        load_ms: t('header_load_ms'),
        is_indexable: t('header_is_indexable'),
        meta_description_length: t('header_meta_description_length'),
        priority_score: t('header_priority_score'),
        priority_level: t('header_priority_level')
      };
      const lower = String(header || '').toLowerCase();
      if (map[lower]) return map[lower];
      return String(header || '')
        .replace(/_/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    function asBoolean(value) {
      const raw = String(value ?? '').toLowerCase();
      return raw === 'true' || raw === '1' || raw === 'yes';
    }

    function createBadge(text, className = '') {
      const badge = document.createElement('span');
      badge.className = `csv-badge ${className}`.trim();
      badge.textContent = text;
      return badge;
    }

    function buildIssuesCell(value) {
      const wrapper = document.createElement('div');
      wrapper.className = 'issues-list';

      const raw = String(value || '').trim();
      if (!raw) {
        wrapper.appendChild(createBadge(t('table_no_issue'), 'csv-badge-ok'));
        return wrapper;
      }

      const issues = raw.split('|').map((part) => part.trim()).filter(Boolean);
      const visible = issues.slice(0, 4);
      visible.forEach((issue) => {
        const item = document.createElement('span');
        item.className = 'issues-item';
        item.textContent = issue;
        item.title = issue;
        wrapper.appendChild(item);
      });

      if (issues.length > visible.length) {
        const more = document.createElement('span');
        more.className = 'issues-item';
        more.textContent = t('table_more_issues', { count: issues.length - visible.length });
        more.title = issues.join(' | ');
        wrapper.appendChild(more);
      }
      return wrapper;
    }

    function buildCellContent(header, value) {
      const key = String(header || '').toLowerCase();
      const raw = String(value ?? '');

      if (key === 'status') {
        const statusNum = Number(raw);
        if (statusNum >= 200 && statusNum < 300) return createBadge(raw, 'csv-badge-ok');
        if (statusNum >= 300 && statusNum < 400) return createBadge(raw, 'csv-badge-warn');
        return createBadge(raw || '-', 'csv-badge-bad');
      }

      if (key === 'is_indexable') {
        return asBoolean(raw) ? createBadge(t('table_indexable_yes'), 'csv-badge-ok') : createBadge(t('table_indexable_no'), 'csv-badge-bad');
      }

      if (key === 'priority_level') {
        const level = raw.toLowerCase() || 'none';
        const classByLevel = {
          critical: 'csv-badge-crit',
          high: 'csv-badge-high',
          medium: 'csv-badge-medium',
          low: 'csv-badge-low',
          none: 'csv-badge-none'
        };
        return createBadge(raw || 'none', classByLevel[level] || 'csv-badge-none');
      }

      if (key === 'issues') {
        return buildIssuesCell(raw);
      }

      const span = document.createElement('span');
      span.className = 'csv-cell';
      span.textContent = raw;
      span.title = raw;

      if (key.endsWith('_url') || key === 'url') span.classList.add('csv-cell-url');
      if (/^-?\d+(\.\d+)?$/.test(raw)) span.classList.add('csv-cell-num');
      if (key.includes('description') || key === 'title' || key === 'h1') span.classList.add('csv-cell-wrap');
      return span;
    }

    function applyPreviewFilters() {
      if (!previewHeaders.length || !previewDataset.length) {
        tableWrap.textContent = t('table_empty');
        updateInsightIssueTagStates();
        updateInsightPriorityChipStates();
        return;
      }

      const issueNeedle = (filterIssue.value || '').trim().toLowerCase();
      const httpFilter = filterStatus.value;
      const indexableFilter = filterIndexable.value;
      const priorityFilter = filterPriority.value;

      const rows = previewDataset.filter((row) => {
        const issues = String(row.issues || '').toLowerCase();
        if (issueNeedle && !issues.includes(issueNeedle)) return false;

        const statusNum = Number(String(row.status || ''));
        if (httpFilter === '200' && statusNum !== 200) return false;
        if (httpFilter === 'not-200' && statusNum === 200) return false;

        const indexRaw = String(row.is_indexable || '').toLowerCase();
        const isIndexable = indexRaw === 'true' || indexRaw === '1';
        if (indexableFilter === 'true' && !isIndexable) return false;
        if (indexableFilter === 'false' && isIndexable) return false;

        const priority = String(row.priority_level || 'none').toLowerCase();
        if (priorityFilter !== 'all' && priority !== priorityFilter) return false;

        return true;
      });

      if (currentSort.key && previewHeaders.includes(currentSort.key)) {
        sortRows(rows, currentSort.key, currentSort.direction);
      }

      const table = document.createElement('table');
      table.className = 'csv-table';
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');

      previewHeaders.forEach((header) => {
        const th = document.createElement('th');
        th.textContent = prettifyHeader(header);
        th.title = header;
        if (header === currentSort.key) {
          th.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
        }
        th.addEventListener('click', () => {
          if (currentSort.key === header) {
            currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
          } else {
            currentSort = { key: header, direction: 'asc' };
          }
          applyPreviewFilters();
        });
        headRow.appendChild(th);
      });

      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement('tbody');
      rows.forEach((row) => {
        const tr = document.createElement('tr');
        previewHeaders.forEach((header) => {
          const td = document.createElement('td');
          td.appendChild(buildCellContent(header, row[header]));
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });

      table.appendChild(tbody);
      tableWrap.innerHTML = '';
      tableWrap.appendChild(table);

      const displayedRows = rows.length;
      const truncated = !!previewTruncated;
      previewMeta.textContent = truncated
        ? t('preview_meta_truncated', { displayed: displayedRows, loaded: previewDataset.length, total: previewTotalRows })
        : t('preview_meta_full', { displayed: displayedRows, loaded: previewDataset.length });
      updateInsightIssueTagStates();
      updateInsightPriorityChipStates();
    }

    function resetPreviewFilters() {
      filterIssue.value = '';
      filterStatus.value = 'all';
      filterIndexable.value = 'all';
      filterPriority.value = 'all';
      applyPreviewFilters();
      filterIssue.focus();
    }

    function renderPreview(previewPayload) {
      const preview = previewPayload.preview || {};
      previewHeaders = Array.isArray(preview.headers) ? preview.headers : [];
      previewDataset = Array.isArray(preview.rows) ? preview.rows : [];
      previewTotalRows = Number(preview.total_rows || previewDataset.length);
      previewTruncated = !!preview.truncated;
      applyPreviewFilters();
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

    async function loadPreview(previewUrl, jobId) {
      if (!previewUrl || previewLoadedFor === jobId) return;

      previewCard.style.display = 'block';
      previewError.textContent = '';
      tableWrap.textContent = t('preview_loading');

      try {
        const separator = previewUrl.includes('?') ? '&' : '?';
        const res = await fetch(`${previewUrl}${separator}rows=300`, { cache: 'no-store' });
        const payload = await res.json();
        if (!res.ok) throw new Error(payload.error || t('preview_error_fallback'));

        renderPreview(payload);
        previewLoadedFor = jobId;
      } catch (err) {
        previewError.textContent = err.message || String(err);
      }
    }

    async function pollStatus(jobId) {
      try {
        const res = await fetch(`status.php?job_id=${encodeURIComponent(jobId)}`, { cache: 'no-store' });
        const payload = await res.json();
        if (!res.ok) throw new Error(payload.error || t('status_error_fallback'));

        renderStatus(payload);
        runError.textContent = payload.error || '';

        if (payload.status === 'completed') {
          await loadPreview(payload.preview_url, payload.job_id);
        }

        if (payload.status === 'completed' || payload.status === 'failed') {
          clearInterval(pollTimer);
          pollTimer = null;
          setRunningState(false);
        }
      } catch (err) {
        clearInterval(pollTimer);
        pollTimer = null;
        setRunningState(false);
        runError.textContent = err.message || String(err);
      }
    }

    async function runMeshAudit(payload) {
      const res = await fetch('mesh.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await parseApiJsonResponse(res, 'mesh_api_invalid_json', 'mesh_api_bad_gateway');
      if (!res.ok) throw new Error(data.error || t('mesh_api_error'));
      return data;
    }

    function renderMeshJobStatus(payload) {
      const progress = payload && payload.progress && typeof payload.progress === 'object' ? payload.progress : null;
      const parts = [
        `${t('status_job')}: ${payload.job_id || '-'}`,
        `${t('status_status')}: ${localizeMeshJobStatus(payload.status)}`,
        payload.start_url ? `${t('mesh_job_start_url')}: ${payload.start_url}` : '',
        progress
          ? t('mesh_progress_line', {
            pct: Number(progress.progress_pct || 0),
            pages: Number(progress.pages_scanned || 0),
            target: Number(progress.pages_target || 0),
            queue: Number(progress.queue_size || 0),
            edges: Number(progress.edges_found || 0),
          })
          : '',
        progress ? `${t('mesh_progress_phase')}: ${localizeMeshProgressStage(progress.stage)}` : '',
        progress
          ? t('mesh_progress_timing', {
            elapsed: Number(progress.elapsed_ms || 0),
            budget: Number(progress.runtime_budget_ms || 0),
          })
          : '',
        payload.started_at ? `${t('status_started')}: ${payload.started_at}` : '',
        payload.completed_at ? `${t('status_completed')}: ${payload.completed_at}` : '',
      ].filter(Boolean);
      meshStatusBox.textContent = parts.join('\n');
    }

    async function pollMeshStatus(jobId) {
      try {
        const res = await fetch(`mesh_status.php?job_id=${encodeURIComponent(jobId)}`, { cache: 'no-store' });
        const data = await parseApiJsonResponse(res, 'mesh_api_invalid_json', 'mesh_api_bad_gateway');
        if (!res.ok) throw new Error(data.error || t('mesh_api_error'));

        renderMeshJobStatus(data);
        meshFormError.textContent = '';

        if (String(data.status || '').toLowerCase() === 'completed') {
          clearInterval(meshPollTimer);
          meshPollTimer = null;
          setMeshRunningState(false);
          if (!data.mesh) {
            throw new Error(t('mesh_api_error'));
          }
          renderMesh({ ...data.mesh, mesh_id: data.mesh_id || '' });
          return;
        }

        if (String(data.status || '').toLowerCase() === 'failed') {
          clearInterval(meshPollTimer);
          meshPollTimer = null;
          setMeshRunningState(false);
          throw new Error(data.error || t('mesh_api_error'));
        }
      } catch (err) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
        setMeshRunningState(false);
        latestMeshPayload = null;
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshKpis.innerHTML = '';
        meshWarnings.innerHTML = '';
        meshActions.innerHTML = '';
        meshOpportunities.innerHTML = '';
        meshSummary.innerHTML = '';
        updateMeshShareTarget('', false);
        setShareMeshFeedback('');
        applyMeshGraphVisibility();
      }
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

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('sitemap');
      formError.textContent = '';
      runError.textContent = '';
      setShareFeedback('');
      sitemapHasOutput = true;
      summary.style.display = 'none';
      downloadLink.style.display = 'none';
      conflictsDownloadLink.style.display = 'none';
      shareReportBtn.style.display = 'none';
      shareReportBtn.dataset.shareUrl = '';
      resultCard.style.display = 'block';
      clearPreview();
      clearInsights();
      diffBox.style.display = 'none';
      historyBox.textContent = '';

      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }

      const payload = {
        sitemap: document.getElementById('sitemap').value.trim(),
        max_urls: Number(document.getElementById('max_urls').value || 500),
        workers: Number(document.getElementById('workers').value || 8),
        timeout: Number(document.getElementById('timeout').value || 15),
        skip_robots_txt: document.getElementById('skip_robots_txt').checked
      };

      setRunningState(true);
      statusBox.textContent = t('audit_starting');
      logTail.textContent = t('logs_waiting');

      try {
        const res = await fetch('audit.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || t('api_audit_error'));

        renderStatus(data);
        await pollStatus(data.job_id);
        pollTimer = setInterval(() => pollStatus(data.job_id), 2500);
      } catch (err) {
        setRunningState(false);
        formError.textContent = err.message || String(err);
      }
    });

    meshForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('mesh');
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
      meshOpportunities.innerHTML = '';
      updateMeshShareTarget('', false);
      setShareMeshFeedback('');
      meshCard.style.display = 'block';
      meshStatusBox.textContent = t('mesh_loading');
      setMeshRunningState(true);
      meshGraphVisible = false;
      applyMeshGraphVisibility();
      meshOpportunityState = {
        sortKey: 'impact_score',
        direction: 'desc',
        quickWinsOnly: false,
        contextualOnly: false,
        minConfidence: 0,
      };

      const payload = {
        start_url: normalizeMeshStartUrl(meshStartUrl.value.trim()),
        max_pages: Number(meshMaxPages.value || 80),
        timeout: Number(meshTimeout.value || 12),
        max_runtime_ms: Math.min(120000, Math.max(60000, Math.round(
          Number(meshMaxPages.value || 80) * Number(meshTimeout.value || 12) * 700
        ))),
      };
      meshStartUrl.value = payload.start_url;

      try {
        const data = await runMeshAudit(payload);
        if (!data || !data.job_id) {
          throw new Error(t('mesh_api_error'));
        }
        renderMeshJobStatus(data);
        await pollMeshStatus(data.job_id);
        meshPollTimer = setInterval(() => pollMeshStatus(data.job_id), 2500);
      } catch (err) {
        setMeshRunningState(false);
        latestMeshPayload = null;
        meshCard.style.display = 'block';
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshKpis.innerHTML = '';
        meshWarnings.innerHTML = '';
        meshActions.innerHTML = '';
        meshOpportunities.innerHTML = '';
        meshSummary.innerHTML = '';
        updateMeshShareTarget('', false);
        setShareMeshFeedback('');
        applyMeshGraphVisibility();
      }
    });

    if (hasTechMode) techForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('tech');
      techFormError.textContent = '';
      techCard.style.display = 'block';
      techStatusBox.textContent = t('tech_loading');
      techKpis.innerHTML = '';
      techChecks.innerHTML = '';
      techRecos.innerHTML = '';
      setTechRunningState(true);

      const payload = {
        url: techUrlInput.value.trim(),
        timeout: Number(techTimeoutInput.value || 12),
      };

      try {
        const data = await runTechAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('tech_api_error'));
        }
        renderTech(data.audit);
      } catch (err) {
        latestTechPayload = null;
        techCard.style.display = 'block';
        techStatusBox.textContent = t('tech_api_error');
        techFormError.textContent = err.message || String(err);
        techKpis.innerHTML = '';
        techChecks.innerHTML = '';
        techRecos.innerHTML = '';
      } finally {
        setTechRunningState(false);
      }
    });

    if (hasRedirectMode) redirectForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('redirect');
      redirectFormError.textContent = '';
      redirectCard.style.display = 'block';
      redirectStatusBox.textContent = t('redirect_loading');
      redirectKpis.innerHTML = '';
      redirectChecks.innerHTML = '';
      redirectRecos.innerHTML = '';
      setRedirectRunningState(true);

      const payload = {
        url: redirectUrlInput.value.trim(),
        timeout: Number(redirectTimeoutInput.value || 12),
      };

      try {
        const data = await runRedirectAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('redirect_api_error'));
        }
        renderRedirect(data.audit);
      } catch (err) {
        latestRedirectPayload = null;
        redirectCard.style.display = 'block';
        redirectStatusBox.textContent = t('redirect_api_error');
        redirectFormError.textContent = err.message || String(err);
        redirectKpis.innerHTML = '';
        redirectChecks.innerHTML = '';
        redirectRecos.innerHTML = '';
      } finally {
        setRedirectRunningState(false);
      }
    });

    if (hasGeoMode) geoForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('geo');
      geoFormError.textContent = '';
      geoCard.style.display = 'block';
      geoStatusBox.textContent = t('geo_loading');
      geoKpis.innerHTML = '';
      geoChecks.innerHTML = '';
      geoRecos.innerHTML = '';
      setGeoRunningState(true);

      const payload = {
        url: geoUrlInput.value.trim(),
        timeout: Number(geoTimeoutInput.value || 12),
      };

      try {
        const data = await runGeoAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('geo_api_error'));
        }
        renderGeo(data.audit);
      } catch (err) {
        latestGeoPayload = null;
        geoCard.style.display = 'block';
        geoStatusBox.textContent = t('geo_api_error');
        geoFormError.textContent = err.message || String(err);
        geoKpis.innerHTML = '';
        geoChecks.innerHTML = '';
        geoRecos.innerHTML = '';
      } finally {
        setGeoRunningState(false);
      }
    });

    meshResetFocusBtn.addEventListener('click', () => {
      if (typeof meshClearSelection === 'function') {
        meshClearSelection();
      }
    });

    meshResetViewBtn.addEventListener('click', () => {
      if (typeof meshResetView === 'function') {
        meshResetView();
      }
    });

    if (meshToggleGraphBtn) {
      meshToggleGraphBtn.addEventListener('click', () => {
        meshGraphVisible = !meshGraphVisible;
        applyMeshGraphVisibility();
      });
    }

    shareReportBtn.addEventListener('click', async () => {
      const shareUrl = String(shareReportBtn.dataset.shareUrl || '').trim();
      if (!shareUrl) {
        setShareFeedback(t('share_unavailable'), true);
        return;
      }

      try {
        await copyTextToClipboard(shareUrl);
        setShareFeedback(t('share_copied'));
      } catch (err) {
        setShareFeedback(t('share_copy_failed', { url: shareUrl }), true);
      }
    });

    shareMeshBtn.addEventListener('click', async () => {
      const shareUrl = String(shareMeshBtn.dataset.shareUrl || '').trim();
      if (!shareUrl) {
        setShareMeshFeedback(t('share_mesh_unavailable'), true);
        return;
      }

      try {
        await copyTextToClipboard(shareUrl);
        setShareMeshFeedback(t('share_mesh_copied'));
      } catch (err) {
        setShareMeshFeedback(t('share_mesh_failed', { url: shareUrl }), true);
      }
    });

    modeSitemapBtn.addEventListener('click', () => setMode('sitemap'));
    modeMeshBtn.addEventListener('click', () => setMode('mesh'));
    if (modeTechBtn) modeTechBtn.addEventListener('click', () => setMode('tech'));
    if (modeRedirectBtn) modeRedirectBtn.addEventListener('click', () => setMode('redirect'));
    if (modeGeoBtn) modeGeoBtn.addEventListener('click', () => setMode('geo'));
    document.getElementById('sitemap').addEventListener('change', (event) => {
      syncMeshUrlFromSitemap(event.target.value || '');
    });
    document.getElementById('sitemap').addEventListener('blur', (event) => {
      syncMeshUrlFromSitemap(event.target.value || '');
    });
    langFrBtn.addEventListener('click', () => setLang('fr'));
    langEnBtn.addEventListener('click', () => setLang('en'));
    setMode(detectInitialMode(), false);
    setLang(detectInitialLang(), false);
    applyMeshGraphVisibility();
    syncMeshUrlFromSitemap(document.getElementById('sitemap').value || '');

    (function loadSharedMeshOnPageLoad() {
      const meshId = new URLSearchParams(window.location.search).get('mesh_id');
      if (!isValidJobId(meshId || '')) return;
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }

      setMode('mesh', false);
      meshCard.style.display = 'block';
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
      meshOpportunities.innerHTML = '';
      meshStatusBox.textContent = t('shared_loading_mesh');
      updateMeshShareTarget(meshId, false);
      setShareMeshFeedback('');

      loadSharedMesh(meshId)
        .then((data) => {
          if (!data || !data.mesh) {
            throw new Error(t('shared_mesh_bad'));
          }
          renderMesh({ ...data.mesh, mesh_id: data.mesh_id || meshId });
        })
        .catch((err) => {
          latestMeshPayload = null;
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshOpportunities.innerHTML = '';
        updateMeshShareTarget('', false);
        applyMeshGraphVisibility();
      });
    })();

    (function loadSharedReportOnPageLoad() {
      const params = new URLSearchParams(window.location.search);
      if (isValidJobId(params.get('mesh_id') || '')) return;
      const jobId = params.get('job_id');
      if (!isValidJobId(jobId || '')) return;
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }

      setMode('sitemap', false);
      resultCard.style.display = 'block';
      sitemapHasOutput = true;
      formError.textContent = '';
      runError.textContent = '';
      setShareFeedback('');
      summary.style.display = 'none';
      downloadLink.style.display = 'none';
      conflictsDownloadLink.style.display = 'none';
      clearPreview();
      clearInsights();
      diffBox.style.display = 'none';
      historyBox.textContent = '';
      statusBox.textContent = t('shared_loading_report');
      logTail.textContent = t('shared_loading_logs');

      updateShareTarget(jobId, false);

      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }

      pollStatus(jobId);
      pollTimer = setInterval(() => pollStatus(jobId), 2500);
    })();

    [filterIssue, filterStatus, filterIndexable, filterPriority].forEach((el) => {
      el.addEventListener('input', applyPreviewFilters);
      el.addEventListener('change', applyPreviewFilters);
    });
    resetFiltersBtn.addEventListener('click', resetPreviewFilters);
