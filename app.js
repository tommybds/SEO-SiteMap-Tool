    const form = document.getElementById('audit-form');
    const runBtn = document.getElementById('run-btn');
    const formError = document.getElementById('form-error');
    const modeSitemapBtn = document.getElementById('mode-sitemap-btn');
    const modeMeshBtn = document.getElementById('mode-mesh-btn');
    const modeHelp = document.getElementById('mode-help');
    const sitemapModePanel = document.getElementById('sitemap-mode-panel');
    const meshModePanel = document.getElementById('mesh-mode-panel');
    const meshForm = document.getElementById('mesh-form');
    const meshRunBtn = document.getElementById('mesh-run-btn');
    const meshFormError = document.getElementById('mesh-form-error');
    const meshStartUrl = document.getElementById('mesh_start_url');
    const meshMaxPages = document.getElementById('mesh_max_pages');
    const meshTimeout = document.getElementById('mesh_timeout');
    const resultCard = document.getElementById('result-card');
    const meshCard = document.getElementById('mesh-card');
    const meshSectionTitle = document.getElementById('mesh-section-title');
    const meshStatusBox = document.getElementById('mesh-status-box');
    const meshInteractionHint = document.getElementById('mesh-interaction-hint');
    const shareMeshBtn = document.getElementById('share-mesh-btn');
    const shareMeshFeedback = document.getElementById('share-mesh-feedback');
    const meshResetFocusBtn = document.getElementById('mesh-reset-focus-btn');
    const meshResetViewBtn = document.getElementById('mesh-reset-view-btn');
    const meshGraph = document.getElementById('mesh-graph');
    const meshHoverTooltip = document.getElementById('mesh-hover-tooltip');
    const meshMeta = document.getElementById('mesh-meta');
    const meshKpis = document.getElementById('mesh-kpis');
    const meshWarnings = document.getElementById('mesh-warnings');
    const meshActions = document.getElementById('mesh-actions');
    const meshSummary = document.getElementById('mesh-summary');
    const meshErrors = document.getElementById('mesh-errors');
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

    let pollTimer = null;
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
    let meshGraphController = null;
    let meshClearSelection = null;
    let meshResetView = null;

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
      modeHelp.textContent = t('mode_help');
      labelSitemap.textContent = t('label_sitemap');
      labelMaxUrls.textContent = t('label_max_urls');
      labelWorkers.textContent = t('label_workers');
      labelTimeout.textContent = t('label_timeout');
      labelSkipRobotsText.textContent = t('label_skip_robots');
      labelMeshStartUrl.textContent = t('label_mesh_start_url');
      labelMeshMaxPages.textContent = t('label_mesh_max_pages');
      labelMeshTimeout.textContent = t('label_mesh_timeout');
      jobSectionTitle.textContent = t('job_section_title');
      meshSectionTitle.textContent = t('mesh_section_title');
      shareMeshBtn.textContent = t('share_mesh_btn');
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
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');
      setRunningState(runBtn.disabled);
      setMeshRunningState(meshRunBtn.disabled);
      if (latestStatusPayload) {
        renderStatus(latestStatusPayload);
      } else if (!logTail.textContent.trim()) {
        logTail.textContent = t('no_logs_yet');
      }
      if (latestMeshPayload) {
        renderMesh(latestMeshPayload);
      } else {
        meshInteractionHint.textContent = t('mesh_interaction_hint_idle');
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
      return mode === 'mesh' ? 'mesh' : 'sitemap';
    }

    function setMeshRunningState(running) {
      meshRunBtn.disabled = running;
      meshRunBtn.textContent = running ? t('mesh_run_btn_running') : t('mesh_run_btn_idle');
    }

    function setMode(mode, syncUrl = true) {
      currentMode = mode === 'mesh' ? 'mesh' : 'sitemap';
      sitemapModePanel.style.display = currentMode === 'sitemap' ? 'block' : 'none';
      meshModePanel.style.display = currentMode === 'mesh' ? 'block' : 'none';
      resultCard.style.display = currentMode === 'sitemap' && sitemapHasOutput ? 'block' : 'none';
      previewCard.style.display = currentMode === 'sitemap' && previewLoadedFor ? 'block' : 'none';
      meshCard.style.display = currentMode === 'mesh' && !!latestMeshPayload ? 'block' : 'none';
      modeSitemapBtn.classList.toggle('active', currentMode === 'sitemap');
      modeMeshBtn.classList.toggle('active', currentMode === 'mesh');
      modeSitemapBtn.setAttribute('aria-selected', currentMode === 'sitemap' ? 'true' : 'false');
      modeMeshBtn.setAttribute('aria-selected', currentMode === 'mesh' ? 'true' : 'false');

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
      if (!meshStartUrl.value.trim()) {
        meshStartUrl.value = root;
      } else {
        const currentRoot = inferSiteRootFromUrl(meshStartUrl.value);
        if (!currentRoot) {
          meshStartUrl.value = root;
        }
      }
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
      updateInsightIssueTagStates();
      updateInsightPriorityChipStates();
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
      if (raw === 'orphan_hreflang_only') return t('mesh_issue_orphan_hreflang_only');
      if (raw === 'hreflang_missing_reciprocal') return t('mesh_issue_hreflang_missing_reciprocal');
      return raw || '-';
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
        meshInteractionHint.textContent = t('mesh_graph_empty');
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
      meshInteractionHint.textContent = t('mesh_interaction_hint_idle');

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

      const edgesLimited = edges.slice(0, 1200).filter((edge) => pos.has(edge.source) && pos.has(edge.target));
      const nodeRadiusByUrl = new Map();
      sorted.forEach((node) => {
        const s = score(node);
        const radius = node.is_start ? 10 : Math.max(4, Math.min(10, 4 + s * 0.3));
        nodeRadiusByUrl.set(node.url, radius);
      });
      const neighbors = new Map();
      sorted.forEach((node) => neighbors.set(node.url, new Set()));
      edgesLimited.forEach((edge) => {
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

      edgesLimited.forEach((edge) => {
        const from = pos.get(edge.source);
        const to = pos.get(edge.target);
        if (!from || !to) return;
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
        line.setAttribute('stroke', '#94a3b8');
        line.setAttribute('stroke-opacity', '0.35');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('marker-end', 'url(#mesh-arrow-default)');
        edgeLayer.appendChild(line);
        edgeEls.push({ el: line, source: edge.source, target: edge.target });
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
          setEdgeStyle(item, '#94a3b8', 0.35, 1, 'mesh-arrow-default');
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
          meshInteractionHint.textContent = t('mesh_interaction_hint_idle');
          return;
        }

        const focusedNode = nodeDataByUrl.get(selectedUrl);
        const neighborhood = new Set([selectedUrl, ...(neighbors.get(selectedUrl) || [])]);
        meshResetFocusBtn.disabled = false;
        meshInteractionHint.textContent = t('mesh_interaction_hint_active', {
          path: abbreviatePath(selectedUrl),
          inbound: Number(focusedNode.inbound || 0),
          outbound: Number(focusedNode.outbound || 0),
        });

        edgeEls.forEach((item) => {
          const isOutgoing = item.source === selectedUrl;
          const isIncoming = item.target === selectedUrl;
          const neighborhoodEdge = neighborhood.has(item.source) && neighborhood.has(item.target);
          if (isOutgoing) {
            setEdgeStyle(item, '#2563eb', 0.92, 1.8, 'mesh-arrow-out');
          } else if (isIncoming) {
            setEdgeStyle(item, '#ea580c', 0.92, 1.8, 'mesh-arrow-in');
          } else if (neighborhoodEdge) {
            setEdgeStyle(item, '#94a3b8', 0.28, 1.1, 'mesh-arrow-default');
          } else {
            setEdgeStyle(item, '#cbd5e1', 0.08, 1, 'mesh-arrow-muted');
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

      meshSummary.innerHTML = '';
      [
        { title: t('mesh_summary_hubs'), valueHtml: hubsHtml },
        { title: t('mesh_summary_orphans'), valueHtml: orphanHtml },
        { title: t('mesh_summary_hreflang'), valueHtml: hreflangHtml },
        { title: t('mesh_summary_errors'), valueHtml: errorsHtml },
      ].forEach((box) => {
        const el = document.createElement('div');
        el.className = 'mesh-box';
        el.innerHTML = `<strong class="mesh-box-title">${escapeHtml(box.title)}</strong>${box.valueHtml}`;
        meshSummary.appendChild(el);
      });

      meshErrors.textContent = '';
      renderMeshGraph(Array.isArray(mesh.nodes) ? mesh.nodes : [], Array.isArray(mesh.edges) ? mesh.edges : []);
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
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || t('mesh_api_error'));
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
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
      updateMeshShareTarget('', false);
      setShareMeshFeedback('');
      meshCard.style.display = 'block';
      meshStatusBox.textContent = t('mesh_loading');
      setMeshRunningState(true);

      const payload = {
        start_url: meshStartUrl.value.trim(),
        max_pages: Number(meshMaxPages.value || 80),
        timeout: Number(meshTimeout.value || 12),
      };

      try {
        const data = await runMeshAudit(payload);
        if (!data || !data.mesh) {
          throw new Error(t('mesh_api_error'));
        }
        renderMesh({ ...data.mesh, mesh_id: data.mesh_id || '' });
      } catch (err) {
        latestMeshPayload = null;
        meshCard.style.display = 'block';
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshKpis.innerHTML = '';
        meshWarnings.innerHTML = '';
        meshActions.innerHTML = '';
        updateMeshShareTarget('', false);
        setShareMeshFeedback('');
      } finally {
        setMeshRunningState(false);
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
    syncMeshUrlFromSitemap(document.getElementById('sitemap').value || '');

    (function loadSharedMeshOnPageLoad() {
      const meshId = new URLSearchParams(window.location.search).get('mesh_id');
      if (!isValidJobId(meshId || '')) return;

      setMode('mesh', false);
      meshCard.style.display = 'block';
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
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
          updateMeshShareTarget('', false);
        });
    })();

    (function loadSharedReportOnPageLoad() {
      const params = new URLSearchParams(window.location.search);
      if (isValidJobId(params.get('mesh_id') || '')) return;
      const jobId = params.get('job_id');
      if (!isValidJobId(jobId || '')) return;

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
