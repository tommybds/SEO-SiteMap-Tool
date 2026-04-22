// Auto-split from app.js
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
      renderActionPlan();
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
      renderActionPlan();
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
      renderActionPlan();
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

