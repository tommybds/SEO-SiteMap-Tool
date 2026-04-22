// Auto-split from app.js
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

    function buildFullUrlLink(url) {
      const rawUrl = String(url || '').trim();
      const safeUrl = escapeHtml(rawUrl);
      return `<a class="mesh-link" href="${safeUrl}" target="_blank" rel="noopener noreferrer" title="${safeUrl}">${safeUrl}</a>`;
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
      renderActionPlan();
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
        renderActionPlan();
      }
    }

