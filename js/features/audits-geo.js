// GEO audit: labels, recommendations, renderer.

const localizeGeoCheckLabel = buildLabelLookup({
  geo_http_status_2xx: 'geo_http_status_2xx',
  geo_html_content_type: 'geo_html_content_type',
  geo_indexable: 'geo_indexable',
  geo_canonical: 'geo_canonical',
  geo_open_graph: 'geo_open_graph',
  geo_twitter_card: 'geo_twitter_card',
  geo_h1_unique: 'geo_h1_unique',
  geo_structured_data: 'geo_structured_data',
  geo_jsonld_validity: 'geo_jsonld_validity',
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
  geo_heading_anchors: 'geo_heading_anchors',
  geo_llms_txt: 'geo_llms_txt',
  geo_ai_crawlers_allowed: 'geo_ai_crawlers_allowed',
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
  geo_reco_add_canonical: 'geo_reco_add_canonical',
  geo_reco_add_open_graph: 'geo_reco_add_open_graph',
  geo_reco_add_twitter_card: 'geo_reco_add_twitter_card',
  geo_reco_fix_h1: 'geo_reco_fix_h1',
  geo_reco_fix_jsonld: 'geo_reco_fix_jsonld',
  geo_reco_add_heading_anchors: 'geo_reco_add_heading_anchors',
  geo_reco_add_llms_txt: 'geo_reco_add_llms_txt',
  geo_reco_unblock_ai_crawlers: 'geo_reco_unblock_ai_crawlers',
});

function renderGeoChecksTableWithWeight(container, checks) {
  if (!container) return;
  if (!checks.length) {
    container.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('geo_checks_empty'))}</div>`;
    return;
  }
  const sorted = checks.slice().sort((a, b) => {
    const order = { fail: 0, warn: 1, pass: 2 };
    const sa = order[String(a.status || 'warn').toLowerCase()] ?? 1;
    const sb = order[String(b.status || 'warn').toLowerCase()] ?? 1;
    if (sa !== sb) return sa - sb;
    return Number(b.weight || 0) - Number(a.weight || 0);
  });
  const rows = sorted.map((check) => {
    const status = String(check.status || 'warn').toLowerCase();
    const value = String(check.value || '-');
    const weight = Number(check.weight || 0);
    const label = localizeGeoCheckLabel(check.key);
    const statusLabel = localizeAuditStatus(status, 'geo');
    const weightCell = weight > 0
      ? `<span class="geo-weight-pill" title="${escapeHtml(t('geo_detail_weight'))}">${weight}</span>`
      : '';
    return `
      <tr>
        <td>${escapeHtml(label)} ${weightCell}</td>
        <td><span class="tech-check-badge ${escapeHtml(status)}">${escapeHtml(statusLabel)}</span></td>
        <td>${escapeHtml(value)}</td>
      </tr>
    `;
  }).join('');
  container.innerHTML = `
    <div class="tech-checks-head">${escapeHtml(t('geo_checks_title'))}</div>
    <div class="tech-checks-table-wrap">
      <table class="tech-checks-table geo-checks-table">
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

function renderGeoAiBots(metrics) {
  const bots = metrics && typeof metrics.ai_bots === 'object' ? metrics.ai_bots : {};
  const robotsReachable = !!metrics.robots_txt_reachable;
  if (!robotsReachable) {
    return `<div class="geo-ai-bots geo-ai-bots-empty"><strong>${escapeHtml(t('geo_detail_ai_bots'))}</strong><br><span class="muted">${escapeHtml(t('geo_detail_ai_bots_no_robots'))}</span></div>`;
  }
  const entries = Object.entries(bots);
  if (!entries.length) return '';
  const items = entries.map(([bot, info]) => {
    const allowed = !!(info && info.allowed);
    const ruleText = info && info.matched_rule ? String(info.matched_rule) : '';
    const ruleHint = ruleText ? `<span class="geo-bot-rule">${escapeHtml(ruleText)}</span>` : '';
    return `
      <li class="geo-bot-row ${allowed ? 'allowed' : 'blocked'}">
        <span class="geo-bot-name">${escapeHtml(bot)}</span>
        <span class="geo-bot-status">${escapeHtml(allowed ? t('geo_bot_allowed') : t('geo_bot_blocked'))}</span>
        ${ruleHint}
      </li>
    `;
  }).join('');
  return `
    <div class="geo-ai-bots">
      <strong>${escapeHtml(t('geo_detail_ai_bots'))}</strong>
      <ul class="geo-bot-list">${items}</ul>
    </div>
  `;
}

function buildGeoSnippet(key, ctx) {
  const finalUrl = String(ctx.finalUrl || '').replace(/`/g, '');
  const host = ctx.host || '';
  const title = String(ctx.title || 'Page title');
  const desc = String(ctx.description || 'Short summary of the page.');
  const today = new Date().toISOString().slice(0, 10);
  switch (key) {
    case 'geo_snippet_canonical':
      return `<link rel="canonical" href="${finalUrl}">`;
    case 'geo_snippet_open_graph':
      return `<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:type" content="article">
<meta property="og:url" content="${finalUrl}">
<meta property="og:image" content="https://${host}/path/to/cover.jpg">`;
    case 'geo_snippet_twitter_card':
      return `<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image" content="https://${host}/path/to/cover.jpg">`;
    case 'geo_snippet_dates':
      return `<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "${title}",
  "datePublished": "${today}T08:00:00+00:00",
  "dateModified": "${today}T08:00:00+00:00",
  "author": { "@type": "Person", "name": "Author Name" },
  "publisher": {
    "@type": "Organization",
    "name": "${host}",
    "logo": { "@type": "ImageObject", "url": "https://${host}/logo.png" }
  }
}
</script>`;
    case 'geo_snippet_organization':
      return `<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "${host}",
  "url": "https://${host}/",
  "logo": "https://${host}/logo.png",
  "sameAs": [
    "https://www.linkedin.com/company/your-company",
    "https://twitter.com/your-handle"
  ]
}
</script>`;
    case 'geo_snippet_author':
      return `<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Person",
  "name": "Author Name",
  "jobTitle": "Role / Topic expertise",
  "url": "https://${host}/team/author-slug",
  "sameAs": [
    "https://www.linkedin.com/in/author-handle",
    "https://twitter.com/author-handle"
  ]
}
</script>`;
    case 'geo_snippet_faq':
      return `<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Question 1?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Direct, factual answer in 2-4 sentences."
      }
    },
    {
      "@type": "Question",
      "name": "Question 2?",
      "acceptedAnswer": { "@type": "Answer", "text": "Answer 2." }
    }
  ]
}
</script>`;
    case 'geo_snippet_llms_txt':
      return `# ${host}

> Short pitch: what this site/company does in one sentence.

## Key pages
- [Homepage](https://${host}/)
- [Pricing](https://${host}/pricing)
- [Docs](https://${host}/docs)

## About
- Founded: YYYY
- Location: City, Country
- Contact: hello@${host}`;
    case 'geo_snippet_robots_ai':
      return `# robots.txt — explicitly allow major AI crawlers
User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: Applebot-Extended
Allow: /

User-agent: CCBot
Allow: /

# Block paths you don't want indexed by anyone
User-agent: *
Disallow: /admin/`;
    default:
      return '';
  }
}

function renderGeoSnippets(audit, statusByKey) {
  const finalUrl = String(audit.final_url || audit.url || '');
  let host = '';
  try { host = new URL(finalUrl).host; } catch (_) { host = ''; }
  const metrics = audit.metrics || {};
  const ctx = {
    finalUrl,
    host,
    title: metrics.title || '',
    description: metrics.meta_description || metrics.og_description || '',
  };
  const planned = [];
  const want = (cond, key, titleKey) => { if (cond) planned.push({ key, titleKey }); };
  want(statusByKey.geo_canonical !== 'pass', 'geo_snippet_canonical', 'geo_snippet_canonical');
  want(statusByKey.geo_open_graph !== 'pass', 'geo_snippet_open_graph', 'geo_snippet_open_graph');
  want(statusByKey.geo_twitter_card !== 'pass', 'geo_snippet_twitter_card', 'geo_snippet_twitter_card');
  want(statusByKey.geo_date_metadata !== 'pass' || statusByKey.geo_jsonld_validity !== 'pass', 'geo_snippet_dates', 'geo_snippet_dates');
  want(statusByKey.geo_organization_entity !== 'pass', 'geo_snippet_organization', 'geo_snippet_organization');
  want(statusByKey.geo_author_signal !== 'pass', 'geo_snippet_author', 'geo_snippet_author');
  want(statusByKey.geo_faq_markup !== 'pass' && (Number(metrics.question_headings_count || 0) >= 1 || statusByKey.geo_qa_format !== 'pass'), 'geo_snippet_faq', 'geo_snippet_faq');
  want(statusByKey.geo_llms_txt !== 'pass', 'geo_snippet_llms_txt', 'geo_snippet_llms_txt');
  want(statusByKey.geo_ai_crawlers_allowed !== 'pass', 'geo_snippet_robots_ai', 'geo_snippet_robots_ai');

  if (!planned.length) return '';
  const blocks = planned.map(({ key, titleKey }) => {
    const code = buildGeoSnippet(key, ctx);
    if (!code) return '';
    return `
      <details class="geo-snippet">
        <summary>${escapeHtml(t(titleKey))}</summary>
        <pre class="geo-snippet-code"><code>${escapeHtml(code)}</code></pre>
      </details>
    `;
  }).join('');
  return `
    <div class="geo-snippets">
      <div class="tech-recos-head">${escapeHtml(t('geo_snippets_title'))}</div>
      ${blocks}
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

  const statusByKey = {};
  checks.forEach((c) => { statusByKey[String(c.key || '')] = String(c.status || 'warn').toLowerCase(); });

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

  renderGeoChecksTableWithWeight(geoChecks, checks);

  const datesValue = [publishedDate, modifiedDate].filter(Boolean).join(' / ');
  const wordCount = Number(metrics.word_count || 0);
  const internalLinks = Number(metrics.internal_links_count || 0);
  const externalLinks = Number(metrics.external_links_count || 0);
  const h1c = Number(metrics.h1_count || 0);
  const h2c = Number(metrics.h2_count || 0);
  const h3c = Number(metrics.h3_count || 0);
  const jsonValid = Number(metrics.jsonld_valid || 0);
  const jsonInvalid = Number(metrics.jsonld_invalid || 0);
  const jsonIssues = Array.isArray(metrics.jsonld_issues) ? metrics.jsonld_issues : [];
  const authorPersons = Array.isArray(metrics.author_persons) ? metrics.author_persons : [];
  const canonical = String(metrics.canonical || '').trim();
  const ogTitle = String(metrics.og_title || '').trim();
  const ogDesc = String(metrics.og_description || '').trim();
  const ogType = String(metrics.og_type || '').trim();
  const twitterCard = String(metrics.twitter_card || '').trim();

  const dash = `<span class="muted">-</span>`;
  const detailsRows = [
    `<div><strong>${escapeHtml(t('geo_detail_canonical'))}</strong><br>${canonical ? escapeHtml(canonical) : dash}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_open_graph'))}</strong><br>${(ogTitle || ogDesc || ogType) ? escapeHtml(`${ogType || '-'} · ${ogTitle ? '✓' : '·'} title · ${ogDesc ? '✓' : '·'} desc`) : dash}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_twitter'))}</strong><br>${twitterCard ? escapeHtml(twitterCard) : dash}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_word_count'))}</strong><br>${escapeHtml(String(wordCount))}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_headings'))}</strong><br>${escapeHtml(`${h1c} / ${h2c} / ${h3c}`)}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_links'))}</strong><br>${escapeHtml(`${internalLinks} / ${externalLinks}`)}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_structured_types'))}</strong><br>${structuredTypes.length ? escapeHtml(structuredTypes.slice(0, 8).join(', ')) : `<span class="muted">${escapeHtml(t('mesh_none'))}</span>`}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_jsonld_health'))}</strong><br>${escapeHtml(t('geo_detail_jsonld_health_value', { valid: jsonValid, invalid: jsonInvalid }))}${jsonIssues.length ? `<br><span class="muted">${escapeHtml(jsonIssues.slice(0, 3).join(' | '))}</span>` : ''}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_authors'))}</strong><br>${authorPersons.length ? escapeHtml(authorPersons.slice(0, 3).map((p) => p.name + (p.sameAs && p.sameAs.length ? ` (${p.sameAs.length} sameAs)` : '')).join(', ')) : dash}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_dates'))}</strong><br>${datesValue ? escapeHtml(datesValue) : dash}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_freshness'))}</strong><br>${escapeHtml(freshnessText)}</div>`,
    `<div><strong>${escapeHtml(t('geo_detail_llms_txt'))}</strong><br>${metrics.llms_txt_present ? escapeHtml(t('geo_detail_llms_txt_present', { size: Number(metrics.llms_txt_size || 0) })) : escapeHtml(t('geo_detail_llms_txt_missing'))}</div>`,
  ].join('');

  geoRecos.innerHTML = `
    <div class="tech-recos-head">${escapeHtml(t('geo_recos_title'))}</div>
    ${renderPriorityChecklist(checklist, recommendations, localizeGeoRecommendation, 'geo')}
    <div class="tech-details-grid">${detailsRows}</div>
    ${renderGeoAiBots(metrics)}
    ${renderGeoSnippets(audit, statusByKey)}
  `;
  renderActionPlan();
}
