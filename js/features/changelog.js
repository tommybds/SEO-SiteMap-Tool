// App version + changelog modal.

const APP_VERSION = '1.1.0';

const CHANGELOG_ENTRIES = [
  {
    version: '1.1.0',
    date: '2026-04-30',
    fr: [
      'Audit GEO: nouveaux checks /llms.txt et accès des bots IA dans robots.txt (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, Applebot-Extended, CCBot, etc.).',
      'Audit GEO: validation des champs requis JSON-LD (Article, Organization, FAQPage, Person, HowTo) au lieu d’un simple comptage de @type.',
      'Audit GEO: nouveaux checks canonical, Open Graph, Twitter Card, H1 unique et ancres sur les H2 (TOC).',
      'Audit GEO: meilleure détection auteur (schema Person + sameAs prioritaires sur les classes CSS).',
      'Audit GEO: snippets prêts à coller pour chaque correction (canonical, OG, dates Article, FAQPage, Organization, /llms.txt, robots.txt IA).',
      'Audit GEO: poids de chaque check exposé dans le tableau pour prioriser les corrections.',
      'Audit GEO: corrections de bugs (premier paragraphe vide, doublons FAQ DOM, regex de questions FR/EN/ES/DE/IT, support de <base href>).',
    ],
    en: [
      'GEO audit: new checks for /llms.txt and AI-bot access in robots.txt (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, Applebot-Extended, CCBot…).',
      'GEO audit: required-field validation for JSON-LD (Article, Organization, FAQPage, Person, HowTo) instead of just counting @type.',
      'GEO audit: new canonical, Open Graph, Twitter Card, single-H1 and H2-anchor (TOC) checks.',
      'GEO audit: improved author detection (schema Person + sameAs prioritized over CSS classes).',
      'GEO audit: copy-paste snippets for each fix (canonical, OG, Article dates, FAQPage, Organization, /llms.txt, AI robots.txt).',
      'GEO audit: weight of each check exposed in the table to help prioritize fixes.',
      'GEO audit: bug fixes (empty first paragraph, FAQ DOM dedupe, FR/EN/ES/DE/IT question regex, <base href> support).',
    ],
  },
];

(function setupChangelog() {
  function escapeChangelogHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function renderChangelog() {
    const lang = (typeof currentLang === 'string' && currentLang) ? currentLang : 'fr';
    const blocks = CHANGELOG_ENTRIES.map((entry) => {
      const items = (entry[lang] || entry.fr || []).map((line) => `<li>${escapeChangelogHtml(line)}</li>`).join('');
      return `
        <article class="changelog-entry">
          <header class="changelog-entry-head">
            <span class="changelog-entry-version">v${escapeChangelogHtml(entry.version)}</span>
            <span class="changelog-entry-date">${escapeChangelogHtml(entry.date)}</span>
          </header>
          <ul class="changelog-entry-list">${items}</ul>
        </article>
      `;
    }).join('');
    return blocks;
  }

  function openChangelog() {
    const modal = document.getElementById('changelog-modal');
    const body = document.getElementById('changelog-body');
    if (!modal || !body) return;
    body.innerHTML = renderChangelog();
    modal.removeAttribute('hidden');
    document.body.classList.add('changelog-open');
  }

  function closeChangelog() {
    const modal = document.getElementById('changelog-modal');
    if (!modal) return;
    modal.setAttribute('hidden', '');
    document.body.classList.remove('changelog-open');
  }

  function init() {
    const btn = document.getElementById('footer-version');
    if (btn) {
      btn.textContent = `v${APP_VERSION}`;
      btn.addEventListener('click', openChangelog);
    }
    const modal = document.getElementById('changelog-modal');
    if (modal) {
      modal.addEventListener('click', (event) => {
        if (event.target === modal || event.target.matches('[data-changelog-close]')) {
          closeChangelog();
        }
      });
    }
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeChangelog();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
