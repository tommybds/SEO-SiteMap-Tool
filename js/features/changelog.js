// App version + changelog modal.

const APP_VERSION = '1.4.0';

const CHANGELOG_ENTRIES = [
  {
    version: '1.4.0',
    date: '2026-04-30',
    fr: [
      'Audits page (tech, GEO, sécurité, accessibilité, images, redirections): l’URL scannée est désormais portée dans la querystring (`?url=…`) à chaque lancement, et le champ se pré-remplit automatiquement quand on arrive avec ce paramètre.',
      'Audit accessibilité: le référentiel choisi (RGAA 4.1.2 ou RGAA 5) est aussi sérialisé dans `?std=…`.',
      'Conséquence: les liens d’audit sont désormais bookmarkables et partageables. L’ouverture d’un lien partagé pré-remplit le formulaire mais ne lance pas le scan automatiquement (privilège du destinataire).',
    ],
    en: [
      'Page audits (tech, GEO, security, accessibility, images, redirects): the scanned URL is now carried in the querystring (`?url=…`) on each run, and the input field is automatically pre-filled when arriving with that parameter.',
      'Accessibility audit: the selected standard (RGAA 4.1.2 or RGAA 5) is also serialized as `?std=…`.',
      'Result: audit links are now bookmarkable and shareable. Opening a shared link pre-fills the form but does not auto-run the scan (recipient stays in control).',
    ],
  },
  {
    version: '1.3.0',
    date: '2026-04-30',
    fr: [
      'Navigation: « Audit page » devient la catégorie par défaut, « Audit site » passe en seconde position. L’écran d’ouverture présente maintenant l’audit SEO technique sur URL unique (le cas d’usage le plus fréquent).',
      'Projet: première publication d’un fichier LICENSE (PolyForm Noncommercial 1.0.0) — usage personnel/recherche/éducation autorisé, usage commercial interdit.',
      'README: badges (last commit, repo size, PHP, Python, license, version), sections obsolètes mises à jour, bloc License ajouté.',
    ],
    en: [
      'Navigation: "Page audit" is now the default category, "Site audit" moves to second position. The landing screen now presents the single-URL technical SEO audit (the most common use case).',
      'Project: first published LICENSE file (PolyForm Noncommercial 1.0.0) — personal, research, education use allowed, commercial use prohibited.',
      'README: badges (last commit, repo size, PHP, Python, license, version), outdated sections refreshed, License section added.',
    ],
  },
  {
    version: '1.2.0',
    date: '2026-04-30',
    fr: [
      'Navigation simplifiée: 2 catégories au lieu de 3 (« Synthèse » supprimée car elle ne contenait qu’un seul item).',
      'Plan d’action sorti de la nav: il s’affiche désormais en bas dès qu’un audit a tourné, repliable d’un clic et état mémorisé entre les visites.',
      'Audits page réordonnés par fréquence d’usage: SEO technique → GEO → sécurité → accessibilité → images → redirections.',
      'Audit GEO: les buckets « Priorité haute/moyenne/basse » affichent désormais des actions lisibles au lieu des clés de check brutes (geo_organization_entity → « Renforcer les signaux d’entité »).',
    ],
    en: [
      'Simplified navigation: 2 categories instead of 3 ("Synthesis" removed since it only held a single item).',
      'Action plan moved out of the nav: it now sits at the bottom and shows up as soon as one audit has run, collapsible with a single click, state persisted across visits.',
      'Page audits reordered by usage frequency: technical SEO → GEO → security → accessibility → images → redirects.',
      'GEO audit: priority buckets now show readable actions instead of raw check keys (geo_organization_entity → "Strengthen entity signals").',
    ],
  },
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
