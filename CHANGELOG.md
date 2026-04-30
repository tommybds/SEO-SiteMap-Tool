# Changelog

Toutes les évolutions notables du projet sont consignées ici.
Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [1.3.0] - 2026-04-30

### Modifié — Navigation
- « Audit page » devient la catégorie par défaut, « Audit site » passe en seconde position. L'écran d'ouverture présente maintenant l'audit SEO technique sur URL unique (le cas d'usage le plus fréquent).

### Ajouté — Projet
- Première publication d'un fichier [LICENSE](LICENSE) — **PolyForm Noncommercial 1.0.0**. Usage personnel, recherche, éducation, association caritative autorisé. Usage commercial interdit.
- README enrichi : badges (last commit, repo size, PHP, Python, license, version), sections obsolètes mises à jour, bloc License ajouté.

## [1.2.0] - 2026-04-30

### Modifié — Navigation
- Suppression de la catégorie « Synthèse » (elle ne contenait qu'un seul item) — la navigation passe à 2 catégories : « Audit site » et « Audit page ».
- Le « Plan d'action » sort de la navigation et devient un panneau **toujours visible en bas** de la page dès qu'un audit a tourné. Il est repliable d'un clic, et l'état (replié/déplié) est mémorisé entre les visites via `localStorage`.
- Les modes de « Audit page » sont réordonnés par fréquence d'usage : SEO technique → GEO → sécurité → accessibilité → images → redirections.

### Corrigé — Audit GEO
- Les buckets « Priorité haute/moyenne/basse » affichent désormais des actions lisibles (« Renforcer les signaux d'entité… ») au lieu des clés de check brutes (`geo_organization_entity`).

## [1.1.0] - 2026-04-30

### Ajouté — Audit GEO
- Nouveaux checks `/llms.txt` et accès des bots IA dans `robots.txt` (GPTBot, OAI-SearchBot, ChatGPT-User, ClaudeBot, anthropic-ai, PerplexityBot, Perplexity-User, Google-Extended, Applebot-Extended, CCBot, Bytespider, Meta-ExternalAgent, cohere-ai, DuckAssistBot).
- Validation des champs requis JSON-LD par `@type` (Article, Organization, FAQPage, Person, HowTo) — au lieu d'un simple comptage de types.
- Nouveaux checks `canonical`, Open Graph (`og:title`/`og:description`/`og:type`), Twitter Card, H1 unique et ancres sur les H2 (TOC).
- Détection auteur via schema `Person` + `sameAs`, prioritaire sur les heuristiques de classes CSS.
- Snippets prêts à coller pour chaque correction (canonical, OG, dates Article, FAQPage, Organization, Person, `/llms.txt`, `robots.txt` IA).
- Poids de chaque check exposé dans le tableau pour aider à prioriser les corrections.

### Corrigé — Audit GEO
- Premier paragraphe vide ne casse plus la longueur d'intro mesurée (cherche désormais le premier `<p>` non-vide).
- Doublons de blocs FAQ DOM (un même élément ne peut plus être compté plusieurs fois).
- Détection de questions étendue à FR/EN/ES/DE/IT, exige `?` ou un verbe interrogatif en début de heading (plus de faux positifs sur le mot français « comment »).
- Support de `<base href>` pour résoudre les liens relatifs.
- Score recalibré en pourcentage du poids maximum atteignable plutôt qu'en valeur absolue.

### Ajouté — Interface
- Numéro de version `v1.1.0` dans le pied de page, cliquable pour ouvrir une modale changelog bilingue (fr/en).

---

# Changelog (English)

## [1.3.0] - 2026-04-30

### Changed — Navigation
- "Page audit" is now the default category and "Site audit" moves to second position. The landing screen now presents the single-URL technical SEO audit (the most common use case).

### Added — Project
- First published [LICENSE](LICENSE) file — **PolyForm Noncommercial 1.0.0**. Personal, research, education, charity use allowed. Commercial use prohibited.
- README enriched: badges (last commit, repo size, PHP, Python, license, version), outdated sections refreshed, License section added.

## [1.2.0] - 2026-04-30

### Changed — Navigation
- Removed the "Synthesis" category (it only held a single item) — the nav is now down to 2 categories: "Site audit" and "Page audit".
- The "Action plan" moved out of the nav into a **persistent bottom panel** that appears as soon as one audit has run. It collapses with a single click, and the collapsed state is persisted across visits via `localStorage`.
- "Page audit" modes are reordered by usage frequency: technical SEO → GEO → security → accessibility → images → redirects.

### Fixed — GEO audit
- Priority buckets ("High/Medium/Low priority") now display readable actions ("Strengthen entity signals…") instead of raw check keys (`geo_organization_entity`).

## [1.1.0] - 2026-04-30

### Added — GEO audit
- New checks for `/llms.txt` presence and AI-bot access in `robots.txt` (GPTBot, OAI-SearchBot, ChatGPT-User, ClaudeBot, anthropic-ai, PerplexityBot, Perplexity-User, Google-Extended, Applebot-Extended, CCBot, Bytespider, Meta-ExternalAgent, cohere-ai, DuckAssistBot).
- Required-field validation for JSON-LD per `@type` (Article, Organization, FAQPage, Person, HowTo) — instead of just counting types.
- New checks for canonical, Open Graph (`og:title`/`og:description`/`og:type`), Twitter Card, single H1, and H2 anchor ids (TOC).
- Author detection prioritizes schema `Person` + `sameAs` over CSS-class heuristics.
- Copy-paste snippets for every recommended fix (canonical, OG, Article dates, FAQPage, Organization, Person, `/llms.txt`, AI `robots.txt`).
- Per-check weight surfaced in the table to help prioritize fixes.

### Fixed — GEO audit
- An empty first paragraph no longer breaks the intro-length measurement (now scans for the first non-empty `<p>`).
- FAQ DOM blocks are deduplicated (the same element can no longer be counted multiple times).
- Question-heading detection extended to FR/EN/ES/DE/IT and requires `?` or a leading interrogative verb (no more false positives on the French word "comment").
- `<base href>` is now honored when resolving relative links.
- Score recalibrated as a percentage of the maximum achievable weight instead of an absolute value.

### Added — UI
- Version pill `v1.1.0` in the footer; clicking opens a bilingual (fr/en) changelog modal.

[1.3.0]: https://github.com/tommybds/SEO-SiteMap-Tool/releases/tag/v1.3.0
[1.2.0]: https://github.com/tommybds/SEO-SiteMap-Tool/releases/tag/v1.2.0
[1.1.0]: https://github.com/tommybds/SEO-SiteMap-Tool/releases/tag/v1.1.0
