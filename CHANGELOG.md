# Changelog

Toutes les évolutions notables du projet sont consignées ici.
Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

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

[1.1.0]: https://github.com/tommybds/SEO-SiteMap-Tool/releases/tag/v1.1.0
