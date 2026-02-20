# SEO Sitemap Tool (PHP + JS + Python)

## FR

Outil web prêt à déployer sur Plesk pour auditer un sitemap XML, analyser les pages, générer des rapports CSV et visualiser les résultats directement dans l’interface.

### Fonctionnalités

- Scan récursif des sitemaps (`sitemapindex` + `urlset`)
- Vérifications SEO on-page (title, meta description, H1, indexabilité, robots meta)
- Vérifications SEO techniques (`hreflang`, canonical cross-domain/invalide, Open Graph, Twitter Cards, JSON-LD)
- Contrôle de cohérence `robots.txt` vs sitemap/indexation
- Détection de conflits sitemap/indexation (CSV dédié)
- Scoring de priorité (`priority_score`, `priority_level`)
- Historique des scans + diff avec le scan précédent
- Aperçu CSV dans la page (tri + filtres)
- URL de partage de rapport (`?job_id=...`) + bouton de copie
- Interface bilingue FR/EN (`?lang=fr` ou `?lang=en`)

### Insights visibles sur la page publique

- KPIs: pages analysées, pages sans problèmes, pages avec problèmes
- Bloc **Insights clés**:
  - répartition des priorités (critique/haute/moyenne/basse/aucune)
  - nombre de conflits sitemap/indexation
  - top problèmes détectés (regroupés par type)
  - top causes de conflit
- Bloc **Comparaison avec le scan précédent**:
  - nouvelles URLs avec problèmes
  - URLs corrigées
  - URLs modifiées
  - URLs ajoutées/supprimées
- Bloc **Aperçu du CSV**:
  - tableau lisible avec tri
  - filtres (issue, HTTP, indexable, priorité)
  - badges visuels (HTTP, indexable, priorité)

### Structure du dossier

- `index.html`: interface web (JS vanilla)
- `audit.php`: démarre un job d’audit
- `status.php`: suivi du job (statut, logs, résumé, insights)
- `preview.php`: aperçu CSV en JSON
- `download.php`: téléchargement du CSV principal
- `download_conflicts.php`: téléchargement du CSV de conflits
- `lib.php`: fonctions partagées (sécurité, jobs, rate-limit, parsing)
- `seo_sitemap_checker.py`: moteur d’audit Python
- `storage/`: données runtime (jobs, logs, rapports)

### Prérequis serveur (Plesk)

1. PHP actif avec `shell_exec` disponible
2. Python 3 disponible en CLI (`python3`)
3. Droits d’écriture sur `storage/`

### Déploiement

1. Uploader ce dossier sur ton vhost, par exemple `https://tools.ton-domaine.fr/seo/`
2. Vérifier les permissions d’écriture sur `storage/`
3. Ouvrir `index.html` et lancer un audit

### Endpoints

- `POST audit.php`
- `GET status.php?job_id=<id>`
- `GET preview.php?job_id=<id>&rows=120`
- `GET download.php?job_id=<id>`
- `GET download_conflicts.php?job_id=<id>`

### Sécurité

- Validation stricte des URLs sitemap
- Protection SSRF (DNS + blocage IP privées/réservées + contrôles de redirection)
- Rate limiting par IP (`audit`, `status`, `preview`, `download`)
- Limites de jobs concurrents (global + IP)
- `job_id` sanitizé (anti traversal)
- Accès HTTP direct au contenu de `storage/` bloqué via `.htaccess`

## EN

Deploy-ready web tool for Plesk to audit XML sitemaps, crawl pages, generate CSV reports, and display actionable SEO insights in the UI.

### Features

- Recursive sitemap crawling (`sitemapindex` + `urlset`)
- On-page SEO checks (title, meta description, H1, indexability, robots meta)
- Technical SEO checks (`hreflang`, cross-domain/invalid canonical, Open Graph, Twitter Cards, JSON-LD)
- `robots.txt` vs sitemap/indexation consistency checks
- Sitemap/indexation conflict detection (dedicated CSV)
- Priority scoring (`priority_score`, `priority_level`)
- Scan history + diff against previous scan
- In-page CSV preview (sorting + filtering)
- Shareable report URL (`?job_id=...`) + copy button
- Bilingual UI FR/EN (`?lang=fr` or `?lang=en`)

### Public page insights

- KPI cards: scanned pages, pages without issues, pages with issues
- **Key Insights** panel:
  - priority distribution (critical/high/medium/low/none)
  - sitemap/indexation conflict count
  - top detected issues (grouped by issue type)
  - top conflict reasons
- **Diff vs previous scan** panel:
  - new problematic URLs
  - fixed URLs
  - changed problematic URLs
  - added/removed URLs
- **CSV Preview** panel:
  - sortable table
  - filters (issue, HTTP, indexable, priority)
  - visual badges (HTTP, indexable, priority)

### Folder structure

- `index.html`: web UI (vanilla JS)
- `audit.php`: starts audit jobs
- `status.php`: job status/logs/summary/insights
- `preview.php`: JSON CSV preview endpoint
- `download.php`: main CSV download
- `download_conflicts.php`: conflicts CSV download
- `lib.php`: shared helpers (security, jobs, rate-limit, parsing)
- `seo_sitemap_checker.py`: Python audit engine
- `storage/`: runtime data (jobs, logs, reports)

### Server requirements (Plesk)

1. PHP enabled with `shell_exec` available
2. Python 3 available in CLI (`python3`)
3. Write permissions on `storage/`

### Security

- Strict sitemap URL validation
- SSRF protection (DNS resolution + private/reserved IP blocking + redirect checks)
- IP-based rate limiting (`audit`, `status`, `preview`, `download`)
- Concurrent jobs limits (global + per IP)
- Sanitized `job_id` (anti-path-traversal)
- Direct HTTP access to `storage/` blocked via `.htaccess`

## Notes

- If `shell_exec` is disabled by your host, jobs cannot start.
- Runtime files are excluded from Git via `.gitignore`.
