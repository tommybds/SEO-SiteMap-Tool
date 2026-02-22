# SEO Sitemap Tool (PHP + JS + Python)

Deploy-ready web tool for Plesk to audit XML sitemaps, crawl pages, generate CSV reports, and display actionable SEO insights in the UI.

### Demo

- [https://tools.tommy-bordas.fr/](https://tools.tommy-bordas.fr/)

### Features

- Recursive sitemap crawling (`sitemapindex` + `urlset`)
- On-page SEO checks (title, meta description, H1, indexability, robots meta)
- Technical SEO checks (`hreflang`, cross-domain/invalid canonical, Open Graph, Twitter Cards, JSON-LD)
- `robots.txt` vs sitemap/indexation consistency checks
- Sitemap/indexation conflict detection (dedicated CSV)
- Priority scoring (`priority_score`, `priority_level`)
- Scan history + diff against previous scan
- In-page CSV preview (sorting + filtering)
- Internal linking mini-audit with graph visualization
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
- `mesh.php`: internal linking mesh endpoint (JSON graph)
- `download.php`: main CSV download
- `download_conflicts.php`: conflicts CSV download
- `lib.php`: shared helpers (security, jobs, rate-limit, parsing)
- `seo_sitemap_checker.py`: Python audit engine
- `internal_link_mesh.py`: Python internal-link graph engine
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
