# SEO Tool (PHP + JS + Python)

Deploy-ready web tool for Plesk. The UI is now organized in three top-level categories:

- **Audit site** (batch, multi-URL): `Audit sitemap`, `Maillage interne`
- **Audit page** (URL unique): `Audit SEO technique`, `Audit sécurité`, `Audit accessibilité`, `Audit images`, `Audit GEO`, `Test redirections`
- **Synthèse**: `Plan d'action`

### Demo

- [https://tools.tommy-bordas.fr/](https://tools.tommy-bordas.fr/)

### Features

- Two-level navigation: top-level categories (Site / Page / Synthèse) + contextual sub-tabs
- Recursive sitemap crawling (`sitemapindex` + `urlset`)
- On-page SEO checks (title, meta description, H1, indexability, robots meta)
- Technical SEO checks (`hreflang`, cross-domain/invalid canonical, Open Graph, Twitter Cards, JSON-LD)
- `robots.txt` vs sitemap/indexation consistency checks
- Sitemap/indexation conflict detection (dedicated CSV)
- Priority scoring (`priority_score`, `priority_level`)
- Scan history + diff against previous scan
- In-page CSV preview (sorting + filtering)
- Internal linking mini-audit with graph visualization
- Internal linking live status/progress endpoint (for in-page scan progress)
- Redirect audit with visual chain flow (full URL per hop, HTTP codes, permanent/temporary detection)
- **Security headers audit** (HTTP headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies flags, mixed-content detection)
- Accessibility pre-audit (RGAA 4.1.2 / WCAG 2.1 AA: technical + publication obligations)
- **Images audit** (alt coverage, width/height for CLS protection, lazy loading ratio, modern formats webp/avif, responsive `srcset`/`<picture>`)
- GEO audit focused on AI-answer readiness signals (entity, structure, freshness, Q/A patterns)
- Prioritized action-plan view aggregating findings by source and owner (includes security + images)
- Smart URL normalization in all URL fields (`example.com` -> `https://example.com`)
- Shareable report URL (`?job_id=...`) + copy button
- Bilingual UI FR/EN (`?lang=fr` or `?lang=en`)
- **Account system** (optional, scans remain public): first-registered account becomes admin; subsequent registrations require admin approval. Logged-in users see their own scan history; admins see everyone's scans (including anonymous). Honeypot + CSRF + rate-limited login/register.

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

- `index.html`: web UI shell (vanilla JS)
- `js/core/`: shared globals + runtime helpers
- `js/features/`: feature modules
  - `sitemap.js`, `mesh.js`
  - `audits-shared.js` (helpers reused by every single-URL audit)
  - `audits-tech.js`, `audits-redirect.js`, `audits-geo.js`, `audits-accessibility.js`
  - `audits-security.js`, `audits-images.js`
  - `action-plan.js`
- `js/init.js`: event binding + startup flow
- `i18n.js`: FR/EN translations
- `styles.css`: stylesheet entrypoint importing split CSS files
- `css/`: split stylesheets (`tokens`, `base`, `layout`, `controls`, `forms`, `status`, `tables`, `insights`, `mesh`, `audits`, `action-plan`, `responsive`)
- `audit.php`: starts sitemap audit jobs
- `status.php`: job status/logs/summary/insights
- `preview.php`: JSON CSV preview endpoint
- `mesh.php` / `mesh_status.php` / `mesh_result.php`: internal linking endpoints
- `tech_audit.php`: technical + redirect audit endpoint
- `geo_audit.php`: GEO audit endpoint
- `accessibility_audit.php`: accessibility audit endpoint
- `security_audit.php`: security headers audit endpoint
- `images_audit.php`: images audit endpoint
- `download.php` / `download_conflicts.php`: CSV downloads
- `lib.php`: shared helpers (security, jobs, rate-limit, parsing)
- `auth.php`: auth library (sessions, CSRF, honeypot, users.json store, scan history log)
- `login.php` / `register.php` / `logout.php`: auth pages
- `history.php`: per-user scan history (admin sees all + anonymous)
- `admin_users.php`: admin-only account management (approve, disable, promote, delete)
- `me.php`: JSON endpoint used by the auth bar in `index.html`
- `seo_sitemap_checker.py`: Python audit engine
- `internal_link_mesh.py`: Python internal-link graph engine
- `storage/`: runtime data (jobs, logs, reports)

### Server requirements (Plesk)

1. PHP enabled with `shell_exec` available
2. Python 3 available in CLI (`python3`)
3. PHP cURL extension enabled
4. PHP DOM/XML extension enabled
5. Write permissions on `storage/`

### Security

- Strict sitemap URL validation
- SSRF protection (DNS resolution + private/reserved IP blocking + redirect checks)
- IP-based rate limiting (`audit`, `status`, `preview`, `download`, `mesh`, `tech`, `geo`, `accessibility`, `security`, `images`)
- Concurrent jobs limits (global + per IP)
- Sanitized `job_id` (anti-path-traversal)
- Direct HTTP access to `storage/` blocked via `.htaccess`
- Account system: `password_hash` (bcrypt), 12-char minimum, secure cookies (HttpOnly, SameSite=Lax, Secure on HTTPS), `session_regenerate_id` on login, CSRF tokens on all POST forms, invisible honeypot + time-trap on login/register, generic error messages (no account enumeration), rate limit (login 8 / 15 min, register 5 / 15 min)
- HTTPS must be enforced server-side (Plesk → Hosting Settings → Permanent SEO-safe 301 redirect to HTTPS) — without HTTPS the session cookie can be intercepted

### Adding a new single-URL audit

The project now follows a stable pattern for any new single-URL audit. To add one named `X`:

1. Backend: create `X_audit.php` (follow `security_audit.php` as the minimal template — cURL fetch + DOM/header parsing + `checks[]` + `score` + `checklist` + `respond_json`).
2. Frontend module: `js/features/audits-X.js` exporting `runXAudit()` and `renderX()` using the shared helpers in `audits-shared.js`.
3. UI: in `index.html` add a `<button id="mode-X-btn">` inside the `modes-page` group, the `#X-mode-panel` form and `#X-card` result card.
4. Wiring: register the DOM refs in `js/core/globals.js`, the mode in `MODE_TO_CATEGORY`, the `setMode`/`applyTranslations` blocks in `js/core/runtime.js`, and the submit handler in `js/init.js`.
5. i18n: add the FR + EN keys in `i18n.js` (mode label, help text, form labels, run button states, status/KPIs/checks/recos, API error strings).
6. Action plan: optionally add a `collectXActionPlanFindings()` in `js/features/action-plan.js` and wire it into `buildActionPlanPayload()`.

## Roadmap (not yet shipped)

The following are planned and will reuse the established patterns:

- **Audit site → Liens cassés** (batch, sitemap-scoped): crawl every URL from the sitemap and flag 4xx/5xx.
- **Audit site → Cannibalisation**: cluster pages by title/H1/slug similarity to detect intent overlap.
- **Audit site → Performance (Core Web Vitals batch)**: PageSpeed Insights API over every URL of the sitemap. Needs a `SEO_TOOL_PSI_KEY` env var (or `config.local.php` fallback). Single-URL is intentionally skipped — it's a duplicate of pagespeed.web.dev.
- **Sitemap enrichment → orphan detection**: cross-reference sitemap URLs with mesh-audit internal-link data to flag pages in the sitemap but never linked internally (and vice versa).
- **Mesh enrichment → internal PageRank**: compute an internal PageRank in `internal_link_mesh.py` and surface "pages with high business value but low internal link juice".
- **Action plan enrichment → ROI estimation**: order findings by `impact × ease` instead of pure severity, using per-check weight × effort × (optionally) traffic data.

## Notes

- If `shell_exec` is disabled by your host, jobs cannot start.
- Runtime files are excluded from Git via `.gitignore`.
- All static assets use a `?v=YYYYMMDD-N` cache-buster query string. Bump it when you ship front-end changes so browsers re-fetch CSS/JS.
