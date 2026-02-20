# SEO Sitemap Tool (PHP + JS + Python)

Outil web prêt à déployer sur Plesk pour auditer un sitemap XML, analyser les pages, générer des rapports CSV et visualiser les résultats directement dans l’interface.

## Fonctionnalités

- Scan récursif des sitemaps (`sitemapindex` + `urlset`)
- Vérifications SEO on-page (title, meta description, H1, indexabilité, robots meta)
- Vérifications SEO techniques:
  - `hreflang`
  - canonical cross-domain / invalide
  - Open Graph / Twitter Cards
  - structured data JSON-LD
- Contrôle cohérence `robots.txt` vs sitemap/indexation
- Détection de conflits sitemap/indexation (CSV dédié)
- Scoring de priorité (`priority_score`, `priority_level`)
- Historique des scans + diff avec le scan précédent
- Aperçu CSV dans la page (filtres + tri)
- URL de partage de rapport (`?job_id=...`) + bouton de copie

## Structure du dossier

- `index.html`: interface web (JS vanilla)
- `audit.php`: démarre un job d’audit
- `status.php`: suivi du job (statut, logs, résumé, insights)
- `preview.php`: aperçu CSV en JSON
- `download.php`: téléchargement du CSV principal
- `download_conflicts.php`: téléchargement du CSV de conflits
- `lib.php`: fonctions partagées (sécurité, jobs, rate-limit, parsing)
- `seo_sitemap_checker.py`: moteur d’audit Python
- `storage/`: données runtime (jobs, logs, rapports)

## Prérequis serveur (Plesk)

1. PHP actif avec `shell_exec` disponible
2. Python 3 disponible en CLI (`python3`)
3. Droits d’écriture sur `storage/`

## Déploiement

1. Uploader ce dossier sur ton vhost, par exemple:
   - `https://tools.ton-domaine.fr/seo/`
2. Vérifier les permissions d’écriture sur `storage/`
3. Ouvrir `index.html` et lancer un audit

## Endpoints

- `POST audit.php`
- `GET status.php?job_id=<id>`
- `GET preview.php?job_id=<id>&rows=120`
- `GET download.php?job_id=<id>`
- `GET download_conflicts.php?job_id=<id>`

## Partage de rapport

- Après un scan, utiliser le bouton **Copier l’URL du rapport**
- Le lien partagé contient `job_id`:
  - `https://tools.ton-domaine.fr/seo/?job_id=<id>`
- Ouvrir ce lien recharge automatiquement le rapport

## Sécurité intégrée

- Validation stricte des URLs sitemap
- Protection SSRF (résolution DNS + blocage IP privées/réservées + contrôles de redirection)
- Rate limiting par IP (`audit`, `status`, `preview`, `download`)
- Limites de jobs concurrents (global + IP)
- `job_id` sanitizé (anti traversal)
- Accès HTTP direct au contenu de `storage/` bloqué via `.htaccess`

## Notes

- Si `shell_exec` est désactivé chez l’hébergeur, les jobs ne démarreront pas.
- Les fichiers runtime sont exclus du git via `.gitignore`.
