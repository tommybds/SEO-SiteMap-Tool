(function () {
  const panel = document.getElementById('user-recent-scans');
  const list = document.getElementById('user-recent-scans-list');
  const typeBadge = document.getElementById('user-recent-scans-type');
  if (!panel || !list) return;

  const MODE_TO_TYPE = {
    sitemap: 'sitemap_audit',
    mesh: 'mesh_audit',
    tech: 'tech_audit',
    redirect: 'tech_audit',
    security: 'security_audit',
    accessibility: 'accessibility_audit',
    images: 'images_audit',
    geo: 'geo_audit',
  };

  const MODE_TO_INPUT = {
    sitemap: 'sitemap',
    mesh: 'mesh_start_url',
    tech: 'tech_url',
    redirect: 'redirect_url',
    security: 'security_url',
    accessibility: 'accessibility_url',
    images: 'images_url',
    geo: 'geo_url',
  };

  const TYPE_LABEL = {
    sitemap_audit: 'Sitemap',
    mesh_audit: 'Maillage',
    tech_audit: 'SEO technique',
    security_audit: 'Securite',
    accessibility_audit: 'Accessibilite',
    images_audit: 'Images',
    geo_audit: 'GEO',
  };

  let isAuthed = false;
  let currentMode = null;

  function escape(value) {
    return String(value || '').replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function shortDate(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, '0');
    return pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function shortTarget(url) {
    if (!url) return '';
    try {
      const u = new URL(url);
      return (u.host + u.pathname).replace(/\/$/, '') || url;
    } catch (e) {
      return url;
    }
  }

  function detectMode() {
    const active = document.querySelector('.mode-btn.active, .mode-btn[aria-selected="true"]');
    if (!active || !active.id) return null;
    const m = active.id.match(/^mode-([a-z\-]+)-btn$/);
    if (!m) return null;
    return m[1];
  }

  function fillUrlField(mode, url) {
    const inputId = MODE_TO_INPUT[mode];
    if (!inputId) return false;
    const input = document.getElementById(inputId);
    if (!input) return false;
    input.value = url;
    input.focus();
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  }

  function handleClick(mode, entry, ev) {
    ev.preventDefault();
    const target = entry.target || '';
    const jobId = entry.job_id || '';
    const kind = entry.job_kind || '';

    if (kind === 'audit' && jobId) {
      const url = new URL(window.location.href);
      url.searchParams.set('job_id', jobId);
      url.searchParams.set('mode', 'sitemap');
      window.location.href = url.toString();
      return;
    }
    if (kind === 'mesh' && jobId) {
      window.location.href = 'mesh_status.php?job_id=' + encodeURIComponent(jobId);
      return;
    }
    if (target) {
      const filled = fillUrlField(mode, target);
      if (filled) {
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }
  }

  function render(mode, entries) {
    const type = MODE_TO_TYPE[mode];
    typeBadge.textContent = TYPE_LABEL[type] || '';

    if (!entries || entries.length === 0) {
      list.innerHTML = '<li class="user-recent-scans-empty">Aucun scan dans cette categorie pour le moment.</li>';
      return;
    }

    list.innerHTML = '';
    entries.forEach(function (entry) {
      const li = document.createElement('li');
      li.className = 'user-recent-scans-item';
      const isPersisted = (entry.job_kind === 'audit' || entry.job_kind === 'mesh') && entry.job_id;
      const cta = isPersisted ? 'Voir le rapport' : 'Reutiliser l URL';
      li.innerHTML =
        '<button type="button" class="user-recent-scans-link">' +
          '<span class="user-recent-scans-target" title="' + escape(entry.target) + '">' + escape(shortTarget(entry.target)) + '</span>' +
          '<span class="user-recent-scans-meta"><span class="user-recent-scans-date">' + escape(shortDate(entry.ts)) + '</span><span class="user-recent-scans-cta">' + cta + '</span></span>' +
        '</button>';
      li.querySelector('button').addEventListener('click', function (ev) {
        handleClick(mode, entry, ev);
      });
      list.appendChild(li);
    });
  }

  function loadForMode(mode) {
    if (!isAuthed) return;
    if (!mode) return;
    const type = MODE_TO_TYPE[mode];
    if (!type) {
      panel.hidden = true;
      return;
    }
    currentMode = mode;
    const url = 'history_recent.php?type=' + encodeURIComponent(type) + '&limit=8';
    fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.authenticated) {
          panel.hidden = true;
          return;
        }
        render(mode, data.entries || []);
        panel.hidden = false;
      })
      .catch(function () { panel.hidden = true; });
  }

  function bindModeChanges() {
    document.querySelectorAll('.mode-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setTimeout(function () {
          const m = detectMode();
          if (m && m !== currentMode) loadForMode(m);
        }, 30);
      });
    });
    document.querySelectorAll('.nav-category-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setTimeout(function () {
          const m = detectMode();
          if (m) loadForMode(m);
        }, 60);
      });
    });
  }

  function init() {
    fetch('me.php', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.authenticated) {
          panel.hidden = true;
          return;
        }
        isAuthed = true;
        bindModeChanges();
        const mode = detectMode() || 'sitemap';
        loadForMode(mode);
      })
      .catch(function () { /* silent */ });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
