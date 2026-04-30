// Auto-split from app.js
form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('sitemap');
      formError.textContent = '';
      runError.textContent = '';
      setShareFeedback('');
      sitemapHasOutput = true;
      summary.style.display = 'none';
      downloadLink.style.display = 'none';
      conflictsDownloadLink.style.display = 'none';
      shareReportBtn.style.display = 'none';
      shareReportBtn.dataset.shareUrl = '';
      resultCard.style.display = 'block';
      clearPreview();
      clearInsights();
      diffBox.style.display = 'none';
      historyBox.textContent = '';

      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }

      const sitemapInput = document.getElementById('sitemap');
      const normalizedSitemap = normalizeUrlInputValue(sitemapInput);
      const payload = {
        sitemap: normalizedSitemap,
        max_urls: Number(document.getElementById('max_urls').value || 500),
        workers: Number(document.getElementById('workers').value || 8),
        timeout: Number(document.getElementById('timeout').value || 15),
        skip_robots_txt: document.getElementById('skip_robots_txt').checked
      };

      setRunningState(true);
      statusBox.textContent = t('audit_starting');
      logTail.textContent = t('logs_waiting');

      try {
        const res = await fetch('audit.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || t('api_audit_error'));

        renderStatus(data);
        await pollStatus(data.job_id);
        pollTimer = setInterval(() => pollStatus(data.job_id), 2500);
      } catch (err) {
        setRunningState(false);
        formError.textContent = err.message || String(err);
      }
    });

    meshForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('mesh');
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
      meshOpportunities.innerHTML = '';
      updateMeshShareTarget('', false);
      setShareMeshFeedback('');
      meshCard.style.display = 'block';
      meshStatusBox.textContent = t('mesh_loading');
      setMeshRunningState(true);
      meshGraphVisible = false;
      applyMeshGraphVisibility();
      meshOpportunityState = {
        sortKey: 'impact_score',
        direction: 'desc',
        quickWinsOnly: false,
        contextualOnly: false,
        minConfidence: 0,
      };

      const normalizedMeshStart = normalizeUrlInputValue(meshStartUrl);
      const payload = {
        start_url: normalizeMeshStartUrl(normalizedMeshStart),
        max_pages: Number(meshMaxPages.value || 80),
        timeout: Number(meshTimeout.value || 12),
        max_runtime_ms: Math.min(120000, Math.max(60000, Math.round(
          Number(meshMaxPages.value || 80) * Number(meshTimeout.value || 12) * 700
        ))),
      };
      meshStartUrl.value = payload.start_url;

      try {
        const data = await runMeshAudit(payload);
        if (!data || !data.job_id) {
          throw new Error(t('mesh_api_error'));
        }
        renderMeshJobStatus(data);
        await pollMeshStatus(data.job_id);
        meshPollTimer = setInterval(() => pollMeshStatus(data.job_id), 2500);
      } catch (err) {
        setMeshRunningState(false);
        latestMeshPayload = null;
        meshCard.style.display = 'block';
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshKpis.innerHTML = '';
        meshWarnings.innerHTML = '';
        meshActions.innerHTML = '';
        meshOpportunities.innerHTML = '';
        meshSummary.innerHTML = '';
        updateMeshShareTarget('', false);
        setShareMeshFeedback('');
        applyMeshGraphVisibility();
        renderActionPlan();
      }
    });

    if (hasTechMode) techForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('tech');
      techFormError.textContent = '';
      techCard.style.display = 'block';
      techStatusBox.textContent = t('tech_loading');
      techKpis.innerHTML = '';
      techChecks.innerHTML = '';
      techRecos.innerHTML = '';
      setTechRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(techUrlInput),
        timeout: Number(techTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: null });

      try {
        const data = await runTechAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('tech_api_error'));
        }
        renderTech(data.audit);
      } catch (err) {
        latestTechPayload = null;
        techCard.style.display = 'block';
        techStatusBox.textContent = t('tech_api_error');
        techFormError.textContent = err.message || String(err);
        techKpis.innerHTML = '';
        techChecks.innerHTML = '';
        techRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setTechRunningState(false);
      }
    });

    if (hasRedirectMode) redirectForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('redirect');
      redirectFormError.textContent = '';
      redirectCard.style.display = 'block';
      redirectStatusBox.textContent = t('redirect_loading');
      if (redirectFlow) {
        redirectFlow.innerHTML = `<div class="mesh-actions-empty">${escapeHtml(t('redirect_loading'))}</div>`;
      }
      redirectKpis.innerHTML = '';
      redirectChecks.innerHTML = '';
      redirectRecos.innerHTML = '';
      setRedirectRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(redirectUrlInput),
        timeout: Number(redirectTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: null });

      try {
        const data = await runRedirectAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('redirect_api_error'));
        }
        renderRedirect(data.audit);
      } catch (err) {
        latestRedirectPayload = null;
        redirectCard.style.display = 'block';
        redirectStatusBox.textContent = t('redirect_api_error');
        if (redirectFlow) {
          redirectFlow.innerHTML = `<div class="danger">${escapeHtml(err.message || t('redirect_api_error'))}</div>`;
        }
        redirectFormError.textContent = err.message || String(err);
        redirectKpis.innerHTML = '';
        redirectChecks.innerHTML = '';
        redirectRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setRedirectRunningState(false);
      }
    });

    if (hasGeoMode) geoForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('geo');
      geoFormError.textContent = '';
      geoCard.style.display = 'block';
      geoStatusBox.textContent = t('geo_loading');
      geoKpis.innerHTML = '';
      geoChecks.innerHTML = '';
      geoRecos.innerHTML = '';
      setGeoRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(geoUrlInput),
        timeout: Number(geoTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: null });

      try {
        const data = await runGeoAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('geo_api_error'));
        }
        renderGeo(data.audit);
      } catch (err) {
        latestGeoPayload = null;
        geoCard.style.display = 'block';
        geoStatusBox.textContent = t('geo_api_error');
        geoFormError.textContent = err.message || String(err);
        geoKpis.innerHTML = '';
        geoChecks.innerHTML = '';
        geoRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setGeoRunningState(false);
      }
    });

    if (hasSecurityMode) securityForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('security');
      securityFormError.textContent = '';
      securityCard.style.display = 'block';
      securityStatusBox.textContent = t('security_loading');
      securityKpis.innerHTML = '';
      securityChecks.innerHTML = '';
      securityRecos.innerHTML = '';
      setSecurityRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(securityUrlInput),
        timeout: Number(securityTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: null });

      try {
        const data = await runSecurityAudit(payload);
        if (!data || !data.audit) throw new Error(t('security_api_error'));
        renderSecurity(data.audit);
      } catch (err) {
        latestSecurityPayload = null;
        securityCard.style.display = 'block';
        securityStatusBox.textContent = t('security_api_error');
        securityFormError.textContent = err.message || String(err);
        securityKpis.innerHTML = '';
        securityChecks.innerHTML = '';
        securityRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setSecurityRunningState(false);
      }
    });

    if (hasImagesMode) imagesForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('images');
      imagesFormError.textContent = '';
      imagesCard.style.display = 'block';
      imagesStatusBox.textContent = t('images_loading');
      imagesKpis.innerHTML = '';
      imagesChecks.innerHTML = '';
      imagesRecos.innerHTML = '';
      setImagesRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(imagesUrlInput),
        timeout: Number(imagesTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: null });

      try {
        const data = await runImagesAudit(payload);
        if (!data || !data.audit) throw new Error(t('images_api_error'));
        renderImages(data.audit);
      } catch (err) {
        latestImagesPayload = null;
        imagesCard.style.display = 'block';
        imagesStatusBox.textContent = t('images_api_error');
        imagesFormError.textContent = err.message || String(err);
        imagesKpis.innerHTML = '';
        imagesChecks.innerHTML = '';
        imagesRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setImagesRunningState(false);
      }
    });

    if (hasAccessibilityMode) accessibilityForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMode('accessibility');
      accessibilityFormError.textContent = '';
      accessibilityCard.style.display = 'block';
      accessibilityStatusBox.textContent = t('accessibility_loading');
      accessibilityKpis.innerHTML = '';
      accessibilityChecks.innerHTML = '';
      accessibilityRecos.innerHTML = '';
      setAccessibilityRunningState(true);

      const payload = {
        url: normalizeUrlInputValue(accessibilityUrlInput),
        standard: String(accessibilityStandardInput && accessibilityStandardInput.value ? accessibilityStandardInput.value : 'rgaa4'),
        timeout: Number(accessibilityTimeoutInput.value || 12),
      };
      syncAuditUrlParams({ url: payload.url, std: payload.standard });

      try {
        const data = await runAccessibilityAudit(payload);
        if (!data || !data.audit) {
          throw new Error(t('accessibility_api_error'));
        }
        renderAccessibility(data.audit);
      } catch (err) {
        latestAccessibilityPayload = null;
        accessibilityCard.style.display = 'block';
        accessibilityStatusBox.textContent = t('accessibility_api_error');
        accessibilityFormError.textContent = err.message || String(err);
        accessibilityKpis.innerHTML = '';
        accessibilityChecks.innerHTML = '';
        accessibilityRecos.innerHTML = '';
        renderActionPlan();
      } finally {
        setAccessibilityRunningState(false);
      }
    });

    meshResetFocusBtn.addEventListener('click', () => {
      if (typeof meshClearSelection === 'function') {
        meshClearSelection();
      }
    });

    meshResetViewBtn.addEventListener('click', () => {
      if (typeof meshResetView === 'function') {
        meshResetView();
      }
    });

    if (meshToggleGraphBtn) {
      meshToggleGraphBtn.addEventListener('click', () => {
        meshGraphVisible = !meshGraphVisible;
        applyMeshGraphVisibility();
      });
    }

    // Context filter pills — toggle which link types appear in the graph.
    document.querySelectorAll('.mesh-filter-pill').forEach((pill) => {
      pill.addEventListener('click', () => {
        const ctx = String(pill.dataset.context || '').toLowerCase();
        if (!ctx) return;
        if (meshActiveContexts.has(ctx)) {
          meshActiveContexts.delete(ctx);
          pill.classList.remove('is-active');
          pill.setAttribute('aria-pressed', 'false');
        } else {
          meshActiveContexts.add(ctx);
          pill.classList.add('is-active');
          pill.setAttribute('aria-pressed', 'true');
        }
        refreshMeshGraphView();
      });
    });

    shareReportBtn.addEventListener('click', async () => {
      const shareUrl = String(shareReportBtn.dataset.shareUrl || '').trim();
      if (!shareUrl) {
        setShareFeedback(t('share_unavailable'), true);
        return;
      }

      try {
        await copyTextToClipboard(shareUrl);
        setShareFeedback(t('share_copied'));
      } catch (err) {
        setShareFeedback(t('share_copy_failed', { url: shareUrl }), true);
      }
    });

    shareMeshBtn.addEventListener('click', async () => {
      const shareUrl = String(shareMeshBtn.dataset.shareUrl || '').trim();
      if (!shareUrl) {
        setShareMeshFeedback(t('share_mesh_unavailable'), true);
        return;
      }

      try {
        await copyTextToClipboard(shareUrl);
        setShareMeshFeedback(t('share_mesh_copied'));
      } catch (err) {
        setShareMeshFeedback(t('share_mesh_failed', { url: shareUrl }), true);
      }
    });

    modeSitemapBtn.addEventListener('click', () => setMode('sitemap'));
    modeMeshBtn.addEventListener('click', () => setMode('mesh'));
    if (modeTechBtn) modeTechBtn.addEventListener('click', () => setMode('tech'));
    if (modeRedirectBtn) modeRedirectBtn.addEventListener('click', () => setMode('redirect'));
    if (modeAccessibilityBtn) modeAccessibilityBtn.addEventListener('click', () => setMode('accessibility'));
    if (modeSecurityBtn) modeSecurityBtn.addEventListener('click', () => setMode('security'));
    if (modeImagesBtn) modeImagesBtn.addEventListener('click', () => setMode('images'));
    if (modeGeoBtn) modeGeoBtn.addEventListener('click', () => setMode('geo'));
    if (catSiteBtn) catSiteBtn.addEventListener('click', () => {
      if (modeCategory(currentMode) !== 'site') setMode(CATEGORY_DEFAULT_MODE.site);
    });
    if (catPageBtn) catPageBtn.addEventListener('click', () => {
      if (modeCategory(currentMode) !== 'page') setMode(CATEGORY_DEFAULT_MODE.page);
    });
    const sitemapInput = document.getElementById('sitemap');
    [sitemapInput, meshStartUrl, techUrlInput, redirectUrlInput, accessibilityUrlInput, securityUrlInput, imagesUrlInput, geoUrlInput]
      .filter((inputEl) => !!inputEl)
      .forEach((inputEl) => {
        const applyAutoScheme = () => {
          const normalized = normalizeUrlInputValue(inputEl);
          if (inputEl === sitemapInput) {
            syncMeshUrlFromSitemap(normalized);
          }
        };
        inputEl.addEventListener('blur', applyAutoScheme);
        inputEl.addEventListener('change', applyAutoScheme);
        inputEl.addEventListener('keydown', (event) => {
          if (event.key === 'Enter') {
            applyAutoScheme();
          }
        });
      });
    langFrBtn.addEventListener('click', () => setLang('fr'));
    langEnBtn.addEventListener('click', () => setLang('en'));
    setMode(detectInitialMode(), false);
    setLang(detectInitialLang(), false);
    applyInitialAuditParams();
    applyMeshGraphVisibility();
    syncMeshUrlFromSitemap(normalizeUrlInputValue(sitemapInput));

    (function loadSharedMeshOnPageLoad() {
      const meshId = new URLSearchParams(window.location.search).get('mesh_id');
      if (!isValidJobId(meshId || '')) return;
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }

      setMode('mesh', false);
      meshCard.style.display = 'block';
      meshFormError.textContent = '';
      meshErrors.textContent = '';
      meshSummary.innerHTML = '';
      meshMeta.textContent = '';
      meshKpis.innerHTML = '';
      meshWarnings.innerHTML = '';
      meshActions.innerHTML = '';
      meshOpportunities.innerHTML = '';
      meshStatusBox.textContent = t('shared_loading_mesh');
      updateMeshShareTarget(meshId, false);
      setShareMeshFeedback('');

      loadSharedMesh(meshId)
        .then((data) => {
          if (!data || !data.mesh) {
            throw new Error(t('shared_mesh_bad'));
          }
          renderMesh({ ...data.mesh, mesh_id: data.mesh_id || meshId });
        })
        .catch((err) => {
          latestMeshPayload = null;
        meshStatusBox.textContent = t('mesh_api_error');
        meshFormError.textContent = err.message || String(err);
        meshOpportunities.innerHTML = '';
        updateMeshShareTarget('', false);
        applyMeshGraphVisibility();
        renderActionPlan();
      });
    })();

    (function loadSharedReportOnPageLoad() {
      const params = new URLSearchParams(window.location.search);
      if (isValidJobId(params.get('mesh_id') || '')) return;
      const jobId = params.get('job_id');
      if (!isValidJobId(jobId || '')) return;
      if (meshPollTimer) {
        clearInterval(meshPollTimer);
        meshPollTimer = null;
      }

      setMode('sitemap', false);
      resultCard.style.display = 'block';
      sitemapHasOutput = true;
      formError.textContent = '';
      runError.textContent = '';
      setShareFeedback('');
      summary.style.display = 'none';
      downloadLink.style.display = 'none';
      conflictsDownloadLink.style.display = 'none';
      clearPreview();
      clearInsights();
      diffBox.style.display = 'none';
      historyBox.textContent = '';
      statusBox.textContent = t('shared_loading_report');
      logTail.textContent = t('shared_loading_logs');

      updateShareTarget(jobId, false);

      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }

      pollStatus(jobId);
      pollTimer = setInterval(() => pollStatus(jobId), 2500);
    })();

    [filterIssue, filterStatus, filterIndexable, filterPriority].forEach((el) => {
      el.addEventListener('input', applyPreviewFilters);
      el.addEventListener('change', applyPreviewFilters);
    });
    resetFiltersBtn.addEventListener('click', resetPreviewFilters);
