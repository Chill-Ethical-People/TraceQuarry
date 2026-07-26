    const form = document.getElementById('run-form');
    const button = document.getElementById('run-button');
    const inspectButton = document.getElementById('inspect-button');
    const statusBox = document.getElementById('status');
    const runProgress = document.getElementById('run-progress');
    const progressTitle = document.getElementById('progress-title');
    const progressPercent = document.getElementById('progress-percent');
    const progressFill = document.getElementById('progress-fill');
    const progressSteps = document.getElementById('progress-steps');
    const collectionQueue = document.getElementById('collection-queue');
    const queueTitle = document.getElementById('queue-title');
    const queuePath = document.getElementById('queue-path');
    const queueFilter = document.getElementById('queue-filter');
    const queueStatuses = document.getElementById('queue-statuses');
    const queueBody = document.getElementById('queue-body');
    const metricsBox = document.getElementById('metrics');
    const runActions = document.getElementById('run-actions');
    const previewSummary = document.getElementById('preview-summary');
    const reviewBriefing = document.getElementById('review-briefing');
    const exploreTimeline = document.getElementById('explore-timeline');
    const exportWorkbook = document.getElementById('export-workbook');
    const exportTimeline = document.getElementById('export-timeline');
    const downloadSummary = document.getElementById('download-summary');
    const previousCase = document.getElementById('previous-case');
    const previousCasePicker = document.getElementById('previous-case-picker');
    const previousCaseTrigger = document.getElementById('previous-case-trigger');
    const previousCaseValue = document.getElementById('previous-case-value');
    const previousCaseSubtitle = document.getElementById('previous-case-subtitle');
    const previousCaseCount = document.getElementById('previous-case-count');
    const previousCaseMenu = document.getElementById('previous-case-menu');
    const openPreviousCase = document.getElementById('open-previous-case');
    const previousCaseMeta = document.getElementById('previous-case-meta');
    const serviceHealth = document.getElementById('service-health');
    const filesBox = document.getElementById('files');
    const consoleBox = document.getElementById('console');
    const detailsBox = document.getElementById('details');
    const summaryModal = document.getElementById('summary-modal');
    const summaryPreview = document.getElementById('summary-preview');
    const summaryOpen = document.getElementById('summary-open');
    const summaryWorkbook = document.getElementById('summary-workbook');
    const summaryExport = document.getElementById('summary-export');
    const summaryClose = document.getElementById('summary-close');
    const summaryCloseFooter = document.getElementById('summary-close-footer');
    const briefingModal = document.getElementById('briefing-modal');
    const briefingContent = document.getElementById('briefing-content');
    const briefingWorkbook = document.getElementById('briefing-workbook');
    const briefingExport = document.getElementById('briefing-export');
    const briefingClose = document.getElementById('briefing-close');
    const briefingCloseFooter = document.getElementById('briefing-close-footer');
    const timelineModal = document.getElementById('timeline-modal');
    const timelineClose = document.getElementById('timeline-close');
    const timelineSearch = document.getElementById('timeline-search');
    const timelineSeverity = document.getElementById('timeline-severity');
    const timelineSource = document.getElementById('timeline-source');
    const timelinePhase = document.getElementById('timeline-phase');
    const timelineSummary = document.getElementById('timeline-summary');
    const timelineScope = document.getElementById('timeline-scope');
    const timelineWorkbook = document.getElementById('timeline-workbook');
    const timelineExport = document.getElementById('timeline-export');
    const timelineList = document.getElementById('timeline-list');
    const timelineCount = document.getElementById('timeline-count');
    const timelinePage = document.getElementById('timeline-page');
    const timelinePrev = document.getElementById('timeline-prev');
    const timelineNext = document.getElementById('timeline-next');
    const eventDetail = document.getElementById('event-detail');
    const rangePanel = document.getElementById('range-panel');
    const rangeSummary = document.getElementById('range-summary');
    const rangeEarliest = document.getElementById('range-earliest');
    const rangeLatest = document.getElementById('range-latest');
    const coverageScore = document.getElementById('coverage-score');
    const coverageGroups = document.getElementById('coverage-groups');
    const incidentStart = document.getElementById('incident_start');
    const incidentEnd = document.getElementById('incident_end');
    const sourceRadios = [...document.querySelectorAll('input[name="source_mode"]')];
    const uploadCard = document.getElementById('upload-card');
    const pathCard = document.getElementById('path-card');
    const uploadPanel = document.getElementById('upload-panel');
    const pathPanel = document.getElementById('path-panel');
    const uploadInput = document.getElementById('uac_file');
    const uploadDrop = document.getElementById('evidence-drop');
    const browseUpload = document.getElementById('browse-upload');
    const clearUpload = document.getElementById('clear-upload');
    const uploadSelection = document.getElementById('upload-selection');
    const pathInput = document.getElementById('input_path');
    const threatType = document.getElementById('threat_type');
    const assistProfile = document.getElementById('assist-profile');
    const assistProfileLabel = document.getElementById('assist-profile-label');
    const assistProfileDescription = document.getElementById('assist-profile-description');
    const threatProfiles = JSON.parse(document.querySelector('meta[name="tracequarry-profiles"]').content);
    const guidedAnalystTags = [
      ['lateral_movement', 'Lateral Movement'],
      ['persistence', 'Persistence'],
      ['execution', 'Execution'],
      ['exfiltration', 'Exfiltration'],
      ['credential_harvesting', 'Credential Harvesting'],
      ['discovery_reconnaissance', 'Discovery / Reconnaissance']
    ];
    const attackPhaseLabels = {
      reconnaissance: 'Reconnaissance', resource_development: 'Resource Development',
      initial_access: 'Initial Access', execution: 'Execution', persistence: 'Persistence',
      privilege_escalation: 'Privilege Escalation', stealth: 'Stealth',
      defense_impairment: 'Defense Impairment', credential_access: 'Credential Access',
      discovery: 'Discovery', lateral_movement: 'Lateral Movement', collection: 'Collection',
      command_and_control: 'Command and Control', exfiltration: 'Exfiltration', impact: 'Impact'
    };
    const csrfToken = document.querySelector('meta[name="tracequarry-csrf"]').content;
    const datePickers = {
      incident_start: createDateTimePicker('incident_start', 'Select start time'),
      incident_end: createDateTimePicker('incident_end', 'Select end time')
    };
    let pollTimer = null;
    let activeJobId = null;
    let activeSummaryUrl = '';
    let summaryShownForJob = '';
    let previousCases = [];
    let timelineSearchTimer = null;
    let timelineState = { offset: 0, limit: 80, total: 0, items: [], selectedEventId: '' };
    let stagedUpload = null;
    let stagedFingerprint = '';
    let selectedUploadFiles = [];
    let uploadDragDepth = 0;
    let queueCollections = [];
    let queueStagingPath = '';
    let queueRenderPending = false;
    const progressStages = [
      ['uploading', 'Staging evidence'],
      ['staged', 'Upload verified'],
      ['queued', 'Job accepted'],
      ['parsing', 'Parsing evidence'],
      ['normalizing', 'Normalizing timeline'],
      ['writing_outputs', 'Writing outputs'],
      ['complete', 'Ready for review']
    ];

    for (const radio of sourceRadios) {
      radio.addEventListener('change', syncSourceMode);
    }
    syncSourceMode();
    uploadInput.addEventListener('change', () => {
      selectUploadFiles([...uploadInput.files], { append: false, source: 'browse' });
    });
    browseUpload.addEventListener('click', (event) => {
      event.stopPropagation();
      uploadInput.click();
    });
    clearUpload.addEventListener('click', (event) => {
      event.stopPropagation();
      uploadInput.value = '';
      selectUploadFiles([], { append: false, source: 'clear' });
      browseUpload.focus();
    });
    uploadDrop.addEventListener('dragenter', (event) => {
      event.preventDefault();
      uploadDragDepth += 1;
      uploadDrop.classList.add('is-dragover');
    });
    uploadDrop.addEventListener('dragover', (event) => {
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
    });
    uploadDrop.addEventListener('dragleave', () => {
      uploadDragDepth = Math.max(0, uploadDragDepth - 1);
      if (!uploadDragDepth) uploadDrop.classList.remove('is-dragover');
    });
    uploadDrop.addEventListener('drop', (event) => {
      event.preventDefault();
      uploadDragDepth = 0;
      uploadDrop.classList.remove('is-dragover');
      selectUploadFiles([...event.dataTransfer.files], { append: true, source: 'drop' });
    });
    queueFilter.addEventListener('input', renderCollectionQueue);
    threatType.addEventListener('change', syncThreatProfile);
    syncThreatProfile();
    loadPreviousCases();
    refreshServiceHealth();
    window.setInterval(refreshServiceHealth, 30000);

    function syncThreatProfile() {
      const selected = threatProfiles.find(profile => profile.id === threatType.value);
      assistProfile.hidden = !selected;
      assistProfileLabel.textContent = selected ? selected.label : '';
      assistProfileDescription.textContent = selected ? selected.description : '';
    }

    async function refreshServiceHealth() {
      try {
        const response = await fetch('/api/health', { cache: 'no-store' });
        const health = await response.json();
        const capacity = health.capacity || {};
        const jobs = health.jobs || {};
        const used = Number(capacity.committed_bytes || 0);
        const maximum = Number(capacity.max_work_bytes || 0);
        const reserved = Number(capacity.reserved_bytes || 0);
        const running = Number(jobs.running || 0) + Number(jobs.queued || 0);
        serviceHealth.className = `service-health ${health.ready ? 'ready' : 'degraded'}`;
        serviceHealth.textContent = health.ready
          ? `Service ready · ${formatBytes(used)} of ${formatBytes(maximum)} committed · ${formatBytes(reserved)} reserved · ${running} active job(s)`
          : `Service degraded · ${formatBytes(used)} of ${formatBytes(maximum)} committed · review /api/health`;
      } catch (_error) {
        serviceHealth.className = 'service-health degraded';
        serviceHealth.textContent = 'Service health unavailable. Existing analysis jobs may still be running.';
      }
    }

    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) entry.target.classList.add('visible');
      }
    }, { threshold: 0.12 });
    document.querySelectorAll('.reveal').forEach((node, index) => {
      node.style.transitionDelay = `${index * 70}ms`;
      observer.observe(node);
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const mode = getSourceMode();
      if (!validateEvidenceInput(mode)) return;
      button.disabled = true;
      inspectButton.disabled = true;
      filesBox.innerHTML = '';
      runActions.hidden = true;
      activeSummaryUrl = '';
      summaryShownForJob = '';
      metricsBox.hidden = true;
      consoleBox.hidden = true;
      try {
        if (mode === 'upload') await ensureUploadsStaged();
        updateProgress({ status: 'queued', stage: 'queued', progress: 27 });
        setStatus('running', 'Submitting analysis job...');
        const body = buildEvidenceFormData(mode);
        const response = await fetch('/api/run', {
          method: 'POST', headers: { 'X-TraceQuarry-CSRF': csrfToken }, body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to start job');
        activeJobId = data.job_id;
        pollJob(data.job_id);
      } catch (error) {
        setStatus('failed', error.message || 'Unable to start job');
        button.disabled = false;
        inspectButton.disabled = false;
      }
    });

    inspectButton.addEventListener('click', async () => {
      const mode = getSourceMode();
      if (!validateEvidenceInput(mode)) return;
      button.disabled = true;
      inspectButton.disabled = true;
      try {
        if (mode === 'upload') await ensureUploadsStaged();
        setStatus('running', 'Submitting evidence inspection...');
        const response = await fetch('/api/inspect', {
          method: 'POST', headers: { 'X-TraceQuarry-CSRF': csrfToken }, body: buildEvidenceFormData(mode)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to inspect time range');
        activeJobId = data.job_id;
        pollJob(data.job_id);
      } catch (error) {
        setStatus('failed', error.message || 'Unable to inspect time range');
        button.disabled = false;
        inspectButton.disabled = false;
      }
    });

    async function pollJob(jobId) {
      clearTimeout(pollTimer);
      const response = await fetch(`/api/job/${jobId}`);
      const job = await response.json();
      if (job.job_type === 'inspection') renderInspectionJob(job);
      else renderJob(job);
      if (job.status === 'queued' || job.status === 'running') {
        pollTimer = setTimeout(() => pollJob(jobId), 1500);
      } else {
        button.disabled = false;
        inspectButton.disabled = false;
        if (job.status === 'complete' && job.job_type !== 'inspection') loadPreviousCases(job.id);
      }
    }

    async function loadPreviousCases(preferredJobId = '') {
      try {
        const response = await fetch('/api/cases', { cache: 'no-store' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to load previous cases');
        previousCases = data.cases || [];
        const currentJobId = previousCase.value;
        previousCase.value = previousCases.some(item => item.id === preferredJobId)
          ? preferredJobId
          : (previousCases.some(item => item.id === currentJobId) ? currentJobId : '');
        renderPreviousCaseMenu();
        syncPreviousCase();
      } catch (error) {
        previousCases = [];
        previousCase.value = '';
        previousCaseMenu.innerHTML = '';
        closePreviousCaseMenu();
        previousCaseTrigger.disabled = true;
        previousCaseValue.textContent = 'Previous cases unavailable';
        previousCaseSubtitle.textContent = 'The local case index could not be loaded';
        previousCaseCount.hidden = true;
        previousCaseMeta.textContent = error.message || 'Unable to load previous cases.';
        openPreviousCase.disabled = true;
      }
    }

    function caseOptionElements() {
      return Array.from(previousCaseMenu.querySelectorAll('[role="option"]'));
    }

    function completedCaseLabel(item) {
      return item.completed_at
        ? new Date(Number(item.completed_at) * 1000).toLocaleString()
        : 'Completion time unavailable';
    }

    function pluralizedCount(value, singular, plural = `${singular}s`) {
      const count = Number(value || 0);
      return `${count.toLocaleString()} ${count === 1 ? singular : plural}`;
    }

    function caseResultLabel(item) {
      const result = item.result || {};
      const scope = item.is_case
        ? pluralizedCount(result.collections, 'collection')
        : 'Single collection';
      return [
        scope,
        pluralizedCount(result.events, 'event'),
        pluralizedCount(result.findings, 'finding')
      ].join(' · ');
    }

    function renderPreviousCaseMenu() {
      previousCaseMenu.innerHTML = previousCases.map(item => {
        const selected = item.id === previousCase.value;
        const kind = item.is_case ? 'Case workspace' : 'Host analysis';
        return `
          <button
            class="case-select-option"
            type="button"
            role="option"
            data-case-id="${escapeHtml(String(item.id))}"
            aria-selected="${selected ? 'true' : 'false'}"
          >
            <span class="case-option-copy">
              <strong>${escapeHtml(String(item.case_name || 'TraceQuarry Case'))}</strong>
              <small>${escapeHtml(completedCaseLabel(item))} · ${escapeHtml(caseResultLabel(item))}</small>
            </span>
            <span class="case-option-kind">${kind}</span>
          </button>`;
      }).join('');
    }

    function closePreviousCaseMenu({ focusTrigger = false } = {}) {
      previousCaseMenu.hidden = true;
      previousCaseTrigger.setAttribute('aria-expanded', 'false');
      previousCasePicker.classList.remove('is-open');
      if (focusTrigger) previousCaseTrigger.focus();
    }

    function openPreviousCaseMenu(focusMode = 'selected') {
      if (previousCaseTrigger.disabled || !previousCases.length) return;
      previousCaseMenu.hidden = false;
      previousCaseTrigger.setAttribute('aria-expanded', 'true');
      previousCasePicker.classList.add('is-open');
      requestAnimationFrame(() => {
        const options = caseOptionElements();
        let target = options.find(option => option.getAttribute('aria-selected') === 'true');
        if (focusMode === 'first') target = options[0];
        if (focusMode === 'last') target = options[options.length - 1];
        (target || options[0])?.focus();
      });
    }

    function selectPreviousCase(caseId) {
      if (!previousCases.some(item => item.id === caseId)) return;
      previousCase.value = caseId;
      syncPreviousCase();
    }

    function focusAdjacentCaseOption(direction) {
      const options = caseOptionElements();
      if (!options.length) return;
      const activeIndex = options.indexOf(document.activeElement);
      const nextIndex = activeIndex < 0
        ? 0
        : (activeIndex + direction + options.length) % options.length;
      options[nextIndex].focus();
    }

    function syncPreviousCase() {
      const selected = previousCases.find(item => item.id === previousCase.value);
      const count = previousCases.length;
      previousCaseTrigger.disabled = count === 0;
      previousCaseCount.textContent = String(count);
      previousCaseCount.hidden = count === 0;
      openPreviousCase.disabled = !selected;
      caseOptionElements().forEach(option => {
        option.setAttribute('aria-selected', String(option.dataset.caseId === previousCase.value));
      });
      if (!selected) {
        previousCaseValue.textContent = count ? 'Select a completed case' : 'No completed cases found';
        previousCaseSubtitle.textContent = count
          ? 'Choose a preserved analysis workspace'
          : 'Completed analyses will appear here';
        previousCaseMeta.textContent = previousCases.length
          ? `${previousCases.length} completed case(s) available in this work directory.`
          : 'Completed outputs in this work directory remain available after restart.';
        return;
      }
      previousCaseValue.textContent = selected.case_name || 'TraceQuarry Case';
      previousCaseSubtitle.textContent = `${completedCaseLabel(selected)} · ${selected.is_case ? 'Case workspace' : 'Host analysis'}`;
      previousCaseMeta.textContent = caseResultLabel(selected);
    }

    previousCase.addEventListener('change', syncPreviousCase);
    previousCaseTrigger.addEventListener('click', () => {
      if (previousCaseMenu.hidden) openPreviousCaseMenu();
      else closePreviousCaseMenu();
    });
    previousCaseTrigger.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        openPreviousCaseMenu(event.key === 'ArrowDown' ? 'first' : 'last');
      }
    });
    previousCaseMenu.addEventListener('click', event => {
      const option = event.target.closest('[data-case-id]');
      if (!option) return;
      selectPreviousCase(option.dataset.caseId);
      closePreviousCaseMenu({ focusTrigger: true });
    });
    previousCaseMenu.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        focusAdjacentCaseOption(event.key === 'ArrowDown' ? 1 : -1);
      } else if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault();
        const options = caseOptionElements();
        options[event.key === 'Home' ? 0 : options.length - 1]?.focus();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        closePreviousCaseMenu({ focusTrigger: true });
      } else if (event.key === 'Tab') {
        closePreviousCaseMenu();
      }
    });
    document.addEventListener('pointerdown', event => {
      if (!previousCasePicker.contains(event.target)) closePreviousCaseMenu();
    });
    openPreviousCase.addEventListener('click', async () => {
      if (!previousCase.value) return;
      setStatus('running', 'Opening completed case...');
      const response = await fetch(`/api/job/${previousCase.value}`, { cache: 'no-store' });
      const job = await response.json();
      if (!response.ok) {
        setStatus('failed', job.error || 'Unable to open the selected case.');
        return;
      }
      summaryShownForJob = '';
      renderJob(job);
    });

    const acceptedEvidenceSuffixes = [
      '.tar.gz', '.tar', '.tgz', '.zip', '.gz', '.gzip',
      '.log', '.txt', '.db', '.sqlite', '.sqlite3'
    ];

    function evidenceFileKey(file) {
      return `${file.name}:${file.size}:${file.lastModified}`;
    }

    function isAcceptedEvidenceFile(file) {
      const name = String(file.name || '').toLowerCase();
      if (!name || name === '.ds_store') return false;
      if (!name.includes('.')) return true;
      if (
        /(?:^|\.)(?:auth|secure|messages|syslog|audit|kern|daemon)(?:\.log)?(?:\.\d+)?(?:\.(?:gz|gzip))?(?:\.\d+)?$/.test(name)
      ) return true;
      if (/\.(?:log|txt)(?:\.\d+)?(?:\.(?:gz|gzip))?(?:\.\d+)?$/.test(name)) return true;
      return acceptedEvidenceSuffixes.some(suffix => name.endsWith(suffix));
    }

    function selectUploadFiles(files, { append, source }) {
      const accepted = files.filter(isAcceptedEvidenceFile);
      const rejected = files.length - accepted.length;
      const base = append ? selectedUploadFiles : [];
      const selected = [];
      const seen = new Set();
      let duplicates = 0;
      for (const file of [...base, ...accepted]) {
        const key = evidenceFileKey(file);
        if (seen.has(key)) {
          duplicates += 1;
          continue;
        }
        seen.add(key);
        selected.push(file);
      }
      selectedUploadFiles = selected;
      syncNativeUploadInput(selected);
      resetUploadQueue();
      renderUploadSelection({ source, added: Math.max(0, selected.length - base.length), duplicates, rejected });
    }

    function syncNativeUploadInput(files) {
      try {
        const transfer = new DataTransfer();
        for (const file of files) transfer.items.add(file);
        uploadInput.files = transfer.files;
      } catch (_error) {
        // selectedUploadFiles remains the source of truth on older browsers.
      }
    }

    function renderUploadSelection({ source = '', added = 0, duplicates = 0, rejected = 0 } = {}) {
      const totalBytes = selectedUploadFiles.reduce((sum, file) => sum + file.size, 0);
      uploadSelection.className = `upload-selection${selectedUploadFiles.length ? ' has-files' : ''}${rejected ? ' has-warning' : ''}`;
      clearUpload.hidden = !selectedUploadFiles.length;
      if (!selectedUploadFiles.length) {
        uploadSelection.firstElementChild.textContent = rejected
          ? `${rejected.toLocaleString()} unsupported file(s) rejected`
          : 'No evidence selected';
        return;
      }
      const detail = [];
      if (source === 'drop' && added) detail.push(`${added.toLocaleString()} added`);
      if (duplicates) detail.push(`${duplicates.toLocaleString()} duplicate(s) skipped`);
      if (rejected) detail.push(`${rejected.toLocaleString()} unsupported file(s) rejected`);
      const suffix = detail.length ? ` · ${detail.join(' · ')}` : '';
      uploadSelection.firstElementChild.textContent =
        `${selectedUploadFiles.length.toLocaleString()} file(s) · ${formatBytes(totalBytes)} selected${suffix}`;
    }

    function selectedUploadFingerprint() {
      return selectedUploadFiles
        .map(file => `${file.name}:${file.size}:${file.lastModified}`)
        .join('|');
    }

    function resetUploadQueue() {
      stagedUpload = null;
      stagedFingerprint = '';
      queueStagingPath = '';
      queueCollections = selectedUploadFiles.map((file, index) => ({
        index: index + 1,
        name: file.name,
        size: file.size,
        status: 'pending',
        stage: 'pending',
        progress: 0
      }));
      renderCollectionQueue();
    }

    async function ensureUploadsStaged() {
      const files = selectedUploadFiles;
      const fingerprint = selectedUploadFingerprint();
      let session = null;
      if (stagedUpload && stagedFingerprint === fingerprint) {
        const existingResponse = await fetch(`/api/upload/${stagedUpload.upload_id}`, { cache: 'no-store' });
        if (existingResponse.ok) session = await existingResponse.json();
        if (session?.status === 'ready') {
          stagedUpload = session;
          queueStagingPath = session.staging_path || queueStagingPath;
          queueCollections = session.files.map(item => ({ ...item, index: Number(item.index) + 1, progress: 100 }));
          renderCollectionQueue();
          return session;
        }
      }
      setStatus('running', `Preparing ${files.length.toLocaleString()} evidence file(s) for upload...`);
      if (!session) {
        const response = await fetch('/api/upload/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-TraceQuarry-CSRF': csrfToken },
          body: JSON.stringify({ files: files.map(file => ({ name: file.name, size: file.size })) })
        });
        session = await response.json();
        if (!response.ok) throw new Error(session.error || 'Unable to create upload session');
      }
      stagedUpload = session;
      stagedFingerprint = fingerprint;
      queueStagingPath = session.staging_path || '';
      queueCollections = session.files.map(item => ({
        ...item,
        index: Number(item.index) + 1,
        progress: item.status === 'staged' ? 100 : 0
      }));
      renderCollectionQueue();
      const pendingIndexes = session.files
        .filter(item => item.status !== 'staged')
        .map(item => Number(item.index));
      let nextIndex = 0;
      const workerCount = Math.min(4, pendingIndexes.length);
      async function worker() {
        while (nextIndex < pendingIndexes.length) {
          const index = pendingIndexes[nextIndex++];
          await uploadEvidenceFile(session.upload_id, index, files[index]);
        }
      }
      await Promise.all(Array.from({ length: workerCount }, worker));
      const verify = await fetch(`/api/upload/${session.upload_id}`, { cache: 'no-store' });
      const verified = await verify.json();
      if (!verify.ok || verified.status !== 'ready') {
        throw new Error(verified.error || 'Evidence staging did not complete.');
      }
      stagedUpload = verified;
      queueStagingPath = verified.staging_path || queueStagingPath;
      queueCollections = verified.files.map(item => ({
        ...item,
        index: Number(item.index) + 1,
        progress: item.status === 'staged' ? 100 : 0
      }));
      renderCollectionQueue();
      updateProgress({ status: 'running', stage: 'staged', progress: 25 });
      setStatus('complete', `${files.length.toLocaleString()} evidence file(s) staged and verified.`);
      return verified;
    }

    function uploadEvidenceFile(uploadId, index, file) {
      return new Promise((resolve, reject) => {
        const row = queueCollections[index];
        row.status = 'uploading';
        row.stage = 'uploading';
        scheduleQueueRender();
        const request = new XMLHttpRequest();
        request.open('POST', `/api/upload/${uploadId}/${index}`);
        request.setRequestHeader('Content-Type', 'application/octet-stream');
        request.setRequestHeader('X-TraceQuarry-CSRF', csrfToken);
        request.upload.onprogress = (event) => {
          if (!event.lengthComputable) return;
          row.uploaded_bytes = event.loaded;
          row.progress = Math.round((event.loaded / Math.max(1, event.total)) * 100);
          const totalBytes = queueCollections.reduce((sum, item) => sum + Number(item.size || 0), 0);
          const uploadedBytes = queueCollections.reduce((sum, item) => {
            const size = Number(item.size || 0);
            return sum + Math.min(size, Number(item.uploaded_bytes || (item.status === 'staged' ? size : 0)));
          }, 0);
          updateProgress({ status: 'running', stage: 'uploading', progress: totalBytes ? Math.round(uploadedBytes / totalBytes * 25) : 0 });
          setStatus('running', `Uploading evidence · ${formatBytes(uploadedBytes)} of ${formatBytes(totalBytes)}`);
          scheduleQueueRender();
        };
        request.onload = () => {
          let payload = {};
          try { payload = JSON.parse(request.responseText || '{}'); } catch (_error) {}
          if (request.status < 200 || request.status >= 300) {
            row.status = 'failed';
            row.stage = 'failed';
            row.error = payload.error || `Upload failed with HTTP ${request.status}`;
            renderCollectionQueue();
            reject(new Error(row.error));
            return;
          }
          row.status = 'staged';
          row.stage = 'staged';
          row.uploaded_bytes = file.size;
          row.progress = 100;
          renderCollectionQueue();
          resolve(payload);
        };
        request.onerror = () => {
          row.status = 'failed';
          row.stage = 'failed';
          row.error = 'The browser lost its connection while uploading this file.';
          renderCollectionQueue();
          reject(new Error(row.error));
        };
        request.send(file);
      });
    }

    function scheduleQueueRender() {
      if (queueRenderPending) return;
      queueRenderPending = true;
      requestAnimationFrame(() => {
        queueRenderPending = false;
        renderCollectionQueue();
      });
    }

    function renderCollectionQueue(collections = queueCollections, stagingPath = queueStagingPath) {
      queueCollections = Array.isArray(collections) ? collections : [];
      queueStagingPath = stagingPath || queueStagingPath;
      collectionQueue.hidden = !queueCollections.length;
      if (!queueCollections.length) return;
      const knownSizes = queueCollections.filter(item => item.size != null);
      const selectedBytes = knownSizes.reduce((sum, item) => sum + Number(item.size || 0), 0);
      queueTitle.textContent = `${queueCollections.length.toLocaleString()} collection(s)${knownSizes.length ? ` · ${formatBytes(selectedBytes)}` : ''}`;
      queuePath.textContent = queueStagingPath
        ? `Staged at ${queueStagingPath} beneath the configured --work-dir`
        : getSourceMode() === 'upload'
          ? 'Selected files will be staged beneath the configured --work-dir.'
          : 'Server-side evidence remains in its configured input path.';
      const categories = [
        ['pending', 'Pending'], ['uploading', 'Uploading'], ['staged', 'Staged'],
        ['parsing', 'Parsing'], ['complete', 'Complete'], ['failed', 'Failed']
      ];
      const countFor = key => queueCollections.filter(item => queueStatusKey(item.status) === key).length;
      queueStatuses.innerHTML = categories.map(([key, label]) => `
        <div class="queue-status"><strong>${countFor(key).toLocaleString()}</strong><span>${label}</span></div>
      `).join('');
      const filter = queueFilter.value.trim().toLowerCase();
      const visible = queueCollections
        .filter(item => !filter || String(item.name || '').toLowerCase().includes(filter) || String(item.stage || '').toLowerCase().includes(filter))
        .sort((left, right) => Number(right.status === 'failed') - Number(left.status === 'failed') || Number(left.index || 0) - Number(right.index || 0));
      queueBody.innerHTML = visible.map(item => {
        const status = queueStatusKey(item.status);
        const progress = Math.max(0, Math.min(100, Number(item.progress || (status === 'complete' || status === 'staged' ? 100 : 0))));
        const stateLabel = item.error || collectionStageLabel(item.stage || item.status);
        return `<tr title="${escapeHtml(String(item.error || item.source || ''))}">
          <td class="queue-name">${escapeHtml(String(item.name || `Collection ${item.index || ''}`))}</td>
          <td class="queue-size">${item.size == null ? '—' : formatBytes(Number(item.size || 0))}</td>
          <td><span class="queue-state ${status}">${escapeHtml(stateLabel)}</span></td>
          <td><div class="queue-progress"><div class="queue-progress-track"><div class="queue-progress-fill" style="width:${progress}%"></div></div><span>${Math.round(progress)}%</span></div></td>
        </tr>`;
      }).join('');
    }

    function queueStatusKey(status) {
      if (status === 'queued' || status === 'pending') return 'pending';
      if (status === 'uploading') return 'uploading';
      if (status === 'staged' || status === 'ready') return 'staged';
      if (status === 'parsing' || status === 'running') return 'parsing';
      if (status === 'complete') return 'complete';
      if (status === 'failed') return 'failed';
      return 'pending';
    }

    function collectionStageLabel(stage) {
      const labels = {
        pending: 'Pending upload', uploading: 'Uploading', staged: 'Staged', queued: 'Queued',
        loading_collection: 'Opening evidence', sources_discovered: 'Sources indexed',
        hashing_evidence: 'Hashing evidence', parsing_sources: 'Parsing artifacts',
        enriching_collection: 'Enriching timeline', writing_collection: 'Writing outputs',
        collection_complete: 'Complete', complete: 'Complete', failed: 'Failed'
      };
      return labels[stage] || stageLabel(stage);
    }

    function renderInspectionJob(job) {
      if (job.id) activeJobId = job.id;
      updateProgress(job);
      renderCollectionQueue(job.collections || queueCollections, job.staging_path || queueStagingPath);
      runActions.hidden = true;
      metricsBox.hidden = true;
      if (job.status === 'complete' && job.result) {
        renderTimeRange(job.result);
        setStatus('complete', 'Evidence range parsed. Review or adjust the incident window.');
      } else if (job.status === 'failed') {
        setStatus('failed', job.error || 'Evidence inspection failed.');
      } else {
        setStatus('running', `Inspecting ${(job.collections || []).length.toLocaleString()} collection(s)...`);
      }
    }

    function renderJob(job) {
      if (job.id) activeJobId = job.id;
      setStatus(job.status || 'failed', job.status ? `Job ${job.id}: ${job.status}` : 'Unknown job');
      updateProgress(job);
      renderCollectionQueue(job.collections || queueCollections, job.staging_path || queueStagingPath);
      consoleBox.hidden = false;
      detailsBox.textContent = JSON.stringify(job, null, 2);
      if (job.result) {
        metricsBox.hidden = false;
        const metricItems = [
          metric('Events', job.result.events),
          metric('Mini Events', job.result.mini_events),
          metric('Findings', job.result.findings),
          metric('IoC Hits', job.result.ioc_hits)
        ];
        if (job.result.collections) metricItems.unshift(metric('Collections', job.result.collections));
        if (job.result.correlations) metricItems.push(metric('Correlations', job.result.correlations));
        metricsBox.innerHTML = metricItems.join('');
      }
      filesBox.innerHTML = '';
      const summaryFile = (job.outputs || []).find(file => file.name === 'case_summary.md') ||
        (job.outputs || []).find(file => file.name === 'summary.md');
      activeSummaryUrl = summaryFile ? summaryFile.url : '';
      const reviewCsvUrl = job.id ? timelineCsvUrl('mini') : '';
      runActions.hidden = job.status !== 'complete';
      if (activeSummaryUrl) {
        downloadSummary.href = activeSummaryUrl;
        summaryOpen.href = activeSummaryUrl;
      }
      if (reviewCsvUrl) {
        exportTimeline.href = reviewCsvUrl;
        summaryExport.href = reviewCsvUrl;
        briefingExport.href = `${reviewCsvUrl}&summary=selected`;
      }
      if (job.id) {
        const workbookUrl = investigationWorkbookUrl('full');
        exportWorkbook.href = workbookUrl;
        summaryWorkbook.href = workbookUrl;
        briefingWorkbook.href = workbookUrl;
      }
      for (const file of job.outputs || []) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = file.url;
        a.textContent = file.name;
        a.target = '_blank';
        const size = document.createElement('span');
        size.className = 'hint';
        size.textContent = formatBytes(file.size);
        li.appendChild(a);
        li.appendChild(size);
        filesBox.appendChild(li);
      }
      if (job.status === 'complete' && activeSummaryUrl && summaryShownForJob !== job.id) {
        summaryShownForJob = job.id;
        openSummaryPreview(activeSummaryUrl);
      }
      if (job.error) setStatus('failed', job.error);
    }

    previewSummary.addEventListener('click', () => {
      if (activeSummaryUrl) openSummaryPreview(activeSummaryUrl);
    });
    reviewBriefing.addEventListener('click', openIncidentBriefing);
    exploreTimeline.addEventListener('click', openTimelineExplorer);
    timelineClose.addEventListener('click', closeTimelineExplorer);
    timelineModal.addEventListener('click', (event) => {
      if (event.target === timelineModal) closeTimelineExplorer();
    });
    timelineSearch.addEventListener('input', () => {
      clearTimeout(timelineSearchTimer);
      timelineSearchTimer = setTimeout(() => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); }, 280);
    });
    timelineSeverity.addEventListener('change', () => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); });
    timelineSource.addEventListener('change', () => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); });
    timelinePhase.addEventListener('change', () => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); });
    timelineSummary.addEventListener('change', () => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); });
    timelineScope.addEventListener('change', () => { timelineState.offset = 0; updateTimelineExport(); loadTimelinePage(); });
    timelinePrev.addEventListener('click', () => {
      timelineState.offset = Math.max(0, timelineState.offset - timelineState.limit);
      loadTimelinePage();
    });
    timelineNext.addEventListener('click', () => {
      if (timelineState.offset + timelineState.limit < timelineState.total) {
        timelineState.offset += timelineState.limit;
        loadTimelinePage();
      }
    });
    summaryClose.addEventListener('click', closeSummaryPreview);
    summaryCloseFooter.addEventListener('click', closeSummaryPreview);
    summaryModal.addEventListener('click', (event) => {
      if (event.target === summaryModal) closeSummaryPreview();
    });
    briefingClose.addEventListener('click', closeIncidentBriefing);
    briefingCloseFooter.addEventListener('click', closeIncidentBriefing);
    briefingModal.addEventListener('click', (event) => {
      if (event.target === briefingModal) closeIncidentBriefing();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !summaryModal.hidden) closeSummaryPreview();
      if (event.key === 'Escape' && !briefingModal.hidden) closeIncidentBriefing();
      if (event.key === 'Escape' && !timelineModal.hidden) closeTimelineExplorer();
    });

    function openTimelineExplorer() {
      if (!activeJobId) return;
      timelineModal.hidden = false;
      timelineState = { offset: 0, limit: 80, total: 0, items: [], selectedEventId: '' };
      timelineSearch.value = '';
      timelineSeverity.value = '';
      timelineSource.value = '';
      timelinePhase.value = '';
      timelineSummary.value = '';
      timelineScope.value = 'mini';
      updateTimelineExport();
      eventDetail.innerHTML = '<div class="event-empty">Select an event to inspect its normalized fields and original raw record.</div>';
      loadTimelinePage();
      timelineSearch.focus();
    }

    function closeTimelineExplorer() {
      timelineModal.hidden = true;
      clearTimeout(timelineSearchTimer);
      if (!runActions.hidden) exploreTimeline.focus();
    }

    async function loadTimelinePage() {
      if (!activeJobId) return;
      timelineList.innerHTML = '<p class="summary-empty">Loading timeline evidence...</p>';
      const params = new URLSearchParams({
        scope: timelineScope.value,
        offset: String(timelineState.offset),
        limit: String(timelineState.limit)
      });
      if (timelineSearch.value.trim()) params.set('q', timelineSearch.value.trim());
      if (timelineSeverity.value) params.set('severity', timelineSeverity.value);
      if (timelineSource.value) params.set('source_type', timelineSource.value);
      if (timelinePhase.value) params.set('attack_phase', timelinePhase.value);
      if (timelineSummary.value) params.set('summary', timelineSummary.value);
      try {
        const response = await fetch(`/api/job/${activeJobId}/timeline?${params.toString()}`);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to load timeline');
        timelineState.total = Number(data.total || 0);
        timelineState.items = data.items || [];
        timelineState.limit = Number(data.limit || 80);
        timelineState.offset = Number(data.offset || 0);
        timelineScope.value = data.scope || timelineScope.value;
        updateTimelineExport();
        renderTimelineFacets(data.facets || {});
        renderTimelineEvents();
        const first = timelineState.items.find(item => item.event_id === timelineState.selectedEventId) || timelineState.items[0];
        if (first) showEventDetail(first.event_id);
        else eventDetail.innerHTML = '<div class="event-empty">No events match the selected filters.</div>';
      } catch (error) {
        timelineList.innerHTML = `<p class="summary-empty">${escapeHtml(String(error.message || error))}</p>`;
      }
    }

    function timelineCsvUrl(scope = timelineScope.value, includeFilters = false) {
      if (!activeJobId) return '#';
      const params = new URLSearchParams({ scope });
      if (includeFilters && timelineSearch.value.trim()) params.set('q', timelineSearch.value.trim());
      if (includeFilters && timelineSeverity.value) params.set('severity', timelineSeverity.value);
      if (includeFilters && timelineSource.value) params.set('source_type', timelineSource.value);
      if (includeFilters && timelinePhase.value) params.set('attack_phase', timelinePhase.value);
      if (includeFilters && timelineSummary.value) params.set('summary', timelineSummary.value);
      return `/api/job/${activeJobId}/timeline.csv?${params.toString()}`;
    }

    function investigationWorkbookUrl(scope = timelineScope.value, includeFilters = false) {
      if (!activeJobId) return '#';
      const params = new URLSearchParams({ scope });
      if (includeFilters && timelineSearch.value.trim()) params.set('q', timelineSearch.value.trim());
      if (includeFilters && timelineSeverity.value) params.set('severity', timelineSeverity.value);
      if (includeFilters && timelineSource.value) params.set('source_type', timelineSource.value);
      if (includeFilters && timelinePhase.value) params.set('attack_phase', timelinePhase.value);
      if (includeFilters && timelineSummary.value) params.set('summary', timelineSummary.value);
      return `/api/job/${activeJobId}/investigation.xlsx?${params.toString()}`;
    }

    function updateTimelineExport() {
      timelineExport.href = timelineCsvUrl(timelineScope.value, true);
      timelineWorkbook.href = investigationWorkbookUrl(timelineScope.value, true);
    }

    function renderTimelineFacets(facets) {
      const selectedSeverity = timelineSeverity.value;
      const selectedSource = timelineSource.value;
      const selectedPhase = timelinePhase.value;
      timelineSeverity.innerHTML = '<option value="">All severities</option>' + Object.entries(facets.severity || {})
        .map(([value, count]) => `<option value="${escapeHtml(value)}">${escapeHtml(value)} (${Number(count).toLocaleString()})</option>`).join('');
      timelineSource.innerHTML = '<option value="">All source types</option>' + Object.entries(facets.source_type || {})
        .map(([value, count]) => `<option value="${escapeHtml(value)}">${escapeHtml(value)} (${Number(count).toLocaleString()})</option>`).join('');
      timelinePhase.innerHTML = '<option value="">All ATT&amp;CK phases</option>' + Object.entries(facets.attack_phase || {})
        .map(([value, count]) => `<option value="${escapeHtml(value)}">${escapeHtml(attackPhaseLabel(value))} (${Number(count).toLocaleString()})</option>`).join('');
      timelineSeverity.value = selectedSeverity;
      timelineSource.value = selectedSource;
      timelinePhase.value = selectedPhase;
    }

    function renderTimelineEvents() {
      timelineCount.textContent = `${timelineState.total.toLocaleString()} matching event(s)`;
      const start = timelineState.total ? timelineState.offset + 1 : 0;
      const end = Math.min(timelineState.total, timelineState.offset + timelineState.items.length);
      timelinePage.textContent = `${start.toLocaleString()}-${end.toLocaleString()} of ${timelineState.total.toLocaleString()}`;
      timelinePrev.disabled = timelineState.offset <= 0;
      timelineNext.disabled = end >= timelineState.total;
      if (!timelineState.items.length) {
        timelineList.innerHTML = '<p class="summary-empty">No events match the selected filters.</p>';
        return;
      }
      timelineList.innerHTML = timelineState.items.map((event) => {
        const annotation = event.analyst_annotation || {};
        const selectedForSummary = annotation.include_in_summary === true;
        const annotated = selectedForSummary || (annotation.tags || []).length || annotation.note || (annotation.disposition && annotation.disposition !== 'unreviewed');
        const source = [event.collection_host || event.host, event.source_type].filter(Boolean).join(' · ');
        const phases = event.attack_phases || [];
        return `
          <button class="timeline-event${event.event_id === timelineState.selectedEventId ? ' active' : ''}" type="button" data-event-id="${escapeHtml(String(event.event_id || ''))}">
            <span class="timeline-time">${escapeHtml(formatUtcTimestamps(String(event.timestamp || 'Untimed')))}</span>
            <span class="severity-pill ${escapeHtml(String(event.severity || 'informational'))}">${escapeHtml(String(event.severity || 'info'))}</span>
            <span class="timeline-event-copy">
              <strong>${annotated ? '<span class="annotation-dot"></span>' : ''}${escapeHtml(String(event.summary || event.event_action || 'Timeline event'))}${selectedForSummary ? '<span class="summary-marker">Summary</span>' : ''}</strong>
              <small>${escapeHtml(source || event.source_path || 'unknown source')}</small>
              ${phases.length ? `<span class="timeline-phase-row">${phases.map(phase => `<span class="timeline-phase">${escapeHtml(attackPhaseLabel(phase))}</span>`).join('')}</span>` : ''}
            </span>
          </button>`;
      }).join('');
      timelineList.querySelectorAll('[data-event-id]').forEach((button) => {
        button.addEventListener('click', () => showEventDetail(button.dataset.eventId));
      });
    }

    function showEventDetail(eventId) {
      const event = timelineState.items.find(item => item.event_id === eventId);
      if (!event) return;
      timelineState.selectedEventId = eventId;
      renderTimelineEvents();
      const annotation = event.analyst_annotation || {};
      const tags = [
        ...(event.attack_phases || []).map(phase => `phase.${phase}`),
        ...(event.tags || []), ...(event.detection_names || []), ...(event.mitre || [])
      ];
      const fields = [
        ['Timestamp', formatUtcTimestamps(String(event.timestamp || 'Untimed'))],
        ['Host', event.collection_host || event.host || '-'],
        ['Collection', event.collection_name || event.collection_id || 'single collection'],
        ['Source', `${event.source_type || '-'} · ${event.source_path || '-' }`],
        ['Source SHA-256', event.source_sha256 || '-'],
        ['Action', event.event_action || '-'],
        ['User', event.user || '-'],
        ['Source IP', event.src_ip || '-'],
        ['Destination', [event.dst_ip, event.port].filter(Boolean).join(':') || '-'],
        ['Process', [event.process, event.pid].filter(Boolean).join(' · ') || '-'],
        ['ATT&CK phase', (event.attack_phases || []).map(attackPhaseLabel).join(', ') || '-'],
        ['Phase candidates', (event.attack_phase_candidates || []).map(attackPhaseLabel).join(', ') || '-'],
        ['Confidence', event.confidence || '-']
      ];
      eventDetail.innerHTML = `
        <div class="event-detail-head">
          <h3>${escapeHtml(String(event.summary || event.event_action || 'Timeline event'))}</h3>
          <p>${escapeHtml(String(event.event_id || ''))}</p>
        </div>
        <div class="event-field-grid">${fields.map(([label, value]) => `
          <div class="event-field"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`).join('')}</div>
        <section class="event-section"><h4>Detection and ATT&amp;CK tags</h4><div class="tag-row">${
          tags.length ? [...new Set(tags)].map(tag => `<span class="event-tag">${escapeHtml(String(tag))}</span>`).join('') : '<span class="hint">No parser tags.</span>'
        }</div></section>
        <section class="event-section"><h4>Raw evidence</h4><div class="raw-record">${escapeHtml(String(event.raw || event.command || event.file_path || 'No raw record retained.'))}</div></section>
        ${event.related_event_ids?.length ? `<section class="event-section"><h4>Related events</h4><div class="tag-row">${event.related_event_ids.map(id => `<span class="event-tag">${escapeHtml(String(id))}</span>`).join('')}</div></section>` : ''}
        <section class="event-section"><h4>Analyst annotation</h4>
          <div class="annotation-form">
            <label class="summary-toggle">
              <input id="annotation-summary" type="checkbox"${annotation.include_in_summary === true ? ' checked' : ''}>
              <span><strong>Include in reconstructed summary</strong><small>Promote pivotal, validated evidence only. The full timeline and raw record remain unchanged.</small></span>
            </label>
            <label>Disposition<select id="annotation-disposition">
              ${annotationDispositionOptions(annotation.disposition || 'unreviewed')}
            </select></label>
            <label>Investigation tags</label>
            <div class="tag-presets">${guidedTagButtons(annotation.tags || [])}</div>
            <label>Additional tags<input id="annotation-tags" value="${escapeHtml((annotation.tags || []).join(', '))}" placeholder="confirmed, escalation, false_positive"></label>
            <label>Note<textarea id="annotation-note" placeholder="Record validation, context, or next action...">${escapeHtml(String(annotation.note || ''))}</textarea></label>
            <div id="annotation-status" class="annotation-status"></div>
            <button id="annotation-save" type="button">Save annotation</button>
          </div>
        </section>`;
      document.getElementById('annotation-save').addEventListener('click', () => saveEventAnnotation(event));
      document.querySelectorAll('.tag-preset').forEach((preset) => {
        preset.addEventListener('click', () => toggleGuidedTag(preset));
      });
    }

    function guidedTagButtons(selectedTags) {
      const selected = new Set(selectedTags || []);
      return guidedAnalystTags.map(([value, label]) => `
        <button class="tag-preset${selected.has(value) ? ' selected' : ''}" type="button" data-tag="${value}" aria-pressed="${selected.has(value)}">${label}</button>`
      ).join('');
    }

    function toggleGuidedTag(button) {
      const input = document.getElementById('annotation-tags');
      const tags = new Set(input.value.split(',').map(value => value.trim()).filter(Boolean));
      const tag = button.dataset.tag;
      if (tags.has(tag)) tags.delete(tag);
      else tags.add(tag);
      input.value = [...tags].join(', ');
      button.classList.toggle('selected', tags.has(tag));
      button.setAttribute('aria-pressed', String(tags.has(tag)));
    }

    function annotationDispositionOptions(selected) {
      const options = [
        ['unreviewed', 'Unreviewed'], ['suspicious', 'Suspicious'], ['malicious', 'Malicious'],
        ['benign', 'Benign'], ['needs_context', 'Needs context']
      ];
      return options.map(([value, label]) => `<option value="${value}"${value === selected ? ' selected' : ''}>${label}</option>`).join('');
    }

    async function saveEventAnnotation(event) {
      const status = document.getElementById('annotation-status');
      const payload = {
        event_id: event.event_id,
        include_in_summary: document.getElementById('annotation-summary').checked,
        disposition: document.getElementById('annotation-disposition').value,
        tags: document.getElementById('annotation-tags').value.split(',').map(value => value.trim()).filter(Boolean),
        note: document.getElementById('annotation-note').value
      };
      status.textContent = 'Saving...';
      try {
        const response = await fetch(`/api/job/${activeJobId}/annotations`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-TraceQuarry-CSRF': csrfToken },
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to save annotation');
        event.analyst_annotation = data.annotation || {};
        status.textContent = 'Annotation saved separately from parser evidence.';
        if (timelineSummary.value) loadTimelinePage();
        else renderTimelineEvents();
      } catch (error) {
        status.textContent = error.message || 'Unable to save annotation.';
      }
    }

    function updateProgress(job) {
      const status = job.status || 'queued';
      const stage = job.stage || status;
      let percent = Number(job.progress || 0);
      if (!percent) {
        if (status === 'queued') percent = 8;
        else if (status === 'running') percent = 44;
        else if (status === 'complete') percent = 100;
        else if (status === 'failed') percent = 100;
      }
      runProgress.hidden = false;
      progressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
      const startedAt = Number(job.started_at || 0);
      const endedAt = Number(job.completed_at || Date.now() / 1000);
      const elapsed = startedAt ? ` · ${formatDuration(Math.max(0, endedAt - startedAt))}` : '';
      progressPercent.textContent = `${Math.round(percent)}%${elapsed}`;
      const detail = status === 'running' ? (job.progress_detail || {}) : {};
      const sourceDetail = detail.source ? ` · ${detail.source}` : '';
      const countDetail = detail.total ? ` (${Number(detail.completed || 0).toLocaleString()}/${Number(detail.total).toLocaleString()})` : '';
      progressTitle.textContent = status === 'failed'
        ? 'Parser stopped with an error'
        : `${stageLabel(stage)}${countDetail}${sourceDetail}`;
      const phase = progressPhase(stage);
      const activeIndex = status === 'failed'
        ? progressStages.findIndex(([key]) => key === 'writing_outputs')
        : Math.max(0, progressStages.findIndex(([key]) => key === phase));
      progressSteps.innerHTML = progressStages.map(([key, label], index) => {
        const klass = status === 'complete' || index < activeIndex ? 'done' : index === activeIndex ? 'active' : '';
        return `<div class="progress-step ${klass}"><span class="step-dot"></span><span>${escapeHtml(label)}</span></div>`;
      }).join('');
    }

    function stageLabel(stage) {
      const labels = {
        uploading: 'Uploading evidence',
        staged: 'Evidence staged and verified',
        queued: 'Queued for analysis',
        parsing: 'Parsing UAC evidence',
        inspecting: 'Inspecting evidence time range',
        loading_collection: 'Opening evidence collection',
        sources_discovered: 'Indexing discovered evidence',
        hashing_evidence: 'Hashing evidence for provenance',
        parsing_sources: 'Parsing source artifacts',
        enriching_collection: 'Enriching collection timeline',
        writing_collection: 'Writing collection outputs',
        collection_complete: 'Collection complete',
        inspection_complete: 'Evidence range ready',
        case_complete: 'Finalizing case correlation',
        normalizing: 'Normalizing forensic timeline',
        writing_outputs: 'Writing review outputs',
        complete: 'Summary ready for review',
        failed: 'Parser stopped with an error'
      };
      return labels[stage] || 'Parser is running';
    }

    function progressPhase(stage) {
      if (stage === 'uploading') return 'uploading';
      if (stage === 'staged') return 'staged';
      if (stage === 'queued') return 'queued';
      if (['parsing', 'inspecting', 'loading_collection', 'sources_discovered', 'hashing_evidence', 'parsing_sources', 'enriching_collection', 'writing_collection', 'collection_complete'].includes(stage)) return 'parsing';
      if (stage === 'inspection_complete' || stage === 'case_complete') return 'writing_outputs';
      return stage;
    }

    async function openIncidentBriefing() {
      if (!activeJobId) return;
      briefingModal.hidden = false;
      briefingContent.innerHTML = '<p class="summary-empty">Building the analyst-selected briefing...</p>';
      try {
        const response = await fetch(`/api/job/${activeJobId}/briefing`, { cache: 'no-store' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to build incident briefing');
        briefingExport.href = `/api/job/${activeJobId}/timeline.csv?scope=${encodeURIComponent(data.scope || 'mini')}&summary=selected`;
        briefingWorkbook.href = `/api/job/${activeJobId}/investigation.xlsx?scope=${encodeURIComponent(data.scope || 'full')}`;
        briefingContent.innerHTML = renderIncidentBriefing(data);
      } catch (error) {
        briefingContent.innerHTML = `<p class="summary-empty">${escapeHtml(String(error.message || error))}</p>`;
      }
      briefingClose.focus();
    }

    function closeIncidentBriefing() {
      briefingModal.hidden = true;
      if (!runActions.hidden) reviewBriefing.focus();
    }

    function renderIncidentBriefing(data) {
      const metrics = data.metrics || {};
      const phases = data.phase_breakdown || [];
      const selectedEvents = data.selected_events || [];
      const executive = data.executive || {};
      const metricItems = [
        ['Selected events', metrics.selected_events || 0],
        ['Hosts in scope', metrics.hosts || 0],
        ['Phases observed', metrics.phases_observed || 0],
        ['Timeline events', metrics.timeline_events || 0]
      ];
      const phaseRail = phases.length
        ? phases.map(phase => `<span class="phase-chip${phase.selected_events ? ' selected' : ''}">${escapeHtml(phase.label)} <b>${Number(phase.selected_events || phase.confirmed_events || 0).toLocaleString()}</b></span>`).join('')
        : '<p class="summary-empty">No evidence-derived phases observed in this scope.</p>';
      const phaseRows = phases.length
        ? phases.map(phase => `<tr>
            <td>${escapeHtml(phase.label)} <span class="hint">${escapeHtml(phase.tactic_id)}</span></td>
            <td>${Number(phase.confirmed_events || 0).toLocaleString()}</td>
            <td>${Number(phase.candidate_events || 0).toLocaleString()}</td>
            <td>${Number(phase.selected_events || 0).toLocaleString()}</td>
            <td>${escapeHtml(formatUtcTimestamps(phase.first_observed || '—'))}</td>
          </tr>`).join('')
        : '<tr><td colspan="5">No phase-tagged evidence in scope.</td></tr>';
      const timeline = selectedEvents.length
        ? selectedEvents.map(renderBriefingEvent).join('')
        : '<p class="summary-empty">No analyst-selected events yet. Open the evidence timeline, validate a pivotal record, and enable Include in reconstructed summary.</p>';
      const truncated = data.selected_events_truncated
        ? `<p class="briefing-note">Preview limited to ${Number(data.selected_events_returned || 0).toLocaleString()} records. The selected CSV export retains the complete set.</p>`
        : '';
      const executiveTimeline = (executive.incident_timeline || []).slice(0, 5).map(event =>
        `<li><time>${escapeHtml(formatUtcTimestamps(event.timestamp || 'Untimed'))}</time><span>${escapeHtml(event.summary || 'Timeline event')}</span></li>`
      ).join('') || '<li><span>No analyst-selected milestones.</span></li>';
      const executiveMetrics = (executive.key_metrics || []).slice(0, 5).map(item =>
        `<li><span>${escapeHtml(item.label || '')}</span><strong>${Number(item.value || 0).toLocaleString()}</strong></li>`
      ).join('');
      const executiveActions = (executive.threat_actions || []).slice(0, 5).map(item =>
        `<li><span>${escapeHtml(item.summary || '')}</span></li>`
      ).join('') || '<li><span>No observed action promoted by the analyst.</span></li>';
      const compactList = values => (values || []).slice(0, 4).map(value => `<li>${escapeHtml(String(value || ''))}</li>`).join('');
      return `
        <div class="briefing-metrics">${metricItems.map(([label, value]) => `<div class="briefing-metric"><strong>${Number(value).toLocaleString()}</strong><span>${escapeHtml(label)}</span></div>`).join('')}</div>
        <section class="executive-preview">
          <div class="executive-preview-title"><strong>Cybersecurity incident executive briefing</strong><span>${escapeHtml(data.case_name || 'TraceQuarry case')}</span></div>
          <div class="executive-preview-grid">
            <article><h3>Incident timeline</h3><ul class="executive-timeline">${executiveTimeline}</ul></article>
            <article><h3>Key metrics</h3><ul class="executive-metric-list">${executiveMetrics}</ul></article>
            <article class="executive-actions"><h3>Observed actions</h3><ul>${executiveActions}</ul></article>
          </div>
          <div class="executive-preview-secondary">
            <article class="exfil"><h3>Data exfiltration</h3><ul>${compactList(executive.data_exfiltration)}</ul></article>
            <article class="impact"><h3>Impact / recovery</h3><ul>${compactList(executive.impact)}</ul></article>
            <article class="accounts"><h3>Key accounts</h3><ul>${compactList(executive.accounts)}</ul></article>
          </div>
          <div class="executive-preview-copy"><h3>Executive summary</h3><p>${escapeHtml(executive.summary || data.narrative || '')}</p></div>
          <p class="executive-legal">${escapeHtml(executive.legal_note || '')}</p>
        </section>
        <div class="briefing-lead">
          <div><h3>Reconstructed incident timeline</h3><p>${escapeHtml(data.narrative || '')}</p></div>
          <div class="briefing-scope">${escapeHtml(String(data.scope || 'mini').toUpperCase())} SCOPE<br>${escapeHtml(`ATT&CK v${data.attack?.attack_version || 'unknown'}`)}</div>
        </div>
        <section class="briefing-section">
          <div class="briefing-section-head"><h3>Attack path coverage</h3><span>Highlighted phases contain selected evidence</span></div>
          <div class="phase-rail">${phaseRail}</div>
        </section>
        <section class="briefing-section">
          <div class="briefing-section-head"><h3>ATT&amp;CK phase breakdown</h3><span>Confirmed and candidate evidence remain distinct</span></div>
          <table class="phase-table"><thead><tr><th>Phase</th><th>Confirmed</th><th>Candidate</th><th>Summary</th><th>First observed</th></tr></thead><tbody>${phaseRows}</tbody></table>
        </section>
        <section class="briefing-section">
          <div class="briefing-section-head"><h3>Defensible chronology</h3><span>${Number(metrics.selected_events || 0).toLocaleString()} analyst-selected event(s)</span></div>
          <div class="briefing-events">${timeline}</div>
        </section>
        ${truncated}
        <p class="briefing-note">${escapeHtml(data.evidence_note || '')}</p>`;
    }

    function renderBriefingEvent(event) {
      const phaseTags = (event.attack_phases || []).map(phase => `<span class="timeline-phase">${escapeHtml(attackPhaseLabel(phase))}</span>`).join('');
      const source = [event.source_type, event.source_path].filter(Boolean).join(' · ') || 'Unknown source';
      const hash = event.source_sha256 ? `SHA-256 ${event.source_sha256}` : 'Source hash unavailable';
      return `<article class="briefing-event">
        <div class="briefing-event-time">${escapeHtml(formatUtcTimestamps(event.timestamp || 'Untimed'))}<span>${escapeHtml(event.host || 'Unknown host')}</span></div>
        <div class="briefing-event-copy">
          <h4>${escapeHtml(event.summary || 'Timeline event')}</h4>
          ${phaseTags ? `<div class="timeline-phase-row">${phaseTags}</div>` : ''}
          ${event.analyst_note ? `<p>${escapeHtml(event.analyst_note)}</p>` : ''}
          <div class="briefing-event-meta">${escapeHtml(event.event_id || '')}<br>${escapeHtml(source)}<br>${escapeHtml(hash)}</div>
          <details><summary>Preview raw evidence</summary><pre>${escapeHtml(event.raw || 'No raw record retained.')}</pre></details>
        </div>
      </article>`;
    }

    async function openSummaryPreview(url) {
      summaryModal.hidden = false;
      summaryPreview.innerHTML = '<p class="summary-empty">Loading summary...</p>';
      summaryOpen.href = url;
      try {
        const response = await fetch(url, { cache: 'no-store' });
        if (!response.ok) throw new Error('Unable to load summary.md');
        const rawSummary = await response.text();
        summaryPreview.innerHTML = renderSummaryReport(rawSummary);
      } catch (error) {
        summaryPreview.innerHTML = `<pre class="summary-raw">${escapeHtml(error.message || 'Unable to load summary.md')}</pre>`;
      }
      summaryClose.focus();
    }

    function closeSummaryPreview() {
      summaryModal.hidden = true;
      if (previewSummary && !previewSummary.disabled && !runActions.hidden) previewSummary.focus();
    }

    function renderSummaryReport(raw) {
      const parsed = parseSummary(raw);
      const metrics = parsed.metrics;
      const highCount = Number(metrics['High severity findings'] || 0);
      const statItems = [
        ['Total events', metrics['Total parsed events'] || metrics['Total events'] || '0'],
        ['Findings', metrics['Findings'] || '0'],
        ['High severity', metrics['High severity findings'] || '0'],
        ['Storylines', metrics['Storylines'] || '0']
      ];
      const statsHtml = statItems.map(([label, value]) => `
        <div class="summary-stat">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(String(value))}</strong>
        </div>
      `).join('');
      const sectionsHtml = parsed.sections.length
        ? parsed.sections.map(renderSummarySection).join('')
        : `<section class="summary-section"><p class="summary-empty">No structured sections found in summary.md.</p></section>`;
      return `
        <div class="summary-hero">
          <div>
            <h3>${escapeHtml(parsed.title || 'TraceQuarry Summary')}</h3>
            <p>Review the parser findings, scope notes, storylines, and recommended next steps. Timestamps are displayed in analyst-readable UTC form.</p>
          </div>
          <span class="summary-badge">${highCount ? `${highCount} high severity` : 'No high severity'}</span>
        </div>
        <div class="summary-stat-grid">${statsHtml}</div>
        ${sectionsHtml}
      `;
    }

    function parseSummary(raw) {
      const lines = raw.split(/\r?\n/);
      const metrics = {};
      const sections = [];
      let title = 'TraceQuarry Summary';
      let current = null;
      for (const line of lines) {
        if (line.startsWith('# ')) {
          title = line.slice(2).trim();
          continue;
        }
        if (line.startsWith('## ')) {
          current = { title: line.slice(3).trim(), items: [] };
          sections.push(current);
          continue;
        }
        if (!current) {
          const match = line.match(/^([^:]+):\s*(.+)$/);
          if (match) metrics[match[1].trim()] = match[2].trim();
          continue;
        }
        if (!line.trim()) continue;
        current.items.push(line);
      }
      return { title, metrics, sections };
    }

    function renderSummarySection(section) {
      const title = section.title || 'Summary';
      const normalized = title.toLowerCase();
      const cardType = normalized.includes('high severity') ? 'high' :
        normalized.includes('recommended next') ? 'next' : '';
      const content = section.items.length
        ? section.items.map((item) => renderSummaryItem(item, cardType)).join('')
        : '<p class="summary-empty">No entries identified.</p>';
      const wrapperClass = section.items.some(item => item.trim().startsWith('-')) ? 'summary-list' : '';
      return `
        <section class="summary-section">
          <h3>${escapeHtml(title)}</h3>
          <div class="${wrapperClass}">${content}</div>
        </section>
      `;
    }

    function renderSummaryItem(item, cardType) {
      const trimmed = item.trim();
      if (trimmed.startsWith('-')) {
        const text = trimmed.replace(/^-\s*/, '');
        const titleMatch = text.match(/^\*\*([^*]+)\*\*:\s*(.*)$/);
        const title = titleMatch ? titleMatch[1] : '';
        const body = titleMatch ? titleMatch[2] : text;
        const klass = ['finding-card', cardType].filter(Boolean).join(' ');
        return `
          <article class="${klass}">
            <span class="finding-dot" aria-hidden="true"></span>
            <div>
              ${title ? `<strong class="finding-title">${escapeHtml(formatUtcTimestamps(title))}</strong>` : ''}
              <div class="finding-text">${formatSummaryInline(body)}</div>
            </div>
          </article>
        `;
      }
      return `<p class="summary-paragraph">${formatSummaryInline(trimmed)}</p>`;
    }

    function formatSummaryInline(value) {
      return escapeHtml(formatUtcTimestamps(value))
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    }

    function formatUtcTimestamps(value) {
      return String(value).replace(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z/g, '$1-$2-$3 $4:$5:$6 (UTC)');
    }

    function attackPhaseLabel(value) {
      return attackPhaseLabels[value] || String(value || '').replaceAll('_', ' ');
    }

    function renderTimeRange(data) {
      rangePanel.hidden = false;
      if (!data.earliest || !data.latest) {
        rangeSummary.textContent = `Parsed ${Number(data.events || 0).toLocaleString()} events, but no timestamped events were found.`;
        rangeEarliest.textContent = '-';
        rangeLatest.textContent = '-';
        renderCoverageReadiness(data.source_types || []);
        return;
      }
      if (data.earliest_local) incidentStart.value = data.earliest_local;
      if (data.latest_local) incidentEnd.value = data.latest_local;
      if (data.earliest_local) updateDateTimePicker('incident_start', data.earliest_local);
      if (data.latest_local) updateDateTimePicker('incident_end', data.latest_local);
      const basis = data.range_basis === 'log_time' ? `${Number(data.log_events || 0).toLocaleString()} log-time events` : `${Number(data.timed_events || 0).toLocaleString()} timestamped events`;
      const collectionText = data.collections && data.collections > 1 ? ` across ${Number(data.collections).toLocaleString()} collections` : '';
      const exclusionText = data.excluded_files ? ` ${Number(data.excluded_files).toLocaleString()} non-evidence metadata file(s) excluded and recorded.` : '';
      const evidenceText = data.evidence_files ? ` ${Number(data.evidence_files).toLocaleString()} evidence file(s) inventoried; ${Number(data.unsupported_sources || 0).toLocaleString()} unsupported source view(s) and ${Number(data.unmatched_files || 0).toLocaleString()} unmatched file(s).` : '';
      rangeSummary.textContent = `${basis} across ${Number(data.sources || 0).toLocaleString()} sources${collectionText}. Window filled in ${data.timezone || 'UTC'}.${evidenceText}${exclusionText}`;
      rangeEarliest.textContent = data.earliest_display || data.earliest;
      rangeLatest.textContent = data.latest_display || data.latest;
      renderCoverageReadiness(data.source_types || []);
    }

    function renderCoverageReadiness(sourceTypes) {
      const available = new Set(sourceTypes);
      const groups = [
        ['Authentication', ['auth_log', 'login_history']],
        ['Audit', ['auditd']],
        ['Command history', ['shell_history']],
        ['Network state', ['ss_output', 'netstat_output']],
        ['Processes', ['ps_output']],
        ['Accounts', ['passwd', 'shadow', 'group']],
        ['Persistence', ['cron_file', 'systemd_unit', 'authorized_keys', 'pam_config']],
        ['Filesystem', ['bodyfile']]
      ];
      const states = groups.map(([label, kinds]) => [label, kinds.some(kind => available.has(kind))]);
      const present = states.filter(([, ready]) => ready).length;
      coverageScore.textContent = `${present}/${states.length} evidence classes present`;
      coverageGroups.innerHTML = states.map(([label, ready]) =>
        `<span class="coverage-chip${ready ? '' : ' missing'}" title="${ready ? 'Evidence discovered' : 'Evidence not discovered'}">${escapeHtml(label)}</span>`
      ).join('');
    }

    function createDateTimePicker(id, placeholder) {
      const root = document.querySelector(`[data-picker="${id}"]`);
      const input = document.getElementById(id);
      const trigger = document.getElementById(`${id}_trigger`);
      const display = document.getElementById(`${id}_display`);
      const panel = document.getElementById(`${id}_panel`);
      const now = new Date();
      const selected = parsePickerValue(input.value) || new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), now.getMinutes(), 0);
      const picker = {
        id,
        root,
        input,
        trigger,
        display,
        panel,
        placeholder,
        viewYear: selected.getFullYear(),
        viewMonth: selected.getMonth(),
        selected
      };
      trigger.addEventListener('click', (event) => {
        event.stopPropagation();
        toggleDateTimePicker(id);
      });
      panel.addEventListener('click', (event) => event.stopPropagation());
      renderDateTimePicker(picker);
      syncDateTimeDisplay(picker);
      return picker;
    }

    document.addEventListener('click', () => closeDateTimePickers());
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeDateTimePickers();
    });

    function toggleDateTimePicker(id) {
      const picker = datePickers[id];
      const willOpen = !picker.root.classList.contains('open');
      closeDateTimePickers();
      picker.root.classList.toggle('open', willOpen);
      picker.trigger.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    }

    function closeDateTimePickers() {
      for (const picker of Object.values(datePickers)) {
        picker.root.classList.remove('open');
        picker.trigger.setAttribute('aria-expanded', 'false');
      }
    }

    function updateDateTimePicker(id, value) {
      const picker = datePickers[id];
      const parsed = parsePickerValue(value);
      if (!picker || !parsed) return;
      picker.selected = parsed;
      picker.viewYear = parsed.getFullYear();
      picker.viewMonth = parsed.getMonth();
      picker.input.value = toLocalInputValue(parsed);
      renderDateTimePicker(picker);
      syncDateTimeDisplay(picker);
    }

    function renderDateTimePicker(picker) {
      const monthName = new Intl.DateTimeFormat('en', { month: 'long', year: 'numeric' }).format(new Date(picker.viewYear, picker.viewMonth, 1));
      const selectedHour = String(picker.selected.getHours()).padStart(2, '0');
      const selectedMinute = String(picker.selected.getMinutes()).padStart(2, '0');
      const selectedSecond = String(picker.selected.getSeconds()).padStart(2, '0');
      picker.panel.innerHTML = `
        <div class="tq-dt-head">
          <div class="tq-dt-month">${escapeHtml(monthName)}</div>
          <button class="tq-dt-nav" type="button" data-dt-prev aria-label="Previous month">‹</button>
          <button class="tq-dt-nav" type="button" data-dt-next aria-label="Next month">›</button>
        </div>
        <div class="tq-dt-weekdays" aria-hidden="true">
          <span>Su</span><span>Mo</span><span>Tu</span><span>We</span><span>Th</span><span>Fr</span><span>Sa</span>
        </div>
        <div class="tq-dt-days">${renderCalendarDays(picker)}</div>
        <div class="tq-dt-time">
          ${renderTimeSelect('Hour', 'hour', 0, 23, selectedHour)}
          ${renderTimeSelect('Min', 'minute', 0, 59, selectedMinute)}
          ${renderTimeSelect('Sec', 'second', 0, 59, selectedSecond)}
        </div>
        <div class="tq-dt-actions">
          <button class="tq-dt-action clear" type="button" data-dt-clear>Clear</button>
          <button class="tq-dt-action now" type="button" data-dt-now>Use now</button>
        </div>
      `;
      picker.panel.querySelector('[data-dt-prev]').addEventListener('click', () => shiftPickerMonth(picker, -1));
      picker.panel.querySelector('[data-dt-next]').addEventListener('click', () => shiftPickerMonth(picker, 1));
      picker.panel.querySelector('[data-dt-clear]').addEventListener('click', () => clearDateTimePicker(picker));
      picker.panel.querySelector('[data-dt-now]').addEventListener('click', () => setPickerDate(picker, new Date()));
      picker.panel.querySelectorAll('[data-dt-day]').forEach((button) => {
        button.addEventListener('click', () => {
          const date = new Date(Number(button.dataset.year), Number(button.dataset.month), Number(button.dataset.day), picker.selected.getHours(), picker.selected.getMinutes(), picker.selected.getSeconds());
          setPickerDate(picker, date);
        });
      });
      picker.panel.querySelectorAll('[data-dt-time]').forEach((select) => {
        select.addEventListener('change', () => {
          const next = new Date(picker.selected);
          if (select.dataset.dtTime === 'hour') next.setHours(Number(select.value));
          if (select.dataset.dtTime === 'minute') next.setMinutes(Number(select.value));
          if (select.dataset.dtTime === 'second') next.setSeconds(Number(select.value));
          setPickerDate(picker, next, false);
        });
      });
    }

    function renderCalendarDays(picker) {
      const first = new Date(picker.viewYear, picker.viewMonth, 1);
      const start = new Date(picker.viewYear, picker.viewMonth, 1 - first.getDay());
      const todayKey = dateKey(new Date());
      const selectedKey = dateKey(picker.selected);
      let html = '';
      for (let i = 0; i < 42; i++) {
        const date = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
        const key = dateKey(date);
        const classes = [
          'tq-dt-day',
          date.getMonth() !== picker.viewMonth ? 'muted' : '',
          key === todayKey ? 'today' : '',
          key === selectedKey ? 'selected' : ''
        ].filter(Boolean).join(' ');
        html += `<button class="${classes}" type="button" data-dt-day data-year="${date.getFullYear()}" data-month="${date.getMonth()}" data-day="${date.getDate()}" aria-label="${escapeHtml(formatDateLabel(date))}">${date.getDate()}</button>`;
      }
      return html;
    }

    function renderTimeSelect(label, key, min, max, selected) {
      let options = '';
      for (let value = min; value <= max; value++) {
        const text = String(value).padStart(2, '0');
        options += `<option value="${text}"${text === selected ? ' selected' : ''}>${text}</option>`;
      }
      return `<label>${label}<select data-dt-time="${key}">${options}</select></label>`;
    }

    function shiftPickerMonth(picker, delta) {
      const next = new Date(picker.viewYear, picker.viewMonth + delta, 1);
      picker.viewYear = next.getFullYear();
      picker.viewMonth = next.getMonth();
      renderDateTimePicker(picker);
    }

    function setPickerDate(picker, date, rerender = true) {
      picker.selected = new Date(date.getFullYear(), date.getMonth(), date.getDate(), date.getHours(), date.getMinutes(), date.getSeconds());
      picker.viewYear = picker.selected.getFullYear();
      picker.viewMonth = picker.selected.getMonth();
      picker.input.value = toLocalInputValue(picker.selected);
      syncDateTimeDisplay(picker);
      if (rerender) renderDateTimePicker(picker);
    }

    function clearDateTimePicker(picker) {
      picker.input.value = '';
      syncDateTimeDisplay(picker);
      closeDateTimePickers();
    }

    function syncDateTimeDisplay(picker) {
      if (!picker.input.value) {
        picker.display.textContent = picker.placeholder;
        picker.display.classList.add('placeholder');
        return;
      }
      const parsed = parsePickerValue(picker.input.value);
      picker.display.textContent = parsed ? formatPickerDisplay(parsed) : picker.input.value;
      picker.display.classList.remove('placeholder');
    }

    function parsePickerValue(value) {
      if (!value) return null;
      const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/);
      if (!match) return null;
      return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6] || 0));
    }

    function toLocalInputValue(date) {
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}T${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    }

    function dateKey(date) {
      return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
    }

    function formatPickerDisplay(date) {
      const day = String(date.getDate()).padStart(2, '0');
      const month = new Intl.DateTimeFormat('en', { month: 'short' }).format(date);
      return `${day} ${month} ${date.getFullYear()}, ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
    }

    function formatDateLabel(date) {
      return new Intl.DateTimeFormat('en', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }).format(date);
    }

    function syncSourceMode() {
      const mode = getSourceMode();
      const uploadActive = mode === 'upload';
      uploadCard.classList.toggle('active', uploadActive);
      pathCard.classList.toggle('active', !uploadActive);
      uploadPanel.hidden = !uploadActive;
      pathPanel.hidden = uploadActive;
      uploadInput.disabled = !uploadActive;
      pathInput.disabled = uploadActive;
    }

    function getSourceMode() {
      return document.querySelector('input[name="source_mode"]:checked')?.value || 'upload';
    }

    function validateEvidenceInput(mode) {
      if (mode === 'upload' && !selectedUploadFiles.length) {
        setStatus('failed', 'Choose a UAC archive upload, or switch to server path.');
        browseUpload.focus();
        return false;
      }
      if (mode === 'path' && !pathInput.value.trim()) {
        setStatus('failed', 'Provide a server-side input path, or switch to archive upload.');
        pathInput.focus();
        return false;
      }
      return true;
    }

    function buildEvidenceFormData(mode) {
      const body = new FormData(form);
      if (mode === 'upload') {
        body.set('input_path', '');
        body.delete('uac_file');
        if (!stagedUpload?.upload_id) throw new Error('Evidence files have not been staged.');
        body.set('staged_upload_id', stagedUpload.upload_id);
      }
      if (mode === 'path') body.delete('uac_file');
      return new URLSearchParams(body);
    }

    function setStatus(kind, text) {
      statusBox.className = `status ${kind}`;
      statusBox.textContent = text;
    }

    function metric(label, value) {
      return `<div class="metric"><strong>${Number(value || 0).toLocaleString()}</strong><span>${escapeHtml(label)}</span></div>`;
    }

    function formatBytes(bytes) {
      if (!bytes) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB'];
      let size = bytes;
      let idx = 0;
      while (size >= 1024 && idx < units.length - 1) { size /= 1024; idx++; }
      return `${size.toFixed(idx ? 1 : 0)} ${units[idx]}`;
    }

    function formatDuration(seconds) {
      const total = Math.round(seconds);
      if (total < 60) return `${total}s`;
      const minutes = Math.floor(total / 60);
      const remainder = total % 60;
      return `${minutes}m ${String(remainder).padStart(2, '0')}s`;
    }

    function escapeHtml(value) {
      return value.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
