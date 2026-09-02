(() => {
  'use strict';

  const ui = window.HappyScanUI;
  if (!ui) return;
  const {api, esc, toast, formatTime, renderFinding, severityLabel, httpRequestEditor} = ui;
  const byId = id => document.getElementById(id);
  const terminalStatuses = new Set(['completed', 'failed', 'cancelled', 'stopped']);
  const state = {
    sessions: [],
    sessionId: '',
    session: null,
    assets: [],
    assetsTotal: 0,
    assetPage: 1,
    assetPageSize: 10,
    assetId: '',
    assetSessionId: '',
    assetDetail: null,
    assetDetailToken: '',
    expandedFindingAssetId: '',
    findings: [],
    findingGroups: [],
    interceptions: [],
    interceptionId: '',
    interceptionDetail: null,
    interceptionDirty: false,
    interceptionRevision: 0,
    interceptionController: null,
    interceptionLoopKey: '',
    interceptionQueueToken: '',
    interceptionSummaryToken: '',
    interceptionRawToken: '',
    reportGroup: '',
    assetRevisionToken: '',
    progressRevisionToken: '',
    findingRevisionToken: '',
    loadedAssetRevisionToken: '',
    loadedProgressRevisionToken: '',
    loadedFindingRevisionToken: '',
    assetContentToken: '',
    forceReload: true,
    timer: null,
    busy: false,
    refreshPending: false,
    changeRevision: 0,
    changeController: null,
    changeLoop: false,
    clientTLSFile: '',
    clientTLSFormat: '',
    clientTLSName: ''
  };
  const interceptionEditor = window.HappyScanEditor.create(byId('webscan-interception-raw'), {
    readOnly: true,
    onChange: () => { state.interceptionDirty = true; }
  });
  const detailRequestEditor = window.HappyScanEditor.create(byId('webscan-detail-request'), {readOnly: true});
  const detailResponseEditor = window.HappyScanEditor.create(byId('webscan-detail-response'), {readOnly: true});
  const browserOwner = (() => {
    const key = 'happyScanWebOwner';
    let value = sessionStorage.getItem(key);
    if (!value) {
      value = globalThis.crypto?.randomUUID?.() || `browser_${Date.now()}_${Math.random().toString(16).slice(2)}`;
      sessionStorage.setItem(key, value);
    }
    return value;
  })();

  byId('webscan-client-tls-upload').addEventListener('click', () => byId('webscan-client-tls-file-input').click());
  byId('webscan-client-tls-file-input').addEventListener('change', async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size < 1 || file.size > 2000000) {
      event.target.value = '';
      return toast('客户端 TLS 证书必须小于 2 MiB', true);
    }
    const extension = (file.name.split('.').pop() || '').toLowerCase();
    if (!['pem', 'pfx', 'p12'].includes(extension)) {
      event.target.value = '';
      return toast('仅支持 PEM、PFX 或 P12 文件', true);
    }
    const button = byId('webscan-client-tls-upload');
    button.disabled = true;
    button.textContent = '正在导入…';
    try {
      const form = new FormData();
      form.append('file', file);
      const response = await fetch('/api/v1/client-tls-files', {method: 'POST', body: form});
      let data = {};
      try { data = await response.json(); } catch (_) {}
      if (!response.ok) throw new Error(data.error || `证书上传失败 (${response.status})`);
      state.clientTLSFile = data.client_tls_file;
      state.clientTLSFormat = data.format;
      state.clientTLSName = file.name;
      byId('webscan-client-tls-name').textContent = file.name;
      byId('webscan-client-tls-clear').classList.remove('hidden');
      byId('webscan-client-tls-password').classList.toggle('hidden', extension === 'pem');
      byId('webscan-intercept-tls').checked = true;
      toast('mTLS 客户端证书已导入；启动代理后将用于作用域内 HTTPS 上游连接');
    } catch (error) {
      event.target.value = '';
      toast(error.message, true);
    } finally {
      button.disabled = false;
      button.textContent = '导入 mTLS 证书';
    }
  });
  byId('webscan-client-tls-clear').addEventListener('click', () => {
    state.clientTLSFile = '';
    state.clientTLSFormat = '';
    state.clientTLSName = '';
    byId('webscan-client-tls-file-input').value = '';
    byId('webscan-client-tls-password').value = '';
    byId('webscan-client-tls-password').classList.add('hidden');
    byId('webscan-client-tls-clear').classList.add('hidden');
    byId('webscan-client-tls-name').textContent = '未选择';
  });

  const sessionObject = value => value?.web_scan || value?.session || value?.scan || value || {};
  const assetObject = value => value?.asset || value?.interface || value || {};
  const idOf = value => String(value?.id || value?.web_scan_id || value?.session_id || value?.asset_id || value?.interface_id || '');
  const listFrom = (value, names) => {
    if (Array.isArray(value)) return value;
    for (const name of names) if (Array.isArray(value?.[name])) return value[name];
    return [];
  };
  const lineValues = value => String(value || '').split(/\r?\n|,/).map(item => item.trim()).filter(Boolean);
  const numberFrom = (...values) => {
    for (const value of values) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
    return 0;
  };
  const statusLabel = value => ({
    starting: '启动中', listening: '监听中', running: '运行中', active: '运行中',
    observed: '待扫描', pending: '待扫描', queued: '排队中', scanning: '扫描中',
    completed: '已完成', failed: '失败', skipped: '已跳过', stopped: '已停止',
    cancelled: '已取消', deleting: '正在停止'
  })[String(value || '').toLowerCase()] || value || '未知';
  const severityToken = value => ({
    '严重': 'critical', '高危': 'high', '中危': 'medium', '低危': 'low', '提示': 'info'
  })[String(value || '')] || String(value || '').toLowerCase();
  const dateLabel = value => {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', {hour12: false});
  };
  const proxyAddress = session => session.proxy_address || session.proxy_listen || session.listen || '—';
  const sessionStatus = session => session.status || session.proxy_status || 'starting';
  const assetStatus = asset => asset.scan_status || asset.status || 'observed';
  const sessionCounters = session => session.counters || session.stats || session.summary || {};
  const proxyIsListening = session => ['starting', 'listening', 'running', 'active'].includes(String(sessionStatus(session)).toLowerCase());

  function activeWebView() {
    if (byId('proxy-view')?.classList.contains('active')) return 'proxy';
    if (byId('assets-view')?.classList.contains('active')) return 'assets';
    return '';
  }

  function currentView() { return Boolean(activeWebView()); }

  function syncChangeStream() {
    const enabled = currentView() && !document.hidden;
    if (enabled === state.changeLoop) return;
    state.changeLoop = enabled;
    if (state.changeController) state.changeController.abort();
    state.changeController = null;
    if (enabled) void runChangeStream();
  }

  async function runChangeStream() {
    while (state.changeLoop && !document.hidden) {
      const controller = new AbortController();
      state.changeController = controller;
      try {
        const query = new URLSearchParams({since: String(state.changeRevision), wait: '1'});
        const response = await fetch(`/api/v3/web-scans/history/changes?${query}`, {
          headers: {'Accept': 'application/json'}, cache: 'no-store', signal: controller.signal
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!state.changeLoop) return;
        const revision = numberFrom(data.revision);
        const changed = state.changeRevision !== 0 && revision !== state.changeRevision;
        state.changeRevision = revision;
        if (changed) await refresh(false);
      } catch (error) {
        if (controller.signal.aborted || !state.changeLoop) return;
        await new Promise(resolve => window.setTimeout(resolve, 1200));
      }
    }
  }

  function renderSession() {
    const session = state.session;
    const runtime = byId('webscan-runtime');
    if (!session || !state.sessionId) {
      runtime.classList.add('hidden');
      updateProxyToggle(false);
      renderInterceptions();
      return;
    }
    runtime.classList.remove('hidden');
    const status = sessionStatus(session);
    const metricStatus = byId('webscan-metric-status');
    metricStatus.textContent = statusLabel(status);
    metricStatus.className = `webscan-metric-state ${esc(String(status).toLowerCase())}`;

    const counters = sessionCounters(session);
    const observed = numberFrom(counters.observed_requests, counters.observed, session.observed_requests, session.captured_requests);
    const assets = numberFrom(counters.assets, state.assetsTotal);
    const findings = numberFrom(counters.findings, state.findings.length);
    byId('webscan-metric-observed').textContent = observed.toLocaleString();
    byId('webscan-metric-assets').textContent = assets.toLocaleString();
    byId('webscan-metric-findings').textContent = findings.toLocaleString();
    const listening = proxyIsListening(session);
    const requestToggle = byId('webscan-intercept-request');
    const responseToggle = byId('webscan-intercept-response');
    requestToggle.classList.toggle('hidden', !listening);
    responseToggle.classList.toggle('hidden', !listening);
    requestToggle.classList.toggle('active', Boolean(session.intercept_requests));
    responseToggle.classList.toggle('active', Boolean(session.intercept_responses));
    requestToggle.setAttribute('aria-pressed', String(Boolean(session.intercept_requests)));
    responseToggle.setAttribute('aria-pressed', String(Boolean(session.intercept_responses)));
    updateProxyToggle(proxyIsListening(session));
    renderInterceptions();
    syncInterceptionStream();
  }

  function interceptionStatus(value) {
    return ({pending: '等待处理', forwarded: '已放行', modified: '修改后放行', dropped: '已丢弃',
      timed_out: '处理超时', cancelled: '连接已关闭'})[value] || value || '未知';
  }

  function renderInterceptions() {
    const panel = byId('webscan-interception-panel');
    const enabled = Boolean(state.session?.intercept_requests || state.session?.intercept_responses);
    panel.classList.toggle('hidden', !proxyIsListening(state.session || {}) || !enabled);
    const pending = state.interceptions.filter(item => item.status === 'pending').length;
    byId('webscan-interception-summary').textContent = `${pending} 个等待处理`;
    const summary = state.interceptions.find(value => value.id === state.interceptionId);
    const item = state.interceptionDetail?.id === state.interceptionId
      ? {...state.interceptionDetail, status: summary?.status || state.interceptionDetail.status,
        resolution: summary?.resolution || state.interceptionDetail.resolution}
      : summary;
    const pendingItem = item?.status === 'pending';
    const summaryToken = item ? JSON.stringify([item.id, item.status, item.resolution, item.direction,
      item.method, item.host, item.path, item.editable]) : 'empty';
    if (!item) {
      if (state.interceptionSummaryToken !== summaryToken) byId('webscan-interception-meta').textContent = '等待 HTTP 报文…';
      if (state.interceptionRawToken !== 'empty' && !interceptionEditor.hasFocus()) {
        interceptionEditor.setValue('');
        state.interceptionDirty = false;
      }
      state.interceptionRawToken = 'empty';
    } else {
      if (state.interceptionSummaryToken !== summaryToken) {
        byId('webscan-interception-meta').textContent = `${item.direction === 'request' ? '请求' : '响应'} · ${item.method || ''} ${item.host || ''}${item.path || ''} · ${interceptionStatus(item.status)} · 60 秒超时自动丢弃`;
      }
      const rawToken = state.interceptionDetail ? `${item.id}:${String(item.raw || '').length}:${item.created_at || ''}` : '';
      if (rawToken && rawToken !== state.interceptionRawToken && !state.interceptionDirty && !interceptionEditor.hasFocus()) {
        interceptionEditor.setValue(item.raw || '');
        state.interceptionDirty = false;
        state.interceptionRawToken = rawToken;
      }
    }
    state.interceptionSummaryToken = summaryToken;
    interceptionEditor.setReadOnly(!pendingItem || !item?.editable || !state.interceptionDetail);
    byId('webscan-interception-forward').disabled = !pendingItem;
    byId('webscan-interception-drop').disabled = !pendingItem;
  }

  function updateProxyToggle(listening) {
    const button = byId('webscan-create-button');
    button.textContent = listening ? '关闭代理' : '启动代理';
    button.classList.toggle('closing', listening);
    byId('webscan-intercept-request').classList.toggle('hidden', !listening);
    byId('webscan-intercept-response').classList.toggle('hidden', !listening);
  }

  function progressLabel(asset) {
    if (asset.response_pending) return '等待响应 Body';
    const progress = asset.progress || asset.scan_progress || {};
    const finite = (...items) => items.map(Number).filter(Number.isFinite);
    const done = Math.max(0, ...finite(progress.resolved_requests, progress.completed_checks, progress.completed, asset.requests_completed));
    const total = Math.max(0, ...finite(progress.planned_requests, progress.total_checks, progress.total, asset.requests_planned));
    const sent = Math.max(0, ...finite(progress.requests_sent, asset.requests_sent));
    const status = String(assetStatus(asset)).toLowerCase();
    if (total > 0) return `${Math.min(done, total)}/${total}`;
    if (['queued', 'pending'].includes(status)) return '排队中';
    if (['running', 'scanning'].includes(status)) return sent > 0 ? `已发 ${sent}` : '扫描中';
    if (status === 'completed') return sent > 0 ? `${sent} 个请求` : '已完成';
    if (status === 'failed') return '失败';
    return asset.scan_id ? '准备中' : '—';
  }

  function assetPath(asset) {
    const host = asset.host || asset.hostname || '';
    const path = asset.normalized_path || asset.path || asset.url || '';
    return {host, path};
  }

  function renderAssets() {
    const body = byId('webscan-assets-body');
    const assets = state.assets;
    if (!assets.length) {
      body.innerHTML = `<tr><td colspan="10" class="webscan-table-empty">${state.assetsTotal ? '当前页没有接口' : '等待浏览器流量…'}</td></tr>`;
    } else {
      body.innerHTML = assets.map(asset => {
        const id = idOf(asset);
        const sessionId = String(asset.web_scan_id || state.sessionId);
        const location = assetPath(asset);
        const findingCount = numberFrom(asset.findings_count, asset.vulnerabilities_count);
        const selected = id === state.assetId && sessionId === state.assetSessionId ? ' selected' : '';
        return `<tr class="webscan-asset-row${selected}" data-asset-id="${esc(id)}" data-session-id="${esc(sessionId)}">
          <td><span class="webscan-method">${esc(asset.method || '—')}</span></td>
          <td class="webscan-host-cell">${esc(location.host || '—')}</td>
          <td class="webscan-path-cell">${esc(location.path || '/')}</td>
          <td>${esc(asset.content_type || asset.type || '—')}</td>
          <td title="${numberFrom(asset.response_bytes, asset.response_size).toLocaleString()} bytes">${esc(byteSize(asset.response_bytes || asset.response_size))}</td>
          <td>${numberFrom(asset.seen_count, asset.occurrences, 1).toLocaleString()}</td>
          <td><span class="webscan-asset-status ${esc(asset.response_pending ? 'receiving' : String(assetStatus(asset)).toLowerCase())}">${esc(asset.response_pending ? '响应接收中' : statusLabel(assetStatus(asset)))}</span></td>
          <td>${esc(progressLabel(asset))}</td>
          <td><span class="webscan-finding-count${findingCount ? ' has-findings' : ''}">${findingCount.toLocaleString()}</span></td>
          <td>${esc(dateLabel(asset.last_seen || asset.updated_at || asset.first_seen))}</td>
        </tr>`;
      }).join('');
    }
    body.querySelectorAll('[data-asset-id]').forEach(row => row.addEventListener('click', () =>
      selectAsset(row.dataset.assetId, row.dataset.sessionId)));
    const pages = Math.max(1, Math.ceil(state.assetsTotal / state.assetPageSize));
    if (state.assetPage > pages) state.assetPage = pages;
    byId('webscan-assets-page-label').textContent = `第 ${state.assetPage}/${pages} 页 · ${state.assetsTotal.toLocaleString()} 条接口`;
    byId('webscan-assets-prev').disabled = state.assetPage <= 1;
    byId('webscan-assets-next').disabled = state.assetPage >= pages;
  }

  function byteSize(value) {
    const bytes = Number(value || 0);
    if (!Number.isFinite(bytes) || bytes <= 0) return '—';
    if (bytes < 1024) return `${bytes.toLocaleString()} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  }

  function preserveExpandedDetails(container, render) {
    const expanded = new Set(
      Array.from(container.querySelectorAll('details'))
        .map((detail, index) => detail.open ? index : -1)
        .filter(index => index >= 0)
    );
    const scrollPositions = Array.from(container.querySelectorAll('.evidence')).map(node => ({
      top: node.scrollTop, left: node.scrollLeft
    }));
    const containerScroll = {top: container.scrollTop, left: container.scrollLeft};
    render();
    container.querySelectorAll('details').forEach((detail, index) => {
      detail.open = expanded.has(index);
    });
    container.querySelectorAll('.evidence').forEach((node, index) => {
      node.scrollTop = scrollPositions[index]?.top || 0;
      node.scrollLeft = scrollPositions[index]?.left || 0;
    });
    container.scrollTop = containerScroll.top;
    container.scrollLeft = containerScroll.left;
  }

  function renderAssetDetail() {
    const detail = state.assetDetail;
    const card = byId('webscan-asset-detail-card');
    const placeholder = byId('webscan-detail-placeholder');
    if (!detail || !state.assetId) {
      card.classList.add('hidden');
      placeholder.classList.remove('hidden');
      byId('webscan-detail-content').classList.add('hidden');
      byId('webscan-scan-asset').classList.add('hidden');
      byId('webscan-copy-request').classList.add('hidden');
      return;
    }
    const asset = assetObject(detail);
    const findings = listFrom(detail, ['findings', 'vulnerabilities']).length
      ? listFrom(detail, ['findings', 'vulnerabilities'])
      : listFrom(asset, ['findings', 'vulnerabilities']);
    card.classList.remove('hidden');
    placeholder.classList.add('hidden');
    byId('webscan-detail-content').classList.remove('hidden');
    byId('webscan-scan-asset').classList.remove('hidden');
    byId('webscan-copy-request').classList.remove('hidden');
    byId('webscan-scan-asset').disabled = false;
    byId('webscan-copy-request').disabled = false;
    const request = detail.raw_request || asset.raw_request || detail.request || asset.request || '';
    const response = detail.raw_response || asset.raw_response || detail.response || asset.response || '';
    byId('webscan-detail-finding-count').textContent = String(findings.length);
    const contentToken = `${state.assetSessionId}:${state.assetId}:${request.length}:${response.length}:${findings.length}`;
    if (state.assetContentToken === contentToken) return;
    state.assetContentToken = contentToken;
    detailRequestEditor.setValue(request);
    detailResponseEditor.setValue(response);
    const findingsNode = byId('webscan-detail-findings');
    const detailedFindings = findings.map(finding => withFallbackEvidence(finding, request, response));
    preserveExpandedDetails(findingsNode, () => {
      findingsNode.innerHTML = detailedFindings.length
        ? detailedFindings.map(renderFinding).join('')
        : '<div class="webscan-empty compact"><strong>当前接口暂无漏洞结果</strong><p>灰色、跳过或覆盖不完整的插件不代表目标安全。</p></div>';
    });
    state.expandedFindingAssetId = state.assetId;
  }

  function withFallbackEvidence(finding, request, response) {
    if (Array.isArray(finding.evidence) && finding.evidence.length) return finding;
    let summary = '该漏洞对应的原始请求与响应';
    const title = String(finding.title || '');
    if (String(finding.plugin_id || '') === 'sensitive_data' && title.startsWith('响应泄露')) {
      const label = title.slice('响应泄露'.length) || '敏感信息';
      summary = `匹配到 ${label}`;
      if (label === 'Linux 绝对文件路径') {
        const matched = String(response || '').match(/(?:\/[a-zA-Z0-9_.-]+){4,}/)?.[0] || '';
        if (matched) summary += `: ${matched}`;
      }
    }
    return {...finding, evidence: [{
      summary,
      request: String(request || ''),
      response: String(response || ''),
      response_status: responseStatus(response)
    }]};
  }

  function responseStatus(response) {
    const matched = String(response || '').match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/);
    return matched ? Number(matched[1]) : 0;
  }

  const findingGroupKey = finding => `${String(finding.plugin_id || finding.category || 'other')}␟${findingTitle(finding)}`;
  const findingInterfaceKey = finding => {
    if (finding.asset_id) return `${String(finding.web_scan_id || state.sessionId)}␞${String(finding.asset_id)}`;
    if (finding.interface_host || finding.interface_path) {
      return `${finding.interface_method || ''}|${finding.interface_host || ''}|${finding.interface_path || ''}`;
    }
    return String(finding.affected || 'unknown');
  };
  const findingInterfaceLabel = finding => {
    const location = `${finding.interface_host || ''}${finding.interface_path || ''}`;
    return location ? `${finding.interface_method || ''} ${location}`.trim() : String(finding.affected || '未标记接口');
  };
  const findingTitle = finding => String(finding.title || finding.plugin_id || finding.category || '其他漏洞');

  function renderReport() {
    const findings = state.findings;
    const totalFindings = state.findingGroups.reduce((sum, group) => sum + numberFrom(group.count), 0);
    byId('webscan-report-summary').textContent = `${totalFindings} 个发现`;
    const groupsNode = byId('webscan-report-groups');
    const interfacesNode = byId('webscan-report-interfaces');
    if (!state.findingGroups.length) {
      state.reportGroup = '';
      groupsNode.innerHTML = '<div class="empty-result"><strong>暂未发现漏洞</strong><p>接口完成扫描后，站点级漏洞结果会在这里汇总。</p></div>';
      interfacesNode.classList.add('hidden');
      return;
    }
    if (state.reportGroup && !state.findingGroups.some(group => group.key === state.reportGroup)) {
      state.reportGroup = '';
    }
    groupsNode.innerHTML = state.findingGroups.map(group => {
      const selected = state.reportGroup === group.key ? ' selected' : '';
      return `<button type="button" class="webscan-vulnerability-card${selected}" data-report-group="${esc(group.key)}">
        <strong>${esc(group.title || group.plugin_id || '其他漏洞')}</strong><small>${numberFrom(group.count)} 个发现 · ${numberFrom(group.interfaces)} 个接口</small>
      </button>`;
    }).join('');
    groupsNode.querySelectorAll('[data-report-group]').forEach(button => button.addEventListener('click', async () => {
      const next = state.reportGroup === button.dataset.reportGroup ? '' : button.dataset.reportGroup;
      state.reportGroup = next;
      state.findings = [];
      renderReport();
      if (!next) return;
      try {
        const data = await api(`/api/v3/web-scans/history/findings?group=${encodeURIComponent(next)}`);
        if (state.reportGroup !== next) return;
        state.findings = listFrom(data, ['findings', 'vulnerabilities']);
        renderReport();
      } catch (error) { toast(error.message, true); }
    }));

    const selectedFindings = state.reportGroup ? findings : [];
    if (!selectedFindings.length) {
      interfacesNode.classList.add('hidden');
      interfacesNode.innerHTML = '';
      return;
    }
    const interfaces = new Map();
    selectedFindings.forEach(finding => {
      const key = findingInterfaceKey(finding);
      if (!interfaces.has(key)) interfaces.set(key, {
        label: findingInterfaceLabel(finding), findings: [],
        assetId: String(finding.asset_id || ''), sessionId: String(finding.web_scan_id || state.sessionId)
      });
      interfaces.get(key).findings.push(finding);
    });
    interfacesNode.classList.remove('hidden');
    interfacesNode.innerHTML = `<div class="webscan-report-level-title">受影响接口</div><div class="webscan-interface-cards">${Array.from(interfaces, ([key, item]) =>
      `<button type="button" class="webscan-interface-card" data-report-asset="${esc(item.assetId)}" data-report-session="${esc(item.sessionId)}"><strong>${esc(item.label)}</strong></button>`
    ).join('')}</div>`;
    interfacesNode.querySelectorAll('[data-report-asset]').forEach(button => button.addEventListener('click', () =>
      openAssetFromReport(button.dataset.reportAsset, button.dataset.reportSession)));
  }

  async function loadSessions() {
    const data = await api('/api/v3/web-scans');
    const all = listFrom(data, ['web_scans', 'sessions', 'scans'])
      .sort((left, right) => new Date(right.created_at || 0) - new Date(left.created_at || 0));
    state.assetRevisionToken = all.map(session => `${idOf(session)}:${numberFrom(session.asset_revision, session.revision)}`).join('|');
    state.progressRevisionToken = all.map(session => `${idOf(session)}:${numberFrom(session.progress_revision, session.revision)}`).join('|');
    state.findingRevisionToken = all.map(session => `${idOf(session)}:${numberFrom(session.finding_revision, session.revision)}`).join('|');
    state.sessions = all;
    if (!state.sessions.some(session => idOf(session) === state.sessionId)) {
      state.sessionId = state.sessions.length ? idOf(state.sessions[0]) : '';
      state.forceReload = true;
    }
    state.session = state.sessions.find(session => idOf(session) === state.sessionId) || null;
  }

  async function applyInterceptions(interceptionsData, encodedSession) {
    const nextInterceptions = listFrom(interceptionsData, ['interceptions']);
    const nextToken = JSON.stringify(nextInterceptions.map(item => [item.id, item.status, item.resolution]));
    const queueChanged = nextToken !== state.interceptionQueueToken;
    state.interceptionQueueToken = nextToken;
    state.interceptions = nextInterceptions;
    state.interceptionRevision = numberFrom(interceptionsData?.revision, state.interceptionRevision);
    const pendingItems = state.interceptions.filter(item => item.status === 'pending');
    const currentPending = pendingItems.some(item => item.id === state.interceptionId);
    if (!currentPending) {
      const next = pendingItems[0];
      state.interceptionId = next?.id || '';
      state.interceptionDetail = null;
      state.interceptionDirty = false;
    }
    if (state.interceptionId && !state.interceptionDetail) {
      try {
        const detailData = await api(`/api/v3/web-scans/${encodedSession}/interceptions/${encodeURIComponent(state.interceptionId)}`);
        state.interceptionDetail = detailData.interception || detailData;
      } catch (_) {
        state.interceptionId = '';
        state.interceptionDetail = null;
      }
    }
    if (!state.interceptionId) {
      state.interceptionDetail = null;
      state.interceptionDirty = false;
    }
    if (queueChanged || state.interceptionDetail) renderInterceptions();
  }

  function syncInterceptionStream() {
    const enabled = activeWebView() === 'proxy' && !document.hidden && state.sessionId &&
      proxyIsListening(state.session || {}) &&
      Boolean(state.session?.intercept_requests || state.session?.intercept_responses);
    const key = enabled ? state.sessionId : '';
    if (state.interceptionLoopKey === key) return;
    if (state.interceptionController) state.interceptionController.abort();
    state.interceptionController = null;
    state.interceptionLoopKey = key;
    state.interceptionRevision = 0;
    if (!key) return;
    void runInterceptionStream(key);
  }

  async function runInterceptionStream(sessionId) {
    while (state.interceptionLoopKey === sessionId && !document.hidden) {
      const controller = new AbortController();
      state.interceptionController = controller;
      try {
        const query = new URLSearchParams({since: String(state.interceptionRevision), wait: '1'});
        const response = await fetch(`/api/v3/web-scans/${encodeURIComponent(sessionId)}/interceptions?${query}`, {
          headers: {'Accept': 'application/json'}, cache: 'no-store', signal: controller.signal
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (state.interceptionLoopKey !== sessionId) return;
        await applyInterceptions(data, encodeURIComponent(sessionId));
      } catch (error) {
        if (controller.signal.aborted || state.interceptionLoopKey !== sessionId) return;
        await new Promise(resolve => window.setTimeout(resolve, 1000));
      }
    }
  }

  async function loadCurrentSession() {
    if (!state.sessionId) {
      state.session = null;
      state.assets = [];
      state.findings = [];
      state.findingGroups = [];
      renderSession();
      renderAssets();
      renderReport();
      return;
    }
    const assetsChanged = state.forceReload || state.assetRevisionToken !== state.loadedAssetRevisionToken ||
      state.progressRevisionToken !== state.loadedProgressRevisionToken;
    const findingsChanged = state.forceReload || state.findingRevisionToken !== state.loadedFindingRevisionToken;
    if (assetsChanged || findingsChanged) {
      const query = new URLSearchParams({
        page: String(state.assetPage), page_size: String(state.assetPageSize),
        q: byId('webscan-asset-search').value.trim(), status: byId('webscan-asset-status').value
      });
      const [assetsData, findingsData] = await Promise.all([
        assetsChanged ? api(`/api/v3/web-scans/history/assets?${query}`) : Promise.resolve(null),
        findingsChanged ? api('/api/v3/web-scans/history/findings') : Promise.resolve(null)
      ]);
      if (assetsData) {
        state.assets = listFrom(assetsData, ['assets', 'interfaces']);
        state.assetsTotal = numberFrom(assetsData.total, state.assets.length);
        state.loadedAssetRevisionToken = state.assetRevisionToken;
        state.loadedProgressRevisionToken = state.progressRevisionToken;
      }
      if (findingsData) {
        state.findingGroups = listFrom(findingsData, ['groups']);
        state.findings = [];
        state.reportGroup = '';
        state.loadedFindingRevisionToken = state.findingRevisionToken;
      }
      state.forceReload = false;
    }
    renderSession();
    if (assetsChanged || findingsChanged) {
      renderAssets();
      if (findingsChanged) renderReport();
      if (state.assetId) {
        const selected = state.assets.find(item => idOf(item) === state.assetId &&
          String(item.web_scan_id || state.sessionId) === state.assetSessionId);
        const findingToken = selected ? `${selected.findings_count || 0}:${selected.highest_severity || ''}` : '';
        if (selected && state.assetDetail) {
          const detailAsset = assetObject(state.assetDetail);
          detailAsset.scan_status = selected.scan_status;
          detailAsset.progress = selected.progress;
          detailAsset.seen_count = selected.seen_count;
          detailAsset.last_seen = selected.last_seen;
          detailAsset.error = selected.error;
        }
        if (findingToken !== state.assetDetailToken) {
          state.assetDetailToken = findingToken;
          await loadAssetDetail(false);
        } else if (selected && state.assetDetail) {
          renderAssetDetail();
        }
      }
    }
  }

  async function refresh(showError = true) {
    if (state.busy) {
      state.refreshPending = true;
      return;
    }
    state.busy = true;
    try {
      await loadSessions();
      if (activeWebView() === 'assets') await loadCurrentSession();
      else renderSession();
    } catch (error) {
      if (showError) toast(error.message, true);
    } finally {
      state.busy = false;
      if (state.refreshPending) {
        state.refreshPending = false;
        queueMicrotask(() => refresh(false));
      }
    }
  }

  async function selectAsset(id, sessionId) {
    sessionId = String(sessionId || state.sessionId);
    if (state.assetId === id && state.assetSessionId === sessionId) {
      state.assetId = '';
      state.assetSessionId = '';
      state.assetDetail = null;
      state.assetDetailToken = '';
      state.assetContentToken = '';
      state.expandedFindingAssetId = '';
      renderAssets();
      renderAssetDetail();
      return;
    }
    state.assetId = id;
    state.assetSessionId = sessionId;
    renderAssets();
    await loadAssetDetail(true);
  }

  async function loadAssetDetail(showError) {
    if (!state.assetSessionId || !state.assetId) return;
    try {
      state.assetDetail = await api(`/api/v3/web-scans/${encodeURIComponent(state.assetSessionId)}/assets/${encodeURIComponent(state.assetId)}`);
      renderAssetDetail();
    } catch (error) {
      if (showError) toast(error.message, true);
    }
  }

  async function openAssetFromReport(assetId, sessionId) {
    if (!sessionId || !assetId) return;
    state.assetId = assetId;
    state.assetSessionId = sessionId;
    state.assetDetail = null;
    state.assetDetailToken = '';
    state.assetContentToken = '';
    state.expandedFindingAssetId = '';
    renderAssets();
    await loadAssetDetail(true);
  }

  byId('webscan-form').addEventListener('submit', async event => {
    event.preventDefault();
    const activeSession = state.session;
    if (activeSession && state.sessionId && proxyIsListening(activeSession)) {
      const button = byId('webscan-create-button');
      button.disabled = true;
      button.textContent = '正在关闭…';
      try {
        await api(`/api/v3/web-scans/${encodeURIComponent(state.sessionId)}/proxy`, {method: 'DELETE'});
        toast('代理已关闭；未完成扫描和历史记录继续保留');
        await refresh(false);
      } catch (error) {
        toast(error.message, true);
      } finally {
        button.disabled = false;
        updateProxyToggle(proxyIsListening(state.session || {}));
      }
      return;
    }
    const targetURL = byId('webscan-target').value.trim();
    const globalScope = !targetURL || targetURL === '*';
    const proxyListen = byId('webscan-proxy-listen').value.trim();
    if (!proxyListen) return toast('请填写代理监听地址', true);
    if (globalScope && byId('webscan-mode').value !== 'passive') {
      return toast('全局作用域只允许使用 Passive 模式', true);
    }
    const button = byId('webscan-create-button');
    button.disabled = true;
    button.textContent = '正在启动…';
    const payload = {
      target_url: globalScope ? '*' : targetURL,
      scope_hosts: globalScope ? [] : lineValues(byId('webscan-scope-hosts').value),
      proxy_listen: proxyListen,
      scan_mode: byId('webscan-mode').value,
      auto_scan: byId('webscan-auto-scan').checked,
      filter_static: byId('webscan-filter-static').checked,
      static_extensions: byId('webscan-filter-static').checked ? lineValues(byId('webscan-static-extensions').value) : [],
      intercept_tls: byId('webscan-intercept-tls').checked,
      client_tls_file: state.clientTLSFile || undefined,
      client_tls_password: state.clientTLSFile ? byId('webscan-client-tls-password').value : undefined,
      intercept_requests: false,
      intercept_responses: false,
      browser_owner: browserOwner
    };
    try {
      const data = await api('/api/v3/web-scans', {method: 'POST', body: JSON.stringify(payload)});
      const created = sessionObject(data);
      state.sessionId = idOf(created) || String(data.web_scan_id || data.session_id || '');
      state.assetId = '';
      state.assetSessionId = '';
      state.assetDetail = null;
      state.assetContentToken = '';
      state.loadedAssetRevisionToken = '';
      state.loadedProgressRevisionToken = '';
      state.loadedFindingRevisionToken = '';
      state.forceReload = true;
      toast(globalScope ? '全局 Passive 代理已启动' : 'WEB扫描代理任务已启动');
      await refresh();
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
      updateProxyToggle(proxyIsListening(state.session || {}));
    }
  });

  function syncGlobalScopeForm() {
    const targetURL = byId('webscan-target').value.trim();
    const globalScope = !targetURL || targetURL === '*';
    const mode = byId('webscan-mode');
    const normal = mode.querySelector('option[value="normal"]');
    if (globalScope) mode.value = 'passive';
    if (normal) normal.disabled = globalScope;
    byId('webscan-scope-hosts').disabled = globalScope;
    byId('webscan-scope-hosts').title = globalScope ? '全局 Passive 模式不需要配置 Host 作用域' : '';
  }
  byId('webscan-target').addEventListener('input', syncGlobalScopeForm);
  syncGlobalScopeForm();
  const syncStaticExtensions = () => {
    const input = byId('webscan-static-extensions');
    input.disabled = !byId('webscan-filter-static').checked;
    input.title = input.disabled ? '启用“过滤静态资源”后可追加后缀' : '';
  };
  byId('webscan-filter-static').addEventListener('change', syncStaticExtensions);
  syncStaticExtensions();

  let filterTimer = null;
  const reloadAssets = () => {
    state.assetPage = 1;
    state.forceReload = true;
    refresh(false);
  };
  byId('webscan-asset-search').addEventListener('input', () => {
    window.clearTimeout(filterTimer);
    filterTimer = window.setTimeout(reloadAssets, 250);
  });
  byId('webscan-asset-status').addEventListener('change', reloadAssets);
  byId('webscan-clear-history').addEventListener('click', async () => {
    if (!window.confirm('确定清空全部历史接口资产和漏洞结果吗？此操作不可恢复。')) return;
    if (!window.confirm('请再次确认：删除本机保存的全部 WEB 扫描历史资产？')) return;
    const button = byId('webscan-clear-history');
    button.disabled = true;
    try {
      const result = await api('/api/v3/web-scans/history/assets', {
        method: 'DELETE',
        body: JSON.stringify({confirm: 'CLEAR_ALL_HISTORY_ASSETS'})
      });
      state.assetId = '';
      state.assetSessionId = '';
      state.assetDetail = null;
      state.assets = [];
      state.assetsTotal = 0;
      state.findings = [];
      state.findingGroups = [];
      state.loadedAssetRevisionToken = '';
      state.loadedProgressRevisionToken = '';
      state.loadedFindingRevisionToken = '';
      state.forceReload = true;
      renderAssetDetail();
      await refresh(false);
      toast(`已清空 ${numberFrom(result.removed).toLocaleString()} 条历史接口资产`);
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  });
  byId('webscan-assets-prev').addEventListener('click', () => {
    if (state.assetPage <= 1) return;
    state.assetPage--;
    state.forceReload = true;
    refresh(false);
  });
  byId('webscan-assets-next').addEventListener('click', () => {
    if (state.assetPage * state.assetPageSize >= state.assetsTotal) return;
    state.assetPage++;
    state.forceReload = true;
    refresh(false);
  });
  async function updateInterceptionSettings(direction) {
    if (!state.sessionId || !proxyIsListening(state.session || {})) return;
    const requestEnabled = direction === 'request' ? !Boolean(state.session?.intercept_requests) : Boolean(state.session?.intercept_requests);
    const responseEnabled = direction === 'response' ? !Boolean(state.session?.intercept_responses) : Boolean(state.session?.intercept_responses);
    try {
      const data = await api(`/api/v3/web-scans/${encodeURIComponent(state.sessionId)}/interception`, {
        method: 'PUT',
        body: JSON.stringify({
          intercept_requests: requestEnabled,
          intercept_responses: responseEnabled
        })
      });
      state.session = sessionObject(data);
      await loadCurrentSession();
    } catch (error) {
      toast(error.message, true);
      await refresh(false);
    }
  }
  byId('webscan-intercept-request').addEventListener('click', () => updateInterceptionSettings('request'));
  byId('webscan-intercept-response').addEventListener('click', () => updateInterceptionSettings('response'));
  async function decideInterception(action) {
    if (!state.sessionId || !state.interceptionId) return;
    const endpoint = action === 'drop' ? 'drop' : 'forward';
    const payload = action === 'forward' && state.interceptionDetail?.editable
      ? {raw: interceptionEditor.getValue()}
      : {};
    try {
      await api(`/api/v3/web-scans/${encodeURIComponent(state.sessionId)}/interceptions/${encodeURIComponent(state.interceptionId)}/${endpoint}`, {
        method: 'POST', body: JSON.stringify(payload)
      });
      state.interceptionDirty = false;
      await loadCurrentSession();
    } catch (error) {
      toast(error.message, true);
    }
  }
  byId('webscan-interception-forward').addEventListener('click', () => decideInterception('forward'));
  byId('webscan-interception-drop').addEventListener('click', () => decideInterception('drop'));
  byId('webscan-scan-asset').addEventListener('click', async () => {
    if (!state.assetSessionId || !state.assetId) return;
    const asset = assetObject(state.assetDetail || {});
    const request = state.assetDetail?.raw_request || asset.raw_request || state.assetDetail?.request || asset.request || '';
    if (!request) return toast('该接口没有可用的原始请求报文', true);
    httpRequestEditor.setValue(request);
    byId('request-scheme').value = 'auto';
    const scanViewButton = document.querySelector('.nav-button[data-view="scan"]');
    if (scanViewButton) scanViewButton.click();
    httpRequestEditor.focus();
    toast('接口报文已填入扫描引擎，请确认插件后手工发起');
  });
  byId('webscan-copy-request').addEventListener('click', async () => {
    const asset = assetObject(state.assetDetail || {});
    const request = state.assetDetail?.raw_request || asset.raw_request || state.assetDetail?.request || asset.request || '';
    if (!request) return toast('该接口没有可复制的请求报文', true);
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(request);
      } else {
        const temporary = document.createElement('textarea');
        temporary.value = request;
        temporary.style.position = 'fixed';
        temporary.style.opacity = '0';
        document.body.appendChild(temporary);
        temporary.select();
        if (!document.execCommand('copy')) throw new Error('copy failed');
        temporary.remove();
      }
      toast('HTTP请求报文已复制');
    } catch (_) {
      toast('浏览器未允许访问剪贴板，请手工复制', true);
    }
  });
  window.addEventListener('happy:viewchange', event => {
    if (event.detail?.view === 'proxy' || event.detail?.view === 'assets') refresh(false);
    syncInterceptionStream();
    syncChangeStream();
  });
  document.addEventListener('visibilitychange', () => {
    syncInterceptionStream();
    syncChangeStream();
    if (!document.hidden && currentView()) refresh(false);
  });
  refresh(false);
  syncChangeStream();
})();
