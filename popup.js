const searchEngines = [
  { id: 'baidupc', name: '百度PC' },
  { id: 'google', name: 'Google' },
  { id: '360', name: '360搜索' },
  { id: 'baidum', name: '百度移动' },
  { id: 'sougou', name: '搜狗' },
  { id: 'shenma', name: '神马' }
];
const imageCache = new WeakMap();
let tabId = null;
let cachedVulnReports = [];
let selectedReportIds = new Set();
let activeReportSeverityFilter = 'all';
let selectedReport = null;
let currentAiSessionId = '';
let latestScanResults = null;
const frameResults = {};
let currentFrameId = '0';
let scannerRenderTimeout = null;
let pendingScannerRender = null;
let scannerLastRenderAt = 0;
let scannerDelegationBound = false;
let renderedFrameId = null;
const sectionContainers = new Map();
const renderedCounts = new Map();
const SCANNER_RENDER_THROTTLE_MS = 280;
const queryParams = new URLSearchParams(window.location.search);
const isStandaloneView = queryParams.get('view') === 'tab';
const forcedTabId = Number.parseInt(queryParams.get('tabId') || '', 10);
const forcedPage = queryParams.get('page');
const validPages = new Set(['scanner', 'report', 'fingerprint', 'analysis', 'debug', 'config']);
const REPORT_SEVERITY_FILTERS = new Set(['all', 'critical', 'high', 'medium', 'low', 'info']);
const REPORT_SCHEMA = globalThis.SNOWEYES_REPORT_SCHEMA || {};
const REPORT_UTILS = REPORT_SCHEMA.utils || {};
const REPORT_SEVERITY_LEVELS = Array.isArray(REPORT_SCHEMA.REPORT_SEVERITY_LEVELS)
  ? REPORT_SCHEMA.REPORT_SEVERITY_LEVELS
  : ['critical', 'high', 'medium', 'low', 'info'];
const AI_PROVIDER_DEFAULTS = {
  local: {
    endpoint: '',
    model: 'heuristic-local'
  },
  codex: {
    endpoint: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-5.1-codex'
  },
  deepseek: {
    endpoint: 'https://api.deepseek.com/v1/chat/completions',
    model: 'deepseek-chat'
  },
  glm: {
    endpoint: 'https://open.bigmodel.cn/api/paas/v4/chat/completions',
    model: 'glm-4-flash'
  }
};
// 页面切换功能
function switchPage(pageName) {
  // 清理旧页面的资源
  if (currentPageCleanup) currentPageCleanup();
  if (pageName !== 'report') {
    closeReportDetail();
  }
  
  // 更新导航栏状态
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.classList.remove('active');
    if (tab.dataset.page === pageName) {
      tab.classList.add('active');
    }
  });

  // 更新页面显示
  document.querySelectorAll('.page').forEach(page => {
    page.style.display = 'none';
    if (page.classList.contains(`${pageName}-page`)) {
      page.style.display = 'block';
      initializePage(pageName);
    }
  });

  if (pageName === 'scanner') {
    updateFrameNavigationUI();
    const activeFrame = frameResults[currentFrameId] || frameResults['0'];
    if (activeFrame?.results) {
      scheduleScannerRender(activeFrame.results, {
        isInIframe: Boolean(activeFrame.isInIframe),
        forceReset: true,
        forceRenderWhenHidden: true
      });
    } else if (latestScanResults) {
      scheduleScannerRender(latestScanResults, { forceReset: true, forceRenderWhenHidden: true });
    }
  } else {
    const frameBar = document.querySelector('.frame-nav-bar');
    const scannerPage = document.querySelector('.scanner-page');
    if (frameBar) {
      frameBar.style.display = 'none';
    }
    if (scannerPage) {
      scannerPage.classList.remove('with-frame-nav');
    }
  }
}

// 统一页面初始化逻辑
function initializePage(pageName) {
  switch(pageName) {
    case 'report':
      initReportPage();
      break;
    case 'config':
      initConfigPage();
      break;
    case 'fingerprint':
      initFingerprintPage();
      break;
    case 'analysis':
      initAnalysisPage();
      break;
    case 'debug':
      initDebugPage();
      break;
  }
}
function getInitialPage() {
  if (forcedPage && validPages.has(forcedPage)) {
    return forcedPage;
  }
  return document.querySelector('.nav-tab.active')?.dataset.page || 'scanner';
}
function setActiveNav(pageName) {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.page === pageName);
  });
}

// 保存白名单
function saveWhitelist() {
  const whitelistInput = document.getElementById('whitelistInput');
  if (!whitelistInput) return;
  
  // 获取输入的域名，过滤空行
  const domains = whitelistInput.value
    .split('\n')
    .map(domain => domain.trim())
    .filter(domain => domain && domain.length > 0);
  
  // 保存到存储
  chrome.storage.local.set({ customWhitelist: domains }, () => {
    showSaveTooltip('保存成功');
  });
}

// 显示保存提示
function showSaveTooltip(text) {
  const saveBtn = document.getElementById('saveWhitelist');
  if (!saveBtn) return;
  
  const rect = saveBtn.getBoundingClientRect();
  const tooltip = document.createElement('div');
  tooltip.className = 'copy-tooltip';
  tooltip.textContent = text;
  tooltip.style.left = `${rect.left + rect.width / 2}px`;
  tooltip.style.top = `${rect.top - 30}px`;
  document.body.appendChild(tooltip);
  
  setTimeout(() => tooltip.remove(), 1500);
}

// 检查当前域名是否在白名单中
function checkIfWhitelisted(hostname, callback) {
  chrome.storage.local.get(['customWhitelist'], (result) => {
    if (!result.customWhitelist || result.customWhitelist.length === 0) {
      callback(false);
      return;
    }
    
    const customWhitelist = result.customWhitelist.map(domain => domain.toLowerCase());
    const isWhitelisted = customWhitelist.some(domain => 
      hostname === domain || hostname.endsWith(`.${domain}`)
    );
    
    callback(isWhitelisted);
  });
}

function getScannerSections(results = {}) {
  return [
    { id: 'domxss-list', data: results.domxssVulns, title: 'DOM XSS 可疑点' },
    { id: 'domain-list', data: results.domains, title: '域名' },
    { id: 'absolute-api-list', data: results.absoluteApis, title: 'API接口(绝对路径)', hasUrlCopy: true },
    { id: 'api-list', data: results.apis, title: 'API接口(相对路径)', hasUrlCopy: true },
    { id: 'route-list', data: results.pageRoutes || results.routes, title: '页面路由', hasUrlCopy: true },
    { id: 'module-list', data: results.moduleFiles, title: '模块路径' },
    { id: 'doc-list', data: results.docFiles, title: '文档文件' },
    { id: 'credentials-list', data: results.credentials, title: '用户名密码' },
    { id: 'cookie-list', data: results.cookies, title: 'Cookie' },
    { id: 'id-key-list', data: results.idKeys, title: 'ID密钥' },
    { id: 'phone-list', data: results.phones, title: '手机号码' },
    { id: 'email-list', data: results.emails, title: '邮箱' },
    { id: 'idcard-list', data: results.idcards, title: '身份证号' },
    { id: 'ip-list', data: results.ips, title: 'IP地址' },
    { id: 'company-list', data: results.companies, title: '公司机构' },
    { id: 'jwt-list', data: results.jwts, title: 'JWT Token' },
    { id: 'windows-path-list', data: results.windowsPaths, title: 'Windows路径' },
    { id: 'iframe-list', data: results.iframes, title: 'Iframe' },
    { id: 'image-list', data: results.imageFiles, title: '音频图片' },
    { id: 'github-list', data: results.githubUrls, title: 'GitHub链接' },
    { id: 'vue-list', data: results.vueFiles, title: 'Vue文件' },
    { id: 'js-list', data: results.jsFiles, title: 'JS文件' },
    { id: 'third-party-list', data: results.thirdPartyLibs, title: 'JS库' },
    { id: 'url-list', data: results.urls, title: 'URL' }
  ];
}
function resetScannerRenderState(clearDom = true) {
  sectionContainers.clear();
  renderedCounts.clear();
  renderedFrameId = null;
  if (!clearDom) return;
  const container = document.querySelector('.scanner-page .container');
  if (container) {
    container.innerHTML = '';
  }
}
function ensureScannerEventDelegation() {
  if (scannerDelegationBound) return;
  const container = document.querySelector('.scanner-page .container');
  if (!container) return;
  scannerDelegationBound = true;

  container.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const copyBtn = target.closest('.copy-btn');
    if (copyBtn) {
      const section = copyBtn.closest('.section');
      if (!section) return;
      const text = Array.from(section.querySelectorAll('.item'))
        .map(item => item.textContent.trim())
        .filter(Boolean)
        .join('\n');
      copyToClipboard(text, event.clientX, event.clientY);
      return;
    }

    const copyUrlBtn = target.closest('.copy-url-btn');
    if (copyUrlBtn) {
      const section = copyUrlBtn.closest('.section');
      const wrapper = section?.querySelector('.content-wrapper');
      const sectionId = wrapper?.className.split(' ')[1] || '';
      const items = Array.from(section?.querySelectorAll('.item') || []);
      getCurrentTab().then(tab => {
        if (!tab?.url) return;
        const baseUrl = new URL(tab.url).origin;
        const currentUrl = new URL(tab.url);
        const urls = items.map(item => {
          const value = item.textContent.trim();
          if (sectionId === 'absolute-api-list') {
            return `${baseUrl}${value}`;
          }
          if (sectionId === 'api-list') {
            try {
              return new URL(value, currentUrl.href).href;
            } catch {
              const currentDir = currentUrl.pathname.substring(0, currentUrl.pathname.lastIndexOf('/'));
              return `${baseUrl}${currentDir}/${value}`;
            }
          }
          return value;
        }).filter(Boolean).join('\n');
        copyToClipboard(urls, event.clientX, event.clientY);
      });
      return;
    }

    const item = target.closest('.item');
    if (!item) return;
    const source = String(item.dataset.source || '').trim();
    if (!source) return;

    if (event.ctrlKey || event.metaKey) {
      event.preventDefault();
      const safeSource = sanitizeNavigationTarget(source);
      if (!safeSource) {
        showCopyTooltip('已拦截危险链接', event.clientX, event.clientY);
        return;
      }
      if (item.dataset.type === 'route-list') {
        getCurrentTab().then(tab => {
          if (!tab?.id) return;
          const frameHint = String(item.dataset.frameId || currentFrameId || '0');
          const targetFrameId = Number.parseInt(frameHint, 10);
          if (Number.isInteger(targetFrameId) && targetFrameId > 0) {
            chrome.tabs.sendMessage(tab.id, { type: 'UPDATE_ROUTE', route: safeSource }, { frameId: targetFrameId }, () => {
              if (chrome.runtime.lastError) {
                showCopyTooltip('子frame跳转失败', event.clientX, event.clientY);
                return;
              }
              showCopyTooltip('已在子frame跳转路由', event.clientX, event.clientY);
            });
            return;
          }
          chrome.tabs.update(tab.id, { url: safeSource }, () => {
            showCopyTooltip('已跳转路由', event.clientX, event.clientY);
          });
        });
        return;
      }
      chrome.tabs.create({ url: safeSource });
      showCopyTooltip('已在新标签页打开', event.clientX, event.clientY);
      return;
    }
    copyToClipboard(source, event.clientX, event.clientY);
  });

  container.addEventListener('contextmenu', (event) => {
    const target = event.target instanceof Element ? event.target.closest('.item') : null;
    if (!target) return;
    event.preventDefault();
    copyToClipboard(target.textContent.trim(), event.clientX, event.clientY);
  });
}
function displayResults(results, options = {}) {
  ensureScannerEventDelegation();

  const { isInIframe = false, forceReset = false } = options;
  const sections = getScannerSections(results);
  const container = document.querySelector('.scanner-page .container');
  if (!container) return;

  const hasShrink = sections.some(({ id, data }) => {
    const prev = renderedCounts.get(id) || 0;
    const next = Array.isArray(data) ? data.length : 0;
    return next < prev;
  });
  if (forceReset || renderedFrameId !== currentFrameId || hasShrink) {
    resetScannerRenderState(true);
  }
  renderedFrameId = currentFrameId;

  let hasResults = false;
  sections.forEach(({ id, data, title, hasUrlCopy }) => {
    if (!Array.isArray(data) || data.length === 0) return;
    hasResults = true;

    let wrapper = sectionContainers.get(id);
    const previousCount = renderedCounts.get(id) || 0;
    if (!wrapper) {
      const section = document.createElement('div');
      section.className = 'section';
      section.dataset.sectionId = id;

      const header = document.createElement('div');
      header.className = 'section-header';

      const titleWrapper = document.createElement('div');
      titleWrapper.className = 'title-wrapper';

      const titleEl = document.createElement('span');
      titleEl.className = 'title';
      titleEl.textContent = title;
      const countEl = document.createElement('span');
      countEl.className = 'count';
      countEl.textContent = `(${data.length})`;
      titleWrapper.append(titleEl, countEl);

      const buttonGroup = document.createElement('div');
      buttonGroup.className = 'button-group';

      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.title = '复制全部';
      copyBtn.type = 'button';
      copyBtn.innerHTML = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>复制全部';
      buttonGroup.appendChild(copyBtn);

      if (hasUrlCopy) {
        const copyUrlBtn = document.createElement('button');
        copyUrlBtn.className = 'copy-url-btn';
        copyUrlBtn.title = '复制URL';
        copyUrlBtn.type = 'button';
        copyUrlBtn.innerHTML = '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z"/></svg>复制URL';
        buttonGroup.appendChild(copyUrlBtn);
      }

      header.append(titleWrapper, buttonGroup);
      const sectionContent = document.createElement('div');
      sectionContent.className = 'section-content';
      wrapper = document.createElement('div');
      wrapper.className = `content-wrapper ${id}`;
      sectionContent.appendChild(wrapper);
      section.append(header, sectionContent);
      const sectionOrder = sections.findIndex(item => item.id === id);
      const existingSections = Array.from(container.querySelectorAll('.section'));
      let inserted = false;
      for (const existing of existingSections) {
        const existingId = existing.dataset.sectionId || '';
        const existingOrder = sections.findIndex(item => item.id === existingId);
        if (existingOrder > sectionOrder) {
          container.insertBefore(section, existing);
          inserted = true;
          break;
        }
      }
      if (!inserted) {
        container.appendChild(section);
      }
      sectionContainers.set(id, wrapper);
    }

    if (data.length > previousCount) {
      const fragment = document.createDocumentFragment();
      data.slice(previousCount).forEach((item) => {
        const value = Array.isArray(item) ? item[0] : item;
        const source = Array.isArray(item) ? item[1] : '';
        const textValue = String(value ?? '').trim();
        if (!textValue) return;

        const node = document.createElement('div');
        node.className = 'item';
        node.textContent = textValue;
        node.dataset.type = id;
        node.dataset.isiniframe = isInIframe ? 'true' : 'false';
        node.dataset.frameId = currentFrameId;

        const sourceText = String(source ?? '').trim();
        if (sourceText) {
          node.dataset.source = sourceText;
          node.title = `来源: ${sourceText}`;
        } else {
          node.title = '来源: 未提供';
        }
        fragment.appendChild(node);
      });
      wrapper.appendChild(fragment);
      renderedCounts.set(id, data.length);
    }

    const countEl = wrapper.closest('.section')?.querySelector('.count');
    if (countEl) {
      countEl.textContent = `(${data.length})`;
    }
  });

  const empty = container.querySelector('.no-results');
  if (!hasResults && sectionContainers.size === 0) {
    if (!empty) {
      const emptyEl = document.createElement('div');
      emptyEl.className = 'no-results';
      emptyEl.textContent = '未发现敏感信息';
      container.appendChild(emptyEl);
    }
  } else if (empty) {
    empty.remove();
  }
}

// 复制文本到剪贴板
async function copyToClipboard(text, x, y) {
  try {
    await navigator.clipboard.writeText(text);
    showCopyTooltip('复制成功', x, y);
  } catch (err) {
    showCopyTooltip('复制失败', x, y);
  }
}

// 显示复制成功提示
function showCopyTooltip(text, x, y) {
  const tooltip = document.createElement('div');
  tooltip.className = 'copy-tooltip';
  tooltip.textContent = text;
  tooltip.style.left = `${x}px`;
  tooltip.style.top = `${y}px`;
  document.body.appendChild(tooltip);
  
  setTimeout(() => tooltip.remove(), 1500);
}
function sanitizeNavigationTarget(url) {
  const target = String(url || '').trim();
  if (!target) return '';
  if (/^(javascript|data|vbscript):/i.test(target)) {
    return '';
  }
  return target;
}
function cacheLatestResults(results) {
  if (!results || typeof results !== 'object') return;
  latestScanResults = results;
}
function scheduleScannerRender(results, options = {}) {
  if (!results || typeof results !== 'object') return;
  pendingScannerRender = { results, options };
  const isScannerPage = document.querySelector('.nav-tab.active')?.dataset.page === 'scanner';
  if (!isScannerPage && !options.forceRenderWhenHidden) return;
  if (scannerRenderTimeout) return;

  const now = Date.now();
  const elapsed = now - scannerLastRenderAt;
  const delay = elapsed >= SCANNER_RENDER_THROTTLE_MS ? 0 : (SCANNER_RENDER_THROTTLE_MS - elapsed);
  scannerRenderTimeout = window.setTimeout(() => {
    scannerRenderTimeout = null;
    if (!pendingScannerRender) return;
    const payload = pendingScannerRender;
    pendingScannerRender = null;
    displayResults(payload.results, payload.options || {});
    scannerLastRenderAt = Date.now();
  }, delay);
}
function updateFrameNavigationUI() {
  const frameBar = document.querySelector('.frame-nav-bar');
  const frameList = document.querySelector('.frame-nav-left');
  const scannerPage = document.querySelector('.scanner-page');
  if (!frameBar || !frameList || !scannerPage) return;

  const frameIds = Object.keys(frameResults);
  if (frameIds.length <= 1) {
    frameBar.style.display = 'none';
    scannerPage.classList.remove('with-frame-nav');
    frameList.innerHTML = '';
    return;
  }

  frameBar.style.display = 'flex';
  scannerPage.classList.add('with-frame-nav');
  frameList.innerHTML = '';
  frameIds
    .sort((a, b) => (a === '0' ? -1 : (b === '0' ? 1 : a.localeCompare(b))))
    .forEach((frameId, idx) => {
      const data = frameResults[frameId] || {};
      let label = `frame ${idx}`;
      try {
        const url = new URL(data.frameUrl || '');
        label = `${url.hostname}${url.port ? `:${url.port}` : ''}`;
      } catch {}
      const button = document.createElement('button');
      button.className = 'frame-nav-tab';
      if (frameId === '0') {
        button.classList.add('main-frame');
      }
      button.dataset.frameId = frameId;
      button.textContent = frameId === '0' ? (label || '主页面') : label;
      button.title = button.textContent;
      button.classList.toggle('active', frameId === currentFrameId);
      frameList.appendChild(button);
    });
}
function switchFrame(frameId) {
  const targetId = String(frameId || '0');
  if (!frameResults[targetId]) return;
  currentFrameId = targetId;
  updateFrameNavigationUI();
  resetScannerRenderState(true);
  const target = frameResults[targetId];
  scheduleScannerRender(target.results || {}, {
    isInIframe: Boolean(target.isInIframe),
    forceReset: true,
    forceRenderWhenHidden: true
  });
  updateProgress(target?.results?.progress?.[0]?.[1] || 0);
}
function storeFrameResults(message = {}) {
  const frameId = String(message.frameId ?? '0');
  const frameEntry = {
    results: message.results || {},
    isInIframe: Boolean(message.isInIframe),
    frameUrl: String(message.frameUrl || '')
  };
  frameResults[frameId] = frameEntry;
  if (!frameResults[currentFrameId]) {
    currentFrameId = frameId;
  }
  if (frameId === '0') {
    cacheLatestResults(frameEntry.results);
    updateProgress(frameEntry.results?.progress?.[0]?.[1] || 0);
  }
  updateFrameNavigationUI();

  if (frameId === currentFrameId) {
    scheduleScannerRender(frameEntry.results, { isInIframe: frameEntry.isInIframe });
  }
}
function requestFrameResults(tab, frameId, frameUrl = '', isInIframe = false) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS', tabId: tab.id, from: 'popup' }, { frameId }, (response) => {
      if (chrome.runtime.lastError || !response) {
        resolve(false);
        return;
      }
      storeFrameResults({
        tabId: tab.id,
        frameId: String(frameId),
        frameUrl,
        isInIframe,
        results: response
      });
      resolve(true);
    });
  });
}
async function requestAllFrameResults(tab) {
  if (!tab?.id) return;
  frameResults['0'] = frameResults['0'] || { results: {}, isInIframe: false, frameUrl: tab.url || '' };
  const hasWebNav = chrome.webNavigation && typeof chrome.webNavigation.getAllFrames === 'function';
  if (!hasWebNav) {
    await requestFrameResults(tab, 0, tab.url || '', false);
    return;
  }
  await new Promise((resolve) => {
    chrome.webNavigation.getAllFrames({ tabId: tab.id }, (frames) => {
      if (chrome.runtime.lastError || !Array.isArray(frames) || !frames.length) {
        requestFrameResults(tab, 0, tab.url || '', false).finally(() => resolve());
        return;
      }
      const tasks = frames.map((frame) => requestFrameResults(
        tab,
        frame.frameId,
        frame.url || '',
        frame.frameId !== 0
      ));
      Promise.all(tasks).finally(() => resolve());
    });
  });
}
function handleFrameNavClick(e) {
  const button = e.target.closest('.frame-nav-tab');
  if (!button?.dataset.frameId) return;
  switchFrame(button.dataset.frameId);
}
function normalizeDebugEntries(rawEntries = []) {
  if (!Array.isArray(rawEntries)) return [];
  return rawEntries.map((entry) => {
    if (Array.isArray(entry)) {
      return [String(entry[0] || '-'), String(entry[1] || '-')];
    }
    return [String(entry || '-'), '-'];
  });
}
function createDebugBlock(title, entries = []) {
  const block = document.createElement('div');
  block.className = 'debug-block';

  const heading = document.createElement('div');
  heading.className = 'debug-block-title';
  heading.textContent = `${title} (${entries.length})`;
  block.appendChild(heading);

  const list = document.createElement('div');
  list.className = 'debug-list';
  entries.forEach(([key, value]) => {
    const item = document.createElement('div');
    item.className = 'debug-item';

    const keyEl = document.createElement('div');
    keyEl.className = 'debug-key';
    keyEl.textContent = key;

    const valueEl = document.createElement('div');
    valueEl.className = 'debug-value';
    valueEl.textContent = value || '-';

    item.append(keyEl, valueEl);
    list.appendChild(item);
  });
  block.appendChild(list);
  return block;
}
function renderDebugPage(results = {}) {
  const panel = document.getElementById('debugPanel');
  if (!panel) return;
  panel.textContent = '';

  const sections = [
    { key: 'debugSummary', title: '扫描概要', limit: 120 },
    { key: 'debugDiscoveredJs', title: '发现JS', limit: 400 },
    { key: 'debugFetchedJs', title: '抓取成功JS', limit: 400 },
    { key: 'debugFetchFailedJs', title: '抓取失败/跳过JS', limit: 400 },
    { key: 'debugDomxssCandidates', title: 'DOMXSS候选Sink', limit: 120 },
    { key: 'debugSourceInference', title: 'Source推断记录', limit: 120 },
    { key: 'debugDomxssFiltered', title: 'DOMXSS过滤原因', limit: 120 },
    { key: 'debugDomxssTrace', title: 'DOMXSS最终报告链路', limit: 120 }
  ];
  let hasAnyData = false;
  sections.forEach((section) => {
    const entries = normalizeDebugEntries(results?.[section.key]).slice(-section.limit);
    if (!entries.length) return;
    hasAnyData = true;
    panel.appendChild(createDebugBlock(section.title, entries));
  });

  if (!hasAnyData) {
    const empty = document.createElement('div');
    empty.className = 'no-results';
    empty.textContent = '暂无调试数据，请先在目标页面触发扫描。';
    panel.appendChild(empty);
  }
}
function formatDebugExport(results = {}) {
  const sectionDefs = [
    ['debugSummary', '扫描概要'],
    ['debugDiscoveredJs', '发现JS'],
    ['debugFetchedJs', '抓取成功JS'],
    ['debugFetchFailedJs', '抓取失败/跳过JS'],
    ['debugDomxssCandidates', 'DOMXSS候选Sink'],
    ['debugSourceInference', 'Source推断记录'],
    ['debugDomxssFiltered', 'DOMXSS过滤原因'],
    ['debugDomxssTrace', 'DOMXSS最终报告链路']
  ];
  const parts = [];
  sectionDefs.forEach(([key, title]) => {
    const entries = normalizeDebugEntries(results?.[key]);
    if (!entries.length) return;
    parts.push(`## ${title}`);
    entries.forEach(([k, v]) => {
      parts.push(`${k}\t${v}`);
    });
    parts.push('');
  });
  return parts.join('\n').trim();
}
async function requestCurrentTabResults() {
  const tab = await getCurrentTab();
  if (!tab?.id) {
    return { error: '未找到目标页面', results: null };
  }
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tab.id, { type: 'GET_RESULTS', tabId: tab.id, from: 'popup' }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message || '无法连接到页面', results: null });
        return;
      }
      resolve({ error: '', results: response || null });
    });
  });
}
async function initDebugPage() {
  const panel = document.getElementById('debugPanel');
  if (latestScanResults) {
    renderDebugPage(latestScanResults);
  } else {
    if (panel) {
      panel.innerHTML = '<div class="loading">正在加载调试信息...</div>';
    }
  }
  const result = await requestCurrentTabResults();
  if (result.error || !result.results) {
    if (panel && !latestScanResults) {
      panel.textContent = '';
      const errorEl = document.createElement('div');
      errorEl.className = 'error';
      errorEl.textContent = result.error || '暂无调试信息';
      panel.appendChild(errorEl);
    }
    return;
  }
  cacheLatestResults(result.results);
  renderDebugPage(result.results);
}
async function handleRefreshDebug(e) {
  const panel = document.getElementById('debugPanel');
  if (panel) {
    panel.innerHTML = '<div class="loading">正在刷新调试信息...</div>';
  }
  const result = await requestCurrentTabResults();
  if (result.error || !result.results) {
    if (panel) {
      panel.textContent = '';
      const errorEl = document.createElement('div');
      errorEl.className = 'error';
      errorEl.textContent = result.error || '刷新失败';
      panel.appendChild(errorEl);
    }
    showCopyTooltip('调试数据刷新失败', e?.clientX || 180, e?.clientY || 80);
    return;
  }
  cacheLatestResults(result.results);
  renderDebugPage(result.results);
  showCopyTooltip('调试数据已刷新', e?.clientX || 180, e?.clientY || 80);
}
function handleCopyDebug(e) {
  if (!latestScanResults) {
    showCopyTooltip('暂无调试数据', e.clientX, e.clientY);
    return;
  }
  const text = formatDebugExport(latestScanResults);
  if (!text) {
    showCopyTooltip('暂无可复制内容', e.clientX, e.clientY);
    return;
  }
  copyToClipboard(text, e.clientX, e.clientY);
}

// 页面加载完成时的初始化
document.addEventListener('DOMContentLoaded', () => {
  if (isStandaloneView) {
    document.body.classList.add('full-tab');
  }
  const initialPage = getInitialPage();
  setActiveNav(initialPage);
  switchPage(initialPage);

  // 初始化扫描页面
  const container = document.querySelector('.scanner-page .container');
  container.innerHTML = '<div class="loading">正在扫描...</div>';

  getCurrentTab().then(tab => {
    if (tab) {
      tabId = tab.id;
      const hostname = new URL(tab.url).hostname.toLowerCase();
      // 先检查自定义白名单
      checkIfWhitelisted(hostname, async (isWhitelisted) => {
        if (isWhitelisted) {
          container.innerHTML = '<div class="whitelisted">当前域名在白名单中，已跳过扫描</div>';
          updateProgress(100);
          return;
        }

        resetScannerRenderState(true);
        Object.keys(frameResults).forEach((key) => delete frameResults[key]);
        currentFrameId = '0';

        await requestAllFrameResults(tab);
        updateFrameNavigationUI();
        const activeFrame = frameResults[currentFrameId] || frameResults['0'];
        if (!activeFrame?.results || !Object.keys(activeFrame.results).length) {
          container.innerHTML = '<div class="no-results">暂无扫描结果</div>';
          updateProgress(0);
          return;
        }
        scheduleScannerRender(activeFrame.results, {
          isInIframe: Boolean(activeFrame.isInIframe),
          forceReset: true,
          forceRenderWhenHidden: true
        });
        if (document.querySelector('.nav-tab.active')?.dataset.page === 'debug' && frameResults['0']?.results) {
          renderDebugPage(frameResults['0'].results);
        }
        updateProgress(activeFrame.results?.progress?.[0]?.[1] || 0);
      });
    }
  });

  initConfigPage();
  initEventListeners();
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeReportDetail();
    }
  });
});

// 更新进度显示
function updateProgress(percent) {
  const progressTab = document.querySelector('.progress-tab');
  if (progressTab) {
    progressTab.textContent = `${percent}%`;
  }
}

// 监听来自 content script 的消息
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'SCAN_UPDATE' && message.tabId === tabId) {
    if (message.results) {
      storeFrameResults(message);
      if (document.querySelector('.nav-tab.active')?.dataset.page === 'debug' && String(message.frameId ?? '0') === '0') {
        renderDebugPage(message.results);
      }
    }
  }
});

// 初始化配置页面
function initConfigPage() {
  // 获取扫描设置和自定义白名单
  chrome.storage.local.get(['dynamicScan', 'deepScan', 'customWhitelist', 'aiReviewConfig'], (result) => {
    const dynamicScanCheckbox = document.getElementById('dynamicScan');
    const deepScanCheckbox = document.getElementById('deepScan');
    const whitelistInput = document.getElementById('whitelistInput');
    
    if (dynamicScanCheckbox) {
      dynamicScanCheckbox.checked = result.dynamicScan === true;
    }
    if (deepScanCheckbox) {
      deepScanCheckbox.checked = result.deepScan === true;
    }
    
    // 显示自定义白名单
    if (whitelistInput && result.customWhitelist) {
      whitelistInput.value = result.customWhitelist.join('\n');
    }

    const aiConfig = result.aiReviewConfig || {};
    const provider = aiConfig.provider || 'local';
    const defaults = AI_PROVIDER_DEFAULTS[provider] || AI_PROVIDER_DEFAULTS.codex;

    const providerSelect = document.getElementById('aiProvider');
    const endpointInput = document.getElementById('aiEndpoint');
    const modelInput = document.getElementById('aiModel');
    const keyInput = document.getElementById('aiApiKey');
    const temperatureInput = document.getElementById('aiTemperature');
    const maxTokensInput = document.getElementById('aiMaxTokens');

    if (providerSelect) providerSelect.value = provider;
    if (endpointInput) endpointInput.value = aiConfig.endpoint || defaults.endpoint;
    if (modelInput) modelInput.value = aiConfig.model || defaults.model;
    if (keyInput) keyInput.value = aiConfig.apiKey || '';
    if (temperatureInput) temperatureInput.value = String(aiConfig.temperature ?? 0.2);
    if (maxTokensInput) maxTokensInput.value = String(aiConfig.maxTokens ?? 1200);
    toggleAiRemoteFields(provider);
  });
}
function toggleAiRemoteFields(provider) {
  const isLocal = provider === 'local';
  ['aiEndpoint', 'aiModel', 'aiApiKey', 'aiTemperature', 'aiMaxTokens'].forEach((id) => {
    const input = document.getElementById(id);
    if (!input) return;
    input.disabled = isLocal;
    input.classList.toggle('ai-input-disabled', isLocal);
  });
}
function handleAiProviderChange(e) {
  const provider = e.target.value;
  const defaults = AI_PROVIDER_DEFAULTS[provider] || AI_PROVIDER_DEFAULTS.codex;
  const endpointInput = document.getElementById('aiEndpoint');
  const modelInput = document.getElementById('aiModel');
  const keyInput = document.getElementById('aiApiKey');
  const temperatureInput = document.getElementById('aiTemperature');
  const maxTokensInput = document.getElementById('aiMaxTokens');
  if (!endpointInput || !modelInput || !keyInput || !temperatureInput || !maxTokensInput) return;

  if (provider === 'local') {
    endpointInput.value = '';
    keyInput.value = '';
    modelInput.value = defaults.model;
    temperatureInput.value = '0.2';
    maxTokensInput.value = '1200';
  } else {
    endpointInput.value = defaults.endpoint;
    modelInput.value = defaults.model;
  }
  toggleAiRemoteFields(provider);
}
function saveAiConfig(e) {
  const provider = document.getElementById('aiProvider')?.value || 'local';
  const endpoint = document.getElementById('aiEndpoint')?.value?.trim() || '';
  const model = document.getElementById('aiModel')?.value?.trim() || '';
  const apiKey = document.getElementById('aiApiKey')?.value?.trim() || '';
  const temperatureValue = Number.parseFloat(document.getElementById('aiTemperature')?.value || '0.2');
  const maxTokensValue = Number.parseInt(document.getElementById('aiMaxTokens')?.value || '1200', 10);
  const temperature = Number.isFinite(temperatureValue) ? Math.min(1, Math.max(0, temperatureValue)) : 0.2;
  const maxTokens = Number.isFinite(maxTokensValue) ? Math.min(4096, Math.max(100, maxTokensValue)) : 1200;

  if (provider !== 'local' && (!endpoint || !model || !apiKey)) {
    showCopyTooltip('请完整填写 AI 配置', e.clientX, e.clientY);
    return;
  }

  chrome.storage.local.set({
    aiReviewConfig: {
      provider,
      endpoint: provider === 'local' ? '' : endpoint,
      model: model || (AI_PROVIDER_DEFAULTS[provider]?.model || ''),
      apiKey: provider === 'local' ? '' : apiKey,
      temperature,
      maxTokens
    }
  }, () => {
    showCopyTooltip('AI配置已保存', e.clientX, e.clientY);
  });
}
function formatReportTime(time) {
  if (!time) return '未知时间';
  const date = new Date(time);
  if (Number.isNaN(date.getTime())) return '未知时间';
  return date.toLocaleString();
}
function normalizeSeverity(severity = 'medium') {
  if (typeof REPORT_UTILS.normalizeSeverity === 'function') {
    return REPORT_UTILS.normalizeSeverity(severity, {
      allowed: REPORT_SEVERITY_LEVELS,
      fallback: 'medium'
    });
  }
  const safeSeverity = String(severity || 'medium').toLowerCase();
  const allowed = new Set(REPORT_SEVERITY_LEVELS);
  return allowed.has(safeSeverity) ? safeSeverity : 'medium';
}
function normalizeSeverityFilter(filter = 'all') {
  const safeFilter = String(filter || 'all').toLowerCase();
  return REPORT_SEVERITY_FILTERS.has(safeFilter) ? safeFilter : 'all';
}
function getFilteredVulnReports(reports = cachedVulnReports) {
  const safeReports = Array.isArray(reports) ? reports : [];
  const severityFilter = normalizeSeverityFilter(activeReportSeverityFilter);
  if (severityFilter === 'all') {
    return safeReports;
  }
  return safeReports.filter(report => normalizeSeverity(report?.severity) === severityFilter);
}
function syncSelectedReportIdsWithCache() {
  if (!selectedReportIds.size) return;
  const validIds = new Set(
    (Array.isArray(cachedVulnReports) ? cachedVulnReports : [])
      .map(report => String(report?.id || '').trim())
      .filter(Boolean)
  );
  selectedReportIds.forEach((reportId) => {
    if (!validIds.has(reportId)) {
      selectedReportIds.delete(reportId);
    }
  });
}
function getSelectedVulnReports() {
  if (!selectedReportIds.size) return [];
  return cachedVulnReports.filter(report => selectedReportIds.has(String(report?.id || '').trim()));
}
function updateReportBatchToolbar(reports = getFilteredVulnReports(cachedVulnReports)) {
  const safeReports = Array.isArray(reports) ? reports : [];
  const selectedCountEl = document.getElementById('selectedReportsCount');
  const selectAllBtn = document.getElementById('toggleSelectAllReports');
  const batchExportBtn = document.getElementById('batchExportReports');
  const batchDeleteBtn = document.getElementById('batchDeleteReports');
  const filterSelect = document.getElementById('reportSeverityFilter');
  const visibleIds = safeReports
    .map(report => String(report?.id || '').trim())
    .filter(Boolean);
  const selectedVisibleCount = visibleIds.filter(id => selectedReportIds.has(id)).length;
  const selectedTotalCount = selectedReportIds.size;
  const allVisibleSelected = visibleIds.length > 0 && selectedVisibleCount === visibleIds.length;

  if (selectedCountEl) {
    selectedCountEl.textContent = `已选 ${selectedTotalCount} 条`;
  }
  if (selectAllBtn) {
    selectAllBtn.disabled = visibleIds.length === 0;
    selectAllBtn.textContent = allVisibleSelected ? '取消全选' : '全选';
  }
  if (batchExportBtn) {
    batchExportBtn.disabled = selectedTotalCount === 0;
  }
  if (batchDeleteBtn) {
    batchDeleteBtn.disabled = selectedTotalCount === 0;
  }
  if (filterSelect && filterSelect.value !== activeReportSeverityFilter) {
    filterSelect.value = activeReportSeverityFilter;
  }
}
function renderCurrentVulnReports() {
  renderVulnReports(getFilteredVulnReports(cachedVulnReports));
}
function renderVulnReports(reports = []) {
  const list = document.querySelector('.report-list');
  if (!list) return;
  list.textContent = '';
  if (!reports.length) {
    const empty = document.createElement('div');
    empty.className = 'no-results';
    if (cachedVulnReports.length > 0 && activeReportSeverityFilter !== 'all') {
      empty.textContent = '当前筛选条件下暂无漏洞报告';
    } else {
      empty.textContent = '暂无漏洞报告';
    }
    list.appendChild(empty);
    updateReportBatchToolbar(reports);
    return;
  }

  const fragment = document.createDocumentFragment();
  reports.forEach((report) => {
    const item = document.createElement('div');
    item.className = 'report-item';
    const reportId = String(report?.id || '').trim();
    if (reportId) {
      item.dataset.reportId = reportId;
    }
    const source = String(report?.source || '');
    if (source) {
      item.dataset.source = source;
    }

    const head = document.createElement('div');
    head.className = 'report-head';

    const severity = normalizeSeverity(report?.severity);
    const severityTag = document.createElement('span');
    severityTag.className = `severity-tag ${severity}`;
    severityTag.textContent = severity.toUpperCase();

    const title = document.createElement('span');
    title.className = 'report-title';
    title.textContent = report?.title || '未命名漏洞';

    const selectWrap = document.createElement('label');
    selectWrap.className = 'report-select-wrap';

    const selectCheckbox = document.createElement('input');
    selectCheckbox.className = 'report-select-checkbox';
    selectCheckbox.type = 'checkbox';
    selectCheckbox.title = '选择该漏洞';
    if (reportId) {
      selectCheckbox.dataset.reportId = reportId;
      const checked = selectedReportIds.has(reportId);
      selectCheckbox.checked = checked;
      item.classList.toggle('selected', checked);
    } else {
      selectCheckbox.disabled = true;
    }
    selectWrap.appendChild(selectCheckbox);

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'report-delete-btn';
    deleteBtn.type = 'button';
    deleteBtn.textContent = '删除';
    deleteBtn.title = '删除该漏洞';
    if (reportId) {
      deleteBtn.dataset.reportId = reportId;
    } else {
      deleteBtn.disabled = true;
    }

    head.append(selectWrap, severityTag, title, deleteBtn);

    const meta = document.createElement('div');
    meta.className = 'report-meta';
    meta.textContent = `${report?.category || 'GENERIC'} · ${formatReportTime(report?.detectedAt)}`;

    const sourceEl = document.createElement('div');
    sourceEl.className = 'report-source';
    sourceEl.textContent = report?.source || report?.pageUrl || '未知来源';

    item.append(head, meta, sourceEl);
    fragment.appendChild(item);
  });
  list.appendChild(fragment);
  updateReportBatchToolbar(reports);
}
function loadVulnReports() {
  const list = document.querySelector('.report-list');
  if (list) {
    list.innerHTML = '<div class="loading">正在加载漏洞报告...</div>';
  }
  chrome.runtime.sendMessage({
    type: 'GET_VULN_REPORTS',
    from: 'popup',
    to: 'background'
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      if (list) {
        list.innerHTML = '<div class="error">漏洞报告加载失败</div>';
      }
      updateReportBatchToolbar([]);
      return;
    }
    cachedVulnReports = Array.isArray(response.reports) ? response.reports : [];
    syncSelectedReportIdsWithCache();
    renderCurrentVulnReports();
  });
}
function initReportPage() {
  activeReportSeverityFilter = normalizeSeverityFilter(activeReportSeverityFilter);
  const filterSelect = document.getElementById('reportSeverityFilter');
  if (filterSelect) {
    filterSelect.value = activeReportSeverityFilter;
  }
  updateReportBatchToolbar([]);
  loadVulnReports();
}
function handleRefreshReports() {
  loadVulnReports();
}
function handleClearReports(e) {
  chrome.runtime.sendMessage({
    type: 'CLEAR_VULN_REPORTS',
    from: 'popup',
    to: 'background'
  }, (response) => {
    if (response?.success) {
      cachedVulnReports = [];
      selectedReportIds.clear();
      renderCurrentVulnReports();
      closeReportDetail();
      showCopyTooltip('已清空', e?.clientX || 160, e?.clientY || 60);
      return;
    }
    showCopyTooltip('清空失败', e?.clientX || 160, e?.clientY || 60);
  });
}
function handleReportSeverityFilterChange(e) {
  activeReportSeverityFilter = normalizeSeverityFilter(e.target?.value || 'all');
  renderCurrentVulnReports();
}
function handleReportSelectChange(e) {
  const checkbox = e.target?.closest('.report-select-checkbox');
  if (!checkbox) return;
  const reportId = String(checkbox.dataset.reportId || '').trim();
  if (!reportId) return;
  if (checkbox.checked) {
    selectedReportIds.add(reportId);
  } else {
    selectedReportIds.delete(reportId);
  }
  const reportItem = checkbox.closest('.report-item');
  if (reportItem) {
    reportItem.classList.toggle('selected', checkbox.checked);
  }
  updateReportBatchToolbar(getFilteredVulnReports(cachedVulnReports));
}
function handleToggleSelectAllReports(e) {
  const filteredReports = getFilteredVulnReports(cachedVulnReports);
  if (!filteredReports.length) {
    showCopyTooltip('当前筛选无可选报告', e?.clientX || 180, e?.clientY || 80);
    return;
  }
  const visibleIds = filteredReports
    .map(report => String(report?.id || '').trim())
    .filter(Boolean);
  const allSelected = visibleIds.every(id => selectedReportIds.has(id));
  if (allSelected) {
    visibleIds.forEach(id => selectedReportIds.delete(id));
    showCopyTooltip('已取消全选', e?.clientX || 180, e?.clientY || 80);
  } else {
    visibleIds.forEach(id => selectedReportIds.add(id));
    showCopyTooltip(`已选中 ${visibleIds.length} 条`, e?.clientX || 180, e?.clientY || 80);
  }
  renderVulnReports(filteredReports);
}
function handleBatchDeleteReports(e) {
  const selectedReports = getSelectedVulnReports();
  const tipX = e?.clientX || 180;
  const tipY = e?.clientY || 80;
  if (!selectedReports.length) {
    showCopyTooltip('请先选择要删除的漏洞', tipX, tipY);
    return;
  }
  if (!window.confirm(`确认删除已选中的 ${selectedReports.length} 条漏洞吗？`)) {
    return;
  }
  const reportIds = selectedReports
    .map(report => String(report?.id || '').trim())
    .filter(Boolean);
  if (!reportIds.length) {
    showCopyTooltip('未找到可删除ID', tipX, tipY);
    return;
  }
  chrome.runtime.sendMessage({
    type: 'DELETE_VULN_REPORTS',
    from: 'popup',
    to: 'background',
    reportIds
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      showCopyTooltip('批量删除失败', tipX, tipY);
      return;
    }
    const removedSet = new Set(reportIds);
    cachedVulnReports = cachedVulnReports.filter(report => !removedSet.has(String(report?.id || '').trim()));
    reportIds.forEach(id => selectedReportIds.delete(id));
    if (removedSet.has(String(selectedReport?.id || '').trim())) {
      closeReportDetail();
    }
    renderCurrentVulnReports();
    const deleted = Number.isFinite(response?.deleted) ? Number(response.deleted) : reportIds.length;
    showCopyTooltip(`已删除 ${deleted} 条`, tipX, tipY);
  });
}
function handleCopyReports(e) {
  if (!cachedVulnReports.length) {
    showCopyTooltip('暂无可复制报告', e.clientX, e.clientY);
    return;
  }
  const text = cachedVulnReports.map((report, idx) => {
    return [
      `#${idx + 1}`,
      `时间: ${formatReportTime(report.detectedAt)}`,
      `等级: ${(report.severity || 'medium').toUpperCase()}`,
      `类型: ${report.category || 'GENERIC'}`,
      `标题: ${report.title || '未命名漏洞'}`,
      `来源: ${report.source || report.pageUrl || '未知来源'}`,
      `Source点: ${report.sourcePoint || '未明确'}${report.sourceParam ? ` (param=${report.sourceParam})` : ''}`,
      `Sink点: ${report.sinkPoint || '未明确'}`,
      `链路: ${report.sourceSinkChain || '-'}`,
      ''
    ].join('\n');
  }).join('\n');
  copyToClipboard(text, e.clientX, e.clientY);
}
function formatExportFileTime(time = Date.now()) {
  const date = new Date(time);
  const pad = value => String(value).padStart(2, '0');
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}_${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}
function buildVulnReportsExportPayload(reports = [], options = {}) {
  const scope = options.scope || 'all';
  const severityFilter = normalizeSeverityFilter(options.severityFilter || 'all');
  const safeReports = (Array.isArray(reports) ? reports : []).map((report) => ({
    ...report,
    evidence: ''
  }));
  return {
    meta: {
      tool: 'SnowEyesPlus',
      exportedAt: new Date().toISOString(),
      total: safeReports.length,
      scope,
      severityFilter
    },
    reports: safeReports
  };
}
function triggerFileDownload(filename, content, mimeType = 'application/json;charset=utf-8') {
  const blob = new Blob([content], { type: mimeType });
  const blobUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = filename;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1200);
}
function exportReportCollection(reports = [], filenamePrefix, options = {}, tipX = 180, tipY = 80) {
  if (!reports.length) {
    showCopyTooltip('暂无可导出报告', tipX, tipY);
    return false;
  }
  try {
    const payload = buildVulnReportsExportPayload(reports, options);
    const content = JSON.stringify(payload, null, 2);
    const filename = `${filenamePrefix}_${formatExportFileTime()}.json`;
    triggerFileDownload(filename, content);
    showCopyTooltip(`已导出 ${reports.length} 条`, tipX, tipY);
    return true;
  } catch (error) {
    showCopyTooltip('导出失败', tipX, tipY);
    return false;
  }
}
function handleExportReports(e) {
  const tipX = e?.clientX || 180;
  const tipY = e?.clientY || 80;
  chrome.runtime.sendMessage({
    type: 'GET_VULN_REPORTS',
    from: 'popup',
    to: 'background'
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      showCopyTooltip('导出失败', tipX, tipY);
      return;
    }

    const reports = Array.isArray(response.reports) ? response.reports : [];
    cachedVulnReports = reports;
    syncSelectedReportIdsWithCache();
    renderCurrentVulnReports();
    exportReportCollection(reports, 'snoweyes_vuln_reports', {
      scope: 'all',
      severityFilter: activeReportSeverityFilter
    }, tipX, tipY);
  });
}
function handleBatchExportReports(e) {
  const tipX = e?.clientX || 180;
  const tipY = e?.clientY || 80;
  const selectedReports = getSelectedVulnReports();
  exportReportCollection(selectedReports, 'snoweyes_vuln_reports_selected', {
    scope: 'selected',
    severityFilter: activeReportSeverityFilter
  }, tipX, tipY);
}
function handleDeleteReport(e) {
  const deleteBtn = e.target?.closest('.report-delete-btn');
  if (!deleteBtn) return;
  e.preventDefault();
  e.stopPropagation();

  const reportId = String(deleteBtn.dataset.reportId || '').trim();
  const tipX = e?.clientX || 180;
  const tipY = e?.clientY || 80;
  if (!reportId) {
    showCopyTooltip('无效报告ID', tipX, tipY);
    return;
  }

  const report = getReportById(reportId);
  const reportTitle = report?.title || '该漏洞';
  if (!window.confirm(`确认删除「${reportTitle}」吗？`)) {
    return;
  }

  chrome.runtime.sendMessage({
    type: 'DELETE_VULN_REPORT',
    from: 'popup',
    to: 'background',
    reportId
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      showCopyTooltip('删除失败', tipX, tipY);
      return;
    }

    cachedVulnReports = cachedVulnReports.filter(item => String(item?.id || '').trim() !== reportId);
    selectedReportIds.delete(reportId);
    renderCurrentVulnReports();
    if (String(selectedReport?.id || '').trim() === reportId) {
      closeReportDetail();
    }
    showCopyTooltip('已删除', tipX, tipY);
  });
}
function getReportById(reportId) {
  if (!reportId) return null;
  const targetId = String(reportId).trim();
  return cachedVulnReports.find(report => String(report?.id || '').trim() === targetId) || null;
}
function getDomXssExpTemplate(report) {
  const sink = (report.sinkPoint || '').toLowerCase();
  const source = String(report.sourcePoint || '');
  const sourceParam = String(report.sourceParam || '').trim() || 'xss';
  const payload = `"><svg/onload=alert(document.domain)>`;

  if (sink.includes('eval') || sink.includes('function') || sink.includes('settimeout') || sink.includes('setinterval')) {
    return `示例EXP（代码执行型）:\nalert(document.domain)\n\n建议验证:\n1. 将用户可控参数传入该 Sink。\n2. 观察是否触发脚本执行。`;
  }
  if (sink.includes('href') || sink.includes('location')) {
    return `示例EXP（链接型）:\njavascript:alert(document.domain)\n\n建议验证:\n1. 注入到可控链接参数。\n2. 点击触发后确认是否执行。`;
  }
  if (source.includes('location.hash')) {
    return `示例EXP（Hash场景）:\n${window.location.origin}${window.location.pathname}#${encodeURIComponent(payload)}\n\n建议验证:\n1. 访问上述URL。\n2. 检查是否写入危险 Sink 并执行。`;
  }
  if (source.includes('location.search') || source.includes('query')) {
    const targetUrl = new URL(window.location.href);
    targetUrl.searchParams.set(sourceParam, payload);
    return `示例EXP（Query场景）:\n${targetUrl.toString()}\n\n建议验证:\n1. 访问上述URL。\n2. 观察参数是否流入危险 Sink。`;
  }
  return `示例EXP（HTML注入型）:\n${payload}\n\n建议验证:\n1. 将 payload 注入 Source。\n2. 观察 Sink 渲染后是否执行。`;
}
function getDomXssChainTemplate(report = {}) {
  const source = String(report.sourcePoint || '未明确');
  const sink = String(report.sinkPoint || '未明确');
  return [
    `SOURCE: ${source}`,
    `SINK: ${sink}`
  ].join('\n');
}
function setDetailText(id, value) {
  const element = document.getElementById(id);
  if (!element) return;
  element.textContent = value || '-';
}
function getAiSessionId(report) {
  if (!report?.id) return '';
  return `report_${String(report.id).slice(0, 120)}`;
}
function renderAiAgentConversation(messages = [], metaText = '') {
  const panel = document.getElementById('aiAgentConversation');
  if (!panel) return;
  const safeMessages = Array.isArray(messages) ? messages : [];
  if (!safeMessages.length) {
    panel.textContent = metaText || '可在这里持续对话调试：source/sink链路、PoC失败原因、下一步验证动作。';
    return;
  }
  const lines = [];
  if (metaText) {
    lines.push(metaText, '');
  }
  safeMessages.slice(-16).forEach((item) => {
    const role = item?.role === 'assistant' ? 'AI' : '你';
    const content = String(item?.content || '').trim();
    if (!content) return;
    lines.push(`[${role}] ${content}`);
  });
  panel.textContent = lines.join('\n\n');
  panel.scrollTop = panel.scrollHeight;
}
function loadAiAgentSession(report) {
  currentAiSessionId = getAiSessionId(report);
  const input = document.getElementById('aiAgentInput');
  if (input) {
    input.value = '';
  }
  if (!currentAiSessionId) {
    renderAiAgentConversation([]);
    return;
  }
  renderAiAgentConversation([], 'AI会话加载中...');
  chrome.runtime.sendMessage({
    type: 'AI_AGENT_GET_SESSION',
    from: 'popup',
    to: 'background',
    sessionId: currentAiSessionId
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      renderAiAgentConversation([], `加载会话失败: ${response?.message || chrome.runtime.lastError?.message || 'unknown error'}`);
      return;
    }
    renderAiAgentConversation(response.messages || []);
  });
}
function openReportDetail(report) {
  selectedReport = report;
  const mask = document.getElementById('reportDetailMask');
  const severityTag = document.getElementById('detailSeverityTag');
  const consoleAssistBtn = document.getElementById('runDomxssConsoleAssist');
  const copyConsoleBtn = document.getElementById('copyDomxssConsoleScript');
  const pocBtn = document.getElementById('triggerXssPoc');
  if (!mask || !severityTag) return;

  const severity = normalizeSeverity(report.severity);
  severityTag.textContent = severity.toUpperCase();
  severityTag.className = `severity-tag ${severity}`;

  setDetailText('detailTitle', report.title || '未命名漏洞');
  setDetailText('detailCategory', report.category || 'GENERIC');
  setDetailText('detailTime', formatReportTime(report.detectedAt));
  setDetailText('detailSourceUrl', report.source || '-');
  setDetailText('detailPageUrl', report.pageUrl || '-');
  const sourcePointText = String(report.sourcePoint || '未提供');
  const sourceParam = String(report.sourceParam || '').trim();
  const sourceDisplay = sourceParam && !sourcePointText.includes(`(${sourceParam})`)
    ? `${sourcePointText} (${sourceParam})`
    : sourcePointText;
  setDetailText('detailSourcePoint', sourceDisplay);
  setDetailText('detailSinkPoint', report.sinkPoint || '未提供');
  setDetailText('detailSourceSinkChain', report.sourceSinkChain || getDomXssChainTemplate(report));
  setDetailText('detailAdvice', report.advice || '-');
  setDetailText('detailExp', report.exp || (report.category === 'DOM_XSS' ? getDomXssExpTemplate(report) : '暂无通用EXP。'));
  setDetailText('pocResult', '建议先点击“Console验证助手（动态验证）”；该模式默认使用无执行标记 payload，仅验证 source 是否流入 sink。');
  setDetailText('aiReviewResult', '点击“开始研判”生成结果。');
  loadAiAgentSession(report);

  const canTrigger = report.category === 'DOM_XSS';
  if (consoleAssistBtn) {
    consoleAssistBtn.disabled = !canTrigger;
    consoleAssistBtn.title = canTrigger ? '' : '仅DOM_XSS支持Console验证助手';
  }
  if (copyConsoleBtn) {
    copyConsoleBtn.disabled = !canTrigger;
    copyConsoleBtn.title = canTrigger ? '' : '仅DOM_XSS支持Console脚本生成';
  }
  if (pocBtn) {
    pocBtn.disabled = !canTrigger;
    pocBtn.title = canTrigger ? '会改写URL并主动注入参数，请谨慎使用' : '仅DOM_XSS支持自动触发';
  }

  mask.classList.add('active');
}
function closeReportDetail() {
  const mask = document.getElementById('reportDetailMask');
  if (mask) {
    mask.classList.remove('active');
  }
  selectedReport = null;
  currentAiSessionId = '';
}
function handleReportDetailMaskClick(e) {
  if (e.target?.id === 'reportDetailMask') {
    closeReportDetail();
  }
}
function runAiFalsePositiveReview(report) {
  const reasons = [];
  let score = 0;
  const severity = String(report.severity || 'medium').toLowerCase();

  if (report.category === 'DOM_XSS') {
    if (report.sourcePoint && !/未知|未明确/.test(report.sourcePoint)) {
      score += 3;
      reasons.push('存在明确 Source 点。');
    } else {
      score -= 1;
      reasons.push('缺少明确 Source 点，可信度下降。');
    }
    if (report.sinkPoint) {
      score += 2;
      reasons.push('存在危险 Sink 点。');
    }
    if (report.hasSanitizer) {
      score -= 3;
      reasons.push('检测到净化迹象，可能为误报。');
    }
    if (severity === 'high') {
      score += 1;
    }
  }

  let verdict = '需人工复核';
  if (score >= 3) verdict = '疑似真实漏洞';
  if (score <= 0) verdict = '疑似误报';
  const confidence = Math.min(95, Math.max(55, 65 + score * 7));

  return {
    verdict,
    confidence,
    reasons
  };
}
function buildLocalAiReviewOutput(fallback = {}, options = {}) {
  const lines = [];
  if (options.modelLabel) {
    lines.push(`模型: ${options.modelLabel}`);
  }
  if (options.header) {
    lines.push(options.header);
  }
  if (options.error) {
    lines.push(`错误: ${options.error}`, '');
  }
  lines.push(
    `结论: ${fallback.verdict || '需人工复核'}`,
    `置信度: ${fallback.confidence ?? '-'}%`,
    '依据:',
    ...(Array.isArray(fallback.reasons) && fallback.reasons.length
      ? fallback.reasons.map((reason, index) => `${index + 1}. ${reason}`)
      : ['1. 本地规则未返回依据'])
  );
  return lines.join('\n');
}
function handleRunAiReview() {
  if (!selectedReport) return;
  setDetailText('aiReviewResult', 'AI分析中，请稍候...');
  chrome.storage.local.get(['aiReviewConfig'], (storage) => {
    const aiConfig = storage.aiReviewConfig || {};
    const provider = aiConfig.provider || 'local';
    if (provider === 'local') {
      const fallback = runAiFalsePositiveReview(selectedReport);
      const output = buildLocalAiReviewOutput(fallback, { modelLabel: '本地启发式判定' });
      setDetailText('aiReviewResult', output);
      return;
    }

    chrome.runtime.sendMessage({
      type: 'AI_REVIEW_REPORT',
      from: 'popup',
      to: 'background',
      report: selectedReport
    }, (response) => {
      if (chrome.runtime.lastError || !response?.success) {
        const fallback = runAiFalsePositiveReview(selectedReport);
        const output = buildLocalAiReviewOutput(fallback, {
          header: '远程AI分析失败，已切换本地研判',
          error: response?.message || chrome.runtime.lastError?.message || 'unknown error'
        });
        setDetailText('aiReviewResult', output);
        return;
      }

      const review = response.review || {};
      const reasons = Array.isArray(review.reasons) ? review.reasons : [];
      const output = [
        `模型: ${response.provider || '-'} / ${response.model || '-'}`,
        `结论: ${review.verdict || '需人工复核'}`,
        `置信度: ${review.confidence ?? '-'}%`,
        review.isFalsePositive === true ? '判定: 疑似误报' : (review.isFalsePositive === false ? '判定: 疑似真实漏洞' : '判定: 未明确'),
        '',
        '依据:',
        ...(reasons.length ? reasons.map((reason, index) => `${index + 1}. ${reason}`) : ['1. 模型未返回详细依据']),
        '',
        `补充建议: ${review.recommendation || '请结合人工审计进一步确认。'}`
      ].join('\n');
      setDetailText('aiReviewResult', output);
    });
  });
}
function handleSendAiAgent() {
  if (!selectedReport || !currentAiSessionId) return;
  const input = document.getElementById('aiAgentInput');
  if (!input) return;
  const message = String(input.value || '').trim();
  if (!message) {
    showCopyTooltip('请输入问题后再发送', 200, 120);
    return;
  }

  const sendBtn = document.getElementById('sendAiAgent');
  if (sendBtn) {
    sendBtn.disabled = true;
  }
  renderAiAgentConversation([], 'AI思考中，请稍候...');

  chrome.runtime.sendMessage({
    type: 'AI_AGENT_CHAT',
    from: 'popup',
    to: 'background',
    sessionId: currentAiSessionId,
    report: selectedReport,
    message
  }, (response) => {
    if (sendBtn) {
      sendBtn.disabled = false;
    }
    if (chrome.runtime.lastError || !response?.success) {
      renderAiAgentConversation([], `AI会话失败: ${response?.message || chrome.runtime.lastError?.message || 'unknown error'}`);
      return;
    }
    input.value = '';
    const modelInfo = `模型: ${response.provider || '-'} / ${response.model || '-'}`;
    renderAiAgentConversation(response.messages || [], modelInfo);
  });
}
function handleClearAiAgent(e) {
  if (!currentAiSessionId) return;
  chrome.runtime.sendMessage({
    type: 'AI_AGENT_CLEAR_SESSION',
    from: 'popup',
    to: 'background',
    sessionId: currentAiSessionId
  }, (response) => {
    if (response?.success) {
      renderAiAgentConversation([]);
      const input = document.getElementById('aiAgentInput');
      if (input) {
        input.value = '';
      }
      showCopyTooltip('AI会话已清空', e?.clientX || 160, e?.clientY || 60);
      return;
    }
    showCopyTooltip('清空会话失败', e?.clientX || 160, e?.clientY || 60);
  });
}
function handleAiAgentInputKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    handleSendAiAgent();
  }
}
function handleReportItemClick(e) {
  if (e.target?.closest('.report-delete-btn')) {
    return;
  }
  if (e.target?.closest('.report-select-wrap') || e.target?.closest('.report-select-checkbox')) {
    return;
  }
  const reportItem = e.target.closest('.report-item');
  if (!reportItem) return;
  const report = getReportById(reportItem.dataset.reportId);
  if (!report) return;
  const source = report.source || report.pageUrl || '';
  if (e.ctrlKey || e.metaKey) {
    const safeSource = sanitizeNavigationTarget(source);
    if (safeSource) {
      chrome.tabs.create({ url: safeSource });
      showCopyTooltip('已在新标签页打开', e.clientX, e.clientY);
    } else {
      showCopyTooltip('已拦截危险链接', e.clientX, e.clientY);
    }
  } else {
    openReportDetail(report);
  }
}
async function handleOpenStandalone(e) {
  const targetTab = await getCurrentTab();
  if (!targetTab?.id) {
    showCopyTooltip('未找到目标页面', e.clientX, e.clientY);
    return;
  }
  const activePage = document.querySelector('.nav-tab.active')?.dataset.page || 'scanner';
  const dashboardUrl = chrome.runtime.getURL(`popup.html?view=tab&tabId=${targetTab.id}&page=${activePage}`);
  chrome.tabs.create({ url: dashboardUrl });
}
function buildConsoleAssistOutput(response = {}) {
  const reasons = Array.isArray(response.reasons) ? response.reasons : [];
  const details = response.details || {};
  const scriptPreview = response.consoleScript
    ? String(response.consoleScript).split('\n').slice(0, 10).join('\n')
    : String(response.consoleScriptPreview || '').trim();
  const lines = [
    `模式: Console验证助手(动态验证)`,
    `结论: ${response.verdictText || '需人工复核'}`,
    `风险标签: ${response.riskTag || '-'}`,
    `验证Payload(无执行): ${response.payload || '-'}`,
    `Payload依据: ${response.payloadReason || '-'}`,
    response.exploitPayload ? `利用Payload(参考): ${response.exploitPayload}` : '',
    `说明: ${response.message || '-'}`,
    ''
  ].filter(Boolean);
  if (reasons.length) {
    lines.push('依据:');
    reasons.forEach((reason, index) => {
      lines.push(`${index + 1}. ${reason}`);
    });
    lines.push('');
  }
  if (response.recommendation) {
    lines.push(`下一步: ${response.recommendation}`);
  }
  if (details.sinkSnippet) {
    lines.push('', 'Sink片段:');
    lines.push(details.sinkSnippet);
  }
  if (Array.isArray(details.attempts) && details.attempts.length) {
    lines.push('', '动态尝试:');
    details.attempts.forEach((attempt, index) => {
      const status = attempt?.sinkHit ? '命中sink' : (attempt?.payloadReflected ? '已反射未命中sink' : '未命中');
      const action = attempt?.actionResult
        ? ` [typed:${attempt.actionResult.typedCount ?? 0}, trigger:${attempt.actionResult.triggerAction || 'none'}]`
        : '';
      const invoked = Array.isArray(attempt?.invokedHandlers) && attempt.invokedHandlers.length
        ? ` [invoke:${attempt.invokedHandlers.join(', ')}]`
        : '';
      lines.push(`${index + 1}. ${attempt?.note || attempt?.type || 'candidate'} -> ${status}${action}${invoked}`);
    });
  }
  if (typeof details.sourceFileLoaded === 'boolean') {
    lines.push('', `Source文件加载状态: ${details.sourceFileLoaded ? '已加载' : '未加载'}`);
  }
  if (scriptPreview) {
    lines.push('', 'Console脚本预览:');
    lines.push(scriptPreview);
    lines.push('', '提示: 仅展示前10行。点击“复制Console脚本”可获取完整脚本。');
  }
  return lines.join('\n');
}
async function handleRunDomxssConsoleAssist() {
  if (!selectedReport) return;
  if (selectedReport.category !== 'DOM_XSS') {
    setDetailText('pocResult', '当前报告类型不是 DOM_XSS，暂不支持 Console 验证助手。');
    return;
  }
  const targetTab = await getCurrentTab();
  if (!targetTab?.id) {
    setDetailText('pocResult', '未找到目标页面，无法执行 Console 验证。');
    return;
  }
  setDetailText('pocResult', '正在执行 Console 验证助手（动态尝试参数/路由并监控 sink）...');
  chrome.runtime.sendMessage({
    type: 'RUN_DOMXSS_CONSOLE_ASSIST',
    from: 'popup',
    to: 'background',
    tabId: targetTab.id,
    report: selectedReport
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      setDetailText('pocResult', `Console验证失败: ${response?.message || chrome.runtime.lastError?.message || 'unknown error'}`);
      return;
    }
    setDetailText('pocResult', buildConsoleAssistOutput(response));
  });
}
async function handleCopyDomxssConsoleScript(e) {
  if (!selectedReport) return;
  if (selectedReport.category !== 'DOM_XSS') {
    showCopyTooltip('当前报告不是 DOM_XSS', e?.clientX || 180, e?.clientY || 80);
    return;
  }
  const targetTab = await getCurrentTab();
  if (!targetTab?.id) {
    showCopyTooltip('未找到目标页面', e?.clientX || 180, e?.clientY || 80);
    return;
  }
  chrome.runtime.sendMessage({
    type: 'GET_DOMXSS_CONSOLE_SCRIPT',
    from: 'popup',
    to: 'background',
    tabId: targetTab.id,
    report: selectedReport
  }, async (response) => {
    if (chrome.runtime.lastError || !response?.success || !response?.script) {
      showCopyTooltip('脚本生成失败', e?.clientX || 180, e?.clientY || 80);
      return;
    }
    await copyToClipboard(response.script, e?.clientX || 180, e?.clientY || 80);
    const preview = String(response.script || '').split('\n').slice(0, 10).join('\n');
    setDetailText('pocResult', [
      '已复制 Console 调试脚本（完整）到剪贴板，可直接粘贴到 DevTools Console 执行。',
      '',
      '脚本预览:',
      preview,
      '',
      '提示: 仅展示前10行，完整脚本已在剪贴板。'
    ].join('\n'));
  });
}
async function handleTriggerXssPoc() {
  if (!selectedReport) return;
  if (selectedReport.category !== 'DOM_XSS') {
    setDetailText('pocResult', '当前报告类型不是 DOM_XSS，暂不支持自动触发。');
    return;
  }
  const targetTab = await getCurrentTab();
  if (!targetTab?.id) {
    setDetailText('pocResult', '未找到目标页面，无法复现。');
    return;
  }
  setDetailText('pocResult', '正在触发PoC（主动注入，可能改写URL），请稍候...');
  chrome.runtime.sendMessage({
    type: 'TRIGGER_XSS_POC',
    from: 'popup',
    to: 'background',
    tabId: targetTab.id,
    report: selectedReport
  }, (response) => {
    if (chrome.runtime.lastError || !response?.success) {
      setDetailText('pocResult', `触发失败: ${response?.message || chrome.runtime.lastError?.message || 'unknown error'}`);
      return;
    }
    const output = [
      `状态: ${response.status || '已执行'}`,
      `方式: ${response.method || 'unknown'}`,
      `验证Payload(无执行): ${response.payload || '-'}`,
      `Payload依据: ${response.payloadReason || '-'}`,
      response.exploitPayload ? `利用Payload(参考): ${response.exploitPayload}` : '',
      response.exploitReason ? `利用依据: ${response.exploitReason}` : '',
      `说明: ${response.message || '-'}`,
      response.url ? `URL: ${response.url}` : '',
      response.details?.hash ? `Hash: ${response.details.hash}` : '',
      response.details?.lessonSnippet ? `Sink片段: ${response.details.lessonSnippet}` : ''
    ].filter(Boolean).join('\n');
    setDetailText('pocResult', output);
  });
}

// 更新服务器指纹信息
function normalizeClassToken(value, fallback = 'unknown') {
  const safeValue = String(value || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
  return safeValue || fallback;
}
function updateServerFingerprints(fingerprints = {}) {
  const fingerprintSection = document.querySelector('.fingerprint-section');
  if (!fingerprintSection) return;
  fingerprintSection.textContent = '';
  
  // 检查是否有任何指纹
  let hasFingerprints = false;
  for (const type in fingerprints) {
    if (Array.isArray(fingerprints[type]) && fingerprints[type].length > 0) {
      hasFingerprints = true;
      break;
    }
  }
  
  // 如果没有识别到任何指纹，显示提示信息
  if (!hasFingerprints) {
    const notice = document.createElement('div');
    notice.className = 'notice';
    notice.textContent = '暂未识别到指纹';
    fingerprintSection.appendChild(notice);
    return;
  }
  
  // 遍历所有指纹类型
  for (const [type, fingerprintData] of Object.entries(fingerprints)) {
    if (!Array.isArray(fingerprintData) || fingerprintData.length === 0 || type === 'nameMap') continue;
    for (const fingerprint of fingerprintData) {
      const matchedFields = Array.isArray(fingerprint.matchedFields)
        ? fingerprint.matchedFields.filter(Boolean).join(',')
        : '';
      addFingerprint(fingerprintSection, {
        type: type,
        name: fingerprint.name,
        description: fingerprint.description,
        value: fingerprint.version || '',
        source: fingerprint.source || '',
        confidence: fingerprint.confidence || '',
        score: Number(fingerprint.score || 0),
        matchedFields
      });
    }
  }
}

// 添加单个指纹组
function addFingerprint(container, info) {
  if (!container || !info) return;
  const safeType = normalizeClassToken(info.type);
  const compactMeta = shouldUseCompactFingerprintCard(info);
  const metaText = buildFingerprintMetaText(info);

  const group = document.createElement('div');
  group.className = `fingerprint-group ${safeType}-group`;

  const title = document.createElement('h3');
  title.className = 'fingerprint-title';
  const tag = document.createElement('span');
  tag.className = `tag ${safeType}-tag`;
  const typeText = String(info.type || 'unknown');
  tag.textContent = typeText ? `${typeText[0].toUpperCase()}${typeText.slice(1)}` : 'Unknown';
  title.appendChild(tag);
  const name = document.createElement('span');
  name.className = 'fingerprint-name';
  name.textContent = info.name || '-';
  title.appendChild(name);
  if (shouldShowFingerprintValue(info)) {
    const value = document.createElement('span');
    value.className = 'fingerprint-inline-value detected';
    value.textContent = String(info.value || '');
    title.appendChild(value);
  }

  const item = document.createElement('div');
  item.className = `fingerprint-item${compactMeta ? ' compact' : ''}`;

  if (!compactMeta) {
    const label = document.createElement('div');
    label.className = 'fingerprint-description';
    label.textContent = info.description == null || info.description === '' ? '-' : String(info.description);
    item.appendChild(label);
  }

  const meta = document.createElement('div');
  meta.className = 'fingerprint-meta compact-line';
  meta.textContent = metaText;
  item.appendChild(meta);
  group.append(title, item);
  container.appendChild(group);
}
function shouldUseCompactFingerprintCard(info = {}) {
  return Boolean(
    info.source ||
    info.confidence ||
    Number(info.score || 0) > 0 ||
    info.matchedFields
  );
}
function shouldShowFingerprintValue(info = {}) {
  const valueText = String(info.value || '').trim();
  const nameText = String(info.name || '').trim();
  if (!valueText) return false;
  return valueText !== nameText;
}
function buildFingerprintMetaText(info = {}) {
  const metaParts = [];
  const sourceText = String(info.source || '').trim();
  const confidenceText = String(info.confidence || '').trim();
  const scoreValue = Number(info.score || 0);
  const matchedFieldsText = String(info.matchedFields || '').trim();

  if (sourceText) metaParts.push(`来源: ${sourceText}`);
  if (confidenceText && scoreValue > 0) {
    metaParts.push(`置信度: ${confidenceText}/${scoreValue}`);
  } else if (confidenceText) {
    metaParts.push(`置信度: ${confidenceText}`);
  } else if (scoreValue > 0) {
    metaParts.push(`评分: ${scoreValue}`);
  }
  if (matchedFieldsText) metaParts.push(`字段: ${matchedFieldsText}`);
  return metaParts.length ? metaParts.join(' · ') : '-';
}

// 初始化指纹页面
function initFingerprintPage() {
  getCurrentTab().then(tab => {
    if (tab) {
      console.log('Requesting fingerprints for tab:', tab.id);
      chrome.runtime.sendMessage({
        type: 'GET_FINGERPRINTS',
        tabId: tab.id,
        from: 'popup',
        to: 'background'
      }, response => {
        console.log('Received response:', response);
        if (response) {
          updateServerFingerprints(response);
        }
      });
    }
  });
}
// 初始化网站解析页面
function initAnalysisPage() {
  const container = document.querySelector('.analysis-section');
  container.innerHTML = '<div class="loading">正在获取网站信息...</div>';
  
  let timeoutId = null;
  
  getCurrentTab().then(tab => {
    if (tab) {
      const domain = new URL(tab.url).hostname;
      timeoutId = setTimeout(() => {
        container.innerHTML = '<div class="error">请求超时，请重试</div>';
      }, 10000);

      chrome.runtime.sendMessage({
        type: 'GET_SITE_ANALYSIS',
        domain: domain,
        tabId: tab.id,
        from: 'popup',
        to: 'background'
      }, (response) => {
        clearTimeout(timeoutId);
        if (!response) {
          container.innerHTML = '<div class="error">获取网站信息失败</div>';
          return;
        }
        if (response.isPrivateIP) {
          container.innerHTML = '<div class="notice">内网地址无需解析</div>';
          return;
        }
        updateAnalysisPage(response, domain);
      });
    }
  });
  return () => {
    if (timeoutId) clearTimeout(timeoutId);
  };
}

// 更新网站解析页面内容
function updateAnalysisPage(data, domain) {
  const container = document.querySelector('.analysis-section');
  if (!container) return;
  const icpData = data?.icp || {};
  container.textContent = '';

  const basicGroup = document.createElement('div');
  basicGroup.className = 'analysis-group basic-group';
  const basicTitle = document.createElement('h3');
  basicTitle.textContent = '基本信息';
  const basicInfo = document.createElement('div');
  basicInfo.className = 'basic-info';
  basicInfo.append(
    createInfoItem('域名', icpData.domain || domain),
    createInfoItem('备案号', icpData.icp || '暂无备案信息'),
    createInfoItem('主办单位', icpData.unit || '未知'),
    createInfoItem('备案时间', icpData.time || '未知')
  );
  basicGroup.append(basicTitle, basicInfo);

  const weightGroup = document.createElement('div');
  weightGroup.className = 'analysis-group weight-group';
  const weightTitle = document.createElement('h3');
  weightTitle.textContent = '搜索引擎权重';
  const weightGrid = document.createElement('div');
  weightGrid.className = 'weight-grid';
  weightGroup.append(weightTitle, weightGrid);

  const ipGroup = document.createElement('div');
  ipGroup.className = 'analysis-group ip-group';
  const ipTitle = document.createElement('h3');
  ipTitle.textContent = 'IP信息';
  const ipInfo = document.createElement('div');
  ipInfo.className = 'ip-info';
  ipGroup.append(ipTitle, ipInfo);

  container.append(basicGroup, weightGroup, ipGroup);
  
  // 更新权重信息
  if (data.weight) {
    const weightData = data.weight.data;
    updateWeightInfo(weightData);
  }

  // 更新IP信息
  if (data.ip) {
    const ipData = data.ip.data;
    updateIpInfo(ipData);
  }
}

// 创建文档碎片批量更新
function updateElementsWithFragment(container, elements) {
  const fragment = document.createDocumentFragment();
  elements.forEach(element => fragment.appendChild(element));
  container.textContent = '';
  container.appendChild(fragment);
}
function createInfoItem(label, value) {
  const item = document.createElement('div');
  item.className = 'info-item';

  const labelEl = document.createElement('span');
  labelEl.className = 'info-label';
  labelEl.textContent = label;

  const valueEl = document.createElement('span');
  valueEl.className = 'info-value';
  valueEl.textContent = value == null || value === '' ? '无' : String(value);

  item.append(labelEl, valueEl);
  return item;
}

// 修改updateWeightInfo函数
function updateWeightInfo(weightData) {
  const container = document.querySelector('.weight-grid');
  
  if (weightData?.error) {
    container.textContent = weightData.error;
    return;
  }

  const elements = searchEngines.map(engine => {
    const element = document.createElement('div');
    element.className = 'weight-item';
    
    // 直接使用原始值
    const rawValue = weightData[engine.id] || 'n';
    
    const displayValue = rawValue;
    const imgValue = rawValue;

    const img = document.createElement('img');
    img.className = 'weight-img';
    img.dataset.engine = engine.id;
    img.dataset.src = `https://api.mir6.com/data/quanzhong_img/${engine.id}/${imgValue}.png`;
    img.alt = engine.name;

    const label = document.createElement('span');
    label.className = 'weight-label';
    label.textContent = engine.name;

    const valueSpan = document.createElement('span');
    valueSpan.className = 'weight-value';
    valueSpan.textContent = displayValue;

    element.append(img, label, valueSpan);
    
    // 立即加载图片
    const tempImg = new Image();
    tempImg.src = img.dataset.src;
    
    tempImg.onload = () => {
      img.src = tempImg.src;
      img.classList.add('loaded');
    };
    
    tempImg.onerror = () => {
      img.src = `https://api.mir6.com/data/quanzhong_img/${engine.id}/0.png`;
      img.classList.add('loaded');
    };

    return element;
  });

  updateElementsWithFragment(container, elements);
}

// 更新IP信息
function updateIpInfo(ipData) {
  const ipInfo = document.querySelector('.ip-info');
  if (!ipInfo) return;
  const data = ipData || {};
  const items = [
    ['IPv4/6', data.ip || '无'],
    ['地理位置', data.location || '无'],
    ['邮政编码', data.zipcode || '无'],
    ['运营商', data.isp || '无'],
    ['协议', data.protocol || '无'],
    ['网络类型', data.net || '无']
  ];

  const fragment = document.createDocumentFragment();
  items.forEach(([label, value]) => {
    fragment.appendChild(createInfoItem(label, value));
  });
  ipInfo.textContent = '';
  ipInfo.appendChild(fragment);
}

// 统一事件管理
const eventListeners = {
  'click .nav-tab': handleNavClick,
  'click .frame-nav-tab': handleFrameNavClick,
  'change #dynamicScan': handleDynamicScan,
  'change #deepScan': handleDeepScan,
  'change #aiProvider': handleAiProviderChange,
  'error .weight-img': handleImageError,
  'click #saveWhitelist': saveWhitelist,
  'click #saveAiConfig': saveAiConfig,
  'click #openStandalone': handleOpenStandalone,
  'click #refreshReports': handleRefreshReports,
  'click #copyReports': handleCopyReports,
  'click #exportReports': handleExportReports,
  'click #toggleSelectAllReports': handleToggleSelectAllReports,
  'click #batchExportReports': handleBatchExportReports,
  'click #batchDeleteReports': handleBatchDeleteReports,
  'click #clearReports': handleClearReports,
  'click #refreshDebug': handleRefreshDebug,
  'click #copyDebug': handleCopyDebug,
  'change #reportSeverityFilter': handleReportSeverityFilterChange,
  'change .report-select-checkbox': handleReportSelectChange,
  'click .report-delete-btn': handleDeleteReport,
  'click .report-item': handleReportItemClick,
  'click #closeReportDetail': closeReportDetail,
  'click #runDomxssConsoleAssist': handleRunDomxssConsoleAssist,
  'click #copyDomxssConsoleScript': handleCopyDomxssConsoleScript,
  'click #triggerXssPoc': handleTriggerXssPoc,
  'click #runAiReview': handleRunAiReview,
  'click #sendAiAgent': handleSendAiAgent,
  'click #clearAiAgent': handleClearAiAgent,
  'keydown #aiAgentInput': handleAiAgentInputKeydown,
  'click #reportDetailMask': handleReportDetailMaskClick
};

function initEventListeners() {
  Object.entries(eventListeners).forEach(([eventKey, handler]) => {
    const [event, selector] = eventKey.split(' ');
    document.body.addEventListener(event, e => {
      if (!selector) {
        handler(e);
        return;
      }
      if (!(e.target instanceof Element)) {
        return;
      }
      if (e.target.matches(selector) || e.target.closest(selector)) {
        handler(e);
      }
    });
  });
}

// 统一使用handleNavClick处理页面切换
function handleNavClick(e) {
  const tab = e.target.closest('.nav-tab');
  if (tab) {
    const pageName = tab.dataset.page;
    switchPage(pageName);
    if (isStandaloneView) {
      const newUrl = new URL(window.location.href);
      newUrl.searchParams.set('page', pageName);
      window.history.replaceState({}, '', newUrl.toString());
    }
  }
}

// 添加通用的标签页查询函数
async function getCurrentTab() {
  if (isStandaloneView && Number.isInteger(forcedTabId) && forcedTabId > 0) {
    try {
      const tab = await chrome.tabs.get(forcedTabId);
      tabId = tab.id;
      return tab;
    } catch (e) {
      console.warn('获取指定目标Tab失败:', e);
    }
  }
  const tabs = await chrome.tabs.query({active: true, currentWindow: true});
  const extensionBase = chrome.runtime.getURL('');
  const targetTab = tabs.find(tab => tab?.url && !tab.url.startsWith(extensionBase)) || tabs[0] || null;
  if (targetTab?.id) {
    tabId = targetTab.id;
  }
  return targetTab;
}

// 修改使用标签页查询的函数
function handleDynamicScan(e) {
  const enabled = e.target.checked;
  chrome.storage.local.set({ dynamicScan: enabled });
  
  getCurrentTab().then(tab => {
    if (tab) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'UPDATE_DYNAMIC_SCAN',
        enabled: enabled
      });
    }
  });
}

function handleDeepScan(e) {
  const enabled = e.target.checked;
  chrome.storage.local.set({ deepScan: enabled });
  
  getCurrentTab().then(tab => {
    if (tab) {
      chrome.tabs.sendMessage(tab.id, {
        type: 'UPDATE_DEEP_SCAN',
        enabled: enabled
      });
    }
  });
}

function handleImageError(e) {
  if (e.target.classList.contains('weight-img')) {
    const engine = e.target.dataset.engine;
    e.target.src = `https://api.mir6.com/data/quanzhong_img/${engine}/0.png`;
  }
}

let currentPageCleanup = null; // 添加页面清理函数存储 
