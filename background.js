import { createReportStore } from './report-store.js';
import { createAiService } from './ai-service.js';
import { createDomxssAssistService } from './domxss-assist.js';
import { createPocTriggerService } from './poc-trigger.js';
import './fingerprint-core.js';
// SnowEyesPlus: flattened from modular source
const FINGERPRINT_CORE = globalThis.SNOWEYES_FINGERPRINT || {};
const FINGERPRINT_UTILS = FINGERPRINT_CORE.utils || {};
const DEFAULT_FINGERPRINT_CONFIG = FINGERPRINT_CORE.DEFAULT_FINGERPRINT_CONFIG || {
  HEADERS: [],
  COOKIES: [],
  ANALYTICS: {},
  DESCRIPTIONS: []
};
const EXTERNAL_FINGERPRINT_LIBRARY_FILES = Array.isArray(FINGERPRINT_CORE.constants?.FINGERPRINT_LIBRARY_FILES)
  ? FINGERPRINT_CORE.constants.FINGERPRINT_LIBRARY_FILES
  : ['finger.json', 'kscan_fingerprint.json', 'webapp.json', 'apps.json'];
const EXTERNAL_FINGERPRINT_SCORE_THRESHOLD = Number(FINGERPRINT_CORE.constants?.FINGERPRINT_SCORE_THRESHOLD || 72);
const EXTERNAL_FINGERPRINT_STORE_CACHE_KEY = 'snoweyes_unified_fingerprint_store_v2';
const EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION = Number(FINGERPRINT_CORE.constants?.FINGERPRINT_RULE_CACHE_VERSION || 5);
const MAX_HEADER_MATCH_CACHE = 180;
const FINGERPRINT_TYPE_BUCKETS = Array.isArray(FINGERPRINT_CORE.constants?.TYPE_BUCKETS)
  ? FINGERPRINT_CORE.constants.TYPE_BUCKETS
  : ['server', 'component', 'technology', 'security', 'analytics', 'builder', 'framework', 'os', 'panel', 'cdn'];

let runtimeFingerprintConfig = FINGERPRINT_UTILS.createRuntimeFingerprintConfig
  ? FINGERPRINT_UTILS.createRuntimeFingerprintConfig(DEFAULT_FINGERPRINT_CONFIG)
  : DEFAULT_FINGERPRINT_CONFIG;
let analyticsPatterns = FINGERPRINT_UTILS.buildAnalyticsPatterns
  ? FINGERPRINT_UTILS.buildAnalyticsPatterns(runtimeFingerprintConfig)
  : [];
const headerMatchCache = new Map();
let externalFingerprintLibrary = null;
let externalFingerprintLibraryPromise = null;

function normalizeFingerprintType(type = '') {
  if (typeof FINGERPRINT_UTILS.normalizeFingerprintType === 'function') {
    return FINGERPRINT_UTILS.normalizeFingerprintType(type);
  }
  const safeType = String(type || '').trim().toLowerCase();
  return safeType || 'component';
}
function getTypeDescription(type = '') {
  if (typeof FINGERPRINT_UTILS.getTypeDescription === 'function') {
    return FINGERPRINT_UTILS.getTypeDescription(runtimeFingerprintConfig, type);
  }
  return '';
}
function getFingerprintConfig() {
  return runtimeFingerprintConfig;
}
async function readCachedUnifiedFingerprintStore() {
  try {
    const cache = await chrome.storage.session.get(EXTERNAL_FINGERPRINT_STORE_CACHE_KEY);
    const payload = cache?.[EXTERNAL_FINGERPRINT_STORE_CACHE_KEY];
    if (!payload || payload.version !== EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION) return null;
    const rules = payload?.normalizedStore?.rules;
    if (!Array.isArray(rules) || rules.length === 0) return null;
    return {
      normalizedStore: payload.normalizedStore,
      wappalyzerCatalog: payload.wappalyzerCatalog && typeof payload.wappalyzerCatalog === 'object'
        ? payload.wappalyzerCatalog
        : null
    };
  } catch {
    return null;
  }
}
async function writeCachedUnifiedFingerprintStore(normalizedStore, wappalyzerCatalog) {
  try {
    await chrome.storage.session.set({
      [EXTERNAL_FINGERPRINT_STORE_CACHE_KEY]: {
        version: EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION,
        normalizedStore,
        wappalyzerCatalog: wappalyzerCatalog && typeof wappalyzerCatalog === 'object' ? wappalyzerCatalog : null
      }
    });
  } catch {}
}
async function fetchFingerprintPayload(fileName = '') {
  const target = String(fileName || '').trim();
  if (!target) return null;
  try {
    const url = chrome.runtime.getURL(target);
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.warn(`[SnowEyesPlus] 指纹文件加载失败(${target}):`, error?.message || error);
    return null;
  }
}
function buildCompiledStoreFromNormalizedStore(normalizedStore = {}, wappalyzerCatalogInput = null) {
  const compiled = typeof FINGERPRINT_UTILS.compileNormalizedRuleStore === 'function'
    ? FINGERPRINT_UTILS.compileNormalizedRuleStore(normalizedStore)
    : { rules: [], stats: {} };
  const wappalyzerCatalog = (wappalyzerCatalogInput && typeof wappalyzerCatalogInput === 'object')
    ? wappalyzerCatalogInput
    : (typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
      ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog({})
      : { apps: [], categories: {} });
  return {
    ...compiled,
    normalizedRuleStore: normalizedStore,
    wappalyzerCatalog
  };
}
async function loadExternalFingerprintLibrary() {
  if (externalFingerprintLibrary) return externalFingerprintLibrary;
  if (externalFingerprintLibraryPromise) return externalFingerprintLibraryPromise;

  externalFingerprintLibraryPromise = (async () => {
    const cachedStore = await readCachedUnifiedFingerprintStore();
    let normalizedStore = cachedStore?.normalizedStore || null;
    let cachedWappalyzerCatalog = cachedStore?.wappalyzerCatalog || null;
    if (normalizedStore?.rules?.length > 0) {
      if (!cachedWappalyzerCatalog) {
        const wappPayload = await fetchFingerprintPayload('apps.json');
        cachedWappalyzerCatalog = typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
          ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog(wappPayload || {})
          : { apps: [], categories: {} };
      }
      externalFingerprintLibrary = buildCompiledStoreFromNormalizedStore(normalizedStore, cachedWappalyzerCatalog);
      console.info(`[SnowEyesPlus] 指纹库已从会话缓存恢复: rules=${externalFingerprintLibrary?.rules?.length || 0}`);
      return externalFingerprintLibrary;
    }

    const payloadMap = Object.create(null);
    await Promise.all(EXTERNAL_FINGERPRINT_LIBRARY_FILES.map(async (fileName) => {
      payloadMap[fileName] = await fetchFingerprintPayload(fileName);
    }));

    if (typeof FINGERPRINT_UTILS.buildUnifiedCompiledFingerprintStore === 'function') {
      externalFingerprintLibrary = FINGERPRINT_UTILS.buildUnifiedCompiledFingerprintStore(payloadMap);
    } else if (typeof FINGERPRINT_UTILS.buildNormalizedRuleStore === 'function') {
      normalizedStore = FINGERPRINT_UTILS.buildNormalizedRuleStore(payloadMap);
      const wappPayload = payloadMap['apps.json'] || payloadMap['wappalyzer_apps.json'] || payloadMap.wappalyzer || {};
      cachedWappalyzerCatalog = typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
        ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog(wappPayload)
        : { apps: [], categories: {} };
      externalFingerprintLibrary = buildCompiledStoreFromNormalizedStore(normalizedStore, cachedWappalyzerCatalog);
    } else {
      externalFingerprintLibrary = { rules: [], stats: {}, wappalyzerCatalog: { apps: [], categories: {} } };
    }

    if (externalFingerprintLibrary?.normalizedRuleStore?.rules?.length > 0) {
      void writeCachedUnifiedFingerprintStore(
        externalFingerprintLibrary.normalizedRuleStore,
        null
      );
    }
    console.info(
      `[SnowEyesPlus] 统一指纹库加载完成: rules=${externalFingerprintLibrary?.rules?.length || 0}, wappalyzer=${externalFingerprintLibrary?.wappalyzerCatalog?.apps?.length || 0}`
    );
    return externalFingerprintLibrary;
  })().catch((error) => {
    console.warn('[SnowEyesPlus] 统一指纹库加载失败，已回退内置模式:', error?.message || error);
    externalFingerprintLibrary = { rules: [], stats: {}, wappalyzerCatalog: { apps: [], categories: {} } };
    return externalFingerprintLibrary;
  }).finally(() => {
    externalFingerprintLibraryPromise = null;
  });

  return externalFingerprintLibraryPromise;
}
function resetBuiltinFingerprintConfig() {
  try {
    runtimeFingerprintConfig = FINGERPRINT_UTILS.createRuntimeFingerprintConfig
      ? FINGERPRINT_UTILS.createRuntimeFingerprintConfig(DEFAULT_FINGERPRINT_CONFIG)
      : DEFAULT_FINGERPRINT_CONFIG;
    analyticsPatterns = FINGERPRINT_UTILS.buildAnalyticsPatterns
      ? FINGERPRINT_UTILS.buildAnalyticsPatterns(runtimeFingerprintConfig)
      : [];
  } catch {
    runtimeFingerprintConfig = DEFAULT_FINGERPRINT_CONFIG;
    analyticsPatterns = [];
  }
}
resetBuiltinFingerprintConfig();
void loadExternalFingerprintLibrary();
const tabCountsCache = new Map();
const tabJsMap = {}
const VULN_REPORTS_KEY = 'snoweyes_vuln_reports';
const MAX_VULN_REPORTS = 500;
const AI_AGENT_SESSIONS_KEY = 'snoweyes_ai_agent_sessions';
const MAX_AI_AGENT_SESSIONS = 40;
const MAX_AI_AGENT_MESSAGES = 20;

const reportStore = createReportStore({
  chromeApi: chrome,
  storageKey: VULN_REPORTS_KEY,
  maxReports: MAX_VULN_REPORTS
});
const domxssAssistService = createDomxssAssistService({ chromeApi: chrome });
const pocTriggerService = createPocTriggerService({
  chromeApi: chrome,
  domxssAssist: domxssAssistService
});
const aiService = createAiService({
  chromeApi: chrome,
  fetchImpl: fetch,
  sessionsKey: AI_AGENT_SESSIONS_KEY,
  maxSessions: MAX_AI_AGENT_SESSIONS,
  maxMessages: MAX_AI_AGENT_MESSAGES,
  buildLocalAgentReply: (report, message) => buildLocalAgentReply(report, message)
});

function ensureTabFrameJsMap(tabId) {
  const key = String(tabId);
  if (!tabJsMap[key]) {
    tabJsMap[key] = new Map();
  }
  return tabJsMap[key];
}
function clearTabFrameJsMap(tabId) {
  const key = String(tabId);
  const frameMap = tabJsMap[key];
  if (!frameMap) return;
  frameMap.forEach((set) => set?.clear?.());
  delete tabJsMap[key];
}
function addTabFrameJs(tabId, frameId, url) {
  const frameMap = ensureTabFrameJsMap(tabId);
  const frameKey = String(frameId ?? 0);
  if (!frameMap.has(frameKey)) {
    frameMap.set(frameKey, new Set());
  }
  frameMap.get(frameKey).add(url);
}
function getTabFrameJs(tabId, frameId) {
  const frameMap = tabJsMap[String(tabId)];
  if (!frameMap) return [];
  return Array.from(frameMap.get(String(frameId ?? 0)) || []);
}

chrome.webNavigation.onCommitted.addListener(details => {
  const { tabId, frameId } = details;
  if (frameId === 0) {
    clearTabFrameJsMap(tabId);
    return;
  }
  const frameMap = tabJsMap[String(tabId)];
  if (frameMap?.has(String(frameId))) {
    frameMap.get(String(frameId)).clear();
  }
});

function setTabCount(tabId, count) {
  tabCountsCache.set(tabId, count);
  chrome.storage.session.set({ [`tab_${tabId}`]: count });
}
function getTabCount(tabId, callback) {
  if (tabCountsCache.has(tabId)) {
    callback(tabCountsCache.get(tabId));
    return;
  }
  chrome.storage.session.get(`tab_${tabId}`, (data) => {
    const count = data[`tab_${tabId}`] || 0;
    tabCountsCache.set(tabId, count);
    callback(count);
  });
}
function setBadgeUI(tabId, count) {
  const hasCount = count > 0;
  chrome.action.setBadgeText({
    text: hasCount ? String(count) : '',
    tabId
  });
  chrome.action.setBadgeBackgroundColor({
    color: hasCount ? '#4dabf7' : '#666666',
    tabId
  });
}
function updateBadge(results, tabId, frameId = '0') {
  if (String(frameId) !== '0') return;
  const fields = [
    'domains', 'absoluteApis', 'apis', 'pageRoutes', 'moduleFiles', 'docFiles', 'ips', 'phones',
    'emails', 'idcards', 'jwts', 'imageFiles', 'jsFiles', 'vueFiles', 'urls',
    'githubUrls', 'companies', 'credentials', 'cookies', 'idKeys', 'domxssVulns',
    'thirdPartyLibs', 'windowsPaths', 'iframes'
  ];

  const count = fields.reduce((acc, field) => {
    const arr = results[field];
    return acc + (Array.isArray(arr) && arr.length > 0 ? 1 : 0);
  }, 0);

  setTabCount(tabId, count);

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const activeTab = tabs?.[0];
    if (activeTab?.id === tabId) {
      setBadgeUI(tabId, count);
    }
  });
}
chrome.tabs.onActivated.addListener(({ tabId }) => {
  getTabCount(tabId, (count) => {
    setBadgeUI(tabId, count);
  });
});
chrome.tabs.onRemoved.addListener((tabId) => {
  tabCountsCache.delete(tabId);
  chrome.storage.session.remove(`tab_${tabId}`);
  chrome.storage.session.remove(`analysis_${tabId}`)
  clearTabFrameJsMap(tabId);
  Object.values(analyticsDetected).forEach(map => map.delete(tabId));
  serverFingerprints.delete(tabId);
});

async function tryFetchContent(url) {
  const response = await fetch(url, {
    headers: {
      'Accept': '*/*',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    },
    credentials: 'include'
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const content = await response.text();
  return {
    content,
    status: response.status
  };
}
async function fallbackFetchContentViaTab(tabId, url) {
  const [result] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (url) => {
      return fetch(url, { credentials: 'include' }).then(res => res.text());
    },
    args: [url]
  });

  return result?.result ?? null;
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer || new ArrayBuffer(0));
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}
async function handleFetchBinaryRequest(request, sender, sendResponse) {
  const targetUrl = String(request.url || '').trim();
  if (!targetUrl) {
    sendResponse({ success: false, message: 'url 不能为空', base64: '' });
    return;
  }
  try {
    const response = await fetch(targetUrl, {
      headers: { 'Accept': '*/*' },
      credentials: 'include'
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const buffer = await response.arrayBuffer();
    sendResponse({
      success: true,
      base64: arrayBufferToBase64(buffer),
      contentType: response.headers.get('content-type') || '',
      status: response.status
    });
  } catch (error) {
    sendResponse({
      success: false,
      message: String(error?.message || 'fetch binary failed'),
      base64: ''
    });
  }
}
function looksLikeUnexpectedHtmlForJs(url, content) {
  if (!/\.js(?:\?|$)/i.test(String(url || ''))) return false;
  const head = String(content || '').slice(0, 2500).toLowerCase();
  if (!head) return true;
  return head.includes('<!doctype') || head.includes('<html') || head.includes('<body');
}
async function handleFetchRequest(request, sender, sendResponse) {
  const targetUrl = request.url;
  const tabId = sender.tab?.id;
  const frameId = String(sender.frameId ?? request.frameId ?? 0);
  try {
    const directResult = await tryFetchContent(targetUrl);
    const content = directResult?.content || '';
    if (looksLikeUnexpectedHtmlForJs(targetUrl, content) && tabId) {
      const fallbackContent = await fallbackFetchContentViaTab(tabId, targetUrl);
      sendResponse({
        content: fallbackContent,
        frameId,
        fetchMeta: {
          method: 'tab-fallback',
          reason: 'direct-html-for-js',
          status: fallbackContent ? 'ok' : 'empty'
        }
      });
      return;
    }
    sendResponse({
      content,
      frameId,
      fetchMeta: {
        method: 'direct',
        status: 'ok',
        httpStatus: directResult?.status || 200
      }
    });
  } catch (error) {
    console.warn('Primary fetch failed:', error.message);

    if (tabId) {
      try {
        const fallbackContent = await fallbackFetchContentViaTab(tabId, targetUrl);
        sendResponse({
          content: fallbackContent,
          frameId,
          fetchMeta: {
            method: 'tab-fallback',
            reason: `direct-error:${String(error?.message || 'unknown').slice(0, 120)}`,
            status: fallbackContent ? 'ok' : 'empty'
          }
        });
      } catch (e2) {
        console.warn('Fallback fetch via tab failed:', e2.message);
        sendResponse({
          content: null,
          frameId,
          fetchMeta: {
            method: 'failed',
            reason: `direct-error:${String(error?.message || 'unknown').slice(0, 80)};fallback-error:${String(e2?.message || 'unknown').slice(0, 80)}`,
            status: 'failed'
          }
        });
      }
    } else {
      sendResponse({
        content: null,
        frameId,
        fetchMeta: {
          method: 'failed',
          reason: `direct-error:${String(error?.message || 'unknown').slice(0, 120)}`,
          status: 'failed'
        }
      });
    }
  }
}
let serverFingerprints = new Map();
const analyticsDetected = {
  baidu: new Map(),
  yahoo: new Map(),
  google: new Map(),
};
function handleAnalyticsDetection(details, type) {
  if (!analyticsDetected[type]) {
    analyticsDetected[type] = new Map();
  }
  if (analyticsDetected[type].get(details.tabId)) {
    return;
  }
  const analyticsConfig = getFingerprintConfig().ANALYTICS[type];
  if (!analyticsConfig) return;

  let fingerprints = getFingerprints(details.tabId);
  analyticsDetected[type].set(details.tabId, true);
  fingerprints.analytics.push({
    name: analyticsConfig.name,
    description: analyticsConfig.description,
    version: analyticsConfig.version
  });
  serverFingerprints.set(details.tabId, fingerprints);
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const matchedAnalytics = analyticsPatterns.find(item => item.regex.test(details.url));
    if (matchedAnalytics) {
      handleAnalyticsDetection(details, matchedAnalytics.type);
    }
    const { tabId, url, type, frameId } = details;
    if (tabId < 0) return;
    let isScriptLike = type === 'script';
    if (!isScriptLike) {
      try {
        const pathname = new URL(url).pathname;
        isScriptLike = /\.(?:js|mjs|jsx|ts|tsx)$/i.test(pathname);
      } catch {
        isScriptLike = false;
      }
    }
    if (!isScriptLike) return;
    try {
      if (details.initiator) {
        const initiatorUrl = new URL(details.initiator);
        const currentUrl = new URL(url);
        if (initiatorUrl.hostname !== currentUrl.hostname) {
          return;
        }
      }
    } catch {}
    addTabFrameJs(tabId, frameId, url);
    return;
  },
  { urls: ['<all_urls>'] },
  []
);
// 识别Cookie
function identifyTechnologyFromCookie(cookieHeader) {
  if (typeof FINGERPRINT_UTILS.identifyTechnologyFromCookie === 'function') {
    return FINGERPRINT_UTILS.identifyTechnologyFromCookie(cookieHeader, getFingerprintConfig());
  }
  return null;
}
function normalizeFingerprintNameKey(name = '') {
  return String(name || '').trim().toLowerCase();
}
function ensureFingerprintBucket(fingerprints, type = '') {
  const safeType = normalizeFingerprintType(type || 'component');
  if (!Array.isArray(fingerprints[safeType])) {
    fingerprints[safeType] = [];
  }
  return safeType;
}
function parseCookieMapFromText(source = '') {
  const map = new Map();
  String(source || '')
    .split(/[\n\r;]+/)
    .forEach((rawToken) => {
      const token = String(rawToken || '').replace(/^(?:set-cookie|cookie)\s*:/i, '').trim();
      if (!token) return;
      const equalIndex = token.indexOf('=');
      if (equalIndex > 0) {
        const key = String(token.slice(0, equalIndex) || '').trim().toLowerCase();
        if (!key || ['path', 'domain', 'expires', 'max-age', 'secure', 'httponly', 'samesite', 'priority', 'version', 'comment'].includes(key)) return;
        const value = String(token.slice(equalIndex + 1) || '').trim();
        if (!map.has(key)) {
          map.set(key, value);
        }
        return;
      }
      const key = token.toLowerCase();
      if (/^[a-z0-9_.-]{1,120}$/.test(key) && !map.has(key)) {
        map.set(key, '');
      }
    });
  return map;
}
function buildHeaderSignalInput(headers = [], requestUrl = '') {
  const headersMap = new Map();
  const headerLines = [];
  (Array.isArray(headers) ? headers : []).forEach((header) => {
    const name = String(header?.name || '').trim().toLowerCase();
    if (!name) return;
    const value = String(header?.value || '').trim();
    const prev = headersMap.get(name);
    headersMap.set(name, prev ? `${prev}; ${value}` : value);
  });
  headersMap.forEach((value, key) => {
    headerLines.push(`${key}: ${value}`);
  });
  const headerText = headerLines.join('\n');
  const cookieText = [headersMap.get('cookie') || '', headersMap.get('set-cookie') || '']
    .map(item => String(item || '').trim())
    .filter(Boolean)
    .join('\n');
  const cookiesMap = parseCookieMapFromText(cookieText);
  return {
    url: String(requestUrl || ''),
    title: '',
    body: '',
    headersMap,
    headerText,
    cookieText,
    cookiesMap,
    responseText: headerText,
    metaMap: new Map(),
    scripts: [],
    env: [],
    iconHashes: [],
    jsProbe: {}
  };
}
function buildCookieSignalInput(cookieNames = '', requestUrl = '') {
  const value = String(cookieNames || '').trim();
  const headersMap = new Map();
  if (value) {
    headersMap.set('set-cookie', value);
    headersMap.set('cookie', value);
  }
  const headerText = value ? `set-cookie: ${value}\ncookie: ${value}` : '';
  const cookiesMap = parseCookieMapFromText(value);
  return {
    url: String(requestUrl || ''),
    title: '',
    body: '',
    headersMap,
    headerText,
    cookieText: value,
    cookiesMap,
    responseText: headerText,
    metaMap: new Map(),
    scripts: [],
    env: [],
    iconHashes: [],
    jsProbe: {}
  };
}
function confidenceRank(value = '') {
  const key = String(value || '').trim().toLowerCase();
  if (key === 'high') return 3;
  if (key === 'medium') return 2;
  if (key === 'low') return 1;
  return 0;
}
function mergeUniqueStrings(a, b, limit = 20) {
  const result = [];
  const seen = new Set();
  [a, b].forEach((value) => {
    (Array.isArray(value) ? value : []).forEach((item) => {
      const text = String(item || '').trim();
      if (!text || seen.has(text)) return;
      seen.add(text);
      if (result.length < limit) result.push(text);
    });
  });
  return result;
}
function mergeUniqueEvidence(a, b, limit = 20) {
  const result = [];
  const seen = new Set();
  [a, b].forEach((value) => {
    (Array.isArray(value) ? value : []).forEach((item) => {
      const context = String(item?.context || '').trim();
      const evidenceValue = String(item?.value || '').trim();
      const signature = `${context}|${evidenceValue}`;
      if (!signature || seen.has(signature)) return;
      seen.add(signature);
      if (result.length < limit) {
        result.push({ context, value: evidenceValue });
      }
    });
  });
  return result;
}
function findFingerprintRecordByName(fingerprints, name = '') {
  const nameKey = normalizeFingerprintNameKey(name);
  if (!nameKey) return null;
  for (const bucket of FINGERPRINT_TYPE_BUCKETS) {
    const list = Array.isArray(fingerprints[bucket]) ? fingerprints[bucket] : [];
    for (let i = 0; i < list.length; i += 1) {
      const item = list[i];
      if (normalizeFingerprintNameKey(item?.name) !== nameKey) continue;
      return {
        bucket,
        index: i,
        item
      };
    }
  }
  return null;
}
function buildFingerprintDescription(payload = {}) {
  const type = normalizeFingerprintType(payload?.type || 'component');
  const name = String(payload?.name || '').trim();
  const source = String(payload?.source || 'unified-fingerprint-engine').trim();
  const confidence = String(payload?.confidence || '').trim();
  const score = Number(payload?.score || 0);
  const fields = Array.isArray(payload?.matchedFields) ? payload.matchedFields.filter(Boolean) : [];
  const description = `通过${source}识别到网站使用${name}${getTypeDescription(type)}`;
  const tails = [];
  if (confidence) tails.push(`置信度:${confidence}`);
  if (score > 0) tails.push(`评分:${score}`);
  if (fields.length) tails.push(`字段:${fields.join(',')}`);
  return tails.length ? `${description}（${tails.join('，')}）` : description;
}
function createFingerprintFromUnifiedHit(hit = {}, sourceTag = 'unified-fingerprint-engine') {
  const name = String(hit?.name || '').trim();
  if (!name) return null;
  const score = Number(hit?.score || 0);
  const confidence = String(hit?.confidence || (score >= 90 ? 'high' : score >= 75 ? 'medium' : 'low'));
  const type = normalizeFingerprintType(hit?.type || 'component');
  const payload = {
    type,
    name,
    version: String(hit?.version || name),
    source: String(hit?.source || sourceTag || 'unified-fingerprint-engine'),
    score,
    confidence,
    matchedFields: Array.isArray(hit?.matchedFields) ? hit.matchedFields.filter(Boolean) : [],
    evidence: Array.isArray(hit?.traces) ? hit.traces.slice(0, 20) : []
  };
  payload.description = buildFingerprintDescription(payload);
  return payload;
}
function upsertFingerprint(fingerprints, rawFingerprint = {}) {
  const name = String(rawFingerprint?.name || '').trim();
  if (!name) return false;
  const incoming = { ...rawFingerprint };
  const safeType = ensureFingerprintBucket(fingerprints, incoming.type || 'component');
  incoming.type = safeType;
  if (!incoming.description) {
    incoming.description = buildFingerprintDescription(incoming);
  }
  if (!incoming.version) {
    incoming.version = name;
  }
  if (!Array.isArray(incoming.matchedFields)) incoming.matchedFields = [];
  if (!Array.isArray(incoming.evidence)) incoming.evidence = [];

  const found = findFingerprintRecordByName(fingerprints, name);
  if (!found) {
    fingerprints[safeType].push(incoming);
    fingerprints.nameMap.set(name, true);
    return true;
  }

  const existing = found.item || {};
  const incomingScore = Number(incoming.score || 0);
  const existingScore = Number(existing.score || 0);
  const preferIncoming = incomingScore > existingScore ||
    (incomingScore === existingScore && confidenceRank(incoming.confidence) > confidenceRank(existing.confidence));

  const merged = {
    ...existing,
    ...(preferIncoming ? incoming : {}),
    type: preferIncoming ? safeType : normalizeFingerprintType(existing.type || safeType),
    name: String(existing.name || incoming.name || ''),
    version: preferIncoming ? (incoming.version || existing.version || name) : (existing.version || incoming.version || name),
    source: preferIncoming ? (incoming.source || existing.source || '') : (existing.source || incoming.source || ''),
    score: Math.max(existingScore, incomingScore),
    confidence: preferIncoming ? (incoming.confidence || existing.confidence || '') : (existing.confidence || incoming.confidence || ''),
    matchedFields: mergeUniqueStrings(existing.matchedFields, incoming.matchedFields, 30),
    evidence: mergeUniqueEvidence(existing.evidence, incoming.evidence, 30)
  };
  const hasScoreSignal = Number(merged.score || 0) > 0 || merged.matchedFields.length > 0;
  if (!String(merged.description || '').trim() || hasScoreSignal) {
    merged.description = buildFingerprintDescription(merged);
  }

  const targetType = ensureFingerprintBucket(fingerprints, merged.type);
  if (targetType === found.bucket) {
    fingerprints[targetType][found.index] = merged;
  } else {
    fingerprints[found.bucket].splice(found.index, 1);
    fingerprints[targetType].push(merged);
  }
  fingerprints.nameMap.set(merged.name, true);
  return true;
}
async function detectFingerprintsByUnifiedEngine(input = {}, sourceTag = 'unified-fingerprint-engine') {
  const library = await loadExternalFingerprintLibrary();
  if (typeof FINGERPRINT_UTILS.detectFingerprintsWithUnifiedStore !== 'function') {
    return [];
  }
  const hits = FINGERPRINT_UTILS.detectFingerprintsWithUnifiedStore(library, input, {
    threshold: EXTERNAL_FINGERPRINT_SCORE_THRESHOLD
  });
  return (Array.isArray(hits) ? hits : [])
    .map(hit => createFingerprintFromUnifiedHit(hit, sourceTag))
    .filter(Boolean);
}
function applyBuiltinHeaderFingerprints(headers, fingerprints) {
  if (typeof FINGERPRINT_UTILS.applyHeaderFingerprints !== 'function') {
    return fingerprints;
  }
  return FINGERPRINT_UTILS.applyHeaderFingerprints({
    headers,
    fingerprints,
    runtimeConfig: getFingerprintConfig(),
    headerMatchCache,
    maxHeaderMatchCache: MAX_HEADER_MATCH_CACHE
  });
}
// 识别Header
async function processHeaders(headers, tabId, requestUrl = '') {
  const fingerprints = getFingerprints(tabId);
  applyBuiltinHeaderFingerprints(headers, fingerprints);
  try {
    const hits = await detectFingerprintsByUnifiedEngine(buildHeaderSignalInput(headers, requestUrl), 'response-headers');
    hits.forEach((hit) => {
      upsertFingerprint(fingerprints, hit);
    });
  } catch (error) {
    console.warn('[SnowEyesPlus] Header指纹识别失败:', error?.message || error);
  }
  return fingerprints;
}
async function processCookies(cookieNames = '', tabId, requestUrl = '') {
  const fingerprints = getFingerprints(tabId);
  const techFromCookies = identifyTechnologyFromCookie(cookieNames);
  if (techFromCookies?.name) {
    upsertFingerprint(fingerprints, {
      ...techFromCookies,
      type: normalizeFingerprintType(techFromCookies.type),
      source: 'cookie'
    });
  }
  if (String(cookieNames || '').trim()) {
    try {
      const hits = await detectFingerprintsByUnifiedEngine(buildCookieSignalInput(cookieNames, requestUrl), 'cookie');
      hits.forEach((hit) => {
        upsertFingerprint(fingerprints, hit);
      });
    } catch (error) {
      console.warn('[SnowEyesPlus] Cookie指纹识别失败:', error?.message || error);
    }
  }
  return fingerprints;
}
function getFingerprints(tabId){
  if(serverFingerprints.has(tabId)){
    return serverFingerprints.get(tabId);
  }
  let fingerprints = {
    server: [],
    component: [],
    technology: [],
    security: [],
    analytics: [],
    builder: [],
    framework: [],
    os: [],
    panel: [],
    cdn: [],
    nameMap: new Map()
  };
  serverFingerprints.set(tabId, fingerprints);
  return fingerprints;
}
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return { responseHeaders: details.responseHeaders };
    if (!details.responseHeaders) return { responseHeaders: details.responseHeaders };

    setTimeout(() => {
      void (async () => {
        const fingerprints = await processHeaders(details.responseHeaders, details.tabId, details.url);
        serverFingerprints.set(details.tabId, fingerprints);
        chrome.cookies.getAll({ url: details.url }, (cookies) => {
          if (!Array.isArray(cookies) || cookies.length === 0) return;
          const cookieNames = cookies
            .map((cookie) => {
              const name = String(cookie?.name || '').trim();
              if (!name) return '';
              const value = String(cookie?.value || '').trim();
              return value ? `${name}=${value}` : name;
            })
            .filter(Boolean)
            .join(';');
          if (!cookieNames) return;
          void processCookies(cookieNames, details.tabId, details.url)
            .then((updated) => {
              serverFingerprints.set(details.tabId, updated);
            })
            .catch((error) => {
              console.warn('[SnowEyesPlus] Cookie指纹写入失败:', error?.message || error);
            });
        });
      })();
    }, 0);

    return { responseHeaders: details.responseHeaders };
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);
function performRegexMatching(chunk, patterns, patternType) {
  const matches = [];
  let maxIterations = 10000;
  
  try {
    for (const patternInfo of patterns) {
      const { pattern: patternString} = patternInfo;
      let regex;
      try {
        const match = patternString.match(/^\/(.+)\/([gimuy]*)$/);
        if (match) {
          regex = new RegExp(match[1], match[2]);
        }
      } catch (e) {
        console.error(`无效的正则表达式: ${patternString}`, e);
        continue;
      }
      let patternLastIndex = 0;
      let match;
      while ((match = regex.exec(chunk)) !== null) {
        if (regex.lastIndex <= patternLastIndex) {
          console.warn(`检测到可能的无限循环: ${patternType} Pattern - ${patternString}`);
          break;
        }
        patternLastIndex = regex.lastIndex;
        if (--maxIterations <= 0) {
          console.warn(`达到最大迭代次数: ${patternType}`);
          break;
        }
        matches.push({
          match: match[0],
        });
      }
      regex.lastIndex = 0;
    }
  } catch (e) {
    console.error(`${patternType} 匹配出错:`, e);
  }
  
  return matches;
}
function buildLocalAgentReply(report = {}, message = '') {
  const sink = String(report.sinkPoint || '').toLowerCase();
  const sourcePoint = String(report.sourcePoint || '');
  const sourceParam = domxssAssistService.extractSourceParamFromReport(report) || 'xss';
  const pageUrl = String(report.pageUrl || report.source || '');
  const hrefLike = domxssAssistService.isHrefLikeSink(report);
  const payload = domxssAssistService.pickXssPayload(report);
  let pocUrl = '';
  try {
    const url = new URL(pageUrl || 'http://localhost/');
    if (sourcePoint.toLowerCase().includes('location.hash')) {
      url.hash = `${sourceParam}=${encodeURIComponent(payload)}`;
    } else {
      url.searchParams.set(sourceParam, payload);
    }
    pocUrl = url.toString();
  } catch {}

  const steps = [
    `当前判断: ${sourcePoint || 'source 未明确'} -> ${sink || 'sink 未明确'}。`,
    hrefLike
      ? `该点更像 href 场景，优先使用 payload: ${payload}，并在注入后点击页面中的目标链接触发。`
      : `建议先用 payload: ${payload} 进行注入验证。`,
    pocUrl ? `可直接尝试URL: ${pocUrl}` : '未能生成稳定URL，请结合页面逻辑手工设置参数。',
    '如果仍未触发，请抓取目标函数完整代码（含上游变量赋值）继续追踪 taint 传播。'
  ];
  if (message) {
    steps.push(`本轮问题聚焦: ${message}`);
  }
  return steps.join('\n');
}
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.to !== 'background') return false;
  try {
    switch (request.type) {
      case 'UPDATE_BUILDER': {
        const tabId = sender.tab?.id || request.tabId;
        if (!Number.isFinite(Number(tabId))) return true;
        const fingerprints = getFingerprints(tabId);
        const finger = request.finger && typeof request.finger === 'object' ? request.finger : {};

        if (finger.extType && finger.extName) {
          upsertFingerprint(fingerprints, {
            type: normalizeFingerprintType(finger.extType),
            name: String(finger.extName || '').trim(),
            header: String(finger.name || '').trim(),
            source: String(finger.source || 'content'),
            description: `通过${String(finger.name || '关联特征')}识别到网站使用${String(finger.extName || '')}${getTypeDescription(finger.extType)}`
          });
        }
        upsertFingerprint(fingerprints, {
          ...finger,
          type: normalizeFingerprintType(finger.type)
        });
        serverFingerprints.set(tabId, fingerprints);
        return true;
      }
      case 'GET_FINGERPRINTS': {
        const fingerprints = getFingerprints(request.tabId);
        sendResponse(fingerprints);
        return true;
      }
      case 'FETCH_JS': {
        handleFetchRequest(request, sender, sendResponse);
        return true; 
      }
      case 'FETCH_BINARY': {
        handleFetchBinaryRequest(request, sender, sendResponse);
        return true;
      }
      case 'REGISTER_CONTENT': {
        const senderTabId = sender.tab?.id || request.tabId;
        const frameId = String(sender.frameId ?? request.frameId ?? 0);
        const tabJs = senderTabId ? getTabFrameJs(senderTabId, frameId) : [];
        sendResponse({
          tabJs,
          tabId: senderTabId || null,
          frameId
        });
        return true;
      }
      case 'UPDATE_BADGE': {
        updateBadge(request.results, request.tabId, request.frameId);
        return true;
      }
      case 'GET_TAB_ID': {
        sendResponse({ tabId: sender.tab?.id });
        return true;
      }
      case 'GET_IFRAME_ID': {
        sendResponse({ frameId: String(sender.frameId ?? 0) });
        return true;
      }
      case 'REGEX_MATCH': {
        const { chunk, patterns, patternType } = request;
        const matches = performRegexMatching(chunk, patterns, patternType);
        sendResponse({ matches });
        return true;
      }
      case 'ADD_VULN_REPORTS': {
        reportStore.addVulnReports(request.reports, sender)
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('保存漏洞报告失败:', error);
            sendResponse({ success: false, message: error?.message || 'save failed' });
          });
        return true;
      }
      case 'GET_VULN_REPORTS': {
        reportStore.getVulnReports()
          .then(reports => sendResponse({ success: true, reports }))
          .catch(error => {
            console.error('读取漏洞报告失败:', error);
            sendResponse({ success: false, reports: [] });
          });
        return true;
      }
      case 'CLEAR_VULN_REPORTS': {
        reportStore.clearVulnReports()
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('清空漏洞报告失败:', error);
            sendResponse({ success: false, message: error?.message || 'clear failed' });
          });
        return true;
      }
      case 'DELETE_VULN_REPORT': {
        reportStore.deleteVulnReport(request.reportId)
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('删除漏洞报告失败:', error);
            sendResponse({ success: false, message: error?.message || 'delete failed' });
          });
        return true;
      }
      case 'DELETE_VULN_REPORTS': {
        reportStore.deleteVulnReports(request.reportIds)
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('批量删除漏洞报告失败:', error);
            sendResponse({ success: false, message: error?.message || 'batch delete failed' });
          });
        return true;
      }
      case 'AI_REVIEW_REPORT': {
        aiService.readAiReviewConfig()
          .then(aiConfig => aiService.callAiProviderForReview(request.report || {}, aiConfig))
          .then(result => {
            sendResponse({
              success: true,
              provider: result.provider,
              model: result.model,
              review: result.review
            });
          })
          .catch(error => {
            console.error('AI误报研判失败:', error);
            sendResponse({
              success: false,
              message: error?.message || 'ai review failed'
            });
          });
        return true;
      }
      case 'AI_AGENT_GET_SESSION': {
        aiService.getAiAgentSession(request.sessionId || '')
          .then(result => sendResponse({ success: true, ...result }))
          .catch(error => {
            console.error('读取AI会话失败:', error);
            sendResponse({ success: false, message: error?.message || 'get ai session failed', messages: [] });
          });
        return true;
      }
      case 'AI_AGENT_CLEAR_SESSION': {
        aiService.clearAiAgentSession(request.sessionId || '')
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('清理AI会话失败:', error);
            sendResponse({ success: false, message: error?.message || 'clear ai session failed' });
          });
        return true;
      }
      case 'AI_AGENT_CHAT': {
        aiService.chatWithAiAgent({
          sessionId: request.sessionId || '',
          report: request.report || {},
          message: request.message || ''
        }).then(result => sendResponse(result))
          .catch(error => {
            console.error('AI会话失败:', error);
            sendResponse({ success: false, message: error?.message || 'ai chat failed' });
          });
        return true;
      }
      case 'RUN_DOMXSS_CONSOLE_ASSIST': {
        domxssAssistService.runDomxssConsoleAssistOnTab(request.tabId, request.report || {})
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('Console验证助手执行失败:', error);
            sendResponse({
              success: false,
              message: error?.message || 'console assist failed'
            });
          });
        return true;
      }
      case 'GET_DOMXSS_CONSOLE_SCRIPT': {
        domxssAssistService.getDomxssConsoleScript(request.tabId, request.report || {})
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('生成Console脚本失败:', error);
            sendResponse({
              success: false,
              message: error?.message || 'generate console script failed',
              script: ''
            });
          });
        return true;
      }
      case 'TRIGGER_XSS_POC': {
        pocTriggerService.triggerXssPocOnTab(request.tabId, request.report || {})
          .then(result => sendResponse(result))
          .catch(error => {
            console.error('一键复现执行失败:', error);
            sendResponse({
              success: false,
              message: error?.message || 'trigger poc failed'
            });
          });
        return true;
      }
      case 'GET_SITE_ANALYSIS': {
        const domain = getRootDomain(request.domain);
        // 查询IP需要完整域名
        const fullDomain = request.domain
        const tabId = request.tabId;

        if (analysisPending) return true;
        analysisPending = true;
  
        if (isPrivateIP(domain)) {
          analysisPending = false;
          sendResponse({
            weight: null,
            ip: null,
            icp: null,
            isComplete: true,
            isPrivateIP: true
          });
          return true;
        }
        
        getAnalysisFromStorage(tabId).then(cachedData => {
          if (cachedData.isComplete) {
            analysisPending = false;
            sendResponse(cachedData);
            return;
          }

          Promise.all([
            cachedData.weight || fetchDomainWeight(domain, tabId),
            cachedData.ip || fetchIpInfo(fullDomain, tabId),
            cachedData.icp || fetchIcpInfo(domain, tabId)
          ]).then(([weightData, ipData, icpData]) => {
            analysisPending = false;
            saveAnalysisToStorage(tabId, weightData, ipData, icpData);
            sendResponse({
              weight: weightData?.data || null,
              ip: ipData?.data || null,
              icp: icpData?.data || null,
              isComplete: true,
              isPrivateIP: false
            });
          }).catch(error => {
            analysisPending = false;
            console.error('分析请求失败:', error);
            sendResponse(null);
          });
        });

        return true;
      }
    }
  } catch (error) {
    console.error('消息处理出错:', error);
    sendResponse(null);
    return true;
  }
});

function getAnalysisFromStorage(tabId) {
  return new Promise(resolve => {
    const key = `analysis_${tabId}`;
    chrome.storage.session.get(key, res => {
      const cache = res[key];
      if (!cache) return resolve(emptyCache());

      resolve({
        weight: cache.weight?.data || null,
        ip: cache.ip?.data || null,
        icp: cache.icp?.data || null,
        isComplete: !!(cache.weight && cache.ip && cache.icp)
      });
    });
  });
}

function saveAnalysisToStorage(tabId, weight, ip, icp) {
  const key = `analysis_${tabId}`;
  chrome.storage.session.set({
    [key]: {
      weight: weight ? { data: weight.data } : null,
      ip: ip ? { data: ip.data } : null,
      icp: icp ? { data: icp.data } : null
    }
  });
}

function emptyCache() {
  return {
    weight: null,
    ip: null,
    icp: null,
    isComplete: false
  };
}

function isPrivateIP(domain) {
  const ipv4Pattern = /^\d{1,3}(\.\d{1,3}){3}$/;
  if (ipv4Pattern.test(domain)) {
    const parts = domain.split('.');
    const first = parseInt(parts[0]), second = parseInt(parts[1]);
    return (
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      domain === '127.0.0.1'
    );
  }
  return false;
}

function getRootDomain(domain) {
  const specialTlds = ['com.cn', 'edu.cn', 'gov.cn', 'org.cn', 'net.cn', 'co.jp', 'co.uk', 'co.kr', 'com.hk'];
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  for (const tld of specialTlds) {
    if (domain.endsWith(`.${tld}`)) {
      return parts.slice(-(tld.split('.').length + 1)).join('.');
    }
  }
  return parts.slice(-2).join('.');
}

async function fetchWithCache(url, tabId) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = await response.json();
  return { data };
}

async function fetchDomainWeight(domain, tabId) {
  const apiUrl = `https://api.mir6.com/api/bdqz?myKey=84fbd322b048f19626e861932ec7d572&domain=${domain}&type=json`;
  try {
    return await fetchWithCache(apiUrl, tabId);
  } catch (e) {
    console.error('域名权重查询失败:', e);
    return null;
  }
}

async function fetchIpInfo(domain, tabId) {
  const apiUrl = `https://api.mir6.com/api/ip_json?myKey=7f5860bc55587662c37cf678a7871ad0&ip=${domain}`;
  try {
    return await fetchWithCache(apiUrl, tabId);
  } catch (e) {
    console.error('IP 查询失败:', e);
    return null;
  }
}

async function fetchIcpInfo(domain, tabId) {
  const ipv4Pattern = /^\d{1,3}(\.\d{1,3}){3}$/;
  if (ipv4Pattern.test(domain)) {
    return {
      data: { icp: 'IP地址不适用', unit: 'IP地址不适用', time: 'IP地址不适用' }
    };
  }
  const apiUrl = `https://cn.apihz.cn/api/wangzhan/icp.php?id=88888888&key=88888888&domain=${domain}`;
  try {
    const icp = await fetchWithCache(apiUrl, tabId);
    if (icp?.data?.code === 404) {
      return {
        data: { icp: '未查询到备案信息', unit: '未知', time: '未知' }
      };
    }
    return icp;
  } catch (e) {
    console.error('备案查询失败:', e);
    return null;
  }
}

let analysisPending = false;
