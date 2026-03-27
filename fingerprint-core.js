(function initSnowEyesFingerprintCore(global) {
  if (global.SNOWEYES_FINGERPRINT) return;

  const DEFAULT_FINGERPRINT_CONFIG = {
    HEADERS: [
      { type: 'server', name: 'Apache', pattern: /apache\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'Apache Tomcat', pattern: /apache-(coyote)\/?([\d\.]+)?/i, header: 'server', value: 'component,version', extType: 'technology', extName: 'Java' },
      { type: 'server', name: 'Nginx', pattern: /nginx\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'IIS', pattern: /microsoft-iis\/?([\d\.]+)?/i, header: 'server', value: 'version', extType: 'os', extName: 'Windows' },
      { type: 'server', name: 'Jetty', pattern: /jetty\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version', extType: 'technology', extName: 'Java' },
      { type: 'server', name: 'Resin', pattern: /resin\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'Cloudflare', pattern: /cloudflare\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'Varnish', pattern: /varnish\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'OpenResty', pattern: /openresty\/?([\d\.]+)?/i, header: 'server', value: 'version', extType: 'server', extName: 'Nginx' },
      { type: 'server', name: 'Tengine', pattern: /tengine\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'BWS', pattern: /bws\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'Zeus', pattern: /zeus\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'server', name: 'Server', pattern: /waf|server\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'component', name: 'OpenSSL', pattern: /openssl\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version' },
      { type: 'component', name: 'Mod_wsgi', pattern: /mod_wsgi+\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version' },
      { type: 'component', name: 'Mod_fcgid', pattern: /mod_fcgid+\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version' },
      { type: 'component', name: 'Mod_log_rotate', pattern: /mod_log_rotate+\s?\/?\(?([0-9a-zA-Z.-]*)\)?/i, header: 'server', value: 'version' },
      { type: 'os', name: 'Windows', pattern: /win64|win32|win10|win7|win8|win11/i, header: 'server' },
      { type: 'os', name: 'Ubuntu', pattern: /ubuntu/i, header: 'server' },
      { type: 'os', name: 'Unix', pattern: /unix/i, header: 'server' },
      { type: 'framework', name: 'Spring', pattern: /([a-zA-Z0-9\.\-]+):([a-zA-Z0-9\-]+):(\d+)/i, header: 'x-application-context', value: 'app,env,port', extType: 'technology', extName: 'Java' },
      { type: 'framework', name: 'JFinal', pattern: /jfinal\s?\/?([\d\.]+)?/i, header: 'server', value: 'version', extType: 'technology', extName: 'Java' },
      { type: 'framework', name: 'ASP.NET', pattern: /[0-9.]+/i, header: 'x-aspnet-version', value: 'version' },
      { type: 'framework', name: 'ASP.NET', pattern: /asp.net/i, header: 'x-powered-by' },
      { type: 'framework', name: 'ASP.NET', match: /ASP\.NET_SessionId|ASPSESSIONID/i, header: 'set-cookie' },
      { type: 'framework', name: 'ASP.NET MVC', pattern: /[0-9.]+/i, header: 'x-aspnetmvc-version', value: 'version' },
      { type: 'framework', name: 'Express', pattern: /express/i, header: 'x-powered-by', extType: 'technology', extName: 'Node.js' },
      { type: 'technology', name: 'PHP', pattern: /php\/?([\d\.]+)?/i, header: 'x-powered-by', value: 'version' },
      { type: 'technology', name: 'PHP', pattern: /PHPSESSID/i, header: 'set-cookie', value: 'version' },
      { type: 'technology', name: 'Java', pattern: /java/i, header: 'x-powered-by' },
      { type: 'technology', name: 'Java', pattern: /JSESSIONID|jeesite/i, header: 'set-cookie' },
      { type: 'technology', name: 'Python', pattern: /python\/?([\d\.]+)?/i, header: 'server', value: 'version' },
      { type: 'security', name: '安全狗', pattern: /^waf\/?([\d\.]+)?$/i, header: 'x-powered-by', value: 'version' },
      { type: 'security', name: 'Janusec', pattern: /janusec/i, header: 'x-powered-by' },
      { type: 'security', name: '360', pattern: /([a-zA-Z0-9\-\.]+)\s([0-9.]+)\s([A-Za-z0-9]+)$/i, header: 'x-safe-firewall', value: 'app,version,appType' },
      { type: 'security', name: 'HSTS', pattern: /max-age=(\d+)/i, header: 'strict-transport-security', value: 'time' },
      { type: 'panel', name: 'Plesk', pattern: /plesk/i, header: 'x-powered-by' }
    ],
    COOKIES: [
      { type: 'technology', name: 'PHP', match: /PHPSESSID/i },
      { type: 'framework', name: 'ASP.NET', match: /ASP\.NET_SessionId|ASPSESSIONID/i },
      { type: 'technology', name: 'Java', match: /JSESSIONID|jeesite/i }
    ],
    ANALYTICS: {
      baidu: {
        pattern: '*://hm.baidu.com/hm.js*',
        name: '百度统计',
        description: '通过网络请求识别到百度统计服务，网站的用户访问数据会被百度记录',
        version: 'Baidu Analytics'
      },
      yahoo: {
        pattern: '*://analytics.yahoo.com/*',
        name: '雅虎统计',
        description: '通过网络请求识别到雅虎统计服务，网站的用户访问数据会被雅虎记录',
        version: 'Yahoo Analytics'
      },
      google: {
        pattern: '*://www.google-analytics.com/*',
        name: '谷歌统计',
        description: '通过网络请求识别到谷歌统计服务，网站的用户访问数据会被谷歌记录',
        version: 'Google Analytics'
      }
    },
    DESCRIPTIONS: [
      { name: 'framework', description: '框架' },
      { name: 'technology', description: '语言' },
      { name: 'security', description: '(安全应用/策略)' },
      { name: 'server', description: '服务器' },
      { name: 'os', description: '操作系统' },
      { name: 'app', description: '应用' },
      { name: 'env', description: '环境' },
      { name: 'port', description: '端口' },
      { name: 'version', description: '版本' },
      { name: 'builder', description: '构建工具' },
      { name: 'framework', description: '框架' },
      { name: 'appType', description: '应用类型' },
      { name: 'time', description: '时间' },
      { name: 'component', description: '组件' },
      { name: 'panel', description: '面板' }
    ]
  };

  const FINGERPRINT_LIBRARY_URL = 'finger.json';
  const FINGERPRINT_LIBRARY_FILES = Object.freeze([
    'finger.json',
    'kscan_fingerprint.json',
    'webapp.json',
    'apps.json'
  ]);
  const FINGERPRINT_RULE_CACHE_VERSION = 5;
  const FINGERPRINT_SCORE_THRESHOLD = 72;
  const FINGERPRINT_MAX_RULES_PER_NAME = 30;
  const FINGERPRINT_MAX_TOTAL_RULES = 30000;
  const FINGERPRINT_KSCAN_REGEX_FALLBACK = 'literal';
  const FINGERPRINT_KSCAN_MIN_LITERAL_LEN = 5;
  const FINGERPRINT_WEAK_KEYWORD_MIN_LEN = 4;
  const FINGERPRINT_WEAK_KEYWORDS = new Set([
    'login',
    'powered by',
    'copyright',
    '<a',
    '?ver',
    'admin',
    'index.php',
    'welcome',
    'bundle.js',
    'main.js',
    'vendor.js',
    'runtime.js',
    'manifest.js',
    'app.js'
  ]);
  const FINGERPRINT_GENERIC_WEAK_LITERALS = new Set([
    'module',
    'modules',
    'server',
    'system',
    'website',
    'default'
  ]);
  const FINGERPRINT_NAME_SUFFIX_TOKENS = new Set([
    'body',
    'title',
    'header',
    'headers',
    'response',
    'cookie',
    'html'
  ]);
  const FINGERPRINT_TRACE_GENERIC_TOKENS = new Set([
    'web',
    'www',
    'http',
    'https',
    'html',
    'system',
    'server',
    'cms',
    'panel',
    'login',
    'default',
    'welcome',
    'powered',
    'manager',
    'application',
    'software'
  ]);
  const FINGERPRINT_MUTEX_GROUPS = Object.freeze([
    ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Caddy', 'Lighttpd'],
    ['OpenResty', 'Tengine', 'Nginx'],
    ['Tomcat', 'Jetty', 'Resin']
  ]);
  const WAPPALYZER_MAX_JS_PROBES = 180;
  const DEFAULT_WAPPALYZER_APPS = Object.freeze({
    categories: Object.freeze({
      1: Object.freeze({ name: 'CMS' }),
      2: Object.freeze({ name: 'JavaScript Frameworks' }),
      3: Object.freeze({ name: 'Web Servers' }),
      4: Object.freeze({ name: 'Programming Languages' })
    }),
    apps: Object.freeze({
      'WordPress': Object.freeze({
        cats: Object.freeze([1]),
        html: Object.freeze(['wp-content/', 'wp-includes/']),
        meta: Object.freeze({ generator: Object.freeze(['WordPress\\;version:\\1']) }),
        headers: Object.freeze({
          'x-pingback': Object.freeze(['/xmlrpc\\.php$']),
          link: Object.freeze(['rel=\\"https://api\\.w\\.org/\\"'])
        }),
        implies: Object.freeze(['PHP'])
      }),
      'Vue.js': Object.freeze({
        cats: Object.freeze([2]),
        html: Object.freeze(['data-v-', 'id="app"']),
        script: Object.freeze(['vue(?:\\.runtime)?(?:\\.min)?\\.js\\;version:\\1']),
        js: Object.freeze({ 'Vue.version': Object.freeze(['^(.+)$\\;version:\\1']) })
      }),
      'React': Object.freeze({
        cats: Object.freeze([2]),
        html: Object.freeze(['data-reactroot', 'react-container']),
        script: Object.freeze(['react(?:-dom)?(?:\\.min)?\\.js\\;version:\\1']),
        js: Object.freeze({ 'React.version': Object.freeze(['^(.+)$\\;version:\\1']) })
      }),
      'jQuery': Object.freeze({
        cats: Object.freeze([2]),
        script: Object.freeze(['jquery(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1']),
        js: Object.freeze({ 'jQuery.fn.jquery': Object.freeze(['([\\d.]+)\\;version:\\1']) })
      }),
      'Apache': Object.freeze({
        cats: Object.freeze([3]),
        headers: Object.freeze({ server: Object.freeze(['Apache(?:/([\\d.]+))?\\;version:\\1']) })
      }),
      'Nginx': Object.freeze({
        cats: Object.freeze([3]),
        headers: Object.freeze({ server: Object.freeze(['nginx(?:/([\\d.]+))?\\;version:\\1']) })
      }),
      'OpenResty': Object.freeze({
        cats: Object.freeze([3]),
        headers: Object.freeze({ server: Object.freeze(['openresty(?:/([\\d.]+))?\\;version:\\1']) }),
        implies: Object.freeze(['Nginx'])
      }),
      'PHP': Object.freeze({
        cats: Object.freeze([4]),
        headers: Object.freeze({
          'x-powered-by': Object.freeze(['PHP(?:/([\\d.]+))?\\;version:\\1']),
          'set-cookie': Object.freeze(['PHPSESSID'])
        })
      })
    })
  });
  const TYPE_BUCKETS = Object.freeze(['server', 'component', 'technology', 'security', 'analytics', 'builder', 'framework', 'os', 'panel', 'cdn']);

  function createDescriptionMap(items) {
    const map = new Map();
    (Array.isArray(items) ? items : []).forEach((item) => {
      const name = String(item?.name || '').trim();
      const description = String(item?.description || '').trim();
      if (name && description && !map.has(name)) {
        map.set(name, description);
      }
    });
    return map;
  }
  function normalizeFingerprintType(type) {
    const safeType = String(type || '').trim().toLowerCase();
    return TYPE_BUCKETS.includes(safeType) ? safeType : 'component';
  }
  function getTypeDescription(config, type) {
    const key = String(type || '').trim();
    if (!key) return '';
    if (config?.DESCRIPTION_MAP instanceof Map) {
      return config.DESCRIPTION_MAP.get(key) || '';
    }
    return createDescriptionMap(config?.DESCRIPTIONS).get(key) || '';
  }
  function createRuntimeFingerprintConfig(baseConfig, externalHeaderIndex) {
    const source = baseConfig && typeof baseConfig === 'object' ? baseConfig : DEFAULT_FINGERPRINT_CONFIG;
    const descriptions = Array.isArray(source.DESCRIPTIONS) ? source.DESCRIPTIONS.slice() : [];
    return {
      HEADERS: Array.isArray(source.HEADERS) ? source.HEADERS.map(item => ({ ...item })) : [],
      COOKIES: Array.isArray(source.COOKIES) ? source.COOKIES.map(item => ({ ...item })) : [],
      ANALYTICS: { ...(source.ANALYTICS || {}) },
      DESCRIPTIONS: descriptions,
      DESCRIPTION_MAP: createDescriptionMap(descriptions),
      EXTERNAL_HEADER_INDEX: normalizeExternalHeaderIndex(externalHeaderIndex || { byHeader: {}, global: [] })
    };
  }
  function normalizeFingerprintName(rawName) {
    const sourceName = String(rawName || '').trim();
    if (!sourceName) return '';
    return sourceName.replace(/[_\s-]*header$/i, '').trim() || sourceName;
  }
  function normalizeFingerprintIdentityKey(rawName) {
    let value = normalizeFingerprintName(rawName)
      .toLowerCase()
      .replace(/[()（）\[\]{}]/g, ' ')
      .trim();
    if (!value) return '';
    let parts = value.split(/[\s_\-./:]+/).filter(Boolean);
    while (parts.length > 1 && FINGERPRINT_NAME_SUFFIX_TOKENS.has(parts[parts.length - 1])) {
      parts = parts.slice(0, -1);
    }
    return parts.join('');
  }
  function normalizeTraceText(value) {
    return String(value || '')
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .trim();
  }
  function extractUnicodeWordTokens(value) {
    const source = normalizeTraceText(value);
    if (!source) return [];
    const matches = source.match(/[\p{L}\p{N}]+/gu) || source.match(/[a-z0-9\u4e00-\u9fa5]+/g) || [];
    return matches
      .map(item => String(item || '').trim())
      .filter(item => item && !FINGERPRINT_TRACE_GENERIC_TOKENS.has(item));
  }
  function getHitTraceComparables(hit) {
    return asArray(hit?.traces)
      .map((trace) => {
        const field = normalizeRuleFieldName(trace?.field || String(trace?.context || '').split(':')[0]);
        const value = normalizeTraceText(trace?.value || '');
        if (!value) return null;
        if (!['body', 'title', 'response'].includes(field)) return null;
        return {
          field,
          value,
          length: value.length,
          tokens: extractUnicodeWordTokens(value)
        };
      })
      .filter(Boolean);
  }
  function compareTokenSubset(tokensA, tokensB) {
    if (!Array.isArray(tokensA) || !Array.isArray(tokensB) || !tokensA.length || !tokensB.length) return false;
    const setB = new Set(tokensB);
    return tokensA.every(item => setB.has(item));
  }
  function computeFingerprintHitSpecificity(hit) {
    const traces = getHitTraceComparables(hit);
    const longestTraceLength = traces.reduce((max, item) => Math.max(max, Number(item.length || 0)), 0);
    const strongestTokenCount = traces.reduce((max, item) => Math.max(max, Array.isArray(item.tokens) ? item.tokens.length : 0), 0);
    const matchedFieldCount = asArray(hit?.matchedFields).length;
    return (
      Number(hit?.score || 0) * 1000 +
      longestTraceLength * 10 +
      strongestTokenCount * 3 +
      matchedFieldCount
    );
  }
  function mergeFingerprintHitDetails(base, incoming) {
    const keep = { ...(base || {}) };
    const candidate = incoming && typeof incoming === 'object' ? incoming : {};
    if (computeFingerprintHitSpecificity(candidate) > computeFingerprintHitSpecificity(keep)) {
      Object.assign(keep, candidate);
    }
    keep.score = Math.max(Number(base?.score || 0), Number(candidate.score || 0));
    keep.matchedFields = Array.from(new Set([...asArray(base?.matchedFields), ...asArray(candidate?.matchedFields)]));
    keep.weakSignals = Array.from(new Set([...asArray(base?.weakSignals), ...asArray(candidate?.weakSignals)]));
    keep.traces = [...asArray(base?.traces), ...asArray(candidate?.traces)].slice(0, 12);
    return keep;
  }
  function shouldCollapseSimilarFingerprintHits(a, b) {
    if (!a || !b) return false;
    if (String(a?.source || '') === 'wappalyzer' || String(b?.source || '') === 'wappalyzer') return false;
    const fieldsA = new Set(asArray(a?.matchedFields).map(item => normalizeRuleFieldName(item)));
    const fieldsB = new Set(asArray(b?.matchedFields).map(item => normalizeRuleFieldName(item)));
    const blockedField = ['header', 'cookie', 'icon_hash', 'url', 'js', 'script', 'meta', 'env'].some((field) => fieldsA.has(field) || fieldsB.has(field));
    if (blockedField) return false;
    const tracesA = getHitTraceComparables(a);
    const tracesB = getHitTraceComparables(b);
    if (!tracesA.length || !tracesB.length) return false;

    for (const left of tracesA) {
      for (const right of tracesB) {
        if (left.field !== right.field) continue;
        if (left.value === right.value && left.length >= 8) return true;
        const shorter = left.length <= right.length ? left : right;
        const longer = shorter === left ? right : left;
        if (shorter.length >= 8 && longer.value.includes(shorter.value) && (longer.length - shorter.length) >= 4) {
          return true;
        }
        const shortTokens = shorter.tokens || [];
        const longTokens = longer.tokens || [];
        if (shortTokens.length >= 2 && compareTokenSubset(shortTokens, longTokens)) {
          return true;
        }
      }
    }
    return false;
  }
  function collapseSimilarFingerprintHits(results) {
    const sorted = asArray(results)
      .slice()
      .sort((a, b) => computeFingerprintHitSpecificity(b) - computeFingerprintHitSpecificity(a));
    const collapsed = [];
    sorted.forEach((item) => {
      const existing = collapsed.find(current => shouldCollapseSimilarFingerprintHits(current, item));
      if (!existing) {
        collapsed.push({ ...item });
        return;
      }
      const merged = mergeFingerprintHitDetails(existing, item);
      Object.assign(existing, merged);
    });
    return collapsed;
  }
  function buildAnchorPopularityStats(compiledRules) {
    const popularity = new Map();
    asArray(compiledRules).forEach((rule) => {
      asArray(rule?.positiveAnchors).forEach((anchor) => {
        const field = normalizeRuleFieldName(anchor?.field);
        const needle = String(anchor?.needle || '').trim();
        if (!field || !needle) return;
        const key = `${field}|${needle}`;
        popularity.set(key, Number(popularity.get(key) || 0) + 1);
      });
    });
    return popularity;
  }
  function inferFingerprintType(name) {
    const lowerName = String(name || '').toLowerCase();
    if (/waf|firewall|shield|safe|security|防火墙|安全/.test(lowerName)) return 'security';
    if (/nginx|apache|tomcat|jetty|openresty|tengine|iis|server/.test(lowerName)) return 'server';
    if (/windows|ubuntu|linux|debian|centos/.test(lowerName)) return 'os';
    if (/panel|plesk|宝塔|bt-/.test(lowerName)) return 'panel';
    if (/spring|django|laravel|rails|express|flask|asp\.net|struts|thinkphp/.test(lowerName)) return 'framework';
    if (/php|java|python|node/.test(lowerName)) return 'technology';
    return 'component';
  }
  function normalizeKeywordNeedle(value) {
    return String(value || '').replace(/\s+/g, ' ').trim().toLowerCase();
  }
  function buildAnalyticsPatterns(config) {
    return Object.entries(config?.ANALYTICS || {}).map(([type, item]) => {
      const pattern = String(item?.pattern || '').trim();
      if (!pattern) return null;
      try {
        return { type, pattern, regex: new RegExp(pattern.replace(/[*]/g, '.*')) };
      } catch {
        return null;
      }
    }).filter(Boolean);
  }
  function parseFingerHeaderKeyword(keyword) {
    const normalized = normalizeKeywordNeedle(keyword);
    if (!normalized) return null;
    const separatorIndex = normalized.indexOf(':');
    if (separatorIndex > 0 && separatorIndex < 50) {
      const header = normalized.slice(0, separatorIndex).trim();
      const needle = normalized.slice(separatorIndex + 1).trim();
      if (/^[a-z0-9-]+$/.test(header) && needle) {
        return { header, needle };
      }
    }
    return { header: '', needle: normalized };
  }
  function sanitizeExternalHeaderRecord(item) {
    const name = String(item?.name || '').trim();
    const needle = normalizeKeywordNeedle(item?.needle || '');
    if (!name || !needle) return null;
    return {
      type: normalizeFingerprintType(item?.type || 'component'),
      name,
      header: String(item?.header || '').trim().toLowerCase(),
      needle
    };
  }
  function normalizeExternalHeaderIndex(index) {
    const byHeader = Object.create(null);
    const rawByHeader = index?.byHeader && typeof index.byHeader === 'object' ? index.byHeader : {};
    Object.entries(rawByHeader).forEach(([header, list]) => {
      const safeHeader = String(header || '').trim().toLowerCase();
      if (!safeHeader) return;
      const safeList = (Array.isArray(list) ? list : [])
        .map(item => sanitizeExternalHeaderRecord(item))
        .filter(Boolean);
      if (safeList.length > 0) {
        byHeader[safeHeader] = safeList;
      }
    });
    const globalList = (Array.isArray(index?.global) ? index.global : [])
      .map(item => sanitizeExternalHeaderRecord(item))
      .filter(Boolean)
      .map(item => ({ ...item, header: '' }));
    const total = globalList.length + Object.values(byHeader).reduce((acc, list) => acc + list.length, 0);
    return { byHeader, global: globalList, total };
  }
  function buildExternalHeaderIndexFromFingerprintList(sourceList, options) {
    const maxHeaderRules = Number(options?.maxHeaderRules || 8000);
    const byHeader = Object.create(null);
    const globalList = [];
    const dedupe = new Set();
    let total = 0;

    for (const item of (Array.isArray(sourceList) ? sourceList : [])) {
      if (total >= maxHeaderRules) break;
      const location = String(item?.location || '').toLowerCase();
      const method = String(item?.method || '').toLowerCase();
      if (location !== 'header' || method !== 'keyword') continue;

      const name = normalizeFingerprintName(item?.cms || item?.name || '');
      if (!name) continue;
      const type = inferFingerprintType(name);
      const keywords = Array.isArray(item?.keyword) ? item.keyword : [item?.keyword];
      for (const rawKeyword of keywords) {
        if (total >= maxHeaderRules) break;
        const parsed = parseFingerHeaderKeyword(rawKeyword);
        if (!parsed) continue;
        const dedupeKey = `${name}|${parsed.header}|${parsed.needle}`;
        if (dedupe.has(dedupeKey)) continue;
        dedupe.add(dedupeKey);

        const record = { type, name, header: parsed.header, needle: parsed.needle };
        if (record.header) {
          if (!byHeader[record.header]) byHeader[record.header] = [];
          byHeader[record.header].push(record);
        } else {
          globalList.push(record);
        }
        total += 1;
      }
    }
    return normalizeExternalHeaderIndex({ byHeader, global: globalList });
  }
  function buildKeywordPrefixIndex(records, prefixLength) {
    const usePrefixLength = Number(prefixLength || 3);
    const byPrefix = new Map();
    const shortList = [];
    (Array.isArray(records) ? records : []).forEach((record) => {
      const keyword = String(record?.keyword || '');
      if (!keyword) return;
      if (keyword.length < usePrefixLength) {
        shortList.push(record);
        return;
      }
      const prefix = keyword.slice(0, usePrefixLength);
      if (!byPrefix.has(prefix)) {
        byPrefix.set(prefix, []);
      }
      byPrefix.get(prefix).push(record);
    });
    return { byPrefix, shortList, total: records.length, prefixLength: usePrefixLength };
  }
  function collectTextPrefixes(text, prefixLength) {
    const source = String(text || '');
    const size = Number(prefixLength || 3);
    const set = new Set();
    if (source.length < size) return set;
    for (let i = 0; i <= source.length - size; i += 1) {
      set.add(source.slice(i, i + size));
    }
    return set;
  }
  function matchKeywordIndex(text, index, maxMatches, prefixLength) {
    const source = String(text || '').toLowerCase();
    if (!source) return [];
    const limit = Number(maxMatches || 40);
    const usePrefixLength = Number(prefixLength || index?.prefixLength || 3);
    const matches = [];
    const foundNames = new Set();
    const checkedKeys = new Set();
    const byPrefix = index?.byPrefix instanceof Map ? index.byPrefix : new Map();

    if (byPrefix.size > 0 && source.length >= usePrefixLength) {
      const prefixSet = collectTextPrefixes(source, usePrefixLength);
      prefixSet.forEach((prefix) => {
        const candidates = byPrefix.get(prefix);
        if (!Array.isArray(candidates)) return;
        candidates.forEach((candidate) => {
          if (matches.length >= limit) return;
          const checkKey = `${candidate.location}|${candidate.name}|${candidate.keyword}`;
          if (checkedKeys.has(checkKey)) return;
          checkedKeys.add(checkKey);
          if (!source.includes(candidate.keyword)) return;
          const nameKey = `${candidate.location}|${candidate.name}`;
          if (foundNames.has(nameKey)) return;
          foundNames.add(nameKey);
          matches.push(candidate);
        });
      });
    }

    if (matches.length < limit) {
      const shortList = Array.isArray(index?.shortList) ? index.shortList : [];
      shortList.forEach((candidate) => {
        if (matches.length >= limit) return;
        const checkKey = `${candidate.location}|${candidate.name}|${candidate.keyword}`;
        if (checkedKeys.has(checkKey)) return;
        checkedKeys.add(checkKey);
        if (!source.includes(candidate.keyword)) return;
        const nameKey = `${candidate.location}|${candidate.name}`;
        if (foundNames.has(nameKey)) return;
        foundNames.add(nameKey);
        matches.push(candidate);
      });
    }

    return matches;
  }
  function sampleBodyHtmlForFingerprint(rawHtml, limit) {
    const html = String(rawHtml || '');
    const maxSize = Number(limit || 480000);
    if (html.length <= maxSize) return html;
    const headLen = Math.floor(maxSize * 0.7);
    const tailLen = maxSize - headLen;
    return `${html.slice(0, headLen)}\n${html.slice(-tailLen)}`;
  }
  function buildFaviconHashIndexFromFingerprintList(sourceList) {
    const map = new Map();
    const dedupe = new Set();
    (Array.isArray(sourceList) ? sourceList : []).forEach((item) => {
      const method = String(item?.method || '').toLowerCase();
      if (method !== 'faviconhash') return;
      const name = normalizeFingerprintName(item?.cms || item?.name || '');
      if (!name) return;
      const type = inferFingerprintType(name);
      const keywords = Array.isArray(item?.keyword) ? item.keyword : [item?.keyword];
      keywords.forEach((rawKeyword) => {
        const hash = String(rawKeyword || '').trim();
        if (!/^-?\d+$/.test(hash)) return;
        const dedupeKey = `${name}|${hash}`;
        if (dedupe.has(dedupeKey)) return;
        dedupe.add(dedupeKey);
        if (!map.has(hash)) map.set(hash, []);
        map.get(hash).push({ name, type, hash, location: 'favicon' });
      });
    });
    return map;
  }
  function extractIndexesFromPayload(payload, options) {
    const sourceList = Array.isArray(payload?.fingerprint) ? payload.fingerprint : [];
    const prefixLength = Number(options?.prefixLength || 3);
    const bodyRecords = [];
    const titleRecords = [];
    const dedupe = new Set();

    sourceList.forEach((item) => {
      const method = String(item?.method || '').toLowerCase();
      const location = String(item?.location || '').toLowerCase();
      if (method !== 'keyword' || (location !== 'body' && location !== 'title')) return;
      const name = normalizeFingerprintName(item?.cms || item?.name || '');
      if (!name) return;
      const type = inferFingerprintType(name);
      const keywords = Array.isArray(item?.keyword) ? item.keyword : [item?.keyword];
      keywords.forEach((rawKeyword) => {
        const keyword = normalizeKeywordNeedle(rawKeyword);
        if (!keyword) return;
        const dedupeKey = `${location}|${name}|${keyword}`;
        if (dedupe.has(dedupeKey)) return;
        dedupe.add(dedupeKey);
        const record = { location, name, type, keyword };
        if (location === 'title') {
          titleRecords.push(record);
        } else {
          bodyRecords.push(record);
        }
      });
    });

    const headerIndex = buildExternalHeaderIndexFromFingerprintList(sourceList, options);
    const bodyKeywordIndex = buildKeywordPrefixIndex(bodyRecords, prefixLength);
    const titleKeywordIndex = buildKeywordPrefixIndex(titleRecords, prefixLength);
    const faviconHashMap = buildFaviconHashIndexFromFingerprintList(sourceList);
    return {
      headerIndex,
      bodyKeywordIndex,
      titleKeywordIndex,
      faviconHashMap,
      stats: {
        header: headerIndex.total || 0,
        body: bodyKeywordIndex.total || 0,
        title: titleKeywordIndex.total || 0,
        favicon: faviconHashMap.size || 0
      }
    };
  }
  function hashHeaderMapSignature(headerMap) {
    const pairs = [];
    headerMap.forEach((value, key) => {
      pairs.push(`${key}:${String(value || '').toLowerCase()}`);
    });
    pairs.sort();
    const merged = pairs.join('\n');
    let hash = 2166136261;
    for (let i = 0; i < merged.length; i += 1) {
      hash ^= merged.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return `${merged.length}:${(hash >>> 0).toString(16)}`;
  }
  function setMapCacheEntry(cacheMap, key, value, maxSize) {
    if (!(cacheMap instanceof Map)) return;
    cacheMap.set(key, value);
    const limit = Number(maxSize || 180);
    if (cacheMap.size > limit) {
      const firstKey = cacheMap.keys().next().value;
      if (firstKey) cacheMap.delete(firstKey);
    }
  }
  function matchExternalHeaderFingerprints(headerMap, index, cacheMap, maxCacheSize) {
    const normalizedIndex = normalizeExternalHeaderIndex(index);
    if (!normalizedIndex.total) return [];

    const cacheKey = hashHeaderMapSignature(headerMap);
    if (cacheMap instanceof Map && cacheMap.has(cacheKey)) {
      return cacheMap.get(cacheKey);
    }

    const matched = [];
    const seen = new Set();
    const addMatched = (item) => {
      const key = `${item.type}:${item.name}`;
      if (seen.has(key)) return;
      seen.add(key);
      matched.push(item);
    };

    headerMap.forEach((value, key) => {
      const candidates = normalizedIndex.byHeader[key];
      if (!Array.isArray(candidates) || !candidates.length) return;
      const lowerValue = String(value || '').toLowerCase();
      candidates.forEach((item) => {
        if (lowerValue.includes(item.needle)) {
          addMatched(item);
        }
      });
    });

    if (Array.isArray(normalizedIndex.global) && normalizedIndex.global.length > 0) {
      const fullText = Array.from(headerMap.entries())
        .map(([key, value]) => `${key}: ${String(value || '').toLowerCase()}`)
        .join('\n');
      normalizedIndex.global.forEach((item) => {
        if (fullText.includes(item.needle)) {
          addMatched(item);
        }
      });
    }

    setMapCacheEntry(cacheMap, cacheKey, matched, maxCacheSize);
    return matched;
  }
  function ensureFingerprintBucket(fingerprints, type) {
    const safeType = normalizeFingerprintType(type);
    if (!Array.isArray(fingerprints[safeType])) {
      fingerprints[safeType] = [];
    }
    return safeType;
  }
  function identifyTechnologyFromCookie(cookieHeader, runtimeConfig) {
    const config = runtimeConfig || createRuntimeFingerprintConfig(DEFAULT_FINGERPRINT_CONFIG);
    const sourceText = String(cookieHeader || '');
    for (const cookie of config.COOKIES || []) {
      const matcher = cookie.match || cookie.pattern;
      if (!(matcher instanceof RegExp)) continue;
      if (matcher.test(sourceText)) {
        const safeType = normalizeFingerprintType(cookie.type);
        return {
          type: safeType,
          name: cookie.name,
          description: `通过cookie识别到网站使用${cookie.name}作为服务端${getTypeDescription(config, safeType)}`
        };
      }
    }
    return null;
  }
  function applyHeaderFingerprints(options) {
    const runtimeConfig = options?.runtimeConfig || createRuntimeFingerprintConfig(DEFAULT_FINGERPRINT_CONFIG);
    const fingerprints = options?.fingerprints || {};
    const headers = Array.isArray(options?.headers) ? options.headers : [];
    const headerMatchCache = options?.headerMatchCache instanceof Map ? options.headerMatchCache : new Map();
    const maxHeaderMatchCache = Number(options?.maxHeaderMatchCache || 180);
    if (!(fingerprints.nameMap instanceof Map)) {
      fingerprints.nameMap = new Map();
    }

    const headerMap = new Map(
      headers.map(item => [String(item?.name || '').toLowerCase(), String(item?.value || '')])
    );

    for (const config of (runtimeConfig.HEADERS || [])) {
      const headerName = String(config?.header || '').toLowerCase();
      if (!headerName) continue;
      const headerValue = headerMap.get(headerName);
      if (!headerValue) continue;

      const matcher = config.pattern || config.match;
      if (!(matcher instanceof RegExp)) continue;
      const result = String(headerValue).match(matcher);
      if (!result || fingerprints.nameMap.has(config.name)) continue;

      const safeType = ensureFingerprintBucket(fingerprints, config.type);
      const fingerprint = { ...config, type: safeType };
      fingerprint.description = `通过${fingerprint.header}识别到网站使用${fingerprint.name}${getTypeDescription(runtimeConfig, safeType)}`;

      if (config.extType && !fingerprints.nameMap.has(config.extName)) {
        const extType = ensureFingerprintBucket(fingerprints, config.extType);
        const extFingerprint = {
          type: extType,
          name: config.extName,
          header: config.header,
          description: `通过${config.header}识别到网站使用${config.extName}${getTypeDescription(runtimeConfig, extType)}`
        };
        fingerprints[extType].push(extFingerprint);
        fingerprints.nameMap.set(config.extName, true);
      }

      if (config.value) {
        const valueFields = String(config.value)
          .split(',')
          .map(item => String(item || '').trim())
          .filter(Boolean);
        if (valueFields.length > 0) {
          let captureIndex = 1;
          valueFields.forEach((fieldName) => {
            const capture = result.length > 1 ? result[captureIndex] : result[0];
            fingerprint[fieldName] = capture || null;
            fingerprint.description += `，${getTypeDescription(runtimeConfig, fieldName)}为${fingerprint[fieldName] || '未知'}`;
            captureIndex += 1;
          });
        }
      }
      fingerprints[safeType].push(fingerprint);
      fingerprints.nameMap.set(config.name, true);
    }

    const externalHits = matchExternalHeaderFingerprints(
      headerMap,
      runtimeConfig.EXTERNAL_HEADER_INDEX,
      headerMatchCache,
      maxHeaderMatchCache
    );
    externalHits.forEach((item) => {
      if (fingerprints.nameMap.has(item.name)) return;
      const safeType = ensureFingerprintBucket(fingerprints, item.type);
      fingerprints[safeType].push({
        type: safeType,
        name: item.name,
        header: item.header || 'header',
        version: item.name,
        source: 'finger.json',
        description: `通过header关键字识别到网站使用${item.name}${getTypeDescription(runtimeConfig, safeType)}`
      });
      fingerprints.nameMap.set(item.name, true);
    });

    return fingerprints;
  }
  function wrapBase64LikePython(base64) {
    const value = String(base64 || '').trim();
    if (!value) return '';
    const chunks = value.match(/.{1,76}/g) || [];
    return `${chunks.join('\n')}\n`;
  }
  function murmurhash3_32_gc(key, seed) {
    const source = String(key || '');
    let remainder = source.length & 3;
    let bytes = source.length - remainder;
    let h1 = seed || 0;
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    let i = 0;
    let k1 = 0;

    while (i < bytes) {
      k1 =
        ((source.charCodeAt(i) & 0xff)) |
        ((source.charCodeAt(i + 1) & 0xff) << 8) |
        ((source.charCodeAt(i + 2) & 0xff) << 16) |
        ((source.charCodeAt(i + 3) & 0xff) << 24);
      i += 4;
      k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;

      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      const h1b = (((h1 & 0xffff) * 5) + ((((h1 >>> 16) * 5) & 0xffff) << 16)) & 0xffffffff;
      h1 = (((h1b & 0xffff) + 0x6b64) + ((((h1b >>> 16) + 0xe654) & 0xffff) << 16));
    }

    k1 = 0;
    switch (remainder) {
      case 3:
        k1 ^= (source.charCodeAt(i + 2) & 0xff) << 16;
      case 2:
        k1 ^= (source.charCodeAt(i + 1) & 0xff) << 8;
      case 1:
        k1 ^= (source.charCodeAt(i) & 0xff);
        k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
        h1 ^= k1;
    }

    h1 ^= source.length;
    h1 ^= h1 >>> 16;
    h1 = (((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16)) & 0xffffffff;
    h1 ^= h1 >>> 13;
    h1 = (((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16)) & 0xffffffff;
    h1 ^= h1 >>> 16;
    return h1 >>> 0;
  }
  function toSignedInt32(value) {
    const unsigned = (Number(value) >>> 0);
    return unsigned > 0x7fffffff ? unsigned - 0x100000000 : unsigned;
  }
  function computeFaviconHashCandidates(base64) {
    const raw = String(base64 || '').trim();
    if (!raw) return [];
    const candidates = [wrapBase64LikePython(raw), raw];
    const hashes = [];
    const seen = new Set();
    candidates.forEach((candidate) => {
      if (!candidate) return;
      const signed = String(toSignedInt32(murmurhash3_32_gc(candidate, 0)));
      if (!seen.has(signed)) {
        seen.add(signed);
        hashes.push(signed);
      }
    });
    return hashes;
  }
  function clampNumber(value, min, max) {
    const source = Number(value);
    if (!Number.isFinite(source)) return min;
    if (source < min) return min;
    if (source > max) return max;
    return source;
  }
  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (value == null) return [];
    return [value];
  }
  function escapeRuleValue(value) {
    return String(value || '')
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"');
  }
  function tryParseJsonObject(rawValue) {
    try {
      return JSON.parse(String(rawValue || ''));
    } catch {
      return null;
    }
  }
  function normalizeRuleFieldName(rawField) {
    const key = String(rawField || '').trim().toLowerCase();
    if (!key) return 'body';
    if (['body', 'html', 'content', 'class', 'src', 'href', 'name', 'id', 'target', 'alt', 'action', 'realm', 'uri', 'location', 'server', 'type', 'config', 'value', 'username', 't', 'mod'].includes(key)) return 'body';
    if (['header', 'headers'].includes(key)) return 'header';
    if (['cookie', 'cookies', 'set-cookie'].includes(key)) return 'cookie';
    if (key === 'title') return 'title';
    if (['url', 'path'].includes(key)) return 'url';
    if (['icon', 'iconhash', 'icon_hash', 'faviconhash', 'favicon_hash'].includes(key)) return 'icon_hash';
    if (key === 'response') return 'response';
    if (key === 'script') return 'script';
    if (key === 'meta') return 'meta';
    if (key === 'js') return 'js';
    if (key === 'env') return 'env';
    return 'body';
  }
  function normalizeRuleFieldNameStrict(rawField) {
    const key = String(rawField || '').trim().toLowerCase();
    if (!key) return '';
    if (['body', 'html', 'content', 'class', 'src', 'href', 'name', 'id', 'target', 'alt', 'action', 'realm', 'uri', 'location', 'server', 'type', 'config', 'value', 'username', 't', 'mod'].includes(key)) return 'body';
    if (['header', 'headers'].includes(key)) return 'header';
    if (['cookie', 'cookies', 'set-cookie'].includes(key)) return 'cookie';
    if (key === 'title') return 'title';
    if (['url', 'path'].includes(key)) return 'url';
    if (['icon', 'iconhash', 'icon_hash', 'faviconhash', 'favicon_hash'].includes(key)) return 'icon_hash';
    if (key === 'response') return 'response';
    if (key === 'script') return 'script';
    if (key === 'meta') return 'meta';
    if (key === 'js') return 'js';
    if (key === 'env') return 'env';
    return '';
  }
  function normalizeRuleExpressionSyntax(expression) {
    return String(expression || '')
      .replace(/\b(?:AND|and)\b/g, '&&')
      .replace(/\b(?:OR|or)\b/g, '||')
      .replace(/\b(?:NOT|not)\b/g, '!');
  }
  function buildRuleFragment(field, op, value) {
    const safeField = normalizeRuleFieldName(field);
    const safeOp = ['=', '==', '!=', '~='].includes(String(op || '').trim()) ? String(op).trim() : '=';
    const safeValue = escapeRuleValue(value);
    return `${safeField}${safeOp}"${safeValue}"`;
  }
  function unquoteRuleValue(rawValue) {
    let value = String(rawValue == null ? '' : rawValue).trim();
    if (!value) return '';
    if (
      value.length >= 2 &&
      ((value[0] === '"' && value[value.length - 1] === '"') || (value[0] === '\'' && value[value.length - 1] === '\''))
    ) {
      value = value.slice(1, -1);
    } else if (value[0] === '"' || value[0] === '\'') {
      value = value.slice(1);
    }
    return value
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t')
      .replace(/\\r/g, '\r')
      .replace(/\\"/g, '"')
      .replace(/\\'/g, '\'')
      .replace(/\\\\/g, '\\');
  }
  function extractLiteralFromRegex(rawPattern, minLen) {
    const minLiteralLen = Math.max(2, Number(minLen || FINGERPRINT_KSCAN_MIN_LITERAL_LEN));
    let text = String(unquoteRuleValue(rawPattern) || '').trim();
    if (!text) return '';
    if (text.startsWith('/') && text.lastIndexOf('/') > 0) {
      text = text.slice(1, text.lastIndexOf('/'));
    }
    text = text
      .replace(/\\\//g, '/')
      .replace(/\\\./g, '.')
      .replace(/\\-/g, '-')
      .replace(/\\_/g, '_')
      .replace(/\\ /g, ' ')
      .replace(/\\x[0-9a-fA-F]{2}/g, ' ')
      .replace(/\\u[0-9a-fA-F]{4}/g, ' ')
      .replace(/\[[^\]]*]/g, ' ')
      .replace(/[\^\$\(\)\{\}\|\?\*\+]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (!text) return '';
    const candidates = (text.match(new RegExp(`[A-Za-z0-9_\\-./\\u4e00-\\u9fa5]{${minLiteralLen},}`, 'g')) || [])
      .map(item => String(item || '').trim())
      .filter(Boolean)
      .filter(item => !FINGERPRINT_GENERIC_WEAK_LITERALS.has(String(item).toLowerCase()));
    if (!candidates.length) return '';
    candidates.sort((a, b) => b.length - a.length);
    return candidates[0];
  }
  function normalizeKscanToken(rawToken, options) {
    const token = String(rawToken || '').trim();
    if (!token) return { fragment: '', reason: 'empty_token' };
    const match = token.match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*(~=|==|!=|=)\s*([\s\S]+)$/);
    if (!match) return { fragment: '', reason: 'invalid_token' };
    const field = normalizeRuleFieldNameStrict(match[1]);
    if (!field) return { fragment: '', reason: 'unsupported_field' };
    let op = String(match[2] || '=').trim();
    let value = String(unquoteRuleValue(match[3]) || '').trim();
    if (!value) return { fragment: '', reason: 'empty_value' };
    if (op === '~=' && String(options?.regexFallback || FINGERPRINT_KSCAN_REGEX_FALLBACK) === 'literal') {
      value = extractLiteralFromRegex(match[3], Number(options?.minLiteralLen || FINGERPRINT_KSCAN_MIN_LITERAL_LEN));
      if (!value) return { fragment: '', reason: 'regex_no_literal' };
      op = '=';
    }
    if (field === 'icon_hash' && op === '=') {
      op = '==';
    }
    if (field === 'icon_hash' && !/^-?\d+$/.test(value)) {
      return { fragment: '', reason: 'icon_hash_not_numeric' };
    }
    return {
      fragment: buildRuleFragment(field, op, value),
      reason: ''
    };
  }
  function normalizeKscanHumanRuleExpression(rawExpression, options) {
    const expression = normalizeRuleExpressionSyntax(rawExpression);
    if (!String(expression || '').trim()) {
      return { expression: '', reason: 'empty_expression' };
    }
    const tokens = tokenizeRuleExpression(expression);
    if (!Array.isArray(tokens) || !tokens.length) {
      return { expression: '', reason: 'invalid_expression' };
    }
    const normalized = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (!token || !token.type) continue;
      if (token.type === 'LPAREN' || token.type === 'RPAREN') {
        normalized.push(token.value);
        continue;
      }
      if (token.type === 'AND' || token.type === 'OR' || token.type === 'NOT') {
        normalized.push(token.value);
        continue;
      }
      if (token.type !== 'ATOM') continue;
      const atom = String(token.value || '').trim();
      if (!atom) continue;
      if (!/(==|!=|~=|=)/.test(atom)) {
        const field = normalizeRuleFieldNameStrict(atom);
        if (!field) return { expression: '', reason: 'unsupported_field' };
        normalized.push(field);
        continue;
      }
      const parsed = normalizeKscanToken(atom, options);
      if (!parsed.fragment) return { expression: '', reason: parsed.reason || 'normalize_failed' };
      normalized.push(parsed.fragment);
    }
    const normalizedExpression = normalized.join(' ').trim();
    if (!normalizedExpression) {
      return { expression: '', reason: 'empty_expression' };
    }
    if (!parseRuleExpression(normalizedExpression)) {
      return { expression: '', reason: 'parse_expression_failed' };
    }
    return {
      expression: normalizedExpression,
      reason: ''
    };
  }
  function coerceFingerprintItems(payload) {
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload?.fingerprint)) return payload.fingerprint;
    return [];
  }
  function normalizeFingerSourceRulesWithStats(payload, options) {
    const grouped = new Map();
    const items = coerceFingerprintItems(payload);
    const maxRulesPerName = Math.max(1, Number(options?.maxRulesPerName || FINGERPRINT_MAX_RULES_PER_NAME));
    const maxTotalRules = Math.max(0, Number(options?.maxTotalRules || FINGERPRINT_MAX_TOTAL_RULES));
    const stats = {
      source: 'finger.json',
      items: items.length,
      skipEmptyName: 0,
      skipEmptyKeyword: 0,
      skipUnsupportedMethod: 0,
      skipUnsupportedLocation: 0,
      skipOverMaxRulesPerName: 0,
      stopByMaxTotalRules: 0
    };
    items.forEach((item) => {
      const method = String(item?.method || '').trim().toLowerCase();
      const location = String(item?.location || '').trim().toLowerCase();
      const name = normalizeFingerprintName(item?.cms || item?.name || '');
      if (!name) {
        stats.skipEmptyName += 1;
        return;
      }
      const keywords = asArray(item?.keyword).map(v => String(v || '').trim()).filter(Boolean);
      if (!keywords.length) {
        stats.skipEmptyKeyword += 1;
        return;
      }
      if (!grouped.has(name)) grouped.set(name, new Set());
      const bucket = grouped.get(name);
      if (method === 'faviconhash') {
        keywords.forEach((keyword) => {
          if (bucket.size >= maxRulesPerName) {
            stats.skipOverMaxRulesPerName += 1;
            return;
          }
          if (/^-?\d+$/.test(keyword)) {
            bucket.add(buildRuleFragment('icon_hash', '==', keyword));
          }
        });
        return;
      }
      if (method !== 'keyword') {
        stats.skipUnsupportedMethod += 1;
        return;
      }
      if (!['body', 'header', 'title', 'cookie'].includes(location)) {
        stats.skipUnsupportedLocation += 1;
        return;
      }
      keywords.forEach((keyword) => {
        if (bucket.size >= maxRulesPerName) {
          stats.skipOverMaxRulesPerName += 1;
          return;
        }
        if (location === 'header') {
          const parsed = parseFingerHeaderKeyword(keyword);
          if (parsed?.header) {
            bucket.add(buildRuleFragment('header', '=', `${parsed.header}: ${parsed.needle}`));
            return;
          }
        }
        bucket.add(buildRuleFragment(location, '=', keyword));
      });
    });
    const rules = [];
    grouped.forEach((fragments, name) => {
      if (maxTotalRules > 0 && rules.length >= maxTotalRules) {
        stats.stopByMaxTotalRules += 1;
        return;
      }
      const expression = Array.from(fragments).join(' || ');
      if (!expression) return;
      if (!parseRuleExpression(expression)) return;
      rules.push({
        name,
        type: inferFingerprintType(name),
        source: 'finger.json',
        expression
      });
    });
    stats.appAccept = rules.length;
    stats.ruleAccept = rules.length;
    return { rules, stats };
  }
  function normalizeFingerSourceRules(payload, options) {
    return normalizeFingerSourceRulesWithStats(payload, options).rules;
  }
  function buildRuleFromStandardItem(item, source) {
    const name = normalizeFingerprintName(item?.name || item?.cms || '');
    if (!name) return null;
    const method = String(item?.method || item?.type || '').trim().toLowerCase();
    const field = normalizeRuleFieldName(method);
    const keywords = asArray(item?.keyword ?? item?.keywords ?? item?.path).map(v => String(v || '').trim()).filter(Boolean);
    if (!keywords.length) return null;
    const fragments = [];
    keywords.forEach((keyword) => {
      if (field === 'icon_hash') {
        if (/^-?\d+$/.test(keyword)) {
          fragments.push(buildRuleFragment('icon_hash', '==', keyword));
        }
      } else {
        fragments.push(buildRuleFragment(field, '=', keyword));
      }
    });
    if (!fragments.length) return null;
    return {
      name,
      type: inferFingerprintType(name),
      source,
      expression: fragments.join(' || ')
    };
  }
  function normalizeKscanSourceRulesWithStats(payload, options) {
    const items = coerceFingerprintItems(payload);
    const grouped = new Map();
    const seen = new Map();
    const maxRulesPerName = Math.max(1, Number(options?.maxRulesPerName || FINGERPRINT_MAX_RULES_PER_NAME));
    const maxTotalRules = Math.max(0, Number(options?.maxTotalRules || FINGERPRINT_MAX_TOTAL_RULES));
    const regexFallback = String(options?.kscanRegexFallback || FINGERPRINT_KSCAN_REGEX_FALLBACK || 'literal').toLowerCase();
    const minLiteralLen = Math.max(2, Number(options?.kscanMinLiteralLen || FINGERPRINT_KSCAN_MIN_LITERAL_LEN));
    const stats = {
      source: 'kscan_fingerprint.json',
      items: items.length,
      skipEmptyName: 0,
      skipNormalizeFailed: 0,
      skipDuplicateRule: 0,
      skipOverMaxRulesPerName: 0,
      stopByMaxTotalRules: 0
    };
    let acceptedRules = 0;
    items.forEach((item) => {
      const name = normalizeFingerprintName(item?.name || item?.cms || '');
      if (!name) {
        stats.skipEmptyName += 1;
        return;
      }
      if (!grouped.has(name)) grouped.set(name, []);
      if (!seen.has(name)) seen.set(name, new Set());
      const nameRules = grouped.get(name);
      const nameSeen = seen.get(name);
      if (nameRules.length >= maxRulesPerName) {
        stats.skipOverMaxRulesPerName += 1;
        return;
      }
      if (maxTotalRules > 0 && acceptedRules >= maxTotalRules) {
        stats.stopByMaxTotalRules += 1;
        return;
      }
      const humanRule = String(item?.human_rule || item?.rule || '').trim();
      let normalizedExpression = '';
      if (humanRule) {
        const normalized = normalizeKscanHumanRuleExpression(humanRule, {
          regexFallback,
          minLiteralLen
        });
        if (!normalized.expression) {
          stats.skipNormalizeFailed += 1;
          return;
        }
        normalizedExpression = normalized.expression;
      } else {
        const derived = buildRuleFromStandardItem(item, 'kscan_fingerprint.json');
        if (!derived?.expression) {
          stats.skipNormalizeFailed += 1;
          return;
        }
        normalizedExpression = String(derived.expression || '').trim();
      }
      if (!normalizedExpression || !parseRuleExpression(normalizedExpression)) {
        stats.skipNormalizeFailed += 1;
        return;
      }
      if (nameSeen.has(normalizedExpression)) {
        stats.skipDuplicateRule += 1;
        return;
      }
      nameSeen.add(normalizedExpression);
      nameRules.push(normalizedExpression);
      acceptedRules += 1;
    });
    const rules = [];
    Array.from(grouped.keys()).sort((a, b) => a.localeCompare(b)).forEach((name) => {
      const list = grouped.get(name) || [];
      if (!list.length) return;
      rules.push({
        name,
        type: inferFingerprintType(name),
        source: 'kscan_fingerprint.json',
        expression: list.join(' || ')
      });
    });
    stats.appAccept = rules.length;
    stats.ruleAccept = acceptedRules;
    return { rules, stats };
  }
  function normalizeKscanSourceRules(payload, options) {
    return normalizeKscanSourceRulesWithStats(payload, options).rules;
  }
  function normalizeWebappSourceRulesWithStats(payload, options) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { rules: [], stats: { source: 'webapp.json', items: 0, appAccept: 0, ruleAccept: 0 } };
    }
    const maxRulesPerName = Math.max(1, Number(options?.maxRulesPerName || FINGERPRINT_MAX_RULES_PER_NAME));
    const maxTotalRules = Math.max(0, Number(options?.maxTotalRules || FINGERPRINT_MAX_TOTAL_RULES));
    const stats = {
      source: 'webapp.json',
      items: Object.keys(payload).length,
      skipEmptyName: 0,
      skipEmptyExpression: 0,
      skipInvalidExpression: 0,
      skipOverMaxRulesPerName: 0,
      stopByMaxTotalRules: 0
    };
    const rules = [];
    Object.entries(payload).forEach(([rawName, config]) => {
      if (maxTotalRules > 0 && rules.length >= maxTotalRules) {
        stats.stopByMaxTotalRules += 1;
        return;
      }
      const name = normalizeFingerprintName(rawName);
      if (!name) {
        stats.skipEmptyName += 1;
        return;
      }
      const fragments = [];
      const pushFragment = (field, rawValue) => {
        if (fragments.length >= maxRulesPerName) {
          stats.skipOverMaxRulesPerName += 1;
          return;
        }
        const value = String(rawValue || '').trim();
        if (!value) return;
        fragments.push(buildRuleFragment(field, '=', value));
      };
      asArray(config?.headers).forEach((item) => pushFragment('header', item));
      asArray(config?.html).forEach((item) => pushFragment('body', item));
      asArray(config?.body).forEach((item) => pushFragment('body', item));
      asArray(config?.title).forEach((item) => pushFragment('title', item));
      asArray(config?.response).forEach((item) => pushFragment('response', item));
      asArray(config?.url).forEach((item) => pushFragment('url', item));
      asArray(config?.icon_hash || config?.faviconhash).forEach((item) => {
        if (fragments.length >= maxRulesPerName) {
          stats.skipOverMaxRulesPerName += 1;
          return;
        }
        const value = String(item || '').trim();
        if (/^-?\d+$/.test(value)) {
          fragments.push(buildRuleFragment('icon_hash', '==', value));
        }
      });
      let expression = fragments.join(' || ');
      if (!expression) {
        const fallback = String(config?.fofa_rule || '').trim();
        if (fallback) {
          expression = normalizeRuleExpressionSyntax(fallback);
        }
      }
      if (!expression) {
        stats.skipEmptyExpression += 1;
        return;
      }
      if (!parseRuleExpression(expression)) {
        stats.skipInvalidExpression += 1;
        return;
      }
      rules.push({
        name,
        type: inferFingerprintType(name),
        source: 'webapp.json',
        expression
      });
    });
    stats.appAccept = rules.length;
    stats.ruleAccept = rules.length;
    return { rules, stats };
  }
  function normalizeWebappSourceRules(payload, options) {
    return normalizeWebappSourceRulesWithStats(payload, options).rules;
  }
  function dedupeNormalizedRules(rules) {
    const seen = new Set();
    const deduped = [];
    asArray(rules).forEach((rule) => {
      const name = String(rule?.name || '').trim();
      const expression = String(rule?.expression || '').trim();
      if (!name || !expression) return;
      const key = `${name.toLowerCase()}|${expression}`;
      if (seen.has(key)) return;
      seen.add(key);
      deduped.push({
        name,
        type: normalizeFingerprintType(rule?.type || inferFingerprintType(name)),
        source: String(rule?.source || 'external'),
        expression
      });
    });
    return deduped;
  }
  function tokenizeRuleExpression(expression) {
    const source = String(expression || '');
    const tokens = [];
    let buffer = '';
    let quote = '';
    let escaped = false;
    const flushBuffer = () => {
      const text = buffer.trim();
      if (text) tokens.push({ type: 'ATOM', value: text });
      buffer = '';
    };
    for (let i = 0; i < source.length; i += 1) {
      const ch = source[i];
      if (quote) {
        buffer += ch;
        if (escaped) {
          escaped = false;
          continue;
        }
        if (ch === '\\') {
          escaped = true;
          continue;
        }
        if (ch === quote) {
          quote = '';
        }
        continue;
      }
      if (ch === '"' || ch === '\'') {
        quote = ch;
        buffer += ch;
        continue;
      }
      if (ch === '(') {
        flushBuffer();
        tokens.push({ type: 'LPAREN', value: ch });
        continue;
      }
      if (ch === ')') {
        flushBuffer();
        tokens.push({ type: 'RPAREN', value: ch });
        continue;
      }
      if (ch === '&' && source[i + 1] === '&') {
        flushBuffer();
        tokens.push({ type: 'AND', value: '&&' });
        i += 1;
        continue;
      }
      if (ch === '|' && source[i + 1] === '|') {
        flushBuffer();
        tokens.push({ type: 'OR', value: '||' });
        i += 1;
        continue;
      }
      if (ch === '!' && source[i + 1] !== '=') {
        flushBuffer();
        tokens.push({ type: 'NOT', value: '!' });
        continue;
      }
      buffer += ch;
    }
    flushBuffer();
    return tokens;
  }
  function parseAtomicCondition(rawAtom) {
    const atom = String(rawAtom || '').trim();
    if (!atom) return null;
    const match = atom.match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*(==|!=|~=|=)\s*([\s\S]+)$/);
    if (!match) {
      const fieldName = normalizeRuleFieldName(atom);
      return { kind: 'var', field: fieldName };
    }
    const field = normalizeRuleFieldName(match[1]);
    const op = match[2];
    let rawValue = String(match[3] || '').trim();
    if (rawValue.length >= 2 && ((rawValue[0] === '"' && rawValue[rawValue.length - 1] === '"') || (rawValue[0] === '\'' && rawValue[rawValue.length - 1] === '\''))) {
      rawValue = rawValue.slice(1, -1);
    } else if (rawValue[0] === '"' || rawValue[0] === '\'') {
      rawValue = rawValue.slice(1);
    }
    rawValue = rawValue
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t')
      .replace(/\\r/g, '\r')
      .replace(/\\"/g, '"')
      .replace(/\\'/g, '\'')
      .replace(/\\\\/g, '\\');
    return {
      kind: 'cmp',
      field,
      op,
      value: rawValue,
      valueLower: String(rawValue || '').toLowerCase()
    };
  }
  function parseRuleExpression(expression) {
    const tokens = tokenizeRuleExpression(normalizeRuleExpressionSyntax(expression));
    const precedence = { OR: 1, AND: 2, NOT: 3 };
    const rightAssoc = new Set(['NOT']);
    const output = [];
    const stack = [];
    tokens.forEach((token) => {
      if (token.type === 'ATOM') {
        output.push(token);
        return;
      }
      if (token.type === 'LPAREN') {
        stack.push(token);
        return;
      }
      if (token.type === 'RPAREN') {
        while (stack.length && stack[stack.length - 1].type !== 'LPAREN') {
          output.push(stack.pop());
        }
        if (stack.length && stack[stack.length - 1].type === 'LPAREN') {
          stack.pop();
        }
        return;
      }
      while (stack.length) {
        const top = stack[stack.length - 1];
        if (!precedence[top.type]) break;
        const topPrec = precedence[top.type];
        const nowPrec = precedence[token.type] || 0;
        if (topPrec > nowPrec || (topPrec === nowPrec && !rightAssoc.has(token.type))) {
          output.push(stack.pop());
        } else {
          break;
        }
      }
      stack.push(token);
    });
    while (stack.length) {
      const token = stack.pop();
      if (token.type === 'LPAREN' || token.type === 'RPAREN') continue;
      output.push(token);
    }
    const astStack = [];
    output.forEach((token) => {
      if (token.type === 'ATOM') {
        const atomNode = parseAtomicCondition(token.value);
        if (atomNode) astStack.push(atomNode);
        return;
      }
      if (token.type === 'NOT') {
        const child = astStack.pop();
        if (child) astStack.push({ kind: 'not', expr: child });
        return;
      }
      if (token.type === 'AND' || token.type === 'OR') {
        const right = astStack.pop();
        const left = astStack.pop();
        if (!left || !right) return;
        astStack.push({
          kind: token.type === 'AND' ? 'and' : 'or',
          left,
          right
        });
      }
    });
    if (astStack.length !== 1) return null;
    return astStack[0];
  }
  function collectRuleAtomNodes(astNode, list, negated) {
    if (!astNode) return;
    if (astNode.kind === 'cmp') {
      list.push({
        field: astNode.field,
        op: astNode.op,
        value: astNode.value,
        valueLower: astNode.valueLower,
        negated: !!negated
      });
      return;
    }
    if (astNode.kind === 'var') {
      list.push({
        field: astNode.field,
        op: '=',
        value: '',
        valueLower: '',
        negated: !!negated
      });
      return;
    }
    if (astNode.kind === 'not') {
      collectRuleAtomNodes(astNode.expr, list, !negated);
      return;
    }
    if (astNode.kind === 'and' || astNode.kind === 'or') {
      collectRuleAtomNodes(astNode.left, list, negated);
      collectRuleAtomNodes(astNode.right, list, negated);
    }
  }
  function getFingerprintFieldText(inputs, field) {
    if (field === 'body') return inputs.bodyText;
    if (field === 'header') return inputs.headerText;
    if (field === 'cookie') return inputs.cookieText;
    if (field === 'title') return inputs.titleText;
    if (field === 'url') return inputs.urlText;
    if (field === 'response') return inputs.responseText;
    if (field === 'script') return inputs.scriptText;
    if (field === 'meta') return inputs.metaText;
    if (field === 'js') return inputs.jsText;
    if (field === 'env') return inputs.envText;
    return '';
  }
  function evaluateAtomicCondition(atom, inputs) {
    if (!atom) return false;
    if (atom.kind === 'var') {
      if (atom.field === 'icon_hash') {
        return inputs.iconHashSet.size > 0;
      }
      return Boolean(getFingerprintFieldText(inputs, atom.field));
    }
    if (atom.field === 'icon_hash') {
      const value = String(atom.value || '').trim();
      const exists = inputs.iconHashSet.has(value);
      if (atom.op === '!=') return !exists;
      return exists;
    }
    const fieldText = getFingerprintFieldText(inputs, atom.field);
    const source = String(fieldText || '').toLowerCase();
    const needle = String(atom.valueLower || '').trim();
    if (atom.op === '==') return source === needle;
    if (atom.op === '!=') return source !== needle;
    if (atom.op === '~=') {
      try {
        return new RegExp(String(atom.value || ''), 'i').test(fieldText);
      } catch {
        return source.includes(needle);
      }
    }
    if (!needle) return Boolean(source);
    return source.includes(needle);
  }
  function evaluateRuleAst(astNode, inputs, traces) {
    if (!astNode) return false;
    if (astNode.kind === 'cmp' || astNode.kind === 'var') {
      const matched = evaluateAtomicCondition(astNode, inputs);
      if (Array.isArray(traces)) {
        traces.push({
          field: astNode.field,
          op: astNode.op || '=',
          value: astNode.value || '',
          matched
        });
      }
      return matched;
    }
    if (astNode.kind === 'not') {
      return !evaluateRuleAst(astNode.expr, inputs, traces);
    }
    if (astNode.kind === 'and') {
      const left = evaluateRuleAst(astNode.left, inputs, traces);
      const right = evaluateRuleAst(astNode.right, inputs, traces);
      return left && right;
    }
    if (astNode.kind === 'or') {
      const left = evaluateRuleAst(astNode.left, inputs, traces);
      const right = evaluateRuleAst(astNode.right, inputs, traces);
      return left || right;
    }
    return false;
  }
  const COOKIE_ATTRIBUTE_KEYS = new Set([
    'path',
    'domain',
    'expires',
    'max-age',
    'secure',
    'httponly',
    'samesite',
    'priority',
    'version',
    'comment'
  ]);
  function appendCookieToken(cookieMap, rawToken, treatBareTokenAsName) {
    if (!(cookieMap instanceof Map)) return;
    let token = String(rawToken || '').trim();
    if (!token) return;
    token = token.replace(/^(?:set-cookie|cookie)\s*:/i, '').trim();
    if (!token) return;
    const equalsIndex = token.indexOf('=');
    if (equalsIndex > 0) {
      const key = String(token.slice(0, equalsIndex) || '').trim().toLowerCase();
      if (!key || COOKIE_ATTRIBUTE_KEYS.has(key)) return;
      const value = String(token.slice(equalsIndex + 1) || '').trim();
      if (!cookieMap.has(key)) {
        cookieMap.set(key, value);
        return;
      }
      const prev = String(cookieMap.get(key) || '');
      if (!prev && value) {
        cookieMap.set(key, value);
      }
      return;
    }
    if (!treatBareTokenAsName) return;
    const key = token.toLowerCase();
    if (!/^[a-z0-9_.-]{1,120}$/.test(key)) return;
    if (!cookieMap.has(key)) {
      cookieMap.set(key, '');
    }
  }
  function parseCookieSourceTextToMap(cookieMap, source, treatBareTokenAsName) {
    const text = String(source || '').trim();
    if (!text) return;
    text
      .split(/[\n\r]+/)
      .forEach((line) => {
        String(line || '')
          .split(';')
          .forEach((token) => appendCookieToken(cookieMap, token, treatBareTokenAsName));
      });
  }
  function buildFingerprintSignalInputs(input) {
    const headersMap = new Map();
    if (input?.headersMap instanceof Map) {
      input.headersMap.forEach((value, key) => {
        headersMap.set(String(key || '').toLowerCase(), String(value || ''));
      });
    }
    const metaMap = new Map();
    if (input?.metaMap instanceof Map) {
      input.metaMap.forEach((value, key) => {
        metaMap.set(String(key || '').toLowerCase(), String(value || ''));
      });
    }
    const scripts = asArray(input?.scripts).map(v => String(v || '')).filter(Boolean);
    const env = asArray(input?.env).map(v => String(v || '')).filter(Boolean);
    const rawJsProbe = input?.jsProbe && typeof input.jsProbe === 'object' ? input.jsProbe : {};
    const jsProbe = Object.create(null);
    Object.entries(rawJsProbe).forEach(([key, value]) => {
      const safeKey = String(key || '').trim();
      if (!safeKey) return;
      jsProbe[safeKey] = value;
      const lowerKey = safeKey.toLowerCase();
      if (!(lowerKey in jsProbe)) {
        jsProbe[lowerKey] = value;
      }
    });
    const iconHashes = asArray(input?.iconHashes).map(v => String(v || '').trim()).filter(Boolean);
    const cookiesMap = new Map();
    if (input?.cookiesMap instanceof Map) {
      input.cookiesMap.forEach((value, key) => {
        const safeKey = String(key || '').trim().toLowerCase();
        if (!safeKey) return;
        cookiesMap.set(safeKey, String(value || ''));
      });
    }
    const headerText = String(input?.headerText || input?.header || '').trim() || Array.from(headersMap.entries()).map(([k, v]) => `${String(k || '').toLowerCase()}: ${String(v || '')}`).join('\n');
    const metaText = String(input?.metaText || '').trim() || Array.from(metaMap.entries()).map(([k, v]) => `${String(k || '').toLowerCase()}=${String(v || '')}`).join('\n');
    const jsText = Object.entries(rawJsProbe).slice(0, WAPPALYZER_MAX_JS_PROBES).map(([k, v]) => `${k}=${String(v == null ? '' : v)}`).join('\n');
    const bodyText = String(input?.bodyText || input?.body || input?.html || '');
    const titleText = String(input?.titleText || input?.title || '');
    const urlText = String(input?.urlText || input?.url || '');
    const scriptText = scripts.join('\n');
    const envText = env.join('\n');
    let cookieText = String(input?.cookieText || input?.cookie || '').trim();
    asArray(input?.cookies).forEach((item) => {
      parseCookieSourceTextToMap(cookiesMap, item, true);
    });
    if (cookieText) {
      parseCookieSourceTextToMap(cookiesMap, cookieText, true);
    }
    const rawCookieHeader = String(headersMap.get('cookie') || '').trim();
    const rawSetCookieHeader = String(headersMap.get('set-cookie') || '').trim();
    if (rawCookieHeader) {
      parseCookieSourceTextToMap(cookiesMap, rawCookieHeader, true);
      if (!cookieText) cookieText = rawCookieHeader;
    }
    if (rawSetCookieHeader) {
      parseCookieSourceTextToMap(cookiesMap, rawSetCookieHeader, true);
      if (!cookieText) cookieText = rawSetCookieHeader;
    }
    if (!cookieText && cookiesMap.size > 0) {
      cookieText = Array.from(cookiesMap.entries()).map(([k, v]) => (v ? `${k}=${v}` : k)).join('; ');
    }
    const responseText = String(input?.responseText || '').trim() || [headerText, cookieText, bodyText].filter(Boolean).join('\n');
    return {
      bodyText,
      titleText,
      headerText,
      cookieText,
      urlText,
      responseText,
      scriptText,
      metaText,
      jsText,
      envText,
      scripts,
      env,
      jsProbe,
      headersMap,
      metaMap,
      cookiesMap,
      iconHashSet: new Set(iconHashes)
    };
  }
  function estimateMatchScore(meta, traces) {
    const matchedFields = new Set();
    const matchedWeakValues = [];
    let matchedBodyGenericCount = 0;
    let matchedShortLiteralCount = 0;
    let longestMatchedLiteralLength = 0;
    let bodyLiteralTraceCount = 0;
    asArray(traces).forEach((trace) => {
      if (!trace?.matched) return;
      const field = normalizeRuleFieldName(trace.field);
      matchedFields.add(field);
      const valueLower = String(trace.value || '').trim().toLowerCase();
      if (!valueLower) return;
      longestMatchedLiteralLength = Math.max(longestMatchedLiteralLength, valueLower.length);
      if (field === 'body') {
        bodyLiteralTraceCount += 1;
      }
      if (valueLower.length <= Math.max(2, FINGERPRINT_WEAK_KEYWORD_MIN_LEN - 1)) {
        matchedShortLiteralCount += 1;
      }
      if (field === 'body' && FINGERPRINT_GENERIC_WEAK_LITERALS.has(valueLower)) {
        matchedBodyGenericCount += 1;
      }
      if (valueLower.length < FINGERPRINT_WEAK_KEYWORD_MIN_LEN || FINGERPRINT_WEAK_KEYWORDS.has(valueLower)) {
        matchedWeakValues.push(valueLower);
      }
    });
    let base = 70;
    if (matchedFields.has('icon_hash')) {
      base = 95;
    } else if ((matchedFields.has('header') || matchedFields.has('cookie')) && ['body', 'title', 'response', 'url', 'meta', 'script', 'js', 'env'].some(field => matchedFields.has(field))) {
      base = 90;
    } else if (matchedFields.has('response')) {
      base = 86;
    } else if (matchedFields.has('header')) {
      base = 82;
    } else if (matchedFields.has('cookie')) {
      base = 80;
    } else if (matchedFields.has('title')) {
      base = 78;
    } else if (matchedFields.has('url')) {
      base = 76;
    } else if (['body', 'meta', 'script', 'js', 'env'].some(field => matchedFields.has(field))) {
      base = 72;
    }
    const fragments = Math.max(Number(meta?.fragmentCount || 1), 1);
    const bonus = Math.min(Math.max(fragments - 1, 0) * 2, 8);
    const bodyOnly = matchedFields.size === 1 && matchedFields.has('body');
    let score = base + bonus;
    if (String(meta?.source || '').includes('kscan')) score += 1;
    if (String(meta?.source || '').includes('finger')) score += 1;
    if (matchedWeakValues.length > 0 && matchedFields.size <= 2 && !matchedFields.has('header') && !matchedFields.has('cookie') && !matchedFields.has('icon_hash')) {
      score -= Math.min(18, matchedWeakValues.length * 6);
    }
    if (matchedFields.size === 1 && matchedFields.has('body') && matchedBodyGenericCount > 0) {
      score -= Math.min(16, matchedBodyGenericCount * 8);
    }
    if (matchedFields.size <= 1 && matchedShortLiteralCount > 0 && !matchedFields.has('icon_hash') && !matchedFields.has('cookie')) {
      score -= Math.min(12, matchedShortLiteralCount * 4);
    }
    if (bodyOnly) {
      if (fragments <= 1) {
        score -= 4;
      }
      if (bodyLiteralTraceCount <= 1 && longestMatchedLiteralLength <= 8) {
        score -= 6;
      } else if (bodyLiteralTraceCount <= 1 && longestMatchedLiteralLength >= 12) {
        score += 3;
      }
      if (bodyLiteralTraceCount <= 1 && longestMatchedLiteralLength >= 18) {
        score += 2;
      }
      const bodyAnchorPopularity = Number(meta?.bodyAnchorPopularity || meta?.anchorPopularity || 0);
      if (bodyAnchorPopularity >= 20) {
        score -= 18;
      } else if (bodyAnchorPopularity >= 12) {
        score -= 12;
      } else if (bodyAnchorPopularity >= 8) {
        score -= 8;
      } else if (bodyAnchorPopularity > 0 && bodyAnchorPopularity <= 2 && longestMatchedLiteralLength >= 10) {
        score += 2;
      }
    }
    return {
      score: clampNumber(score, 20, 99),
      matchedFields: Array.from(matchedFields),
      weakSignals: matchedWeakValues.concat(matchedBodyGenericCount > 0 ? ['generic-body-literal'] : [])
    };
  }
  function buildNormalizedRuleStore(payloadMap, options) {
    const payloads = payloadMap && typeof payloadMap === 'object' ? payloadMap : {};
    const fingerPayload = payloads['finger.json'] || payloads.finger || null;
    const kscanPayload = payloads['kscan_fingerprint.json'] || payloads.kscan || null;
    const webappPayload = payloads['webapp.json'] || payloads.webapp || null;
    const fingerNormalized = normalizeFingerSourceRulesWithStats(fingerPayload, options);
    const kscanNormalized = normalizeKscanSourceRulesWithStats(kscanPayload, options);
    const webappNormalized = normalizeWebappSourceRulesWithStats(webappPayload, options);
    const rules = dedupeNormalizedRules([
      ...fingerNormalized.rules,
      ...kscanNormalized.rules,
      ...webappNormalized.rules
    ]);
    return {
      version: FINGERPRINT_RULE_CACHE_VERSION,
      generatedAt: Date.now(),
      rules,
      stats: {
        total: rules.length,
        finger: rules.filter(item => item.source === 'finger.json').length,
        kscan: rules.filter(item => item.source === 'kscan_fingerprint.json').length,
        webapp: rules.filter(item => item.source === 'webapp.json').length,
        sourceStats: {
          finger: fingerNormalized.stats,
          kscan: kscanNormalized.stats,
          webapp: webappNormalized.stats
        }
      }
    };
  }
  function compileNormalizedRuleStore(store) {
    const sourceStore = store && typeof store === 'object' ? store : { rules: [] };
    const compiledRules = [];
    asArray(sourceStore.rules).forEach((rule, index) => {
      const expression = String(rule?.expression || '').trim();
      if (!expression) return;
      const ast = parseRuleExpression(expression);
      if (!ast) return;
      const atoms = [];
      collectRuleAtomNodes(ast, atoms, false);
      const positiveAnchors = atoms
        .filter(item => !item.negated && item.op !== '!=' && String(item.valueLower || '').length >= 3)
        .map(item => ({ field: item.field, needle: String(item.valueLower || '') }))
        .sort((a, b) => b.needle.length - a.needle.length);
      compiledRules.push({
        id: `${String(rule?.source || 'ext')}#${index}`,
        name: String(rule?.name || '').trim(),
        type: normalizeFingerprintType(rule?.type || inferFingerprintType(rule?.name || '')),
        source: String(rule?.source || 'external'),
        expression,
        ast,
        atoms,
        fragmentCount: atoms.length || 1,
        anchor: positiveAnchors[0] || null,
        positiveAnchors
      });
    });
    const anchorPopularity = buildAnchorPopularityStats(compiledRules);
    compiledRules.forEach((rule) => {
      const anchorValues = asArray(rule?.positiveAnchors)
        .map((anchor) => Number(anchorPopularity.get(`${normalizeRuleFieldName(anchor?.field)}|${String(anchor?.needle || '').trim()}`) || 0))
        .filter(value => Number.isFinite(value) && value > 0);
      const bodyAnchorValues = asArray(rule?.positiveAnchors)
        .filter(anchor => normalizeRuleFieldName(anchor?.field) === 'body')
        .map((anchor) => Number(anchorPopularity.get(`body|${String(anchor?.needle || '').trim()}`) || 0))
        .filter(value => Number.isFinite(value) && value > 0);
      rule.anchorPopularity = anchorValues.length ? Math.max(...anchorValues) : 0;
      rule.bodyAnchorPopularity = bodyAnchorValues.length ? Math.max(...bodyAnchorValues) : 0;
    });
    return {
      version: sourceStore.version || FINGERPRINT_RULE_CACHE_VERSION,
      generatedAt: sourceStore.generatedAt || Date.now(),
      stats: sourceStore.stats || {},
      rules: compiledRules
    };
  }
  function applyFingerprintMutualExclusion(results) {
    const source = asArray(results);
    if (!source.length) return [];
    const byName = new Map();
    source.forEach((item) => {
      const key = normalizeFingerprintIdentityKey(item?.name || '');
      if (!key) return;
      const prev = byName.get(key);
      if (!prev || computeFingerprintHitSpecificity(item) > computeFingerprintHitSpecificity(prev)) {
        byName.set(key, item);
      }
    });
    const deduped = collapseSimilarFingerprintHits(Array.from(byName.values()));
    const keepName = new Set(deduped.map(item => String(item.name || '').toLowerCase()));
    FINGERPRINT_MUTEX_GROUPS.forEach((group) => {
      const hits = group
        .map(name => deduped.find(item => String(item.name || '').toLowerCase() === String(name).toLowerCase()))
        .filter(Boolean)
        .sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
      if (hits.length <= 1) return;
      const preserve = String(hits[0].name || '').toLowerCase();
      hits.slice(1).forEach((item) => {
        const key = String(item.name || '').toLowerCase();
        if (preserve === 'openresty' && key === 'nginx') return;
        if (preserve === 'tengine' && key === 'nginx') return;
        keepName.delete(key);
      });
    });
    return deduped
      .filter(item => keepName.has(String(item.name || '').toLowerCase()))
      .sort((a, b) => Number(b.score || 0) - Number(a.score || 0) || String(a.name || '').localeCompare(String(b.name || '')));
  }
  function matchCompiledRuleStore(compiledStore, input, options) {
    const store = compiledStore && typeof compiledStore === 'object' ? compiledStore : { rules: [] };
    const threshold = clampNumber(Number(options?.threshold || FINGERPRINT_SCORE_THRESHOLD), 20, 99);
    const includeLowScore = !!options?.includeLowScore;
    const signalInput = buildFingerprintSignalInputs(input);
    const hits = [];
    asArray(store.rules).forEach((rule) => {
      if (!rule?.name || !rule.ast) return;
      if (rule.anchor) {
        const anchorText = getFingerprintFieldText(signalInput, rule.anchor.field).toLowerCase();
        if (!anchorText.includes(rule.anchor.needle)) return;
      }
      const traces = [];
      const matched = evaluateRuleAst(rule.ast, signalInput, traces);
      if (!matched) return;
      const scoreMeta = estimateMatchScore(rule, traces);
      if (!includeLowScore && scoreMeta.score < threshold) return;
      hits.push({
        id: rule.id,
        name: rule.name,
        type: rule.type,
        source: rule.source,
        expression: rule.expression,
        score: scoreMeta.score,
        confidence: scoreMeta.score >= 90 ? 'high' : scoreMeta.score >= 75 ? 'medium' : 'low',
        matchedFields: scoreMeta.matchedFields,
        weakSignals: scoreMeta.weakSignals,
        traces: traces.filter(item => item?.matched).slice(0, 12)
      });
    });
    return applyFingerprintMutualExclusion(hits);
  }
  function parseWappalyzerPattern(rawPattern) {
    const text = String(rawPattern || '').trim();
    if (!text) {
      return {
        string: '',
        regex: null,
        confidence: 100,
        version: ''
      };
    }
    const fragments = text.split('\\;');
    const patternText = String(fragments.shift() || '').trim();
    const attrs = {
      string: patternText,
      regex: null,
      confidence: 100,
      version: ''
    };
    try {
      attrs.regex = patternText ? new RegExp(patternText.replace('/', '\\/'), 'i') : null;
    } catch {
      attrs.regex = null;
    }
    fragments.forEach((item) => {
      const part = String(item || '').trim();
      if (!part) return;
      const splitIndex = part.indexOf(':');
      if (splitIndex <= 0) return;
      const key = String(part.slice(0, splitIndex) || '').trim().toLowerCase();
      const value = String(part.slice(splitIndex + 1) || '').trim();
      if (!key) return;
      if (key === 'confidence') {
        attrs.confidence = clampNumber(Number(value || 100), 0, 100);
        return;
      }
      if (key === 'version') {
        attrs.version = value;
      }
    });
    return attrs;
  }
  function parseWappalyzerPatternList(patterns) {
    return asArray(patterns)
      .map(item => parseWappalyzerPattern(item))
      .filter(item => item != null);
  }
  function parseWappalyzerPatternMap(record, options) {
    const map = Object.create(null);
    const lowerCaseKeys = options?.lowerCaseKeys !== false;
    if (!record || typeof record !== 'object') return map;
    Object.entries(record).forEach(([key, value]) => {
      const list = parseWappalyzerPatternList(value);
      if (!list.length) return;
      const safeKey = lowerCaseKeys ? String(key || '').toLowerCase() : String(key || '');
      if (!safeKey) return;
      map[safeKey] = list;
    });
    return map;
  }
  function parseWappalyzerRelationList(value) {
    return asArray(value).map((item) => {
      const parsed = parseWappalyzerPattern(item);
      const name = String(parsed?.string || '').trim();
      if (!name) return null;
      return {
        name,
        confidence: clampNumber(Number(parsed?.confidence || 100), 0, 100)
      };
    }).filter(Boolean);
  }
  function inferFingerprintTypeFromCategoryText(categoryText, fallbackName) {
    const text = String(categoryText || '').toLowerCase();
    if (/web server|reverse proxy|cdn/.test(text)) return 'server';
    if (/programming language|language/.test(text)) return 'technology';
    if (/javascript framework|web framework|framework|cms/.test(text)) return 'framework';
    if (/analytics/.test(text)) return 'analytics';
    if (/security|waf|firewall/.test(text)) return 'security';
    if (/operating system/.test(text)) return 'os';
    return inferFingerprintType(fallbackName || '');
  }
  function normalizeWappalyzerCatalog(payload) {
    const source = payload && typeof payload === 'object' ? payload : {};
    const fallback = DEFAULT_WAPPALYZER_APPS;
    const appsObject = source?.apps && typeof source.apps === 'object'
      ? source.apps
      : (source && Object.keys(source).length > 0 ? source : fallback.apps);
    const categories = source?.categories && typeof source.categories === 'object'
      ? source.categories
      : fallback.categories;
    const apps = [];
    if (!appsObject || typeof appsObject !== 'object') {
      return { apps, categories };
    }
    Object.entries(appsObject).forEach(([appName, app]) => {
      if (!app || typeof app !== 'object') return;
      const catIds = asArray(app.cats).map(v => String(v || '').trim()).filter(Boolean);
      const catNames = catIds
        .map(id => String(categories?.[id]?.name || '').trim())
        .filter(Boolean);
      const inferredType = inferFingerprintTypeFromCategoryText(catNames.join(' '), appName);
      apps.push({
        name: String(appName || '').trim(),
        type: inferredType,
        website: String(app?.website || '').trim(),
        categories: catNames,
        url: parseWappalyzerPatternList(app?.url),
        html: parseWappalyzerPatternList(app?.html),
        script: parseWappalyzerPatternList(app?.script),
        env: parseWappalyzerPatternList(app?.env),
        headers: parseWappalyzerPatternMap(app?.headers),
        cookies: parseWappalyzerPatternMap(app?.cookies),
        meta: parseWappalyzerPatternMap(app?.meta),
        js: parseWappalyzerPatternMap(app?.js, { lowerCaseKeys: false }),
        implies: parseWappalyzerRelationList(app?.implies),
        excludes: parseWappalyzerRelationList(app?.excludes)
      });
    });
    return { apps, categories };
  }
  function applyWappalyzerVersionTemplate(template, matchResult) {
    let version = String(template || '');
    if (!version || !Array.isArray(matchResult) || !matchResult.length) return '';
    matchResult.forEach((item, index) => {
      const token = new RegExp(`\\\\${index}`, 'g');
      version = version.replace(token, item || '');
      const ternary = new RegExp(`\\\\${index}\\?([^:]+):(.*)$`).exec(version);
      if (ternary && ternary.length === 3) {
        version = version.replace(ternary[0], item ? ternary[1] : ternary[2]);
      }
    });
    return String(version || '').trim();
  }
  function matchWappalyzerPatternAgainstValue(pattern, value) {
    const source = String(value == null ? '' : value);
    if (!source) {
      return {
        matched: false,
        matchResult: []
      };
    }
    if (pattern?.regex instanceof RegExp) {
      pattern.regex.lastIndex = 0;
      const matchResult = pattern.regex.exec(source);
      if (matchResult) {
        return {
          matched: true,
          matchResult
        };
      }
    }
    if (!pattern?.string) {
      return {
        matched: Boolean(source),
        matchResult: []
      };
    }
    const matched = source.toLowerCase().includes(String(pattern.string || '').toLowerCase());
    return {
      matched,
      matchResult: []
    };
  }
  function matchWappalyzerCatalog(catalog, input, options) {
    const sourceCatalog = catalog && typeof catalog === 'object' ? catalog : { apps: [] };
    const signalInput = buildFingerprintSignalInputs(input);
    const threshold = clampNumber(Number(options?.threshold || FINGERPRINT_SCORE_THRESHOLD), 20, 99);
    const includeLowScore = !!options?.includeLowScore;
    const matchedMap = new Map();
    const registerMatch = (app, context, pattern, value, matchResult) => {
      const key = String(app?.name || '').trim().toLowerCase();
      if (!key) return;
      if (!matchedMap.has(key)) {
        matchedMap.set(key, {
          name: app.name,
          type: normalizeFingerprintType(app.type || inferFingerprintType(app.name)),
          source: 'wappalyzer',
          score: 0,
          confidence: 'low',
          evidence: [],
          versions: new Set(),
          implies: asArray(app.implies),
          excludes: asArray(app.excludes)
        });
      }
      const target = matchedMap.get(key);
      const confidenceDelta = clampNumber(Number(pattern?.confidence || 100), 0, 100);
      target.score = clampNumber(Number(target.score || 0) + confidenceDelta, 0, 100);
      target.evidence.push({
        context,
        value: String(value == null ? '' : value).slice(0, 220)
      });
      const version = applyWappalyzerVersionTemplate(pattern?.version || '', matchResult);
      if (version) target.versions.add(version);
    };
    asArray(sourceCatalog.apps).forEach((app) => {
      if (!app?.name) return;
      asArray(app.url).forEach((pattern) => {
        const result = matchWappalyzerPatternAgainstValue(pattern, signalInput.urlText);
        if (result.matched) registerMatch(app, 'url', pattern, signalInput.urlText, result.matchResult);
      });
      asArray(app.html).forEach((pattern) => {
        const result = matchWappalyzerPatternAgainstValue(pattern, signalInput.bodyText);
        if (result.matched) registerMatch(app, 'html', pattern, signalInput.bodyText, result.matchResult);
      });
      asArray(app.script).forEach((pattern) => {
        signalInput.scripts.some((scriptValue) => {
          const result = matchWappalyzerPatternAgainstValue(pattern, scriptValue);
          if (!result.matched) return false;
          registerMatch(app, 'script', pattern, scriptValue, result.matchResult);
          return false;
        });
      });
      Object.entries(app.headers || {}).forEach(([headerName, patterns]) => {
        const value = signalInput.headersMap.get(String(headerName || '').toLowerCase()) || '';
        asArray(patterns).forEach((pattern) => {
          const result = matchWappalyzerPatternAgainstValue(pattern, value);
          if (result.matched) registerMatch(app, `header:${headerName}`, pattern, value, result.matchResult);
        });
      });
      Object.entries(app.cookies || {}).forEach(([cookieName, patterns]) => {
        const key = String(cookieName || '').toLowerCase();
        if (!key) return;
        const exists = signalInput.cookiesMap.has(key);
        const value = signalInput.cookiesMap.get(key) || '';
        asArray(patterns).forEach((pattern) => {
          // Wappalyzer cookies often use empty pattern to express presence-only match.
          if ((!pattern?.string && !(pattern?.regex instanceof RegExp)) && exists) {
            registerMatch(app, `cookie:${cookieName}`, pattern, value || key, []);
            return;
          }
          const result = matchWappalyzerPatternAgainstValue(pattern, value);
          if (result.matched) registerMatch(app, `cookie:${cookieName}`, pattern, value, result.matchResult);
        });
      });
      Object.entries(app.meta || {}).forEach(([metaName, patterns]) => {
        const value = signalInput.metaMap.get(String(metaName || '').toLowerCase()) || '';
        asArray(patterns).forEach((pattern) => {
          const result = matchWappalyzerPatternAgainstValue(pattern, value);
          if (result.matched) registerMatch(app, `meta:${metaName}`, pattern, value, result.matchResult);
        });
      });
      Object.entries(app.js || {}).forEach(([jsPath, patterns]) => {
        const value = signalInput.jsProbe[jsPath] != null
          ? signalInput.jsProbe[jsPath]
          : signalInput.jsProbe[String(jsPath || '').toLowerCase()];
        asArray(patterns).forEach((pattern) => {
          const result = matchWappalyzerPatternAgainstValue(pattern, value);
          if (result.matched) registerMatch(app, `js:${jsPath}`, pattern, value, result.matchResult);
        });
      });
      const envCandidates = asArray(signalInput.env).length ? asArray(signalInput.env) : [signalInput.envText];
      asArray(app.env).forEach((pattern) => {
        let matched = false;
        envCandidates.some((candidate) => {
          const result = matchWappalyzerPatternAgainstValue(pattern, candidate);
          if (!result.matched) return false;
          registerMatch(app, 'env', pattern, candidate, result.matchResult);
          matched = true;
          return true;
        });
        if (!matched) {
          const result = matchWappalyzerPatternAgainstValue(pattern, signalInput.envText);
          if (result.matched) registerMatch(app, 'env', pattern, signalInput.envText, result.matchResult);
        }
      });
    });
    const filtered = Array.from(matchedMap.values()).map((item) => {
      const score = clampNumber(Number(item.score || 0), 0, 100);
      return {
        name: item.name,
        type: item.type,
        source: item.source,
        score,
        confidence: score >= 90 ? 'high' : score >= 75 ? 'medium' : 'low',
        matchedFields: Array.from(new Set(asArray(item.evidence).map(e => String(e?.context || '').split(':')[0]).filter(Boolean))),
        traces: asArray(item.evidence).slice(0, 12),
        version: Array.from(item.versions).sort((a, b) => String(b).length - String(a).length)[0] || '',
        implies: item.implies,
        excludes: item.excludes
      };
    }).filter((item) => includeLowScore || item.score >= threshold);
    const appMap = new Map(asArray(sourceCatalog.apps).map(app => [String(app?.name || '').trim().toLowerCase(), app]));
    const resolved = new Map(filtered.map(item => [String(item.name || '').toLowerCase(), item]));
    let changed = true;
    let loop = 0;
    while (changed && loop < 6) {
      loop += 1;
      changed = false;
      Array.from(resolved.values()).forEach((item) => {
        asArray(item.implies).forEach((implied) => {
          const impliedName = String(implied?.name || '').trim();
          if (!impliedName) return;
          const impliedKey = impliedName.toLowerCase();
          const impliedScore = clampNumber(Number(item.score || 0) * (Number(implied?.confidence || 100) / 100), 0, 100);
          if (!includeLowScore && impliedScore < threshold) return;
          const existing = resolved.get(impliedKey);
          if (!existing) {
            const def = appMap.get(impliedKey);
            resolved.set(impliedKey, {
              name: impliedName,
              type: normalizeFingerprintType(def?.type || inferFingerprintType(impliedName)),
              source: 'wappalyzer-implied',
              score: impliedScore,
              confidence: impliedScore >= 90 ? 'high' : impliedScore >= 75 ? 'medium' : 'low',
              matchedFields: ['implies'],
              traces: [{ context: 'implies', value: item.name }],
              implies: asArray(def?.implies),
              excludes: asArray(def?.excludes)
            });
            changed = true;
            return;
          }
          if (impliedScore > Number(existing.score || 0)) {
            existing.score = impliedScore;
            existing.confidence = impliedScore >= 90 ? 'high' : impliedScore >= 75 ? 'medium' : 'low';
            existing.traces = asArray(existing.traces).concat([{ context: 'implies', value: item.name }]).slice(0, 12);
            changed = true;
          }
        });
      });
    }
    const excludedKeys = new Set();
    Array.from(resolved.values()).forEach((item) => {
      asArray(item.excludes).forEach((excluded) => {
        const key = String(excluded?.name || '').trim().toLowerCase();
        if (key) excludedKeys.add(key);
      });
    });
    excludedKeys.forEach((key) => resolved.delete(key));
    return applyFingerprintMutualExclusion(Array.from(resolved.values()));
  }
  function extractWappalyzerJsProbePaths(catalog, maxCount) {
    const max = Math.max(1, Number(maxCount || WAPPALYZER_MAX_JS_PROBES));
    const set = new Set();
    asArray(catalog?.apps).forEach((app) => {
      Object.keys(app?.js || {}).forEach((path) => {
        if (set.size < max) set.add(path);
      });
    });
    return Array.from(set);
  }
  function readObjectPathValue(target, path) {
    const source = target && typeof target === 'object' ? target : {};
    const segments = String(path || '').split('.').map(item => String(item || '').trim()).filter(Boolean);
    if (!segments.length) return undefined;
    let current = source;
    for (let i = 0; i < segments.length; i += 1) {
      const segment = segments[i];
      if (current == null) return undefined;
      try {
        current = current[segment];
      } catch {
        return undefined;
      }
    }
    return current;
  }
  function collectWappalyzerJsProbeValues(catalog, globalObject, maxCount) {
    const result = Object.create(null);
    const paths = extractWappalyzerJsProbePaths(catalog, maxCount);
    paths.forEach((path) => {
      const value = readObjectPathValue(globalObject, path);
      if (value == null) return;
      if (typeof value === 'function') {
        result[path] = 'function';
        return;
      }
      if (typeof value === 'object') {
        try {
          result[path] = JSON.stringify(value).slice(0, 280);
        } catch {
          result[path] = Object.prototype.toString.call(value);
        }
        return;
      }
      result[path] = String(value).slice(0, 280);
    });
    return result;
  }
  function buildUnifiedCompiledFingerprintStore(payloadMap, options) {
    const payloads = payloadMap && typeof payloadMap === 'object' ? payloadMap : {};
    const normalizedRuleStore = buildNormalizedRuleStore(payloads, options);
    const compiledRuleStore = compileNormalizedRuleStore(normalizedRuleStore);
    const wappPayload = payloads['apps.json'] || payloads['wappalyzer_apps.json'] || payloads.wappalyzer || {};
    const wappalyzerCatalog = normalizeWappalyzerCatalog(wappPayload);
    return {
      version: compiledRuleStore.version,
      generatedAt: compiledRuleStore.generatedAt,
      stats: {
        ...(compiledRuleStore.stats || {}),
        wappalyzer: asArray(wappalyzerCatalog.apps).length
      },
      rules: compiledRuleStore.rules,
      wappalyzerCatalog,
      normalizedRuleStore
    };
  }
  function mergeFingerprintHitResults() {
    const lists = Array.from(arguments);
    const merged = new Map();
    lists.forEach((list) => {
      asArray(list).forEach((item) => {
        const key = normalizeFingerprintIdentityKey(item?.name || '');
        if (!key) return;
        const current = merged.get(key);
        if (!current) {
          merged.set(key, {
            ...item,
            matchedFields: Array.from(new Set(asArray(item?.matchedFields))),
            traces: asArray(item?.traces).slice(0, 12)
          });
          return;
        }
        if (computeFingerprintHitSpecificity(item) > computeFingerprintHitSpecificity(current)) {
          merged.set(key, {
            ...item,
            matchedFields: Array.from(new Set([...asArray(current?.matchedFields), ...asArray(item?.matchedFields)])),
            traces: [...asArray(current?.traces), ...asArray(item?.traces)].slice(0, 12)
          });
          return;
        }
        current.matchedFields = Array.from(new Set([...asArray(current.matchedFields), ...asArray(item?.matchedFields)]));
        current.traces = [...asArray(current.traces), ...asArray(item?.traces)].slice(0, 12);
      });
    });
    return applyFingerprintMutualExclusion(Array.from(merged.values()));
  }
  function detectFingerprintsWithUnifiedStore(store, input, options) {
    const runtimeStore = store && typeof store === 'object' ? store : { rules: [], wappalyzerCatalog: { apps: [] } };
    const expressionHits = matchCompiledRuleStore({ rules: runtimeStore.rules }, input, options);
    const wappalyzerHits = matchWappalyzerCatalog(runtimeStore.wappalyzerCatalog, input, options);
    return mergeFingerprintHitResults(expressionHits, wappalyzerHits);
  }

  global.SNOWEYES_FINGERPRINT = Object.freeze({
    constants: Object.freeze({
      FINGERPRINT_LIBRARY_URL,
      FINGERPRINT_LIBRARY_FILES,
      FINGERPRINT_RULE_CACHE_VERSION,
      FINGERPRINT_SCORE_THRESHOLD,
      FINGERPRINT_MAX_RULES_PER_NAME,
      FINGERPRINT_MAX_TOTAL_RULES,
      FINGERPRINT_KSCAN_REGEX_FALLBACK,
      FINGERPRINT_KSCAN_MIN_LITERAL_LEN,
      TYPE_BUCKETS
    }),
    DEFAULT_FINGERPRINT_CONFIG,
    utils: Object.freeze({
      createDescriptionMap,
      normalizeFingerprintType,
      getTypeDescription,
      createRuntimeFingerprintConfig,
      normalizeFingerprintName,
      inferFingerprintType,
      normalizeKeywordNeedle,
      buildAnalyticsPatterns,
      parseFingerHeaderKeyword,
      sanitizeExternalHeaderRecord,
      normalizeExternalHeaderIndex,
      buildExternalHeaderIndexFromFingerprintList,
      buildKeywordPrefixIndex,
      matchKeywordIndex,
      sampleBodyHtmlForFingerprint,
      buildFaviconHashIndexFromFingerprintList,
      extractIndexesFromPayload,
      hashHeaderMapSignature,
      matchExternalHeaderFingerprints,
      identifyTechnologyFromCookie,
      applyHeaderFingerprints,
      wrapBase64LikePython,
      murmurhash3_32_gc,
      toSignedInt32,
      computeFaviconHashCandidates,
      clampNumber,
      asArray,
      escapeRuleValue,
      tryParseJsonObject,
      normalizeRuleFieldName,
      normalizeRuleFieldNameStrict,
      normalizeRuleExpressionSyntax,
      buildRuleFragment,
      unquoteRuleValue,
      extractLiteralFromRegex,
      normalizeKscanToken,
      normalizeKscanHumanRuleExpression,
      coerceFingerprintItems,
      normalizeFingerSourceRules,
      normalizeFingerSourceRulesWithStats,
      normalizeKscanSourceRules,
      normalizeKscanSourceRulesWithStats,
      normalizeWebappSourceRules,
      normalizeWebappSourceRulesWithStats,
      dedupeNormalizedRules,
      tokenizeRuleExpression,
      parseAtomicCondition,
      parseRuleExpression,
      collectRuleAtomNodes,
      evaluateAtomicCondition,
      evaluateRuleAst,
      buildFingerprintSignalInputs,
      estimateMatchScore,
      buildNormalizedRuleStore,
      compileNormalizedRuleStore,
      applyFingerprintMutualExclusion,
      matchCompiledRuleStore,
      parseWappalyzerPattern,
      parseWappalyzerPatternList,
      parseWappalyzerPatternMap,
      parseWappalyzerRelationList,
      inferFingerprintTypeFromCategoryText,
      normalizeWappalyzerCatalog,
      applyWappalyzerVersionTemplate,
      matchWappalyzerPatternAgainstValue,
      matchWappalyzerCatalog,
      extractWappalyzerJsProbePaths,
      readObjectPathValue,
      collectWappalyzerJsProbeValues,
      buildUnifiedCompiledFingerprintStore,
      mergeFingerprintHitResults,
      detectFingerprintsWithUnifiedStore
    })
  });
})(globalThis);
