export function createDomxssAssistService(options = {}) {
  const chromeApi = options.chromeApi || chrome;
function pickXssPayloadDetail(report = {}) {
  const payloadHint = String(report.payloadHint || '').trim();
  if (payloadHint) {
    return {
      payload: payloadHint,
      reason: String(report.payloadReason || '').trim() || '来自扫描阶段语义推断',
      profile: String(report.payloadProfile || '').trim() || 'from-scan'
    };
  }

  const sink = String(report.sinkPoint || '').toLowerCase();
  const payloadProfile = String(report.payloadProfile || '').toLowerCase();
  if (sink.includes('href') || sink.includes('location')) {
    return { payload: 'javascript:alert(document.domain)', reason: '按 sink 类型兜底（href/location）', profile: 'fallback-href' };
  }
  if (
    sink.includes('eval') ||
    sink.includes('function') ||
    sink.includes('settimeout') ||
    sink.includes('setinterval') ||
    sink.includes('onevent') ||
    sink.includes('setattribute(on*)') ||
    payloadProfile.includes('code') ||
    payloadProfile.includes('event-handler')
  ) {
    return { payload: 'alert(document.domain)', reason: '按 sink 类型兜底（代码/事件执行）', profile: 'fallback-js' };
  }
  return { payload: '<svg/onload=alert(document.domain)>', reason: '通用兜底 payload', profile: 'fallback-html' };
}
function pickXssPayload(report = {}) {
  return pickXssPayloadDetail(report).payload;
}
function dedupePayloadCandidates(items = []) {
  const list = [];
  (Array.isArray(items) ? items : []).forEach((item) => {
    const value = String(item || '').trim();
    if (!value || list.includes(value)) return;
    list.push(value);
  });
  return list;
}
function inferJsQuotePreference(report = {}) {
  const chain = String(report.sourceSinkChain || '');
  const evidence = String(report.evidence || '');
  const merged = `${chain}\n${evidence}`;
  if (/["][^"\n]{0,200}\+\s*[A-Za-z_$][\w$]*\s*\+[^"\n]{0,200}["]/.test(merged) && !/'][^'\n]{0,200}\+\s*[A-Za-z_$][\w$]*\s*\+[^'\n]{0,200}'/.test(merged)) {
    return 'double';
  }
  return 'single';
}
function buildExploitPayloadCandidates(report = {}, payloadDetail = {}) {
  const sink = String(report.sinkPoint || '').toLowerCase();
  const profile = String(payloadDetail.profile || '').toLowerCase();
  const byScan = String(payloadDetail.payload || '').trim();
  const candidates = [];
  const push = (value = '') => {
    const safe = String(value || '').trim();
    if (!safe || candidates.includes(safe)) return;
    candidates.push(safe);
  };
  if (byScan) push(byScan);

  const isCodeLike = (
    sink.includes('eval') ||
    sink.includes('function') ||
    sink.includes('settimeout') ||
    sink.includes('setinterval') ||
    sink.includes('onevent') ||
    sink.includes('setattribute(on*)') ||
    profile.includes('code') ||
    profile.includes('event-handler')
  );
  const isUrlLike = (
    sink.includes('href') ||
    sink.includes('src') ||
    sink.includes('location') ||
    sink.includes('action') ||
    profile.includes('href')
  );
  const isAttrLike = profile.includes('attr');
  const isHtmlLike = (
    sink.includes('innerhtml') ||
    sink.includes('outerhtml') ||
    sink.includes('insertadjacenthtml') ||
    sink.includes('document.write') ||
    sink.includes('jquery') ||
    profile.includes('html') ||
    profile === 'generic'
  );

  if (isCodeLike) {
    push("';alert(document.domain);//");
    push('";alert(document.domain);//');
    push('`);alert(document.domain);//');
  } else if (isUrlLike) {
    push('javascript:alert(document.domain)');
    push('data:text/html,<svg/onload=alert(document.domain)>');
  } else if (isAttrLike) {
    push("x' onclick='alert(document.domain)' x='");
    push('x" onmouseover="alert(document.domain)" x="');
  } else if (isHtmlLike) {
    push('<svg/onload=alert(document.domain)>');
    push('"><svg/onload=alert(document.domain)>');
    push('</script><svg/onload=alert(document.domain)>');
  } else {
    push('<svg/onload=alert(document.domain)>');
  }
  return dedupePayloadCandidates(candidates).slice(0, 6);
}
function buildDomxssProbePayloadDetail(report = {}, payloadDetail = {}) {
  const sink = String(report.sinkPoint || '').toLowerCase();
  const payloadProfile = String(payloadDetail.profile || '').toLowerCase();
  const marker = `DOM_PROBE_${Math.random().toString(36).slice(2, 5)}`.toUpperCase();
  const baseReason = 'Console动态验证使用无执行标记 payload，仅验证输入是否进入目标 sink/DOM。';
  const exploitPayloadCandidates = buildExploitPayloadCandidates(report, payloadDetail);
  const exploitPayload = exploitPayloadCandidates[0] || String(payloadDetail.payload || '');
  const exploitReason = String(payloadDetail.reason || '');
  const isHtmlLikeSink = (
    sink.includes('jquery html()') ||
    sink.includes('jquery append()') ||
    sink.includes('jquery prepend()') ||
    sink.includes('jquery before()') ||
    sink.includes('jquery after()') ||
    sink.includes('jquery replacewith()') ||
    sink.includes('jquery insertafter()') ||
    sink.includes('jquery insertbefore()') ||
    sink.includes('jquery replaceall()') ||
    sink.includes('jquery wrap()') ||
    sink.includes('jquery wrapinner()') ||
    sink.includes('jquery wrapall()') ||
    sink.includes('jquery.parsehtml') ||
    sink.includes('jquery $() selector') ||
    sink.includes('$() selector') ||
    sink.includes('innerhtml') ||
    sink.includes('outerhtml') ||
    sink.includes('insertadjacenthtml') ||
    sink.includes('document.write')
  );
  const isCodeLikeContext = (
    sink.includes('eval') ||
    sink.includes('function') ||
    sink.includes('settimeout') ||
    sink.includes('setinterval') ||
    sink.includes('onevent') ||
    sink.includes('setattribute(on*)') ||
    payloadProfile.includes('code') ||
    payloadProfile.includes('event-handler')
  );
  const isUrlLikeContext = (
    sink.includes('href') ||
    sink.includes('src') ||
    sink.includes('location') ||
    sink.includes('action') ||
    payloadProfile.includes('href')
  );
  const isAttrLikeContext = payloadProfile.includes('attr') && !isUrlLikeContext;
  const isHtmlLikeContext = isHtmlLikeSink || payloadProfile.includes('html') || payloadProfile === 'generic';

  if (isCodeLikeContext) {
    const quotePref = inferJsQuotePreference(report);
    const jsProbeSingle = `';window.__SE_DOM_PROBE='${marker}';//`;
    const jsProbeDouble = `";window.__SE_DOM_PROBE='${marker}';//`;
    return {
      payload: quotePref === 'double' ? jsProbeDouble : jsProbeSingle,
      reason: `${baseReason} 当前为JS字符串上下文，使用赋值型探针验证代码上下文可控（双引号场景可改用 ${jsProbeDouble}）。`,
      profile: 'probe-js-string',
      probeMarker: marker,
      probeKind: 'js-string',
      probeAltPayload: quotePref === 'double' ? jsProbeSingle : jsProbeDouble,
      exploitPayload,
      exploitReason,
      exploitPayloadCandidates
    };
  }

  if (isUrlLikeContext) {
    return {
      payload: `#${marker}`,
      reason: `${baseReason} 已规避 javascript: 等高特征协议字符串，当前按URL值写入做低噪声验证。`,
      profile: 'probe-marker-url',
      probeMarker: marker,
      probeKind: 'url-marker',
      exploitPayload,
      exploitReason,
      exploitPayloadCandidates
    };
  }

  if (isAttrLikeContext) {
    return {
      payload: `x' data-se="${marker}" x='`,
      reason: `${baseReason} 当前为HTML属性上下文，使用无害属性探针验证属性边界可控。`,
      profile: 'probe-attr-marker',
      probeMarker: marker,
      probeKind: 'attr-marker',
      exploitPayload,
      exploitReason,
      exploitPayloadCandidates
    };
  }

  if (isHtmlLikeContext) {
    return {
      payload: `<domprobe data-se="${marker}"></domprobe>`,
      reason: `${baseReason} 当前为HTML标签上下文，使用无害标签探针，仅在标签真实进入DOM时提升结论置信度。`,
      profile: 'probe-html-tag',
      probeMarker: marker,
      probeKind: 'html-tag',
      exploitPayload,
      exploitReason,
      exploitPayloadCandidates
    };
  }

  return {
    payload: marker,
    reason: `${baseReason} 当前按通用 DOM 插入场景验证。`,
    profile: 'probe-marker-dom',
    probeMarker: marker,
    probeKind: 'text-marker',
    exploitPayload,
    exploitReason,
    exploitPayloadCandidates
  };
}
function extractSourceParamFromReport(report = {}) {
  const directParam = String(report.sourceParam || '').trim();
  if (directParam) return directParam;
  const sourcePoint = String(report.sourcePoint || '');
  const sourceMatch = sourcePoint.match(/\(([^)]+)\)/);
  if (sourceMatch?.[1]) return sourceMatch[1].trim();
  const evidence = String(report.evidence || '');
  const patterns = [
    /split\(\s*['"`]([A-Za-z0-9_.-]{1,60})=/i,
    /searchParams\.get\(\s*['"`]([A-Za-z0-9_.-]{1,60})['"`]\s*\)/i,
    /[?&]([A-Za-z0-9_.-]{1,60})=/i
  ];
  for (const regex of patterns) {
    const match = evidence.match(regex);
    if (match?.[1]) return match[1];
  }
  return '';
}
function collectLikelyQueryParams(report = {}, currentUrl = '') {
  const list = [];
  const sourceParam = extractSourceParamFromReport(report);
  if (sourceParam) {
    list.push(sourceParam);
  }
  try {
    const url = new URL(currentUrl);
    for (const key of url.searchParams.keys()) {
      if (key && !list.includes(key)) {
        list.push(key);
      }
      if (list.length >= 2) break;
    }
  } catch {}

  ['xss', 'text', 'payload', 'q'].forEach((key) => {
    if (!list.includes(key) && list.length < 3) list.push(key);
  });
  return list.slice(0, 3);
}
function isHrefLikeSink(report = {}) {
  const sinkPoint = String(report.sinkPoint || '').toLowerCase();
  const evidence = String(report.evidence || '').toLowerCase();
  const chain = String(report.sourceSinkChain || '').toLowerCase();
  return sinkPoint.includes('href') || /href\s*=/.test(`${evidence}\n${chain}`);
}
function lowerFirst(value = '') {
  if (!value) return '';
  return value[0].toLowerCase() + value.slice(1);
}
function extractRouteNamesFromReport(report = {}, currentUrl = '') {
  const names = [];
  const chain = String(report.sourceSinkChain || '');
  const fnMatch = chain.match(/->\s*\[L\d+\]\s*([A-Za-z_$][\w$]*)\s*:\s*function\s*\(/);
  const fnName = fnMatch?.[1] || '';
  if (fnName) {
    const showParamMatch = fnName.match(/^show([A-Za-z0-9_]+)Param$/i);
    if (showParamMatch?.[1]) {
      names.push(lowerFirst(showParamMatch[1]));
    }
    const handlerMatch = fnName.match(/^([A-Za-z0-9_]+)Handler$/i);
    if (handlerMatch?.[1]) {
      names.push(lowerFirst(handlerMatch[1]));
    }
    if (/^test/i.test(fnName)) {
      names.push('test');
    }
  }

  try {
    const decodedHash = decodeURIComponent(new URL(currentUrl).hash.replace(/^#/, ''));
    const hashParts = decodedHash.split('/').filter(Boolean);
    if (hashParts[0] && !hashParts[0].includes('=')) {
      names.push(hashParts[0]);
    }
  } catch {}

  const sourcePoint = String(report.sourcePoint || '').toLowerCase();
  if (sourcePoint.includes('route')) {
    names.push('test');
  }
  names.push('lesson', 'start');
  return dedupePayloadCandidates(names).slice(0, 6);
}
function buildHashRouteCandidates(currentUrl = '', report = {}, payload = '') {
  const sourceParam = extractSourceParamFromReport(report) || 'param';
  const encodedPayload = encodeURIComponent(payload);
  const routeNames = extractRouteNamesFromReport(report, currentUrl);
  const candidates = [];

  routeNames.forEach((routeName) => {
    const cleanRoute = String(routeName || '').replace(/^#/, '').replace(/^\//, '');
    if (!cleanRoute) return;
    candidates.push({
      method: 'hash-route',
      route: cleanRoute,
      hash: `${cleanRoute}/${encodedPayload}`,
      note: `route(${cleanRoute})/payload`
    });
    candidates.push({
      method: 'hash-route-query',
      route: cleanRoute,
      hash: `${cleanRoute}?${sourceParam}=${encodedPayload}`,
      note: `route(${cleanRoute})?${sourceParam}=payload`
    });
    candidates.push({
      method: 'hash-route-pair',
      route: cleanRoute,
      hash: `${cleanRoute}/${sourceParam}/${encodedPayload}`,
      note: `route(${cleanRoute})/${sourceParam}/payload`
    });
  });

  return candidates.slice(0, 12);
}
function buildDomxssAssistContext(report = {}, currentUrl = '') {
  const payloadDetail = pickXssPayloadDetail(report);
  const probeDetail = buildDomxssProbePayloadDetail(report, payloadDetail);
  return {
    id: String(report.id || ''),
    title: String(report.title || ''),
    category: String(report.category || ''),
    pageUrl: String(report.pageUrl || currentUrl || report.source || ''),
    sourceFile: String(report.source || ''),
    sourcePoint: String(report.sourcePoint || ''),
    sinkPoint: String(report.sinkPoint || ''),
    sourceParam: extractSourceParamFromReport(report) || 'xss',
    sourceSinkChain: String(report.sourceSinkChain || ''),
    evidence: String(report.evidence || ''),
    hasSanitizer: Boolean(report.hasSanitizer),
    payload: probeDetail.payload,
    payloadReason: String(probeDetail.reason || ''),
    payloadProfile: String(probeDetail.profile || ''),
    probeMarker: String(probeDetail.probeMarker || ''),
    probeKind: String(probeDetail.probeKind || ''),
    exploitPayload: String(probeDetail.exploitPayload || ''),
    exploitReason: String(probeDetail.exploitReason || ''),
    exploitPayloadCandidates: dedupePayloadCandidates(probeDetail.exploitPayloadCandidates || []),
    routeHints: extractRouteNamesFromReport(report, currentUrl)
  };
}
async function domxssAssistRuntime(ctxInput = {}) {
  const ctx = Object.assign({
    sourcePoint: '',
    sinkPoint: '',
    sourceParam: 'xss',
    sourceSinkChain: '',
    evidence: '',
    payload: '',
    payloadReason: '',
    payloadProfile: '',
    probeMarker: '',
    probeKind: '',
    exploitPayload: '',
    exploitReason: '',
    exploitPayloadCandidates: [],
    hasSanitizer: false,
    routeHints: [],
    sourceFile: '',
    pageUrl: ''
  }, ctxInput || {});

  const sleep = (ms = 0) => new Promise(resolve => setTimeout(resolve, ms));
  const safeDecode = (value = '') => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  };
  const payload = String(ctx.payload || '');
  const probeMarker = String(ctx.probeMarker || '').trim();
  const probeKind = String(ctx.probeKind || '').trim();
  const payloadVariants = Array.from(new Set([
    payload,
    probeMarker,
    safeDecode(payload),
    safeDecode(payload).replace(/\+/g, ' '),
    safeDecode(probeMarker)
  ].filter(Boolean)));
  const containsPayload = (value = '') => {
    const text = String(value || '').toLowerCase();
    return payloadVariants.some(item => item && text.includes(String(item).toLowerCase()));
  };
  const dedupeExploitPayloadCandidates = (items = []) => Array.from(new Set(
    (Array.isArray(items) ? items : [])
      .map(item => String(item || '').trim())
      .filter(Boolean)
  )).slice(0, 6);

  const loadedJs = Array.from(new Set([
    ...Array.from(document.scripts || []).map(script => script.src).filter(Boolean),
    ...performance.getEntriesByType('resource')
      .map(entry => entry?.name || '')
      .filter(url => /\.js(?:[?#].*)?$/i.test(url))
  ]));
  const sourceFile = String(ctx.sourceFile || '');
  const sourceFileLoaded = Boolean(sourceFile) && loadedJs.some((url) => {
    const clean = String(url || '').split('?')[0].split('#')[0];
    const target = sourceFile.split('?')[0].split('#')[0];
    return clean === target || clean.endsWith(target.split('/').pop() || '');
  });

  const sourceChainLines = String(ctx.sourceSinkChain || '').split(/\r?\n/);
  const sinkLine = (() => {
    for (let i = 0; i < sourceChainLines.length; i++) {
      if (/^\s*SINK\[L\d+\]\s*:/i.test(sourceChainLines[i] || '')) {
        const nextLine = String(sourceChainLines[i + 1] || '').trim();
        if (nextLine.startsWith('->')) return nextLine.replace(/^->\s*/, '').trim();
        return nextLine;
      }
    }
    return String(ctx.evidence || '').trim();
  })();
  const functionName = (() => {
    const fnMatch = String(ctx.sourceSinkChain || '').match(/->\s*\[L\d+\]\s*([A-Za-z_$][\w$]*)\s*:\s*function\s*\(/);
    return fnMatch?.[1] || '';
  })();
  const sourceSinkChainText = String(ctx.sourceSinkChain || '');
  const findLikelyInvokerNames = () => {
    const names = [];
    const pushName = (name) => {
      const safe = String(name || '').trim();
      if (!safe || names.includes(safe)) return;
      names.push(safe);
    };
    if (functionName) pushName(functionName);
    const fnDefRegex = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
    let match = fnDefRegex.exec(sourceSinkChainText);
    while (match) {
      pushName(match[1]);
      match = fnDefRegex.exec(sourceSinkChainText);
    }
    pushName('domxss');
    return names.slice(0, 6);
  };

  const hookHits = [];
  const restorers = [];
  const runtimeNotes = [];
  const pushHit = (sinkName, detail = {}) => {
    hookHits.push({
      sink: String(sinkName || ''),
      snippet: String(detail?.snippet || detail || '').slice(0, 1200),
      href: location.href,
      at: Date.now()
    });
  };

  try {
    const methods = ['html', 'append', 'prepend', 'before', 'after', 'replaceWith', 'insertAfter', 'insertBefore'];
    const jq = window.jQuery || window.$;
    if (jq?.fn) {
      if (typeof jq.fn.init === 'function') {
        const originalInit = jq.fn.init;
        const patchedInit = function patchedInit(selector, context, root) {
          if (containsPayload(selector)) {
            pushHit('jQuery $() selector', { snippet: String(selector).slice(0, 1200) });
          }
          return originalInit.call(this, selector, context, root);
        };
        patchedInit.prototype = originalInit.prototype;
        jq.fn.init = patchedInit;
        restorers.push(() => { jq.fn.init = originalInit; });
      }

      methods.forEach((method) => {
        if (typeof jq.fn[method] !== 'function') return;
        const original = jq.fn[method];
        jq.fn[method] = function patchedMethod(...args) {
          if (args.length && containsPayload(args[0])) {
            pushHit(`jquery ${method}()`, { snippet: String(args[0]).slice(0, 1200) });
          }
          return original.apply(this, args);
        };
        restorers.push(() => { jq.fn[method] = original; });
      });
    } else {
      runtimeNotes.push('当前页面未检测到 jQuery，jQuery sink hook 跳过。');
    }
  } catch (error) {
    runtimeNotes.push(`hook jQuery 失败: ${error?.message || 'unknown'}`);
  }

  try {
    const innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (innerDesc?.set) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        configurable: true,
        enumerable: innerDesc.enumerable,
        get: innerDesc.get,
        set(value) {
          if (containsPayload(value)) {
            pushHit('innerHTML', { snippet: String(value).slice(0, 1200) });
          }
          return innerDesc.set.call(this, value);
        }
      });
      restorers.push(() => Object.defineProperty(Element.prototype, 'innerHTML', innerDesc));
    }
  } catch (error) {
    runtimeNotes.push(`hook innerHTML 失败: ${error?.message || 'unknown'}`);
  }

  try {
    const outerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (outerDesc?.set) {
      Object.defineProperty(Element.prototype, 'outerHTML', {
        configurable: true,
        enumerable: outerDesc.enumerable,
        get: outerDesc.get,
        set(value) {
          if (containsPayload(value)) {
            pushHit('outerHTML', { snippet: String(value).slice(0, 1200) });
          }
          return outerDesc.set.call(this, value);
        }
      });
      restorers.push(() => Object.defineProperty(Element.prototype, 'outerHTML', outerDesc));
    }
  } catch (error) {
    runtimeNotes.push(`hook outerHTML 失败: ${error?.message || 'unknown'}`);
  }

  try {
    if (typeof Element.prototype.insertAdjacentHTML === 'function') {
      const original = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function patchedInsertAdjacentHTML(position, html) {
        if (containsPayload(html)) {
          pushHit('insertAdjacentHTML', { snippet: String(html).slice(0, 1200) });
        }
        return original.call(this, position, html);
      };
      restorers.push(() => { Element.prototype.insertAdjacentHTML = original; });
    }
  } catch (error) {
    runtimeNotes.push(`hook insertAdjacentHTML 失败: ${error?.message || 'unknown'}`);
  }

  try {
    if (typeof document.write === 'function') {
      const originalWrite = document.write.bind(document);
      const originalWriteln = typeof document.writeln === 'function' ? document.writeln.bind(document) : null;
      document.write = (...args) => {
        const text = args.map(item => String(item || '')).join('');
        if (containsPayload(text)) pushHit('document.write', { snippet: text.slice(0, 1200) });
        return originalWrite(...args);
      };
      if (originalWriteln) {
        document.writeln = (...args) => {
          const text = args.map(item => String(item || '')).join('');
          if (containsPayload(text)) pushHit('document.writeln', { snippet: text.slice(0, 1200) });
          return originalWriteln(...args);
        };
      }
      restorers.push(() => {
        document.write = originalWrite;
        if (originalWriteln) document.writeln = originalWriteln;
      });
    }
  } catch (error) {
    runtimeNotes.push(`hook document.write 失败: ${error?.message || 'unknown'}`);
  }

  try {
    if (typeof Element.prototype.setAttribute === 'function') {
      const original = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function patchedSetAttribute(name, value) {
        const attrName = String(name || '').toLowerCase();
        if ((/^on[a-z]{3,20}$/.test(attrName) || /^(?:href|src|action|formaction|xlink:href)$/.test(attrName)) && containsPayload(value)) {
          pushHit(`setAttribute(${attrName})`, { snippet: `${attrName}=${String(value || '').slice(0, 600)}` });
        }
        return original.call(this, name, value);
      };
      restorers.push(() => { Element.prototype.setAttribute = original; });
    }
  } catch (error) {
    runtimeNotes.push(`hook setAttribute 失败: ${error?.message || 'unknown'}`);
  }

  const triggerRouteRefresh = async () => {
    try { window.dispatchEvent(new Event('hashchange')); } catch {}
    try { window.dispatchEvent(new Event('popstate')); } catch {}
    try {
      const jq = window.jQuery || window.$;
      if (jq) {
        jq(window).trigger('hashchange');
        jq(window).trigger('popstate');
      }
    } catch {}
    await sleep(120);
  };
  const invokeLikelyHandlers = async () => {
    const called = [];
    const names = findLikelyInvokerNames();
    names.forEach((name) => {
      try {
        if (typeof window[name] === 'function') {
          window[name]();
          called.push(`window.${name}()`);
        }
      } catch {}
    });
    if (called.length) {
      await sleep(120);
    }
    return called;
  };

  const sourcePoint = String(ctx.sourcePoint || '').toLowerCase();
  const sourceParam = String(ctx.sourceParam || 'xss').trim() || 'xss';
  const isDomInputSource = (
    sourcePoint.includes('dom input value') ||
    sourcePoint.includes('event target value') ||
    sourcePoint.includes('jquery val()') ||
    sourcePoint.includes('input')
  );
  const hashRaw = safeDecode(location.hash.replace(/^#/, ''));
  const hashSeg = hashRaw.split('/').filter(Boolean);
  const currentRoute = hashSeg[0] && !hashSeg[0].includes('=') ? hashSeg[0] : '';
  const routeHints = Array.isArray(ctx.routeHints) ? ctx.routeHints.map(item => String(item || '').trim()).filter(Boolean) : [];
  if (functionName && /^show([A-Za-z0-9_]+)Param$/i.test(functionName)) {
    routeHints.unshift(functionName.replace(/^show([A-Za-z0-9_]+)Param$/i, (_, p1) => p1.charAt(0).toLowerCase() + p1.slice(1)));
  }
  if (currentRoute) routeHints.unshift(currentRoute);
  const finalRouteHints = Array.from(new Set(routeHints.concat(['test', 'lesson', 'start']))).slice(0, 8);

  const candidates = [];
  const pushCandidate = (type, note, targetUrl) => {
    const target = String(targetUrl || '').trim();
    if (!target) return;
    if (candidates.some(item => item.target === target)) return;
    candidates.push({ type, note, target });
  };
  const pushActionCandidate = (type, note, action) => {
    if (typeof action !== 'function') return;
    candidates.push({ type, note, target: location.href, action });
  };

  const findInputHints = () => {
    const chain = String(ctx.sourceSinkChain || '');
    const hints = {
      id: '',
      name: '',
      selector: ''
    };
    const idMatch = chain.match(/getElementById\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\.value/i);
    if (idMatch?.[1]) hints.id = idMatch[1].trim();
    const nameMatch = chain.match(/getElementsByName\(\s*['"`]([^'"`]+)['"`]\s*\)\s*(?:\[[^\]]+\])?\s*\.value/i);
    if (nameMatch?.[1]) hints.name = nameMatch[1].trim();
    const selectorMatch = chain.match(/querySelector(?:All)?\(\s*['"`]([^'"`]+)['"`]\s*\)\s*(?:\[[^\]]+\])?\s*\.value/i);
    if (selectorMatch?.[1]) hints.selector = selectorMatch[1].trim();
    return hints;
  };

  const runDomInputProbe = async () => {
    const hints = findInputHints();
    const inputCandidates = [];
    if (hints.id) {
      const byId = document.getElementById(hints.id);
      if (byId) inputCandidates.push(byId);
    }
    if (hints.name) {
      const byName = Array.from(document.getElementsByName(hints.name) || []);
      byName.forEach((el) => inputCandidates.push(el));
    }
    if (hints.selector) {
      try {
        const bySelector = Array.from(document.querySelectorAll(hints.selector) || []);
        bySelector.forEach((el) => inputCandidates.push(el));
      } catch {}
    }

    const genericInputs = Array.from(document.querySelectorAll('input,textarea,select'));
    genericInputs.forEach((el) => inputCandidates.push(el));

    const uniqueInputs = [];
    const seen = new Set();
    inputCandidates.forEach((el) => {
      if (!el || seen.has(el)) return;
      seen.add(el);
      uniqueInputs.push(el);
    });

    const editableInputs = uniqueInputs.filter((el) => {
      if (!(el instanceof Element)) return false;
      const tag = el.tagName.toLowerCase();
      if (tag === 'textarea' || tag === 'select') return true;
      if (tag !== 'input') return false;
      const type = String(el.getAttribute('type') || 'text').toLowerCase();
      return !['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image', 'reset'].includes(type);
    });

    const typedCount = Math.min(3, editableInputs.length);
    for (let i = 0; i < typedCount; i++) {
      const el = editableInputs[i];
      try {
        el.focus?.();
        el.value = payload;
        el.setAttribute?.('value', payload);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Enter' }));
      } catch {}
    }

    let triggerAction = '';
    try {
      const fnName = String(functionName || '').trim();
      if (fnName && typeof window[fnName] === 'function') {
        window[fnName]();
        triggerAction = `window.${fnName}()`;
      }
    } catch {}

    if (!triggerAction) {
      const clickables = Array.from(document.querySelectorAll('button,input[type="button"],input[type="submit"],a[onclick],*[onclick]'));
      const hitByText = clickables.find((el) => {
        const text = `${el.textContent || ''} ${el.id || ''} ${el.name || ''} ${el.getAttribute('value') || ''} ${el.getAttribute('onclick') || ''}`.toLowerCase();
        return /domxss|xss|click|submit|run|go|test|trigger|执行|触发/.test(text);
      }) || clickables[0];
      if (hitByText && typeof hitByText.click === 'function') {
        hitByText.click();
        triggerAction = 'click trigger';
      }
    }

    await sleep(260);
    return {
      typedCount,
      triggerAction: triggerAction || 'none'
    };
  };

  const currentUrlObj = new URL(location.href);
  if (isDomInputSource) {
    pushActionCandidate('dom-input', 'fill input and trigger handler', runDomInputProbe);
  }
  if (sourcePoint.includes('search') || sourcePoint.includes('query')) {
    const queryUrl = new URL(currentUrlObj.toString());
    queryUrl.searchParams.set(sourceParam, payload);
    pushCandidate('query', `${sourceParam}=payload`, queryUrl.toString());
  }
  if (sourcePoint.includes('hash') || sourcePoint.includes('route') || sourcePoint.includes('function argument')) {
    finalRouteHints.forEach((route) => {
      const url1 = new URL(currentUrlObj.toString());
      url1.hash = `${route}/${encodeURIComponent(payload)}`;
      pushCandidate('hash-route', `#${route}/payload`, url1.toString());

      const url2 = new URL(currentUrlObj.toString());
      url2.hash = `${route}/${sourceParam}/${encodeURIComponent(payload)}`;
      pushCandidate('hash-route-pair', `#${route}/${sourceParam}/payload`, url2.toString());

      const url3 = new URL(currentUrlObj.toString());
      url3.hash = `${route}?${sourceParam}=${encodeURIComponent(payload)}`;
      pushCandidate('hash-route-query', `#${route}?${sourceParam}=payload`, url3.toString());
    });
  }
  if (!candidates.length) {
    const fallbackHash = new URL(currentUrlObj.toString());
    fallbackHash.hash = `${sourceParam}=${encodeURIComponent(payload)}`;
    pushCandidate('hash-fallback', `#${sourceParam}=payload`, fallbackHash.toString());
    const fallbackQuery = new URL(currentUrlObj.toString());
    fallbackQuery.searchParams.set(sourceParam, payload);
    pushCandidate('query-fallback', `?${sourceParam}=payload`, fallbackQuery.toString());
  }

  const attempts = [];
  const baselineHits = hookHits.length;
  const detectDomProbeHit = () => {
    if (!probeMarker) return false;
    try {
      if (probeKind === 'js-string') {
        return String(window.__SE_DOM_PROBE || '') === probeMarker;
      }
      if (probeKind === 'attr-marker') {
        return Boolean(document.querySelector(`[data-se="${probeMarker}"]`));
      }
      if (probeKind === 'html-tag') {
        return Boolean(document.querySelector(`domprobe[data-se="${probeMarker}"]`));
      }
      return false;
    } catch {
      return false;
    }
  };
  let domProbeHitCount = 0;
  if (probeKind === 'js-string') {
    try { window.__SE_DOM_PROBE = ''; } catch {}
  }
  for (const candidate of candidates.slice(0, 10)) {
    const targetUrl = new URL(candidate.target || location.href, location.href);
    const beforeHits = hookHits.length;
    const beforeHref = location.href;
    let actionResult = null;
    let invokedHandlers = [];

    if (typeof candidate.action === 'function') {
      actionResult = await candidate.action();
    } else if (candidate.type.startsWith('query')) {
      history.replaceState({}, '', targetUrl.toString());
    } else {
      location.hash = targetUrl.hash;
    }
    await triggerRouteRefresh();
    invokedHandlers = await invokeLikelyHandlers();
    await sleep(260);

    const html = document.documentElement?.innerHTML || '';
    const domProbeHit = detectDomProbeHit();
    const payloadReflected = containsPayload(html) || domProbeHit;
    const newHits = hookHits.slice(beforeHits);
    if (domProbeHit) domProbeHitCount += 1;
    attempts.push({
      type: candidate.type,
      note: candidate.note,
      target: targetUrl.toString(),
      changedFrom: beforeHref,
      changedTo: location.href,
      sinkHit: newHits.length > 0,
      payloadReflected,
      domProbeHit,
      actionResult,
      invokedHandlers
    });
    if (newHits.length > 0) {
      break;
    }
  }

  restorers.reverse().forEach((restore) => {
    try { restore(); } catch {}
  });

  const sourceKnown = Boolean(ctx.sourcePoint) && !/未知|未明确|未提供/.test(String(ctx.sourcePoint || ''));
  const sinkKnown = Boolean(ctx.sinkPoint) && !/未知|未明确|未提供/.test(String(ctx.sinkPoint || ''));
  const jsProbeHit = probeKind === 'js-string' && attempts.some(item => item.domProbeHit);
  const runtimeHit = hookHits.length > baselineHits || jsProbeHit;
  const reflectedOnly = attempts.some(item => item.payloadReflected);
  const structuralProbeExpected = probeKind === 'html-tag' || probeKind === 'attr-marker' || probeKind === 'js-string';
  const structuralProbeInserted = attempts.some(item => item.domProbeHit);
  const reasons = [];
  reasons.push(sinkKnown ? `Sink点已识别: ${ctx.sinkPoint}` : 'Sink点未明确。');
  reasons.push(sourceKnown ? `Source点已识别: ${ctx.sourcePoint}` : 'Source点未明确。');
  reasons.push(sourceFile ? `Source文件: ${sourceFileLoaded ? '已加载' : '未加载'} (${sourceFile})` : 'Source文件未提供。');
  reasons.push(`动态尝试次数: ${attempts.length}`);
  reasons.push(`sink hook命中次数: ${hookHits.length}`);
  if (probeKind === 'js-string') reasons.push(`JS探针命中: ${jsProbeHit ? '是' : '否'}`);
  if (structuralProbeExpected) reasons.push(`结构化探针落地次数: ${domProbeHitCount}`);
  if (ctx.payloadReason) reasons.push(`payload依据: ${ctx.payloadReason}`);
  if (ctx.hasSanitizer) reasons.push('报告标记 hasSanitizer=true。');
  if (runtimeNotes.length) reasons.push(...runtimeNotes.slice(0, 3));

  let verdict = 'needs_manual';
  let verdictText = '需人工复核';
  let riskTag = '待确认';
  let message = '建议继续结合业务流程进行手工验证。';
  let recommendation = '可使用一键复现继续自动注入，或在关键交互步骤手工触发。';

  if (runtimeHit && (!structuralProbeExpected || structuralProbeInserted)) {
    verdict = 'verified_real';
    verdictText = '已动态验证命中';
    riskTag = '高置信度真实漏洞';
    message = '已在当前页面动态捕获 payload 进入 sink。';
    recommendation = '建议保留当前 URL/步骤录屏并导出复现链路。';
  } else if (runtimeHit && structuralProbeExpected && !structuralProbeInserted) {
    verdict = 'possible_real';
    verdictText = '已命中sink，但结构化探针未落地';
    riskTag = '中等风险';
    message = '数据已流入目标 sink，但结构化探针未进入DOM，可能存在过滤/编码。';
    recommendation = '建议补充上下文敏感 payload 进一步验证可利用性。';
  } else if (reflectedOnly) {
    verdict = 'possible_real';
    verdictText = '检测到反射，未捕获sink执行';
    riskTag = '中等风险';
    message = 'payload 已进入页面，但未在本轮 hook 中命中 sink。';
    recommendation = '补充关键交互动作（点击、提交、切页）后再次验证。';
  } else if (!sourceKnown || !sinkKnown) {
    verdict = 'likely_false_positive';
    verdictText = '线索不足，疑似误报';
    riskTag = '误报概率较高';
    message = '缺少清晰 source/sink 信息，且动态验证未命中。';
    recommendation = '先完善 source-sink 链路，再进行主动注入。';
  } else {
    verdict = 'not_confirmed';
    verdictText = '未动态命中';
    riskTag = '待复核';
    message = '已按当前上下文主动尝试参数/路由注入，未命中 sink。';
    recommendation = '更换业务流程入口或提高交互覆盖后重试。';
  }

  const firstHit = hookHits[0];
  const sinkSnippet = firstHit?.snippet || sinkLine || String(ctx.evidence || '').slice(0, 1200);
  console.groupCollapsed('[SnowEyesPlus] DOM_XSS Console验证助手(动态)');
  console.log('结论:', verdictText);
  console.log('Risk:', riskTag);
  console.log('验证Payload(无执行):', payload || '-');
  console.log('Payload依据:', ctx.payloadReason || '-');
  if (ctx.exploitPayload) {
    console.log('利用Payload(参考):', ctx.exploitPayload);
  }
  console.log('Source点:', ctx.sourcePoint || '-');
  console.log('Sink点:', ctx.sinkPoint || '-');
  console.log('候选尝试:', attempts);
  console.log('Sink片段:', sinkSnippet || '-');
  console.log('依据:', reasons);
  console.groupEnd();

  const details = {
    currentUrl: location.href,
    sourceFileLoaded,
    loadedJsCount: loadedJs.length,
    loadedJsSample: loadedJs.slice(0, 8),
    candidateCount: candidates.length,
    attempts,
    domProbeHitCount,
    hookHitCount: hookHits.length,
    hookHits: hookHits.slice(0, 6),
    sinkSnippet
  };

  return {
    verdict,
    verdictText,
    riskTag,
    message,
    recommendation,
    payload: payload || '',
    payloadReason: ctx.payloadReason || '',
    payloadProfile: ctx.payloadProfile || '',
    exploitPayload: ctx.exploitPayload || '',
    exploitReason: ctx.exploitReason || '',
    exploitPayloadCandidates: dedupeExploitPayloadCandidates(ctx.exploitPayloadCandidates || []),
    sourceParam,
    reasons,
    details
  };
}
function buildDomxssConsoleScript(report = {}, currentUrl = '') {
  const context = buildDomxssAssistContext(report, currentUrl);
  return [
    '(async () => {',
    `  const ctx = ${JSON.stringify(context)};`,
    `  const run = ${domxssAssistRuntime.toString()};`,
    '  const result = await run(ctx);',
    '  window.__snoweyesDomxss = result;',
    '  return result;',
    '})();'
  ].join('\n');
}
async function getDomxssConsoleScript(tabId, report = {}) {
  let currentUrl = '';
  if (tabId) {
    const tab = await chromeApi.tabs.get(tabId).catch(() => null);
    currentUrl = tab?.url || '';
  }
  const context = buildDomxssAssistContext(report, currentUrl);
  return {
    success: true,
    payload: context.payload,
    payloadReason: context.payloadReason || '',
    payloadProfile: context.payloadProfile || '',
    exploitPayload: context.exploitPayload || '',
    exploitReason: context.exploitReason || '',
    exploitPayloadCandidates: dedupePayloadCandidates(context.exploitPayloadCandidates || []),
    sourceParam: context.sourceParam || 'xss',
    script: buildDomxssConsoleScript(report, currentUrl)
  };
}
async function runDomxssConsoleAssistOnTab(tabId, report = {}) {
  const tab = await chromeApi.tabs.get(tabId);
  const currentUrl = tab?.url || '';
  if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
    throw new Error('当前页面不支持脚本注入');
  }
  const context = buildDomxssAssistContext(report, currentUrl);
  const [res] = await chromeApi.scripting.executeScript({
    target: { tabId },
    func: domxssAssistRuntime,
    args: [context],
    world: 'MAIN'
  });
  const script = buildDomxssConsoleScript(report, currentUrl);
  const result = (res?.result && typeof res.result === 'object') ? res.result : null;
  if (!result || !Object.keys(result).length) {
    return {
      success: false,
      message: '动态验证脚本执行后未返回结果。请查看目标页面 Console 报错并重试。'
    };
  }
  return {
    success: true,
    ...result,
    consoleScript: script
  };
}
  return {
    pickXssPayloadDetail,
    pickXssPayload,
    dedupePayloadCandidates,
    inferJsQuotePreference,
    buildExploitPayloadCandidates,
    buildDomxssProbePayloadDetail,
    extractSourceParamFromReport,
    collectLikelyQueryParams,
    isHrefLikeSink,
    extractRouteNamesFromReport,
    buildHashRouteCandidates,
    buildDomxssAssistContext,
    domxssAssistRuntime,
    buildDomxssConsoleScript,
    getDomxssConsoleScript,
    runDomxssConsoleAssistOnTab
  };
}
