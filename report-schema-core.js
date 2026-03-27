(function initSnowEyesReportSchema(global) {
  if (global.SNOWEYES_REPORT_SCHEMA) return;

  const REPORT_SEVERITY_LEVELS = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
  const BACKGROUND_SEVERITY_LEVELS = Object.freeze(['high', 'medium', 'low']);

  const REPORT_FIELD_LIMITS = Object.freeze({
    advice: 4000,
    sourcePoint: 2000,
    sourceParam: 200,
    sinkPoint: 2000,
    sourceSinkChain: 20000,
    exp: 12000,
    payloadHint: 3000,
    payloadReason: 3000,
    payloadProfile: 300
  });

  const REPORT_FIELDS = Object.freeze([
    'id',
    'category',
    'type',
    'title',
    'severity',
    'source',
    'pageUrl',
    'pageTitle',
    'evidence',
    'advice',
    'sourcePoint',
    'sourceParam',
    'sinkPoint',
    'sourceSinkChain',
    'exp',
    'payloadHint',
    'payloadReason',
    'payloadProfile',
    'hasSanitizer',
    'detectedAt'
  ]);

  function stableHash(value) {
    const text = String(value || '');
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  function normalizeSeverity(severity, options) {
    const opts = options && typeof options === 'object' ? options : {};
    const allowed = Array.isArray(opts.allowed) && opts.allowed.length ? opts.allowed : REPORT_SEVERITY_LEVELS;
    const fallback = String(opts.fallback || 'medium').toLowerCase();
    const normalized = String(severity || fallback).toLowerCase();
    return allowed.includes(normalized) ? normalized : fallback;
  }

  function clampText(value, maxLen) {
    const text = String(value || '');
    const limit = Number.isFinite(maxLen) ? maxLen : text.length;
    return text.slice(0, limit);
  }

  function buildReportId(report, source, options) {
    const opts = options && typeof options === 'object' ? options : {};
    const prefix = String(opts.prefix || 'SNOWEYES_');
    if (report && report.id) return String(report.id);
    const seed = [
      report?.category || '',
      report?.title || '',
      source || '',
      report?.sourceSinkChain || ''
    ].join('|');
    return `${prefix}${stableHash(seed)}`;
  }

  function normalizeReport(report, context, options) {
    const raw = report && typeof report === 'object' ? report : {};
    const ctx = context && typeof context === 'object' ? context : {};
    const opts = options && typeof options === 'object' ? options : {};
    const limits = Object.assign({}, REPORT_FIELD_LIMITS, opts.limits || {});

    const now = String(ctx.now || new Date().toISOString());
    const source = String(raw.source || ctx.source || '');
    const pageUrl = String(raw.pageUrl || ctx.pageUrl || source);
    const pageTitle = String(raw.pageTitle || ctx.pageTitle || '');

    const allowedSeverity = Array.isArray(opts.allowedSeverity) && opts.allowedSeverity.length
      ? opts.allowedSeverity
      : BACKGROUND_SEVERITY_LEVELS;

    return {
      id: buildReportId(raw, source, opts),
      category: String(raw.category || 'GENERIC'),
      type: String(raw.type || raw.category || 'GENERIC'),
      title: String(raw.title || '未命名漏洞'),
      severity: normalizeSeverity(raw.severity, { allowed: allowedSeverity, fallback: 'medium' }),
      source,
      pageUrl,
      pageTitle,
      evidence: '',
      advice: clampText(raw.advice, limits.advice),
      sourcePoint: clampText(raw.sourcePoint, limits.sourcePoint),
      sourceParam: clampText(raw.sourceParam, limits.sourceParam),
      sinkPoint: clampText(raw.sinkPoint, limits.sinkPoint),
      sourceSinkChain: clampText(raw.sourceSinkChain, limits.sourceSinkChain),
      exp: clampText(raw.exp, limits.exp),
      payloadHint: clampText(raw.payloadHint, limits.payloadHint),
      payloadReason: clampText(raw.payloadReason, limits.payloadReason),
      payloadProfile: clampText(raw.payloadProfile, limits.payloadProfile),
      hasSanitizer: Boolean(raw.hasSanitizer),
      detectedAt: String(raw.detectedAt || now)
    };
  }

  global.SNOWEYES_REPORT_SCHEMA = Object.freeze({
    REPORT_FIELDS,
    REPORT_FIELD_LIMITS,
    REPORT_SEVERITY_LEVELS,
    BACKGROUND_SEVERITY_LEVELS,
    utils: Object.freeze({
      stableHash,
      normalizeSeverity,
      normalizeReport,
      clampText,
      buildReportId
    })
  });
})(globalThis);
