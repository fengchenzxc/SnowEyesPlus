const DEFAULT_AI_AGENT_SESSIONS_KEY = 'snoweyes_ai_agent_sessions';
const DEFAULT_MAX_AI_AGENT_SESSIONS = 40;
const DEFAULT_MAX_AI_AGENT_MESSAGES = 20;

export function createAiService(options = {}) {
  const chromeApi = options.chromeApi || chrome;
  const fetchImpl = options.fetchImpl || fetch;
  const buildLocalAgentReply = typeof options.buildLocalAgentReply === 'function'
    ? options.buildLocalAgentReply
    : (() => '本地策略未配置');

  const sessionsKey = String(options.sessionsKey || DEFAULT_AI_AGENT_SESSIONS_KEY);
  const maxSessions = Number.isFinite(options.maxSessions) ? options.maxSessions : DEFAULT_MAX_AI_AGENT_SESSIONS;
  const maxMessages = Number.isFinite(options.maxMessages) ? options.maxMessages : DEFAULT_MAX_AI_AGENT_MESSAGES;

  function readAiAgentSessions() {
    return new Promise(resolve => {
      chromeApi.storage.local.get([sessionsKey], (res) => {
        const sessions = res?.[sessionsKey];
        if (sessions && typeof sessions === 'object' && !Array.isArray(sessions)) {
          resolve(sessions);
          return;
        }
        resolve({});
      });
    });
  }

  function trimAiAgentSessions(sessionMap = {}) {
    const entries = Object.entries(sessionMap);
    entries.sort((a, b) => new Date(b?.[1]?.updatedAt || 0).getTime() - new Date(a?.[1]?.updatedAt || 0).getTime());
    const kept = entries.slice(0, maxSessions);
    return Object.fromEntries(kept);
  }

  function writeAiAgentSessions(sessionMap = {}) {
    const trimmed = trimAiAgentSessions(sessionMap);
    return new Promise(resolve => {
      chromeApi.storage.local.set({ [sessionsKey]: trimmed }, () => resolve(true));
    });
  }

  function readAiReviewConfig() {
    return new Promise(resolve => {
      chromeApi.storage.local.get(['aiReviewConfig'], (storage) => {
        resolve(storage.aiReviewConfig || {});
      });
    });
  }

  function safeJsonParse(text) {
    if (!text || typeof text !== 'string') return null;
    try {
      return JSON.parse(text);
    } catch {
      const match = text.match(/\{[\s\S]*\}/);
      if (!match) return null;
      try {
        return JSON.parse(match[0]);
      } catch {
        return null;
      }
    }
  }

  function normalizeAiReviewOutput(parsed) {
    const review = parsed && typeof parsed === 'object' ? parsed : {};
    const confidenceValue = Number.parseInt(review.confidence, 10);
    const confidence = Number.isFinite(confidenceValue) ? Math.min(100, Math.max(0, confidenceValue)) : 70;
    const reasons = Array.isArray(review.reasons) ? review.reasons.slice(0, 6).map(item => String(item)) : [];
    const verdict = String(review.verdict || '需人工复核');
    let isFalsePositive = null;
    if (typeof review.isFalsePositive === 'boolean') {
      isFalsePositive = review.isFalsePositive;
    } else if (/误报/.test(verdict)) {
      isFalsePositive = true;
    } else if (/真实|有效|可利用/.test(verdict)) {
      isFalsePositive = false;
    }
    return {
      verdict,
      confidence,
      isFalsePositive,
      reasons,
      recommendation: String(review.recommendation || '')
    };
  }

  function buildAiReviewPrompts(report = {}) {
    const systemPrompt = [
      '你是一名资深Web安全审计专家，专注于DOM XSS和前端敏感信息泄露检测。',
      '请根据给定的漏洞上下文评估误报概率，并只返回JSON。',
      '返回JSON字段: verdict(string), confidence(0-100 number), isFalsePositive(boolean), reasons(string[]), recommendation(string)。',
      '不要输出Markdown，不要输出额外文本。'
    ].join('\n');

    const userPrompt = [
      '请评估以下漏洞记录：',
      JSON.stringify({
        category: report.category || '',
        type: report.type || '',
        title: report.title || '',
        severity: report.severity || '',
        source: report.source || '',
        pageUrl: report.pageUrl || '',
        sourcePoint: report.sourcePoint || '',
        sourceParam: report.sourceParam || '',
        sinkPoint: report.sinkPoint || '',
        sourceSinkChain: report.sourceSinkChain || '',
        evidence: report.evidence || '',
        hasSanitizer: Boolean(report.hasSanitizer),
        exp: report.exp || '',
        advice: report.advice || ''
      }, null, 2),
      '',
      '重点判断：',
      '1. source->sink 是否真实可达。',
      '2. 是否有净化/编码导致不可利用。',
      '3. 样本是否为占位符或测试值。',
      '4. 最终给出误报或真实漏洞倾向。'
    ].join('\n');

    return { systemPrompt, userPrompt };
  }

  async function callAiProviderForReview(report, aiConfig) {
    const provider = String(aiConfig.provider || 'codex').toLowerCase();
    const endpoint = String(aiConfig.endpoint || '').trim();
    const model = String(aiConfig.model || '').trim();
    const apiKey = String(aiConfig.apiKey || '').trim();
    const temperature = Number.isFinite(aiConfig.temperature) ? aiConfig.temperature : 0.2;
    const maxTokens = Number.isFinite(aiConfig.maxTokens) ? aiConfig.maxTokens : 1200;

    if (!endpoint || !model || !apiKey) {
      throw new Error('AI配置不完整，请先在配置页面填写 provider/endpoint/model/apikey');
    }

    const { systemPrompt, userPrompt } = buildAiReviewPrompts(report);
    const payload = {
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature,
      max_tokens: maxTokens,
      response_format: { type: 'json_object' }
    };

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    };

    let response = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    if (!response.ok && payload.response_format) {
      delete payload.response_format;
      response = await fetchImpl(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AI接口请求失败: HTTP ${response.status} ${errorText.slice(0, 220)}`);
    }

    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error('AI接口未返回有效内容');
    }

    const parsed = safeJsonParse(content);
    if (!parsed) {
      throw new Error('AI返回内容不是有效JSON');
    }

    const normalized = normalizeAiReviewOutput(parsed);
    return {
      provider,
      model,
      review: normalized
    };
  }

  function buildAiAgentSystemPrompt(report = {}) {
    return [
      '你是一名资深Web安全测试助手，正在协助白盒/授权测试场景下的DOM XSS调试。',
      '你的目标是帮助用户快速确认 source -> sink 链路、复现步骤与失败原因。',
      '回答请使用简洁中文，优先给可执行步骤；如果上下文不足，明确列出还需要的证据。',
      '已知漏洞上下文如下：',
      JSON.stringify({
        category: report.category || '',
        title: report.title || '',
        severity: report.severity || '',
        sourcePoint: report.sourcePoint || '',
        sourceParam: report.sourceParam || '',
        sinkPoint: report.sinkPoint || '',
        sourceSinkChain: report.sourceSinkChain || '',
        evidence: report.evidence || '',
        exp: report.exp || '',
        pageUrl: report.pageUrl || ''
      }, null, 2),
      '输出建议时优先包含：1) 利用链判断 2) 下一步验证动作 3) 误报排除点。'
    ].join('\n');
  }

  async function callAiProviderForAgent(report, message, historyMessages, aiConfig) {
    const provider = String(aiConfig.provider || 'local').toLowerCase();
    const endpoint = String(aiConfig.endpoint || '').trim();
    const model = String(aiConfig.model || '').trim() || (provider === 'local' ? 'heuristic-local' : '');
    const apiKey = String(aiConfig.apiKey || '').trim();
    const temperature = Number.isFinite(aiConfig.temperature) ? aiConfig.temperature : 0.2;
    const maxTokens = Number.isFinite(aiConfig.maxTokens) ? aiConfig.maxTokens : 1200;

    if (provider === 'local') {
      return {
        provider: 'local',
        model: 'heuristic-local',
        content: buildLocalAgentReply(report, message)
      };
    }
    if (!endpoint || !model || !apiKey) {
      throw new Error('AI配置不完整，请先在配置页面填写 provider/endpoint/model/apikey');
    }

    const safeHistory = Array.isArray(historyMessages)
      ? historyMessages
        .filter(item => item?.role === 'user' || item?.role === 'assistant')
        .slice(-8)
        .map(item => ({
          role: item.role,
          content: String(item.content || '').slice(0, 3000)
        }))
      : [];

    const payload = {
      model,
      messages: [
        { role: 'system', content: buildAiAgentSystemPrompt(report) },
        ...safeHistory,
        { role: 'user', content: String(message || '').slice(0, 4000) }
      ],
      temperature,
      max_tokens: maxTokens
    };

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    };

    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AI接口请求失败: HTTP ${response.status} ${errorText.slice(0, 220)}`);
    }
    const data = await response.json();
    const content = String(data?.choices?.[0]?.message?.content || '').trim();
    if (!content) {
      throw new Error('AI接口未返回有效内容');
    }
    return {
      provider,
      model,
      content
    };
  }

  async function getAiAgentSession(sessionId) {
    const safeSessionId = String(sessionId || '').slice(0, 120);
    if (!safeSessionId) {
      return { sessionId: '', messages: [] };
    }
    const sessions = await readAiAgentSessions();
    const session = sessions[safeSessionId];
    if (!session || !Array.isArray(session.messages)) {
      return { sessionId: safeSessionId, messages: [] };
    }
    return {
      sessionId: safeSessionId,
      messages: session.messages.slice(-maxMessages)
    };
  }

  async function clearAiAgentSession(sessionId) {
    const safeSessionId = String(sessionId || '').slice(0, 120);
    if (!safeSessionId) return { success: true, sessionId: '' };
    const sessions = await readAiAgentSessions();
    if (sessions[safeSessionId]) {
      delete sessions[safeSessionId];
      await writeAiAgentSessions(sessions);
    }
    return { success: true, sessionId: safeSessionId };
  }

  async function chatWithAiAgent({ sessionId, report, message }) {
    const safeSessionId = String(sessionId || '').slice(0, 120);
    const userMessage = String(message || '').trim();
    if (!safeSessionId) {
      throw new Error('sessionId 不能为空');
    }
    if (!userMessage) {
      throw new Error('消息不能为空');
    }

    const sessions = await readAiAgentSessions();
    const existing = sessions[safeSessionId] || {
      sessionId: safeSessionId,
      reportId: report?.id || '',
      messages: []
    };
    const historyMessages = Array.isArray(existing.messages) ? existing.messages.slice(-maxMessages) : [];
    const aiConfig = await readAiReviewConfig();

    const aiResult = await callAiProviderForAgent(report || {}, userMessage, historyMessages, aiConfig);
    const now = new Date().toISOString();
    const mergedMessages = [
      ...historyMessages,
      { role: 'user', content: userMessage, at: now },
      { role: 'assistant', content: aiResult.content, at: now }
    ].slice(-maxMessages);

    sessions[safeSessionId] = {
      sessionId: safeSessionId,
      reportId: report?.id || existing.reportId || '',
      updatedAt: now,
      messages: mergedMessages
    };
    await writeAiAgentSessions(sessions);

    return {
      success: true,
      sessionId: safeSessionId,
      provider: aiResult.provider,
      model: aiResult.model,
      reply: aiResult.content,
      messages: mergedMessages
    };
  }

  return {
    readAiAgentSessions,
    writeAiAgentSessions,
    readAiReviewConfig,
    normalizeAiReviewOutput,
    callAiProviderForReview,
    getAiAgentSession,
    clearAiAgentSession,
    chatWithAiAgent
  };
}
