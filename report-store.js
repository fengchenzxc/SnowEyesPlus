import { BACKGROUND_SEVERITY_LEVELS, reportUtils } from './report-schema.module.js';

const DEFAULT_STORAGE_KEY = 'snoweyes_vuln_reports';
const DEFAULT_MAX_REPORTS = 500;

export function createReportStore(options = {}) {
  const chromeApi = options.chromeApi || chrome;
  const storageKey = String(options.storageKey || DEFAULT_STORAGE_KEY);
  const maxReports = Number.isFinite(options.maxReports) ? options.maxReports : DEFAULT_MAX_REPORTS;

  function readVulnReports() {
    return new Promise((resolve) => {
      chromeApi.storage.local.get([storageKey], (res) => {
        const reports = Array.isArray(res[storageKey]) ? res[storageKey] : [];
        resolve(
          reports
            .filter(report => String(report?.category || '').toUpperCase() !== 'JS_SENSITIVE')
            .map(report => ({ ...report, evidence: '' }))
        );
      });
    });
  }

  function writeVulnReports(reports) {
    return new Promise((resolve) => {
      chromeApi.storage.local.set({ [storageKey]: reports }, () => resolve(true));
    });
  }

  async function addVulnReports(reports, sender) {
    if (!Array.isArray(reports) || reports.length === 0) {
      return { success: true, added: 0, total: 0 };
    }

    const existingReports = await readVulnReports();
    const mergedMap = new Map();
    existingReports.forEach(report => {
      if (report?.id) mergedMap.set(report.id, report);
    });

    let added = 0;
    reports.forEach((rawReport) => {
      const normalized = (typeof reportUtils.normalizeReport === 'function')
        ? reportUtils.normalizeReport(rawReport, {
          source: rawReport?.source || sender?.tab?.url || '',
          pageUrl: rawReport?.pageUrl || sender?.tab?.url || rawReport?.source || '',
          pageTitle: rawReport?.pageTitle || sender?.tab?.title || '',
          now: new Date().toISOString()
        }, { allowedSeverity: BACKGROUND_SEVERITY_LEVELS, prefix: 'SNOWEYES_' })
        : rawReport;

      if (!normalized?.id) return;
      if (mergedMap.has(normalized.id)) {
        const existing = mergedMap.get(normalized.id);
        mergedMap.set(normalized.id, { ...existing, ...normalized });
        return;
      }
      mergedMap.set(normalized.id, normalized);
      added += 1;
    });

    const sortedReports = Array.from(mergedMap.values())
      .sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime())
      .slice(0, maxReports);

    await writeVulnReports(sortedReports);
    return { success: true, added, total: sortedReports.length };
  }

  async function getVulnReports() {
    const reports = await readVulnReports();
    return reports.sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());
  }

  async function clearVulnReports() {
    await writeVulnReports([]);
    return { success: true };
  }

  async function deleteVulnReport(reportId) {
    const targetId = String(reportId || '').trim();
    if (!targetId) return { success: false, deleted: 0, message: 'invalid report id' };

    const reports = await readVulnReports();
    const filteredReports = reports.filter(report => String(report?.id || '').trim() !== targetId);
    const deleted = reports.length - filteredReports.length;
    if (deleted > 0) {
      await writeVulnReports(filteredReports);
    }
    return { success: true, deleted, total: filteredReports.length };
  }

  async function deleteVulnReports(reportIds = []) {
    const targetIds = Array.isArray(reportIds)
      ? reportIds.map(id => String(id || '').trim()).filter(Boolean)
      : [];
    if (!targetIds.length) {
      return { success: false, deleted: 0, message: 'invalid report ids' };
    }

    const targetIdSet = new Set(targetIds);
    const reports = await readVulnReports();
    const filteredReports = reports.filter(report => !targetIdSet.has(String(report?.id || '').trim()));
    const deleted = reports.length - filteredReports.length;
    if (deleted > 0) {
      await writeVulnReports(filteredReports);
    }
    return { success: true, deleted, total: filteredReports.length };
  }

  return {
    storageKey,
    maxReports,
    readVulnReports,
    writeVulnReports,
    addVulnReports,
    getVulnReports,
    clearVulnReports,
    deleteVulnReport,
    deleteVulnReports
  };
}
