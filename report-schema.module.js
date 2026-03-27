import './report-schema-core.js';

const schema = globalThis.SNOWEYES_REPORT_SCHEMA || {};

export const REPORT_SCHEMA = schema;
export const REPORT_FIELDS = schema.REPORT_FIELDS || [];
export const REPORT_FIELD_LIMITS = schema.REPORT_FIELD_LIMITS || {};
export const REPORT_SEVERITY_LEVELS = schema.REPORT_SEVERITY_LEVELS || ['critical', 'high', 'medium', 'low', 'info'];
export const BACKGROUND_SEVERITY_LEVELS = schema.BACKGROUND_SEVERITY_LEVELS || ['high', 'medium', 'low'];
export const reportUtils = schema.utils || {};

export default schema;
