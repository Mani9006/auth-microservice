/**
 * Audit Log model for tracking security-relevant events.
 * Provides tamper-evident logging using JSON file storage.
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const config = require('../config');
const { logger } = require('../utils/logger');

const AUDIT_LOGS_FILE = path.join(config.storage.dataDir, config.storage.auditLogsFile);

// In-memory buffer for batch writing
let logBuffer = [];
let bufferFlushTimer = null;
const BUFFER_FLUSH_INTERVAL_MS = 5000; // Flush every 5 seconds
const BUFFER_MAX_SIZE = 50;

/**
 * Initialize the audit log system.
 */
function init() {
  if (!bufferFlushTimer) {
    bufferFlushTimer = setInterval(flushBuffer, BUFFER_FLUSH_INTERVAL_MS);
    // Ensure flush on process exit
    process.on('SIGINT', async () => {
      await flushBuffer();
      process.exit(0);
    });
    process.on('SIGTERM', async () => {
      await flushBuffer();
      process.exit(0);
    });
  }
}

/**
 * Read audit logs from the JSON file.
 * @returns {Promise<Array>} Array of audit log entries.
 */
async function readLogs() {
  try {
    const data = await fs.readFile(AUDIT_LOGS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return [];
    }
    logger.error(`Error reading audit logs file: ${error.message}`);
    throw error;
  }
}

/**
 * Write audit logs to the JSON file.
 * @param {Array} logs - Array of audit log entries.
 */
async function writeLogs(logs) {
  try {
    await fs.writeFile(AUDIT_LOGS_FILE, JSON.stringify(logs, null, 2), 'utf8');
  } catch (error) {
    logger.error(`Error writing audit logs file: ${error.message}`);
    throw error;
  }
}

/**
 * Calculate a hash chain for tamper detection.
 * @param {Object} logEntry - The current log entry.
 * @param {string} [previousHash] - The hash of the previous entry.
 * @returns {string} The SHA-256 hash of this entry.
 */
function calculateHash(logEntry, previousHash = '') {
  const data = JSON.stringify({
    timestamp: logEntry.timestamp,
    userId: logEntry.userId,
    action: logEntry.action,
    resource: logEntry.resource,
    details: logEntry.details,
    previousHash,
  });
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Create a new audit log entry.
 * @param {Object} logData - The audit log data.
 * @param {string} [logData.userId] - The user ID (or 'system', 'anonymous').
 * @param {string} logData.action - The action performed (e.g., 'USER_LOGIN').
 * @param {string} [logData.resource] - The resource affected.
 * @param {boolean} [logData.success] - Whether the action succeeded.
 * @param {string} [logData.ip] - Client IP address.
 * @param {string} [logData.userAgent] - Client user agent.
 * @param {Object} [logData.details] - Additional structured details.
 * @param {string} [logData.severity] - Severity level: 'info', 'warning', 'error', 'critical'.
 * @returns {Promise<Object>} The created audit log entry.
 */
async function create(logData) {
  const logs = await readLogs();
  const previousEntry = logs.length > 0 ? logs[logs.length - 1] : null;
  const previousHash = previousEntry ? previousEntry.hash : '';

  const timestamp = new Date().toISOString();

  const logEntry = {
    id: uuidv4(),
    timestamp,
    userId: logData.userId || 'anonymous',
    action: logData.action,
    resource: logData.resource || 'system',
    success: logData.success !== undefined ? logData.success : true,
    ip: logData.ip || 'unknown',
    userAgent: logData.userAgent || 'unknown',
    severity: logData.severity || 'info',
    details: logData.details || {},
    previousHash,
    hash: '', // Will be calculated
  };

  // Calculate hash for tamper detection
  logEntry.hash = calculateHash(logEntry, previousHash);

  // Add to buffer for batch writing
  logBuffer.push(logEntry);

  // Flush immediately if buffer is full
  if (logBuffer.length >= BUFFER_MAX_SIZE) {
    await flushBuffer();
  }

  return logEntry;
}

/**
 * Flush the log buffer to disk.
 */
async function flushBuffer() {
  if (logBuffer.length === 0) return;

  try {
    const logs = await readLogs();
    logs.push(...logBuffer);

    // Trim logs if exceeding max entries
    if (logs.length > config.cleanup.maxAuditLogEntries) {
      const excess = logs.length - config.cleanup.maxAuditLogEntries;
      logs.splice(0, excess);
      logger.info(`Trimmed ${excess} old audit log entries`);
    }

    await writeLogs(logs);
    logBuffer = [];
  } catch (error) {
    logger.error(`Failed to flush audit log buffer: ${error.message}`);
  }
}

/**
 * Find audit logs with optional filtering.
 * @param {Object} [filters] - Filter criteria.
 * @param {string} [filters.userId] - Filter by user ID.
 * @param {string} [filters.action] - Filter by action.
 * @param {string} [filters.resource] - Filter by resource.
 * @param {string} [filters.severity] - Filter by severity.
 * @param {boolean} [filters.success] - Filter by success status.
 * @param {string} [filters.startDate] - Start date (ISO string).
 * @param {string} [filters.endDate] - End date (ISO string).
 * @param {number} [filters.limit] - Maximum results to return.
 * @param {number} [filters.offset] - Number of results to skip.
 * @returns {Promise<Object>} Object with logs array and total count.
 */
async function findWithFilters(filters = {}) {
  await flushBuffer(); // Ensure buffer is written before querying

  let logs = await readLogs();

  // Apply filters
  if (filters.userId) {
    logs = logs.filter(l => l.userId === filters.userId);
  }
  if (filters.action) {
    logs = logs.filter(l => l.action === filters.action);
  }
  if (filters.resource) {
    logs = logs.filter(l => l.resource === filters.resource);
  }
  if (filters.severity) {
    logs = logs.filter(l => l.severity === filters.severity);
  }
  if (filters.success !== undefined) {
    logs = logs.filter(l => l.success === filters.success);
  }
  if (filters.startDate) {
    const start = new Date(filters.startDate).getTime();
    logs = logs.filter(l => new Date(l.timestamp).getTime() >= start);
  }
  if (filters.endDate) {
    const end = new Date(filters.endDate).getTime();
    logs = logs.filter(l => new Date(l.timestamp).getTime() <= end);
  }

  // Sort by timestamp descending (newest first)
  logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const total = logs.length;

  // Apply pagination
  const offset = filters.offset || 0;
  const limit = filters.limit || 50;
  logs = logs.slice(offset, offset + limit);

  return { logs, total };
}

/**
 * Get recent audit logs.
 * @param {number} [count=10] - Number of recent logs to retrieve.
 * @returns {Promise<Array>} Array of recent audit log entries.
 */
async function getRecent(count = 10) {
  await flushBuffer();

  const logs = await readLogs();
  return logs
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, count);
}

/**
 * Get audit statistics.
 * @returns {Promise<Object>} Statistics object.
 */
async function getStats() {
  await flushBuffer();

  const logs = await readLogs();
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const stats = {
    totalEntries: logs.length,
    last24Hours: logs.filter(l => new Date(l.timestamp) >= oneDayAgo).length,
    last7Days: logs.filter(l => new Date(l.timestamp) >= sevenDaysAgo).length,
    bySeverity: {
      info: logs.filter(l => l.severity === 'info').length,
      warning: logs.filter(l => l.severity === 'warning').length,
      error: logs.filter(l => l.severity === 'error').length,
      critical: logs.filter(l => l.severity === 'critical').length,
    },
    byAction: {},
    failedAttempts: logs.filter(l => !l.success && l.action.includes('LOGIN')).length,
  };

  // Count by action
  for (const log of logs) {
    stats.byAction[log.action] = (stats.byAction[log.action] || 0) + 1;
  }

  return stats;
}

/**
 * Verify the integrity of the audit log chain.
 * Checks that each entry's hash correctly references the previous entry.
 * @returns {Promise<Object>} Verification result with any tampered entries.
 */
async function verifyIntegrity() {
  await flushBuffer();

  const logs = await readLogs();
  const tampered = [];

  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];
    const previousHash = i > 0 ? logs[i - 1].hash : '';
    const expectedHash = calculateHash(entry, previousHash);

    if (entry.hash !== expectedHash) {
      tampered.push({
        index: i,
        id: entry.id,
        timestamp: entry.timestamp,
        expectedHash,
        actualHash: entry.hash,
      });
    }
  }

  return {
    isValid: tampered.length === 0,
    totalEntries: logs.length,
    tamperedEntries: tampered,
    tamperedCount: tampered.length,
  };
}

/**
 * Export audit logs to a portable format.
 * @param {Object} [filters] - Optional filters.
 * @returns {Promise<Array>} Filtered and formatted logs.
 */
async function exportLogs(filters = {}) {
  const { logs } = await findWithFilters(filters);
  return logs.map(log => ({
    timestamp: log.timestamp,
    userId: log.userId,
    action: log.action,
    resource: log.resource,
    success: log.success,
    ip: log.ip,
    severity: log.severity,
    details: log.details,
    integrityHash: log.hash,
  }));
}

/**
 * Clean up old audit log entries.
 * @param {number} [retentionDays=90] - Number of days to retain.
 * @returns {Promise<number>} Number of entries removed.
 */
async function cleanup(retentionDays = 90) {
  await flushBuffer();

  const logs = await readLogs();
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

  const originalLength = logs.length;
  const retained = logs.filter(l => new Date(l.timestamp) >= cutoff);
  const removed = originalLength - retained.length;

  if (removed > 0) {
    await writeLogs(retained);
    logger.info(`Cleaned up ${removed} audit log entries older than ${retentionDays} days`);
  }

  return removed;
}

module.exports = {
  init,
  create,
  findWithFilters,
  getRecent,
  getStats,
  verifyIntegrity,
  exportLogs,
  cleanup,
  flushBuffer,
};