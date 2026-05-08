/**
 * Logger utility using Winston for structured logging.
 * Provides info, warn, error, and debug log levels with file rotation.
 */

'use strict';

const winston = require('winston');
const path = require('path');
const config = require('../config');

const { combine, timestamp, json, printf, colorize } = winston.format;

// Custom format for development (human-readable)
const devFormat = printf(({ level, message, timestamp: ts, ...metadata }) => {
  const metaStr = Object.keys(metadata).length ? JSON.stringify(metadata) : '';
  return `[${ts}] ${level.toUpperCase()}: ${message} ${metaStr}`;
});

// Determine log format based on environment
const isProduction = config.server.env === 'production';

// Create the Winston logger instance
const logger = winston.createLogger({
  level: config.log.level,
  defaultMeta: {
    service: 'auth-microservice',
    environment: config.server.env,
    pid: process.pid,
  },
  transports: [],
  exitOnError: false,
});

// Add console transport for all environments
logger.add(new winston.transports.Console({
  format: isProduction
    ? combine(timestamp(), json())
    : combine(
        colorize(),
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        devFormat
      ),
  handleExceptions: true,
}));

// Add file transport for production
if (isProduction) {
  logger.add(new winston.transports.File({
    filename: config.log.file,
    format: combine(timestamp(), json()),
    maxsize: 5242880, // 5MB
    maxFiles: config.log.maxFiles,
    tailable: true,
    handleExceptions: true,
  }));

  // Separate error log file
  logger.add(new winston.transports.File({
    filename: path.join(config.storage.dataDir, 'error.log'),
    level: 'error',
    format: combine(timestamp(), json()),
    maxsize: 5242880, // 5MB
    maxFiles: config.log.maxFiles,
    tailable: true,
    handleExceptions: true,
  }));
}

/**
 * Log an audit event to the audit log.
 * @param {Object} auditData - The audit data to log.
 * @param {string} auditData.userId - The user ID associated with the event.
 * @param {string} auditData.action - The action performed.
 * @param {string} auditData.resource - The resource affected.
 * @param {string} [auditData.details] - Additional details.
 * @param {string} [auditData.ip] - The IP address.
 * @param {string} [auditData.userAgent] - The user agent string.
 * @param {boolean} [auditData.success] - Whether the action succeeded.
 */
function logAudit(auditData) {
  const auditEntry = {
    timestamp: new Date().toISOString(),
    userId: auditData.userId || 'anonymous',
    action: auditData.action,
    resource: auditData.resource,
    success: auditData.success !== undefined ? auditData.success : true,
    ip: auditData.ip || 'unknown',
    userAgent: auditData.userAgent || 'unknown',
    details: auditData.details || '',
  };

  logger.info('AUDIT_EVENT', auditEntry);
}

/**
 * Create a child logger with request-specific metadata.
 * @param {Object} requestMeta - Metadata from the HTTP request.
 * @returns {winston.Logger} A child logger instance.
 */
function createRequestLogger(requestMeta) {
  return logger.child(requestMeta);
}

module.exports = {
  logger,
  logAudit,
  createRequestLogger,
};