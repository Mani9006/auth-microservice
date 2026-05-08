/**
 * Audit Service provides a high-level interface for security event logging.
 * Wraps the AuditLog model with specific event type helpers.
 */

'use strict';

const AuditLog = require('../models/AuditLog');
const { logger } = require('../utils/logger');

// Common action types for consistency
const ACTIONS = {
  // Authentication events
  USER_REGISTER: 'USER_REGISTER',
  USER_LOGIN: 'USER_LOGIN',
  USER_LOGOUT: 'USER_LOGOUT',
  LOGIN_FAILED: 'LOGIN_FAILED',
  TOKEN_REFRESH: 'TOKEN_REFRESH',
  TOKEN_ROTATION: 'TOKEN_ROTATION',

  // Password events
  PASSWORD_CHANGE: 'PASSWORD_CHANGE',
  PASSWORD_RESET_REQUEST: 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_COMPLETE: 'PASSWORD_RESET_COMPLETE',

  // User management
  USER_CREATE: 'USER_CREATE',
  USER_UPDATE: 'USER_UPDATE',
  USER_DELETE: 'USER_DELETE',
  USER_READ: 'USER_READ',
  USER_LIST: 'USER_LIST',
  USER_ACTIVATE: 'USER_ACTIVATE',
  USER_DEACTIVATE: 'USER_DEACTIVATE',

  // Role management
  ROLE_CREATE: 'ROLE_CREATE',
  ROLE_UPDATE: 'ROLE_UPDATE',
  ROLE_DELETE: 'ROLE_DELETE',
  ROLE_ASSIGN: 'ROLE_ASSIGN',
  ROLE_REVOKE: 'ROLE_REVOKE',

  // Permission management
  PERMISSION_CREATE: 'PERMISSION_CREATE',
  PERMISSION_UPDATE: 'PERMISSION_UPDATE',
  PERMISSION_DELETE: 'PERMISSION_DELETE',
  PERMISSION_GRANT: 'PERMISSION_GRANT',
  PERMISSION_REVOKE: 'PERMISSION_REVOKE',

  // Security events
  TOKEN_BLACKLISTED: 'TOKEN_BLACKLISTED',
  TOKEN_REUSE_DETECTED: 'TOKEN_REUSE_DETECTED',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED: 'ACCOUNT_UNLOCKED',
  UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
  FORBIDDEN_ACCESS: 'FORBIDDEN_ACCESS',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',

  // Audit events
  AUDIT_READ: 'AUDIT_READ',
  AUDIT_EXPORT: 'AUDIT_EXPORT',
  AUDIT_INTEGRITY_CHECK: 'AUDIT_INTEGRITY_CHECK',

  // System events
  SYSTEM_STARTUP: 'SYSTEM_STARTUP',
  SYSTEM_SHUTDOWN: 'SYSTEM_SHUTDOWN',
  SYSTEM_CONFIG_CHANGE: 'SYSTEM_CONFIG_CHANGE',
};

/**
 * Log a generic audit event.
 * @param {Object} eventData - Event details.
 */
async function log(eventData) {
  try {
    return await AuditLog.create(eventData);
  } catch (error) {
    logger.error(`Failed to write audit log: ${error.message}`);
    // Don't throw - audit logging should not break the application
    return null;
  }
}

/**
 * Log an authentication event.
 * @param {string} action - The auth action.
 * @param {Object} details - Event details.
 */
async function logAuth(action, details) {
  return log({
    userId: details.userId || 'anonymous',
    action,
    resource: 'auth',
    success: details.success,
    ip: details.ip,
    userAgent: details.userAgent,
    details: {
      email: details.email,
      method: details.method || 'local',
      reason: details.reason,
      tokenJti: details.tokenJti,
    },
    severity: details.success ? 'info' : 'warning',
  });
}

/**
 * Log a user management event.
 * @param {string} action - The user action.
 * @param {Object} details - Event details.
 */
async function logUserAction(action, details) {
  return log({
    userId: details.performedBy || details.userId || 'system',
    action,
    resource: 'user',
    success: details.success,
    ip: details.ip,
    userAgent: details.userAgent,
    details: {
      targetUserId: details.targetUserId,
      targetEmail: details.targetEmail,
      changes: details.changes,
      reason: details.reason,
    },
    severity: details.success ? 'info' : 'warning',
  });
}

/**
 * Log a role/permission management event.
 * @param {string} action - The role/permission action.
 * @param {Object} details - Event details.
 */
async function logRoleAction(action, details) {
  return log({
    userId: details.performedBy || 'system',
    action,
    resource: 'role',
    success: details.success,
    ip: details.ip,
    userAgent: details.userAgent,
    details: {
      roleId: details.roleId,
      roleName: details.roleName,
      permission: details.permission,
      targetUserId: details.targetUserId,
    },
    severity: details.success ? 'info' : 'warning',
  });
}

/**
 * Log a security event (higher severity).
 * @param {string} action - The security action.
 * @param {Object} details - Event details.
 * @param {string} [severity='warning'] - Event severity.
 */
async function logSecurityEvent(action, details, severity = 'warning') {
  return log({
    userId: details.userId || 'anonymous',
    action,
    resource: 'security',
    success: details.success,
    ip: details.ip,
    userAgent: details.userAgent,
    details: {
      reason: details.reason,
      threatLevel: details.threatLevel,
      evidence: details.evidence,
      ...details.extra,
    },
    severity,
  });
}

/**
 * Log an unauthorized access attempt.
 * @param {Object} req - Express request object.
 * @param {string} resource - The resource being accessed.
 * @param {string} reason - Why it was unauthorized.
 */
async function logUnauthorized(req, resource, reason) {
  return logSecurityEvent(ACTIONS.UNAUTHORIZED_ACCESS, {
    userId: req.user?.userId || 'anonymous',
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    success: false,
    reason,
    extra: {
      resource,
      method: req.method,
      path: req.path,
    },
  }, 'warning');
}

/**
 * Log a forbidden access attempt.
 * @param {Object} req - Express request object.
 * @param {string} resource - The resource being accessed.
 * @param {string} requiredPermission - The permission that was missing.
 */
async function logForbidden(req, resource, requiredPermission) {
  return logSecurityEvent(ACTIONS.FORBIDDEN_ACCESS, {
    userId: req.user?.userId || 'anonymous',
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    success: false,
    reason: `Missing permission: ${requiredPermission}`,
    extra: {
      resource,
      requiredPermission,
      userRole: req.user?.role,
      method: req.method,
      path: req.path,
    },
  }, 'warning');
}

/**
 * Log a rate limit exceeded event.
 * @param {Object} req - Express request object.
 * @param {string} endpoint - The endpoint that was rate limited.
 */
async function logRateLimitExceeded(req, endpoint) {
  return logSecurityEvent(ACTIONS.RATE_LIMIT_EXCEEDED, {
    userId: req.user?.userId || 'anonymous',
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'],
    success: false,
    reason: 'Rate limit exceeded',
    extra: {
      endpoint,
      method: req.method,
    },
  }, 'warning');
}

/**
 * Log a token reuse detection event (security breach).
 * @param {Object} details - Event details.
 */
async function logTokenReuse(details) {
  return logSecurityEvent(ACTIONS.TOKEN_REUSE_DETECTED, {
    userId: details.userId,
    ip: details.ip,
    userAgent: details.userAgent,
    success: false,
    reason: 'Refresh token reuse detected - possible token theft',
    threatLevel: 'high',
    evidence: {
      jti: details.jti,
      timestamp: new Date().toISOString(),
    },
  }, 'critical');
}

/**
 * Log system startup event.
 */
async function logSystemStartup() {
  return log({
    userId: 'system',
    action: ACTIONS.SYSTEM_STARTUP,
    resource: 'system',
    success: true,
    ip: '127.0.0.1',
    details: {
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      pid: process.pid,
    },
    severity: 'info',
  });
}

/**
 * Get recent audit events.
 * @param {number} count - Number of events to retrieve.
 * @returns {Promise<Array>} Recent audit events.
 */
async function getRecentEvents(count = 10) {
  return AuditLog.getRecent(count);
}

/**
 * Get audit statistics.
 * @returns {Promise<Object>} Audit statistics.
 */
async function getStatistics() {
  return AuditLog.getStats();
}

/**
 * Verify audit log integrity.
 * @returns {Promise<Object>} Integrity check result.
 */
async function verifyIntegrity() {
  return AuditLog.verifyIntegrity();
}

/**
 * Search audit logs with filters.
 * @param {Object} filters - Search filters.
 * @returns {Promise<Object>} Filtered logs and total count.
 */
async function searchLogs(filters) {
  return AuditLog.findWithFilters(filters);
}

module.exports = {
  ACTIONS,
  log,
  logAuth,
  logUserAction,
  logRoleAction,
  logSecurityEvent,
  logUnauthorized,
  logForbidden,
  logRateLimitExceeded,
  logTokenReuse,
  logSystemStartup,
  getRecentEvents,
  getStatistics,
  verifyIntegrity,
  searchLogs,
};