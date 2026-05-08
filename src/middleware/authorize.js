/**
 * Authorization middleware for RBAC permission checking.
 * Uses the RBAC service to verify users have required permissions.
 */

'use strict';

const rbacService = require('../services/rbacService');
const auditService = require('../services/auditService');
const { logger } = require('../utils/logger');

/**
 * Authorize middleware - requires specific permissions.
 * @param {...string} permissions - Required permission keys.
 * @returns {Function} Express middleware function.
 */
function requirePermission(...permissions) {
  return async (req, res, next) => {
    try {
      // Ensure user is authenticated
      if (!req.user) {
        await auditService.logUnauthorized(req, req.path, 'No authenticated user');
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'You must be authenticated to access this resource',
          code: 'AUTH_REQUIRED',
        });
      }

      const userRole = req.user.role;

      // Check if user has ALL required permissions
      const hasAll = await rbacService.hasAllPermissions(userRole, permissions);

      if (!hasAll) {
        // Find which specific permission is missing
        const missingPermissions = [];
        for (const perm of permissions) {
          const has = await rbacService.hasPermission(userRole, perm);
          if (!has) missingPermissions.push(perm);
        }

        logger.warn(`Authorization failed for user ${req.user.userId}: missing permissions [${missingPermissions.join(', ')}]`);
        await auditService.logForbidden(req, req.path, missingPermissions.join(', '));

        return res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'You do not have permission to perform this action',
          code: 'FORBIDDEN',
          requiredPermissions: permissions,
          missingPermissions,
        });
      }

      logger.debug(`User ${req.user.userId} authorized for permissions: [${permissions.join(', ')}]`);
      next();
    } catch (error) {
      logger.error(`Authorization middleware error: ${error.message}`);
      next(error);
    }
  };
}

/**
 * Authorize middleware - requires ANY of the specified permissions.
 * @param {...string} permissions - Permission keys (any one suffices).
 * @returns {Function} Express middleware function.
 */
function requireAnyPermission(...permissions) {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        await auditService.logUnauthorized(req, req.path, 'No authenticated user');
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'You must be authenticated to access this resource',
          code: 'AUTH_REQUIRED',
        });
      }

      const userRole = req.user.role;
      const hasAny = await rbacService.hasAnyPermission(userRole, permissions);

      if (!hasAny) {
        logger.warn(`Authorization failed for user ${req.user.userId}: none of [${permissions.join(', ')}] granted`);
        await auditService.logForbidden(req, req.path, permissions.join(' or '));

        return res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'You do not have any of the required permissions',
          code: 'FORBIDDEN',
          requiredPermissions: permissions,
        });
      }

      next();
    } catch (error) {
      logger.error(`Authorization middleware error: ${error.message}`);
      next(error);
    }
  };
}

/**
 * Require a specific role (not recommended - prefer permissions).
 * @param {...string} roles - Allowed role names.
 * @returns {Function} Express middleware function.
 */
function requireRole(...roles) {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'You must be authenticated to access this resource',
          code: 'AUTH_REQUIRED',
        });
      }

      const userRole = req.user.role;

      if (!roles.includes(userRole)) {
        logger.warn(`Role check failed for user ${req.user.userId}: required [${roles.join(', ')}], has ${userRole}`);
        await auditService.logForbidden(req, req.path, `Role: ${userRole}`);

        return res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'Your role does not have access to this resource',
          code: 'FORBIDDEN',
          requiredRoles: roles,
          currentRole: userRole,
        });
      }

      next();
    } catch (error) {
      logger.error(`Role authorization middleware error: ${error.message}`);
      next(error);
    }
  };
}

/**
 * Middleware to ensure users can only access their own resources.
 * Admins can access any resource.
 * @param {string} [paramName='userId'] - The route parameter containing the target user ID.
 * @returns {Function} Express middleware function.
 */
function requireOwnershipOrAdmin(paramName = 'userId') {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTH_REQUIRED',
        });
      }

      const targetUserId = req.params[paramName];
      const currentUserId = req.user.userId;
      const currentRole = req.user.role;

      // Admins can access any resource
      if (currentRole === 'admin') {
        return next();
      }

      // Check ownership
      if (targetUserId !== currentUserId) {
        logger.warn(`Ownership check failed: user ${currentUserId} tried to access ${targetUserId}'s resource`);
        await auditService.logForbidden(req, req.path, 'resource:owner');

        return res.status(403).json({
          success: false,
          error: 'Access denied',
          message: 'You can only access your own resources',
          code: 'NOT_OWNER',
        });
      }

      next();
    } catch (error) {
      logger.error(`Ownership middleware error: ${error.message}`);
      next(error);
    }
  };
}

module.exports = {
  requirePermission,
  requireAnyPermission,
  requireRole,
  requireOwnershipOrAdmin,
};