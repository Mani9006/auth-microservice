/**
 * Admin Controller
 * Handles administrative operations: role management, permission management,
 * audit log access, and system-level operations.
 */

'use strict';

const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const rbacService = require('../services/rbacService');
const auditService = require('../services/auditService');
const tokenService = require('../services/tokenService');
const { logger } = require('../utils/logger');

// ==========================================
// Role Management
// ==========================================

/**
 * GET /admin/roles
 * List all roles.
 */
async function listRoles(req, res, next) {
  try {
    const roles = await Role.findAll();

    res.status(200).json({
      success: true,
      data: { roles },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /admin/roles/:roleId
 * Get a specific role.
 */
async function getRole(req, res, next) {
  try {
    const { roleId } = req.params;
    const role = await Role.findById(roleId);

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      });
    }

    // Include effective permissions
    const effectivePermissions = await rbacService.getEffectivePermissions(role.name);

    res.status(200).json({
      success: true,
      data: {
        role: {
          ...role,
          effectivePermissions,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/roles
 * Create a new role.
 */
async function createRole(req, res, next) {
  try {
    const { name, description, permissions } = req.body;

    const role = await rbacService.createRole({
      name,
      description,
      permissions,
    });

    await auditService.logRoleAction(auditService.ACTIONS.ROLE_CREATE, {
      performedBy: req.user.userId,
      roleId: role.id,
      roleName: role.name,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Role '${name}' created by ${req.user.userId}`);

    res.status(201).json({
      success: true,
      message: 'Role created successfully',
      data: { role },
    });
  } catch (error) {
    if (error.code === 'DUPLICATE_ROLE') {
      return res.status(409).json({
        success: false,
        error: 'Role already exists',
        message: error.message,
        code: 'DUPLICATE_ROLE',
      });
    }
    if (error.code === 'INVALID_PERMISSION') {
      return res.status(400).json({
        success: false,
        error: 'Invalid permission',
        message: error.message,
        code: 'INVALID_PERMISSION',
      });
    }
    next(error);
  }
}

/**
 * PUT /admin/roles/:roleId
 * Update a role.
 */
async function updateRole(req, res, next) {
  try {
    const { roleId } = req.params;
    const { name, description, permissions } = req.body;

    const role = await rbacService.updateRole(roleId, {
      name,
      description,
      permissions,
    });

    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      });
    }

    await auditService.logRoleAction(auditService.ACTIONS.ROLE_UPDATE, {
      performedBy: req.user.userId,
      roleId: role.id,
      roleName: role.name,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Role '${role.name}' updated by ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'Role updated successfully',
      data: { role },
    });
  } catch (error) {
    if (error.code === 'SYSTEM_ROLE_PROTECTED') {
      return res.status(403).json({
        success: false,
        error: 'System role protected',
        message: error.message,
        code: 'SYSTEM_ROLE_PROTECTED',
      });
    }
    if (error.code === 'INVALID_PERMISSION') {
      return res.status(400).json({
        success: false,
        error: 'Invalid permission',
        message: error.message,
        code: 'INVALID_PERMISSION',
      });
    }
    next(error);
  }
}

/**
 * DELETE /admin/roles/:roleId
 * Delete a role.
 */
async function deleteRole(req, res, next) {
  try {
    const { roleId } = req.params;

    const role = await Role.findById(roleId);
    if (!role) {
      return res.status(404).json({
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      });
    }

    const deleted = await Role.remove(roleId);

    if (!deleted) {
      return res.status(403).json({
        success: false,
        error: 'Cannot delete system role',
        code: 'SYSTEM_ROLE_PROTECTED',
      });
    }

    await auditService.logRoleAction(auditService.ACTIONS.ROLE_DELETE, {
      performedBy: req.user.userId,
      roleId,
      roleName: role.name,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Role '${role.name}' deleted by ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'Role deleted successfully',
    });
  } catch (error) {
    if (error.code === 'SYSTEM_ROLE_PROTECTED') {
      return res.status(403).json({
        success: false,
        error: 'System role protected',
        message: error.message,
        code: 'SYSTEM_ROLE_PROTECTED',
      });
    }
    next(error);
  }
}

/**
 * POST /admin/roles/:roleId/permissions
 * Grant a permission to a role.
 */
async function grantPermission(req, res, next) {
  try {
    const { roleId } = req.params;
    const { permission } = req.body;

    const result = await rbacService.grantPermission(roleId, permission);

    if (!result.success) {
      return res.status(404).json({
        success: false,
        error: result.message,
        code: result.message.includes('Permission') ? 'INVALID_PERMISSION' : 'ROLE_NOT_FOUND',
      });
    }

    await auditService.logRoleAction(auditService.ACTIONS.PERMISSION_GRANT, {
      performedBy: req.user.userId,
      roleId,
      permission,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Permission '${permission}' granted to role by ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: `Permission '${permission}' granted successfully`,
      data: { role: result.role },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * DELETE /admin/roles/:roleId/permissions/:permissionKey
 * Revoke a permission from a role.
 */
async function revokePermission(req, res, next) {
  try {
    const { roleId, permissionKey } = req.params;

    const result = await rbacService.revokePermission(roleId, permissionKey);

    if (!result.success) {
      return res.status(404).json({
        success: false,
        error: result.message,
        code: 'ROLE_NOT_FOUND',
      });
    }

    await auditService.logRoleAction(auditService.ACTIONS.PERMISSION_REVOKE, {
      performedBy: req.user.userId,
      roleId,
      permission: permissionKey,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Permission '${permissionKey}' revoked from role by ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: `Permission '${permissionKey}' revoked successfully`,
      data: { role: result.role },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/users/:userId/role
 * Assign a role to a user.
 */
async function assignRole(req, res, next) {
  try {
    const { userId } = req.params;
    const { role } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    const roleExists = await Role.findByName(role);
    if (!roleExists) {
      return res.status(404).json({
        success: false,
        error: 'Role not found',
        code: 'ROLE_NOT_FOUND',
      });
    }

    const result = await rbacService.assignRoleToUser(userId, role);

    await auditService.logRoleAction(auditService.ACTIONS.ROLE_ASSIGN, {
      performedBy: req.user.userId,
      targetUserId: userId,
      roleName: role,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      message: result.message,
      data: { role: result.role },
    });
  } catch (error) {
    next(error);
  }
}

// ==========================================
// Permission Management
// ==========================================

/**
 * GET /admin/permissions
 * List all permissions.
 */
async function listPermissions(req, res, next) {
  try {
    const permissions = await Permission.findAll();
    const grouped = await Permission.getGroupedByResource();

    res.status(200).json({
      success: true,
      data: {
        permissions,
        grouped,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/permissions
 * Create a new permission.
 */
async function createPermission(req, res, next) {
  try {
    const { key, description } = req.body;

    const permission = await Permission.create({
      key,
      description,
    });

    await auditService.logRoleAction(auditService.ACTIONS.PERMISSION_CREATE, {
      performedBy: req.user.userId,
      permission,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`Permission '${key}' created by ${req.user.userId}`);

    res.status(201).json({
      success: true,
      message: 'Permission created successfully',
      data: { permission },
    });
  } catch (error) {
    if (error.code === 'DUPLICATE_PERMISSION') {
      return res.status(409).json({
        success: false,
        error: 'Permission already exists',
        message: error.message,
        code: 'DUPLICATE_PERMISSION',
      });
    }
    if (error.code === 'INVALID_PERMISSION_KEY') {
      return res.status(400).json({
        success: false,
        error: 'Invalid permission key',
        message: error.message,
        code: 'INVALID_PERMISSION_KEY',
      });
    }
    next(error);
  }
}

/**
 * DELETE /admin/permissions/:permissionId
 * Delete a permission.
 */
async function deletePermission(req, res, next) {
  try {
    const { permissionId } = req.params;

    const permission = await Permission.findById(permissionId);
    if (!permission) {
      return res.status(404).json({
        success: false,
        error: 'Permission not found',
        code: 'PERMISSION_NOT_FOUND',
      });
    }

    const deleted = await Permission.remove(permissionId);

    if (!deleted) {
      return res.status(403).json({
        success: false,
        error: 'Cannot delete system permission',
        code: 'SYSTEM_PERMISSION_PROTECTED',
      });
    }

    await auditService.logRoleAction(auditService.ACTIONS.PERMISSION_DELETE, {
      performedBy: req.user.userId,
      permissionKey: permission.key,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      message: 'Permission deleted successfully',
    });
  } catch (error) {
    if (error.code === 'SYSTEM_PERMISSION_PROTECTED') {
      return res.status(403).json({
        success: false,
        error: 'System permission protected',
        message: error.message,
        code: 'SYSTEM_PERMISSION_PROTECTED',
      });
    }
    next(error);
  }
}

// ==========================================
// Audit Log Access
// ==========================================

/**
 * GET /admin/audit-logs
 * Get audit logs with filtering.
 */
async function getAuditLogs(req, res, next) {
  try {
    const filters = {
      limit: parseInt(req.query.limit, 10) || 50,
      offset: parseInt(req.query.offset, 10) || 0,
      userId: req.query.userId,
      action: req.query.action,
      resource: req.query.resource,
      severity: req.query.severity,
      success: req.query.success !== undefined ? req.query.success === 'true' : undefined,
      startDate: req.query.startDate,
      endDate: req.query.endDate,
    };

    // Remove undefined filters
    Object.keys(filters).forEach(key => {
      if (filters[key] === undefined) delete filters[key];
    });

    const { logs, total } = await auditService.searchLogs(filters);

    res.status(200).json({
      success: true,
      data: {
        logs,
        pagination: {
          total,
          limit: filters.limit,
          offset: filters.offset,
          hasMore: filters.offset + logs.length < total,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /admin/audit-logs/stats
 * Get audit log statistics.
 */
async function getAuditStats(req, res, next) {
  try {
    const stats = await auditService.getStatistics();

    res.status(200).json({
      success: true,
      data: stats,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/audit-logs/verify
 * Verify audit log integrity.
 */
async function verifyAuditIntegrity(req, res, next) {
  try {
    const result = await auditService.verifyIntegrity();

    await auditService.logAuth(auditService.ACTIONS.AUDIT_INTEGRITY_CHECK, {
      userId: req.user.userId,
      success: result.isValid,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

// ==========================================
// System Operations
// ==========================================

/**
 * GET /admin/stats
 * Get system statistics.
 */
async function getSystemStats(req, res, next) {
  try {
    const userCount = await User.count();
    const roles = await Role.findAll();
    const permissions = await Permission.findAll();
    const blacklistStats = await tokenService.getBlacklistStats();

    const rbacStats = await rbacService.getStats();
    const auditStats = await auditService.getStatistics();

    const memUsage = process.memoryUsage();

    res.status(200).json({
      success: true,
      data: {
        users: {
          total: userCount,
        },
        roles: {
          total: roles.length,
          list: roles.map(r => r.name),
        },
        permissions: {
          total: permissions.length,
          resources: [...new Set(permissions.map(p => p.resource))],
        },
        rbac: rbacStats,
        audit: auditStats,
        security: {
          blacklistedTokens: blacklistStats,
        },
        system: {
          uptime: process.uptime(),
          memory: {
            rss: Math.round(memUsage.rss / 1024 / 1024 * 100) / 100, // MB
            heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024 * 100) / 100,
            heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024 * 100) / 100,
            external: Math.round(memUsage.external / 1024 / 1024 * 100) / 100,
          },
          nodeVersion: process.version,
          pid: process.pid,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/users/:userId/deactivate
 * Deactivate a user account.
 */
async function deactivateUser(req, res, next) {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    if (!user.isActive) {
      return res.status(400).json({
        success: false,
        error: 'Already deactivated',
        message: 'User account is already deactivated',
        code: 'ALREADY_DEACTIVATED',
      });
    }

    await User.update(userId, { isActive: false });

    // Revoke all tokens for this user
    await tokenService.revokeAllUserTokens(userId);

    await auditService.logUserAction(auditService.ACTIONS.USER_DEACTIVATE, {
      userId: req.user.userId,
      targetUserId: userId,
      targetEmail: user.email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`User ${userId} deactivated by admin ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'User deactivated successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /admin/users/:userId/activate
 * Activate a user account.
 */
async function activateUser(req, res, next) {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    if (user.isActive) {
      return res.status(400).json({
        success: false,
        error: 'Already active',
        message: 'User account is already active',
        code: 'ALREADY_ACTIVE',
      });
    }

    await User.update(userId, { isActive: true, failedLoginAttempts: 0, lockedUntil: null });

    await auditService.logUserAction(auditService.ACTIONS.USER_ACTIVATE, {
      userId: req.user.userId,
      targetUserId: userId,
      targetEmail: user.email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`User ${userId} activated by admin ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'User activated successfully',
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  // Roles
  listRoles,
  getRole,
  createRole,
  updateRole,
  deleteRole,
  grantPermission,
  revokePermission,
  assignRole,

  // Permissions
  listPermissions,
  createPermission,
  deletePermission,

  // Audit
  getAuditLogs,
  getAuditStats,
  verifyAuditIntegrity,

  // System
  getSystemStats,
  deactivateUser,
  activateUser,
};