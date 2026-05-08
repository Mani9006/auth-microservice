/**
 * Admin Routes
 * Administrative endpoints for role management, permission management,
 * audit log access, and system operations.
 */

'use strict';

const express = require('express');
const router = express.Router();

const adminController = require('../controllers/adminController');
const { authenticate } = require('../middleware/authenticate');
const { requirePermission, requireRole } = require('../middleware/authorize');
const { adminLimiter } = require('../middleware/rateLimiter');
const {
  validateRoleCreate,
  validatePermissionCreate,
  validateAuditQuery,
  validateUUIDParam,
} = require('../middleware/validation');

// ==========================================
// All admin routes require authentication + admin role
// ==========================================

router.use(authenticate());
router.use(requireRole('admin', 'moderator'));
router.use(adminLimiter);

// ==========================================
// Role Management
// ==========================================

/**
 * @route   GET /admin/roles
 * @desc    List all roles
 * @access  Admin
 */
router.get('/roles',
  requirePermission('role:list'),
  adminController.listRoles
);

/**
 * @route   GET /admin/roles/:roleId
 * @desc    Get a specific role with effective permissions
 * @access  Admin
 */
router.get('/roles/:roleId',
  requirePermission('role:read'),
  adminController.getRole
);

/**
 * @route   POST /admin/roles
 * @desc    Create a new role
 * @access  Admin (role:create permission)
 * @body    { name, description?, permissions? }
 */
router.post('/roles',
  requirePermission('role:create'),
  validateRoleCreate,
  adminController.createRole
);

/**
 * @route   PUT /admin/roles/:roleId
 * @desc    Update a role
 * @access  Admin (role:update permission)
 */
router.put('/roles/:roleId',
  requirePermission('role:update'),
  validateUUIDParam('roleId'),
  adminController.updateRole
);

/**
 * @route   DELETE /admin/roles/:roleId
 * @desc    Delete a role
 * @access  Admin (role:delete permission)
 */
router.delete('/roles/:roleId',
  requirePermission('role:delete'),
  validateUUIDParam('roleId'),
  adminController.deleteRole
);

/**
 * @route   POST /admin/roles/:roleId/permissions
 * @desc    Grant a permission to a role
 * @access  Admin (role:update permission)
 * @body    { permission }
 */
router.post('/roles/:roleId/permissions',
  requirePermission('role:update'),
  validateUUIDParam('roleId'),
  adminController.grantPermission
);

/**
 * @route   DELETE /admin/roles/:roleId/permissions/:permissionKey
 * @desc    Revoke a permission from a role
 * @access  Admin (role:update permission)
 */
router.delete('/roles/:roleId/permissions/:permissionKey',
  requirePermission('role:update'),
  validateUUIDParam('roleId'),
  adminController.revokePermission
);

/**
 * @route   POST /admin/users/:userId/role
 * @desc    Assign a role to a user
 * @access  Admin (role:assign permission)
 * @body    { role }
 */
router.post('/users/:userId/role',
  requirePermission('role:assign'),
  validateUUIDParam('userId'),
  adminController.assignRole
);

// ==========================================
// Permission Management
// ==========================================

/**
 * @route   GET /admin/permissions
 * @desc    List all permissions (grouped by resource)
 * @access  Admin
 */
router.get('/permissions',
  requirePermission('permission:list'),
  adminController.listPermissions
);

/**
 * @route   POST /admin/permissions
 * @desc    Create a new permission
 * @access  Admin (permission:create permission)
 * @body    { key, description? }
 */
router.post('/permissions',
  requirePermission('permission:create'),
  validatePermissionCreate,
  adminController.createPermission
);

/**
 * @route   DELETE /admin/permissions/:permissionId
 * @desc    Delete a permission
 * @access  Admin (permission:delete permission)
 */
router.delete('/permissions/:permissionId',
  requirePermission('permission:delete'),
  validateUUIDParam('permissionId'),
  adminController.deletePermission
);

// ==========================================
// Audit Log Access
// ==========================================

/**
 * @route   GET /admin/audit-logs
 * @desc    Get audit logs with filtering
 * @access  Admin/Moderator (audit:list permission)
 * @query   { limit?, offset?, userId?, action?, resource?, severity?, startDate?, endDate? }
 */
router.get('/audit-logs',
  requirePermission('audit:list'),
  validateAuditQuery,
  adminController.getAuditLogs
);

/**
 * @route   GET /admin/audit-logs/stats
 * @desc    Get audit log statistics
 * @access  Admin (audit:read permission)
 */
router.get('/audit-logs/stats',
  requirePermission('audit:read'),
  adminController.getAuditStats
);

/**
 * @route   POST /admin/audit-logs/verify
 * @desc    Verify audit log integrity
 * @access  Admin
 */
router.post('/audit-logs/verify',
  requirePermission('audit:read'),
  adminController.verifyAuditIntegrity
);

// ==========================================
// System Operations
// ==========================================

/**
 * @route   GET /admin/stats
 * @desc    Get comprehensive system statistics
 * @access  Admin
 */
router.get('/stats',
  requirePermission('system:metrics'),
  adminController.getSystemStats
);

/**
 * @route   POST /admin/users/:userId/deactivate
 * @desc    Deactivate a user account
 * @access  Admin
 */
router.post('/users/:userId/deactivate',
  requirePermission('user:update'),
  validateUUIDParam('userId'),
  adminController.deactivateUser
);

/**
 * @route   POST /admin/users/:userId/activate
 * @desc    Activate a user account
 * @access  Admin
 */
router.post('/users/:userId/activate',
  requirePermission('user:update'),
  validateUUIDParam('userId'),
  adminController.activateUser
);

module.exports = router;