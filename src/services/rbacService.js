/**
 * RBAC (Role-Based Access Control) Service.
 * Provides role and permission management with hierarchy support.
 */

'use strict';

const Role = require('../models/Role');
const Permission = require('../models/Permission');
const { logger } = require('../utils/logger');

/**
 * Role hierarchy for inheritance.
 * Higher roles inherit permissions from lower roles.
 */
const ROLE_HIERARCHY = {
  admin: ['moderator', 'user', 'guest'],
  moderator: ['user', 'guest'],
  user: ['guest'],
  guest: [],
};

/**
 * Check if a user has a specific permission.
 * Checks direct permissions and inherited permissions through role hierarchy.
 * @param {string} roleName - The user's role name.
 * @param {string} requiredPermission - The permission to check.
 * @returns {Promise<boolean>} True if the user has the permission.
 */
async function hasPermission(roleName, requiredPermission) {
  // Check direct permission
  const hasDirect = await Role.hasPermission(roleName, requiredPermission);
  if (hasDirect) return true;

  // Check inherited permissions through role hierarchy
  const inheritedRoles = ROLE_HIERARCHY[roleName] || [];
  for (const inheritedRole of inheritedRoles) {
    const hasInherited = await Role.hasPermission(inheritedRole, requiredPermission);
    if (hasInherited) return true;
  }

  return false;
}

/**
 * Check if a user has ALL of the specified permissions.
 * @param {string} roleName - The user's role name.
 * @param {Array<string>} requiredPermissions - Array of required permissions.
 * @returns {Promise<boolean>} True if the user has all permissions.
 */
async function hasAllPermissions(roleName, requiredPermissions) {
  if (!requiredPermissions || requiredPermissions.length === 0) return true;

  for (const permission of requiredPermissions) {
    const has = await hasPermission(roleName, permission);
    if (!has) return false;
  }

  return true;
}

/**
 * Check if a user has ANY of the specified permissions.
 * @param {string} roleName - The user's role name.
 * @param {Array<string>} requiredPermissions - Array of permissions (any one suffices).
 * @returns {Promise<boolean>} True if the user has at least one permission.
 */
async function hasAnyPermission(roleName, requiredPermissions) {
  if (!requiredPermissions || requiredPermissions.length === 0) return true;

  for (const permission of requiredPermissions) {
    const has = await hasPermission(roleName, permission);
    if (has) return true;
  }

  return false;
}

/**
 * Get all permissions for a role including inherited ones.
 * @param {string} roleName - The role name.
 * @returns {Promise<Array<string>>} Array of all effective permissions.
 */
async function getEffectivePermissions(roleName) {
  const directPermissions = await Role.getRolePermissions(roleName);

  // Get inherited permissions
  const inheritedRoles = ROLE_HIERARCHY[roleName] || [];
  const inheritedPermissions = new Set(directPermissions);

  for (const inheritedRole of inheritedRoles) {
    const perms = await Role.getRolePermissions(inheritedRole);
    for (const perm of perms) {
      inheritedPermissions.add(perm);
    }
  }

  return Array.from(inheritedPermissions);
}

/**
 * Get all roles in the hierarchy below (and including) the given role.
 * @param {string} roleName - The role name.
 * @returns {Array<string>} Array of role names.
 */
function getRoleHierarchy(roleName) {
  const roles = [roleName];
  const inherited = ROLE_HIERARCHY[roleName] || [];
  roles.push(...inherited);
  return roles;
}

/**
 * Check if a role is higher in hierarchy than another.
 * @param {string} roleA - The first role.
 * @param {string} roleB - The second role to compare against.
 * @returns {boolean} True if roleA is higher or equal to roleB.
 */
function isRoleHigherOrEqual(roleA, roleB) {
  if (roleA === roleB) return true;

  const hierarchyA = ROLE_HIERARCHY[roleA] || [];
  if (hierarchyA.includes(roleB)) return true;

  // Check transitive
  for (const inherited of hierarchyA) {
    const inheritedHierarchy = ROLE_HIERARCHY[inherited] || [];
    if (inheritedHierarchy.includes(roleB)) return true;
  }

  return false;
}

/**
 * Get roles that can be assigned by a given role.
 * A role can assign roles at or below its level.
 * @param {string} assignerRole - The role doing the assigning.
 * @returns {Promise<Array>} Array of assignable roles.
 */
async function getAssignableRoles(assignerRole) {
  const allRoles = await Role.findAll();
  return allRoles.filter(role => isRoleHigherOrEqual(assignerRole, role.name));
}

/**
 * Assign a role to a user.
 * @param {string} userId - The user ID.
 * @param {string} roleName - The role to assign.
 * @returns {Promise<Object>} Result with success flag.
 */
async function assignRoleToUser(userId, roleName) {
  const role = await Role.findByName(roleName);
  if (!role) {
    return { success: false, message: 'Role not found' };
  }

  const User = require('../models/User');
  await User.update(userId, { role: roleName });

  logger.info(`Assigned role '${roleName}' to user ${userId}`);

  return {
    success: true,
    message: `Role '${roleName}' assigned successfully`,
    role: roleName,
  };
}

/**
 * Revoke a role from a user (assign default role).
 * @param {string} userId - The user ID.
 * @returns {Promise<Object>} Result with success flag.
 */
async function revokeRoleFromUser(userId) {
  const User = require('../models/User');
  const defaultRole = await Role.getDefaultRole();

  if (!defaultRole) {
    return { success: false, message: 'No default role configured' };
  }

  await User.update(userId, { role: defaultRole.name });

  logger.info(`Revoked custom role from user ${userId}, assigned default '${defaultRole.name}'`);

  return {
    success: true,
    message: `Role revoked, assigned default '${defaultRole.name}'`,
    role: defaultRole.name,
  };
}

/**
 * Create a new role with permissions.
 * @param {Object} roleData - The role data.
 * @returns {Promise<Object>} The created role.
 */
async function createRole(roleData) {
  // Validate permissions exist
  if (roleData.permissions && roleData.permissions.length > 0) {
    for (const perm of roleData.permissions) {
      if (perm === '*') continue; // Admin wildcard is always valid
      const exists = await Permission.exists(perm);
      if (!exists) {
        const error = new Error(`Permission '${perm}' does not exist`);
        error.code = 'INVALID_PERMISSION';
        throw error;
      }
    }
  }

  return Role.create(roleData);
}

/**
 * Update role permissions.
 * @param {string} roleId - The role ID.
 * @param {Object} updates - Fields to update.
 * @returns {Promise<Object|null>} The updated role.
 */
async function updateRole(roleId, updates) {
  if (updates.permissions) {
    for (const perm of updates.permissions) {
      if (perm === '*') continue;
      const exists = await Permission.exists(perm);
      if (!exists) {
        const error = new Error(`Permission '${perm}' does not exist`);
        error.code = 'INVALID_PERMISSION';
        throw error;
      }
    }
  }

  return Role.update(roleId, updates);
}

/**
 * Grant a permission to a role.
 * @param {string} roleId - The role ID.
 * @param {string} permissionKey - The permission key (e.g., 'user:read').
 * @returns {Promise<Object>} Result with success flag.
 */
async function grantPermission(roleId, permissionKey) {
  if (permissionKey !== '*') {
    const exists = await Permission.exists(permissionKey);
    if (!exists) {
      return { success: false, message: `Permission '${permissionKey}' does not exist` };
    }
  }

  const result = await Role.grantPermission(roleId, permissionKey);
  if (!result) {
    return { success: false, message: 'Role not found' };
  }

  logger.info(`Granted permission '${permissionKey}' to role ${result.name}`);

  return { success: true, role: result };
}

/**
 * Revoke a permission from a role.
 * @param {string} roleId - The role ID.
 * @param {string} permissionKey - The permission key.
 * @returns {Promise<Object>} Result with success flag.
 */
async function revokePermission(roleId, permissionKey) {
  const result = await Role.revokePermission(roleId, permissionKey);
  if (!result) {
    return { success: false, message: 'Role not found' };
  }

  logger.info(`Revoked permission '${permissionKey}' from role ${result.name}`);

  return { success: true, role: result };
}

/**
 * Get RBAC statistics.
 * @returns {Promise<Object>} Statistics about roles and permissions.
 */
async function getStats() {
  const roles = await Role.findAll();
  const permissions = await Permission.findAll();

  const roleStats = {};
  for (const role of roles) {
    const effectivePerms = await getEffectivePermissions(role.name);
    roleStats[role.name] = {
      totalPermissions: role.permissions.length,
      effectivePermissions: effectivePerms.length,
      isSystem: role.isSystem,
      isDefault: role.isDefault,
    };
  }

  return {
    totalRoles: roles.length,
    totalPermissions: permissions.length,
    totalResources: [...new Set(permissions.map(p => p.resource))].length,
    roles: roleStats,
    hierarchy: ROLE_HIERARCHY,
  };
}

module.exports = {
  hasPermission,
  hasAllPermissions,
  hasAnyPermission,
  getEffectivePermissions,
  getRoleHierarchy,
  isRoleHigherOrEqual,
  getAssignableRoles,
  assignRoleToUser,
  revokeRoleFromUser,
  createRole,
  updateRole,
  grantPermission,
  revokePermission,
  getStats,
};