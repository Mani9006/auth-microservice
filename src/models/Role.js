/**
 * Role model for RBAC (Role-Based Access Control).
 * Defines roles and their associated permissions using JSON file storage.
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const { logger } = require('../utils/logger');

const ROLES_FILE = path.join(config.storage.dataDir, config.storage.rolesFile);

// In-memory cache
let roleCache = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 30000;

/**
 * Predefined role definitions with descriptions.
 */
const DEFAULT_ROLES = [
  {
    id: 'role-admin',
    name: 'admin',
    description: 'System administrator with full access to all resources',
    permissions: ['*'], // Wildcard grants all permissions
    isDefault: false,
    isSystem: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'role-user',
    name: 'user',
    description: 'Standard user with access to own profile and basic features',
    permissions: [
      'user:read',
      'user:update',
      'user:change-password',
      'user:delete-own',
    ],
    isDefault: true,
    isSystem: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'role-moderator',
    name: 'moderator',
    description: 'Content moderator with user management and audit access',
    permissions: [
      'user:read',
      'user:update',
      'user:change-password',
      'user:list',
      'audit:read',
      'audit:list',
    ],
    isDefault: false,
    isSystem: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'role-guest',
    name: 'guest',
    description: 'Guest user with minimal read-only access',
    permissions: [
      'user:read',
    ],
    isDefault: false,
    isSystem: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
];

/**
 * Read roles from the JSON file.
 * @returns {Promise<Array>} Array of role objects.
 */
async function readRoles() {
  const now = Date.now();
  if (roleCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return [...roleCache];
  }

  try {
    const data = await fs.readFile(ROLES_FILE, 'utf8');
    const roles = JSON.parse(data);
    roleCache = roles;
    cacheTimestamp = now;
    return [...roles];
  } catch (error) {
    if (error.code === 'ENOENT') {
      roleCache = [];
      cacheTimestamp = now;
      return [];
    }
    logger.error(`Error reading roles file: ${error.message}`);
    throw error;
  }
}

/**
 * Write roles to the JSON file.
 * @param {Array} roles - Array of role objects.
 */
async function writeRoles(roles) {
  try {
    await fs.writeFile(ROLES_FILE, JSON.stringify(roles, null, 2), 'utf8');
    roleCache = [...roles];
    cacheTimestamp = Date.now();
  } catch (error) {
    logger.error(`Error writing roles file: ${error.message}`);
    throw error;
  }
}

/**
 * Create a new role.
 * @param {Object} roleData - The role data.
 * @param {string} roleData.name - Unique role name.
 * @param {string} [roleData.description] - Role description.
 * @param {Array<string>} [roleData.permissions] - Array of permission keys.
 * @returns {Promise<Object>} The created role.
 */
async function create(roleData) {
  const roles = await readRoles();

  // Check for duplicate name
  if (roles.some(r => r.name.toLowerCase() === roleData.name.toLowerCase())) {
    const error = new Error('Role name already exists');
    error.code = 'DUPLICATE_ROLE';
    throw error;
  }

  const newRole = {
    id: uuidv4(),
    name: roleData.name.toLowerCase().trim(),
    description: roleData.description || '',
    permissions: roleData.permissions || [],
    isDefault: false,
    isSystem: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  roles.push(newRole);
  await writeRoles(roles);
  return newRole;
}

/**
 * Find a role by ID.
 * @param {string} id - The role ID.
 * @returns {Promise<Object|null>} The role or null.
 */
async function findById(id) {
  const roles = await readRoles();
  return roles.find(r => r.id === id) || null;
}

/**
 * Find a role by name.
 * @param {string} name - The role name.
 * @returns {Promise<Object|null>} The role or null.
 */
async function findByName(name) {
  const roles = await readRoles();
  return roles.find(r => r.name.toLowerCase() === name.toLowerCase().trim()) || null;
}

/**
 * Get all roles.
 * @returns {Promise<Array>} Array of all roles.
 */
async function findAll() {
  return readRoles();
}

/**
 * Update a role.
 * @param {string} id - The role ID.
 * @param {Object} updates - Fields to update.
 * @returns {Promise<Object|null>} The updated role or null.
 */
async function update(id, updates) {
  const roles = await readRoles();
  const index = roles.findIndex(r => r.id === id);

  if (index === -1) return null;

  // Prevent modifying system roles' name
  if (roles[index].isSystem && updates.name && updates.name !== roles[index].name) {
    const error = new Error('Cannot rename system roles');
    error.code = 'SYSTEM_ROLE_PROTECTED';
    throw error;
  }

  const allowedUpdates = ['description', 'permissions'];
  if (!roles[index].isSystem) {
    allowedUpdates.push('name');
  }

  for (const key of Object.keys(updates)) {
    if (allowedUpdates.includes(key)) {
      roles[index][key] = updates[key];
    }
  }

  roles[index].updatedAt = new Date().toISOString();
  await writeRoles(roles);
  return roles[index];
}

/**
 * Delete a role (non-system only).
 * @param {string} id - The role ID.
 * @returns {Promise<boolean>} True if deleted.
 */
async function remove(id) {
  const roles = await readRoles();
  const role = roles.find(r => r.id === id);

  if (!role) return false;
  if (role.isSystem) {
    const error = new Error('Cannot delete system roles');
    error.code = 'SYSTEM_ROLE_PROTECTED';
    throw error;
  }

  const filtered = roles.filter(r => r.id !== id);
  await writeRoles(filtered);
  return true;
}

/**
 * Get permissions for a role.
 * @param {string} roleName - The role name.
 * @returns {Promise<Array<string>>} Array of permission keys.
 */
async function getRolePermissions(roleName) {
  const role = await findByName(roleName);
  if (!role) return [];
  return role.permissions || [];
}

/**
 * Check if a role has a specific permission.
 * @param {string} roleName - The role name.
 * @param {string} permission - The permission to check.
 * @returns {Promise<boolean>} True if the role has the permission.
 */
async function hasPermission(roleName, permission) {
  const permissions = await getRolePermissions(roleName);

  // Admin wildcard check
  if (permissions.includes('*')) return true;

  // Direct permission check
  if (permissions.includes(permission)) return true;

  // Wildcard resource check (e.g., 'user:*' matches 'user:read')
  const [resource, action] = permission.split(':');
  if (resource && permissions.includes(`${resource}:*`)) return true;

  return false;
}

/**
 * Get the default role for new users.
 * @returns {Promise<Object|null>} The default role.
 */
async function getDefaultRole() {
  const roles = await readRoles();
  return roles.find(r => r.isDefault) || roles.find(r => r.name === 'user') || null;
}

/**
 * Seed default roles if none exist.
 * @returns {Promise<void>}
 */
async function seedDefaultRoles() {
  const roles = await readRoles();
  if (roles.length === 0) {
    await writeRoles([...DEFAULT_ROLES]);
    logger.info('Default roles seeded successfully');
  }
}

/**
 * Grant a permission to a role.
 * @param {string} id - The role ID.
 * @param {string} permission - The permission to grant.
 * @returns {Promise<Object|null>} The updated role or null.
 */
async function grantPermission(id, permission) {
  const roles = await readRoles();
  const index = roles.findIndex(r => r.id === id);

  if (index === -1) return null;

  const currentPermissions = new Set(roles[index].permissions || []);
  currentPermissions.add(permission);
  roles[index].permissions = Array.from(currentPermissions);
  roles[index].updatedAt = new Date().toISOString();

  await writeRoles(roles);
  return roles[index];
}

/**
 * Revoke a permission from a role.
 * @param {string} id - The role ID.
 * @param {string} permission - The permission to revoke.
 * @returns {Promise<Object|null>} The updated role or null.
 */
async function revokePermission(id, permission) {
  const roles = await readRoles();
  const index = roles.findIndex(r => r.id === id);

  if (index === -1) return null;

  roles[index].permissions = (roles[index].permissions || [])
    .filter(p => p !== permission);
  roles[index].updatedAt = new Date().toISOString();

  await writeRoles(roles);
  return roles[index];
}

module.exports = {
  create,
  findById,
  findByName,
  findAll,
  update,
  remove,
  getRolePermissions,
  hasPermission,
  getDefaultRole,
  seedDefaultRoles,
  grantPermission,
  revokePermission,
  DEFAULT_ROLES,
};