/**
 * Permission model for fine-grained access control.
 * Defines available permissions in the system using JSON file storage.
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const { logger } = require('../utils/logger');

const PERMISSIONS_FILE = path.join(config.storage.dataDir, config.storage.permissionsFile);

// In-memory cache
let permissionCache = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 30000;

/**
 * Default system permissions organized by resource.
 */
const DEFAULT_PERMISSIONS = [
  // User resource permissions
  { id: 'perm-user-create', key: 'user:create', resource: 'user', action: 'create', description: 'Create new users' },
  { id: 'perm-user-read', key: 'user:read', resource: 'user', action: 'read', description: 'Read user profiles' },
  { id: 'perm-user-update', key: 'user:update', resource: 'user', action: 'update', description: 'Update user profiles' },
  { id: 'perm-user-delete', key: 'user:delete', resource: 'user', action: 'delete', description: 'Delete any user' },
  { id: 'perm-user-delete-own', key: 'user:delete-own', resource: 'user', action: 'delete-own', description: 'Delete own account' },
  { id: 'perm-user-list', key: 'user:list', resource: 'user', action: 'list', description: 'List all users' },
  { id: 'perm-user-change-password', key: 'user:change-password', resource: 'user', action: 'change-password', description: 'Change own password' },
  { id: 'perm-user-change-role', key: 'user:change-role', resource: 'user', action: 'change-role', description: 'Change user roles' },

  // Role resource permissions
  { id: 'perm-role-create', key: 'role:create', resource: 'role', action: 'create', description: 'Create new roles' },
  { id: 'perm-role-read', key: 'role:read', resource: 'role', action: 'read', description: 'Read role definitions' },
  { id: 'perm-role-update', key: 'role:update', resource: 'role', action: 'update', description: 'Update role definitions' },
  { id: 'perm-role-delete', key: 'role:delete', resource: 'role', action: 'delete', description: 'Delete roles' },
  { id: 'perm-role-list', key: 'role:list', resource: 'role', action: 'list', description: 'List all roles' },
  { id: 'perm-role-assign', key: 'role:assign', resource: 'role', action: 'assign', description: 'Assign roles to users' },

  // Permission resource permissions
  { id: 'perm-perm-create', key: 'permission:create', resource: 'permission', action: 'create', description: 'Create new permissions' },
  { id: 'perm-perm-read', key: 'permission:read', resource: 'permission', action: 'read', description: 'Read permissions' },
  { id: 'perm-perm-update', key: 'permission:update', resource: 'permission', action: 'update', description: 'Update permissions' },
  { id: 'perm-perm-delete', key: 'permission:delete', resource: 'permission', action: 'delete', description: 'Delete permissions' },
  { id: 'perm-perm-list', key: 'permission:list', resource: 'permission', action: 'list', description: 'List all permissions' },

  // Audit log permissions
  { id: 'perm-audit-read', key: 'audit:read', resource: 'audit', action: 'read', description: 'Read audit log entries' },
  { id: 'perm-audit-list', key: 'audit:list', resource: 'audit', action: 'list', description: 'List all audit log entries' },
  { id: 'perm-audit-export', key: 'audit:export', resource: 'audit', action: 'export', description: 'Export audit logs' },

  // System/admin permissions
  { id: 'perm-system-config', key: 'system:config', resource: 'system', action: 'config', description: 'Configure system settings' },
  { id: 'perm-system-health', key: 'system:health', resource: 'system', action: 'health', description: 'View system health' },
  { id: 'perm-system-metrics', key: 'system:metrics', resource: 'system', action: 'metrics', description: 'View system metrics' },
];

/**
 * Read permissions from the JSON file.
 * @returns {Promise<Array>} Array of permission objects.
 */
async function readPermissions() {
  const now = Date.now();
  if (permissionCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return [...permissionCache];
  }

  try {
    const data = await fs.readFile(PERMISSIONS_FILE, 'utf8');
    const permissions = JSON.parse(data);
    permissionCache = permissions;
    cacheTimestamp = now;
    return [...permissions];
  } catch (error) {
    if (error.code === 'ENOENT') {
      permissionCache = [];
      cacheTimestamp = now;
      return [];
    }
    logger.error(`Error reading permissions file: ${error.message}`);
    throw error;
  }
}

/**
 * Write permissions to the JSON file.
 * @param {Array} permissions - Array of permission objects.
 */
async function writePermissions(permissions) {
  try {
    await fs.writeFile(PERMISSIONS_FILE, JSON.stringify(permissions, null, 2), 'utf8');
    permissionCache = [...permissions];
    cacheTimestamp = Date.now();
  } catch (error) {
    logger.error(`Error writing permissions file: ${error.message}`);
    throw error;
  }
}

/**
 * Create a new permission.
 * @param {Object} permData - The permission data.
 * @param {string} permData.key - Permission key in format "resource:action".
 * @param {string} permData.description - Human-readable description.
 * @returns {Promise<Object>} The created permission.
 */
async function create(permData) {
  const permissions = await readPermissions();

  // Validate key format
  if (!/^[a-z-]+:[a-z-]+$/.test(permData.key)) {
    const error = new Error('Permission key must be in format "resource:action" using lowercase letters and hyphens only');
    error.code = 'INVALID_PERMISSION_KEY';
    throw error;
  }

  // Check for duplicate key
  if (permissions.some(p => p.key === permData.key)) {
    const error = new Error('Permission key already exists');
    error.code = 'DUPLICATE_PERMISSION';
    throw error;
  }

  const [resource, action] = permData.key.split(':');

  const newPermission = {
    id: uuidv4(),
    key: permData.key,
    resource,
    action,
    description: permData.description || '',
    isSystem: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  permissions.push(newPermission);
  await writePermissions(permissions);
  return newPermission;
}

/**
 * Find a permission by ID.
 * @param {string} id - The permission ID.
 * @returns {Promise<Object|null>} The permission or null.
 */
async function findById(id) {
  const permissions = await readPermissions();
  return permissions.find(p => p.id === id) || null;
}

/**
 * Find a permission by key.
 * @param {string} key - The permission key (e.g., "user:read").
 * @returns {Promise<Object|null>} The permission or null.
 */
async function findByKey(key) {
  const permissions = await readPermissions();
  return permissions.find(p => p.key === key) || null;
}

/**
 * Get all permissions.
 * @returns {Promise<Array>} Array of all permissions.
 */
async function findAll() {
  return readPermissions();
}

/**
 * Get permissions grouped by resource.
 * @returns {Promise<Object>} Object with resource names as keys.
 */
async function getGroupedByResource() {
  const permissions = await readPermissions();
  const grouped = {};

  for (const perm of permissions) {
    if (!grouped[perm.resource]) {
      grouped[perm.resource] = [];
    }
    grouped[perm.resource].push(perm);
  }

  return grouped;
}

/**
 * Update a permission (description only for system permissions).
 * @param {string} id - The permission ID.
 * @param {Object} updates - Fields to update.
 * @returns {Promise<Object|null>} The updated permission or null.
 */
async function update(id, updates) {
  const permissions = await readPermissions();
  const index = permissions.findIndex(p => p.id === id);

  if (index === -1) return null;

  // Only allow updating description for system permissions
  if (permissions[index].isSystem) {
    if (updates.description) {
      permissions[index].description = updates.description;
    }
  } else {
    const allowed = ['key', 'description'];
    for (const key of Object.keys(updates)) {
      if (allowed.includes(key)) {
        if (key === 'key') {
          // Re-validate key format
          if (!/^[a-z-]+:[a-z-]+$/.test(updates.key)) {
            const error = new Error('Permission key must be in format "resource:action"');
            error.code = 'INVALID_PERMISSION_KEY';
            throw error;
          }
          const [resource, action] = updates.key.split(':');
          permissions[index].key = updates.key;
          permissions[index].resource = resource;
          permissions[index].action = action;
        } else {
          permissions[index][key] = updates[key];
        }
      }
    }
  }

  permissions[index].updatedAt = new Date().toISOString();
  await writePermissions(permissions);
  return permissions[index];
}

/**
 * Delete a permission (non-system only).
 * @param {string} id - The permission ID.
 * @returns {Promise<boolean>} True if deleted.
 */
async function remove(id) {
  const permissions = await readPermissions();
  const perm = permissions.find(p => p.id === id);

  if (!perm) return false;
  if (perm.isSystem) {
    const error = new Error('Cannot delete system permissions');
    error.code = 'SYSTEM_PERMISSION_PROTECTED';
    throw error;
  }

  const filtered = permissions.filter(p => p.id !== id);
  await writePermissions(filtered);
  return true;
}

/**
 * Check if a permission exists.
 * @param {string} key - The permission key.
 * @returns {Promise<boolean>} True if the permission exists.
 */
async function exists(key) {
  const perm = await findByKey(key);
  return perm !== null;
}

/**
 * Get all unique resources.
 * @returns {Promise<Array>} Array of resource names.
 */
async function getResources() {
  const permissions = await readPermissions();
  const resources = new Set(permissions.map(p => p.resource));
  return Array.from(resources);
}

/**
 * Seed default permissions if none exist.
 * @returns {Promise<void>}
 */
async function seedDefaultPermissions() {
  const permissions = await readPermissions();
  if (permissions.length === 0) {
    await writePermissions([...DEFAULT_PERMISSIONS]);
    logger.info('Default permissions seeded successfully');
  }
}

module.exports = {
  create,
  findById,
  findByKey,
  findAll,
  getGroupedByResource,
  update,
  remove,
  exists,
  getResources,
  seedDefaultPermissions,
  DEFAULT_PERMISSIONS,
};