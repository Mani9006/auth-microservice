/**
 * User model for data persistence using JSON file storage.
 * Provides CRUD operations and user-specific business logic.
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const config = require('../config');
const { hashPassword } = require('../utils/hash');
const { logger } = require('../utils/logger');

const USERS_FILE = path.join(config.storage.dataDir, config.storage.usersFile);

// In-memory user cache
let userCache = null;
let cacheTimestamp = 0;
const CACHE_TTL_MS = 30000; // 30 seconds

/**
 * Read users from the JSON file.
 * @returns {Promise<Array>} Array of user objects.
 */
async function readUsers() {
  // Use cache if valid
  const now = Date.now();
  if (userCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return [...userCache];
  }

  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    const users = JSON.parse(data);
    userCache = users;
    cacheTimestamp = now;
    return [...users];
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist, return empty array
      userCache = [];
      cacheTimestamp = now;
      return [];
    }
    logger.error(`Error reading users file: ${error.message}`);
    throw error;
  }
}

/**
 * Write users to the JSON file.
 * @param {Array} users - Array of user objects to save.
 */
async function writeUsers(users) {
  try {
    const data = JSON.stringify(users, null, 2);
    await fs.writeFile(USERS_FILE, data, 'utf8');
    userCache = [...users];
    cacheTimestamp = Date.now();
  } catch (error) {
    logger.error(`Error writing users file: ${error.message}`);
    throw error;
  }
}

/**
 * Invalidate the user cache (call after any write operation).
 */
function invalidateCache() {
  userCache = null;
  cacheTimestamp = 0;
}

/**
 * Create a new user.
 * @param {Object} userData - The user data.
 * @param {string} userData.email - User email (unique).
 * @param {string} userData.password - Plain text password (will be hashed).
 * @param {string} [userData.firstName] - First name.
 * @param {string} [userData.lastName] - Last name.
 * @param {string} [userData.role] - Role name (defaults to 'user').
 * @returns {Promise<Object>} The created user (without password).
 */
async function create(userData) {
  const users = await readUsers();

  // Check for duplicate email
  if (users.some(u => u.email.toLowerCase() === userData.email.toLowerCase())) {
    const error = new Error('Email already registered');
    error.code = 'DUPLICATE_EMAIL';
    throw error;
  }

  const hashedPassword = await hashPassword(userData.password);
  const now = new Date().toISOString();

  const newUser = {
    id: uuidv4(),
    email: userData.email.toLowerCase().trim(),
    passwordHash: hashedPassword,
    firstName: userData.firstName || '',
    lastName: userData.lastName || '',
    role: userData.role || 'user',
    isActive: true,
    isEmailVerified: false,
    emailVerificationToken: null,
    failedLoginAttempts: 0,
    lockedUntil: null,
    lastLoginAt: null,
    passwordChangedAt: now,
    passwordResetToken: null,
    passwordResetExpires: null,
    previousPasswords: [], // Track for password history
    refreshTokens: [], // Active refresh token JTIs
    createdAt: now,
    updatedAt: now,
    metadata: {},
  };

  users.push(newUser);
  await writeUsers(users);

  // Return user without sensitive fields
  return sanitizeUser(newUser);
}

/**
 * Find a user by ID.
 * @param {string} id - The user ID.
 * @returns {Promise<Object|null>} The user object or null if not found.
 */
async function findById(id) {
  const users = await readUsers();
  return users.find(u => u.id === id) || null;
}

/**
 * Find a user by email address.
 * @param {string} email - The email to search for.
 * @returns {Promise<Object|null>} The user object or null if not found.
 */
async function findByEmail(email) {
  const users = await readUsers();
  return users.find(u => u.email.toLowerCase() === email.toLowerCase().trim()) || null;
}

/**
 * Find all users with optional filtering.
 * @param {Object} [filters] - Filter criteria.
 * @param {boolean} [filters.isActive] - Filter by active status.
 * @param {string} [filters.role] - Filter by role.
 * @returns {Promise<Array>} Array of sanitized user objects.
 */
async function findAll(filters = {}) {
  let users = await readUsers();

  if (filters.isActive !== undefined) {
    users = users.filter(u => u.isActive === filters.isActive);
  }
  if (filters.role) {
    users = users.filter(u => u.role === filters.role);
  }

  return users.map(sanitizeUser);
}

/**
 * Update a user by ID.
 * @param {string} id - The user ID.
 * @param {Object} updates - The fields to update.
 * @returns {Promise<Object|null>} The updated user or null if not found.
 */
async function update(id, updates) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return null;

  // Prevent updating sensitive fields directly
  const allowedUpdates = ['firstName', 'lastName', 'isActive', 'isEmailVerified', 'role', 'metadata'];
  const updateKeys = Object.keys(updates).filter(key => allowedUpdates.includes(key));

  for (const key of updateKeys) {
    users[index][key] = updates[key];
  }

  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);

  return sanitizeUser(users[index]);
}

/**
 * Update user password with history tracking.
 * @param {string} id - The user ID.
 * @param {string} newPasswordHash - The new hashed password.
 * @returns {Promise<boolean>} True if updated successfully.
 */
async function updatePassword(id, newPasswordHash) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  // Store previous password hash (keep last 5)
  const previousPasswords = users[index].previousPasswords || [];
  previousPasswords.push(users[index].passwordHash);
  if (previousPasswords.length > 5) {
    previousPasswords.shift();
  }

  users[index].passwordHash = newPasswordHash;
  users[index].passwordChangedAt = new Date().toISOString();
  users[index].previousPasswords = previousPasswords;
  users[index].passwordResetToken = null;
  users[index].passwordResetExpires = null;
  users[index].failedLoginAttempts = 0;
  users[index].lockedUntil = null;
  users[index].updatedAt = new Date().toISOString();

  await writeUsers(users);
  return true;
}

/**
 * Check if a password has been used before.
 * @param {string} id - The user ID.
 * @param {string} newPassword - The new plain text password.
 * @returns {Promise<boolean>} True if password was previously used.
 */
async function isPasswordReused(id, newPassword) {
  const { comparePassword } = require('../utils/hash');
  const user = await findById(id);
  if (!user || !user.previousPasswords) return false;

  for (const oldHash of user.previousPasswords) {
    if (await comparePassword(newPassword, oldHash)) return true;
  }
  return false;
}

/**
 * Delete a user by ID.
 * @param {string} id - The user ID.
 * @returns {Promise<boolean>} True if deleted successfully.
 */
async function remove(id) {
  const users = await readUsers();
  const filtered = users.filter(u => u.id !== id);

  if (filtered.length === users.length) return false;

  await writeUsers(filtered);
  return true;
}

/**
 * Record a failed login attempt and potentially lock the account.
 * @param {string} id - The user ID.
 * @returns {Promise<Object>} Updated lockout info.
 */
async function recordFailedAttempt(id) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return null;

  users[index].failedLoginAttempts = (users[index].failedLoginAttempts || 0) + 1;

  // Check if account should be locked
  if (users[index].failedLoginAttempts >= config.lockout.maxFailedAttempts) {
    users[index].lockedUntil = new Date(Date.now() + config.lockout.lockoutDurationMs).toISOString();
    logger.warn(`Account locked for user ${id} after ${users[index].failedLoginAttempts} failed attempts`);
  }

  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);

  return {
    failedAttempts: users[index].failedLoginAttempts,
    lockedUntil: users[index].lockedUntil,
  };
}

/**
 * Reset failed login attempts and unlock account.
 * @param {string} id - The user ID.
 * @returns {Promise<boolean>} True if reset successfully.
 */
async function resetFailedAttempts(id) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  users[index].failedLoginAttempts = 0;
  users[index].lockedUntil = null;
  users[index].lastLoginAt = new Date().toISOString();
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Check if a user's account is locked.
 * @param {Object} user - The user object.
 * @returns {boolean} True if the account is currently locked.
 */
function isAccountLocked(user) {
  if (!user.lockedUntil) return false;
  return new Date(user.lockedUntil) > new Date();
}

/**
 * Get remaining lockout time in seconds.
 * @param {Object} user - The user object.
 * @returns {number} Seconds until unlock (0 if not locked).
 */
function getLockoutTimeRemaining(user) {
  if (!user.lockedUntil) return 0;
  const remaining = new Date(user.lockedUntil).getTime() - Date.now();
  return Math.max(0, Math.ceil(remaining / 1000));
}

/**
 * Store a refresh token JTI for a user (token rotation tracking).
 * @param {string} id - The user ID.
 * @param {string} jti - The JWT ID.
 * @returns {Promise<boolean>} True if stored successfully.
 */
async function storeRefreshToken(id, jti) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  const refreshTokens = users[index].refreshTokens || [];
  refreshTokens.push({
    jti,
    createdAt: new Date().toISOString(),
  });

  // Limit number of stored refresh tokens
  if (refreshTokens.length > config.rotation.maxRefreshTokens) {
    refreshTokens.shift(); // Remove oldest
  }

  users[index].refreshTokens = refreshTokens;
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Remove a refresh token JTI from a user's stored tokens.
 * @param {string} id - The user ID.
 * @param {string} jti - The JWT ID to remove.
 * @returns {Promise<boolean>} True if removed successfully.
 */
async function removeRefreshToken(id, jti) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  users[index].refreshTokens = (users[index].refreshTokens || [])
    .filter(t => t.jti !== jti);
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Check if a refresh token JTI belongs to a user.
 * @param {string} id - The user ID.
 * @param {string} jti - The JWT ID.
 * @returns {Promise<boolean>} True if the token is valid for this user.
 */
async function hasRefreshToken(id, jti) {
  const user = await findById(id);
  if (!user || !user.refreshTokens) return false;
  return user.refreshTokens.some(t => t.jti === jti);
}

/**
 * Set password reset token for a user.
 * @param {string} id - The user ID.
 * @param {string} resetTokenHash - The hashed reset token.
 * @param {number} expiryMinutes - Token expiry in minutes.
 * @returns {Promise<boolean>} True if set successfully.
 */
async function setPasswordResetToken(id, resetTokenHash, expiryMinutes = 15) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  users[index].passwordResetToken = resetTokenHash;
  users[index].passwordResetExpires = new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString();
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Clear password reset token after use.
 * @param {string} id - The user ID.
 * @returns {Promise<boolean>} True if cleared successfully.
 */
async function clearPasswordResetToken(id) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  users[index].passwordResetToken = null;
  users[index].passwordResetExpires = null;
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Remove all refresh tokens for a user (logout from all devices).
 * @param {string} id - The user ID.
 * @returns {Promise<boolean>} True if cleared successfully.
 */
async function clearAllRefreshTokens(id) {
  const users = await readUsers();
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return false;

  users[index].refreshTokens = [];
  users[index].updatedAt = new Date().toISOString();
  await writeUsers(users);
  return true;
}

/**
 * Count total users.
 * @returns {Promise<number>} The total number of users.
 */
async function count() {
  const users = await readUsers();
  return users.length;
}

/**
 * Remove sensitive fields from user object before returning to client.
 * @param {Object} user - The raw user object.
 * @returns {Object} Sanitized user object.
 */
function sanitizeUser(user) {
  if (!user) return null;
  const {
    passwordHash,
    passwordResetToken,
    passwordResetExpires,
    previousPasswords,
    emailVerificationToken,
    refreshTokens,
    ...safeUser
  } = user;
  return safeUser;
}

/**
 * Seed default users for initial setup.
 * @returns {Promise<void>}
 */
async function seedDefaultUsers() {
  const count = await readUsers();
  if (count.length === 0) {
    const adminPassword = await hashPassword('Admin123!@#');
    const userPassword = await hashPassword('User123!@#');

    const adminUser = {
      id: uuidv4(),
      email: 'admin@auth.local',
      passwordHash: adminPassword,
      firstName: 'System',
      lastName: 'Administrator',
      role: 'admin',
      isActive: true,
      isEmailVerified: true,
      emailVerificationToken: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: null,
      passwordChangedAt: new Date().toISOString(),
      passwordResetToken: null,
      passwordResetExpires: null,
      previousPasswords: [],
      refreshTokens: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: { seeded: true },
    };

    const demoUser = {
      id: uuidv4(),
      email: 'user@auth.local',
      passwordHash: userPassword,
      firstName: 'Demo',
      lastName: 'User',
      role: 'user',
      isActive: true,
      isEmailVerified: true,
      emailVerificationToken: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: null,
      passwordChangedAt: new Date().toISOString(),
      passwordResetToken: null,
      passwordResetExpires: null,
      previousPasswords: [],
      refreshTokens: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: { seeded: true },
    };

    await writeUsers([adminUser, demoUser]);
    logger.info('Default users seeded successfully');
  }
}

module.exports = {
  create,
  findById,
  findByEmail,
  findAll,
  update,
  updatePassword,
  isPasswordReused,
  remove,
  recordFailedAttempt,
  resetFailedAttempts,
  isAccountLocked,
  getLockoutTimeRemaining,
  storeRefreshToken,
  removeRefreshToken,
  hasRefreshToken,
  setPasswordResetToken,
  clearPasswordResetToken,
  clearAllRefreshTokens,
  count,
  sanitizeUser,
  seedDefaultUsers,
};