/**
 * Token Service manages JWT token lifecycle including generation,
 * blacklisting, refresh token rotation, and cleanup.
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const config = require('../config');
const { logger } = require('../utils/logger');
const {
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  decodeToken,
} = require('../utils/jwt');

const BLACKLIST_FILE = path.join(config.storage.dataDir, config.storage.tokenBlacklistFile);

// In-memory blacklist cache
let blacklistCache = new Map();
let lastCacheLoad = 0;
const CACHE_TTL_MS = 60000; // 1 minute

/**
 * Load the token blacklist from storage into memory.
 */
async function loadBlacklist() {
  const now = Date.now();
  if ((now - lastCacheLoad) < CACHE_TTL_MS && blacklistCache.size > 0) {
    return;
  }

  try {
    const data = await fs.readFile(BLACKLIST_FILE, 'utf8');
    const entries = JSON.parse(data);
    blacklistCache = new Map(entries.map(e => [e.jti, e]));
    lastCacheLoad = now;
  } catch (error) {
    if (error.code === 'ENOENT') {
      blacklistCache = new Map();
      lastCacheLoad = now;
    } else {
      logger.error(`Error loading token blacklist: ${error.message}`);
    }
  }
}

/**
 * Persist the in-memory blacklist to storage.
 */
async function persistBlacklist() {
  try {
    const entries = Array.from(blacklistCache.values());
    await fs.writeFile(BLACKLIST_FILE, JSON.stringify(entries, null, 2), 'utf8');
  } catch (error) {
    logger.error(`Error persisting token blacklist: ${error.message}`);
  }
}

/**
 * Issue a new token pair for a user.
 * @param {Object} user - The user object.
 * @returns {Promise<Object>} Token pair with metadata.
 */
async function issueTokenPair(user) {
  const tokenPayload = {
    userId: user.id,
    email: user.email,
    role: user.role,
  };

  const tokenPair = generateTokenPair(tokenPayload);

  // Store refresh token JTI for rotation tracking
  const User = require('../models/User');
  await User.storeRefreshToken(user.id, tokenPair.jti);

  // Log token issuance
  logger.debug(`Issued token pair for user ${user.id}, JTI: ${tokenPair.jti}`);

  return tokenPair;
}

/**
 * Verify an access token and ensure it is not blacklisted.
 * @param {string} token - The access token.
 * @returns {Promise<Object>} Decoded token payload.
 * @throws {Error} If token is invalid or blacklisted.
 */
async function verifyAccessTokenSafe(token) {
  const decoded = verifyAccessToken(token);

  // Check blacklist
  await loadBlacklist();
  if (decoded.jti && blacklistCache.has(decoded.jti)) {
    throw new Error('Token has been revoked');
  }

  return decoded;
}

/**
 * Rotate refresh tokens - issue a new pair and invalidate the old one.
 * Implements token rotation security best practice.
 * @param {string} refreshToken - The current refresh token.
 * @returns {Promise<Object>} New token pair.
 * @throws {Error} If refresh token is invalid or reused.
 */
async function rotateRefreshToken(refreshToken) {
  let decoded;

  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch (error) {
    logger.warn(`Refresh token verification failed: ${error.message}`);
    throw new Error('Invalid or expired refresh token');
  }

  const { sub: userId, jti } = decoded;

  // Verify the refresh token belongs to the user
  const User = require('../models/User');
  const hasToken = await User.hasRefreshToken(userId, jti);

  if (!hasToken) {
    // Token reuse detected! This is a security event.
    logger.warn(`Token reuse detected for user ${userId}, JTI: ${jti}`);

    // Revoke all refresh tokens for this user (force re-authentication)
    await User.clearAllRefreshTokens(userId);
    await blacklistAllUserTokens(userId);

    throw new Error('Token reuse detected. Please authenticate again.');
  }

  // Remove the old refresh token
  await User.removeRefreshToken(userId, jti);

  // Blacklist the used refresh token JTI
  await blacklistToken(jti, userId, 'refresh-rotation');

  // Fetch user for new token generation
  const user = await User.findById(userId);
  if (!user) {
    throw new Error('User not found');
  }

  if (!user.isActive) {
    throw new Error('Account is deactivated');
  }

  // Issue new token pair
  const tokenPayload = {
    userId: user.id,
    email: user.email,
    role: user.role,
  };

  const newTokenPair = generateTokenPair(tokenPayload);
  await User.storeRefreshToken(userId, newTokenPair.jti);

  logger.debug(`Rotated tokens for user ${userId}, new JTI: ${newTokenPair.jti}`);

  return newTokenPair;
}

/**
 * Blacklist a token by its JTI.
 * @param {string} jti - The JWT ID to blacklist.
 * @param {string} userId - The associated user ID.
 * @param {string} [reason='logout'] - Reason for blacklisting.
 */
async function blacklistToken(jti, userId, reason = 'logout') {
  await loadBlacklist();

  blacklistCache.set(jti, {
    jti,
    userId,
    reason,
    blacklistedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + config.cleanup.tokenBlacklistMaxAgeDays * 86400000).toISOString(),
  });

  await persistBlacklist();
  logger.debug(`Blacklisted token JTI: ${jti}, reason: ${reason}`);
}

/**
 * Blacklist all tokens for a user (e.g., on password change or security breach).
 * @param {string} userId - The user ID.
 */
async function blacklistAllUserTokens(userId) {
  const User = require('../models/User');
  const user = await User.findById(userId);

  if (!user || !user.refreshTokens) return;

  for (const tokenEntry of user.refreshTokens) {
    await blacklistToken(tokenEntry.jti, userId, 'security-breach');
  }

  // Clear all stored refresh tokens
  await User.clearAllRefreshTokens(userId);

  logger.info(`All tokens blacklisted for user ${userId}`);
}

/**
 * Check if a token is blacklisted.
 * @param {string} jti - The JWT ID.
 * @returns {Promise<boolean>} True if blacklisted.
 */
async function isBlacklisted(jti) {
  await loadBlacklist();
  return blacklistCache.has(jti);
}

/**
 * Revoke tokens and log out a user from all devices.
 * @param {string} userId - The user ID.
 */
async function revokeAllUserTokens(userId) {
  await blacklistAllUserTokens(userId);
}

/**
 * Clean up expired blacklist entries.
 * @returns {Promise<number>} Number of entries removed.
 */
async function cleanupBlacklist() {
  await loadBlacklist();

  const now = new Date().toISOString();
  let removed = 0;

  for (const [jti, entry] of blacklistCache) {
    if (entry.expiresAt && entry.expiresAt < now) {
      blacklistCache.delete(jti);
      removed++;
    }
  }

  if (removed > 0) {
    await persistBlacklist();
    logger.info(`Cleaned up ${removed} expired blacklist entries`);
  }

  return removed;
}

/**
 * Get blacklist statistics.
 * @returns {Promise<Object>} Statistics about the blacklist.
 */
async function getBlacklistStats() {
  await loadBlacklist();

  const entries = Array.from(blacklistCache.values());
  const byReason = {};

  for (const entry of entries) {
    byReason[entry.reason] = (byReason[entry.reason] || 0) + 1;
  }

  return {
    totalEntries: entries.length,
    byReason,
  };
}

/**
 * Decode a token without verifying (for inspection).
 * @param {string} token - The JWT token.
 * @returns {Object|null} Decoded payload or null.
 */
function inspectToken(token) {
  return decodeToken(token);
}

module.exports = {
  issueTokenPair,
  verifyAccessTokenSafe,
  rotateRefreshToken,
  blacklistToken,
  blacklistAllUserTokens,
  isBlacklisted,
  revokeAllUserTokens,
  cleanupBlacklist,
  getBlacklistStats,
  inspectToken,
};