/**
 * Hashing utility functions using bcryptjs.
 * Provides secure password hashing and comparison with configurable salt rounds.
 */

'use strict';

const bcrypt = require('bcryptjs');
const config = require('../config');

/**
 * Hash a password using bcrypt with configurable salt rounds.
 * @param {string} password - The plain text password to hash.
 * @returns {Promise<string>} The hashed password.
 * @throws {Error} If password is not a non-empty string.
 */
async function hashPassword(password) {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }

  if (password.length > config.passwordPolicy.maxLength) {
    throw new Error(`Password exceeds maximum length of ${config.passwordPolicy.maxLength} characters`);
  }

  const salt = await bcrypt.genSalt(config.bcrypt.saltRounds);
  return bcrypt.hash(password, salt);
}

/**
 * Compare a plain text password with a hashed password.
 * @param {string} password - The plain text password.
 * @param {string} hashedPassword - The hashed password to compare against.
 * @returns {Promise<boolean>} True if the passwords match.
 * @throws {Error} If either argument is not a non-empty string.
 */
async function comparePassword(password, hashedPassword) {
  if (!password || typeof password !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  if (!hashedPassword || typeof hashedPassword !== 'string') {
    throw new Error('Hashed password must be a non-empty string');
  }

  return bcrypt.compare(password, hashedPassword);
}

/**
 * Generate a cryptographically secure random token string.
 * @param {number} length - The desired length of the token (default: 64).
 * @returns {string} A hex-encoded random token.
 */
function generateRandomToken(length = 64) {
  const crypto = require('crypto');
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a secure random password reset token.
 * @returns {string} A URL-safe random token for password reset.
 */
function generateResetToken() {
  const crypto = require('crypto');
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Hash a token for secure storage (used for reset tokens).
 * Uses SHA-256 to create a deterministic hash.
 * @param {string} token - The token to hash.
 * @returns {string} The SHA-256 hash of the token.
 */
function hashToken(token) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Verify if a provided token matches a stored hash.
 * @param {string} token - The token to verify.
 * @param {string} hash - The stored hash.
 * @returns {boolean} True if the token matches the hash.
 */
function verifyTokenHash(token, hash) {
  const computedHash = hashToken(token);
  return crypto.timingSafeEqual(Buffer.from(computedHash, 'hex'), Buffer.from(hash, 'hex'));
}

module.exports = {
  hashPassword,
  comparePassword,
  generateRandomToken,
  generateResetToken,
  hashToken,
  verifyTokenHash,
};