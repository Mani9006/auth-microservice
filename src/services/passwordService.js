/**
 * Password Service handles password validation, strength checking,
 * reset token generation, and password policy enforcement.
 */

'use strict';

const config = require('../config');
const { logger } = require('../utils/logger');
const { hashPassword, comparePassword, generateResetToken, hashToken } = require('../utils/hash');

/**
 * Validate password strength against configured policy.
 * @param {string} password - The password to validate.
 * @returns {Object} Validation result with isValid flag and messages.
 */
function validatePasswordStrength(password) {
  const errors = [];
  const policy = config.passwordPolicy;

  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
    return { isValid: false, errors, strength: 'none' };
  }

  // Check minimum length
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }

  // Check maximum length
  if (password.length > policy.maxLength) {
    errors.push(`Password must not exceed ${policy.maxLength} characters`);
  }

  // Check uppercase
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  // Check lowercase
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  // Check digit
  if (policy.requireDigit && !/\d/.test(password)) {
    errors.push('Password must contain at least one digit');
  }

  // Check special character
  if (policy.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character (!@#$%^&* etc.)');
  }

  // Check for common patterns
  if (/^(.)\1+$/.test(password)) {
    errors.push('Password cannot consist of repeated characters');
  }

  // Check for common sequences
  const commonSequences = ['123456', 'abcdef', 'qwerty', 'password', 'letmein', 'welcome'];
  const lowerPassword = password.toLowerCase();
  for (const seq of commonSequences) {
    if (lowerPassword.includes(seq)) {
      errors.push('Password contains a common sequence or word');
      break;
    }
  }

  const isValid = errors.length === 0;
  const strength = calculateStrength(password);

  return {
    isValid,
    errors,
    strength,
    score: strength.score,
  };
}

/**
 * Calculate password strength score.
 * @param {string} password - The password to assess.
 * @returns {Object} Strength object with score and label.
 */
function calculateStrength(password) {
  let score = 0;

  if (!password) return { score: 0, label: 'none' };

  // Length scoring
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 2;
  if (password.length >= 16) score += 1;

  // Character variety scoring
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;

  // Bonus for mixed variety
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);
  if (hasLower && hasUpper && hasDigit && hasSpecial) score += 1;

  // Determine label
  let label;
  if (score <= 2) label = 'weak';
  else if (score <= 4) label = 'fair';
  else if (score <= 6) label = 'good';
  else label = 'strong';

  return { score: Math.min(score, 8), label };
}

/**
 * Hash a password for storage.
 * @param {string} password - The plain text password.
 * @returns {Promise<string>} The hashed password.
 */
async function hashUserPassword(password) {
  return hashPassword(password);
}

/**
 * Verify a password against a stored hash.
 * @param {string} password - The plain text password.
 * @param {string} hashedPassword - The stored hash.
 * @returns {Promise<boolean>} True if passwords match.
 */
async function verifyPassword(password, hashedPassword) {
  return comparePassword(password, hashedPassword);
}

/**
 * Generate a password reset token and its hash.
 * @returns {Object} Object with plain token and hashed token.
 */
function generatePasswordResetToken() {
  const plainToken = generateResetToken();
  const hashedToken = hashToken(plainToken);

  return {
    plainToken,
    hashedToken,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
  };
}

/**
 * Verify a password reset token.
 * @param {string} plainToken - The plain token from the user.
 * @param {string} hashedToken - The stored hashed token.
 * @param {string} expiresAt - ISO string of token expiry time.
 * @returns {boolean} True if token is valid and not expired.
 */
function verifyResetToken(plainToken, hashedToken, expiresAt) {
  const crypto = require('crypto');
  const computedHash = crypto.createHash('sha256').update(plainToken).digest('hex');

  const hashMatch = crypto.timingSafeEqual(
    Buffer.from(computedHash, 'hex'),
    Buffer.from(hashedToken, 'hex')
  );

  if (!hashMatch) return false;

  // Check expiry
  return new Date(expiresAt) > new Date();
}

/**
 * Change a user's password with validation.
 * @param {Object} user - The user object.
 * @param {string} currentPassword - Current password (for verification).
 * @param {string} newPassword - New password.
 * @returns {Promise<Object>} Result with success flag and messages.
 */
async function changePassword(user, currentPassword, newPassword) {
  // Validate new password strength
  const strengthCheck = validatePasswordStrength(newPassword);
  if (!strengthCheck.isValid) {
    return {
      success: false,
      message: 'New password does not meet requirements',
      errors: strengthCheck.errors,
    };
  }

  // Verify current password
  const passwordMatch = await verifyPassword(currentPassword, user.passwordHash);
  if (!passwordMatch) {
    return {
      success: false,
      message: 'Current password is incorrect',
    };
  }

  // Check password history
  const User = require('../models/User');
  const isReused = await User.isPasswordReused(user.id, newPassword);
  if (isReused) {
    return {
      success: false,
      message: 'Cannot reuse a previous password',
    };
  }

  // Hash and update password
  const newHash = await hashUserPassword(newPassword);
  await User.updatePassword(user.id, newHash);

  logger.info(`Password changed for user ${user.id}`);

  return {
    success: true,
    message: 'Password changed successfully',
  };
}

/**
 * Reset a password using a reset token.
 * @param {Object} user - The user object.
 * @param {string} newPassword - The new password.
 * @returns {Promise<Object>} Result with success flag.
 */
async function resetPassword(user, newPassword) {
  // Validate new password strength
  const strengthCheck = validatePasswordStrength(newPassword);
  if (!strengthCheck.isValid) {
    return {
      success: false,
      message: 'New password does not meet requirements',
      errors: strengthCheck.errors,
    };
  }

  const User = require('../models/User');

  // Check password history
  const isReused = await User.isPasswordReused(user.id, newPassword);
  if (isReused) {
    return {
      success: false,
      message: 'Cannot reuse a previous password',
    };
  }

  // Hash and update password
  const newHash = await hashUserPassword(newPassword);
  await User.updatePassword(user.id, newHash);

  // Clear reset token
  await User.clearPasswordResetToken(user.id);

  // Revoke all existing tokens (security: force re-login after password reset)
  const tokenService = require('./tokenService');
  await tokenService.revokeAllUserTokens(user.id);

  logger.info(`Password reset completed for user ${user.id}`);

  return {
    success: true,
    message: 'Password reset successfully. Please log in with your new password.',
  };
}

/**
 * Get password policy details for client display.
 * @returns {Object} Password policy configuration.
 */
function getPasswordPolicy() {
  return {
    minLength: config.passwordPolicy.minLength,
    maxLength: config.passwordPolicy.maxLength,
    requireUppercase: config.passwordPolicy.requireUppercase,
    requireLowercase: config.passwordPolicy.requireLowercase,
    requireDigit: config.passwordPolicy.requireDigit,
    requireSpecial: config.passwordPolicy.requireSpecial,
    requirements: getPasswordRequirements(),
  };
}

/**
 * Get human-readable password requirements.
 * @returns {Array<string>} List of requirement descriptions.
 */
function getPasswordRequirements() {
  const requirements = [];
  const policy = config.passwordPolicy;

  requirements.push(`Minimum ${policy.minLength} characters`);
  if (policy.requireUppercase) requirements.push('At least one uppercase letter');
  if (policy.requireLowercase) requirements.push('At least one lowercase letter');
  if (policy.requireDigit) requirements.push('At least one digit');
  if (policy.requireSpecial) requirements.push('At least one special character');

  return requirements;
}

module.exports = {
  validatePasswordStrength,
  calculateStrength,
  hashUserPassword,
  verifyPassword,
  generatePasswordResetToken,
  verifyResetToken,
  changePassword,
  resetPassword,
  getPasswordPolicy,
  getPasswordRequirements,
};