/**
 * JWT utility functions for token generation, verification, and decoding.
 * Wraps the jsonwebtoken library with application-specific configuration.
 */

'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');
const { logger } = require('./logger');

/**
 * Generate an access token for a user.
 * @param {Object} payload - The token payload containing user information.
 * @param {string} payload.userId - The user's unique ID.
 * @param {string} payload.email - The user's email.
 * @param {string} payload.role - The user's role name.
 * @param {string} [jti] - Optional JWT ID for token tracking.
 * @returns {string} The signed access token.
 */
function generateAccessToken(payload, jti = null) {
  const tokenPayload = {
    sub: payload.userId,
    email: payload.email,
    role: payload.role,
    type: 'access',
    ...(jti && { jti }),
  };

  return jwt.sign(tokenPayload, config.jwt.secret, {
    expiresIn: config.jwt.accessTokenExpiry,
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    ...(jti && { jwtid: jti }),
  });
}

/**
 * Generate a refresh token for a user.
 * @param {Object} payload - The token payload containing user information.
 * @param {string} payload.userId - The user's unique ID.
 * @param {string} jti - The JWT ID for the refresh token (required for rotation).
 * @returns {string} The signed refresh token.
 */
function generateRefreshToken(payload, jti) {
  const tokenPayload = {
    sub: payload.userId,
    type: 'refresh',
    jti,
  };

  return jwt.sign(tokenPayload, config.jwt.refreshSecret, {
    expiresIn: config.jwt.refreshTokenExpiry,
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    jwtid: jti,
  });
}

/**
 * Generate both access and refresh tokens (token pair).
 * @param {Object} payload - The token payload containing user information.
 * @param {string} payload.userId - The user's unique ID.
 * @param {string} payload.email - The user's email.
 * @param {string} payload.role - The user's role name.
 * @returns {Object} Object containing accessToken, refreshToken, and their metadata.
 */
function generateTokenPair(payload) {
  const jti = require('crypto').randomUUID();

  const accessToken = generateAccessToken(payload, jti);
  const refreshToken = generateRefreshToken(payload, jti);

  // Calculate expiry dates
  const now = Math.floor(Date.now() / 1000);
  const accessDecoded = jwt.decode(accessToken);
  const refreshDecoded = jwt.decode(refreshToken);

  return {
    accessToken,
    refreshToken,
    jti,
    accessTokenExpiresAt: accessDecoded.exp,
    refreshTokenExpiresAt: refreshDecoded.exp,
    tokenType: 'Bearer',
  };
}

/**
 * Verify an access token.
 * @param {string} token - The access token to verify.
 * @returns {Object} The decoded token payload.
 * @throws {Error} If the token is invalid, expired, or blacklisted.
 */
function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, config.jwt.secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      algorithms: ['HS256'],
      clockTolerance: 60, // 1 minute clock skew tolerance
    });

    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.warn(`Access token verification failed: ${error.message}`);
    throw error;
  }
}

/**
 * Verify a refresh token.
 * @param {string} token - The refresh token to verify.
 * @returns {Object} The decoded token payload.
 * @throws {Error} If the token is invalid or expired.
 */
function verifyRefreshToken(token) {
  try {
    const decoded = jwt.verify(token, config.jwt.refreshSecret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      algorithms: ['HS256'],
      clockTolerance: 60,
    });

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.warn(`Refresh token verification failed: ${error.message}`);
    throw error;
  }
}

/**
 * Decode a token without verification (for inspection purposes).
 * @param {string} token - The token to decode.
 * @returns {Object|null} The decoded payload or null if invalid.
 */
function decodeToken(token) {
  try {
    return jwt.decode(token, { complete: false });
  } catch {
    return null;
  }
}

/**
 * Check if a token is expired based on its 'exp' claim.
 * @param {Object} decodedToken - The decoded token payload.
 * @returns {boolean} True if the token is expired.
 */
function isTokenExpired(decodedToken) {
  if (!decodedToken || !decodedToken.exp) return true;
  const now = Math.floor(Date.now() / 1000);
  return decodedToken.exp < now;
}

/**
 * Calculate the remaining time until token expiry in seconds.
 * @param {Object} decodedToken - The decoded token payload.
 * @returns {number} Seconds until expiry (0 if already expired).
 */
function getTokenTimeToExpiry(decodedToken) {
  if (!decodedToken || !decodedToken.exp) return 0;
  const now = Math.floor(Date.now() / 1000);
  return Math.max(0, decodedToken.exp - now);
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  decodeToken,
  isTokenExpired,
  getTokenTimeToExpiry,
};