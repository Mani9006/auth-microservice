/**
 * Authentication middleware for verifying JWT access tokens.
 * Extracts the Bearer token from the Authorization header,
 * verifies it, and attaches user info to the request object.
 */

'use strict';

const { verifyAccessTokenSafe } = require('../services/tokenService');
const User = require('../models/User');
const { logger } = require('../utils/logger');

/**
 * Extract Bearer token from Authorization header.
 * @param {Object} headers - Request headers.
 * @returns {string|null} The token string or null.
 */
function extractBearerToken(headers) {
  const authHeader = headers.authorization;
  if (!authHeader) return null;

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return null;
  }

  return parts[1];
}

/**
 * Authentication middleware.
 * Verifies the JWT access token and attaches user info to req.user.
 * @param {Object} options - Optional configuration.
 * @param {boolean} [options.optional=false] - If true, don't fail on missing token.
 * @returns {Function} Express middleware function.
 */
function authenticate(options = {}) {
  const { optional = false } = options;

  return async (req, res, next) => {
    try {
      const token = extractBearerToken(req.headers);

      if (!token) {
        if (optional) {
          req.user = null;
          return next();
        }

        logger.warn(`Authentication failed: No token provided from ${req.ip}`);
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          message: 'No authentication token provided',
          code: 'NO_TOKEN',
        });
      }

      // Verify the token
      let decoded;
      try {
        decoded = await verifyAccessTokenSafe(token);
      } catch (error) {
        logger.warn(`Token verification failed: ${error.message}`);

        if (error.name === 'TokenExpiredError') {
          return res.status(401).json({
            success: false,
            error: 'Token expired',
            message: 'Your session has expired. Please refresh your token or log in again.',
            code: 'TOKEN_EXPIRED',
            expiredAt: error.expiredAt,
          });
        }

        if (error.name === 'JsonWebTokenError') {
          return res.status(401).json({
            success: false,
            error: 'Invalid token',
            message: 'The provided authentication token is invalid.',
            code: 'INVALID_TOKEN',
          });
        }

        return res.status(401).json({
          success: false,
          error: 'Authentication failed',
          message: error.message,
          code: 'AUTH_FAILED',
        });
      }

      // Fetch the user from database
      const user = await User.findById(decoded.sub);

      if (!user) {
        logger.warn(`Authentication failed: User not found for token subject ${decoded.sub}`);
        return res.status(401).json({
          success: false,
          error: 'User not found',
          message: 'The user associated with this token no longer exists.',
          code: 'USER_NOT_FOUND',
        });
      }

      if (!user.isActive) {
        logger.warn(`Authentication failed: User ${user.id} account is deactivated`);
        return res.status(403).json({
          success: false,
          error: 'Account deactivated',
          message: 'Your account has been deactivated. Please contact an administrator.',
          code: 'ACCOUNT_DEACTIVATED',
        });
      }

      // Attach user info to request
      req.user = {
        userId: decoded.sub,
        email: decoded.email,
        role: decoded.role,
        jti: decoded.jti,
      };

      // Attach raw token for potential blacklisting on logout
      req.token = token;
      req.tokenJti = decoded.jti;

      logger.debug(`Authenticated user ${decoded.sub} (${decoded.email})`);
      next();
    } catch (error) {
      logger.error(`Authentication middleware error: ${error.message}`);
      next(error);
    }
  };
}

/**
 * Optional authentication middleware.
 * Attaches user info if token is valid, but doesn't require it.
 */
function optionalAuth(req, res, next) {
  return authenticate({ optional: true })(req, res, next);
}

module.exports = {
  authenticate,
  optionalAuth,
  extractBearerToken,
};