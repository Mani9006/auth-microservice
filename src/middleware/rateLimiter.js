/**
 * Rate limiting middleware using express-rate-limit.
 * Provides different rate limits for authentication endpoints,
 * general API access, and sensitive operations.
 */

'use strict';

const rateLimit = require('express-rate-limit');
const config = require('../config');
const auditService = require('../services/auditService');
const { logger } = require('../utils/logger');

// In-memory store for rate limit tracking (can be replaced with Redis in production)
const authLimiterStore = new Map();

/**
 * Create a custom rate limiter with configurable options.
 * @param {Object} options - Rate limiter options.
 * @param {number} options.windowMs - Time window in milliseconds.
 * @param {number} options.max - Maximum requests per window.
 * @param {string} options.keyPrefix - Prefix for the key.
 * @param {string} options.message - Message returned when limit exceeded.
 * @returns {Function} Express middleware.
 */
function createLimiter(options) {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // Use authenticated user ID if available, otherwise use IP
      const identifier = req.user?.userId || req.ip;
      return `${options.keyPrefix}:${identifier}`;
    },
    handler: async (req, res, next, options) => {
      logger.warn(`Rate limit exceeded for ${req.ip} on ${req.path}`);
      await auditService.logRateLimitExceeded(req, req.path);

      res.status(429).json({
        success: false,
        error: 'Too many requests',
        message: options.message || 'Rate limit exceeded. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil(options.windowMs / 1000),
      });
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      if (req.path === '/health' || req.path === '/ready') return true;
      return false;
    },
    // Custom store implementation with memory management
    store: {
      incr: (key, cb) => {
        const now = Date.now();
        const windowStart = now - options.windowMs;

        if (!authLimiterStore.has(key)) {
          authLimiterStore.set(key, []);
        }

        const timestamps = authLimiterStore.get(key);
        // Clean old entries
        const validTimestamps = timestamps.filter(ts => ts > windowStart);
        validTimestamps.push(now);
        authLimiterStore.set(key, validTimestamps);

        const count = validTimestamps.length;
        const resetTime = validTimestamps[0] + options.windowMs;

        cb(null, count, { resetTime: Math.ceil(resetTime / 1000) });
      },
      decrement: (key) => {
        const timestamps = authLimiterStore.get(key);
        if (timestamps && timestamps.length > 0) {
          timestamps.pop();
          authLimiterStore.set(key, timestamps);
        }
      },
      resetKey: (key) => {
        authLimiterStore.delete(key);
      },
    },
  });
}

/**
 * Rate limiter for authentication endpoints (login, register).
 * Very strict to prevent brute force and enumeration attacks.
 */
const authLimiter = createLimiter({
  windowMs: config.rateLimit.authWindowMs,
  max: config.rateLimit.authMaxAttempts,
  keyPrefix: 'auth',
  message: 'Too many authentication attempts. Please try again after 15 minutes.',
});

/**
 * Rate limiter for password reset requests.
 * Prevents abuse of the password reset flow.
 */
const passwordResetLimiter = createLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 reset requests per hour
  keyPrefix: 'reset',
  message: 'Too many password reset requests. Please try again after 1 hour.',
});

/**
 * Rate limiter for token refresh.
 */
const refreshTokenLimiter = createLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 refresh requests per 15 minutes
  keyPrefix: 'refresh',
  message: 'Too many token refresh requests.',
});

/**
 * General API rate limiter for all other endpoints.
 */
const generalLimiter = createLimiter({
  windowMs: config.rateLimit.generalWindowMs,
  max: config.rateLimit.generalMaxRequests,
  keyPrefix: 'general',
  message: 'Too many requests. Please slow down.',
});

/**
 * Strict rate limiter for admin operations.
 */
const adminLimiter = createLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 admin requests per minute
  keyPrefix: 'admin',
  message: 'Too many admin operations. Please slow down.',
});

/**
 * Rate limiter for user registration.
 * Prevents mass account creation.
 */
const registerLimiter = createLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  keyPrefix: 'register',
  message: 'Too many registration attempts. Please try again after 1 hour.',
});

/**
 * Middleware to add rate limit info to response headers.
 */
function rateLimitInfo(req, res, next) {
  // This is handled automatically by express-rate-limit with standardHeaders: true
  next();
}

/**
 * Clean up old entries from the in-memory store periodically.
 * Prevents memory leaks in long-running processes.
 */
function cleanupStore() {
  const now = Date.now();
  let cleaned = 0;

  for (const [key, timestamps] of authLimiterStore.entries()) {
    // Find the window for this key based on the prefix
    const windowMs = config.rateLimit.authWindowMs;
    const cutoff = now - (windowMs * 2); // Keep double the window for safety

    const validTimestamps = timestamps.filter(ts => ts > cutoff);
    if (validTimestamps.length === 0) {
      authLimiterStore.delete(key);
      cleaned++;
    } else if (validTimestamps.length !== timestamps.length) {
      authLimiterStore.set(key, validTimestamps);
    }
  }

  if (cleaned > 0) {
    logger.debug(`Cleaned up ${cleaned} expired rate limit entries`);
  }
}

// Run cleanup every 10 minutes
setInterval(cleanupStore, 10 * 60 * 1000);

module.exports = {
  createLimiter,
  authLimiter,
  passwordResetLimiter,
  refreshTokenLimiter,
  generalLimiter,
  adminLimiter,
  registerLimiter,
  rateLimitInfo,
  cleanupStore,
  authLimiterStore,
};