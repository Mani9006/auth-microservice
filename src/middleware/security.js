/**
 * Security middleware for HTTP security headers and request hardening.
 * Uses Helmet for standard headers and custom middleware for additional security.
 */

'use strict';

const helmet = require('helmet');
const { logger } = require('../utils/logger');

/**
 * Configure Helmet with secure defaults.
 * Customized for API use (not serving HTML content).
 */
const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Disable for API compatibility
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'no-referrer' },
  xssFilter: true,
});

/**
 * Custom middleware to remove sensitive headers.
 */
function removeSensitiveHeaders(req, res, next) {
  // Remove headers that could leak server information
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  next();
}

/**
 * Add security-related response headers beyond Helmet.
 */
function addSecurityHeaders(req, res, next) {
  // Prevent MIME type sniffing (redundant with Helmet but explicit)
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Enable browser XSS filtering (legacy but still useful)
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Cache control for sensitive API responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Permissions policy for browser features
  res.setHeader('Permissions-Policy',
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
  );

  next();
}

/**
 * Request sanitization middleware.
 * Removes potential injection patterns from request inputs.
 */
function sanitizeRequest(req, res, next) {
  // Sanitize query parameters
  if (req.query) {
    for (const key of Object.keys(req.query)) {
      if (typeof req.query[key] === 'string') {
        // Remove null bytes and common injection patterns
        req.query[key] = req.query[key]
          .replace(/\0/g, '')
          .replace(/[<>]/g, '');
      }
    }
  }

  // Sanitize URL parameters
  if (req.params) {
    for (const key of Object.keys(req.params)) {
      if (typeof req.params[key] === 'string') {
        req.params[key] = req.params[key]
          .replace(/\0/g, '')
          .replace(/[<>]/g, '');
      }
    }
  }

  // Log potential security patterns in requests
  const suspiciousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /(javascript|data):/gi,
    /\.\./g,
    /\/etc\/passwd/gi,
    /union\s+select/gi,
  ];

  const requestString = JSON.stringify({ query: req.query, params: req.params, body: req.body });
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(requestString)) {
      logger.warn(`Suspicious request pattern detected from ${req.ip}: ${req.method} ${req.path}`);
      break;
    }
  }

  next();
}

/**
 * Request timeout middleware.
 * Aborts requests that take too long to process.
 * @param {number} timeoutMs - Timeout in milliseconds (default: 30000).
 * @returns {Function} Express middleware.
 */
function requestTimeout(timeoutMs = 30000) {
  return (req, res, next) => {
    // Set response timeout
    res.setTimeout(timeoutMs, () => {
      logger.warn(`Request timeout: ${req.method} ${req.path} from ${req.ip}`);
      res.status(504).json({
        success: false,
        error: 'Request timeout',
        message: 'The server took too long to process your request',
        code: 'TIMEOUT',
      });
    });

    // Set request timeout
    req.setTimeout(timeoutMs + 5000, () => {
      logger.error(`Request socket timeout: ${req.method} ${req.path}`);
    });

    next();
  };
}

/**
 * Error handling middleware for security-related errors.
 */
function securityErrorHandler(err, req, res, next) {
  // Handle specific security errors
  if (err.name === 'CORSError') {
    logger.warn(`CORS error from origin: ${req.headers.origin}`);
    return res.status(403).json({
      success: false,
      error: 'CORS policy violation',
      message: 'This origin is not allowed',
      code: 'CORS_ERROR',
    });
  }

  if (err.name === 'CSRFError') {
    logger.warn(`CSRF error for ${req.ip}`);
    return res.status(403).json({
      success: false,
      error: 'CSRF token missing or invalid',
      message: 'Invalid security token',
      code: 'CSRF_ERROR',
    });
  }

  next(err);
}

/**
 * Composite security middleware that applies all security measures.
 * Apply this early in the middleware stack.
 */
const securityMiddleware = [
  helmetConfig,
  removeSensitiveHeaders,
  addSecurityHeaders,
  sanitizeRequest,
  requestTimeout(),
];

module.exports = {
  helmetConfig,
  removeSensitiveHeaders,
  addSecurityHeaders,
  sanitizeRequest,
  requestTimeout,
  securityErrorHandler,
  securityMiddleware,
};