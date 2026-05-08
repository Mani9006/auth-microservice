/**
 * Configuration module for the authentication microservice.
 * Centralizes all environment-based configuration values.
 */

'use strict';

const path = require('path');
const os = require('os');

const config = {
  // Server configuration
  server: {
    port: parseInt(process.env.AUTH_PORT, 10) || 3001,
    host: process.env.AUTH_HOST || '0.0.0.0',
    env: process.env.NODE_ENV || 'development',
    apiVersion: process.env.API_VERSION || 'v1',
  },

  // JWT configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'auth-ms-dev-secret-change-in-production-256bits',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'auth-ms-dev-refresh-secret-change-in-production-256bits',
    accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
    issuer: process.env.JWT_ISSUER || 'auth-microservice',
    audience: process.env.JWT_AUDIENCE || 'auth-api',
  },

  // Bcrypt configuration
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12,
  },

  // Rate limiting configuration
  rateLimit: {
    authWindowMs: parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_MS, 10) || 15 * 60 * 1000, // 15 minutes
    authMaxAttempts: parseInt(process.env.RATE_LIMIT_AUTH_MAX, 10) || 5,
    generalWindowMs: parseInt(process.env.RATE_LIMIT_GENERAL_WINDOW_MS, 10) || 60 * 1000, // 1 minute
    generalMaxRequests: parseInt(process.env.RATE_LIMIT_GENERAL_MAX, 10) || 100,
  },

  // Account lockout configuration
  lockout: {
    maxFailedAttempts: parseInt(process.env.LOCKOUT_MAX_ATTEMPTS, 10) || 5,
    lockoutDurationMs: parseInt(process.env.LOCKOUT_DURATION_MS, 10) || 30 * 60 * 1000, // 30 minutes
    resetAfterMs: parseInt(process.env.LOCKOUT_RESET_MS, 10) || 24 * 60 * 60 * 1000, // 24 hours
  },

  // Token rotation configuration
  rotation: {
    maxRefreshTokens: parseInt(process.env.MAX_REFRESH_TOKENS, 10) || 5,
    reuseDetectionEnabled: process.env.REUSE_DETECTION_ENABLED !== 'false',
  },

  // Data storage paths
  storage: {
    dataDir: process.env.DATA_DIR || path.join(os.homedir(), '.auth-service'),
    usersFile: 'users.json',
    rolesFile: 'roles.json',
    permissionsFile: 'permissions.json',
    auditLogsFile: 'audit-logs.json',
    tokenBlacklistFile: 'token-blacklist.json',
  },

  // Logging configuration
  log: {
    level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
    file: process.env.LOG_FILE || path.join(os.homedir(), '.auth-service', 'auth-service.log'),
    maxFiles: parseInt(process.env.LOG_MAX_FILES, 10) || 14,
    maxSize: process.env.LOG_MAX_SIZE || '20m',
  },

  // CORS configuration
  cors: {
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : ['http://localhost:3000'],
    credentials: process.env.CORS_CREDENTIALS === 'true',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  },

  // Password policy
  passwordPolicy: {
    minLength: parseInt(process.env.PASSWORD_MIN_LENGTH, 10) || 8,
    requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
    requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
    requireDigit: process.env.PASSWORD_REQUIRE_DIGIT !== 'false',
    requireSpecial: process.env.PASSWORD_REQUIRE_SPECIAL !== 'false',
    maxLength: parseInt(process.env.PASSWORD_MAX_LENGTH, 10) || 128,
  },

  // Cleanup configuration
  cleanup: {
    blacklistCleanupIntervalMs: 60 * 60 * 1000, // 1 hour
    tokenBlacklistMaxAgeDays: 7,
    maxAuditLogEntries: parseInt(process.env.MAX_AUDIT_LOG_ENTRIES, 10) || 10000,
  },
};

/**
 * Validate critical configuration at startup.
 * @throws {Error} If critical configuration is missing in production.
 */
function validateConfig() {
  if (config.server.env === 'production') {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required in production');
    }
    if (!process.env.JWT_REFRESH_SECRET) {
      throw new Error('JWT_REFRESH_SECRET environment variable is required in production');
    }
    if (process.env.JWT_SECRET === config.jwt.secret) {
      throw new Error('Default JWT_SECRET cannot be used in production. Please set a custom secret.');
    }
    if (config.jwt.secret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters in production');
    }
  }

  // Validate bcrypt salt rounds
  if (config.bcrypt.saltRounds < 10) {
    throw new Error('BCRYPT_SALT_ROUNDS must be at least 10');
  }

  // Ensure data directory exists
  const fs = require('fs');
  if (!fs.existsSync(config.storage.dataDir)) {
    fs.mkdirSync(config.storage.dataDir, { recursive: true });
  }
}

module.exports = {
  ...config,
  validateConfig,
};