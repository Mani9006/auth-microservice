/**
 * Authentication Microservice - Main Entry Point
 * A standalone Node.js service providing authentication, authorization,
 * and user management with JWT tokens, RBAC, and comprehensive security.
 */

'use strict';

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const config = require('./config');
const { validateConfig } = require('./config');
const { logger } = require('./utils/logger');
const { securityMiddleware } = require('./middleware/security');
const { generalLimiter } = require('./middleware/rateLimiter');
const AuditLog = require('./models/AuditLog');
const User = require('./models/User');
const Role = require('./models/Role');
const Permission = require('./models/Permission');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

// Create Express application
const app = express();

/**
 * Configure middleware stack
 */
function configureMiddleware() {
  // Trust proxy (for accurate IP behind reverse proxy)
  app.set('trust proxy', 1);

  // Security headers and hardening
  app.use(securityMiddleware);

  // CORS
  app.use(cors(config.cors));

  // Body parsing
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));

  // Request logging
  if (config.server.env === 'production') {
    app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));
  } else {
    app.use(morgan('dev', { stream: { write: msg => logger.debug(msg.trim()) } }));
  }

  // General rate limiting
  app.use(generalLimiter);
}

/**
 * Configure API routes
 */
function configureRoutes() {
  // Health check endpoints (before auth)
  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
    });
  });

  app.get('/ready', async (req, res) => {
    try {
      // Check data storage is accessible
      await User.count();
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      res.status(503).json({
        status: 'not ready',
        error: error.message,
      });
    }
  });

  // API routes
  app.use(`/api/${config.server.apiVersion}/auth`, authRoutes);
  app.use(`/api/${config.server.apiVersion}/users`, userRoutes);
  app.use(`/api/${config.server.apiVersion}/admin`, adminRoutes);

  // Root endpoint
  app.get('/', (req, res) => {
    res.status(200).json({
      name: 'Auth Microservice',
      version: '1.0.0',
      description: 'Authentication and Authorization Microservice',
      documentation: '/api/docs',
      health: '/health',
      endpoints: {
        auth: `/api/${config.server.apiVersion}/auth`,
        users: `/api/${config.server.apiVersion}/users`,
        admin: `/api/${config.server.apiVersion}/admin`,
      },
    });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      error: 'Not found',
      message: `Cannot ${req.method} ${req.path}`,
      code: 'ROUTE_NOT_FOUND',
    });
  });
}

/**
 * Global error handler
 */
function configureErrorHandling() {
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, _next) => {
    const statusCode = err.statusCode || err.status || 500;

    // Log error
    if (statusCode >= 500) {
      logger.error(`Server error: ${err.message}`, {
        stack: err.stack,
        path: req.path,
        method: req.method,
        ip: req.ip,
      });
    } else {
      logger.warn(`Client error: ${err.message}`, {
        path: req.path,
        method: req.method,
        ip: req.ip,
        statusCode,
      });
    }

    // Don't leak error details in production
    const isProduction = config.server.env === 'production';

    res.status(statusCode).json({
      success: false,
      error: statusCode >= 500 && isProduction ? 'Internal server error' : err.message,
      message: statusCode >= 500 && isProduction
        ? 'An unexpected error occurred'
        : err.message,
      code: err.code || 'INTERNAL_ERROR',
      ...(isProduction ? {} : { stack: err.stack }),
    });
  });
}

/**
 * Initialize the application
 */
async function initialize() {
  try {
    // Validate configuration
    validateConfig();
    logger.info('Configuration validated');

    // Initialize audit log system
    AuditLog.init();
    logger.info('Audit logging initialized');

    // Seed default data
    await Permission.seedDefaultPermissions();
    await Role.seedDefaultRoles();
    await User.seedDefaultUsers();
    logger.info('Default data seeded');

    // Log system startup
    await auditServiceLogStartup();

    logger.info('Application initialized successfully');
  } catch (error) {
    logger.error(`Failed to initialize application: ${error.message}`);
    throw error;
  }
}

/**
 * Log system startup to audit log.
 */
async function auditServiceLogStartup() {
  try {
    const auditService = require('./services/auditService');
    await auditService.logSystemStartup();
  } catch (error) {
    logger.error(`Failed to log startup: ${error.message}`);
  }
}

/**
 * Schedule periodic cleanup tasks
 */
function scheduleCleanup() {
  // Clean up expired blacklist entries
  const { cleanupBlacklist } = require('./services/tokenService');
  setInterval(async () => {
    try {
      await cleanupBlacklist();
    } catch (error) {
      logger.error(`Blacklist cleanup error: ${error.message}`);
    }
  }, config.cleanup.blacklistCleanupIntervalMs);

  // Clean up old audit logs
  const { cleanup: cleanupAudit } = require('./models/AuditLog');
  setInterval(async () => {
    try {
      await cleanupAudit(90); // 90-day retention
    } catch (error) {
      logger.error(`Audit log cleanup error: ${error.message}`);
    }
  }, 24 * 60 * 60 * 1000); // Daily

  logger.info('Cleanup tasks scheduled');
}

/**
 * Start the HTTP server
 */
function startServer() {
  const port = config.server.port;
  const host = config.server.host;

  const server = app.listen(port, host, () => {
    logger.info(`Auth microservice running on http://${host}:${port}`);
    logger.info(`Environment: ${config.server.env}`);
    logger.info(`API version: ${config.server.apiVersion}`);
    logger.info(`Health check: http://${host}:${port}/health`);
  });

  // Graceful shutdown handling
  process.on('SIGTERM', () => gracefulShutdown(server, 'SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown(server, 'SIGINT'));

  return server;
}

/**
 * Graceful shutdown
 */
function gracefulShutdown(server, signal) {
  logger.info(`Received ${signal}, starting graceful shutdown...`);

  // Flush audit log buffer
  const AuditLogModel = require('./models/AuditLog');
  AuditLogModel.flushBuffer();

  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

// Build and configure the app
configureMiddleware();
configureRoutes();
configureErrorHandling();

// Start application
if (require.main === module) {
  (async () => {
    try {
      await initialize();
      scheduleCleanup();
      startServer();
    } catch (error) {
      logger.error(`Failed to start: ${error.message}`);
      process.exit(1);
    }
  })();
}

module.exports = app;