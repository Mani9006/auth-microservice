/**
 * Input validation middleware using express-validator.
 * Provides validators for all authentication and user management endpoints.
 */

'use strict';

const { body, param, query, validationResult } = require('express-validator');
const { logger } = require('../utils/logger');

/**
 * Handle validation errors and return structured response.
 * @param {Object} req - Express request.
 * @param {Object} res - Express response.
 * @param {Function} next - Express next function.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = errors.array().map(err => ({
    field: err.path || err.param,
    value: err.value,
    message: err.msg,
    location: err.location,
  }));

  logger.debug(`Validation failed for ${req.method} ${req.path}: ${extractedErrors.map(e => e.message).join(', ')}`);

  return res.status(400).json({
    success: false,
    error: 'Validation failed',
    message: 'The request contains invalid data',
    code: 'VALIDATION_ERROR',
    errors: extractedErrors,
  });
}

// ==========================================
// Registration Validation
// ==========================================

const validateRegister = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail()
    .isLength({ max: 255 }).withMessage('Email must not exceed 255 characters'),

  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .isLength({ max: 128 }).withMessage('Password must not exceed 128 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/\d/).withMessage('Password must contain at least one digit')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Password must contain at least one special character'),

  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 }).withMessage('First name must be 1-50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters'),

  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 }).withMessage('Last name must be 1-50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters'),

  handleValidationErrors,
];

// ==========================================
// Login Validation
// ==========================================

const validateLogin = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required'),

  handleValidationErrors,
];

// ==========================================
// Password Change Validation
// ==========================================

const validatePasswordChange = [
  body('currentPassword')
    .notEmpty().withMessage('Current password is required'),

  body('newPassword')
    .notEmpty().withMessage('New password is required')
    .isLength({ min: 8 }).withMessage('New password must be at least 8 characters long')
    .isLength({ max: 128 }).withMessage('New password must not exceed 128 characters')
    .matches(/[A-Z]/).withMessage('New password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('New password must contain at least one lowercase letter')
    .matches(/\d/).withMessage('New password must contain at least one digit')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('New password must contain at least one special character'),

  body('newPassword')
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),

  handleValidationErrors,
];

// ==========================================
// Password Reset Request Validation
// ==========================================

const validatePasswordResetRequest = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),

  handleValidationErrors,
];

// ==========================================
// Password Reset Confirm Validation
// ==========================================

const validatePasswordResetConfirm = [
  body('token')
    .notEmpty().withMessage('Reset token is required'),

  body('newPassword')
    .notEmpty().withMessage('New password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .isLength({ max: 128 }).withMessage('Password must not exceed 128 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/\d/).withMessage('Password must contain at least one digit')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/).withMessage('Password must contain at least one special character'),

  handleValidationErrors,
];

// ==========================================
// Refresh Token Validation
// ==========================================

const validateRefreshToken = [
  body('refreshToken')
    .notEmpty().withMessage('Refresh token is required')
    .isString().withMessage('Refresh token must be a string'),

  handleValidationErrors,
];

// ==========================================
// User Update Validation
// ==========================================

const validateUserUpdate = [
  param('userId')
    .notEmpty().withMessage('User ID is required')
    .isUUID().withMessage('Invalid user ID format'),

  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 }).withMessage('First name must be 1-50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters'),

  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 }).withMessage('Last name must be 1-50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters'),

  handleValidationErrors,
];

// ==========================================
// Role Validation
// ==========================================

const validateRoleCreate = [
  body('name')
    .trim()
    .notEmpty().withMessage('Role name is required')
    .isLength({ min: 1, max: 50 }).withMessage('Role name must be 1-50 characters')
    .matches(/^[a-z][a-z0-9_-]*$/).withMessage('Role name must start with a letter and contain only lowercase letters, numbers, hyphens, and underscores'),

  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 }).withMessage('Description must not exceed 255 characters'),

  body('permissions')
    .optional()
    .isArray().withMessage('Permissions must be an array'),

  handleValidationErrors,
];

// ==========================================
// Permission Validation
// ==========================================

const validatePermissionCreate = [
  body('key')
    .trim()
    .notEmpty().withMessage('Permission key is required')
    .matches(/^[a-z-]+:[a-z-]+$/).withMessage('Permission key must be in format "resource:action"'),

  body('description')
    .optional()
    .trim()
    .isLength({ max: 255 }).withMessage('Description must not exceed 255 characters'),

  handleValidationErrors,
];

// ==========================================
// Audit Log Query Validation
// ==========================================

const validateAuditQuery = [
  query('limit')
    .optional()
    .isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000')
    .toInt(),

  query('offset')
    .optional()
    .isInt({ min: 0 }).withMessage('Offset must be a non-negative integer')
    .toInt(),

  query('severity')
    .optional()
    .isIn(['info', 'warning', 'error', 'critical']).withMessage('Invalid severity level'),

  query('startDate')
    .optional()
    .isISO8601().withMessage('Start date must be a valid ISO 8601 date'),

  query('endDate')
    .optional()
    .isISO8601().withMessage('End date must be a valid ISO 8601 date'),

  handleValidationErrors,
];

// ==========================================
// UUID Parameter Validation
// ==========================================

const validateUUIDParam = (field = 'userId') => [
  param(field)
    .notEmpty().withMessage(`${field} is required`)
    .isUUID().withMessage(`Invalid ${field} format`),

  handleValidationErrors,
];

// ==========================================
// Generic body field sanitizer
// ==========================================

const sanitizeBody = (fields) => [
  ...fields.map(field =>
    body(field)
      .optional()
      .trim()
      .escape()
  ),
  handleValidationErrors,
];

// ==========================================
// Export all validators
// ==========================================

module.exports = {
  handleValidationErrors,
  validateRegister,
  validateLogin,
  validatePasswordChange,
  validatePasswordResetRequest,
  validatePasswordResetConfirm,
  validateRefreshToken,
  validateUserUpdate,
  validateRoleCreate,
  validatePermissionCreate,
  validateAuditQuery,
  validateUUIDParam,
  sanitizeBody,
};