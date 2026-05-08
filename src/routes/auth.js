/**
 * Authentication Routes
 * Endpoints for user registration, login, logout, token management,
 * and password operations.
 */

'use strict';

const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/authenticate');
const {
  validateRegister,
  validateLogin,
  validatePasswordChange,
  validatePasswordResetRequest,
  validatePasswordResetConfirm,
  validateRefreshToken,
} = require('../middleware/validation');
const {
  authLimiter,
  registerLimiter,
  passwordResetLimiter,
  refreshTokenLimiter,
} = require('../middleware/rateLimiter');

/**
 * @route   POST /auth/register
 * @desc    Register a new user account
 * @access  Public
 * @body    { email, password, firstName?, lastName? }
 */
router.post('/register', registerLimiter, validateRegister, authController.register);

/**
 * @route   POST /auth/login
 * @desc    Authenticate and receive JWT token pair
 * @access  Public
 * @body    { email, password }
 */
router.post('/login', authLimiter, validateLogin, authController.login);

/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public (requires valid refresh token)
 * @body    { refreshToken }
 */
router.post('/refresh', refreshTokenLimiter, validateRefreshToken, authController.refresh);

/**
 * @route   POST /auth/logout
 * @desc    Logout and invalidate current token
 * @access  Private
 */
router.post('/logout', authenticate(), authController.logout);

/**
 * @route   POST /auth/logout-all
 * @desc    Logout from all devices
 * @access  Private
 */
router.post('/logout-all', authenticate(), authController.logoutAll);

/**
 * @route   POST /auth/password/change
 * @desc    Change current user password
 * @access  Private
 * @body    { currentPassword, newPassword }
 */
router.post('/password/change', authenticate(), validatePasswordChange, authController.changePassword);

/**
 * @route   POST /auth/password/reset-request
 * @desc    Request password reset email
 * @access  Public
 * @body    { email }
 */
router.post('/password/reset-request', passwordResetLimiter, validatePasswordResetRequest, authController.requestPasswordReset);

/**
 * @route   POST /auth/password/reset
 * @desc    Reset password using token
 * @access  Public
 * @body    { token, newPassword }
 */
router.post('/password/reset', passwordResetLimiter, validatePasswordResetConfirm, authController.resetPassword);

/**
 * @route   GET /auth/password-policy
 * @desc    Get current password policy configuration
 * @access  Public
 */
router.get('/password-policy', authController.getPasswordPolicy);

/**
 * @route   GET /auth/me
 * @desc    Get current authenticated user
 * @access  Private
 */
router.get('/me', authenticate(), authController.me);

module.exports = router;