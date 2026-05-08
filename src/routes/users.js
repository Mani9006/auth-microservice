/**
 * User Routes
 * Endpoints for user profile management and user listing.
 */

'use strict';

const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');
const { authenticate } = require('../middleware/authenticate');
const { requirePermission, requireOwnershipOrAdmin } = require('../middleware/authorize');
const { generalLimiter } = require('../middleware/rateLimiter');
const { validateUserUpdate, validateUUIDParam } = require('../middleware/validation');

/**
 * @route   GET /users/me
 * @desc    Get current user's profile
 * @access  Private
 */
router.get('/me', authenticate(), userController.getMe);

/**
 * @route   PUT /users/me
 * @desc    Update current user's profile
 * @access  Private
 * @body    { firstName?, lastName? }
 */
router.put('/me', authenticate(), validateUserUpdate.slice(1), userController.updateMe);

/**
 * @route   DELETE /users/me
 * @desc    Deactivate own account
 * @access  Private
 */
router.delete('/me', authenticate(), userController.deleteMe);

/**
 * @route   GET /users
 * @desc    List all users (paginated, filterable)
 * @access  Private (user:list permission)
 * @query   { limit?, offset?, role?, isActive?, search? }
 */
router.get('/',
  authenticate(),
  requirePermission('user:list'),
  generalLimiter,
  userController.listUsers
);

/**
 * @route   GET /users/stats
 * @desc    Get user statistics
 * @access  Private (user:list permission)
 */
router.get('/stats',
  authenticate(),
  requirePermission('user:list'),
  userController.getUserStats
);

/**
 * @route   GET /users/:userId
 * @desc    Get a specific user's profile
 * @access  Private (own profile or user:read permission)
 */
router.get('/:userId',
  authenticate(),
  validateUUIDParam('userId'),
  requireOwnershipOrAdmin('userId'),
  userController.getUser
);

/**
 * @route   PUT /users/:userId
 * @desc    Update a specific user (admin)
 * @access  Private (user:update permission)
 * @body    { firstName?, lastName?, isActive? }
 */
router.put('/:userId',
  authenticate(),
  requirePermission('user:update'),
  validateUUIDParam('userId'),
  userController.updateUser
);

/**
 * @route   DELETE /users/:userId
 * @desc    Delete a user (hard delete - admin)
 * @access  Private (user:delete permission)
 */
router.delete('/:userId',
  authenticate(),
  requirePermission('user:delete'),
  validateUUIDParam('userId'),
  userController.deleteUser
);

module.exports = router;