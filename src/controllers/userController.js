/**
 * User Controller
 * Handles user profile management, retrieval, and updates.
 */

'use strict';

const User = require('../models/User');
const auditService = require('../services/auditService');
const { logger } = require('../utils/logger');

/**
 * GET /users/me
 * Get current user's profile.
 */
async function getMe(req, res, next) {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    await auditService.logUserAction(auditService.ACTIONS.USER_READ, {
      userId,
      targetUserId: userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      data: {
        user: User.sanitizeUser(user),
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * PUT /users/me
 * Update current user's profile.
 */
async function updateMe(req, res, next) {
  try {
    const userId = req.user.userId;
    const { firstName, lastName } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    const updates = {};
    if (firstName !== undefined) updates.firstName = firstName.trim();
    if (lastName !== undefined) updates.lastName = lastName.trim();

    const updatedUser = await User.update(userId, updates);

    await auditService.logUserAction(auditService.ACTIONS.USER_UPDATE, {
      userId,
      targetUserId: userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      changes: updates,
    });

    logger.info(`User ${userId} updated their profile`);

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: updatedUser,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * DELETE /users/me
 * Delete current user's account (soft delete via deactivation).
 */
async function deleteMe(req, res, next) {
  try {
    const userId = req.user.userId;

    // Deactivate instead of hard delete
    const updatedUser = await User.update(userId, { isActive: false });

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    await auditService.logUserAction(auditService.ACTIONS.USER_DEACTIVATE, {
      userId,
      targetUserId: userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      reason: 'Self-deactivation',
    });

    logger.info(`User ${userId} deactivated their account`);

    res.status(200).json({
      success: true,
      message: 'Your account has been deactivated successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /users/:userId
 * Get a specific user's profile (requires permission or ownership).
 */
async function getUser(req, res, next) {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    await auditService.logUserAction(auditService.ACTIONS.USER_READ, {
      userId: req.user.userId,
      targetUserId: userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      data: {
        user: User.sanitizeUser(user),
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * PUT /users/:userId
 * Update a specific user's profile (admin only).
 */
async function updateUser(req, res, next) {
  try {
    const { userId } = req.params;
    const { firstName, lastName, isActive } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    const updates = {};
    if (firstName !== undefined) updates.firstName = firstName.trim();
    if (lastName !== undefined) updates.lastName = lastName.trim();
    if (isActive !== undefined) updates.isActive = Boolean(isActive);

    const updatedUser = await User.update(userId, updates);

    await auditService.logUserAction(auditService.ACTIONS.USER_UPDATE, {
      userId: req.user.userId,
      targetUserId: userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      changes: updates,
    });

    logger.info(`User ${userId} updated by admin ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: updatedUser,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * DELETE /users/:userId
 * Delete a user (hard delete - admin only).
 */
async function deleteUser(req, res, next) {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    // Prevent self-deletion through admin endpoint
    if (userId === req.user.userId) {
      return res.status(400).json({
        success: false,
        error: 'Cannot delete self',
        message: 'Use account deactivation instead of deleting your own account',
        code: 'SELF_DELETE_NOT_ALLOWED',
      });
    }

    await User.remove(userId);

    await auditService.logUserAction(auditService.ACTIONS.USER_DELETE, {
      userId: req.user.userId,
      targetUserId: userId,
      targetEmail: user.email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`User ${userId} (${user.email}) deleted by admin ${req.user.userId}`);

    res.status(200).json({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /users
 * List all users with pagination (admin/moderator).
 */
async function listUsers(req, res, next) {
  try {
    const {
      limit = 50,
      offset = 0,
      role,
      isActive,
      search,
    } = req.query;

    const filters = {};
    if (role) filters.role = role;
    if (isActive !== undefined) filters.isActive = isActive === 'true';

    let users = await User.findAll(filters);

    // Search by name or email
    if (search) {
      const searchLower = search.toLowerCase();
      users = users.filter(u =>
        u.email.toLowerCase().includes(searchLower) ||
        (u.firstName && u.firstName.toLowerCase().includes(searchLower)) ||
        (u.lastName && u.lastName.toLowerCase().includes(searchLower))
      );
    }

    const total = users.length;

    // Apply pagination
    const paginatedUsers = users.slice(parseInt(offset, 10), parseInt(offset, 10) + parseInt(limit, 10));

    await auditService.logUserAction(auditService.ACTIONS.USER_LIST, {
      userId: req.user.userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    res.status(200).json({
      success: true,
      data: {
        users: paginatedUsers,
        pagination: {
          total,
          limit: parseInt(limit, 10),
          offset: parseInt(offset, 10),
          hasMore: parseInt(offset, 10) + paginatedUsers.length < total,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /users/stats
 * Get user statistics.
 */
async function getUserStats(req, res, next) {
  try {
    const users = await User.findAll();
    const totalUsers = users.length;
    const activeUsers = users.filter(u => u.isActive).length;
    const inactiveUsers = totalUsers - activeUsers;
    const verifiedUsers = users.filter(u => u.isEmailVerified).length;

    // Count by role
    const byRole = {};
    for (const user of users) {
      byRole[user.role] = (byRole[user.role] || 0) + 1;
    }

    // Count locked accounts
    const lockedUsers = users.filter(u => User.isAccountLocked(u)).length;

    await auditService.logUserAction(auditService.ACTIONS.USER_LIST, {
      userId: req.user.userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      reason: 'Statistics request',
    });

    res.status(200).json({
      success: true,
      data: {
        totalUsers,
        activeUsers,
        inactiveUsers,
        verifiedUsers,
        lockedUsers,
        byRole,
      },
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getMe,
  updateMe,
  deleteMe,
  getUser,
  updateUser,
  deleteUser,
  listUsers,
  getUserStats,
};