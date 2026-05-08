/**
 * Authentication Controller
 * Handles user registration, login, logout, token refresh, and password management.
 */

'use strict';

const User = require('../models/User');
const Role = require('../models/Role');
const tokenService = require('../services/tokenService');
const passwordService = require('../services/passwordService');
const auditService = require('../services/auditService');
const { logger } = require('../utils/logger');
const { comparePassword } = require('../utils/hash');
const config = require('../config');

/**
 * POST /auth/register
 * Register a new user account.
 */
async function register(req, res, next) {
  try {
    const { email, password, firstName, lastName } = req.body;

    // Validate password strength
    const strengthCheck = passwordService.validatePasswordStrength(password);
    if (!strengthCheck.isValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid password',
        message: 'Password does not meet requirements',
        code: 'WEAK_PASSWORD',
        errors: strengthCheck.errors,
        policy: passwordService.getPasswordPolicy(),
      });
    }

    // Get default role
    const defaultRole = await Role.getDefaultRole();

    // Create user
    const user = await User.create({
      email,
      password,
      firstName,
      lastName,
      role: defaultRole ? defaultRole.name : 'user',
    });

    await auditService.logAuth(auditService.ACTIONS.USER_REGISTER, {
      userId: user.id,
      email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    logger.info(`New user registered: ${email}`);

    // Return user (without sensitive data)
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: {
        user,
      },
    });
  } catch (error) {
    if (error.code === 'DUPLICATE_EMAIL') {
      await auditService.logAuth(auditService.ACTIONS.USER_REGISTER, {
        email,
        success: false,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: error.message,
      });

      return res.status(409).json({
        success: false,
        error: 'Email already exists',
        message: 'An account with this email address already exists',
        code: 'DUPLICATE_EMAIL',
      });
    }

    next(error);
  }
}

/**
 * POST /auth/login
 * Authenticate user and issue token pair.
 */
async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findByEmail(email);

    if (!user) {
      await auditService.logAuth(auditService.ACTIONS.LOGIN_FAILED, {
        email,
        success: false,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: 'User not found',
      });

      // Return same error as wrong password to prevent user enumeration
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
        code: 'INVALID_CREDENTIALS',
      });
    }

    // Check if account is locked
    if (User.isAccountLocked(user)) {
      const remaining = User.getLockoutTimeRemaining(user);

      await auditService.logAuth(auditService.ACTIONS.LOGIN_FAILED, {
        userId: user.id,
        email,
        success: false,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: 'Account locked',
      });

      return res.status(423).json({
        success: false,
        error: 'Account locked',
        message: `Account is temporarily locked. Try again in ${remaining} seconds.`,
        code: 'ACCOUNT_LOCKED',
        lockoutRemaining: remaining,
      });
    }

    // Verify password
    const passwordMatch = await comparePassword(password, user.passwordHash);

    if (!passwordMatch) {
      // Record failed attempt
      const lockoutInfo = await User.recordFailedAttempt(user.id);

      await auditService.logAuth(auditService.ACTIONS.LOGIN_FAILED, {
        userId: user.id,
        email,
        success: false,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: 'Invalid password',
      });

      const response = {
        success: false,
        error: 'Invalid credentials',
        message: 'Email or password is incorrect',
        code: 'INVALID_CREDENTIALS',
      };

      // Warn about impending lockout
      if (lockoutInfo && lockoutInfo.lockedUntil) {
        response.warning = 'Account has been locked due to too many failed attempts';
        response.lockoutRemaining = User.getLockoutTimeRemaining({ lockedUntil: lockoutInfo.lockedUntil });
        return res.status(423).json(response);
      }

      // Show remaining attempts
      const remainingAttempts = config.lockout.maxFailedAttempts - (lockoutInfo?.failedAttempts || 0);
      if (remainingAttempts <= 3) {
        response.attemptsRemaining = remainingAttempts;
      }

      return res.status(401).json(response);
    }

    // Check if account is active
    if (!user.isActive) {
      await auditService.logAuth(auditService.ACTIONS.LOGIN_FAILED, {
        userId: user.id,
        email,
        success: false,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: 'Account deactivated',
      });

      return res.status(403).json({
        success: false,
        error: 'Account deactivated',
        message: 'Your account has been deactivated. Please contact an administrator.',
        code: 'ACCOUNT_DEACTIVATED',
      });
    }

    // Reset failed attempts and record login
    await User.resetFailedAttempts(user.id);

    // Issue token pair
    const tokens = await tokenService.issueTokenPair(user);

    await auditService.logAuth(auditService.ACTIONS.USER_LOGIN, {
      userId: user.id,
      email,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      tokenJti: tokens.jti,
      method: 'local',
    });

    logger.info(`User logged in: ${email}`);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: User.sanitizeUser(user),
        tokens: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          tokenType: tokens.tokenType,
          expiresIn: tokens.accessTokenExpiresAt,
          refreshExpiresIn: tokens.refreshTokenExpiresAt,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/refresh
 * Refresh access token using refresh token.
 */
async function refresh(req, res, next) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: 'Missing refresh token',
        message: 'Refresh token is required',
        code: 'MISSING_REFRESH_TOKEN',
      });
    }

    try {
      const tokens = await tokenService.rotateRefreshToken(refreshToken);

      await auditService.logAuth(auditService.ACTIONS.TOKEN_REFRESH, {
        success: true,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        tokenJti: tokens.jti,
      });

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          tokenType: tokens.tokenType,
          expiresIn: tokens.accessTokenExpiresAt,
          refreshExpiresIn: tokens.refreshTokenExpiresAt,
        },
      });
    } catch (error) {
      if (error.message.includes('reuse')) {
        await auditService.logTokenReuse({
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        });
      }

      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token',
        message: error.message,
        code: 'INVALID_REFRESH_TOKEN',
      });
    }
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/logout
 * Logout user and blacklist the token.
 */
async function logout(req, res, next) {
  try {
    const userId = req.user?.userId;
    const tokenJti = req.tokenJti;

    if (tokenJti) {
      await tokenService.blacklistToken(tokenJti, userId || 'anonymous', 'logout');
    }

    // Remove refresh token from user record
    if (tokenJti && userId) {
      await User.removeRefreshToken(userId, tokenJti);
    }

    await auditService.logAuth(auditService.ACTIONS.USER_LOGOUT, {
      userId: userId || 'anonymous',
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      tokenJti,
    });

    logger.info(`User logged out: ${userId || 'anonymous'}`);

    res.status(200).json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/logout-all
 * Logout from all devices by revoking all tokens.
 */
async function logoutAll(req, res, next) {
  try {
    const userId = req.user.userId;

    await tokenService.revokeAllUserTokens(userId);

    await auditService.logAuth(auditService.ACTIONS.USER_LOGOUT, {
      userId,
      success: true,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      reason: 'Logout from all devices',
    });

    logger.info(`User logged out from all devices: ${userId}`);

    res.status(200).json({
      success: true,
      message: 'Logged out from all devices successfully',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/password/change
 * Change user password (authenticated).
 */
async function changePassword(req, res, next) {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }

    const result = await passwordService.changePassword(user, currentPassword, newPassword);

    await auditService.logAuth(result.success ? auditService.ACTIONS.PASSWORD_CHANGE : auditService.ACTIONS.PASSWORD_CHANGE, {
      userId,
      success: result.success,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      reason: result.success ? undefined : result.message,
    });

    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: result.message,
        message: result.message,
        code: 'PASSWORD_CHANGE_FAILED',
        ...(result.errors && { errors: result.errors }),
      });
    }

    logger.info(`Password changed for user ${userId}`);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/password/reset-request
 * Request a password reset token.
 */
async function requestPasswordReset(req, res, next) {
  try {
    const { email } = req.body;

    // Always return success even if email not found (prevent enumeration)
    const user = await User.findByEmail(email);

    if (user) {
      // Generate reset token
      const resetData = passwordService.generatePasswordResetToken();

      // Store hashed token
      await User.setPasswordResetToken(user.id, resetData.hashedToken, 15);

      // In a real application, send email here
      // await emailService.sendPasswordReset(user.email, resetData.plainToken);

      logger.info(`Password reset requested for: ${email}`);

      // Log the event
      await auditService.logAuth(auditService.ACTIONS.PASSWORD_RESET_REQUEST, {
        userId: user.id,
        email,
        success: true,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      // In development, return the token for testing
      if (config.server.env === 'development') {
        return res.status(200).json({
          success: true,
          message: 'Password reset instructions sent to your email',
          data: {
            // Only in dev mode - normally sent via email
            resetToken: resetData.plainToken,
            expiresAt: resetData.expiresAt,
          },
        });
      }
    }

    res.status(200).json({
      success: true,
      message: 'If an account with that email exists, password reset instructions have been sent',
    });
  } catch (error) {
    next(error);
  }
}

/**
 * POST /auth/password/reset
 * Reset password using token.
 */
async function resetPassword(req, res, next) {
  try {
    const { token, newPassword } = req.body;

    // Find user by reset token - iterate all users to check
    const users = await User.findAll();
    let matchedUser = null;

    for (const u of users) {
      // We need the raw user with password reset token
      const fullUser = await User.findById(u.id);
      if (
        fullUser &&
        fullUser.passwordResetToken &&
        fullUser.passwordResetExpires &&
        passwordService.verifyResetToken(token, fullUser.passwordResetToken, fullUser.passwordResetExpires)
      ) {
        matchedUser = fullUser;
        break;
      }
    }

    if (!matchedUser) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or expired token',
        message: 'The password reset token is invalid or has expired',
        code: 'INVALID_RESET_TOKEN',
      });
    }

    const result = await passwordService.resetPassword(matchedUser, newPassword);

    await auditService.logAuth(
      result.success ? auditService.ACTIONS.PASSWORD_RESET_COMPLETE : auditService.ACTIONS.PASSWORD_RESET_COMPLETE,
      {
        userId: matchedUser.id,
        email: matchedUser.email,
        success: result.success,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        reason: result.success ? undefined : result.message,
      }
    );

    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: result.message,
        message: result.message,
        code: 'PASSWORD_RESET_FAILED',
        ...(result.errors && { errors: result.errors }),
      });
    }

    logger.info(`Password reset completed for: ${matchedUser.email}`);

    res.status(200).json({
      success: true,
      message: result.message,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * GET /auth/password-policy
 * Get current password policy.
 */
function getPasswordPolicy(req, res) {
  res.status(200).json({
    success: true,
    data: passwordService.getPasswordPolicy(),
  });
}

/**
 * GET /auth/me
 * Get current authenticated user info.
 */
async function me(req, res, next) {
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

module.exports = {
  register,
  login,
  refresh,
  logout,
  logoutAll,
  changePassword,
  requestPasswordReset,
  resetPassword,
  getPasswordPolicy,
  me,
};