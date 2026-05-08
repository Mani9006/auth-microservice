/**
 * Authentication Tests
 * Comprehensive tests for registration, login, logout, password management,
 * token refresh, and account lockout.
 */

'use strict';

const request = require('supertest');
const app = require('../src/server');
const User = require('../src/models/User');
const tokenService = require('../src/services/tokenService');

describe('Authentication Endpoints', () => {
  const testUser = {
    email: 'test@auth.local',
    password: 'Test123!@#',
    firstName: 'Test',
    lastName: 'User',
  };

  const adminUser = {
    email: 'admin@auth.local',
    password: 'Admin123!@#',
  };

  let tokens = null;
  let testUserId = null;

  beforeEach(async () => {
    // Clean up test user if exists
    const existing = await User.findByEmail(testUser.email);
    if (existing) {
      await User.remove(existing.id);
    }
    tokens = null;
    testUserId = null;
  });

  afterEach(async () => {
    // Cleanup
    const existing = await User.findByEmail(testUser.email);
    if (existing) {
      await User.remove(existing.id);
    }
  });

  // ==========================================
  // Registration Tests
  // ==========================================

  describe('POST /api/v1/auth/register', () => {
    it('should register a new user successfully', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(testUser)
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body.data.user).toBeDefined();
      expect(res.body.data.user.email).toBe(testUser.email.toLowerCase());
      expect(res.body.data.user.firstName).toBe(testUser.firstName);
      expect(res.body.data.user.lastName).toBe(testUser.lastName);
      expect(res.body.data.user.passwordHash).toBeUndefined();
      expect(res.body.data.user.id).toBeDefined();

      testUserId = res.body.data.user.id;
    });

    it('should reject registration with weak password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...testUser,
          password: '123',
        })
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with missing email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          password: testUser.password,
          firstName: testUser.firstName,
        })
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with invalid email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...testUser,
          email: 'not-an-email',
        })
        .expect(400);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject duplicate email registration', async () => {
      // First registration
      await request(app)
        .post('/api/v1/auth/register')
        .send(testUser)
        .expect(201);

      // Duplicate
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(testUser)
        .expect(409);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('DUPLICATE_EMAIL');
    });

    it('should reject registration with password missing uppercase', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...testUser,
          password: 'test123!@#',
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject registration with password missing special character', async () => {
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send({
          ...testUser,
          password: 'Test123456',
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  // ==========================================
  // Login Tests
  // ==========================================

  describe('POST /api/v1/auth/login', () => {
    beforeEach(async () => {
      // Register a test user
      const res = await request(app)
        .post('/api/v1/auth/register')
        .send(testUser);

      testUserId = res.body.data.user.id;
    });

    it('should login with valid credentials', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.tokens.accessToken).toBeDefined();
      expect(res.body.data.tokens.refreshToken).toBeDefined();
      expect(res.body.data.tokens.tokenType).toBe('Bearer');
      expect(res.body.data.user.email).toBe(testUser.email.toLowerCase());

      tokens = res.body.data.tokens;
    });

    it('should reject login with wrong password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123!',
        })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('INVALID_CREDENTIALS');
    });

    it('should reject login for non-existent user', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@auth.local',
          password: 'SomePassword123!',
        })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('INVALID_CREDENTIALS');
    });

    it('should reject login with missing email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          password: testUser.password,
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject login with missing password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should show remaining attempts after failed login', async () => {
      // Make 2 failed attempts
      await request(app).post('/api/v1/auth/login').send({ email: testUser.email, password: 'Wrong1!' });
      await request(app).post('/api/v1/auth/login').send({ email: testUser.email, password: 'Wrong2!' });

      // 3rd failed attempt should show remaining
      const res = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: testUser.email, password: 'Wrong3!' });

      expect(res.body.attemptsRemaining).toBeDefined();
      expect(res.body.attemptsRemaining).toBeLessThan(5);
    });
  });

  // ==========================================
  // Token Refresh Tests
  // ==========================================

  describe('POST /api/v1/auth/refresh', () => {
    beforeEach(async () => {
      // Register and login
      await request(app).post('/api/v1/auth/register').send(testUser);
      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: testUser.email,
        password: testUser.password,
      });
      tokens = loginRes.body.data.tokens;
    });

    it('should refresh tokens with valid refresh token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(res.body.data.refreshToken).toBeDefined();
      expect(res.body.data.accessToken).not.toBe(tokens.accessToken);
      expect(res.body.data.refreshToken).not.toBe(tokens.refreshToken);

      tokens = res.body.data;
    });

    it('should reject refresh with invalid token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid.token.here' })
        .expect(401);

      expect(res.body.success).toBe(false);
      expect(res.body.code).toBe('INVALID_REFRESH_TOKEN');
    });

    it('should reject refresh with missing token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .send({})
        .expect(400);

      expect(res.body.code).toBe('MISSING_REFRESH_TOKEN');
    });

    it('should detect token reuse', async () => {
      // Use the refresh token
      await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(200);

      // Try to reuse the same refresh token
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(401);

      expect(res.body.code).toBe('INVALID_REFRESH_TOKEN');
      expect(res.body.message).toContain('reuse');
    });
  });

  // ==========================================
  // Logout Tests
  // ==========================================

  describe('POST /api/v1/auth/logout', () => {
    beforeEach(async () => {
      await request(app).post('/api/v1/auth/register').send(testUser);
      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: testUser.email,
        password: testUser.password,
      });
      tokens = loginRes.body.data.tokens;
    });

    it('should logout successfully', async () => {
      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('Logged out');
    });

    it('should reject access after logout', async () => {
      // Logout
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`);

      // Try to access protected endpoint
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tokens.accessToken}`);

      // Token is blacklisted
      expect(res.status).toBeGreaterThanOrEqual(401);
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/v1/auth/logout')
        .expect(401);

      expect(res.body.code).toBe('NO_TOKEN');
    });
  });

  // ==========================================
  // Password Change Tests
  // ==========================================

  describe('POST /api/v1/auth/password/change', () => {
    beforeEach(async () => {
      await request(app).post('/api/v1/auth/register').send(testUser);
      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: testUser.email,
        password: testUser.password,
      });
      tokens = loginRes.body.data.tokens;
    });

    it('should change password with correct current password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/change')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({
          currentPassword: testUser.password,
          newPassword: 'NewPass123!@#',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('success');
    });

    it('should reject password change with wrong current password', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/change')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({
          currentPassword: 'WrongPassword!',
          newPassword: 'NewPass123!@#',
        })
        .expect(400);

      expect(res.body.success).toBe(false);
    });

    it('should reject password change when new equals current', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/change')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .send({
          currentPassword: testUser.password,
          newPassword: testUser.password,
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/change')
        .send({
          currentPassword: testUser.password,
          newPassword: 'NewPass123!@#',
        })
        .expect(401);

      expect(res.body.code).toBe('NO_TOKEN');
    });
  });

  // ==========================================
  // Password Reset Tests
  // ==========================================

  describe('POST /api/v1/auth/password/reset-request', () => {
    beforeEach(async () => {
      await request(app).post('/api/v1/auth/register').send(testUser);
    });

    it('should accept reset request for existing email', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/reset-request')
        .send({ email: testUser.email })
        .expect(200);

      expect(res.body.success).toBe(true);
    });

    it('should still return success for non-existent email (no enumeration)', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/reset-request')
        .send({ email: 'nonexistent@auth.local' })
        .expect(200);

      expect(res.body.success).toBe(true);
    });
  });

  describe('POST /api/v1/auth/password/reset', () => {
    let resetToken = null;

    beforeEach(async () => {
      await request(app).post('/api/v1/auth/register').send(testUser);

      // Request reset
      const resetRes = await request(app)
        .post('/api/v1/auth/password/reset-request')
        .send({ email: testUser.email });

      // In dev mode, token is returned
      resetToken = resetRes.body.data?.resetToken;
    });

    it('should reset password with valid token', async () => {
      if (!resetToken) {
        return; // Skip in non-dev mode
      }

      const res = await request(app)
        .post('/api/v1/auth/password/reset')
        .send({
          token: resetToken,
          newPassword: 'ResetPass123!@#',
        })
        .expect(200);

      expect(res.body.success).toBe(true);

      // Verify we can login with new password
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: 'ResetPass123!@#',
        })
        .expect(200);

      expect(loginRes.body.success).toBe(true);
    });

    it('should reject reset with invalid token', async () => {
      const res = await request(app)
        .post('/api/v1/auth/password/reset')
        .send({
          token: 'invalid-token',
          newPassword: 'ResetPass123!@#',
        })
        .expect(400);

      expect(res.body.code).toBe('INVALID_RESET_TOKEN');
    });

    it('should reject reset with weak new password', async () => {
      if (!resetToken) return;

      const res = await request(app)
        .post('/api/v1/auth/password/reset')
        .send({
          token: resetToken,
          newPassword: '123',
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  // ==========================================
  // Get Current User Tests
  // ==========================================

  describe('GET /api/v1/auth/me', () => {
    beforeEach(async () => {
      await request(app).post('/api/v1/auth/register').send(testUser);
      const loginRes = await request(app).post('/api/v1/auth/login').send({
        email: testUser.email,
        password: testUser.password,
      });
      tokens = loginRes.body.data.tokens;
    });

    it('should return current user info', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe(testUser.email.toLowerCase());
      expect(res.body.data.user.passwordHash).toBeUndefined();
    });

    it('should require authentication', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .expect(401);

      expect(res.body.code).toBe('NO_TOKEN');
    });

    it('should reject invalid token', async () => {
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', 'Bearer invalid.token.here')
        .expect(401);

      expect(res.body.code).toBe('INVALID_TOKEN');
    });
  });

  // ==========================================
  // Password Policy Tests
  // ==========================================

  describe('GET /api/v1/auth/password-policy', () => {
    it('should return password policy', async () => {
      const res = await request(app)
        .get('/api/v1/auth/password-policy')
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeDefined();
      expect(res.body.data.minLength).toBeDefined();
      expect(res.body.data.requireUppercase).toBeDefined();
      expect(res.body.data.requireLowercase).toBeDefined();
      expect(res.body.data.requireDigit).toBeDefined();
      expect(res.body.data.requireSpecial).toBeDefined();
      expect(res.body.data.requirements).toBeInstanceOf(Array);
    });
  });

  // ==========================================
  // Health Check Tests
  // ==========================================

  describe('Health Checks', () => {
    it('should return health status', async () => {
      const res = await request(app).get('/health').expect(200);

      expect(res.body.status).toBe('healthy');
      expect(res.body.timestamp).toBeDefined();
      expect(res.body.uptime).toBeDefined();
    });

    it('should return ready status', async () => {
      const res = await request(app).get('/ready').expect(200);

      expect(res.body.status).toBe('ready');
    });
  });

  // ==========================================
  // Root Endpoint Tests
  // ==========================================

  describe('GET /', () => {
    it('should return API info', async () => {
      const res = await request(app).get('/').expect(200);

      expect(res.body.name).toBe('Auth Microservice');
      expect(res.body.version).toBeDefined();
      expect(res.body.endpoints).toBeDefined();
    });
  });

  // ==========================================
  // 404 Tests
  // ==========================================

  describe('404 Handling', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await request(app).get('/api/v1/nonexistent').expect(404);

      expect(res.body.code).toBe('ROUTE_NOT_FOUND');
    });
  });
});