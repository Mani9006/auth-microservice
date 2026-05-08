/**
 * Token Management Tests
 * Tests for token generation, verification, rotation, blacklisting,
 * and token lifecycle management.
 */

'use strict';

const request = require('supertest');
const app = require('../src/server');
const tokenService = require('../src/services/tokenService');
const User = require('../src/models/User');
const {
  generateTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  decodeToken,
  isTokenExpired,
} = require('../src/utils/jwt');

describe('Token Management', () => {
  const testUser = {
    email: 'tokentest@auth.local',
    password: 'Test123!@#',
    firstName: 'Token',
    lastName: 'Test',
  };

  let tokens = null;
  let rawUser = null;

  beforeEach(async () => {
    // Clean up
    const existing = await User.findByEmail(testUser.email);
    if (existing) await User.remove(existing.id);

    // Register and login
    await request(app).post('/api/v1/auth/register').send(testUser);
    const loginRes = await request(app).post('/api/v1/auth/login').send({
      email: testUser.email,
      password: testUser.password,
    });

    tokens = loginRes.body.data.tokens;
    rawUser = await User.findByEmail(testUser.email);
  });

  afterEach(async () => {
    const existing = await User.findByEmail(testUser.email);
    if (existing) await User.remove(existing.id);
  });

  // ==========================================
  // Token Generation Tests
  // ==========================================

  describe('Token Generation', () => {
    it('should generate a token pair', () => {
      const pair = generateTokenPair({
        userId: 'test-id',
        email: 'test@example.com',
        role: 'user',
      });

      expect(pair.accessToken).toBeDefined();
      expect(pair.refreshToken).toBeDefined();
      expect(pair.jti).toBeDefined();
      expect(pair.tokenType).toBe('Bearer');
      expect(pair.accessTokenExpiresAt).toBeDefined();
      expect(pair.refreshTokenExpiresAt).toBeDefined();

      // Tokens should be different strings
      expect(pair.accessToken).not.toBe(pair.refreshToken);
    });

    it('should decode a token', () => {
      const pair = generateTokenPair({
        userId: 'test-id',
        email: 'test@example.com',
        role: 'user',
      });

      const decoded = decodeToken(pair.accessToken);

      expect(decoded).toBeDefined();
      expect(decoded.sub).toBe('test-id');
      expect(decoded.email).toBe('test@example.com');
      expect(decoded.role).toBe('user');
      expect(decoded.type).toBe('access');
      expect(decoded.jti).toBeDefined();
    });

    it('should verify valid access token', () => {
      const pair = generateTokenPair({
        userId: 'test-id',
        email: 'test@example.com',
        role: 'user',
      });

      const decoded = verifyAccessToken(pair.accessToken);

      expect(decoded.sub).toBe('test-id');
      expect(decoded.type).toBe('access');
    });

    it('should verify valid refresh token', () => {
      const pair = generateTokenPair({
        userId: 'test-id',
        email: 'test@example.com',
        role: 'user',
      });

      const decoded = verifyRefreshToken(pair.refreshToken);

      expect(decoded.sub).toBe('test-id');
      expect(decoded.type).toBe('refresh');
    });

    it('should reject token with wrong type', () => {
      const pair = generateTokenPair({
        userId: 'test-id',
        email: 'test@example.com',
        role: 'user',
      });

      // Try to use access token as refresh token
      expect(() => verifyRefreshToken(pair.accessToken)).toThrow();
    });
  });

  // ==========================================
  // Token Service Tests
  // ==========================================

  describe('Token Service', () => {
    it('should issue token pair via service', async () => {
      const user = await User.findByEmail(testUser.email);
      const pair = await tokenService.issueTokenPair(user);

      expect(pair.accessToken).toBeDefined();
      expect(pair.refreshToken).toBeDefined();

      // Verify stored in user record
      const updated = await User.findById(user.id);
      const hasToken = await User.hasRefreshToken(user.id, pair.jti);
      expect(hasToken).toBe(true);
    });

    it('should verify access token via service', async () => {
      const decoded = await tokenService.verifyAccessTokenSafe(tokens.accessToken);

      expect(decoded.sub).toBeDefined();
      expect(decoded.email).toBe(testUser.email.toLowerCase());
      expect(decoded.role).toBeDefined();
    });

    it('should blacklist a token', async () => {
      const pair = generateTokenPair({
        userId: rawUser.id,
        email: rawUser.email,
        role: rawUser.role,
      });

      await tokenService.blacklistToken(pair.jti, rawUser.id, 'test');

      const isBlacklisted = await tokenService.isBlacklisted(pair.jti);
      expect(isBlacklisted).toBe(true);
    });

    it('should reject blacklisted token', async () => {
      const pair = generateTokenPair({
        userId: rawUser.id,
        email: rawUser.email,
        role: rawUser.role,
      });

      // Use the token once
      await tokenService.verifyAccessTokenSafe(pair.accessToken);

      // Blacklist it
      await tokenService.blacklistToken(pair.jti, rawUser.id, 'revoke');

      // Should now fail
      await expect(tokenService.verifyAccessTokenSafe(pair.accessToken)).rejects.toThrow('revoked');
    });

    it('should rotate refresh tokens', async () => {
      const newPair = await tokenService.rotateRefreshToken(tokens.refreshToken);

      expect(newPair.accessToken).toBeDefined();
      expect(newPair.refreshToken).toBeDefined();
      expect(newPair.accessToken).not.toBe(tokens.accessToken);
      expect(newPair.refreshToken).not.toBe(tokens.refreshToken);
    });

    it('should detect refresh token reuse', async () => {
      // First refresh is successful
      await tokenService.rotateRefreshToken(tokens.refreshToken);

      // Second use of same refresh token should fail
      await expect(tokenService.rotateRefreshToken(tokens.refreshToken)).rejects.toThrow('reuse');
    });

    it('should revoke all user tokens', async () => {
      const user = await User.findByEmail(testUser.email);

      // Issue multiple token pairs
      await tokenService.issueTokenPair(user);
      await tokenService.issueTokenPair(user);

      // Revoke all
      await tokenService.revokeAllUserTokens(user.id);

      // Check user has no refresh tokens
      const updated = await User.findById(user.id);
      expect(updated.refreshTokens.length).toBe(0);
    });

    it('should clean up blacklist', async () => {
      const cleaned = await tokenService.cleanupBlacklist();
      expect(typeof cleaned).toBe('number');
    });

    it('should get blacklist stats', async () => {
      const stats = await tokenService.getBlacklistStats();
      expect(typeof stats.totalEntries).toBe('number');
      expect(stats.byReason).toBeDefined();
    });
  });

  // ==========================================
  // Token Expiration Tests
  // ==========================================

  describe('Token Expiration', () => {
    it('should check if valid token is not expired', () => {
      const decoded = decodeToken(tokens.accessToken);
      expect(isTokenExpired(decoded)).toBe(false);
    });

    it('should decode blacklisted but otherwise valid token', () => {
      const decoded = decodeToken(tokens.accessToken);
      expect(decoded).toBeDefined();
      expect(decoded.sub).toBeDefined();
    });
  });

  // ==========================================
  // Token Rotation via API
  // ==========================================

  describe('Token Rotation via API', () => {
    it('should rotate tokens via API', async () => {
      const res = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.accessToken).toBeDefined();
      expect(res.body.data.refreshToken).toBeDefined();

      tokens = res.body.data;
    });

    it('should maintain session after token refresh', async () => {
      // Rotate tokens
      const refreshRes = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken });

      const newTokens = refreshRes.body.data;

      // Use new access token
      const meRes = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${newTokens.accessToken}`)
        .expect(200);

      expect(meRes.body.success).toBe(true);
      expect(meRes.body.data.user.email).toBe(testUser.email.toLowerCase());
    });

    it('should allow using new refresh token after rotation', async () => {
      // First rotation
      const refresh1 = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: tokens.refreshToken })
        .expect(200);

      const newTokens = refresh1.body.data;

      // Second rotation using new refresh token
      const refresh2 = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: newTokens.refreshToken })
        .expect(200);

      expect(refresh2.body.success).toBe(true);
    });
  });

  // ==========================================
  // Token Blacklist via API
  // ==========================================

  describe('Token Blacklist via API', () => {
    it('should blacklist token on logout', async () => {
      // Logout
      await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      // Try to use the same token
      const res = await request(app)
        .get('/api/v1/auth/me')
        .set('Authorization', `Bearer ${tokens.accessToken}`);

      expect(res.status).toBeGreaterThanOrEqual(401);
    });

    it('should allow logout without errors', async () => {
      const res = await request(app)
        .post('/api/v1/auth/logout')
        .set('Authorization', `Bearer ${tokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
    });
  });

  // ==========================================
  // Token Inspection
  // ==========================================

  describe('Token Inspection', () => {
    it('should inspect a token', () => {
      const decoded = tokenService.inspectToken(tokens.accessToken);
      expect(decoded).toBeDefined();
      expect(decoded.sub).toBeDefined();
      expect(decoded.type).toBe('access');
    });

    it('should return null for invalid token', () => {
      const decoded = tokenService.inspectToken('not.a.token');
      expect(decoded).toBeNull();
    });
  });
});