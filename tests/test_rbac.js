/**
 * RBAC (Role-Based Access Control) Tests
 * Tests for role hierarchy, permission checking, role assignment,
 * and authorization middleware.
 */

'use strict';

const request = require('supertest');
const app = require('../src/server');
const rbacService = require('../src/services/rbacService');
const User = require('../src/models/User');
const Role = require('../src/models/Role');
const Permission = require('../src/models/Permission');

describe('RBAC System', () => {
  // Default roles should be seeded
  const testUser = {
    email: 'rbactest@auth.local',
    password: 'Test123!@#',
    firstName: 'RBAC',
    lastName: 'Test',
  };

  let adminTokens = null;
  let userTokens = null;

  beforeAll(async () => {
    // Get admin tokens
    const adminLogin = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'admin@auth.local',
        password: 'Admin123!@#',
      });

    if (adminLogin.body.success) {
      adminTokens = adminLogin.body.data.tokens;
    }
  });

  beforeEach(async () => {
    // Clean up
    const existing = await User.findByEmail(testUser.email);
    if (existing) await User.remove(existing.id);

    const existing2 = await User.findByEmail('moderatortest@auth.local');
    if (existing2) await User.remove(existing2.id);
  });

  // ==========================================
  // Permission Checking Tests
  // ==========================================

  describe('Permission Checking', () => {
    it('should grant admin all permissions', async () => {
      const hasRead = await rbacService.hasPermission('admin', 'user:read');
      const hasDelete = await rbacService.hasPermission('admin', 'user:delete');
      const hasAudit = await rbacService.hasPermission('admin', 'audit:read');

      expect(hasRead).toBe(true);
      expect(hasDelete).toBe(true);
      expect(hasAudit).toBe(true);
    });

    it('should check user role permissions', async () => {
      const hasRead = await rbacService.hasPermission('user', 'user:read');
      const hasUpdate = await rbacService.hasPermission('user', 'user:update');
      const hasDelete = await rbacService.hasPermission('user', 'user:delete');
      const hasList = await rbacService.hasPermission('user', 'user:list');

      expect(hasRead).toBe(true);
      expect(hasUpdate).toBe(true);
      expect(hasDelete).toBe(false); // User cannot delete others
      expect(hasList).toBe(false); // User cannot list all users
    });

    it('should check moderator permissions', async () => {
      const hasRead = await rbacService.hasPermission('moderator', 'user:read');
      const hasList = await rbacService.hasPermission('moderator', 'user:list');
      const hasAudit = await rbacService.hasPermission('moderator', 'audit:read');
      const hasRoleCreate = await rbacService.hasPermission('moderator', 'role:create');

      expect(hasRead).toBe(true);
      expect(hasList).toBe(true);
      expect(hasAudit).toBe(true);
      expect(hasRoleCreate).toBe(false); // Mod cannot create roles
    });

    it('should support wildcard permissions', async () => {
      const hasAnything = await rbacService.hasPermission('admin', 'any:thing');
      expect(hasAnything).toBe(true);
    });

    it('should check hasAllPermissions', async () => {
      const hasAll = await rbacService.hasAllPermissions('admin', ['user:read', 'user:delete', 'audit:read']);
      expect(hasAll).toBe(true);

      const userHasAll = await rbacService.hasAllPermissions('user', ['user:read', 'user:delete']);
      expect(userHasAll).toBe(false);
    });

    it('should check hasAnyPermission', async () => {
      const hasAny = await rbacService.hasAnyPermission('user', ['user:delete', 'user:read']);
      expect(hasAny).toBe(true);

      const hasNone = await rbacService.hasAnyPermission('user', ['role:create', 'system:config']);
      expect(hasNone).toBe(false);
    });
  });

  // ==========================================
  // Role Hierarchy Tests
  // ==========================================

  describe('Role Hierarchy', () => {
    it('should get role hierarchy', () => {
      const adminHierarchy = rbacService.getRoleHierarchy('admin');
      expect(adminHierarchy).toContain('admin');
      expect(adminHierarchy).toContain('moderator');
      expect(adminHierarchy).toContain('user');
      expect(adminHierarchy).toContain('guest');
    });

    it('should inherit permissions from lower roles', async () => {
      // Admin inherits user permissions
      const hasUserRead = await rbacService.hasPermission('admin', 'user:read');
      expect(hasUserRead).toBe(true);

      // Moderator inherits user permissions
      const hasUserUpdate = await rbacService.hasPermission('moderator', 'user:update');
      expect(hasUserUpdate).toBe(true);
    });

    it('should check role hierarchy comparison', () => {
      expect(rbacService.isRoleHigherOrEqual('admin', 'user')).toBe(true);
      expect(rbacService.isRoleHigherOrEqual('admin', 'moderator')).toBe(true);
      expect(rbacService.isRoleHigherOrEqual('user', 'admin')).toBe(false);
      expect(rbacService.isRoleHigherOrEqual('user', 'user')).toBe(true);
    });

    it('should get assignable roles for admin', async () => {
      const assignable = await rbacService.getAssignableRoles('admin');
      expect(assignable.length).toBeGreaterThan(0);
    });
  });

  // ==========================================
  // Effective Permissions Tests
  // ==========================================

  describe('Effective Permissions', () => {
    it('should get effective permissions for admin', async () => {
      const perms = await rbacService.getEffectivePermissions('admin');
      expect(perms).toContain('*');
      expect(perms.length).toBeGreaterThan(0);
    });

    it('should get effective permissions for user', async () => {
      const perms = await rbacService.getEffectivePermissions('user');
      expect(perms).toContain('user:read');
      expect(perms).toContain('user:update');
      expect(perms).not.toContain('role:create');
    });
  });

  // ==========================================
  // API Authorization Tests
  // ==========================================

  describe('API Authorization', () => {
    beforeEach(async () => {
      // Register test user
      await request(app)
        .post('/api/v1/auth/register')
        .send(testUser);

      // Login as test user
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        });

      if (loginRes.body.success) {
        userTokens = loginRes.body.data.tokens;
      }
    });

    it('should allow admin to list users', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data.users).toBeDefined();
    });

    it('should deny regular user from listing all users', async () => {
      const res = await request(app)
        .get('/api/v1/users')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(403);

      expect(res.body.code).toBe('FORBIDDEN');
    });

    it('should allow admin to access admin endpoints', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .get('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
    });

    it('should deny regular user from admin endpoints', async () => {
      const res = await request(app)
        .get('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(403);

      expect(res.status).toBe(403);
    });

    it('should allow user to access own profile', async () => {
      const res = await request(app)
        .get('/api/v1/users/me')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
    });

    it('should allow user to update own profile', async () => {
      const res = await request(app)
        .put('/api/v1/users/me')
        .set('Authorization', `Bearer ${userTokens.accessToken}`)
        .send({ firstName: 'Updated' })
        .expect(200);

      expect(res.body.success).toBe(true);
    });
  });

  // ==========================================
  // Role Management API Tests
  // ==========================================

  describe('Role Management (Admin)', () => {
    it('should list roles', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .get('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.data.roles).toBeInstanceOf(Array);
      expect(res.body.data.roles.length).toBeGreaterThan(0);
    });

    it('should get a specific role', async () => {
      if (!adminTokens) return;

      // Get admin role
      const rolesRes = await request(app)
        .get('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`);

      const adminRole = rolesRes.body.data.roles.find(r => r.name === 'admin');
      if (!adminRole) return;

      const res = await request(app)
        .get(`/api/v1/admin/roles/${adminRole.id}`)
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.data.role).toBeDefined();
      expect(res.body.data.role.name).toBe('admin');
    });

    it('should create a new role', async () => {
      if (!adminTokens) return;

      const roleName = `testrole_${Date.now()}`;
      const res = await request(app)
        .post('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send({
          name: roleName,
          description: 'Test role created by test suite',
          permissions: ['user:read'],
        })
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body.data.role.name).toBe(roleName);
    });

    it('should reject duplicate role name', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .post('/api/v1/admin/roles')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send({
          name: 'admin',
          description: 'Duplicate',
        })
        .expect(409);

      expect(res.body.code).toBe('DUPLICATE_ROLE');
    });
  });

  // ==========================================
  // Permission Management Tests
  // ==========================================

  describe('Permission Management (Admin)', () => {
    it('should list permissions', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .get('/api/v1/admin/permissions')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.data.permissions).toBeInstanceOf(Array);
      expect(res.body.data.permissions.length).toBeGreaterThan(0);
      expect(res.body.data.grouped).toBeDefined();
    });

    it('should create a new permission', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .post('/api/v1/admin/permissions')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send({
          key: 'custom:action',
          description: 'Custom permission for testing',
        })
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body.data.permission.key).toBe('custom:action');
    });

    it('should reject invalid permission key format', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .post('/api/v1/admin/permissions')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send({
          key: 'invalidkey',
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('should reject duplicate permission key', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .post('/api/v1/admin/permissions')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .send({
          key: 'user:read',
        })
        .expect(409);

      expect(res.body.code).toBe('DUPLICATE_PERMISSION');
    });
  });

  // ==========================================
  // RBAC Statistics Tests
  // ==========================================

  describe('RBAC Statistics', () => {
    it('should get RBAC stats', async () => {
      const stats = await rbacService.getStats();

      expect(stats.totalRoles).toBeGreaterThan(0);
      expect(stats.totalPermissions).toBeGreaterThan(0);
      expect(stats.hierarchy).toBeDefined();
      expect(stats.roles).toBeDefined();
    });

    it('should get admin system stats', async () => {
      if (!adminTokens) return;

      const res = await request(app)
        .get('/api/v1/admin/stats')
        .set('Authorization', `Bearer ${adminTokens.accessToken}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeDefined();
    });
  });
});