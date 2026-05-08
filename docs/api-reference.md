# API Reference

## Base URL

```
http://localhost:3001/api/v1
```

## Authentication

Most endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Content Type

```
Content-Type: application/json
```

---

## Auth Endpoints

### POST /auth/register

Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "user",
      "isActive": true,
      "isEmailVerified": false,
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  }
}
```

**Errors:**
- `400` - Validation error
- `409` - Email already registered

---

### POST /auth/login

Authenticate and receive a JWT token pair.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { "..." },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIs...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
      "tokenType": "Bearer",
      "expiresIn": 1704067200,
      "refreshExpiresIn": 1704672000
    }
  }
}
```

**Errors:**
- `400` - Validation error
- `401` - Invalid credentials
- `423` - Account locked

---

### POST /auth/refresh

Refresh the access token using a refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "accessToken": "eyJhbGc...",
    "refreshToken": "eyJhbGc...",
    "tokenType": "Bearer",
    "expiresIn": 1704067200,
    "refreshExpiresIn": 1704672000
  }
}
```

**Errors:**
- `400` - Missing refresh token
- `401` - Invalid or expired refresh token

---

### POST /auth/logout

Logout and invalidate the current token.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### POST /auth/logout-all

Logout from all devices by revoking all tokens.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out from all devices successfully"
}
```

---

### POST /auth/password/change

Change the current user's password.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "currentPassword": "OldPass123!",
  "newPassword": "NewPass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

### POST /auth/password/reset-request

Request a password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "If an account with that email exists, password reset instructions have been sent"
}
```

---

### POST /auth/password/reset

Reset password using a token.

**Request Body:**
```json
{
  "token": "base64url-reset-token",
  "newPassword": "NewPass123!"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Password reset successfully. Please log in with your new password."
}
```

---

### GET /auth/password-policy

Get the current password policy.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "minLength": 8,
    "maxLength": 128,
    "requireUppercase": true,
    "requireLowercase": true,
    "requireDigit": true,
    "requireSpecial": true,
    "requirements": [
      "Minimum 8 characters",
      "At least one uppercase letter",
      "At least one lowercase letter",
      "At least one digit",
      "At least one special character"
    ]
  }
}
```

---

### GET /auth/me

Get current authenticated user information.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "user",
      "isActive": true
    }
  }
}
```

---

## User Endpoints

### GET /users/me

Get current user's profile.

**Headers:** `Authorization: Bearer <token>`

**Response (200):** User object

---

### PUT /users/me

Update current user's profile.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "firstName": "Jane",
  "lastName": "Smith"
}
```

---

### DELETE /users/me

Deactivate own account.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "success": true,
  "message": "Your account has been deactivated successfully"
}
```

---

### GET /users

List all users (admin/moderator only).

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| limit | Number | Max results (default: 50) |
| offset | Number | Skip N results (default: 0) |
| role | String | Filter by role |
| isActive | Boolean | Filter by active status |
| search | String | Search by name/email |

**Response (200):**
```json
{
  "success": true,
  "data": {
    "users": ["..."],
    "pagination": {
      "total": 100,
      "limit": 50,
      "offset": 0,
      "hasMore": true
    }
  }
}
```

---

### GET /users/stats

Get user statistics (admin/moderator).

**Response (200):**
```json
{
  "success": true,
  "data": {
    "totalUsers": 100,
    "activeUsers": 95,
    "inactiveUsers": 5,
    "verifiedUsers": 90,
    "lockedUsers": 2,
    "byRole": {
      "admin": 2,
      "user": 95,
      "moderator": 3
    }
  }
}
```

---

### GET /users/:userId

Get a specific user's profile.

**Headers:** `Authorization: Bearer <token>`

**Response (200):** User object

---

### PUT /users/:userId

Update a specific user (admin only).

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "firstName": "Updated",
  "lastName": "Name",
  "isActive": true
}
```

---

### DELETE /users/:userId

Delete a user permanently (admin only).

**Headers:** `Authorization: Bearer <token>`

---

## Admin Endpoints

### GET /admin/roles

List all roles.

**Headers:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "success": true,
  "data": {
    "roles": [
      {
        "id": "role-admin",
        "name": "admin",
        "description": "System administrator",
        "permissions": ["*"],
        "isSystem": true
      }
    ]
  }
}
```

---

### GET /admin/roles/:roleId

Get a role with effective permissions.

---

### POST /admin/roles

Create a new role.

**Request Body:**
```json
{
  "name": "editor",
  "description": "Content editor",
  "permissions": ["user:read", "user:update"]
}
```

---

### PUT /admin/roles/:roleId

Update a role.

---

### DELETE /admin/roles/:roleId

Delete a role (non-system only).

---

### POST /admin/roles/:roleId/permissions

Grant a permission to a role.

**Request Body:**
```json
{
  "permission": "user:list"
}
```

---

### DELETE /admin/roles/:roleId/permissions/:permissionKey

Revoke a permission from a role.

---

### POST /admin/users/:userId/role

Assign a role to a user.

**Request Body:**
```json
{
  "role": "moderator"
}
```

---

### GET /admin/permissions

List all permissions.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "permissions": ["..."],
    "grouped": {
      "user": ["user:read", "user:update", "..."],
      "role": ["role:read", "role:create", "..."]
    }
  }
}
```

---

### POST /admin/permissions

Create a new permission.

**Request Body:**
```json
{
  "key": "custom:action",
  "description": "Custom permission"
}
```

---

### DELETE /admin/permissions/:permissionId

Delete a permission (non-system only).

---

### GET /admin/audit-logs

Get audit logs with filtering.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| limit | Number | Max results (default: 50) |
| offset | Number | Skip N results |
| userId | String | Filter by user |
| action | String | Filter by action |
| resource | String | Filter by resource |
| severity | String | Filter by severity (info/warning/error/critical) |
| startDate | ISO Date | Filter from date |
| endDate | ISO Date | Filter to date |

**Response (200):**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "uuid",
        "timestamp": "2024-01-01T00:00:00.000Z",
        "userId": "user-uuid",
        "action": "USER_LOGIN",
        "resource": "auth",
        "success": true,
        "ip": "127.0.0.1",
        "severity": "info"
      }
    ],
    "pagination": {
      "total": 1000,
      "limit": 50,
      "offset": 0,
      "hasMore": true
    }
  }
}
```

---

### GET /admin/audit-logs/stats

Get audit log statistics.

---

### POST /admin/audit-logs/verify

Verify audit log integrity (hash chain).

**Response (200):**
```json
{
  "success": true,
  "data": {
    "isValid": true,
    "totalEntries": 1000,
    "tamperedEntries": [],
    "tamperedCount": 0
  }
}
```

---

### GET /admin/stats

Get comprehensive system statistics.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "users": { "total": 100 },
    "roles": { "total": 4, "list": ["admin", "user", "moderator", "guest"] },
    "permissions": { "total": 23 },
    "rbac": { "..." },
    "audit": { "..." },
    "security": { "blacklistedTokens": { "totalEntries": 50 } },
    "system": {
      "uptime": 3600,
      "memory": { "rss": 45.2, "heapUsed": 32.1 }
    }
  }
}
```

---

### POST /admin/users/:userId/deactivate

Deactivate a user account.

---

### POST /admin/users/:userId/activate

Activate a user account.

---

## Health Endpoints

### GET /health

Health check endpoint.

**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 3600,
  "version": "1.0.0"
}
```

---

### GET /ready

Readiness check (verifies data storage).

**Response (200):**
```json
{
  "status": "ready",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

---

## Error Response Format

All errors follow a consistent format:

```json
{
  "success": false,
  "error": "Error Title",
  "message": "Human-readable error description",
  "code": "ERROR_CODE",
  "errors": [
    {
      "field": "email",
      "value": "invalid",
      "message": "Invalid email format",
      "location": "body"
    }
  ]
}
```

## Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful GET, PUT, DELETE |
| 201 | Created | Successful POST (registration, creation) |
| 400 | Bad Request | Validation errors |
| 401 | Unauthorized | Missing or invalid token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Duplicate resource |
| 423 | Locked | Account locked |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Unexpected server error |
| 504 | Gateway Timeout | Request timeout |