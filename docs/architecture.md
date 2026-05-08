# Architecture Documentation

## Overview

The Authentication & Authorization Microservice is a standalone Node.js application that provides secure identity management, token-based authentication, role-based access control (RBAC), and comprehensive audit logging. It is designed as a microservice that can be integrated into any application ecosystem.

## System Architecture

```
+----------------------------------------------------------+
|                    API Gateway / Client                    |
+----------------------------------------------------------+
                          |
                          v
+----------------------------------------------------------+
|          Auth Microservice (Node.js/Express)             |
|                                                          |
|  +------------+  +------------+  +--------------------+  |
|  |   Routes   |  | Middleware |  |    Controllers     |  |
|  |            |  |            |  |                    |  |
|  | /auth      |  | Auth       |  | Auth Controller    |  |
|  | /users     |  | Authorize  |  | User Controller    |  |
|  | /admin     |  | Rate Limit |  | Admin Controller   |  |
|  | /health    |  | Validate   |  |                    |  |
|  |            |  | Security   |  |                    |  |
|  +------+-----+  +-----+------+  +---------+----------+  |
|         |              |                  |              |
|         v              v                  v              |
|  +---------------------------------------------------+  |
|  |                      Services                      |  |
|  |  Token Service | RBAC Service | Password Service |  |
|  |  Audit Service                                    |  |
|  +---------------------------------------------------+  |
|         |              |                  |              |
|         v              v                  v              |
|  +---------------------------------------------------+  |
|  |                       Models                       |  |
|  |  User | Role | Permission | AuditLog               |  |
|  +---------------------------------------------------+  |
|         |              |                  |              |
|         v              v                  v              |
|  +---------------------------------------------------+  |
|  |              JSON File Storage                     |  |
|  |  users.json | roles.json | permissions.json        |  |
|  |  audit-logs.json | token-blacklist.json            |  |
|  +---------------------------------------------------+  |
+----------------------------------------------------------+
```

## Component Diagram

### Request Flow

```
Client Request
     |
     v
[Security Headers] --> [Rate Limiter] --> [CORS] --> [Body Parser]
     |
     v
[Authentication] --> [Authorization] --> [Input Validation]
     |
     v
[Controller] --> [Service] --> [Model] --> [File Storage]
     |
     v
[Audit Log] --> [Response]
```

## Directory Structure

```
src/
|-- server.js              # Application entry point
|-- config.js              # Centralized configuration
|
|-- routes/                # Route definitions
|   |-- auth.js            # Auth endpoints
|   |-- users.js           # User management endpoints
|   |-- admin.js           # Admin endpoints
|
|-- controllers/           # Request handlers
|   |-- authController.js  # Registration, login, tokens
|   |-- userController.js  # Profile management
|   |-- adminController.js # RBAC, audit, system
|
|-- middleware/            # Express middleware
|   |-- authenticate.js    # JWT verification
|   |-- authorize.js       # RBAC permission checking
|   |-- rateLimiter.js     # Rate limiting
|   |-- validation.js      # Input validation
|   |-- security.js        # Security headers
|
|-- services/              # Business logic
|   |-- tokenService.js    # Token lifecycle
|   |-- passwordService.js # Password management
|   |-- rbacService.js     # RBAC operations
|   |-- auditService.js    # Audit logging
|
|-- models/                # Data access layer
|   |-- User.js            # User CRUD
|   |-- Role.js            # Role CRUD
|   |-- Permission.js      # Permission CRUD
|   |-- AuditLog.js        # Audit log CRUD
|
|-- utils/                 # Utilities
|   |-- jwt.js             # JWT helpers
|   |-- hash.js            # Bcrypt utilities
|   |-- logger.js          # Winston logger
```

## Data Models

### User Model

```javascript
{
  id: UUID,
  email: String (unique, indexed),
  passwordHash: String (bcrypt),
  firstName: String,
  lastName: String,
  role: String (references Role.name),
  isActive: Boolean,
  isEmailVerified: Boolean,
  failedLoginAttempts: Number,
  lockedUntil: ISO Date,
  lastLoginAt: ISO Date,
  passwordChangedAt: ISO Date,
  passwordResetToken: String (SHA-256),
  passwordResetExpires: ISO Date,
  previousPasswords: Array<String>,
  refreshTokens: Array<{ jti, createdAt }>,
  createdAt: ISO Date,
  updatedAt: ISO Date,
  metadata: Object
}
```

### Role Model

```javascript
{
  id: UUID,
  name: String (unique, indexed),
  description: String,
  permissions: Array<String> (permission keys),
  isDefault: Boolean,
  isSystem: Boolean,
  createdAt: ISO Date,
  updatedAt: ISO Date
}
```

### Permission Model

```javascript
{
  id: UUID,
  key: String (format: "resource:action"),
  resource: String,
  action: String,
  description: String,
  isSystem: Boolean,
  createdAt: ISO Date,
  updatedAt: ISO Date
}
```

### Audit Log Model

```javascript
{
  id: UUID,
  timestamp: ISO Date,
  userId: String,
  action: String,
  resource: String,
  success: Boolean,
  ip: String,
  userAgent: String,
  severity: String (info|warning|error|critical),
  details: Object,
  previousHash: String (SHA-256),
  hash: String (SHA-256)  // Hash chain for tamper detection
}
```

## Security Architecture

### Authentication Flow

```
1. User Registration
   Client --> POST /auth/register --> Validate Input --> Hash Password
   --> Create User --> Return User (no password)

2. User Login
   Client --> POST /auth/login --> Find User --> Check Lockout
   --> Verify Password --> Generate Token Pair --> Return Tokens

3. Token Refresh (Rotation)
   Client --> POST /auth/refresh --> Verify Refresh Token
   --> Check Token Store --> Blacklist Old Token --> Generate New Pair
   --> Return New Tokens

4. Authenticated Request
   Client --> GET /users/me --> Extract Bearer Token
   --> Verify Token + Not Blacklisted --> Attach req.user --> Process Request

5. Logout
   Client --> POST /auth/logout --> Blacklist Token --> Remove from Store
   --> Return Success
```

### Account Lockout Mechanism

```
Failed Login Attempt
     |
     v
Increment Counter ----> Counter >= Max Attempts?
     |                         |
     v                         v
Return 401            Set lockedUntil = now + 30min
                              |
                              v
                        Return 423 (Locked)

Subsequent Login Attempts:
     |
     v
Check lockedUntil ----> Still Locked?
     |                         |
     v                         v
Reset Counter       Return lockoutRemaining
```

### Token Rotation Security

```
Initial Login: JTI-A
     |
     v
Refresh #1: JTI-A --> JTI-B (A blacklisted, B stored)
     |
     v
Refresh #2: JTI-B --> JTI-C (B blacklisted, C stored)
     |
     v
Replay Attack: JTI-B --> DETECTED (Token Reuse!)
     |
     v
Revoke ALL tokens for user --> Force re-authentication
```

### Role Hierarchy

```
admin (all permissions)
  |
  +-- moderator
  |     |
  |     +-- user
  |     |     |
  |     |     +-- guest
  |     |           |
  |     |           +-- user:read
  |     |
  |     +-- user:list, audit:read
  |
  +-- * (wildcard)
```

## Data Flow

### Write Flow

```
Controller --> Service --> Model --> In-Memory Cache --> JSON File
                                      |
                                      +--> Audit Log Entry
```

### Read Flow

```
Controller --> Service --> Model --> Check Cache --> Return Data
                                          |
                                      Cache Miss
                                          |
                                          v
                                      Read JSON File --> Update Cache
```

## Configuration Management

Configuration is centralized in `config.js` with support for environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PORT` | 3001 | Server port |
| `NODE_ENV` | development | Environment mode |
| `JWT_SECRET` | (dev secret) | JWT signing secret |
| `JWT_REFRESH_SECRET` | (dev secret) | Refresh token secret |
| `JWT_ACCESS_EXPIRY` | 15m | Access token TTL |
| `JWT_REFRESH_EXPIRY` | 7d | Refresh token TTL |
| `BCRYPT_SALT_ROUNDS` | 12 | Password hashing rounds |
| `RATE_LIMIT_AUTH_MAX` | 5 | Auth attempts per window |
| `LOCKOUT_MAX_ATTEMPTS` | 5 | Failed attempts before lockout |
| `LOCKOUT_DURATION_MS` | 30min | Lockout duration |
| `MAX_REFRESH_TOKENS` | 5 | Max stored refresh tokens |
| `DATA_DIR` | ~/.auth-service | Data storage directory |
| `LOG_LEVEL` | debug/info | Logging level |
| `CORS_ORIGIN` | localhost:3000 | Allowed origins |

## Error Handling Strategy

```
Validation Error --> 400 Bad Request
Authentication Error --> 401 Unauthorized
Authorization Error --> 403 Forbidden
Not Found --> 404 Not Found
Conflict --> 409 Conflict
Rate Limited --> 429 Too Many Requests
Account Locked --> 423 Locked
Server Error --> 500 Internal Server Error
```

## Performance Considerations

1. **In-Memory Caching**: Models use a 30-second cache to reduce file I/O
2. **Batch Audit Logging**: Audit logs are buffered and flushed every 5 seconds
3. **Blacklist Cleanup**: Expired blacklist entries are cleaned hourly
4. **Request Timeouts**: All requests have a 30-second timeout
5. **Rate Limiting**: Prevents abuse and DoS attacks

## Scalability Considerations

While the current implementation uses JSON file storage for simplicity, the architecture supports easy migration to:

- **MongoDB**: Replace model methods with Mongoose queries
- **PostgreSQL**: Replace with Sequelize/Prisma queries
- **Redis**: Add Redis for session/token storage and caching
- **Message Queue**: Add RabbitMQ/Kafka for audit log processing

## Monitoring Points

- Health check: `GET /health`
- Readiness check: `GET /ready`
- System stats: `GET /admin/stats`
- Audit log integrity: `POST /admin/audit-logs/verify`
- Token blacklist stats: Available via admin API