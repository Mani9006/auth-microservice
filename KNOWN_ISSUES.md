# Known Issues

The RBAC permission check tests currently have failures in the role hierarchy
and wildcard matching paths. The core authentication flow (JWT issue, validate,
refresh) is solid; the permission engine has cases where role inheritance and
wildcard expansion don't match expected behavior.

To be addressed:
- Permission checking with role hierarchy
- Wildcard permission expansion (`resource:*` matching)
- `hasAllPermissions` and `hasAnyPermission` aggregation logic

Tracking in follow-up commits.
