/**
 * Jest global setup — runs before any test file.
 * Seeds default RBAC data (permissions, roles, users) so tests can
 * exercise the system without depending on server.js startup.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

// Fixed (not pid-based) test data dir so all jest worker processes
// see the same seeded data. Setup process and worker processes have
// different pids, so a pid-based dir would cause workers to read an
// empty directory.
const testDataDir = path.join(os.tmpdir(), 'auth-service-test-fixture');

// Set env var for the setup process so the imported models below resolve
// the right path. Jest also exports globalSetup-set env vars to workers
// IF set before workers spawn, but to be safe we also use a setupFiles
// shim (env-shim.js) loaded by each worker.
process.env.DATA_DIR = testDataDir;

// Wipe any previous fixture so seeds run fresh.
if (fs.existsSync(testDataDir)) {
  fs.rmSync(testDataDir, { recursive: true, force: true });
}
fs.mkdirSync(testDataDir, { recursive: true });

module.exports = async () => {
  const Permission = require('../src/models/Permission');
  const Role = require('../src/models/Role');
  const User = require('../src/models/User');
  const AuditLog = require('../src/models/AuditLog');

  AuditLog.init();
  await Permission.seedDefaultPermissions();
  await Role.seedDefaultRoles();
  await User.seedDefaultUsers();
};
