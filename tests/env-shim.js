/**
 * Loaded by jest setupFiles in every worker process before any tests
 * are loaded. Ensures DATA_DIR points to the fixture seeded by
 * tests/setup.js (globalSetup) regardless of the worker's own pid.
 */

'use strict';

const os = require('os');
const path = require('path');

process.env.DATA_DIR = path.join(os.tmpdir(), 'auth-service-test-fixture');
