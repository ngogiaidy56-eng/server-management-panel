'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const {
  createApp,
  makePasswordHash,
  passwordMatches,
  allowlist,
  trustedOrigin,
  normalizeService,
  wouldLockOutSelf
} = require('../server');

const TEST_ORIGIN = 'https://admin.example.test';
const TEST_SECRET = 'a-test-session-secret-long-enough-for-testing';

function makePool(user) {
  let session = null;
  return {
    async query(sql, params = []) {
      if (sql.startsWith('SELECT 1')) return { rows: [{ ok: 1 }] };

      if (sql.includes('FROM users WHERE email=$1')) {
        return { rows: user && user.email === params[0] ? [user] : [] };
      }

      if (sql.startsWith('INSERT INTO sessions')) {
        session = {
          token_hash: params[0],
          user_id: params[1],
          csrf_token: params[2]
        };
        return { rows: [], rowCount: 1 };
      }

      if (sql.includes('FROM sessions s JOIN users u')) {
        if (session && user && user.active && session.token_hash === params[0]) {
          return {
            rows: [{
              csrf_token: session.csrf_token,
              id: user.id,
              email: user.email,
              role: user.role,
              active: user.active,
              created_at: user.created_at
            }]
          };
        }
        return { rows: [] };
      }

      if (sql.startsWith('DELETE FROM sessions')) {
        if (session && (session.token_hash === params[0] || session.user_id === params[0])) session = null;
        return { rows: [], rowCount: 1 };
      }

      if (sql.startsWith('INSERT INTO audit_logs')) return { rows: [], rowCount: 1 };
      return { rows: [] };
    }
  };
}

async function withServer(pool, run) {
  const app = createApp(pool, {
    NODE_ENV: 'test',
    APP_ORIGIN: TEST_ORIGIN,
    SESSION_SECRET: TEST_SECRET,
    RENDER_API_KEY: '',
    RENDER_ALLOWED_SERVICE_IDS: ''
  });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const base = 'http://127.0.0.1:' + address.port;
  try {
    await run(base);
  } finally {
    await new Promise(resolve => {
      server.close(resolve);
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    });
  }
}

function originRequest(origin, fetchSite) {
  const values = { origin, 'sec-fetch-site': fetchSite, host: 'admin.example.test', 'x-forwarded-proto': 'https' };
  return { get: key => values[key.toLowerCase()] };
}

test('scrypt password verification accepts only matching credentials', async () => {
  const password = 'long-test-password-2026';
  const encoded = await makePasswordHash(password);
  assert.equal(await passwordMatches(password, encoded), true);
  assert.equal(await passwordMatches('wrong-password', encoded), false);
  assert.equal(await passwordMatches(password, 'not-a-password-hash'), false);
  await assert.rejects(makePasswordHash('too-short'), /14 to 256 characters/);
});

test('Render allowlist parses exact service IDs only', () => {
  const set = allowlist({ RENDER_ALLOWED_SERVICE_IDS: 'srv-one, srv-two, ' });
  assert.equal(set.has('srv-one'), true);
  assert.equal(set.has('srv-two'), true);
  assert.equal(set.has('srv-three'), false);
  assert.equal(allowlist({}).size, 0);
});

test('service normalization does not expose arbitrary provider fields', () => {
  const result = normalizeService({
    service: {
      id: 'srv-123',
      name: 'api',
      type: 'web_service',
      region: 'oregon',
      status: 'live',
      secret: 'must-not-leak'
    }
  });
  assert.deepEqual(result, {
    id: 'srv-123',
    name: 'api',
    type: 'web_service',
    status: 'live',
    region: 'oregon',
    url: null,
    updatedAt: null
  });
  assert.equal(Object.hasOwn(result, 'secret'), false);
});

test('state-changing requests require a trusted same-origin context', () => {
  assert.equal(trustedOrigin(originRequest('https://attacker.example', 'cross-site'), { APP_ORIGIN: TEST_ORIGIN }), false);
  assert.equal(trustedOrigin(originRequest(undefined, undefined), { APP_ORIGIN: TEST_ORIGIN }), false);
  assert.equal(trustedOrigin(originRequest(undefined, 'same-origin'), { APP_ORIGIN: TEST_ORIGIN }), true);
  assert.equal(trustedOrigin(originRequest(TEST_ORIGIN, 'same-origin'), { APP_ORIGIN: TEST_ORIGIN }), true);
});

test('administrator cannot demote or disable their own account', () => {
  assert.equal(wouldLockOutSelf('user-1', 'user-1', { role: 'operator' }), true);
  assert.equal(wouldLockOutSelf('user-1', 'user-1', { active: false }), true);
  assert.equal(wouldLockOutSelf('user-1', 'user-1', { password: 'new-password' }), false);
  assert.equal(wouldLockOutSelf('user-1', 'user-2', { role: 'viewer' }), false);
  assert.equal(wouldLockOutSelf('user-1', 'user-1', { role: 'admin', active: true }), false);
});

test('health and metadata endpoints return safe operational headers', async () => {
  await withServer(makePool(null), async base => {
    const metadata = await fetch(base + '/api/v1/meta');
    assert.equal(metadata.status, 200);
    assert.ok(metadata.headers.get('x-request-id'));
    assert.equal(metadata.headers.get('x-powered-by'), null);
    assert.equal(metadata.headers.get('cache-control'), 'no-store');
    assert.ok(metadata.headers.get('content-security-policy'));

    const health = await fetch(base + '/healthz');
    assert.equal(health.status, 200);
    assert.equal((await health.json()).ok, true);
  });
});

test('protected Admin API rejects an unauthenticated caller', async () => {
  await withServer(makePool(null), async base => {
    const response = await fetch(base + '/api/v1/users');
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error.code, 'AUTH_REQUIRED');
  });
});

test('mutations require JSON and block untrusted origins', async () => {
  await withServer(makePool(null), async base => {
    const contentTypeMissing = await fetch(base + '/api/v1/auth/login', { method: 'POST' });
    assert.equal(contentTypeMissing.status, 415);
    assert.equal((await contentTypeMissing.json()).error.code, 'JSON_REQUIRED');

    const foreignOrigin = await fetch(base + '/api/v1/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://attacker.example' },
      body: JSON.stringify({ email: 'admin@example.test', password: 'wrong-password' })
    });
    assert.equal(foreignOrigin.status, 403);
    assert.equal((await foreignOrigin.json()).error.code, 'UNTRUSTED_ORIGIN');
  });
});

test('viewer can authenticate but cannot enter the Admin user API', async () => {
  const password = 'viewer-test-password-2026';
  const user = {
    id: 'user-viewer',
    email: 'viewer@example.test',
    password_hash: await makePasswordHash(password),
    role: 'viewer',
    active: true,
    created_at: new Date().toISOString()
  };

  await withServer(makePool(user), async base => {
    const login = await fetch(base + '/api/v1/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: TEST_ORIGIN },
      body: JSON.stringify({ email: user.email, password })
    });
    assert.equal(login.status, 200);
    const payload = await login.json();
    assert.equal(payload.user.role, 'viewer');
    assert.ok(payload.csrfToken);
    assert.match(login.headers.get('set-cookie'), /HttpOnly/);
    assert.match(login.headers.get('set-cookie'), /SameSite=Strict/);

    const cookie = login.headers.get('set-cookie').split(';')[0];
    const adminOnly = await fetch(base + '/api/v1/users', { headers: { cookie } });
    assert.equal(adminOnly.status, 403);
    assert.equal((await adminOnly.json()).error.code, 'FORBIDDEN');

    const logoutWithoutCsrf = await fetch(base + '/api/v1/auth/logout', {
      method: 'POST',
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json', cookie },
      body: '{}'
    });
    assert.equal(logoutWithoutCsrf.status, 403);
    assert.equal((await logoutWithoutCsrf.json()).error.code, 'CSRF_INVALID');
  });
});
