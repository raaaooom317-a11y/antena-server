const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { PostgresStore } = require('../store');

const migrationPath = path.join(__dirname, '..', 'db', 'migrations', '001_screen_sessions.sql');

function createPool(responses) {
  const calls = [];
  let responseIndex = 0;
  const client = {
    async query(sql, values = []) {
      calls.push({ sql, values });
      return responses[responseIndex++] || { rowCount: 0, rows: [] };
    },
    release() {
      calls.push({ sql: 'RELEASE', values: [] });
    },
  };
  return {
    calls,
    client,
    async connect() {
      return client;
    },
    async query(sql, values = []) {
      return client.query(sql, values);
    },
  };
}

test('screen session migration is additive and idempotent', () => {
  const migration = fs.readFileSync(migrationPath, 'utf8');

  assert.match(migration, /CREATE TABLE IF NOT EXISTS antena_screen_sessions/i);
  assert.match(migration, /CREATE INDEX IF NOT EXISTS antena_screen_sessions_by_helper/i);
  assert.match(migration, /CREATE INDEX IF NOT EXISTS antena_screen_sessions_by_receiver/i);
  assert.match(migration, /REFERENCES antena_assistance_requests\(request_id\)/i);
  assert.match(migration, /REFERENCES antena_devices\(device_id\)/i);
  assert.doesNotMatch(migration, /\b(DROP|TRUNCATE|DELETE FROM)\b/i);
});

test('PostgresStore creates a screen session only after locking and validating accepted assistance and trust', async () => {
  const expectedSession = {
    session_id: 'a140fc5e-2b47-4e16-a4cc-b15e6a824b62',
    helper_id: 'helper-device',
    receiver_id: 'owner-device',
    status: 'pending',
    expires_at: new Date('2026-10-28T20:00:00.000Z'),
  };
  const pool = createPool([
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ helper_id: 'helper-device', receiver_id: 'owner-device' }] },
    { rowCount: 1, rows: [{ owner_id: 'owner-device' }] },
    { rowCount: 1, rows: [{ request_id: 'accepted-assistance' }] },
    { rowCount: 1, rows: [expectedSession] },
    { rowCount: 0, rows: [] },
  ]);
  const store = new PostgresStore(pool);

  const session = await store.createScreenSession({
    sessionId: expectedSession.session_id,
    assistanceRequestId: 'accepted-assistance',
    expiresAt: expectedSession.expires_at,
  });

  assert.deepEqual(session, expectedSession);
  assert.deepEqual(pool.calls.map(({ sql }) => sql.trim().split(/\s+/)[0]), [
    'BEGIN', 'SELECT', 'SELECT', 'SELECT', 'INSERT', 'COMMIT', 'RELEASE',
  ]);
  assert.match(pool.calls[1].sql, /status = 'accepted'/);
  assert.match(pool.calls[2].sql, /FOR UPDATE/);
  assert.match(pool.calls[3].sql, /status = 'accepted'/);
  assert.match(pool.calls[4].sql, /'pending'/);
  assert.deepEqual(pool.calls[4].values, [
    expectedSession.session_id,
    'accepted-assistance',
    'helper-device',
    'owner-device',
    expectedSession.expires_at,
  ]);
});

test('PostgresStore rolls back screen session creation when the trust relation is absent', async () => {
  const pool = createPool([
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ helper_id: 'helper-device', receiver_id: 'owner-device' }] },
    { rowCount: 0, rows: [] },
    { rowCount: 0, rows: [] },
  ]);
  const store = new PostgresStore(pool);

  const session = await store.createScreenSession({
    sessionId: 'a140fc5e-2b47-4e16-a4cc-b15e6a824b62',
    assistanceRequestId: 'accepted-assistance',
    expiresAt: new Date('2026-10-28T20:00:00.000Z'),
  });

  assert.equal(session, null);
  assert.ok(pool.calls.some(({ sql }) => sql.trim() === 'ROLLBACK'));
  assert.equal(pool.calls.some(({ sql }) => /^\s*INSERT INTO antena_screen_sessions/i.test(sql)), false);
  assert.equal(pool.calls.at(-1).sql, 'RELEASE');
});

test('PostgresStore gates ICE and signaling lookups on participant, trust, assistance status, and active state', async () => {
  const expected = {
    session_id: 'a140fc5e-2b47-4e16-a4cc-b15e6a824b62',
    helper_id: 'helper-device',
    receiver_id: 'owner-device',
    status: 'active',
  };
  const pool = createPool([
    { rowCount: 1, rows: [expected] },
    { rowCount: 1, rows: [expected] },
  ]);
  const store = new PostgresStore(pool);

  assert.deepEqual(
    await store.getScreenSessionForParticipant(expected.session_id, expected.helper_id),
    expected
  );
  assert.deepEqual(await store.getActiveScreenSession(expected.session_id), expected);
  assert.match(pool.calls[0].sql, /s\.status IN \('accepted', 'active'\)/);
  assert.match(pool.calls[0].sql, /JOIN antena_trusted_devices/);
  assert.match(pool.calls[0].sql, /a\.status = 'accepted'/);
  assert.match(pool.calls[1].sql, /s\.status = 'active'/);
});

test('PostgresStore revocation atomically removes trust and ends assistance and screen sessions', async () => {
  const endedSession = {
    session_id: 'a140fc5e-2b47-4e16-a4cc-b15e6a824b62',
    helper_id: 'helper-device',
    receiver_id: 'owner-device',
    status: 'ended',
    ended_reason: 'trust_revoked',
  };
  const pool = createPool([
    { rowCount: 0, rows: [] },
    { rowCount: 1, rows: [{ owner_id: 'owner-device' }] },
    { rowCount: 1, rows: [] },
    { rowCount: 1, rows: [endedSession] },
    { rowCount: 0, rows: [] },
  ]);
  const store = new PostgresStore(pool);

  const result = await store.revokeHelper({
    ownerId: 'owner-device',
    helperId: 'helper-device',
  });

  assert.deepEqual(result, { revoked: true, endedSessions: [endedSession] });
  assert.deepEqual(pool.calls.map(({ sql }) => sql.trim().split(/\s+/)[0]), [
    'BEGIN', 'DELETE', 'UPDATE', 'UPDATE', 'COMMIT', 'RELEASE',
  ]);
  assert.match(pool.calls[3].sql, /status IN \('pending', 'accepted', 'active'\)/);
  assert.match(pool.calls[3].sql, /ended_reason = 'trust_revoked'/);
});
