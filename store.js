const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

class PostgresStore {
  constructor(pool) {
    this.pool = pool;
  }

  static async connect(connectionString) {
    if (!connectionString) {
      throw new Error('DATABASE_URL must be configured');
    }

    const pool = new Pool({ connectionString, max: 10 });
    const store = new PostgresStore(pool);
    const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
    const screenSessionsMigration = fs.readFileSync(
      path.join(__dirname, 'db', 'migrations', '001_screen_sessions.sql'),
      'utf8'
    );
    try {
      await pool.query(schema);
      await pool.query(screenSessionsMigration);
    } catch (error) {
      await pool.end();
      throw error;
    }
    return store;
  }

  async close() {
    await this.pool.end();
  }

  async healthCheck() {
    await this.pool.query('SELECT 1');
  }

  async registerDevice({ deviceId, publicKey, displayName }) {
    const result = await this.pool.query(
      `INSERT INTO antena_devices (device_id, public_key, display_name)
       VALUES ($1, $2, $3)
       ON CONFLICT (device_id) DO NOTHING
       RETURNING device_id, display_name`,
      [deviceId, publicKey, displayName]
    );
    if (result.rowCount) {
      return result.rows[0];
    }
    const existing = await this.getDevice(deviceId);
    if (!existing || existing.public_key !== publicKey) {
      return null;
    }
    return { device_id: existing.device_id, display_name: existing.display_name };
  }

  async getDevice(deviceId) {
    const result = await this.pool.query(
      'SELECT device_id, public_key, display_name FROM antena_devices WHERE device_id = $1',
      [deviceId]
    );
    return result.rows[0] || null;
  }

  async createChallenge({ challengeId, deviceId, nonce, expiresAt }) {
    const result = await this.pool.query(
      `INSERT INTO antena_auth_challenges (challenge_id, device_id, nonce, expires_at)
       SELECT $1, device_id, $3, $4
       FROM antena_devices
       WHERE device_id = $2
       RETURNING challenge_id`,
      [challengeId, deviceId, nonce, expiresAt]
    );
    return result.rowCount === 1;
  }

  async consumeChallenge(challengeId, deviceId) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `UPDATE antena_auth_challenges
         SET consumed_at = NOW()
         WHERE challenge_id = $1 AND device_id = $2
           AND consumed_at IS NULL AND expires_at > NOW()
         RETURNING nonce`,
        [challengeId, deviceId]
      );
      if (result.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }

      const deviceResult = await client.query(
        'SELECT public_key FROM antena_devices WHERE device_id = $1',
        [deviceId]
      );
      await client.query('COMMIT');
      if (deviceResult.rowCount !== 1) {
        return null;
      }
      return { nonce: result.rows[0].nonce, publicKey: deviceResult.rows[0].public_key };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async createSession({ tokenHash, deviceId, expiresAt }) {
    await this.pool.query(
      `INSERT INTO antena_access_sessions (token_hash, device_id, expires_at)
       VALUES ($1, $2, $3)`,
      [tokenHash, deviceId, expiresAt]
    );
  }

  async getSessionByHash(tokenHash) {
    const result = await this.pool.query(
      `SELECT s.device_id, d.display_name, s.expires_at
       FROM antena_access_sessions s
       JOIN antena_devices d ON d.device_id = s.device_id
       WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
      [tokenHash]
    );
    return result.rows[0] || null;
  }

  async createLinkRequest({ requestId, helperId, receiverId, expiresAt }) {
    await this.pool.query(
      `UPDATE antena_link_requests
       SET status = 'expired'
       WHERE helper_id = $1 AND receiver_id = $2
         AND status = 'pending' AND expires_at <= NOW()`,
      [helperId, receiverId]
    );
    const existing = await this.pool.query(
      `SELECT request_id, status, expires_at
       FROM antena_link_requests
       WHERE helper_id = $1 AND receiver_id = $2 AND status = 'pending'
         AND expires_at > NOW()
       LIMIT 1`,
      [helperId, receiverId]
    );
    if (existing.rowCount) {
      return { ...existing.rows[0], duplicate: true };
    }

    const result = await this.pool.query(
      `INSERT INTO antena_link_requests (request_id, helper_id, receiver_id, status, expires_at)
       SELECT $1, helper.device_id, receiver.device_id, 'pending', $4
       FROM antena_devices helper, antena_devices receiver
       WHERE helper.device_id = $2 AND receiver.device_id = $3
         AND NOT EXISTS (
           SELECT 1 FROM antena_trusted_devices
           WHERE owner_id = $3 AND helper_id = $2
         )
       RETURNING request_id, status, expires_at`,
      [requestId, helperId, receiverId, expiresAt]
    );
    if (result.rowCount !== 1) {
      return null;
    }
    return { ...result.rows[0], duplicate: false };
  }

  async respondLinkRequest({ requestId, receiverId, accepted }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const request = await client.query(
        `SELECT helper_id
         FROM antena_link_requests
         WHERE request_id = $1 AND receiver_id = $2
           AND status = 'pending' AND expires_at > NOW()
         FOR UPDATE`,
        [requestId, receiverId]
      );
      if (request.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }

      const helperId = request.rows[0].helper_id;
      const status = accepted ? 'accepted' : 'rejected';
      await client.query(
        'UPDATE antena_link_requests SET status = $2 WHERE request_id = $1',
        [requestId, status]
      );
      if (accepted) {
        await client.query(
          `INSERT INTO antena_trusted_devices (owner_id, helper_id)
           VALUES ($1, $2)
           ON CONFLICT (owner_id, helper_id) DO NOTHING`,
          [receiverId, helperId]
        );
      }
      await client.query('COMMIT');
      return { requestId, helperId, receiverId, status };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async listPendingLinkRequests(receiverId) {
    const result = await this.pool.query(
      `SELECT r.request_id, r.helper_id, d.display_name AS helper_name, r.created_at, r.expires_at
       FROM antena_link_requests r
       JOIN antena_devices d ON d.device_id = r.helper_id
       WHERE r.receiver_id = $1 AND r.status = 'pending' AND r.expires_at > NOW()
       ORDER BY r.created_at`,
      [receiverId]
    );
    return result.rows;
  }

  async listTrustedDevicesForHelper(helperId) {
    const result = await this.pool.query(
      `SELECT d.device_id, d.display_name, d.created_at
       FROM antena_trusted_devices t
       JOIN antena_devices d ON d.device_id = t.owner_id
       WHERE t.helper_id = $1
       ORDER BY d.display_name`,
      [helperId]
    );
    return result.rows;
  }

  async listTrustedHelpers(ownerId) {
    const result = await this.pool.query(
      `SELECT d.device_id, d.display_name, t.auto_accept, t.created_at
       FROM antena_trusted_devices t
       JOIN antena_devices d ON d.device_id = t.helper_id
       WHERE t.owner_id = $1
       ORDER BY d.display_name`,
      [ownerId]
    );
    return result.rows;
  }

  async listHelpersForReceiver(receiverId) {
    const result = await this.pool.query(
      'SELECT helper_id FROM antena_trusted_devices WHERE owner_id = $1',
      [receiverId]
    );
    return result.rows.map((row) => row.helper_id);
  }

  async listReceiversForHelper(helperId) {
    const result = await this.pool.query(
      'SELECT owner_id FROM antena_trusted_devices WHERE helper_id = $1',
      [helperId]
    );
    return result.rows.map((row) => row.owner_id);
  }

  async setAutoAccept({ ownerId, helperId, autoAccept }) {
    const result = await this.pool.query(
      `UPDATE antena_trusted_devices
       SET auto_accept = $3
       WHERE owner_id = $1 AND helper_id = $2
       RETURNING owner_id`,
      [ownerId, helperId, autoAccept]
    );
    return result.rowCount === 1;
  }

  async revokeHelper({ ownerId, helperId }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `DELETE FROM antena_trusted_devices
         WHERE owner_id = $1 AND helper_id = $2
         RETURNING owner_id`,
        [ownerId, helperId]
      );
      if (result.rowCount !== 1) {
        await client.query('ROLLBACK');
        return { revoked: false, endedSessions: [] };
      }
      await client.query(
        `UPDATE antena_assistance_requests
         SET status = 'revoked'
         WHERE receiver_id = $1 AND helper_id = $2
           AND status IN ('pending', 'accepted')`,
        [ownerId, helperId]
      );
      const ended = await client.query(
        `UPDATE antena_screen_sessions
         SET status = 'ended', ended_reason = 'trust_revoked'
         WHERE receiver_id = $1 AND helper_id = $2
           AND status IN ('pending', 'accepted', 'active')
         RETURNING session_id, helper_id, receiver_id, status, ended_reason`,
        [ownerId, helperId]
      );
      await client.query('COMMIT');
      return { revoked: true, endedSessions: ended.rows };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async createAssistanceRequest({ requestId, helperId, receiverId, expiresAt }) {
    const result = await this.pool.query(
      `INSERT INTO antena_assistance_requests (request_id, helper_id, receiver_id, status, expires_at)
       SELECT $1, t.helper_id, t.owner_id,
         CASE WHEN t.auto_accept THEN 'accepted' ELSE 'pending' END, $4
       FROM antena_trusted_devices t
       WHERE t.helper_id = $2 AND t.owner_id = $3
       RETURNING request_id, helper_id, receiver_id, status, expires_at`,
      [requestId, helperId, receiverId, expiresAt]
    );
    return result.rows[0] || null;
  }

  async listPendingAssistanceRequests(receiverId) {
    const result = await this.pool.query(
      `SELECT r.request_id, r.helper_id, d.display_name AS helper_name, r.created_at, r.expires_at
       FROM antena_assistance_requests r
       JOIN antena_devices d ON d.device_id = r.helper_id
       WHERE r.receiver_id = $1 AND r.status = 'pending' AND r.expires_at > NOW()
       ORDER BY r.created_at`,
      [receiverId]
    );
    return result.rows;
  }

  async respondAssistanceRequest({ requestId, receiverId, accepted }) {
    const status = accepted ? 'accepted' : 'rejected';
    const result = await this.pool.query(
      `UPDATE antena_assistance_requests r
       SET status = $3
       WHERE r.request_id = $1 AND r.receiver_id = $2
         AND r.status = 'pending' AND r.expires_at > NOW()
         AND EXISTS (
           SELECT 1 FROM antena_trusted_devices t
           WHERE t.owner_id = r.receiver_id AND t.helper_id = r.helper_id
         )
       RETURNING r.request_id, r.helper_id, r.receiver_id, r.status`,
      [requestId, receiverId, status]
    );
    return result.rows[0] || null;
  }

  async createScreenSession({ sessionId, assistanceRequestId, expiresAt }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const participantResult = await client.query(
        `SELECT helper_id, receiver_id
         FROM antena_assistance_requests
         WHERE request_id = $1 AND status = 'accepted'`,
        [assistanceRequestId]
      );
      if (participantResult.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const participant = participantResult.rows[0];
      const trust = await client.query(
        `SELECT owner_id FROM antena_trusted_devices
         WHERE owner_id = $1 AND helper_id = $2 FOR UPDATE`,
        [participant.receiver_id, participant.helper_id]
      );
      if (trust.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const accepted = await client.query(
        `SELECT request_id FROM antena_assistance_requests
         WHERE request_id = $1 AND helper_id = $2 AND receiver_id = $3 AND status = 'accepted'`,
        [assistanceRequestId, participant.helper_id, participant.receiver_id]
      );
      if (accepted.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const result = await client.query(
        `INSERT INTO antena_screen_sessions (
           session_id, assistance_request_id, helper_id, receiver_id, status, expires_at
         ) VALUES ($1, $2, $3, $4, 'pending', $5)
         RETURNING session_id, helper_id, receiver_id, status, expires_at`,
        [sessionId, assistanceRequestId, participant.helper_id, participant.receiver_id, expiresAt]
      );
      await client.query('COMMIT');
      return result.rows[0] || null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async respondScreenSession({ sessionId, receiverId, accepted }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const participant = await client.query(
        `SELECT helper_id FROM antena_screen_sessions
         WHERE session_id = $1 AND receiver_id = $2 AND status = 'pending'`,
        [sessionId, receiverId]
      );
      if (participant.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const trust = await client.query(
        `SELECT owner_id FROM antena_trusted_devices
         WHERE owner_id = $1 AND helper_id = $2 FOR UPDATE`,
        [receiverId, participant.rows[0].helper_id]
      );
      const current = trust.rowCount === 1 ? await client.query(
        `SELECT s.session_id
         FROM antena_screen_sessions s
         JOIN antena_assistance_requests a ON a.request_id = s.assistance_request_id
         WHERE s.session_id = $1 AND s.receiver_id = $2 AND s.status = 'pending'
           AND s.expires_at > NOW() AND a.status = 'accepted'
         FOR UPDATE OF s`,
        [sessionId, receiverId]
      ) : { rowCount: 0 };
      if (current.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const result = await client.query(
        `UPDATE antena_screen_sessions
         SET status = CASE WHEN $2 THEN 'accepted' ELSE 'rejected' END,
             ended_reason = CASE WHEN $2 THEN NULL ELSE 'rejected' END
         WHERE session_id = $1
         RETURNING session_id, helper_id, receiver_id, status`,
        [sessionId, accepted]
      );
      await client.query('COMMIT');
      return result.rows[0] || null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async activateScreenSession({ sessionId, receiverId }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const participant = await client.query(
        `SELECT helper_id FROM antena_screen_sessions
         WHERE session_id = $1 AND receiver_id = $2 AND status = 'accepted'`,
        [sessionId, receiverId]
      );
      if (participant.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const trust = await client.query(
        `SELECT owner_id FROM antena_trusted_devices
         WHERE owner_id = $1 AND helper_id = $2 FOR UPDATE`,
        [receiverId, participant.rows[0].helper_id]
      );
      const current = trust.rowCount === 1 ? await client.query(
        `SELECT s.session_id
         FROM antena_screen_sessions s
         JOIN antena_assistance_requests a ON a.request_id = s.assistance_request_id
         WHERE s.session_id = $1 AND s.receiver_id = $2 AND s.status = 'accepted'
           AND s.expires_at > NOW() AND a.status = 'accepted'
         FOR UPDATE OF s`,
        [sessionId, receiverId]
      ) : { rowCount: 0 };
      if (current.rowCount !== 1) {
        await client.query('ROLLBACK');
        return null;
      }
      const result = await client.query(
        `UPDATE antena_screen_sessions SET status = 'active'
         WHERE session_id = $1
         RETURNING session_id, helper_id, receiver_id, status`,
        [sessionId]
      );
      await client.query('COMMIT');
      return result.rows[0] || null;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async endScreenSession({ sessionId, deviceId, reason = 'ended' }) {
    const result = await this.pool.query(
      `UPDATE antena_screen_sessions
       SET status = 'ended', ended_reason = $3
       WHERE session_id = $1 AND $2 IN (helper_id, receiver_id)
         AND status IN ('pending', 'accepted', 'active')
       RETURNING session_id, helper_id, receiver_id, status, ended_reason`,
      [sessionId, deviceId, reason]
    );
    return result.rows[0] || null;
  }

  async getScreenSessionForParticipant(sessionId, deviceId) {
    const result = await this.pool.query(
      `SELECT s.session_id, s.helper_id, s.receiver_id, s.status
       FROM antena_screen_sessions s
       JOIN antena_assistance_requests a ON a.request_id = s.assistance_request_id
       JOIN antena_trusted_devices t
         ON t.owner_id = s.receiver_id AND t.helper_id = s.helper_id
       WHERE s.session_id = $1 AND $2 IN (s.helper_id, s.receiver_id)
         AND s.status IN ('accepted', 'active') AND s.expires_at > NOW()
         AND a.status = 'accepted'
         AND a.helper_id = s.helper_id AND a.receiver_id = s.receiver_id`,
      [sessionId, deviceId]
    );
    return result.rows[0] || null;
  }

  async getActiveScreenSession(sessionId) {
    const result = await this.pool.query(
      `SELECT s.session_id, s.helper_id, s.receiver_id, s.status
       FROM antena_screen_sessions s
       JOIN antena_assistance_requests a ON a.request_id = s.assistance_request_id
       JOIN antena_trusted_devices t
         ON t.owner_id = s.receiver_id AND t.helper_id = s.helper_id
       WHERE s.session_id = $1 AND s.status = 'active' AND s.expires_at > NOW()
         AND a.status = 'accepted'
         AND a.helper_id = s.helper_id AND a.receiver_id = s.receiver_id`,
      [sessionId]
    );
    return result.rows[0] || null;
  }

  async endScreenSessionsForDevice(deviceId) {
    const result = await this.pool.query(
      `UPDATE antena_screen_sessions
       SET status = 'ended', ended_reason = 'disconnected'
       WHERE $1 IN (helper_id, receiver_id)
         AND status IN ('pending', 'accepted', 'active')
       RETURNING session_id, helper_id, receiver_id, status, ended_reason`,
      [deviceId]
    );
    return result.rows;
  }

  async pruneExpired() {
    await this.pool.query('DELETE FROM antena_auth_challenges WHERE expires_at <= NOW() OR consumed_at IS NOT NULL');
    await this.pool.query('DELETE FROM antena_access_sessions WHERE expires_at <= NOW()');
    await this.pool.query(
      `UPDATE antena_link_requests SET status = 'expired'
       WHERE status = 'pending' AND expires_at <= NOW()`
    );
    await this.pool.query(
      `UPDATE antena_assistance_requests SET status = 'expired'
       WHERE status = 'pending' AND expires_at <= NOW()`
    );
    const ended = await this.pool.query(
      `UPDATE antena_screen_sessions
       SET status = 'expired', ended_reason = 'expired'
       WHERE status IN ('pending', 'accepted', 'active') AND expires_at <= NOW()
       RETURNING session_id, helper_id, receiver_id, status, ended_reason`
    );
    return ended.rows;
  }
}

module.exports = { PostgresStore };
