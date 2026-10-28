const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { once } = require('node:events');
const { after, before, test } = require('node:test');
const { Server } = require('socket.io');
const { io: connectSocket } = require('socket.io-client');
const {
  createApplication,
  createPresence,
  installSocketAuthentication,
} = require('../app');

class MemoryStore {
  constructor() {
    this.devices = new Map();
    this.challenges = new Map();
    this.sessions = new Map();
    this.linkRequests = new Map();
    this.trusted = new Map();
    this.assistanceRequests = new Map();
    this.screenSessions = new Map();
    this.databaseAvailable = true;
  }

  async healthCheck() {
    if (!this.databaseAvailable) {
      throw new Error('Database unavailable');
    }
  }

  async registerDevice(device) {
    const existing = this.devices.get(device.deviceId);
    if (existing && existing.public_key !== device.publicKey) return null;
    if (!existing) this.devices.set(device.deviceId, device);
    return {
      device_id: device.deviceId,
      display_name: existing?.displayName || device.displayName,
    };
  }

  async getDevice(deviceId) {
    const device = this.devices.get(deviceId);
    return device
      ? { device_id: deviceId, public_key: device.publicKey, display_name: device.displayName }
      : null;
  }

  async createChallenge(challenge) {
    if (!this.devices.has(challenge.deviceId)) return false;
    this.challenges.set(challenge.challengeId, challenge);
    return true;
  }

  async consumeChallenge(challengeId, deviceId) {
    const challenge = this.challenges.get(challengeId);
    if (
      !challenge || challenge.deviceId !== deviceId
      || challenge.expiresAt <= new Date() || challenge.consumed
    ) return null;
    challenge.consumed = true;
    const device = this.devices.get(deviceId);
    return { nonce: challenge.nonce, publicKey: device.publicKey };
  }

  async createSession(session) {
    this.sessions.set(session.tokenHash, session);
  }

  async getSessionByHash(tokenHash) {
    const session = this.sessions.get(tokenHash);
    const device = session && session.expiresAt > new Date()
      ? this.devices.get(session.deviceId)
      : null;
    return device
      ? {
        device_id: session.deviceId,
        display_name: device.displayName,
        expires_at: session.expiresAt,
      }
      : null;
  }

  async createLinkRequest(request) {
    if (!this.devices.has(request.receiverId) || this.hasTrust(request.receiverId, request.helperId)) {
      return null;
    }
    const duplicate = [...this.linkRequests.values()].find((item) =>
      item.helperId === request.helperId
      && item.receiverId === request.receiverId
      && item.status === 'pending'
      && item.expiresAt > new Date());
    if (duplicate) return { request_id: duplicate.requestId, status: 'pending', expires_at: duplicate.expiresAt, duplicate: true };
    const record = {
      requestId: request.requestId,
      helperId: request.helperId,
      receiverId: request.receiverId,
      status: 'pending',
      expiresAt: request.expiresAt,
    };
    this.linkRequests.set(record.requestId, record);
    return { request_id: record.requestId, status: record.status, expires_at: record.expiresAt, duplicate: false };
  }

  async respondLinkRequest({ requestId, receiverId, accepted }) {
    const request = this.linkRequests.get(requestId);
    if (
      !request || request.receiverId !== receiverId || request.status !== 'pending'
      || request.expiresAt <= new Date()
    ) return null;
    request.status = accepted ? 'accepted' : 'rejected';
    if (accepted) this.trusted.set(this.trustKey(receiverId, request.helperId), { autoAccept: false });
    return {
      requestId,
      helperId: request.helperId,
      receiverId,
      status: request.status,
    };
  }

  async listPendingLinkRequests(receiverId) {
    return [...this.linkRequests.values()]
      .filter((request) =>
        request.receiverId === receiverId
        && request.status === 'pending'
        && request.expiresAt > new Date())
      .map((request) => ({
        request_id: request.requestId,
        helper_id: request.helperId,
        helper_name: this.devices.get(request.helperId).displayName,
        expires_at: request.expiresAt,
      }));
  }

  async listTrustedDevicesForHelper(helperId) {
    return [...this.trusted.entries()]
      .filter(([key]) => key.endsWith(`:${helperId}`))
      .map(([key]) => {
        const ownerId = key.slice(0, key.lastIndexOf(':'));
        const owner = this.devices.get(ownerId);
        return { device_id: ownerId, display_name: owner.displayName };
      });
  }

  async listTrustedHelpers(ownerId) {
    return [...this.trusted.entries()]
      .filter(([key]) => key.startsWith(`${ownerId}:`))
      .map(([key, trust]) => {
        const helperId = key.slice(ownerId.length + 1);
        const helper = this.devices.get(helperId);
        return {
          device_id: helperId,
          display_name: helper.displayName,
          auto_accept: trust.autoAccept,
        };
      });
  }

  async listHelpersForReceiver(receiverId) {
    return (await this.listTrustedHelpers(receiverId)).map((helper) => helper.device_id);
  }

  async listReceiversForHelper(helperId) {
    return [...this.trusted.entries()]
      .filter(([key]) => key.endsWith(`:${helperId}`))
      .map(([key]) => key.slice(0, key.lastIndexOf(':')));
  }

  async setAutoAccept({ ownerId, helperId, autoAccept }) {
    const trust = this.trusted.get(this.trustKey(ownerId, helperId));
    if (!trust) return false;
    trust.autoAccept = autoAccept;
    return true;
  }

  async revokeHelper({ ownerId, helperId }) {
    const deleted = this.trusted.delete(this.trustKey(ownerId, helperId));
    for (const request of this.assistanceRequests.values()) {
      if (
        request.receiver_id === ownerId && request.helper_id === helperId
        && ['pending', 'accepted'].includes(request.status)
      ) request.status = 'revoked';
    }
    const endedSessions = [];
    for (const session of this.screenSessions.values()) {
      if (session.receiver_id === ownerId && session.helper_id === helperId
        && ['pending', 'accepted', 'active'].includes(session.status)) {
        session.status = 'ended';
        session.ended_reason = 'trust_revoked';
        endedSessions.push(session);
      }
    }
    return { revoked: deleted, endedSessions };
  }

  async createAssistanceRequest(request) {
    const trust = this.trusted.get(this.trustKey(request.receiverId, request.helperId));
    if (!trust) return null;
    const record = {
      request_id: request.requestId,
      helper_id: request.helperId,
      receiver_id: request.receiverId,
      status: trust.autoAccept ? 'accepted' : 'pending',
      expires_at: request.expiresAt,
    };
    this.assistanceRequests.set(record.request_id, record);
    return record;
  }

  async listPendingAssistanceRequests(receiverId) {
    return [...this.assistanceRequests.values()]
      .filter((request) =>
        request.receiver_id === receiverId
        && request.status === 'pending'
        && request.expires_at > new Date())
      .map((request) => ({
        ...request,
        helper_name: this.devices.get(request.helper_id).displayName,
      }));
  }

  async respondAssistanceRequest({ requestId, receiverId, accepted }) {
    const request = this.assistanceRequests.get(requestId);
    if (
      !request || request.receiver_id !== receiverId || request.status !== 'pending'
      || request.expires_at <= new Date()
      || !this.hasTrust(receiverId, request.helper_id)
    ) return null;
    request.status = accepted ? 'accepted' : 'rejected';
    return request;
  }

  async createScreenSession({ sessionId, assistanceRequestId, expiresAt }) {
    const request = this.assistanceRequests.get(assistanceRequestId);
    if (!request || request.status !== 'accepted'
      || !this.hasTrust(request.receiver_id, request.helper_id)) return null;
    const session = {
      session_id: sessionId,
      assistance_request_id: assistanceRequestId,
      helper_id: request.helper_id,
      receiver_id: request.receiver_id,
      status: 'pending',
      expires_at: expiresAt,
    };
    this.screenSessions.set(sessionId, session);
    return session;
  }

  async respondScreenSession({ sessionId, receiverId, accepted }) {
    const session = this.screenSessions.get(sessionId);
    const assistance = session && this.assistanceRequests.get(session.assistance_request_id);
    if (!session || session.receiver_id !== receiverId || session.status !== 'pending'
      || session.expires_at <= new Date() || assistance?.status !== 'accepted'
      || !this.hasTrust(session.receiver_id, session.helper_id)) return null;
    session.status = accepted ? 'accepted' : 'rejected';
    if (!accepted) session.ended_reason = 'rejected';
    return session;
  }

  async activateScreenSession({ sessionId, receiverId }) {
    const session = this.screenSessions.get(sessionId);
    const assistance = session && this.assistanceRequests.get(session.assistance_request_id);
    if (!session || session.receiver_id !== receiverId || session.status !== 'accepted'
      || session.expires_at <= new Date() || assistance?.status !== 'accepted'
      || !this.hasTrust(session.receiver_id, session.helper_id)) return null;
    session.status = 'active';
    return session;
  }

  async endScreenSession({ sessionId, deviceId, reason = 'ended' }) {
    const session = this.screenSessions.get(sessionId);
    if (!session || ![session.helper_id, session.receiver_id].includes(deviceId)
      || !['pending', 'accepted', 'active'].includes(session.status)) return null;
    session.status = 'ended';
    session.ended_reason = reason;
    return session;
  }

  async getActiveScreenSession(sessionId) {
    const session = this.screenSessions.get(sessionId);
    const assistance = session && this.assistanceRequests.get(session.assistance_request_id);
    return session && session.status === 'active' && session.expires_at > new Date()
      && assistance?.status === 'accepted'
      && this.hasTrust(session.receiver_id, session.helper_id) ? session : null;
  }

  async getScreenSessionForParticipant(sessionId, deviceId) {
    const session = this.screenSessions.get(sessionId);
    const assistance = session && this.assistanceRequests.get(session.assistance_request_id);
    return session && [session.helper_id, session.receiver_id].includes(deviceId)
      && ['accepted', 'active'].includes(session.status)
      && session.expires_at > new Date() && assistance?.status === 'accepted'
      && this.hasTrust(session.receiver_id, session.helper_id) ? session : null;
  }

  async endScreenSessionsForDevice(deviceId) {
    const ended = [];
    for (const session of this.screenSessions.values()) {
      if ([session.helper_id, session.receiver_id].includes(deviceId)
        && ['pending', 'accepted', 'active'].includes(session.status)) {
        session.status = 'ended';
        session.ended_reason = 'disconnected';
        ended.push(session);
      }
    }
    return ended;
  }

  trustKey(ownerId, helperId) {
    return `${ownerId}:${helperId}`;
  }

  hasTrust(ownerId, helperId) {
    return this.trusted.has(this.trustKey(ownerId, helperId));
  }
}

let store;
let httpServer;
let socketServer;
let baseUrl;
const clients = new Set();

before(async () => {
  store = new MemoryStore();
  httpServer = http.createServer();
  socketServer = new Server(httpServer, { cors: { origin: false } });
  const presence = createPresence(socketServer, store);
  installSocketAuthentication(socketServer, store, presence);
  httpServer.on('request', createApplication({ store, io: socketServer, presence }));
  httpServer.listen(0, '127.0.0.1');
  await once(httpServer, 'listening');
  baseUrl = `http://127.0.0.1:${httpServer.address().port}`;
});

after(async () => {
  for (const client of clients) client.disconnect();
  socketServer.disconnectSockets(true);
  await new Promise((resolve) => socketServer.close(resolve));
});

async function post(path, body, token) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function registerDevice(displayName) {
  const pair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const { response, body } = await post('/api/v1/devices', {
    publicKey: pair.publicKey.toString('base64'),
    displayName,
  });
  assert.equal(response.status, 201);
  return { deviceId: body.device_id, privateKey: pair.privateKey, displayName };
}

async function authenticate(device) {
  const challengeResult = await post('/api/v1/auth/challenges', { deviceId: device.deviceId });
  assert.equal(challengeResult.response.status, 201);
  const nonce = Buffer.from(challengeResult.body.nonce, 'base64url');
  const signature = crypto.sign('sha256', nonce, device.privateKey).toString('base64');
  const sessionResult = await post('/api/v1/auth/sessions', {
    deviceId: device.deviceId,
    challengeId: challengeResult.body.challengeId,
    signature,
  });
  assert.equal(sessionResult.response.status, 201);
  return sessionResult.body.accessToken;
}

function connect(token) {
  const socket = connectSocket(baseUrl, {
    auth: token ? { token } : {},
    autoConnect: false,
    reconnection: false,
    transports: ['websocket'],
    timeout: 2000,
  });
  clients.add(socket);
  return socket;
}

test('health reports server and database availability separately', async () => {
  const live = await fetch(`${baseUrl}/health/live`);
  assert.equal(live.status, 200);
  assert.deepEqual(await live.json(), { status: 'online' });

  const ready = await fetch(`${baseUrl}/health`);
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), { status: 'online', database: 'connected' });

  store.databaseAvailable = false;
  const unavailable = await fetch(`${baseUrl}/health`);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { status: 'online', database: 'unavailable' });
  store.databaseAvailable = true;
});

function waitForConnection(socket) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('connect', onConnect);
      socket.off('connect_error', onError);
    };
    const onConnect = () => {
      cleanup();
      resolve();
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Socket connection timed out'));
    }, 5000);
    socket.once('connect', onConnect);
    socket.once('connect_error', onError);
  });
}

test('device challenge is signed and cannot be reused', async () => {
  const device = await registerDevice('Receptor de pruebas');
  const challengeResult = await post('/api/v1/auth/challenges', { deviceId: device.deviceId });
  const signature = crypto.sign(
    'sha256',
    Buffer.from(challengeResult.body.nonce, 'base64url'),
    device.privateKey
  ).toString('base64');
  const proof = {
    deviceId: device.deviceId,
    challengeId: challengeResult.body.challengeId,
    signature,
  };
  assert.equal((await post('/api/v1/auth/sessions', proof)).response.status, 201);
  const replay = await post('/api/v1/auth/sessions', proof);
  assert.equal(replay.response.status, 401);
  assert.equal(replay.body.error.code, 'challenge_expired');
});

test('device linking requires receiver approval and support requires the trust', async () => {
  const receiver = await registerDevice('Teléfono receptor');
  const helper = await registerDevice('Teléfono de ayuda');
  const receiverToken = await authenticate(receiver);
  const helperToken = await authenticate(helper);

  const unauthorizedList = await fetch(`${baseUrl}/api/v1/trusted-devices`);
  assert.equal(unauthorizedList.status, 401);

  const linkRequest = await post('/api/v1/link-requests', {
    receiverDeviceId: receiver.deviceId,
  }, helperToken);
  assert.equal(linkRequest.response.status, 201);
  assert.equal(linkRequest.body.status, 'pending');

  const untrustedAssist = await post('/api/v1/assistance-requests', {
    receiverDeviceId: receiver.deviceId,
  }, helperToken);
  assert.equal(untrustedAssist.response.status, 403);

  const incoming = await fetch(`${baseUrl}/api/v1/link-requests/incoming`, {
    headers: { Authorization: `Bearer ${receiverToken}` },
  });
  assert.equal(incoming.status, 200);
  assert.equal((await incoming.json()).length, 1);

  const approval = await post(
    `/api/v1/link-requests/${linkRequest.body.requestId}/respond`,
    { accepted: true },
    receiverToken
  );
  assert.equal(approval.response.status, 200);
  assert.equal(approval.body.status, 'accepted');

  const trusted = await fetch(`${baseUrl}/api/v1/trusted-devices`, {
    headers: { Authorization: `Bearer ${helperToken}` },
  });
  assert.equal((await trusted.json())[0].device_id, receiver.deviceId);

  const linkedHelpers = await fetch(`${baseUrl}/api/v1/linked-helpers`, {
    headers: { Authorization: `Bearer ${receiverToken}` },
  });
  const linkedHelperList = await linkedHelpers.json();
  assert.equal(linkedHelpers.status, 200);
  assert.equal(linkedHelperList[0].device_id, helper.deviceId);
  assert.equal(linkedHelperList[0].auto_accept, false);

  const assist = await post('/api/v1/assistance-requests', {
    receiverDeviceId: receiver.deviceId,
  }, helperToken);
  assert.equal(assist.response.status, 201);
  assert.equal(assist.body.status, 'pending');

  const incomingAssistance = await fetch(`${baseUrl}/api/v1/assistance-requests/incoming`, {
    headers: { Authorization: `Bearer ${receiverToken}` },
  });
  const incomingAssistanceList = await incomingAssistance.json();
  assert.equal(incomingAssistance.status, 200);
  assert.equal(incomingAssistanceList[0].helper_id, helper.deviceId);
  assert.equal(incomingAssistanceList[0].helper_name, helper.displayName);

  const accepted = await post(
    `/api/v1/assistance-requests/${assist.body.requestId}/respond`,
    { accepted: true },
    receiverToken
  );
  assert.equal(accepted.response.status, 200);
  assert.equal(accepted.body.status, 'accepted');

  const automatic = await fetch(`${baseUrl}/api/v1/linked-helpers/${helper.deviceId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${receiverToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ autoAccept: true }),
  });
  assert.equal(automatic.status, 200);

  const autoAccepted = await post('/api/v1/assistance-requests', {
    receiverDeviceId: receiver.deviceId,
  }, helperToken);
  assert.equal(autoAccepted.body.status, 'accepted');

  const revoked = await fetch(`${baseUrl}/api/v1/linked-helpers/${helper.deviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${receiverToken}` },
  });
  assert.equal(revoked.status, 204);
  const afterRevocation = await post('/api/v1/assistance-requests', {
    receiverDeviceId: receiver.deviceId,
  }, helperToken);
  assert.equal(afterRevocation.response.status, 403);
});

test('screen sessions require trusted accepted assistance and isolate active signaling', async () => {
  const owner = await registerDevice('Pantalla propietaria');
  const helper = await registerDevice('Ayudante de pantalla');
  const outsider = await registerDevice('Dispositivo ajeno');
  const ownerToken = await authenticate(owner);
  const helperToken = await authenticate(helper);
  const outsiderToken = await authenticate(outsider);

  const untrustedAttempt = await post('/api/v1/screen-sessions', {
    assistanceRequestId: crypto.randomUUID(),
  }, helperToken);
  assert.equal(untrustedAttempt.response.status, 403);

  store.trusted.set(store.trustKey(owner.deviceId, helper.deviceId), { autoAccept: false });
  const assistance = await post('/api/v1/assistance-requests', {
    receiverDeviceId: owner.deviceId,
  }, helperToken);
  assert.equal(assistance.body.status, 'pending');
  const assistanceApproval = await post(
    `/api/v1/assistance-requests/${assistance.body.requestId}/respond`,
    { accepted: true },
    ownerToken
  );
  assert.equal(assistanceApproval.body.status, 'accepted');
  store.trusted.delete(store.trustKey(owner.deviceId, helper.deviceId));
  const noLongerTrusted = await post('/api/v1/screen-sessions', {
    assistanceRequestId: assistance.body.requestId,
  }, helperToken);
  assert.equal(noLongerTrusted.response.status, 403);
  store.trusted.set(store.trustKey(owner.deviceId, helper.deviceId), { autoAccept: false });

  const ownerSocket = connect(ownerToken);
  const helperSocket = connect(helperToken);
  const outsiderSocket = connect(outsiderToken);
  const ownerConnected = waitForConnection(ownerSocket);
  const helperConnected = waitForConnection(helperSocket);
  const outsiderConnected = waitForConnection(outsiderSocket);
  ownerSocket.connect();
  helperSocket.connect();
  outsiderSocket.connect();
  await Promise.all([ownerConnected, helperConnected, outsiderConnected]);

  const sessionRequestEvent = once(ownerSocket, 'screen:session_request');
  const created = await post('/api/v1/screen-sessions', {
    assistanceRequestId: assistance.body.requestId,
  }, helperToken);
  assert.equal(created.response.status, 201);
  assert.deepEqual(Object.keys(created.body).sort(), ['helperId', 'receiverId', 'sessionId', 'status']);
  assert.equal(created.body.helperId, helper.deviceId);
  assert.equal(created.body.receiverId, owner.deviceId);
  assert.equal(created.body.status, 'pending');
  const [sessionRequest] = await sessionRequestEvent;
  assert.equal(sessionRequest.sessionId, created.body.sessionId);
  assert.equal(sessionRequest.helperId, helper.deviceId);
  assert.equal(sessionRequest.helperName, helper.displayName);

  const previousTurnConfig = {
    url: process.env.TURN_URL,
    username: process.env.TURN_USERNAME,
    credential: process.env.TURN_CREDENTIAL,
  };
  process.env.TURN_URL = 'turn:turn.example.test:3478';
  process.env.TURN_USERNAME = 'pending-user';
  process.env.TURN_CREDENTIAL = 'pending-secret';
  try {
    const pendingIce = await fetch(
      `${baseUrl}/api/v1/screen-sessions/${created.body.sessionId}/ice-servers`,
      { headers: { Authorization: `Bearer ${helperToken}` } }
    );
    assert.equal(pendingIce.status, 404);
    assert.doesNotMatch(await pendingIce.text(), /pending-secret|turn\.example\.test/);
  } finally {
    if (previousTurnConfig.url === undefined) delete process.env.TURN_URL;
    else process.env.TURN_URL = previousTurnConfig.url;
    if (previousTurnConfig.username === undefined) delete process.env.TURN_USERNAME;
    else process.env.TURN_USERNAME = previousTurnConfig.username;
    if (previousTurnConfig.credential === undefined) delete process.env.TURN_CREDENTIAL;
    else process.env.TURN_CREDENTIAL = previousTurnConfig.credential;
  }

  const attackerApproval = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/respond`,
    { accepted: true },
    outsiderToken
  );
  assert.equal(attackerApproval.response.status, 404);
  const prematureActivation = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/activate`,
    {},
    ownerToken
  );
  assert.equal(prematureActivation.response.status, 404);

  const acceptedUpdate = once(helperSocket, 'screen:session_update');
  const accepted = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/respond`,
    { accepted: true },
    ownerToken
  );
  assert.equal(accepted.body.status, 'accepted');
  assert.equal((await acceptedUpdate)[0].status, 'accepted');
  const attackerActivation = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/activate`,
    {},
    outsiderToken
  );
  assert.equal(attackerActivation.response.status, 404);
  const outsiderEnd = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/end`,
    {},
    outsiderToken
  );
  assert.equal(outsiderEnd.response.status, 404);
  const activeUpdate = once(helperSocket, 'screen:session_update');
  const activated = await post(
    `/api/v1/screen-sessions/${created.body.sessionId}/activate`,
    {},
    ownerToken
  );
  assert.equal(activated.body.status, 'active');
  assert.equal((await activeUpdate)[0].status, 'active');

  const unauthorizedIce = await fetch(
    `${baseUrl}/api/v1/screen-sessions/${created.body.sessionId}/ice-servers`,
    { headers: { Authorization: `Bearer ${outsiderToken}` } }
  );
  assert.equal(unauthorizedIce.status, 404);
  const ice = await fetch(
    `${baseUrl}/api/v1/screen-sessions/${created.body.sessionId}/ice-servers`,
    { headers: { Authorization: `Bearer ${helperToken}` } }
  );
  assert.equal(ice.status, 200);
  assert.deepEqual((await ice.json()).iceServers[0], { urls: ['stun:stun.l.google.com:19302'] });

  let outsiderSignalCount = 0;
  outsiderSocket.on('screen:signal', () => { outsiderSignalCount += 1; });
  const incomingOffer = once(ownerSocket, 'screen:signal');
  const offerAck = new Promise((resolve) => helperSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'offer',
    sdp: 'v=0\\r\\n',
  }, resolve));
  assert.deepEqual(await offerAck, { ok: true });
  assert.deepEqual((await incomingOffer)[0], {
    sessionId: created.body.sessionId,
    type: 'offer',
    sdp: 'v=0\\r\\n',
  });
  const incomingAnswer = once(helperSocket, 'screen:signal');
  const answerAck = new Promise((resolve) => ownerSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'answer',
    sdp: 'v=0\\r\\n',
  }, resolve));
  assert.deepEqual(await answerAck, { ok: true });
  assert.equal((await incomingAnswer)[0].type, 'answer');
  const incomingCandidate = once(ownerSocket, 'screen:signal');
  const candidateAck = new Promise((resolve) => helperSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'ice-candidate',
    candidate: { candidate: 'candidate:1', sdpMid: '0', sdpMLineIndex: 0 },
  }, resolve));
  assert.deepEqual(await candidateAck, { ok: true });
  assert.equal((await incomingCandidate)[0].type, 'ice-candidate');

  const unauthorizedOffer = await new Promise((resolve) => ownerSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'offer',
    sdp: 'v=0\\r\\n',
  }, resolve));
  assert.equal(unauthorizedOffer.ok, false);
  const unauthorizedDeviceSignal = await new Promise((resolve) => outsiderSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'ice-candidate',
    candidate: { candidate: 'candidate:1', sdpMid: '0', sdpMLineIndex: 0 },
  }, resolve));
  assert.equal(unauthorizedDeviceSignal.ok, false);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(outsiderSignalCount, 0);

  const endedAtOwner = once(ownerSocket, 'screen:session_update');
  const endedAtHelper = once(helperSocket, 'screen:session_update');
  const revoke = await fetch(`${baseUrl}/api/v1/linked-helpers/${helper.deviceId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  assert.equal(revoke.status, 204);
  assert.equal((await endedAtOwner)[0].status, 'ended');
  assert.equal((await endedAtHelper)[0].reason, 'trust_revoked');
  const afterRevocation = await new Promise((resolve) => helperSocket.emit('screen:signal', {
    sessionId: created.body.sessionId,
    type: 'ice-candidate',
    candidate: { candidate: 'candidate:2', sdpMid: '0', sdpMLineIndex: 0 },
  }, resolve));
  assert.equal(afterRevocation.ok, false);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(outsiderSignalCount, 0);
});

test('Socket.IO rejects anonymous devices and reports authenticated presence', async () => {
  const receiver = await registerDevice('Antena conectada');
  const receiverToken = await authenticate(receiver);
  const helper = await registerDevice('Ayudante conectado');
  const helperToken = await authenticate(helper);
  store.trusted.set(store.trustKey(receiver.deviceId, helper.deviceId), { autoAccept: false });

  const anonymousSocket = connect(null);
  const rejected = once(anonymousSocket, 'connect_error');
  anonymousSocket.connect();
  await rejected;
  assert.equal(anonymousSocket.connected, false);

  const receiverSocket = connect(receiverToken);
  const receiverConnected = waitForConnection(receiverSocket);
  receiverSocket.connect();
  await receiverConnected;
  const helperOnlineEvent = once(receiverSocket, 'device_status');

  const helperSocket = connect(helperToken);
  const statusEvent = once(helperSocket, 'device_status');
  const helperConnected = waitForConnection(helperSocket);
  helperSocket.connect();
  await helperConnected;
  const [helperOnline] = await helperOnlineEvent;
  assert.deepEqual(helperOnline, { deviceId: helper.deviceId, online: true });
  const [status] = await statusEvent;
  assert.deepEqual(status, { deviceId: receiver.deviceId, online: true });

  const receiverOfflineEvent = once(helperSocket, 'device_status');
  receiverSocket.disconnect();
  const [offlineStatus] = await receiverOfflineEvent;
  assert.deepEqual(offlineStatus, { deviceId: receiver.deviceId, online: false });

  const receiverOnlineAgain = once(helperSocket, 'device_status');
  const receiverReconnected = waitForConnection(receiverSocket);
  receiverSocket.connect();
  await receiverReconnected;
  const [receiverOnline] = await receiverOnlineAgain;
  assert.deepEqual(receiverOnline, { deviceId: receiver.deviceId, online: true });

  const helperOfflineEvent = once(receiverSocket, 'device_status');
  helperSocket.disconnect();
  const [helperOffline] = await helperOfflineEvent;
  assert.deepEqual(helperOffline, { deviceId: helper.deviceId, online: false });

  const helperOnlineAgain = once(receiverSocket, 'device_status');
  const helperReconnected = waitForConnection(helperSocket);
  helperSocket.connect();
  await helperReconnected;
  const [helperOnlineAtReconnect] = await helperOnlineAgain;
  assert.deepEqual(helperOnlineAtReconnect, { deviceId: helper.deviceId, online: true });
});
