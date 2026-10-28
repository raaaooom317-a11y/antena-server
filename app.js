const crypto = require('node:crypto');
const express = require('express');

const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ACCESS_TOKEN_TTL_MS = 30 * 60 * 1000;
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const REQUEST_TTL_MS = 3 * 60 * 1000;
const LINK_REQUEST_TTL_MS = 10 * 60 * 1000;

function sendError(response, status, code, message) {
  response.status(status).json({ error: { code, message } });
}

function isText(value, maxLength) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maxLength;
}

function publicKeyFromBase64(value) {
  if (typeof value !== 'string' || value.length > 4096 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return null;
  }
  try {
    const der = Buffer.from(value, 'base64');
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength < 2048) {
      return null;
    }
    return key.export({ type: 'spki', format: 'pem' });
  } catch {
    return null;
  }
}

function createRateLimiter({ limit, windowMs }) {
  const entries = new Map();
  return (request, response, next) => {
    const now = Date.now();
    const key = request.device?.device_id
      || request.ip
      || request.socket.remoteAddress
      || 'unknown';
    const current = entries.get(key);
    if (!current || current.resetAt <= now) {
      entries.set(key, { count: 1, resetAt: now + windowMs });
      if (entries.size > 10000) {
        for (const [entryKey, value] of entries) {
          if (value.resetAt <= now) entries.delete(entryKey);
        }
      }
      return next();
    }
    current.count += 1;
    if (current.count > limit) {
      response.setHeader('Retry-After', Math.max(1, Math.ceil((current.resetAt - now) / 1000)));
      return sendError(response, 429, 'rate_limited', 'Demasiadas solicitudes. Inténtalo más tarde.');
    }
    return next();
  };
}

function createApplication({ store, io, presence }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb', strict: true }));
  app.use((request, response, next) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/', (request, response) => {
    response.status(200).send('Servidor seguro de Antena Remote AI');
  });

  app.get('/health/live', (request, response) => {
    response.status(200).json({ status: 'online' });
  });

  app.get('/health', async (request, response) => {
    try {
      await store.healthCheck();
      response.status(200).json({ status: 'online', database: 'connected' });
    } catch {
      response.status(503).json({ status: 'online', database: 'unavailable' });
    }
  });

  const publicRateLimit = createRateLimiter({ limit: 30, windowMs: 60 * 1000 });
  const actionRateLimit = createRateLimiter({ limit: 20, windowMs: 60 * 1000 });

  app.post('/api/v1/devices', publicRateLimit, async (request, response, next) => {
    try {
      const publicKey = publicKeyFromBase64(request.body?.publicKey);
      const displayName = typeof request.body?.displayName === 'string'
        ? request.body.displayName.trim().slice(0, 60)
        : '';
      if (!publicKey || !isText(displayName, 60)) {
        return sendError(response, 400, 'invalid_device', 'La clave o el nombre del dispositivo no son válidos.');
      }

      const der = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
      const deviceId = crypto.createHash('sha256').update(der).digest('base64url');
      const device = await store.registerDevice({ deviceId, publicKey, displayName });
      if (!device) {
        return sendError(response, 409, 'device_conflict', 'No se pudo registrar esta identidad de dispositivo.');
      }
      return response.status(201).json(device);
    } catch (error) {
      return next(error);
    }
  });

  app.post('/api/v1/auth/challenges', publicRateLimit, async (request, response, next) => {
    try {
      const { deviceId } = request.body || {};
      if (typeof deviceId !== 'string' || !DEVICE_ID_PATTERN.test(deviceId)) {
        return sendError(response, 400, 'invalid_device_id', 'El identificador del dispositivo no es válido.');
      }
      const challengeId = crypto.randomUUID();
      const nonce = crypto.randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
      if (!(await store.createChallenge({ challengeId, deviceId, nonce, expiresAt }))) {
        return sendError(response, 404, 'device_not_found', 'No se encontró el dispositivo.');
      }
      return response.status(201).json({ challengeId, nonce, expiresAt: expiresAt.toISOString() });
    } catch (error) {
      return next(error);
    }
  });

  app.post('/api/v1/auth/sessions', publicRateLimit, async (request, response, next) => {
    try {
      const { deviceId, challengeId, signature } = request.body || {};
      if (
        typeof deviceId !== 'string' || !DEVICE_ID_PATTERN.test(deviceId)
        || typeof challengeId !== 'string' || !UUID_PATTERN.test(challengeId)
        || typeof signature !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature)
      ) {
        return sendError(response, 400, 'invalid_proof', 'La prueba de identidad no tiene un formato válido.');
      }

      const challenge = await store.consumeChallenge(challengeId, deviceId);
      if (!challenge) {
        return sendError(response, 401, 'challenge_expired', 'El reto expiró o ya fue utilizado. Inténtalo de nuevo.');
      }
      const verified = crypto.verify(
        'sha256',
        Buffer.from(challenge.nonce, 'base64url'),
        challenge.publicKey,
        Buffer.from(signature, 'base64')
      );
      if (!verified) {
        return sendError(response, 401, 'invalid_proof', 'No se pudo verificar la identidad del dispositivo.');
      }

      const token = crypto.randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + ACCESS_TOKEN_TTL_MS);
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      await store.createSession({ tokenHash, deviceId, expiresAt });
      return response.status(201).json({ accessToken: token, expiresAt: expiresAt.toISOString() });
    } catch (error) {
      return next(error);
    }
  });

  app.use('/api/v1', async (request, response, next) => {
    try {
      const authorization = request.get('authorization') || '';
      const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization);
      if (!match) {
        return sendError(response, 401, 'unauthorized', 'Vuelve a autenticar el dispositivo.');
      }
      const tokenHash = crypto.createHash('sha256').update(match[1]).digest('hex');
      const device = await store.getSessionByHash(tokenHash);
      if (!device) {
        return sendError(response, 401, 'unauthorized', 'La sesión expiró. Vuelve a autenticar el dispositivo.');
      }
      request.device = device;
      return next();
    } catch (error) {
      return next(error);
    }
  });

  app.get('/api/v1/trusted-devices', async (request, response, next) => {
    try {
      const devices = await store.listTrustedDevicesForHelper(request.device.device_id);
      response.json(devices.map((device) => ({
        ...device,
        online: presence.isOnline(device.device_id),
      })));
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/v1/link-requests', actionRateLimit, async (request, response, next) => {
    try {
      const { receiverDeviceId } = request.body || {};
      if (typeof receiverDeviceId !== 'string' || !DEVICE_ID_PATTERN.test(receiverDeviceId)) {
        return sendError(response, 400, 'invalid_device_id', 'Escribe un identificador de dispositivo válido.');
      }
      if (receiverDeviceId === request.device.device_id) {
        return sendError(response, 400, 'same_device', 'No puedes vincular un dispositivo consigo mismo.');
      }
      const result = await store.createLinkRequest({
        requestId: crypto.randomUUID(),
        helperId: request.device.device_id,
        receiverId: receiverDeviceId,
        expiresAt: new Date(Date.now() + LINK_REQUEST_TTL_MS),
      });
      if (!result) {
        return sendError(response, 404, 'device_unavailable', 'El identificador no existe o el dispositivo ya está vinculado.');
      }
      const helper = await store.getDevice(request.device.device_id);
      io.to(receiverDeviceId).emit('link_request', {
        requestId: result.request_id,
        helperId: request.device.device_id,
        helperName: helper.display_name,
        expiresAt: result.expires_at,
      });
      return response.status(result.duplicate ? 200 : 201).json({
        requestId: result.request_id,
        status: result.status,
        expiresAt: result.expires_at,
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get('/api/v1/link-requests/incoming', async (request, response, next) => {
    try {
      response.json(await store.listPendingLinkRequests(request.device.device_id));
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/v1/link-requests/:requestId/respond', async (request, response, next) => {
    try {
      const { requestId } = request.params;
      const { accepted } = request.body || {};
      if (!UUID_PATTERN.test(requestId) || typeof accepted !== 'boolean') {
        return sendError(response, 400, 'invalid_response', 'La respuesta a la solicitud no es válida.');
      }
      const result = await store.respondLinkRequest({
        requestId,
        receiverId: request.device.device_id,
        accepted,
      });
      if (!result) {
        return sendError(response, 404, 'request_not_found', 'La solicitud expiró o ya fue respondida.');
      }
      io.to(result.helperId).emit('link_response', {
        requestId,
        receiverId: result.receiverId,
        accepted,
      });
      return response.json({ requestId, status: result.status });
    } catch (error) {
      return next(error);
    }
  });

  app.get('/api/v1/linked-helpers', async (request, response, next) => {
    try {
      const helpers = await store.listTrustedHelpers(request.device.device_id);
      response.json(helpers.map((helper) => ({
        ...helper,
        online: presence.isOnline(helper.device_id),
      })));
    } catch (error) {
      next(error);
    }
  });

  app.patch('/api/v1/linked-helpers/:helperId', async (request, response, next) => {
    try {
      const { helperId } = request.params;
      const { autoAccept } = request.body || {};
      if (!DEVICE_ID_PATTERN.test(helperId) || typeof autoAccept !== 'boolean') {
        return sendError(response, 400, 'invalid_setting', 'La autorización permanente debe ser verdadera o falsa.');
      }
      const updated = await store.setAutoAccept({
        ownerId: request.device.device_id,
        helperId,
        autoAccept,
      });
      if (!updated) {
        return sendError(response, 404, 'device_not_linked', 'Ese dispositivo no está autorizado.');
      }
      return response.json({ helperId, autoAccept });
    } catch (error) {
      return next(error);
    }
  });

  app.delete('/api/v1/linked-helpers/:helperId', async (request, response, next) => {
    try {
      const { helperId } = request.params;
      if (!DEVICE_ID_PATTERN.test(helperId)) {
        return sendError(response, 400, 'invalid_device_id', 'El identificador no es válido.');
      }
      const revoked = await store.revokeHelper({ ownerId: request.device.device_id, helperId });
      if (!revoked) {
        return sendError(response, 404, 'device_not_linked', 'Ese dispositivo no está autorizado.');
      }
      io.to(helperId).emit('trust_revoked', { receiverId: request.device.device_id });
      return response.status(204).end();
    } catch (error) {
      return next(error);
    }
  });

  app.post('/api/v1/assistance-requests', actionRateLimit, async (request, response, next) => {
    try {
      const { receiverDeviceId } = request.body || {};
      if (typeof receiverDeviceId !== 'string' || !DEVICE_ID_PATTERN.test(receiverDeviceId)) {
        return sendError(response, 400, 'invalid_device_id', 'El dispositivo seleccionado no es válido.');
      }
      const result = await store.createAssistanceRequest({
        requestId: crypto.randomUUID(),
        helperId: request.device.device_id,
        receiverId: receiverDeviceId,
        expiresAt: new Date(Date.now() + REQUEST_TTL_MS),
      });
      if (!result) {
        return sendError(response, 403, 'not_authorized', 'El propietario no ha autorizado este dispositivo.');
      }
      const helper = await store.getDevice(request.device.device_id);
      if (result.status === 'pending') {
        io.to(receiverDeviceId).emit('assistance_request', {
          requestId: result.request_id,
          helperId: request.device.device_id,
          helperName: helper.display_name,
          expiresAt: result.expires_at,
        });
      } else {
        io.to(request.device.device_id).emit('assistance_response', {
          requestId: result.request_id,
          receiverId: receiverDeviceId,
          status: result.status,
        });
      }
      return response.status(201).json({
        requestId: result.request_id,
        status: result.status,
        expiresAt: result.expires_at,
      });
    } catch (error) {
      return next(error);
    }
  });

  app.get('/api/v1/assistance-requests/incoming', async (request, response, next) => {
    try {
      response.json(await store.listPendingAssistanceRequests(request.device.device_id));
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/v1/assistance-requests/:requestId/respond', async (request, response, next) => {
    try {
      const { requestId } = request.params;
      const { accepted } = request.body || {};
      if (!UUID_PATTERN.test(requestId) || typeof accepted !== 'boolean') {
        return sendError(response, 400, 'invalid_response', 'La respuesta a la solicitud no es válida.');
      }
      const result = await store.respondAssistanceRequest({
        requestId,
        receiverId: request.device.device_id,
        accepted,
      });
      if (!result) {
        return sendError(response, 404, 'request_not_found', 'La solicitud expiró, ya fue respondida o fue revocada.');
      }
      io.to(result.helper_id).emit('assistance_response', {
        requestId,
        receiverId: result.receiver_id,
        status: result.status,
      });
      return response.json({ requestId, status: result.status });
    } catch (error) {
      return next(error);
    }
  });

  app.use((request, response) => {
    sendError(response, 404, 'not_found', 'La ruta solicitada no existe.');
  });

  app.use((error, request, response, next) => {
    if (response.headersSent) {
      return next(error);
    }
    if (error.status === 400) {
      return sendError(response, 400, 'invalid_json', 'El cuerpo JSON no tiene un formato válido.');
    }
    if (error.status === 413) {
      return sendError(response, 413, 'request_too_large', 'La solicitud supera el tamaño permitido.');
    }
    console.error(`Request failed: ${error.message}`);
    return sendError(response, 500, 'server_error', 'No se pudo completar la solicitud. Inténtalo de nuevo.');
  });

  return app;
}

function createPresence(io, store) {
  const connected = new Map();
  return {
    isOnline(deviceId) {
      return connected.has(deviceId);
    },
    async attach(socket, deviceId) {
      const sockets = connected.get(deviceId) || new Set();
      sockets.add(socket.id);
      connected.set(deviceId, sockets);
      socket.join(deviceId);
      const helpers = await store.listHelpersForReceiver(deviceId);
      for (const helperId of helpers) {
        io.to(helperId).emit('device_status', { deviceId, online: true });
      }
      const ownerDevices = await store.listReceiversForHelper(deviceId);
      for (const receiverId of ownerDevices) {
        io.to(receiverId).emit('device_status', { deviceId, online: true });
      }
      const trustedReceivers = await store.listTrustedDevicesForHelper(deviceId);
      for (const receiver of trustedReceivers) {
        socket.emit('device_status', { deviceId: receiver.device_id, online: connected.has(receiver.device_id) });
      }
    },
    async detach(deviceId, socketId) {
      const sockets = connected.get(deviceId);
      if (!sockets) return;
      sockets.delete(socketId);
      if (sockets.size) return;
      connected.delete(deviceId);
      const helpers = await store.listHelpersForReceiver(deviceId);
      for (const helperId of helpers) {
        io.to(helperId).emit('device_status', { deviceId, online: false });
      }
      const ownerDevices = await store.listReceiversForHelper(deviceId);
      for (const receiverId of ownerDevices) {
        io.to(receiverId).emit('device_status', { deviceId, online: false });
      }
    },
  };
}

function installSocketAuthentication(io, store, presence) {
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
        return next(new Error('unauthorized'));
      }
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const device = await store.getSessionByHash(tokenHash);
      if (!device) {
        return next(new Error('unauthorized'));
      }
      socket.data.deviceId = device.device_id;
      socket.data.displayName = device.display_name;
      socket.data.authExpiresAt = new Date(device.expires_at).getTime();
      return next();
    } catch (error) {
      console.error(`Socket authentication failed: ${error.message}`);
      return next(new Error('authentication_unavailable'));
    }
  });

  io.on('connection', async (socket) => {
    const deviceId = socket.data.deviceId;
    const expiryTimer = setTimeout(
      () => socket.disconnect(true),
      Math.max(0, socket.data.authExpiresAt - Date.now())
    );
    try {
      await presence.attach(socket, deviceId);
      const linkRequests = await store.listPendingLinkRequests(deviceId);
      for (const request of linkRequests) {
        socket.emit('link_request', {
          requestId: request.request_id,
          helperId: request.helper_id,
          helperName: request.helper_name,
          expiresAt: request.expires_at,
        });
      }
      const assistanceRequests = await store.listPendingAssistanceRequests(deviceId);
      for (const request of assistanceRequests) {
        socket.emit('assistance_request', {
          requestId: request.request_id,
          helperId: request.helper_id,
          helperName: request.helper_name,
          expiresAt: request.expires_at,
        });
      }
    } catch (error) {
      console.error(`Socket initialization failed: ${error.message}`);
      socket.disconnect(true);
      return;
    }
    socket.on('disconnect', () => {
      clearTimeout(expiryTimer);
      presence.detach(deviceId, socket.id).catch((error) => {
        console.error(`Presence update failed: ${error.message}`);
      });
    });
  });
}

module.exports = {
  createApplication,
  createPresence,
  installSocketAuthentication,
  publicKeyFromBase64,
};
