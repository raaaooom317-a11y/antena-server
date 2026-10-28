const http = require('node:http');
const { Server } = require('socket.io');
const { createApplication, createPresence, installSocketAuthentication } = require('./app');
const { PostgresStore } = require('./store');

async function start() {
  const store = await PostgresStore.connect(process.env.DATABASE_URL);
  const httpServer = http.createServer();
  const io = new Server(httpServer, {
    cors: process.env.WEB_ORIGIN ? { origin: process.env.WEB_ORIGIN } : { origin: false },
    maxHttpBufferSize: 16 * 1024,
  });
  const presence = createPresence(io, store);
  installSocketAuthentication(io, store, presence);
  httpServer.on('request', createApplication({ store, io, presence }));

  const cleanup = setInterval(() => {
    store.pruneExpired().catch((error) => {
      console.error(`Expired record cleanup failed: ${error.message}`);
    });
  }, 60 * 60 * 1000);
  cleanup.unref();

  const port = Number(process.env.PORT || 3000);
  httpServer.listen(port, '0.0.0.0', () => {
    console.log(`Antena Remote AI server listening on port ${port}`);
  });

  const shutdown = async () => {
    clearInterval(cleanup);
    await new Promise((resolve) => io.close(resolve));
    await store.close();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

if (require.main === module) {
  start().catch((error) => {
    console.error(`Server startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { start };
