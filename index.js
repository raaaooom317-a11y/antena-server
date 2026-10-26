const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Ruta de comprobación básica para ver si el servidor está vivo en Railway
app.get('/', (req, res) => {
  res.send('Servidor de Antena Control funcionando correctamente 🚀');
});

// Lógica de conexión tipo TeamViewer / Sala de control
io.on('connection', (socket) => {
  console.log(`Dispositivo conectado: ${socket.id}`);

  // 1. El receptor se registra con un ID único o se une a una sala
  socket.on('registrar-receptor', (deviceId) => {
    socket.join(deviceId);
    console.log(`Receptor registrado con ID de sala: ${deviceId}`);
  });

  // 2. El emisor se conecta a la sala del receptor específico
  socket.on('conectar-emisor', (deviceId) => {
    socket.join(deviceId);
    console.log(`Emisor vinculado al receptor: ${deviceId}`);
    // Avisar al receptor que alguien se conectó
    io.to(deviceId).emit('estado-conexion', { status: 'conectado', emisorId: socket.id });
  });

  // 3. Reenviar comandos del Emisor -> Receptor
  socket.on('enviar-comando', (data) => {
    // data debe contener { deviceId, comando: {...} }
    console.log(`Comando enviado al receptor ${data.deviceId}:`, data.comando);
    io.to(data.deviceId).emit('recibir-comando', data.comando);
  });

  // 4. Reenviar telemetría/respuesta del Receptor -> Emisor
  socket.on('enviar-telemetria', (data) => {
    // data debe contener { deviceId, telemetria: {...} }
    io.to(data.deviceId).emit('recibir-telemetria', data.telemetria);
  });

  socket.on('disconnect', () => {
    console.log(`Dispositivo desconectado: ${socket.id}`);
  });
});

// Railway asigna un puerto dinámico mediante process.env.PORT
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
