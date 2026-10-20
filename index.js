const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

let receptorConnected = false;

// ==========================================
// RUTA HTTP PARA EVITAR EL ERROR 404
// ==========================================
app.get('/', (req, res) => {
  res.status(200).send('¡Servidor de Antena Receptor 1 Activo y Operativo!');
});

// Ruta adicional opcional para chequeos de salud
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'online', receptorConnected });
});

// ==========================================
// CONFIGURACIÓN DE SOCKET.IO
// ==========================================
io.on('connection', (socket) => {
  console.log(`[+] Dispositivo conectado: ${socket.id}`);

  socket.on('register_role', (role) => {
    socket.role = role;
    console.log(`[-] Registrado como: ${role}`);

    if (role === 'receptor') {
      receptorConnected = true;
      io.emit('receptor_status', { connected: true });
    } else if (role === 'emisor') {
      socket.emit('receptor_status', { connected: receptorConnected });
    }
  });

  socket.on('send_command', (data) => {
    console.log('[>] Comando emitido:', data);
    io.emit('execute_command', data);
  });

  socket.on('antena_data', (data) => {
    console.log('[📡] Datos de pantalla recibidos de la emisora:', data);
    io.emit('receive_antena_data', data);
  });

  socket.on('disconnect', () => {
    if (socket.role === 'receptor') {
      receptorConnected = false;
      io.emit('receptor_status', { connected: false });
      console.log('[-] Receptor desconectado');
    }
    console.log(`[-] Dispositivo desconectado: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
