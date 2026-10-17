const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const si = require('systeminformation');
const Docker = require('dockerode');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const docker = new Docker({ socketPath: '/var/run/docker.sock' }); // Kết nối tới Docker Engine

app.use(express.json());
app.use(express.static('public')); // Thư mục chứa giao diện web

// --- REST API: Quản lý Docker Containers (Web Server / App) ---

// 1. Lấy danh sách các ứng dụng/web server đang chạy
app.get('/api/containers', async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    res.json(containers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Khởi động / Dừng 1 Ứng dụng
app.post('/api/containers/:id/:action', async (req, res) => {
  const { id, action } = req.params;
  try {
    const container = docker.getContainer(id);
    if (action === 'start') await container.start();
    else if (action === 'stop') await container.stop();
    else if (action === 'restart') await container.restart();
    else return res.status(400).json({ error: 'Hành động không hợp lệ' });

    res.json({ message: `Thực hiện ${action} thành công cho container ${id}` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- REALTIME SOCKET: Giám sát thông số Server ---
io.on('connection', (socket) => {
  console.log('Admin đã kết nối:', socket.id);

  // Gửi thông số máy chủ mỗi 2 giây
  const interval = setInterval(async () => {
    const cpu = await si.currentLoad();
    const mem = await si.mem();
    const os = await si.osInfo();

    socket.emit('server-metrics', {
      hostname: os.hostname,
      cpuUsage: cpu.currentLoad.toFixed(2),
      ramUsed: (mem.active / 1024 / 1024 / 1024).toFixed(2),
      ramTotal: (mem.total / 1024 / 1024 / 1024).toFixed(2),
      ramPercent: ((mem.active / mem.total) * 100).toFixed(2),
    });
  }, 2000);

  socket.on('disconnect', () => {
    clearInterval(interval);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`[Server Management System] Trạm quản lý đang chạy tại http://localhost:${PORT}`);
});
