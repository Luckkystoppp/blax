const express = require('express');
const expressWs = require('express-ws');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const os = require('os');

const app = express();
expressWs(app);

const PORT = 3000;

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 500 * 1024 * 1024 }
});

// Middleware
app.use(bodyParser.json({ limit: '200mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '200mb' }));
app.use(express.static(path.join(__dirname, 'web')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Data
let loginKeys = [];
let shops = [];
let hotmails = [];
let adminNotes = [];
let notifications = [];
let chatMessages = [];
let tokens = new Map();

const FILES = {
  loginKeys: 'data/login-keys.json',
  shops: 'data/shops.json',
  hotmails: 'data/hotmails.json',
  adminNotes: 'data/admin-notes.json',
  notifications: 'data/notifications.json',
  chatMessages: 'data/chat-messages.json'
};

const ADMIN_KEY = 'XKECEJ-FICMD-XKEK20-X34ICKCK';

// WebSocket clients
const wsClients = new Set();

// Utils
const sanitize = (i) => typeof i !== 'string' ? i : i.replace(/['"`;]/g, '');
const genKey = () => crypto.randomBytes(16).toString('hex').toUpperCase();

const getExpiryDate = (duration) => {
  const now = new Date();
  switch (duration) {
    case '1day': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case '1week': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case '1month': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    default: return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
};

const isKeyExpired = (key) => {
  if (key.role === 'admin') return false;
  if (!key.expiresAt) return false;
  return new Date(key.expiresAt) < new Date();
};

const getDaysRemaining = (expiresAt) => {
  if (!expiresAt) return 'Never';
  const now = new Date();
  const expiry = new Date(expiresAt);
  const diff = expiry - now;
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
  if (days < 0) return 'Expired';
  if (days === 0) return 'Today';
  return `${days} days`;
};

// Get all network interfaces
function getAllNetworkIPs() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal and non-IPv4 addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        addresses.push({
          name: name,
          address: iface.address
        });
      }
    }
  }
  
  return addresses;
}

// Load data
async function loadData() {
  try {
    await fs.mkdir('data', { recursive: true });
    await fs.mkdir('uploads', { recursive: true });

    // Login keys - ensure admin exists
    try {
      const data = await fs.readFile(FILES.loginKeys, 'utf8');
      loginKeys = JSON.parse(data);
      
      const hasAdmin = loginKeys.some(k => k.role === 'admin' && k.key === ADMIN_KEY);
      if (!hasAdmin) {
        loginKeys.unshift({
          id: Date.now(),
          key: ADMIN_KEY,
          role: 'admin',
          keyName: 'Admin Key',
          created: new Date().toISOString()
        });
        await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
      }
    } catch (e) {
      loginKeys = [{
        id: Date.now(),
        key: ADMIN_KEY,
        role: 'admin',
        keyName: 'Admin Key',
        created: new Date().toISOString()
      }];
      await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
    }

    // Load other data
    for (const [key, file] of Object.entries(FILES)) {
      if (key === 'loginKeys') continue;
      try {
        const data = await fs.readFile(file, 'utf8');
        switch (key) {
          case 'shops': shops = JSON.parse(data); break;
          case 'hotmails': hotmails = JSON.parse(data); break;
          case 'adminNotes': adminNotes = JSON.parse(data); break;
          case 'notifications': notifications = JSON.parse(data); break;
          case 'chatMessages': chatMessages = JSON.parse(data); break;
        }
      } catch (e) {
        await fs.writeFile(file, '[]');
        if (key === 'chatMessages') chatMessages = [];
      }
    }
  } catch (e) {
    console.error('Load data error:', e);
  }
}

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (token && tokens.has(token) && tokens.get(token).expire > Date.now()) {
    req.user = tokens.get(token).user;
    return next();
  }
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  res.status(403).json({ success: false, message: 'Admin only' });
};

// Routes

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { key } = req.body;
    const sanitizedKey = sanitize(key);
    
    const loginKey = loginKeys.find(k => k.key === sanitizedKey);
    
    if (!loginKey) {
      return res.json({ success: false, message: 'Invalid key' });
    }

    if (isKeyExpired(loginKey)) {
      return res.json({ success: false, message: 'Key expired (Dead Key)' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, {
      user: {
        id: loginKey.id,
        key: loginKey.key,
        role: loginKey.role,
        keyName: loginKey.keyName || 'User',
        expiresAt: loginKey.expiresAt,
        created: loginKey.created
      },
      expire: Date.now() + 3600000
    });

    res.json({
      success: true,
      token,
      role: loginKey.role,
      user: {
        keyName: loginKey.keyName || 'User',
        expiresAt: loginKey.expiresAt,
        created: loginKey.created
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get profile
app.get('/api/profile', auth, (req, res) => {
  const user = req.user;
  res.json({
    success: true,
    profile: {
      keyName: user.keyName || 'User',
      role: user.role,
      key: user.key,
      created: user.created,
      expiresAt: user.expiresAt,
      daysRemaining: getDaysRemaining(user.expiresAt)
    }
  });
});

// Generate key with name
app.post('/api/genkey', auth, adminOnly, async (req, res) => {
  try {
    const { duration, keyName } = req.body;
    
    if (!keyName || !keyName.trim()) {
      return res.json({ success: false, message: 'Key name required' });
    }
    
    const expiresAt = getExpiryDate(duration);
    
    const newLoginKey = {
      id: Date.now(),
      key: genKey(),
      role: 'user',
      keyName: sanitize(keyName.trim()),
      duration: duration,
      created: new Date().toISOString(),
      expiresAt: expiresAt.toISOString()
    };

    loginKeys.push(newLoginKey);
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));

    res.json({
      success: true,
      key: newLoginKey.key,
      keyName: newLoginKey.keyName,
      duration,
      expiresAt: newLoginKey.expiresAt
    });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteloginkey', auth, adminOnly, async (req, res) => {
  try {
    loginKeys = loginKeys.filter(k => k.id !== req.body.id && k.role !== 'admin');
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/loginkeys', auth, adminOnly, (req, res) => {
  const keys = loginKeys
    .filter(k => k.role !== 'admin')
    .map(k => ({
      ...k,
      expired: isKeyExpired(k),
      daysRemaining: getDaysRemaining(k.expiresAt)
    }));
  res.json(keys);
});

// Notifications
app.get('/api/notifications', auth, (req, res) => res.json(notifications));

app.post('/api/createnotification', auth, adminOnly, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.json({ success: false });
    }

    const notification = {
      id: Date.now(),
      title: sanitize(title),
      content: sanitize(content),
      created: new Date().toISOString()
    };

    notifications.push(notification);
    await fs.writeFile(FILES.notifications, JSON.stringify(notifications, null, 2));
    res.json({ success: true, notification });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deletenotification', auth, adminOnly, async (req, res) => {
  try {
    notifications = notifications.filter(n => n.id !== req.body.id);
    await fs.writeFile(FILES.notifications, JSON.stringify(notifications, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// Shops
app.get('/api/shops', auth, (req, res) => {
  const shopsMetadata = shops.map(s => ({
    id: s.id,
    name: s.name,
    note: s.note,
    image: s.image,
    lines: s.lines,
    created: s.created
  }));
  res.json(shopsMetadata);
});

app.post('/api/createshop', upload.single('image'), auth, adminOnly, async (req, res) => {
  try {
    const { name, note } = req.body;
    let content = req.body.content || '';

    if (!name || !content) {
      return res.json({ success: false, message: 'Name and content required' });
    }

    const lines = content.split('\n').length;
    if (lines > 50000000) {
      return res.json({ success: false, message: 'Max 50M lines' });
    }

    const shop = {
      id: Date.now(),
      name: sanitize(name),
      content: content,
      note: sanitize(note) || '',
      image: req.file ? `/uploads/${req.file.filename}` : null,
      created: new Date().toISOString(),
      lines: lines
    };

    shops.push(shop);
    await fs.writeFile(FILES.shops, JSON.stringify(shops, null, 2));
    res.json({ success: true, shop: { id: shop.id, name: shop.name, lines: shop.lines } });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteshop', auth, adminOnly, async (req, res) => {
  try {
    shops = shops.filter(s => s.id !== req.body.id);
    await fs.writeFile(FILES.shops, JSON.stringify(shops, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/shop/:id', auth, (req, res) => {
  const shop = shops.find(s => s.id === parseInt(req.params.id));
  if (shop) res.json(shop);
  else res.status(404).json({ success: false });
});

// Hotmails
app.get('/api/hotmails', auth, (req, res) => {
  const hotmailsMetadata = hotmails.map(h => ({
    id: h.id,
    name: h.name,
    note: h.note,
    image: h.image,
    lines: h.lines,
    created: h.created
  }));
  res.json(hotmailsMetadata);
});

app.post('/api/createhotmail', upload.single('image'), auth, adminOnly, async (req, res) => {
  try {
    const { name, note } = req.body;
    let content = req.body.content || '';

    if (!name || !content) {
      return res.json({ success: false, message: 'Name and content required' });
    }

    const lines = content.split('\n').length;
    if (lines > 50000000) {
      return res.json({ success: false, message: 'Max 50M lines' });
    }

    const hotmail = {
      id: Date.now(),
      name: sanitize(name),
      content: content,
      note: sanitize(note) || '',
      image: req.file ? `/uploads/${req.file.filename}` : null,
      created: new Date().toISOString(),
      lines: lines
    };

    hotmails.push(hotmail);
    await fs.writeFile(FILES.hotmails, JSON.stringify(hotmails, null, 2));
    res.json({ success: true, hotmail: { id: hotmail.id, name: hotmail.name, lines: hotmail.lines } });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deletehotmail', auth, adminOnly, async (req, res) => {
  try {
    hotmails = hotmails.filter(h => h.id !== req.body.id);
    await fs.writeFile(FILES.hotmails, JSON.stringify(hotmails, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/api/hotmail/:id', auth, (req, res) => {
  const hotmail = hotmails.find(h => h.id === parseInt(req.params.id));
  if (hotmail) res.json(hotmail);
  else res.status(404).json({ success: false });
});

// Admin Notes
app.get('/api/adminnotes', auth, (req, res) => res.json(adminNotes));

app.post('/api/createadminnote', auth, adminOnly, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!title || !content) {
      return res.json({ success: false });
    }

    const note = {
      id: Date.now(),
      title: sanitize(title),
      content: sanitize(content),
      created: new Date().toISOString()
    };

    adminNotes.push(note);
    await fs.writeFile(FILES.adminNotes, JSON.stringify(adminNotes, null, 2));
    res.json({ success: true, note });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/deleteadminnote', auth, adminOnly, async (req, res) => {
  try {
    adminNotes = adminNotes.filter(n => n.id !== req.body.id);
    await fs.writeFile(FILES.adminNotes, JSON.stringify(adminNotes, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// Chat
app.get('/api/chat/messages', auth, (req, res) => {
  res.json(chatMessages.slice(-100));
});

app.post('/api/chat/send', auth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || !message.trim()) {
      return res.json({ success: false });
    }

    const chatMessage = {
      id: Date.now(),
      user: req.user.keyName || 'User',
      role: req.user.role,
      message: sanitize(message.trim()),
      timestamp: new Date().toISOString()
    };

    chatMessages.push(chatMessage);
    
    if (chatMessages.length > 1000) {
      chatMessages = chatMessages.slice(-1000);
    }
    
    await fs.writeFile(FILES.chatMessages, JSON.stringify(chatMessages, null, 2));

    wsClients.forEach(client => {
      if (client.readyState === 1) {
        client.send(JSON.stringify({ type: 'new_message', message: chatMessage }));
      }
    });

    res.json({ success: true, message: chatMessage });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// WebSocket
app.ws('/ws/chat', (ws, req) => {
  wsClients.add(ws);
  ws.on('close', () => {
    wsClients.delete(ws);
  });
});

// ULP Search
app.post('/api/ulpsearch', auth, async (req, res) => {
  try {
    const { target, total, timeout, server } = req.body;
    if (!target) {
      return res.json({ success: false, message: 'Target required' });
    }

    const serverNum = server || 1;
    const url = `http://79.137.76.211:5119/api/search?keyword=${encodeURIComponent(target)}&timeout=${timeout || 10}&format=ulp&total=${total || 100}&mode=regex&username=ducdz122&password=phuvanduc&sever=${serverNum}`;
    
    const response = await axios.get(url, { timeout: 60000 });

    res.json({
      success: true,
      data: response.data,
      results: response.data.results || response.data
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// BIN Checker
app.post('/api/checkbin', auth, async (req, res) => {
  try {
    const { bins } = req.body;
    const results = [];

    for (const bin of bins) {
      try {
        const response = await axios.get(`https://bins.antipublic.cc/bins/${bin.trim()}`, {
          timeout: 15000
        });

        if (response.status === 200 && response.data) {
          results.push({
            bin: bin.trim(),
            status: 'valid',
            brand: response.data.brand || 'N/A',
            type: response.data.type || 'N/A',
            bank: response.data.bank || 'N/A',
            country: response.data.country_name || 'N/A'
          });
        } else {
          results.push({
            bin: bin.trim(),
            status: 'not_found'
          });
        }
      } catch (error) {
        results.push({
          bin: bin.trim(),
          status: 'error'
        });
      }
    }

    res.json({ success: true, results });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// HTML routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'web/main.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'web/login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'web/dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'web/profile.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, 'web/chat.html')));
app.get('/shop', (req, res) => res.sendFile(path.join(__dirname, 'web/shop.html')));
app.get('/hotmail', (req, res) => res.sendFile(path.join(__dirname, 'web/hotmail.html')));
app.get('/ulp', (req, res) => res.sendFile(path.join(__dirname, 'web/ulp.html')));
app.get('/bin', (req, res) => res.sendFile(path.join(__dirname, 'web/bin.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'web/settings.html')));

// Start server
loadData().then(() => {
  // Get all network IPs
  const networkIPs = getAllNetworkIPs();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║       SERVER KEY ULTRA V3.0 - BEAUTIFUL PURPLE EDITION      ║');
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log('║ 🌐 SERVER IS NOW ACCESSIBLE FROM ANY DEVICE ON NETWORK!     ║');
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log(`║ Port         : ${PORT.toString().padEnd(48)}║`);
    console.log('╟──────────────────────────────────────────────────────────────╢');
    
    if (networkIPs.length > 0) {
      console.log('║ 📡 NETWORK ACCESS URLS:                                      ║');
      console.log('╟──────────────────────────────────────────────────────────────╢');
      networkIPs.forEach((net, index) => {
        const url = `http://${net.address}:${PORT}`;
        const label = `${net.name}`.padEnd(10);
        console.log(`║ ${(index + 1)}. ${label}: ${url.padEnd(42)}║`);
      });
    }
    
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log(`║ Local        : http://localhost:${PORT}`.padEnd(63) + '║');
    console.log(`║ LAN (0.0.0.0): Server listening on ALL network interfaces    ║`);
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log('║ 📱 SHARE ANY URL ABOVE WITH OTHERS TO LET THEM ACCESS!      ║');
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log('║ ✨ Beautiful Purple UI                                       ║');
    console.log('║ 👤 Profile Page with Expiry Info                             ║');
    console.log('║ 💬 Real-time Chat System                                     ║');
    console.log('║ 📊 Enhanced Dashboard                                        ║');
    console.log('║ ⚡ Optimized for Large Files (50M lines)                     ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`\n🔑 Admin Key: ${ADMIN_KEY}`);
    console.log('\n💡 TIP: Share the network URL with anyone to give them access!');
    console.log('    They can access from phone, tablet, or any device.\n');
  });
});
