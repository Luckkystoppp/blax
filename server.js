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

// Anti-DDoS: Rate Limiting
const rateLimitMap = new Map();
const RATE_LIMIT = {
  windowMs: 60000, // 1 minute
  maxRequests: 100, // max 100 requests per minute
  blockDuration: 300000 // block for 5 minutes if exceeded
};

const blacklistedIPs = new Set();

// Rate limiter middleware
const rateLimiter = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Check if IP is blacklisted
  if (blacklistedIPs.has(ip)) {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many requests. IP temporarily blocked.' 
    });
  }

  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + RATE_LIMIT.windowMs };

  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT.windowMs;
  } else {
    record.count++;
  }

  rateLimitMap.set(ip, record);

  if (record.count > RATE_LIMIT.maxRequests) {
    blacklistedIPs.add(ip);
    setTimeout(() => blacklistedIPs.delete(ip), RATE_LIMIT.blockDuration);
    return res.status(429).json({ 
      success: false, 
      message: 'Rate limit exceeded. Try again later.' 
    });
  }

  next();
};

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
app.use(rateLimiter);
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
let loginHistory = [];

const FILES = {
  loginKeys: 'data/login-keys.json',
  shops: 'data/shops.json',
  hotmails: 'data/hotmails.json',
  adminNotes: 'data/admin-notes.json',
  notifications: 'data/notifications.json',
  chatMessages: 'data/chat-messages.json',
  loginHistory: 'data/login-history.json'
};

const ADMIN_KEY = 'XKECEJ-FICMD-XKEK20-X34ICKCK';

// WebSocket clients
const wsClients = new Set();

// Utils
const sanitize = (i) => typeof i !== 'string' ? i : i.replace(/['"`;]/g, '');

const genKey = () => {
  const segments = [];
  for (let i = 0; i < 4; i++) {
    const segment = crypto.randomBytes(3).toString('hex').toUpperCase();
    segments.push(segment);
  }
  return segments.join('-');
};

const getExpiryDate = (duration) => {
  const now = new Date();
  switch (duration) {
    case '1day': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case '1week': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case '1month': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    case '3months': return new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
    case '1year': return new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
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

const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.ip;
};

// Get all network interfaces
function getAllNetworkIPs() {
  const interfaces = os.networkInterfaces();
  const addresses = [];
  
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
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
    await fs.mkdir('web', { recursive: true });

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
          keyName: 'Admin Master Key',
          created: new Date().toISOString()
        });
        await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
      }
    } catch (e) {
      loginKeys = [{
        id: Date.now(),
        key: ADMIN_KEY,
        role: 'admin',
        keyName: 'Admin Master Key',
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
          case 'loginHistory': loginHistory = JSON.parse(data); break;
        }
      } catch (e) {
        await fs.writeFile(file, '[]');
      }
    }
  } catch (e) {
    console.error('Load data error:', e);
  }
}

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (token && tokens.has(token)) {
    const tokenData = tokens.get(token);
    if (tokenData.expire > Date.now()) {
      req.user = tokenData.user;
      return next();
    }
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
    const clientIP = getClientIP(req);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    const loginKey = loginKeys.find(k => k.key === sanitizedKey);
    
    if (!loginKey) {
      return res.json({ success: false, message: 'Invalid key' });
    }

    if (isKeyExpired(loginKey)) {
      return res.json({ success: false, message: 'Key expired (Dead Key)' });
    }

    // Track login history
    const loginRecord = {
      id: Date.now(),
      keyId: loginKey.id,
      keyName: loginKey.keyName,
      ip: clientIP,
      userAgent: userAgent,
      timestamp: new Date().toISOString()
    };

    loginHistory.push(loginRecord);
    
    // Keep only last 500 login records
    if (loginHistory.length > 500) {
      loginHistory = loginHistory.slice(-500);
    }
    
    await fs.writeFile(FILES.loginHistory, JSON.stringify(loginHistory, null, 2));

    // Update last login on key
    loginKey.lastLogin = new Date().toISOString();
    loginKey.lastIP = clientIP;
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));

    const token = crypto.randomBytes(32).toString('hex');
    tokens.set(token, {
      user: {
        id: loginKey.id,
        key: loginKey.key,
        role: loginKey.role,
        keyName: loginKey.keyName || 'User',
        expiresAt: loginKey.expiresAt,
        created: loginKey.created,
        lastLogin: loginKey.lastLogin,
        lastIP: clientIP
      },
      expire: Date.now() + 3600000 // 1 hour
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

// Get profile with login history
app.get('/api/profile', auth, (req, res) => {
  const user = req.user;
  const userLoginHistory = loginHistory
    .filter(h => h.keyId === user.id)
    .slice(-10)
    .reverse();

  res.json({
    success: true,
    profile: {
      keyName: user.keyName || 'User',
      role: user.role,
      key: user.key,
      created: user.created,
      expiresAt: user.expiresAt,
      daysRemaining: getDaysRemaining(user.expiresAt),
      lastLogin: user.lastLogin,
      lastIP: user.lastIP,
      loginHistory: userLoginHistory
    }
  });
});

// Generate key with name - FIXED
app.post('/api/genkey', auth, adminOnly, async (req, res) => {
  try {
    const { duration, keyName } = req.body;
    
    if (!keyName || !keyName.trim()) {
      return res.json({ success: false, message: 'Key name is required!' });
    }
    
    const expiresAt = getExpiryDate(duration);
    const newKey = genKey();
    
    const newLoginKey = {
      id: Date.now(),
      key: newKey,
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
      key: newLoginKey
    });
  } catch (error) {
    console.error('Generate key error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get all keys
app.get('/api/keys', auth, adminOnly, (req, res) => {
  const keysWithStatus = loginKeys.map(k => ({
    ...k,
    isExpired: isKeyExpired(k),
    daysRemaining: getDaysRemaining(k.expiresAt)
  }));
  res.json(keysWithStatus);
});

// Delete key
app.post('/api/deletekey', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.body;
    loginKeys = loginKeys.filter(k => k.id !== id);
    await fs.writeFile(FILES.loginKeys, JSON.stringify(loginKeys, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
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
app.get('/shop', (req, res) => res.sendFile(path.join(__dirname, 'web/shop.html')));
app.get('/hotmail', (req, res) => res.sendFile(path.join(__dirname, 'web/hotmail.html')));
app.get('/ulp', (req, res) => res.sendFile(path.join(__dirname, 'web/ulp.html')));
app.get('/bin', (req, res) => res.sendFile(path.join(__dirname, 'web/bin.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'web/settings.html')));

// Start server
loadData().then(() => {
  const networkIPs = getAllNetworkIPs();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║       SERVER KEY ULTRA V3.0 - BEAUTIFUL PURPLE EDITION      ║');
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log('║ 🛡️  ANTI-DDOS PROTECTION ENABLED (Rate Limiting Active)     ║');
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
    console.log('╟──────────────────────────────────────────────────────────────╢');
    console.log('║ ✨ FEATURES:                                                 ║');
    console.log('║ • Beautiful Purple UI                                        ║');
    console.log('║ • Profile Page with Login History & IP Tracking             ║');
    console.log('║ • Fixed Key Generation with Names                            ║');
    console.log('║ • Anti-DDoS Protection (100 req/min)                         ║');
    console.log('║ • Real-time Chat System                                      ║');
    console.log('║ • Optimized for Large Files (50M lines)                      ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`\n🔑 Admin Key: ${ADMIN_KEY}`);
    console.log('🛡️  Rate Limit: 100 requests/minute per IP');
    console.log('💡 TIP: Share the network URL to let others access!\n');
  });
});
