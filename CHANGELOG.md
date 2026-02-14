# 📝 CHANGELOG

## Version 3.0.0 - Beautiful Purple Edition (2026-02-14)

### ✨ New Features

#### 🛡️ Security Enhancements
- **Anti-DDoS Protection**: Rate limiting system (100 requests/minute per IP)
- **IP Blacklisting**: Automatic 5-minute block for rate limit violations
- **Login History Tracking**: Complete audit trail with IP and User-Agent
- **Session Management**: Enhanced token expiration (1 hour)

#### 👤 Profile Management
- **New Profile Page**: Complete user profile with all key information
- **Login History**: View last 10 login sessions
- **IP Tracking**: Monitor which IPs are accessing your account
- **User Agent Logging**: Track devices and browsers used
- **Days Remaining Display**: Visual countdown with color coding
  - Red: 0-3 days
  - Orange: 4-7 days  
  - Green: 8+ days

#### 🔑 Key Management (Admin)
- **Required Key Names**: Admin must name each key (e.g., "John's Key")
- **Extended Durations**: Now supports 3 months and 1 year options
- **Enhanced Key Display**: Shows key name, status, expiry, and last login
- **Better Key Generation**: Fixed algorithm to create valid keys
- **Dead Key System**: Automatic expiration handling

### 🐛 Bug Fixes

#### Critical Fixes
1. **Key Generation Bug**: 
   - Fixed: Key name field was missing
   - Fixed: Keys were generated without names
   - Fixed: Key format was inconsistent
   
2. **Login Tracking Bug**:
   - Fixed: IP addresses not being logged
   - Fixed: Login history not being saved
   - Fixed: Last login timestamp not updating

3. **Profile Page Bug**:
   - Fixed: Profile page didn't exist
   - Fixed: No way to view key information
   - Fixed: No login history display

4. **Settings Panel Bug**:
   - Fixed: Key generation form incomplete
   - Fixed: Admin couldn't specify key names
   - Fixed: Duration options were limited

### 🎨 UI/UX Improvements

#### Visual Enhancements
- **Profile Card**: Beautiful gradient card with avatar
- **Color-Coded Status**: Intuitive status indicators
  - 🟢 Green: Active keys
  - 🟡 Yellow: Admin keys
  - 🔴 Red: Expired keys
- **Login History Table**: Clean, organized display
- **Copy Key Button**: One-click key copying
- **Toast Notifications**: User-friendly feedback system

#### Navigation Updates
- Added "Profile" link to all pages
- Consistent sidebar across all pages
- Better active state indicators

### 🚀 Performance Optimizations

#### Code Quality
- Cleaned up duplicate code
- Improved error handling
- Better async/await patterns
- Optimized database writes

#### Memory Management
- Limit login history to 500 records
- Limit chat messages to 1000 records
- Efficient token cleanup

### 📊 Data Structure Changes

#### New Data Files
```json
// data/login-history.json
{
  "id": 1234567890,
  "keyId": 1234567890,
  "keyName": "John's Key",
  "ip": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "timestamp": "2026-02-14T10:30:00.000Z"
}
```

#### Enhanced Key Structure
```json
{
  "id": 1234567890,
  "key": "ABC123-DEF456-GHI789-JKL012",
  "keyName": "John's Key",  // NEW
  "role": "user",
  "duration": "1month",
  "created": "2026-02-14T10:00:00.000Z",
  "expiresAt": "2026-03-14T10:00:00.000Z",
  "lastLogin": "2026-02-14T10:30:00.000Z",  // NEW
  "lastIP": "192.168.1.100"  // NEW
}
```

### 🔧 Configuration Changes

#### Server Configuration
- Port: 3000 (unchanged)
- Rate Limit: 100 requests/minute per IP (NEW)
- Block Duration: 5 minutes (NEW)
- Token Expiry: 1 hour (NEW)

#### File Limits
- Upload Size: 500MB (unchanged)
- Max Lines: 50M (unchanged)
- Login History: 500 records (NEW)
- Chat Messages: 1000 records (NEW)

### 📝 API Changes

#### New Endpoints
```javascript
// Get profile with login history
GET /api/profile
Response: {
  success: true,
  profile: {
    keyName: string,
    role: string,
    key: string,
    created: string,
    expiresAt: string,
    daysRemaining: string,
    lastLogin: string,
    lastIP: string,
    loginHistory: Array<LoginRecord>
  }
}
```

#### Modified Endpoints
```javascript
// Generate key - now requires keyName
POST /api/genkey
Body: {
  duration: string,
  keyName: string  // REQUIRED NOW
}

// Login - now tracks IP and saves history
POST /api/login
Body: { key: string }
Response: {
  success: true,
  token: string,
  role: string,
  user: { keyName, expiresAt, created }
}
```

### 🎯 Breaking Changes

⚠️ **Important**: These changes may affect existing installations:

1. **Key Generation**: Admin Panel now requires key names
2. **Data Migration**: Old keys without names will show as "Unnamed"
3. **API**: `/api/genkey` now requires `keyName` parameter

### 🔄 Migration Guide

#### From V2.x to V3.0

1. **Backup Data**:
```bash
cp -r data/ data_backup_v2/
```

2. **Install V3.0**:
```bash
npm install
```

3. **Update Key Names** (Optional):
   - Login as admin
   - Go to Settings
   - Old keys will show as "Unnamed"
   - Generate new keys with proper names

4. **Data Files**: V3.0 will auto-create new files:
   - `data/login-history.json`

### 📚 Documentation Updates

- New INSTALL.md with detailed setup guide
- Updated README.md with V3.0 features
- Added CHANGELOG.md (this file)
- Inline code comments improved

### 🎉 What's Next?

#### Planned for V3.1
- [ ] Email notifications for key expiry
- [ ] 2FA authentication
- [ ] API key system for external access
- [ ] Export/Import user data
- [ ] Dark/Light theme toggle
- [ ] Multi-language support

#### Planned for V4.0
- [ ] Docker support
- [ ] Database migration (PostgreSQL/MySQL)
- [ ] Clustering support
- [ ] Advanced analytics dashboard
- [ ] Mobile app (React Native)
- [ ] WebAuthn support

### 🙏 Credits

Special thanks to:
- Node.js community
- Express.js team
- All beta testers

### 📄 License

MIT License - See LICENSE file for details

---

**Server Key Ultra V3.0** - Made with 💜
