# Homeguard v4.0 - Network Access Control System

A TOTP-based network access control system with device management capabilities.

## 🚀 Features

- **TOTP Authentication**: Multi-duration TOTP codes for temporary network access
- **Device Management**: Web-based dashboard to manage all network devices
- **IOT Device Support**: Dedicated proxy chain for IOT devices
- **Two Modes**:
  - **Transparent Mode**: All traffic allowed (internet access for everyone)
  - **TOTP Mode**: Only authenticated devices allowed
- **Testing Mode**: Development mode where iptables commands are logged but not executed

## 📋 Architecture

### System Modes

1. **Transparent Mode**
   - All network traffic flows freely
   - No TOTP authentication required
   - Used during system maintenance

2. **TOTP Mode**
   - Default: All traffic blocked
   - Exceptions:
     - SSH (port 22)
     - VNC (port 5900)
     - Admin web interface (port 8081)
     - Access to gateway IP (192.168.2.1)
   - IOT devices in IOT proxy chain get internet access
   - Granted devices in Homeguard proxy chain get internet access

### Device Access States

- **Blocked**: No internet access (default for new devices)
- **Granted**: Temporary internet access via TOTP authentication
- **IOT**: Permanent internet access via IOT proxy

## 🛠️ Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Ensure totp_secrets.json exists (copy from version-3)
# This file contains the TOTP secrets for all duration codes
```

## 🎯 Usage

### Starting the Service

```bash
# Run in TESTING mode (recommended for development)
python src/main.py
```

### Accessing the Dashboard

Open browser to: `http://192.168.2.1:8081/`

### Dashboard Features

1. **Scan Network**: Discover all active devices on the network
2. **Set Transparent Mode**: Allow all traffic
3. **Set TOTP Mode**: Enable access control
4. **Device Management**:
   - **Grant**: Give temporary access (requires TOTP code)
   - **Block**: Remove access
   - **IOT**: Set as IOT device (permanent access)

## 📡 API Endpoints

### Mode Management
- `POST /set_mode_to_transparent` - Set transparent mode
- `POST /set_mode_to_totp` - Set TOTP mode

### TOTP
- `POST /validate_totp` - Validate a TOTP code
  - Query params: `totp_code`

### Device Management
- `GET /devices` - List all devices
- `GET /scan_network` - Scan network for active devices
- `POST /grant_access_to_ip` - Grant access to IP
  - Query params: `ip_address`, `totp_code`
- `POST /block_access_to_ip` - Block access from IP
  - Query params: `ip_address`
- `POST /grant_access_to_IOT` - Add device to IOT proxy
  - Query params: `ip_address`

### System
- `GET /health` - Health check and system status

## 🔧 Configuration

Configuration is stored in `homeguard_config.json`:

```json
{
  "system_mode": "transparent",
  "execution_mode": "testing"
}
```

### Environment Variables

Set via `.env` file or `homeguard_` prefix:

- `HOMEGUARD_EXECUTION_MODE`: "testing" or "live" (default: "testing")
- `HOMEGUARD_SYSTEM_MODE`: "transparent" or "totp" (default: "transparent")
- `HOMEGUARD_WEB_PORT`: Web server port (default: 8081)
- `HOMEGUARD_GATEWAY_IP`: Gateway IP (default: 192.168.2.1)
- `HOMEGUARD_LOG_LEVEL`: Logging level (default: INFO)

## 🧪 Testing Mode

**IMPORTANT**: The system runs in TESTING mode by default.

In testing mode:
- All iptables commands are LOGGED but NOT EXECUTED
- Safe for development and testing
- No actual network changes are made
- Check `homeguard.log` to see what commands would be executed

To run in LIVE mode (production):
```python
# In src/homeguard/config/settings.py
execution_mode: str = Field(default="live", ...)
```

## 🔒 Security Notes

1. **TOTP Secrets**: Keep `totp_secrets.json` secure
2. **Admin Access**: Always allowed on ports 22 (SSH), 5900 (VNC), 8081 (Web)
3. **Testing Mode**: Always test in testing mode first before going live

## 📊 System Workflow

### Startup
1. Load configuration from `homeguard_config.json`
2. Initialize database
3. Apply mode settings:
   - Transparent: Set permissive iptables
   - TOTP: Load IOT and granted devices, configure restrictive iptables
4. Start background task for access expiration (checks every 30 seconds)
5. Start web server

### Shutdown
1. Set system to transparent mode (restore internet access)
2. Close database connections
3. Exit gracefully

### Access Expiration
- Background task runs every 30 seconds
- Checks all granted devices for expiration
- Automatically blocks expired devices
- Logs expiration events

## 📁 Project Structure

```
homeguard/
├── src/
│   ├── main.py                 # Entry point
│   └── homeguard/
│       ├── api/
│       │   └── service.py      # FastAPI service with all endpoints
│       ├── auth/
│       │   └── totp.py         # TOTP authentication
│       ├── config/
│       │   └── settings.py     # Configuration management
│       ├── database/
│       │   ├── models.py       # SQLAlchemy models
│       │   └── connection.py   # Database connection
│       ├── iptables/
│       │   └── manager.py      # IPTables management
│       ├── network/
│       │   └── scanner.py      # Network device scanner
│       └── frontend/
│           └── templates/
│               └── dashboard.html  # Web interface
├── totp_secrets.json           # TOTP secrets (DO NOT COMMIT)
├── homeguard_config.json       # Persistent config
├── homeguard.db               # SQLite database
├── homeguard.log              # Application logs
└── requirements.txt           # Python dependencies
```

## 🐛 Troubleshooting

### Check Logs
```bash
tail -f homeguard.log
```

### Verify Database
```bash
sqlite3 homeguard.db "SELECT * FROM devices;"
```

### Manual Network Scan
```bash
curl http://192.168.2.1:8081/scan_network
```

### Emergency Restore
If system is stuck, manually set transparent mode:
```bash
curl -X POST http://192.168.2.1:8081/set_mode_to_transparent
```

## 📝 Development Notes

- Always run in TESTING mode during development
- Use the same `totp_secrets.json` from version-3-updates
- All iptables changes are logged to `homeguard.log`
- System automatically sets transparent mode on shutdown
- Frontend auto-refreshes device list every 30 seconds

## 🔄 Version History

### v4.0.0 (Current)
- Clean architecture with modular design
- FastAPI-based REST API
- Web-based device management dashboard
- Network device scanner
- Testing mode for safe development
- Automatic access expiration
- IOT device support
- Graceful shutdown handling
