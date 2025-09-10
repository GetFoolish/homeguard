# MyProxy Deployment Guide

## Quick Start (Raspberry Pi Local Testing)

### 1. Deploy to Pi
```bash
# From your Mac
git push origin main  # Triggers auto-deployment via GitHub Actions

# Or deploy manually
scp -r . raspberrypi@192.168.4.100:myProxy/
ssh raspberrypi@192.168.4.100 'cd myProxy && ./scripts/deploy.sh'
```

### 2. Test Locally on Pi
```bash
ssh raspberrypi@192.168.4.100
cd myProxy
sudo ./scripts/test-local.sh
```

### 3. Access Admin Interface
- URL: http://192.168.4.100:8080
- Authenticate with TOTP code
- Test traffic blocking/allowing

## Local Testing Mode

The Pi is now configured for **local testing mode** where:
- MyProxy intercepts the Pi's own traffic
- Perfect for testing authentication and blocking
- Same containers used for production inline deployment

### Testing Commands (on Pi)
```bash
# Should be intercepted by MyProxy
curl google.com

# Should be blocked (unauthenticated)
curl youtube.com  

# Admin interface (should work)
curl localhost:8080

# After authentication via web interface
curl google.com    # Should work
curl youtube.com   # Should still be blocked
```

## Production Inline Deployment

### Hardware Setup
1. **ISP Router** → **Pi eth0** → **Pi USB-Ethernet** → **WiFi Router WAN**
2. Pi intercepts ALL household traffic transparently
3. Same containers, different network routing

### Switch to Inline Mode
```bash
ssh raspberrypi@192.168.4.100
sudo ./scripts/setup-inline.sh  # TODO: Create this script
```

## GitHub Actions CI/CD

### Setup SSH Key
1. Generate SSH key pair:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/myproxy_deploy
   ```

2. Add public key to Pi:
   ```bash
   ssh-copy-id -i ~/.ssh/myproxy_deploy.pub raspberrypi@192.168.4.100
   ```

3. Add private key to GitHub secrets:
   - Go to GitHub repo → Settings → Secrets → Actions
   - Add `PI_SSH_KEY` with private key content

### Auto-Deployment
- Push to `main` branch triggers automatic deployment
- Manual trigger available in GitHub Actions tab
- Health checks verify deployment success

## Service Management

### Systemd Commands
```bash
# Status
sudo systemctl status myproxy-dual

# Logs
sudo journalctl -u myproxy-dual -f

# Restart
sudo systemctl restart myproxy-dual

# Stop
sudo systemctl stop myproxy-dual
```

### Docker Commands
```bash
# Container status
docker-compose -f docker-compose.pi.yml ps

# Logs
docker-compose -f docker-compose.pi.yml logs -f

# Rebuild
docker-compose -f docker-compose.pi.yml build --no-cache

# Restart containers
docker-compose -f docker-compose.pi.yml restart
```

## Troubleshooting

### Service Won't Start
1. Check logs: `sudo journalctl -u myproxy-dual -f`
2. Check Docker: `docker ps -a`
3. Check mode config: `cat /etc/myproxy/mode.conf`
4. Manual start: `cd myProxy && docker-compose -f docker-compose.pi.yml up`

### Traffic Not Intercepted
1. Check iptables: `sudo iptables -t nat -L OUTPUT`
2. Re-run setup: `sudo ./scripts/setup-local-interception.sh`
3. Check proxy settings: `curl --proxy localhost:8888 google.com`

### Admin Interface Not Accessible
1. Check container: `docker ps | grep myproxy`
2. Check port binding: `netstat -tlnp | grep 8080`
3. Check firewall: `sudo ufw status`

## Current Status ✅

- ✅ **Local Testing Mode**: Pi intercepts own traffic
- ✅ **GitHub Actions**: Auto-deployment on push
- ✅ **Service Management**: Systemd service with auto-restart
- ✅ **Container Health**: Health checks and logging
- 🔄 **Inline Mode**: TODO - Create inline deployment script

## Next Steps

1. **Test Authentication**: Verify TOTP workflow on Pi
2. **Create Inline Script**: For production deployment
3. **USB Ethernet Detection**: Auto-detect second interface
4. **Monitoring**: Add alerting for service failures

**Pi Access**: `ssh raspberrypi@192.168.4.100`  
**Admin Interface**: http://192.168.4.100:8080