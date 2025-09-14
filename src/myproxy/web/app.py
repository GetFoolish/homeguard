"""FastAPI web application for captive portal and admin interface."""

from fastapi import FastAPI, Request, Depends, HTTPException, Form, Cookie, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging
from datetime import datetime
from typing import Optional
from pathlib import Path
import qrcode
import io
import pyotp
import hashlib
import secrets

from ..database.connection import get_session, db_manager
from ..database.models import Device, AccessLog, FilterRule
from ..network.traffic_monitor import traffic_monitor
from ..auth.totp import totp_manager
from ..config.settings import settings
from ..phases.phase_manager import phase_manager

# Import gateway components
try:
    from ..gateway.config import GatewayConfig, GatewayMode
    from ..gateway.iptables_manager import IptablesManager
    GATEWAY_AVAILABLE = True
except ImportError:
    GATEWAY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="MyProxy Network Gateway",
    description="TOTP-based network access control system",
    version="0.1.0",
    docs_url="/admin/docs" if settings.debug else None,
    redoc_url="/admin/redoc" if settings.debug else None
)

@app.on_event("startup")
async def startup_event():
    """Initialize services and set up testing mode blocking if configured."""
    logger.info(f"Starting MyProxy with gateway_mode={settings.gateway_mode}")

    # If we're in TOTP testing mode, automatically block the testing IP
    if settings.gateway_mode == "totp_testing" and settings.testing_ip:
        logger.info(f"🔒 TOTP Testing Mode: Automatically blocking {settings.testing_ip}")
        try:
            # Generate a fake MAC for the testing IP (same logic as client info)
            fake_mac = f"test:{settings.testing_ip}"
            await traffic_monitor.block_device_traffic(fake_mac, settings.testing_ip)
            logger.info(f"✅ Successfully blocked traffic for testing IP {settings.testing_ip}")
        except Exception as e:
            logger.error(f"❌ Failed to block testing IP {settings.testing_ip}: {e}")

# Initialize Jinja2 templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Simple session management
admin_sessions = set()

def generate_session_token() -> str:
    """Generate a secure session token."""
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

def verify_admin_session(session_token: str = Cookie(None)) -> bool:
    """Verify if the admin session is valid."""
    return session_token and session_token in admin_sessions

def require_admin_auth(session_token: str = Cookie(None)):
    """Dependency to require admin authentication."""
    if not verify_admin_session(session_token):
        raise HTTPException(status_code=302, headers={"Location": "/admin/login"})

# Mount static files (we'll create the static directory later)
# app.mount("/static", StaticFiles(directory="static"), name="static")


def get_client_info(request: Request) -> dict:
    """Extract comprehensive client information from request."""
    # Try to get real client IP from forwarded headers first
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip() or
        request.headers.get("x-real-ip", "").strip() or
        request.headers.get("cf-connecting-ip", "").strip() or
        request.client.host
    )

    # Store both the direct connection IP and potential real IP
    direct_ip = request.client.host
    forwarded_ip = client_ip if client_ip != direct_ip else None

    # Get user agent for device fingerprinting
    user_agent = request.headers.get("user-agent", "")

    # Extract device type and browser info from user agent
    device_type = "Unknown"
    browser = "Unknown"
    os = "Unknown"

    if "Mobile" in user_agent or "Android" in user_agent or "iPhone" in user_agent:
        device_type = "Mobile"
    elif "iPad" in user_agent or "Tablet" in user_agent:
        device_type = "Tablet"
    elif "Windows" in user_agent or "Mac" in user_agent or "Linux" in user_agent:
        device_type = "Desktop/Laptop"

    # Parse browser info
    if "Chrome" in user_agent and "Safari" in user_agent:
        if "Edg" in user_agent:
            browser = "Microsoft Edge"
        elif "OPR" in user_agent or "Opera" in user_agent:
            browser = "Opera"
        else:
            browser = "Chrome"
    elif "Firefox" in user_agent:
        browser = "Firefox"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser = "Safari"

    # Parse OS info
    if "Windows NT" in user_agent:
        if "Windows NT 10.0" in user_agent:
            os = "Windows 10/11"
        elif "Windows NT 6.3" in user_agent:
            os = "Windows 8.1"
        elif "Windows NT 6.1" in user_agent:
            os = "Windows 7"
        else:
            os = "Windows"
    elif "Mac OS X" in user_agent or "macOS" in user_agent:
        os = "macOS"
    elif "Linux" in user_agent:
        if "Android" in user_agent:
            os = "Android"
        else:
            os = "Linux"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        os = "iOS"

    # Get additional headers
    accept_language = request.headers.get("accept-language", "")
    accept_encoding = request.headers.get("accept-encoding", "")
    referer = request.headers.get("referer", "")
    host = request.headers.get("host", "").split(":")[0]
    connection = request.headers.get("connection", "")

    # Detect double NAT situation and handle appropriately
    is_behind_nat = client_ip in ["192.168.2.135"]  # Known WiFi router IPs

    # Generate MAC address - use user agent hash for NAT'd devices to ensure uniqueness
    import hashlib
    if is_behind_nat:
        # For devices behind NAT router, use user agent + device type for unique identification
        mac_seed = f"NAT:{user_agent[:100]}:{device_type}"
        logger.info(f"🔍 Device behind NAT router {client_ip}, using enhanced fingerprinting")
    else:
        # Direct connection, use IP + user agent
        mac_seed = f"{client_ip}:{user_agent[:50]}"

    mac_hash = hashlib.md5(mac_seed.encode()).hexdigest()[:12]
    mac_address = ":".join([mac_hash[i:i+2] for i in range(0, 12, 2)])

    return {
        "mac_address": mac_address,
        "ip_address": client_ip,
        "direct_ip": direct_ip,
        "forwarded_ip": forwarded_ip,
        "user_agent": user_agent,
        "device_type": device_type,
        "browser": browser,
        "os": os,
        "accept_language": accept_language,
        "accept_encoding": accept_encoding,
        "referer": referer,
        "hostname": host or f"device-{client_ip.split('.')[-1]}",
        "connection": connection,
        "is_behind_nat": is_behind_nat,
        "nat_router_ip": direct_ip if is_behind_nat else None
    }


def get_client_mac(request: Request) -> str:
    """Extract client MAC address from request (backwards compatibility)."""
    return get_client_info(request)["mac_address"]


def should_enforce_totp(client_ip: str) -> bool:
    """Determine if TOTP authentication should be enforced for this IP."""
    if settings.emergency_mode:
        return False

    if settings.gateway_mode == "transparent":
        return False
    elif settings.gateway_mode == "totp_testing":
        return client_ip == settings.testing_ip
    elif settings.gateway_mode == "totp_enabled":
        return True

    return False


def show_transparent_access_page(client_info: dict) -> HTMLResponse:
    """Show transparent access page for devices not subject to TOTP."""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - Internet Access</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .success {{ color: #28a745; text-align: center; font-size: 28px; margin-bottom: 20px; }}
            .status-badge {{ background: #28a745; color: white; padding: 8px 16px; border-radius: 20px; display: inline-block; margin-bottom: 20px; }}
            .device-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .device-title {{ font-weight: bold; color: #495057; margin-bottom: 15px; font-size: 16px; }}
            .info-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 8px; font-size: 12px; }}
            .info-label {{ font-weight: bold; color: #495057; }}
            .info-value {{ color: #6c757d; font-family: monospace; word-break: break-all; }}
            .actions {{ text-align: center; margin-top: 20px; }}
            .btn {{ display: inline-block; padding: 10px 20px; margin: 5px; text-decoration: none; border-radius: 5px; font-weight: bold; background: #007bff; color: white; }}
            .mode-info {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; margin: 20px 0; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success">✓ Internet Access Active</div>
            <div style="text-align: center;">
                <span class="status-badge">Transparent Mode</span>
            </div>

            <div class="mode-info">
                <strong>Network Status:</strong> You have unrestricted internet access.<br>
                Mode: {settings.gateway_mode.title().replace('_', ' ')}
            </div>

            <div class="device-info">
                <div class="device-title">📱 Device Information</div>
                <div class="info-grid">
                    <div class="info-label">IP Address:</div>
                    <div class="info-value">{client_info['ip_address']}{' (via ' + client_info['direct_ip'] + ')' if client_info['forwarded_ip'] else ''}</div>

                    <div class="info-label">Connection:</div>
                    <div class="info-value">{'Direct' if not client_info['forwarded_ip'] else 'NAT via ' + client_info['direct_ip']}</div>

                    <div class="info-label">Device Type:</div>
                    <div class="info-value">{client_info['device_type']}</div>

                    <div class="info-label">Browser:</div>
                    <div class="info-value">{client_info['browser']}</div>

                    <div class="info-label">Operating System:</div>
                    <div class="info-value">{client_info['os']}</div>

                    <div class="info-label">Generated ID:</div>
                    <div class="info-value">{client_info['mac_address']}</div>
                </div>
            </div>

            <div class="actions">
                <a href="https://google.com" class="btn">Continue to Internet</a>
            </div>

            <p style="text-align: center; color: #666; font-size: 12px; margin-top: 20px;">
                This device is not subject to authentication in current mode.
            </p>
        </div>
    </body>
    </html>
    """)


@app.get("/", response_class=HTMLResponse)
async def captive_portal(request: Request, session: AsyncSession = Depends(get_session)):
    """Main captive portal landing page."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]
    client_ip = client_info["ip_address"]
    user_agent = request.headers.get("user-agent", "")

    # Debug current settings
    print(f"🔧 DEBUG: gateway_mode={settings.gateway_mode}, testing_ip={settings.testing_ip}, client_ip={client_ip}")
    logger.info(f"🔧 Current settings - gateway_mode: {settings.gateway_mode}, testing_ip: {settings.testing_ip}")

    # Check if TOTP enforcement applies to this device
    enforce_totp = should_enforce_totp(client_ip)
    print(f"📍 DEBUG: Device {client_ip} - TOTP enforcement check: {enforce_totp}")
    logger.info(f"📍 Device {client_ip} - TOTP enforcement check: {enforce_totp}")

    if not enforce_totp:
        logger.info(f"📍 Device {client_ip} - TOTP not enforced (mode: {settings.gateway_mode}, testing_ip: {settings.testing_ip})")
        return show_transparent_access_page(client_info)

    logger.info(f"🔐 Device {client_ip} - TOTP enforcement active")

    # For devices subject to TOTP testing, ensure traffic is blocked until authenticated
    print(f"🔧 DEBUG: About to block traffic for {client_ip} (MAC: {mac_address})")
    try:
        print(f"🔧 DEBUG: traffic_monitor object: {traffic_monitor}")
        print(f"🔧 DEBUG: Calling block_device_traffic with MAC={mac_address}, IP={client_ip}")

        await traffic_monitor.block_device_traffic(mac_address, client_ip)

        print(f"🚫 DEBUG: Successfully blocked traffic for device {client_ip} (MAC: {mac_address})")
        logger.info(f"🚫 Blocked traffic for unauthenticated device {client_ip}")
    except Exception as e:
        print(f"❌ DEBUG: FAILED to block traffic for {client_ip}: {type(e).__name__}: {e}")
        logger.error(f"Failed to block traffic for {client_ip}: {e}")
        import traceback
        print(f"❌ DEBUG: Traceback: {traceback.format_exc()}")

    # Check if device is already authorized
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        granted_time = device.access_granted_at or datetime.utcnow()
        expires_time = device.access_expires_at or datetime.utcnow()
        access_duration = device.access_duration or "unknown"
        
        # Debug logging for troubleshooting
        logger.info("=== DEBUG: Status Page Values ===")
        logger.info(f"MAC Address: {mac_address}")
        logger.info(f"Device Found: {device is not None}")
        logger.info(f"Access Valid: {device.is_access_valid if device else 'N/A'}")
        logger.info(f"Granted Time (raw): {device.access_granted_at}")
        logger.info(f"Expires Time (raw): {device.access_expires_at}")
        logger.info(f"Granted Time (used): {granted_time}")
        logger.info(f"Expires Time (used): {expires_time}")
        logger.info(f"Access Duration: {access_duration}")
        logger.info(f"Granted Formatted: {granted_time.strftime('%Y-%m-%dT%H:%M:%S') if granted_time else 'None'}")
        logger.info(f"Expires Formatted: {expires_time.strftime('%Y-%m-%dT%H:%M:%S') if expires_time else 'None'}")
        
        # Calculate time remaining for debugging
        if expires_time:
            time_left_seconds = int((expires_time - datetime.utcnow()).total_seconds())
            logger.info(f"Time Left (seconds): {time_left_seconds}")
            if time_left_seconds > 0:
                hours = time_left_seconds // 3600
                minutes = (time_left_seconds % 3600) // 60
                seconds = time_left_seconds % 60
                logger.info(f"Time Left (formatted): {hours}h {minutes}m {seconds}s")
            else:
                logger.info("Time Left: EXPIRED")
        logger.info("===================================")
        
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MyProxy - Internet Access Active</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .success {{ color: #28a745; text-align: center; font-size: 28px; margin-bottom: 20px; }}
                .status-badge {{ background: #28a745; color: white; padding: 8px 16px; border-radius: 20px; display: inline-block; margin-bottom: 20px; }}
                .access-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .info-row {{ display: flex; justify-content: space-between; margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #e9ecef; }}
                .info-label {{ font-weight: bold; color: #495057; }}
                .info-value {{ color: #6c757d; font-family: monospace; }}
                .countdown {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; font-size: 18px; font-weight: bold; }}
                .actions {{ text-align: center; margin-top: 20px; }}
                .btn {{ display: inline-block; padding: 10px 20px; margin: 5px; text-decoration: none; border-radius: 5px; font-weight: bold; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                .refresh-note {{ color: #666; font-size: 12px; text-align: center; margin-top: 10px; }}
            </style>
            <script>
                // Test if JavaScript is working at all
                console.log('JavaScript is running!');
                
                // Convert UTC times to local time - debug the exact strings being passed
                const grantedTimeStr = "{granted_time.strftime('%Y-%m-%dT%H:%M:%S')}Z";
                const expiresTimeStr = "{expires_time.strftime('%Y-%m-%dT%H:%M:%S')}Z";
                
                console.log('Granted Time String:', grantedTimeStr);
                console.log('Expires Time String:', expiresTimeStr);
                
                // Test if elements exist
                console.log('Granted element:', document.getElementById('granted-time'));
                console.log('Expires element:', document.getElementById('expires-time'));
                console.log('Time left element:', document.getElementById('time-left'));
                
                const grantedTimeUTC = new Date(grantedTimeStr);
                const expiresTimeUTC = new Date(expiresTimeStr);
                
                console.log('Parsed granted date:', grantedTimeUTC);
                console.log('Parsed expires date:', expiresTimeUTC);
                
                function updateTimes() {{
                    try {{
                        // Format times in local timezone
                        let grantedLocal = 'N/A';
                        let expiresLocal = 'N/A';
                        
                        if (!isNaN(grantedTimeUTC.getTime())) {{
                            grantedLocal = grantedTimeUTC.toLocaleString();
                        }}
                        
                        if (!isNaN(expiresTimeUTC.getTime())) {{
                            expiresLocal = expiresTimeUTC.toLocaleString();
                        }}
                        
                        document.getElementById('granted-time').textContent = grantedLocal;
                        document.getElementById('expires-time').textContent = expiresLocal;
                        
                        // Calculate time remaining
                        const now = new Date();
                        if (!isNaN(expiresTimeUTC.getTime())) {{
                            const timeLeft = Math.max(0, Math.floor((expiresTimeUTC - now) / 1000));
                            
                            if (timeLeft > 0) {{
                                const hours = Math.floor(timeLeft / 3600);
                                const minutes = Math.floor((timeLeft % 3600) / 60);
                                const seconds = timeLeft % 60;
                                
                                let timeLeftStr = '';
                                if (hours > 0) timeLeftStr += hours + 'h ';
                                if (minutes > 0 || hours > 0) timeLeftStr += minutes + 'm ';
                                timeLeftStr += seconds + 's';
                                
                                document.getElementById('time-left').textContent = timeLeftStr;
                                document.getElementById('countdown-container').style.background = '#d4edda';
                                document.getElementById('countdown-container').style.color = '#155724';
                                document.getElementById('countdown-container').textContent = 'Time Left: ' + timeLeftStr;
                            }} else {{
                                document.getElementById('time-left').textContent = 'Expired';
                                document.getElementById('countdown-container').style.background = '#f8d7da';
                                document.getElementById('countdown-container').style.color = '#721c24';
                                document.getElementById('countdown-container').textContent = 'Access Expired - Please Re-authenticate';
                                // Refresh page after 5 seconds if expired
                                setTimeout(() => location.reload(), 5000);
                            }}
                        }} else {{
                            document.getElementById('time-left').textContent = 'Unknown';
                            document.getElementById('countdown-container').textContent = 'Unable to calculate remaining time';
                        }}
                        
                    }} catch (error) {{
                        console.error('Error updating times:', error);
                        document.getElementById('granted-time').textContent = 'Error loading time';
                        document.getElementById('expires-time').textContent = 'Error loading time';
                        document.getElementById('time-left').textContent = 'Error';
                    }}
                }}
                
                // Wait for DOM to be loaded before running
                document.addEventListener('DOMContentLoaded', function() {{
                    console.log('DOM loaded, starting timer...');
                    updateTimes();
                    setInterval(updateTimes, 1000);
                }});
                
                // Also try running immediately in case DOMContentLoaded already fired
                if (document.readyState === 'loading') {{
                    // Document is still loading
                }} else {{
                    // Document is already loaded
                    console.log('DOM already loaded, starting timer...');
                    updateTimes();
                    setInterval(updateTimes, 1000);
                }}
            </script>
        </head>
        <body>
            <div class="container">
                <div class="success">✓ Internet Access Active</div>
                <div style="text-align: center;">
                    <span class="status-badge">Access Level: {access_duration}</span>
                </div>
                
                <div class="access-info">
                    <div class="info-row">
                        <span class="info-label">Granted:</span>
                        <span class="info-value" id="granted-time">Loading...</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Expires:</span>
                        <span class="info-value" id="expires-time">Loading...</span>
                    </div>
                    <div class="info-row" style="border-bottom: none;">
                        <span class="info-label">Time Left:</span>
                        <span class="info-value" id="time-left">Calculating...</span>
                    </div>
                </div>
                
                <div class="countdown" id="countdown-container">
                    Calculating remaining time...
                </div>
                
                <div class="actions">
                    <a href="https://google.com" class="btn btn-primary">Continue Browsing</a>
                    <a href="javascript:location.reload()" class="btn btn-secondary">Refresh Status</a>
                </div>
                
                <div class="refresh-note">
                    Status updates automatically every second
                </div>
            </div>
        </body>
        </html>
        """)
    
    # Show authentication form
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - Network Access</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
            .form-group {{ margin-bottom: 20px; }}
            label {{ display: block; margin-bottom: 5px; color: #555; font-weight: bold; }}
            input {{ width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 4px; font-size: 16px; }}
            button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }}
            button:hover {{ background: #0056b3; }}
            .info {{ background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; }}
            .error {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
            .device-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .device-title {{ font-weight: bold; color: #495057; margin-bottom: 15px; font-size: 16px; }}
            .info-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 8px; font-size: 12px; }}
            .info-label {{ font-weight: bold; color: #495057; }}
            .info-value {{ color: #6c757d; font-family: monospace; word-break: break-all; }}
            .client-data {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 10px; margin-top: 10px; }}
            .loading {{ color: #6c757d; font-style: italic; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Network Access Required</h1>
            <div class="info">
                <strong>Welcome!</strong> Enter your TOTP code to access the internet.
                Different codes provide different access durations.
            </div>

            <form method="post" action="/authenticate">
                <div class="form-group">
                    <label for="totp_code">TOTP Code:</label>
                    <input type="text" id="totp_code" name="totp_code" required
                           placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{{6}}">
                </div>
                <button type="submit">Connect to Internet</button>
            </form>

            <div class="device-info">
                <div class="device-title">📱 Device Information</div>
                <div class="info-grid">
                    <div class="info-label">IP Address:</div>
                    <div class="info-value">{client_info['ip_address']}{' (via ' + client_info['direct_ip'] + ')' if client_info['forwarded_ip'] else ''}</div>

                    <div class="info-label">Connection:</div>
                    <div class="info-value">{'Direct' if not client_info['forwarded_ip'] else 'NAT via ' + client_info['direct_ip']}</div>

                    <div class="info-label">Device Type:</div>
                    <div class="info-value">{client_info['device_type']}</div>

                    <div class="info-label">Browser:</div>
                    <div class="info-value">{client_info['browser']}</div>

                    <div class="info-label">Operating System:</div>
                    <div class="info-value">{client_info['os']}</div>

                    <div class="info-label">Language:</div>
                    <div class="info-value">{client_info['accept_language'][:20]}...</div>

                    <div class="info-label">Generated ID:</div>
                    <div class="info-value">{client_info['mac_address']}</div>

                    <div class="info-label">Screen:</div>
                    <div class="info-value loading" id="screen-info">Loading...</div>

                    <div class="info-label">Timezone:</div>
                    <div class="info-value loading" id="timezone-info">Loading...</div>

                    <div class="info-label">CPU Cores:</div>
                    <div class="info-value loading" id="cpu-info">Loading...</div>

                    <div class="info-label">Memory:</div>
                    <div class="info-value loading" id="memory-info">Loading...</div>

                    <div class="info-label">Platform:</div>
                    <div class="info-value loading" id="platform-info">Loading...</div>

                    <div class="info-label">Touch Support:</div>
                    <div class="info-value loading" id="touch-info">Loading...</div>

                    <div class="info-label">Online Status:</div>
                    <div class="info-value loading" id="online-info">Loading...</div>

                    <div class="info-label">Cookies Enabled:</div>
                    <div class="info-value loading" id="cookies-info">Loading...</div>

                    <div class="info-label" style="margin-top: 10px; border-top: 1px solid #e9ecef; padding-top: 8px;">All Headers:</div>
                    <div class="info-value" style="font-size: 10px; max-height: 100px; overflow-y: auto;">
                        {'<br>'.join([f"{k}: {v}" for k, v in dict(request.headers).items()])}
                    </div>
                </div>
            </div>

            <p style="text-align: center; color: #666; font-size: 12px; margin-top: 20px;">
                Need help? Contact your network administrator.
            </p>
        </div>

        <script>
            // Capture client-side device information
            document.addEventListener('DOMContentLoaded', function() {{
                // Screen information
                const screen = window.screen;
                const screenInfo = screen.width + 'x' + screen.height +
                    ' (' + screen.colorDepth + '-bit' +
                    (window.devicePixelRatio ? ', ' + window.devicePixelRatio + 'x pixel ratio' : '') + ')';
                document.getElementById('screen-info').textContent = screenInfo;

                // Timezone
                try {{
                    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                    document.getElementById('timezone-info').textContent = timezone;
                }} catch (e) {{
                    document.getElementById('timezone-info').textContent = 'Unavailable';
                }}

                // CPU cores
                const cpuCores = navigator.hardwareConcurrency || 'Unknown';
                document.getElementById('cpu-info').textContent = cpuCores + (cpuCores !== 'Unknown' ? ' cores' : '');

                // Memory (approximate)
                const memory = navigator.deviceMemory || 'Unknown';
                document.getElementById('memory-info').textContent = memory + (memory !== 'Unknown' ? ' GB' : '');

                // Platform
                document.getElementById('platform-info').textContent = navigator.platform || 'Unknown';

                // Touch support
                const touchPoints = navigator.maxTouchPoints || 0;
                document.getElementById('touch-info').textContent = touchPoints > 0 ? 'Yes (' + touchPoints + ' points)' : 'No';

                // Online status
                document.getElementById('online-info').textContent = navigator.onLine ? 'Online' : 'Offline';

                // Cookies enabled test
                document.cookie = 'testcookie=1';
                const cookiesEnabled = document.cookie.indexOf('testcookie=1') !== -1;
                document.getElementById('cookies-info').textContent = cookiesEnabled ? 'Yes' : 'No';
                if (cookiesEnabled) {{
                    document.cookie = 'testcookie=1; expires=Thu, 01-Jan-1970 00:00:01 GMT'; // Clean up
                }}
            }});
        </script>
    </body>
    </html>
    """)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Main landing page with application-layer blocking."""
    # Get client information
    client_info = get_client_info(request)
    client_ip = client_info["ip_address"]

    logger.info(f"🔧 DEBUG: gateway_mode={settings.gateway_mode}, testing_ip={settings.testing_ip}, client_ip={client_ip}")

    # Check if TOTP should be enforced for this device
    enforce_totp = should_enforce_totp(client_ip)
    logger.info(f"📍 DEBUG: Device {client_ip} - TOTP enforcement check: {enforce_totp}")

    if not enforce_totp:
        # Show transparent access page
        logger.info(f"✅ Allowing transparent access for device {client_ip}")
        return show_transparent_access_page(client_info)

    # Check if device is already authenticated
    async with db_manager.session_maker() as session:
        device = await session.get(Device, client_info["mac_address"])

        if device and device.is_access_valid:
            # Device is authenticated - show success page
            logger.info(f"✅ Device {client_ip} is already authenticated")
            return show_authenticated_success_page(client_info, device)

    # Device needs TOTP authentication - show login form
    logger.info(f"🔐 Device {client_ip} needs TOTP authentication")
    return show_totp_authentication_form(client_info)


def show_authenticated_success_page(client_info: dict, device) -> HTMLResponse:
    """Show success page for already authenticated devices."""
    granted_time = device.access_granted_at if device and device.access_granted_at else datetime.utcnow()
    expires_time = device.access_expires_at if device and device.access_expires_at else datetime.utcnow()
    access_duration = device.access_duration if device and device.access_duration else "unknown"

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - Access Active</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .success {{ color: #28a745; text-align: center; font-size: 28px; margin-bottom: 20px; }}
            .status-badge {{ background: #28a745; color: white; padding: 8px 16px; border-radius: 20px; display: inline-block; margin-bottom: 20px; }}
            .access-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .info-row {{ display: flex; justify-content: space-between; margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #e9ecef; }}
            .info-label {{ font-weight: bold; color: #495057; }}
            .info-value {{ color: #6c757d; font-family: monospace; }}
            .countdown {{ background: #d4edda; color: #155724; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; font-size: 18px; font-weight: bold; }}
            .actions {{ text-align: center; margin-top: 20px; }}
            .btn {{ display: inline-block; padding: 10px 20px; margin: 5px; text-decoration: none; border-radius: 5px; font-weight: bold; background: #007bff; color: white; }}
            .btn-secondary {{ background: #6c757d; }}
            .refresh-note {{ color: #666; font-size: 12px; text-align: center; margin-top: 10px; }}
        </style>
        <script>
            const grantedTimeUTC = new Date("{granted_time.isoformat()}Z");
            const expiresTimeUTC = new Date("{expires_time.isoformat()}Z");

            function updateTimes() {{
                document.getElementById('granted-time').textContent = grantedTimeUTC.toLocaleString();
                document.getElementById('expires-time').textContent = expiresTimeUTC.toLocaleString();

                const now = new Date();
                const timeLeft = Math.max(0, Math.floor((expiresTimeUTC - now) / 1000));

                if (timeLeft > 0) {{
                    const hours = Math.floor(timeLeft / 3600);
                    const minutes = Math.floor((timeLeft % 3600) / 60);
                    const seconds = timeLeft % 60;

                    let timeLeftStr = '';
                    if (hours > 0) timeLeftStr += hours + 'h ';
                    if (minutes > 0 || hours > 0) timeLeftStr += minutes + 'm ';
                    timeLeftStr += seconds + 's';

                    document.getElementById('time-left').textContent = timeLeftStr;
                }} else {{
                    document.getElementById('time-left').textContent = 'Expired';
                    document.getElementById('countdown-container').style.background = '#f8d7da';
                    document.getElementById('countdown-container').style.color = '#721c24';
                }}
            }}

            updateTimes();
            setInterval(updateTimes, 1000);
        </script>
    </head>
    <body>
        <div class="container">
            <div class="success">✓ Internet Access Active</div>
            <div style="text-align: center;">
                <span class="status-badge">Access Level: {access_duration}</span>
            </div>

            <div class="access-info">
                <div class="info-row">
                    <span class="info-label">Granted:</span>
                    <span class="info-value" id="granted-time">Loading...</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Expires:</span>
                    <span class="info-value" id="expires-time">Loading...</span>
                </div>
                <div class="info-row" style="border-bottom: none;">
                    <span class="info-label">Time Left:</span>
                    <span class="info-value" id="time-left">Calculating...</span>
                </div>
            </div>

            <div class="countdown" id="countdown-container">
                Calculating remaining time...
            </div>

            <div class="actions">
                <a href="https://google.com" class="btn btn-primary">Continue Browsing</a>
                <a href="javascript:location.reload()" class="btn btn-secondary">Refresh Status</a>
            </div>

            <div class="refresh-note">
                Status updates automatically every second
            </div>
        </div>
    </body>
    </html>
    """)


def show_totp_authentication_form(client_info: dict) -> HTMLResponse:
    """Show TOTP authentication form for devices that need authentication."""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - Network Access</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; text-align: center; margin-bottom: 30px; }}
            .form-group {{ margin-bottom: 20px; }}
            label {{ display: block; margin-bottom: 5px; color: #555; font-weight: bold; }}
            input {{ width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 4px; font-size: 16px; }}
            button {{ width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }}
            button:hover {{ background: #0056b3; }}
            .info {{ background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; }}
            .device-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .device-title {{ font-weight: bold; color: #495057; margin-bottom: 15px; font-size: 16px; }}
            .info-grid {{ display: grid; grid-template-columns: 1fr 2fr; gap: 8px; font-size: 12px; }}
            .info-label {{ font-weight: bold; color: #495057; }}
            .info-value {{ color: #6c757d; font-family: monospace; word-break: break-all; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Network Access Required</h1>
            <div class="info">
                <strong>Welcome!</strong> Enter your TOTP code to access the internet.
                Different codes provide different access durations.
            </div>

            <form method="post" action="/authenticate">
                <div class="form-group">
                    <label for="totp_code">TOTP Code:</label>
                    <input type="text" id="totp_code" name="totp_code" required
                           placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{{6}}">
                </div>
                <button type="submit">Connect to Internet</button>
            </form>

            <div class="device-info">
                <div class="device-title">📱 Device Information</div>
                <div class="info-grid">
                    <div class="info-label">IP Address:</div>
                    <div class="info-value">{client_info['ip_address']}</div>

                    <div class="info-label">Device Type:</div>
                    <div class="info-value">{client_info['device_type']}</div>

                    <div class="info-label">Browser:</div>
                    <div class="info-value">{client_info['browser']}</div>

                    <div class="info-label">Generated ID:</div>
                    <div class="info-value">{client_info['mac_address']}</div>
                </div>
            </div>

            <p style="text-align: center; color: #666; font-size: 12px; margin-top: 20px;">
                Need help? Contact your network administrator.
            </p>
        </div>
    </body>
    </html>
    """)


@app.post("/authenticate")
async def authenticate_device(
    request: Request,
    totp_code: str = Form(...),
    session: AsyncSession = Depends(get_session)
):
    """Handle TOTP authentication."""
    client_info = get_client_info(request)
    
    try:
        success, message = await traffic_monitor.authenticate_device(
            client_info["mac_address"], 
            totp_code, 
            client_info["user_agent"],
            device_info=client_info
        )
        
        if success:
            # Get device information to show access details
            async with db_manager.session_maker() as db_session:
                device = await db_session.get(Device, client_info["mac_address"])
                
                granted_time = device.access_granted_at if device and device.access_granted_at else datetime.utcnow()
                expires_time = device.access_expires_at if device and device.access_expires_at else datetime.utcnow()
                access_duration = device.access_duration if device and device.access_duration else "unknown"
            
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>MyProxy - Access Granted</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .success {{ color: #28a745; text-align: center; font-size: 28px; margin-bottom: 20px; }}
                    .status-badge {{ background: #28a745; color: white; padding: 8px 16px; border-radius: 20px; display: inline-block; margin-bottom: 20px; }}
                    .access-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                    .info-row {{ display: flex; justify-content: space-between; margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #e9ecef; }}
                    .info-label {{ font-weight: bold; color: #495057; }}
                    .info-value {{ color: #6c757d; font-family: monospace; }}
                    .countdown {{ background: #fff3cd; color: #856404; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; font-size: 18px; font-weight: bold; }}
                    .redirect {{ color: #666; font-size: 14px; text-align: center; margin-top: 20px; }}
                </style>
                <script>
                    // Convert UTC times to local time
                    const grantedTimeUTC = new Date("{granted_time.isoformat()}Z");
                    const expiresTimeUTC = new Date("{expires_time.isoformat()}Z");
                    
                    function updateTimes() {{
                        // Format times in local timezone
                        const grantedLocal = grantedTimeUTC.toLocaleString();
                        const expiresLocal = expiresTimeUTC.toLocaleString();
                        
                        document.getElementById('granted-time').textContent = grantedLocal;
                        document.getElementById('expires-time').textContent = expiresLocal;
                        
                        // Calculate time remaining
                        const now = new Date();
                        const timeLeft = Math.max(0, Math.floor((expiresTimeUTC - now) / 1000));
                        
                        if (timeLeft > 0) {{
                            const hours = Math.floor(timeLeft / 3600);
                            const minutes = Math.floor((timeLeft % 3600) / 60);
                            const seconds = timeLeft % 60;
                            
                            let timeLeftStr = '';
                            if (hours > 0) timeLeftStr += hours + 'h ';
                            if (minutes > 0 || hours > 0) timeLeftStr += minutes + 'm ';
                            timeLeftStr += seconds + 's';
                            
                            document.getElementById('time-left').textContent = timeLeftStr;
                            document.getElementById('countdown-container').style.background = '#d4edda';
                            document.getElementById('countdown-container').style.color = '#155724';
                        }} else {{
                            document.getElementById('time-left').textContent = 'Expired';
                            document.getElementById('countdown-container').style.background = '#f8d7da';
                            document.getElementById('countdown-container').style.color = '#721c24';
                        }}
                    }}
                    
                    // Update times immediately and then every second
                    updateTimes();
                    setInterval(updateTimes, 1000);

                    // Populate device information
                    document.addEventListener('DOMContentLoaded', function() {{
                        // Screen information
                        const screen = window.screen;
                        const screenInfo = screen.width + 'x' + screen.height +
                            ' (' + screen.colorDepth + '-bit' +
                            (window.devicePixelRatio ? ', ' + window.devicePixelRatio + 'x pixel ratio' : '') + ')';
                        document.getElementById('success-screen-info').textContent = screenInfo;

                        // Timezone
                        try {{
                            const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                            document.getElementById('success-timezone-info').textContent = timezone;
                        }} catch (e) {{
                            document.getElementById('success-timezone-info').textContent = 'Unavailable';
                        }}
                    }});

                    // Redirect to internet after 5 seconds
                    setTimeout(function() {{
                        window.location.href = 'https://google.com';
                    }}, 5000);
                </script>
            </head>
            <body>
                <div class="container">
                    <div class="success">✓ Internet Access Active</div>
                    <div style="text-align: center;">
                        <span class="status-badge">Access Level: {access_duration}</span>
                    </div>
                    
                    <div class="access-info">
                        <div class="info-row">
                            <span class="info-label">Granted:</span>
                            <span class="info-value" id="granted-time">Loading...</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Expires:</span>
                            <span class="info-value" id="expires-time">Loading...</span>
                        </div>
                        <div class="info-row" style="border-bottom: none;">
                            <span class="info-label">Time Left:</span>
                            <span class="info-value" id="time-left">Calculating...</span>
                        </div>
                    </div>
                    
                    <div class="countdown" id="countdown-container">
                        <span id="time-left-display">Calculating remaining time...</span>
                    </div>

                    <div class="access-info" style="margin-top: 20px;">
                        <div style="font-weight: bold; color: #495057; margin-bottom: 15px; font-size: 16px;">📱 Device Information</div>
                        <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 8px; font-size: 12px;">
                            <div style="font-weight: bold; color: #495057;">IP Address:</div>
                            <div style="color: #6c757d; font-family: monospace;">{client_info['ip_address']}{' (via ' + client_info['direct_ip'] + ')' if client_info['forwarded_ip'] else ''}</div>

                            <div style="font-weight: bold; color: #495057;">Connection:</div>
                            <div style="color: #6c757d; font-family: monospace;">{'Direct' if not client_info['forwarded_ip'] else 'NAT via ' + client_info['direct_ip']}</div>

                            <div style="font-weight: bold; color: #495057;">Device Type:</div>
                            <div style="color: #6c757d; font-family: monospace;">{client_info['device_type']}</div>

                            <div style="font-weight: bold; color: #495057;">Browser:</div>
                            <div style="color: #6c757d; font-family: monospace;">{client_info['browser']}</div>

                            <div style="font-weight: bold; color: #495057;">Operating System:</div>
                            <div style="color: #6c757d; font-family: monospace;">{client_info['os']}</div>

                            <div style="font-weight: bold; color: #495057;">Generated ID:</div>
                            <div style="color: #6c757d; font-family: monospace;">{client_info['mac_address']}</div>

                            <div style="font-weight: bold; color: #495057;">Screen:</div>
                            <div style="color: #6c757d; font-family: monospace; font-style: italic;" id="success-screen-info">Loading...</div>

                            <div style="font-weight: bold; color: #495057;">Timezone:</div>
                            <div style="color: #6c757d; font-family: monospace; font-style: italic;" id="success-timezone-info">Loading...</div>
                        </div>
                    </div>

                    <div class="redirect">
                        Redirecting to the internet in 5 seconds...<br>
                        Or <a href="https://google.com">click here to continue</a>
                    </div>
                </div>
            </body>
            </html>
            """)
        else:
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>MyProxy - Access Denied</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                    .container {{ max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .error {{ color: #dc3545; text-align: center; font-size: 24px; margin-bottom: 20px; }}
                    .message {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; text-align: center; }}
                    .back {{ text-align: center; margin-top: 20px; }}
                    a {{ color: #007bff; text-decoration: none; }}
                    a:hover {{ text-decoration: underline; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="error">✗ Access Denied</div>
                    <div class="message">
                        {message}
                    </div>
                    <div class="back">
                        <a href="/">Try Again</a>
                    </div>
                </div>
            </body>
            </html>
            """)
            
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MyProxy - System Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h2 style="color: #dc3545;">System Error</h2>
            <p>Please try again later or contact support.</p>
            <a href="/" style="color: #007bff;">Back to Login</a>
        </body>
        </html>
        """, status_code=500)


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    """Admin login page requiring forever TOTP."""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy Admin Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.1);
                width: 100%;
                max-width: 400px;
            }
            h1 {
                text-align: center;
                color: #333;
                margin-bottom: 30px;
                font-size: 28px;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                font-size: 14px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: bold;
                color: #555;
            }
            input[type="text"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 6px;
                font-size: 18px;
                text-align: center;
                letter-spacing: 2px;
                box-sizing: border-box;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                width: 100%;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
                font-weight: bold;
            }
            button:hover {
                opacity: 0.9;
            }
            .back-link {
                text-align: center;
                margin-top: 20px;
            }
            .back-link a {
                color: #667eea;
                text-decoration: none;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 Admin Access</h1>
            <p class="subtitle">Enter your Admin TOTP code (Forever duration)</p>
            
            <form action="/admin/authenticate" method="post">
                <div class="form-group">
                    <label for="totp_code">Admin TOTP Code:</label>
                    <input type="text" id="totp_code" name="totp_code" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required autocomplete="off">
                </div>
                <button type="submit">Access Admin Panel</button>
            </form>
            
            <div class="back-link">
                <a href="/">← Back to Portal</a>
            </div>
        </div>
    </body>
    </html>
    """)


@app.post("/admin/authenticate")
async def admin_authenticate(totp_code: str = Form(...)):
    """Authenticate admin using forever TOTP code."""
    try:
        # Validate TOTP code specifically for 'forever' duration
        validation_result = totp_manager.validate_code(totp_code)
        
        if not validation_result:
            return HTMLResponse("""
            <!DOCTYPE html>
            <html>
            <head><title>Admin Login Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc3545;">❌ Access Denied</h1>
                <p>Invalid admin TOTP code.</p>
                <a href="/admin/login" style="color: #007bff;">Try Again</a>
            </body>
            </html>
            """, status_code=401)
        
        duration_key, duration_seconds = validation_result
        
        # Only allow 'forever' TOTP codes for admin access
        if duration_key != 'forever':
            return HTMLResponse("""
            <!DOCTYPE html>
            <html>
            <head><title>Admin Login Failed</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1 style="color: #dc3545;">❌ Access Denied</h1>
                <p>Admin access requires Forever TOTP code.</p>
                <p style="color: #666;">You provided: {}</p>
                <a href="/admin/login" style="color: #007bff;">Try Again</a>
            </body>
            </html>
            """.format(duration_key.replace('_', ' ').title()), status_code=403)
        
        # Generate session token and set cookie
        session_token = generate_session_token()
        admin_sessions.add(session_token)
        
        response = RedirectResponse(url="/admin", status_code=302)
        response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=3600)  # 1 hour
        
        logger.info("Admin authenticated successfully")
        return response
        
    except Exception as e:
        logger.error(f"Admin authentication error: {e}")
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Admin Login Error</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">❌ Authentication Error</h1>
            <p>System error during authentication.</p>
            <a href="/admin/login" style="color: #007bff;">Try Again</a>
        </body>
        </html>
        """, status_code=500)


@app.get("/admin/logout")
async def admin_logout(session_token: str = Cookie(None)):
    """Logout admin and invalidate session."""
    if session_token and session_token in admin_sessions:
        admin_sessions.remove(session_token)
    
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("session_token")
    return response


@app.get("/admin")
async def admin_panel(request: Request, session_token: str = Cookie(None)):
    """Admin panel landing page - requires authentication."""
    # Check if user is authenticated
    if not verify_admin_session(session_token):
        return RedirectResponse(url="/admin/login", status_code=302)
    
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy Admin Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .nav { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .nav-item { padding: 20px; background: #007bff; color: white; text-align: center; border-radius: 4px; text-decoration: none; }
            .nav-item:hover { background: #0056b3; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
            .stat-card { padding: 15px; background: #e7f3ff; border-radius: 4px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>MyProxy Admin Panel</h1>
                <p>Network Gateway Management</p>
            </div>
            
            <div class="nav">
                <a href="/admin/gateway" class="nav-item">Gateway Control</a>
                <a href="/admin/devices" class="nav-item">Device Management</a>
                <a href="/admin/totp" class="nav-item">TOTP Codes</a>
                <a href="/admin/qr" class="nav-item">QR Codes</a>
                <a href="/admin/logs" class="nav-item">Access Logs</a>
                <a href="/admin/filters" class="nav-item">Content Filters</a>
                <a href="/admin/logout" class="nav-item" style="background: #dc3545;">Logout</a>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Connected Devices</h3>
                    <p id="device-count">Loading...</p>
                </div>
                <div class="stat-card">
                    <h3>Active Sessions</h3>
                    <p id="session-count">Loading...</p>
                </div>
                <div class="stat-card">
                    <h3>System Status</h3>
                    <p id="system-status">Loading...</p>
                </div>
            </div>
        </div>
        
        <script>
            // Simple stats loading simulation
            document.getElementById('device-count').textContent = '0';
            document.getElementById('session-count').textContent = '0';
            document.getElementById('system-status').textContent = 'Running';
        </script>
    </body>
    </html>
    """)


@app.get("/admin/totp")
async def admin_totp_codes(_auth: None = Depends(require_admin_auth)):
    """Admin page showing current TOTP codes."""
    current_codes = totp_manager.generate_current_codes()
    time_remaining = totp_manager.get_time_remaining()
    
    codes_html = ""
    for duration, code in current_codes.items():
        codes_html += f"""
        <div class="code-card">
            <h3>{duration.replace('_', ' ').title()}</h3>
            <div class="code">{code}</div>
        </div>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - TOTP Codes</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .timer {{ text-align: center; font-size: 18px; color: #dc3545; margin-bottom: 20px; }}
            .codes {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
            .code-card {{ padding: 20px; background: #e7f3ff; border-radius: 8px; text-align: center; }}
            .code {{ font-size: 24px; font-weight: bold; color: #007bff; font-family: monospace; margin: 10px 0; }}
            .back {{ text-align: center; margin-top: 30px; }}
            .back a {{ color: #007bff; text-decoration: none; }}
        </style>
        <script>
            let timeRemaining = {time_remaining};
            function updateTimer() {{
                document.getElementById('timer').textContent = 'Codes refresh in: ' + timeRemaining + 's';
                timeRemaining--;
                if (timeRemaining < 0) {{
                    location.reload(); // Refresh page when codes change
                }}
            }}
            setInterval(updateTimer, 1000);
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Current TOTP Codes</h1>
                <div id="timer" class="timer">Codes refresh in: {time_remaining}s</div>
            </div>
            
            <div class="codes">
                {codes_html}
            </div>
            
            <div class="back">
                <a href="/admin">← Back to Admin Panel</a>
            </div>
        </div>
    </body>
    </html>
    """)


@app.get("/admin/devices")
async def admin_devices(session: AsyncSession = Depends(get_session), _auth: None = Depends(require_admin_auth)):
    """Admin page for device management."""
    # Get all devices from database
    stmt = select(Device).order_by(Device.last_seen.desc())
    result = await session.execute(stmt)
    devices = result.scalars().all()
    
    devices_html = ""
    for device in devices:
        status_color = "#28a745" if device.is_access_valid else "#6c757d"
        status_text = "Active" if device.is_access_valid else "Inactive"
        
        # Revoke button (only show for active devices)
        revoke_button = ""
        if device.is_access_valid:
            revoke_button = f'<button onclick="revokeAccess(\'{device.mac_address}\')" style="background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px;">Revoke</button>'
        
        devices_html += f"""
        <tr>
            <td title="{device.mac_address}">{device.mac_address[:12]}...</td>
            <td>{device.ip_address or 'N/A'}</td>
            <td>{device.hostname or 'Unknown'}</td>
            <td>{device.device_type or 'Unknown'}</td>
            <td><span style="color: {status_color};">{status_text}</span></td>
            <td>{device.access_duration or 'None'}</td>
            <td>{device.last_seen.strftime('%m/%d %H:%M') if device.last_seen else 'Never'}</td>
            <td>{revoke_button}</td>
        </tr>
        """
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy - Device Management</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; font-weight: bold; }}
            .back {{ text-align: center; margin-top: 30px; }}
            .back a {{ color: #007bff; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Connected Devices</h1>
            
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Device Type</th>
                        <th>Status</th>
                        <th>Access Level</th>
                        <th>Last Seen</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {devices_html}
                </tbody>
            </table>
            
            <div class="back">
                <a href="/admin">← Back to Admin Panel</a>
            </div>
        </div>
        
        <script>
            async function revokeAccess(macAddress) {{
                if (!confirm(`Are you sure you want to revoke access for device ${{macAddress}}?`)) {{
                    return;
                }}
                
                try {{
                    const response = await fetch('/admin/devices/revoke', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/x-www-form-urlencoded',
                        }},
                        body: `mac_address=${{encodeURIComponent(macAddress)}}`
                    }});
                    
                    const result = await response.json();
                    
                    if (result.success) {{
                        alert('Device access revoked successfully');
                        location.reload();
                    }} else {{
                        alert(`Failed to revoke access: ${{result.message}}`);
                    }}
                }} catch (error) {{
                    alert('Error revoking access: ' + error.message);
                }}
            }}
        </script>
    </body>
    </html>
    """)


@app.post("/admin/devices/revoke")
async def revoke_device_access(
    mac_address: str = Form(...),
    session: AsyncSession = Depends(get_session),
    _auth: None = Depends(require_admin_auth)
):
    """Revoke access for a specific device."""
    try:
        # Find the device in the database
        stmt = select(Device).where(Device.mac_address == mac_address)
        result = await session.execute(stmt)
        device = result.scalar_one_or_none()
        
        if not device:
            return JSONResponse({
                "success": False,
                "message": "Device not found"
            }, status_code=404)
        
        # Revoke access
        device.revoke_access()
        await session.commit()
        
        # Also revoke from traffic monitor (pass IP address for efficiency)
        await traffic_monitor.revoke_device_access(mac_address, device.ip_address)
        
        logger.info(f"Admin revoked access for device: {mac_address}")
        
        return JSONResponse({
            "success": True,
            "message": "Device access revoked successfully"
        })
        
    except Exception as e:
        logger.error(f"Error revoking device access: {e}")
        await session.rollback()
        return JSONResponse({
            "success": False,
            "message": f"Error revoking access: {str(e)}"
        }, status_code=500)


@app.get("/admin/qr", response_class=HTMLResponse)
async def qr_codes_page(_auth: None = Depends(require_admin_auth)):
    """QR codes page with duration dropdown."""
    durations = list(totp_manager._totp_generators.keys())
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MyProxy QR Codes</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #333;
                text-align: center;
                margin-bottom: 30px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                margin-bottom: 8px;
                font-weight: bold;
                color: #555;
            }}
            select {{
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
            }}
            .qr-container {{
                text-align: center;
                margin-top: 30px;
                padding: 20px;
                background: #fafafa;
                border-radius: 8px;
            }}
            .qr-info {{
                margin-top: 15px;
                font-size: 14px;
                color: #666;
            }}
            .secret-code {{
                font-family: monospace;
                background: #e8e8e8;
                padding: 8px;
                border-radius: 4px;
                margin: 10px 0;
                word-break: break-all;
            }}
            .current-code {{
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                margin: 15px 0;
            }}
            button {{
                background-color: #2196F3;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 20px;
            }}
            button:hover {{
                background-color: #1976D2;
            }}
            .back-link {{
                display: inline-block;
                margin-bottom: 20px;
                color: #2196F3;
                text-decoration: none;
            }}
            .back-link:hover {{
                text-decoration: underline;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/admin" class="back-link">← Back to Admin</a>
            <h1>MyProxy TOTP QR Codes</h1>
            
            <div class="form-group">
                <label for="duration">Select Duration:</label>
                <select id="duration" onchange="showQRCode()">
                    <option value="">Choose a duration...</option>
                    {' '.join(f'<option value="{d}">{d}</option>' for d in durations)}
                </select>
            </div>
            
            <div id="qr-display" class="qr-container" style="display: none;">
                <div id="qr-content"></div>
            </div>
        </div>
        
        <script>
            async function showQRCode() {{
                const duration = document.getElementById('duration').value;
                const display = document.getElementById('qr-display');
                const content = document.getElementById('qr-content');
                
                if (!duration) {{
                    display.style.display = 'none';
                    return;
                }}
                
                try {{
                    const response = await fetch(`/admin/qr/${{duration}}`);
                    const data = await response.json();
                    
                    content.innerHTML = `
                        <h3>Duration: ${{duration}}</h3>
                        <img src="/admin/qr/${{duration}}/image" alt="QR Code" style="max-width: 300px;">
                        <div class="qr-info">
                            <div class="current-code">Current Code: ${{data.current_code}}</div>
                            <div>Secret: <div class="secret-code">${{data.secret}}</div></div>
                            <div style="margin-top: 15px; font-size: 12px;">
                                Scan this QR code with Google Authenticator, Authy, or any TOTP app
                            </div>
                        </div>
                    `;
                    
                    display.style.display = 'block';
                }} catch (error) {{
                    content.innerHTML = '<div style="color: red;">Error loading QR code</div>';
                    display.style.display = 'block';
                }}
            }}
            
            // Refresh current code every 30 seconds
            setInterval(() => {{
                const duration = document.getElementById('duration').value;
                if (duration) {{
                    showQRCode();
                }}
            }}, 30000);
        </script>
    </body>
    </html>
    """)


@app.get("/admin/qr/{duration}")
async def get_qr_info(duration: str, _auth: None = Depends(require_admin_auth)):
    """Get QR code information for a specific duration."""
    if duration not in totp_manager._totp_generators:
        raise HTTPException(status_code=404, detail="Duration not found")
    
    secrets = totp_manager.get_generator_secrets()
    secret = secrets[duration]
    
    # Generate current TOTP code
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    
    return JSONResponse({
        "duration": duration,
        "secret": secret,
        "current_code": current_code
    })


@app.get("/admin/qr/{duration}/image")
async def get_qr_image(duration: str, _auth: None = Depends(require_admin_auth)):
    """Generate QR code image for a specific duration."""
    if duration not in totp_manager._totp_generators:
        raise HTTPException(status_code=404, detail="Duration not found")
    
    secrets = totp_manager.get_generator_secrets()
    secret = secrets[duration]
    
    # Create TOTP instance and generate QR code
    totp = pyotp.TOTP(secret)
    qr_url = totp.provisioning_uri(
        name=f"MyProxy-{duration}",
        issuer_name="MyProxy Gateway"
    )
    
    # Generate QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to bytes
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return StreamingResponse(img_bytes, media_type="image/png")


@app.get("/admin/gateway")
async def admin_gateway_control(request: Request, _auth: None = Depends(require_admin_auth)):
    """Gateway mode control panel."""
    if not GATEWAY_AVAILABLE:
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Gateway Not Available</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">Gateway Control Not Available</h1>
            <p>Gateway components are not installed or configured.</p>
            <a href="/admin" style="color: #007bff;">← Back to Admin Panel</a>
        </body>
        </html>
        """)
    
    try:
        gateway_config = GatewayConfig()
        current_mode = gateway_config.get_mode()
        is_emergency = gateway_config.is_emergency_mode()
        interfaces = gateway_config.get_network_interfaces()
        ports = gateway_config.get_service_ports()
        
        iptables_manager = IptablesManager(gateway_config)
        authenticated_devices = iptables_manager.list_authenticated_devices()
        
        mode_color = "#28a745" if current_mode == GatewayMode.TRANSPARENT else "#007bff"
        emergency_warning = ""
        if is_emergency:
            emergency_warning = """
            <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #f5c6cb;">
                <strong>⚠️ EMERGENCY MODE ACTIVE</strong><br>
                Gateway is in emergency transparent mode. All traffic is allowed.
            </div>
            """
        
        authenticated_devices_html = ""
        if current_mode == GatewayMode.TOTP_ENABLED and authenticated_devices:
            authenticated_devices_html = f"""
            <div class="info-section">
                <h3>Authenticated Devices ({len(authenticated_devices)})</h3>
                <div class="device-list">
                    {''.join(f'<div class="device-item">{mac}</div>' for mac in authenticated_devices)}
                </div>
            </div>
            """
        
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>MyProxy - Gateway Control</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .back-link {{ display: inline-block; margin-bottom: 20px; color: #007bff; text-decoration: none; }}
                .back-link:hover {{ text-decoration: underline; }}
                .status-section {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .mode-indicator {{ display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; background: {mode_color}; }}
                .mode-controls {{ margin: 20px 0; }}
                .mode-button {{ padding: 12px 24px; margin: 10px 5px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; }}
                .mode-button.transparent {{ background: #28a745; color: white; }}
                .mode-button.totp {{ background: #007bff; color: white; }}
                .mode-button.emergency {{ background: #dc3545; color: white; }}
                .mode-button:hover {{ opacity: 0.9; }}
                .mode-button:disabled {{ background: #6c757d; cursor: not-allowed; }}
                .info-section {{ margin: 20px 0; padding: 15px; background: #e7f3ff; border-radius: 8px; }}
                .info-row {{ display: flex; justify-content: space-between; margin: 8px 0; }}
                .info-label {{ font-weight: bold; color: #495057; }}
                .info-value {{ color: #6c757d; font-family: monospace; }}
                .device-list {{ margin-top: 10px; }}
                .device-item {{ padding: 8px; background: white; margin: 5px 0; border-radius: 4px; font-family: monospace; }}
                .actions {{ text-align: center; margin: 20px 0; }}
                .restart-note {{ color: #666; font-size: 14px; text-align: center; margin-top: 10px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/admin" class="back-link">← Back to Admin Panel</a>
                <h1>Gateway Control</h1>
                
                {emergency_warning}
                
                <div class="status-section">
                    <h2>Current Status</h2>
                    <div class="info-row">
                        <span class="info-label">Mode:</span>
                        <span class="mode-indicator">{current_mode.value.replace('_', ' ').title()}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">WAN Interface:</span>
                        <span class="info-value">{interfaces['wan']}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">LAN Interface:</span>
                        <span class="info-value">{interfaces['lan']}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Admin Port:</span>
                        <span class="info-value">{ports['admin']}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">SSH Port:</span>
                        <span class="info-value">{ports['ssh']}</span>
                    </div>
                </div>
                
                {authenticated_devices_html}
                
                <div class="mode-controls">
                    <h3>Gateway Mode Control</h3>
                    <p>Select the gateway operating mode:</p>
                    
                    <div class="actions">
                        <button class="mode-button transparent" 
                                onclick="setMode('transparent')"
                                {'disabled' if current_mode == GatewayMode.TRANSPARENT and not is_emergency else ''}>
                            Transparent Mode
                        </button>
                        
                        <button class="mode-button totp" 
                                onclick="setMode('totp_enabled')"
                                {'disabled' if current_mode == GatewayMode.TOTP_ENABLED and not is_emergency else ''}>
                            TOTP Authentication
                        </button>
                        
                        <button class="mode-button emergency" 
                                onclick="enableEmergency()"
                                {'disabled' if is_emergency else ''}>
                            Emergency Transparent
                        </button>
                    </div>
                    
                    <div class="restart-note">
                        Note: Mode changes require service restart to take effect
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>Mode Descriptions</h3>
                    <p><strong>Transparent Mode:</strong> All traffic passes through without blocking. Basic bridge functionality.</p>
                    <p><strong>TOTP Authentication:</strong> Block all traffic until TOTP authentication. Devices need to authenticate to access internet.</p>
                    <p><strong>Emergency Transparent:</strong> Immediate bypass of all blocking. Use for emergency access.</p>
                </div>
            </div>
            
            <script>
                async function setMode(mode) {{
                    if (!confirm(`Are you sure you want to switch to ${{mode.replace('_', ' ')}} mode?`)) {{
                        return;
                    }}
                    
                    try {{
                        const response = await fetch('/admin/gateway/set-mode', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/x-www-form-urlencoded',
                            }},
                            body: `mode=${{encodeURIComponent(mode)}}`
                        }});
                        
                        const result = await response.json();
                        
                        if (result.success) {{
                            alert(`Gateway mode set to: ${{mode.replace('_', ' ')}}\\n\\nRestart the service to apply changes.`);
                            location.reload();
                        }} else {{
                            alert(`Failed to set mode: ${{result.message}}`);
                        }}
                    }} catch (error) {{
                        alert('Error setting mode: ' + error.message);
                    }}
                }}
                
                async function enableEmergency() {{
                    if (!confirm('Are you sure you want to enable EMERGENCY TRANSPARENT mode?\\n\\nThis will immediately allow all traffic without authentication!')) {{
                        return;
                    }}
                    
                    try {{
                        const response = await fetch('/admin/gateway/emergency', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/x-www-form-urlencoded',
                            }}
                        }});
                        
                        const result = await response.json();
                        
                        if (result.success) {{
                            alert('Emergency transparent mode enabled!\\n\\nRestart the service to apply changes.');
                            location.reload();
                        }} else {{
                            alert(`Failed to enable emergency mode: ${{result.message}}`);
                        }}
                    }} catch (error) {{
                        alert('Error enabling emergency mode: ' + error.message);
                    }}
                }}
            </script>
        </body>
        </html>
        """)
        
    except Exception as e:
        logger.error(f"Error in gateway control panel: {e}")
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Gateway Control Error</title></head>
        <body style="font-family: Arial; text-align: center; padding: 50px;">
            <h1 style="color: #dc3545;">Gateway Control Error</h1>
            <p>Error loading gateway status: {str(e)}</p>
            <a href="/admin" style="color: #007bff;">← Back to Admin Panel</a>
        </body>
        </html>
        """, status_code=500)


@app.post("/admin/gateway/set-mode")
async def set_gateway_mode(mode: str = Form(...), _auth: None = Depends(require_admin_auth)):
    """Set gateway mode."""
    if not GATEWAY_AVAILABLE:
        return JSONResponse({"success": False, "message": "Gateway not available"}, status_code=503)
    
    try:
        gateway_mode = GatewayMode(mode.lower())
        gateway_config = GatewayConfig()
        gateway_config.set_mode(gateway_mode)
        
        logger.info(f"Admin set gateway mode to: {gateway_mode.value}")
        
        return JSONResponse({
            "success": True,
            "message": f"Gateway mode set to {gateway_mode.value}",
            "mode": gateway_mode.value
        })
        
    except ValueError:
        return JSONResponse({
            "success": False,
            "message": f"Invalid mode: {mode}"
        }, status_code=400)
    except Exception as e:
        logger.error(f"Error setting gateway mode: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error setting mode: {str(e)}"
        }, status_code=500)


@app.post("/admin/gateway/emergency")
async def enable_emergency_mode(_auth: None = Depends(require_admin_auth)):
    """Enable emergency transparent mode."""
    if not GATEWAY_AVAILABLE:
        return JSONResponse({"success": False, "message": "Gateway not available"}, status_code=503)
    
    try:
        gateway_config = GatewayConfig()
        gateway_config.enable_emergency_mode()
        
        logger.warning("Admin enabled emergency transparent mode")
        
        return JSONResponse({
            "success": True,
            "message": "Emergency transparent mode enabled"
        })
        
    except Exception as e:
        logger.error(f"Error enabling emergency mode: {e}")
        return JSONResponse({
            "success": False,
            "message": f"Error enabling emergency mode: {str(e)}"
        }, status_code=500)


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    try:
        db_healthy = await db_manager.health_check()
        return JSONResponse({
            "status": "healthy" if db_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }, status_code=500)


@app.get("/blocked", response_class=HTMLResponse)
async def content_blocked_page(
    request: Request, 
    url: str = Query("unknown", description="Blocked URL"),
    reason: str = Query("Content blocked by security policy", description="Block reason"),
    rule_type: str = Query("policy", description="Rule type that blocked the content"),
    pattern: str = Query("", description="Pattern that matched"),
    client_mac: str = Query("", description="Client MAC address")
):
    """Show content blocked splash screen."""
    try:
        # Get current phase info
        current_phase = phase_manager.get_current_phase()
        phase_info = phase_manager.get_phase_info(current_phase)
        
        return templates.TemplateResponse("content_blocked.html", {
            "request": request,
            "blocked_url": url,
            "block_reason": reason,
            "rule_type": rule_type,
            "rule_pattern": pattern,
            "client_mac": client_mac or get_client_mac(request),
            "block_time": datetime.utcnow().isoformat(),
            "current_phase": current_phase,
            "phase_name": phase_info.get("name", f"Phase {current_phase}")
        })
        
    except Exception as e:
        logger.error(f"Error rendering content blocked page: {e}")
        return HTMLResponse(f"<h1>Content Blocked</h1><p>URL: {url}</p><p>Reason: {reason}</p>", status_code=200)


# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("Starting MyProxy web application")
    await db_manager.initialize()


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down MyProxy web application")