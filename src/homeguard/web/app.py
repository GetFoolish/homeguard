"""FastAPI web application for HomeguardGuard captive portal and admin interface."""

import hashlib
import logging
import secrets
from fastapi import FastAPI, Request, Depends, HTTPException, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from ..database.connection import get_session, db_manager
from ..database.models import Device, AccessLog, FilterRule
from ..network.traffic_monitor import traffic_monitor
from ..auth.totp import totp_manager
from ..config.settings import settings
from ..phases.phase_manager import phase_manager

# Import route modules
from .routes.captive_portal import router as captive_portal_router
from .routes.connectivity import router as connectivity_router

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="HomeguardGuard Network Gateway",
    description="TOTP-based network access control system with captive portal",
    version="3.0.0",
    docs_url="/admin/docs" if settings.debug else None,
    redoc_url="/admin/redoc" if settings.debug else None
)

# Include route modules
app.include_router(captive_portal_router)
app.include_router(connectivity_router)

# Initialize Jinja2 templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Simple session management for admin
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


@app.on_event("startup")
async def startup_event():
    """Initialize services and set up testing mode blocking if configured."""
    logger.info(f"Starting HomeguardGuard Web Application with gateway_mode={settings.gateway_mode}")
    await db_manager.initialize()

    # If we're in TOTP testing mode, automatically block the testing IP
    if settings.gateway_mode == "totp_testing" and settings.testing_ip:
        logger.info(f"🔒 TOTP Testing Mode: Automatically blocking {settings.testing_ip}")
        try:
            fake_mac = f"test:{settings.testing_ip}"
            await traffic_monitor.block_device_traffic(fake_mac, settings.testing_ip)
            logger.info(f"✅ Successfully blocked traffic for testing IP {settings.testing_ip}")
        except Exception as e:
            logger.error(f"❌ Failed to block testing IP {settings.testing_ip}: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down HomeguardGuard web application")


# =============================================================================
# ADMIN PANEL ROUTES (Simplified - keeping essential functionality)
# =============================================================================

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    """Admin login page requiring forever TOTP."""
    return HTMLResponse("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>HomeguardGuard Admin Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .login-container {
                background: white;
                border-radius: 16px;
                box-shadow: 0 15px 35px rgba(0,0,0,0.1);
                max-width: 400px;
                width: 100%;
                padding: 40px 30px;
                text-align: center;
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 30px;
                font-size: 24px;
            }
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            label {
                display: block;
                color: #555;
                margin-bottom: 8px;
                font-weight: 600;
            }
            input[type="text"] {
                width: 100%;
                padding: 12px 16px;
                border: 2px solid #e1e8ed;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #1e3c72;
            }
            .submit-btn {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s;
            }
            .submit-btn:hover {
                transform: translateY(-2px);
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 Admin Access</h1>
            <form method="post" action="/admin/authenticate">
                <div class="form-group">
                    <label for="admin_totp_code">Admin TOTP Code</label>
                    <input type="text" id="admin_totp_code" name="admin_totp_code"
                           maxlength="6" pattern="[0-9]{6}" required autofocus>
                </div>
                <button type="submit" class="submit-btn">Login</button>
            </form>
        </div>
    </body>
    </html>
    """)


@app.post("/admin/authenticate")
async def admin_authenticate(admin_totp_code: str = Form(...)):
    """Handle admin authentication with forever TOTP."""
    try:
        validation_result = totp_manager.validate_code(admin_totp_code)

        if validation_result:
            duration_key, duration_seconds = validation_result

            # Only allow forever access for admin
            if duration_key == "forever":
                session_token = generate_session_token()
                admin_sessions.add(session_token)

                response = RedirectResponse(url="/admin", status_code=302)
                response.set_cookie(key="session_token", value=session_token, httponly=True)
                return response
            else:
                return HTMLResponse(f"""
                <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                    <h2 style="color: #dc3545;">❌ Access Denied</h2>
                    <p>Admin access requires forever TOTP code.</p>
                    <p>Provided code grants only: {duration_key.replace('_', ' ')}</p>
                    <a href="/admin/login" style="color: #007bff;">Try Again</a>
                </div>
                """, status_code=403)
        else:
            return HTMLResponse("""
            <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                <h2 style="color: #dc3545;">❌ Invalid Code</h2>
                <p>Please check your TOTP code and try again.</p>
                <a href="/admin/login" style="color: #007bff;">Try Again</a>
            </div>
            """, status_code=401)

    except Exception as e:
        logger.error(f"Admin authentication error: {e}")
        return HTMLResponse("""
        <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
            <h2 style="color: #dc3545;">⚠️ System Error</h2>
            <p>Please try again later.</p>
            <a href="/admin/login" style="color: #007bff;">Back to Login</a>
        </div>
        """, status_code=500)


@app.get("/admin/logout")
async def admin_logout(session_token: str = Cookie(None)):
    """Admin logout."""
    if session_token:
        admin_sessions.discard(session_token)

    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie(key="session_token")
    return response


@app.post("/admin/revoke/{ip_address}")
async def revoke_device_access(
    ip_address: str,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_admin_auth)
):
    """Revoke access for a specific device by IP address."""
    # Find device by IP address
    result = await session.execute(select(Device).where(Device.ip_address == ip_address))
    device = result.scalar_one_or_none()

    if device:
        device.revoke_access()
        await session.commit()

        # Block traffic for this IP
        try:
            await traffic_monitor.block_device_traffic(device.mac_address, ip_address)
            logger.info(f"🔒 Revoked access and blocked traffic for device {ip_address} (MAC: {device.mac_address})")
        except Exception as e:
            logger.error(f"Failed to block traffic for {ip_address}: {e}")

        return JSONResponse({"status": "success", "message": "Device access revoked"})

    return JSONResponse({"status": "error", "message": "Device not found"}, status_code=404)


def generate_devices_html(devices):
    """Generate HTML for devices table rows."""
    html_rows = []
    for device in devices:
        status_class = 'status-authorized' if device.is_access_valid else 'status-unauthorized'
        status_text = 'Authorized' if device.is_access_valid else 'Unauthorized'
        last_seen = device.last_seen.strftime('%Y-%m-%d %H:%M:%S') if device.last_seen else 'Never'

        if device.ip_address:
            if device.is_access_valid and device.ip_address:
                revoke_btn = f'<button class="revoke-btn" onclick="revokeAccess(\'{device.ip_address}\')">Revoke</button>'
            else:
                revoke_btn = '<button class="revoke-btn" disabled>Revoke</button>'
        else:
            revoke_btn = 'No IP'

        row = f'''<tr>
            <td>{device.ip_address or 'N/A'}</td>
            <td><code>{device.mac_address}</code></td>
            <td>{device.hostname or 'Unknown'}</td>
            <td>{device.device_type or 'Unknown'}</td>
            <td>
                <span class="status-badge {status_class}">
                    {status_text}
                </span>
            </td>
            <td>{last_seen}</td>
            <td>
                {revoke_btn}
            </td>
        </tr>'''
        html_rows.append(row)

    return ''.join(html_rows)


@app.get("/admin")
async def admin_dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: None = Depends(require_admin_auth)
):
    """Admin dashboard with tabbed interface."""
    # Get device statistics
    total_devices = await session.scalar(select(func.count()).select_from(Device))
    authorized_devices = await session.scalar(
        select(func.count()).select_from(Device).where(Device.is_authorized == True)
    )

    # Get all devices for device management
    devices_result = await session.execute(select(Device).order_by(Device.last_seen.desc()))
    devices = devices_result.scalars().all()

    # Get current TOTP codes
    current_codes = totp_manager.generate_current_codes()

    # Generate QR codes for each TOTP duration
    qr_codes = {}
    provisioning_uris = totp_manager.get_provisioning_uris(issuer="HomeguardGuard")
    for duration_key, uri in provisioning_uris.items():
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(uri)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_codes[duration_key] = base64.b64encode(buffer.getvalue()).decode()

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>HomeguardGuard Admin Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #f8f9fa;
                min-height: 100vh;
            }}
            .header {{
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: white;
                padding: 20px 0;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
            }}
            .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
            .header .subtitle {{ opacity: 0.9; font-size: 16px; }}

            /* Tab Navigation */
            .tab-nav {{
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                margin-bottom: 0;
            }}
            .tab-nav .container {{
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .tab-buttons {{
                display: flex;
                gap: 0;
            }}
            .tab-btn {{
                background: none;
                border: none;
                padding: 20px 24px;
                font-size: 15px;
                font-weight: 600;
                color: #6c757d;
                cursor: pointer;
                transition: all 0.3s ease;
                border-bottom: 3px solid transparent;
                position: relative;
            }}
            .tab-btn:hover {{
                color: #1e3c72;
                background: #f8f9fa;
            }}
            .tab-btn.active {{
                color: #1e3c72;
                border-bottom-color: #1e3c72;
                background: #fff;
            }}
            .logout-btn {{
                background: #dc3545;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: 600;
                text-decoration: none;
                transition: transform 0.2s;
                margin-left: 20px;
            }}
            .logout-btn:hover {{
                transform: translateY(-1px);
                background: #c82333;
            }}

            /* Tab Content */
            .tab-content {{
                padding: 30px 0;
            }}
            .tab-pane {{
                display: none;
            }}
            .tab-pane.active {{
                display: block;
            }}

            /* Cards */
            .card {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                margin-bottom: 24px;
                overflow: hidden;
            }}
            .card-header {{
                background: #f8f9fa;
                padding: 20px 24px;
                border-bottom: 1px solid #e9ecef;
                font-weight: 600;
                color: #2c3e50;
            }}
            .card-body {{
                padding: 24px;
            }}

            /* Stats Grid */
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 24px;
            }}
            .stat-card {{
                background: white;
                padding: 24px;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                text-align: center;
                border-left: 4px solid #1e3c72;
            }}
            .stat-number {{
                font-size: 32px;
                font-weight: 700;
                color: #1e3c72;
                margin-bottom: 8px;
            }}
            .stat-label {{
                color: #6c757d;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 1px;
            }}

            /* Device Table */
            .device-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 16px;
            }}
            .device-table th,
            .device-table td {{
                padding: 12px 16px;
                text-align: left;
                border-bottom: 1px solid #e9ecef;
            }}
            .device-table th {{
                background: #f8f9fa;
                font-weight: 600;
                color: #495057;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .device-table td {{
                font-size: 14px;
            }}
            .device-table tbody tr:hover {{
                background: #f8f9fa;
            }}
            .status-badge {{
                display: inline-block;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .status-authorized {{
                background: #d4edda;
                color: #155724;
            }}
            .status-unauthorized {{
                background: #f8d7da;
                color: #721c24;
            }}
            .revoke-btn {{
                background: #dc3545;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .revoke-btn:hover {{
                background: #c82333;
                transform: translateY(-1px);
            }}
            .revoke-btn:disabled {{
                background: #6c757d;
                cursor: not-allowed;
                transform: none;
            }}

            /* TOTP Grid */
            .totp-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 16px;
                margin-top: 16px;
            }}
            .totp-item {{
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                padding: 20px;
                border-radius: 12px;
                text-align: center;
                border-left: 4px solid #1e3c72;
            }}
            .totp-code {{
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
                font-size: 24px;
                font-weight: 700;
                color: #1e3c72;
                margin-bottom: 8px;
                letter-spacing: 2px;
            }}
            .totp-duration {{
                color: #6c757d;
                font-size: 13px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            /* QR Code Grid */
            .qr-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 24px;
                margin-top: 16px;
            }}
            .qr-item {{
                background: white;
                border: 1px solid #e9ecef;
                border-radius: 12px;
                padding: 24px;
                text-align: center;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }}
            .qr-title {{
                font-weight: 600;
                color: #2c3e50;
                margin-bottom: 16px;
                font-size: 16px;
            }}
            .qr-code {{
                margin: 16px 0;
            }}
            .qr-code img {{
                max-width: 200px;
                height: auto;
                border: 1px solid #e9ecef;
                border-radius: 8px;
            }}
            .qr-subtitle {{
                color: #6c757d;
                font-size: 12px;
                margin-top: 8px;
            }}

            /* Responsive */
            @media (max-width: 768px) {{
                .container {{ padding: 0 16px; }}
                .tab-buttons {{ flex-wrap: wrap; }}
                .tab-btn {{ padding: 16px 20px; font-size: 14px; }}
                .logout-btn {{ margin: 8px 0 0 0; width: 100%; }}
                .stats-grid {{ grid-template-columns: 1fr; }}
                .device-table {{ font-size: 12px; }}
                .device-table th,
                .device-table td {{ padding: 8px 12px; }}
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>📊 HomeguardGuard Admin</h1>
                <p class="subtitle">Network Gateway Management Dashboard</p>
            </div>
        </div>

        <div class="tab-nav">
            <div class="container">
                <div class="tab-buttons">
                    <button class="tab-btn active" data-tab="gateway">📊 Gateway</button>
                    <button class="tab-btn" data-tab="devices">🔧 Device Management</button>
                    <button class="tab-btn" data-tab="totp">🔑 TOTP Codes</button>
                    <button class="tab-btn" data-tab="qr">📱 QR Codes</button>
                </div>
                <a href="/admin/logout" class="logout-btn">Logout</a>
            </div>
        </div>

        <div class="container">
            <div class="tab-content">
                <!-- Gateway Tab -->
                <div id="gateway" class="tab-pane active">
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{total_devices}</div>
                            <div class="stat-label">Total Devices</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{authorized_devices}</div>
                            <div class="stat-label">Authorized Devices</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{gateway_mode}</div>
                            <div class="stat-label">Gateway Mode</div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">🌐 System Overview</div>
                        <div class="card-body">
                            <p><strong>Gateway IP:</strong> {gateway_ip}</p>
                            <p><strong>Web Port:</strong> {web_port}</p>
                            <p><strong>Debug Mode:</strong> {debug_mode}</p>
                            <p><strong>Auto Recovery:</strong> {auto_recovery}</p>
                            <p><strong>Interface:</strong> {gateway_interface}</p>
                        </div>
                    </div>
                </div>

                <!-- Device Management Tab -->
                <div id="devices" class="tab-pane">
                    <div class="card">
                        <div class="card-header">🔧 Connected Devices</div>
                        <div class="card-body">
                            <table class="device-table">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>MAC Address</th>
                                        <th>Hostname</th>
                                        <th>Device Type</th>
                                        <th>Status</th>
                                        <th>Last Seen</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {devices_html}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- TOTP Codes Tab -->
                <div id="totp" class="tab-pane">
                    <div class="card">
                        <div class="card-header">🔑 Current TOTP Codes</div>
                        <div class="card-body">
                            <div class="totp-grid">
                                {current_codes_html}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- QR Codes Tab -->
                <div id="qr" class="tab-pane">
                    <div class="card">
                        <div class="card-header">📱 TOTP QR Codes</div>
                        <div class="card-body">
                            <div class="qr-grid">
                                {qr_codes_html}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Tab switching
            document.querySelectorAll('.tab-btn').forEach(btn => {{
                btn.addEventListener('click', () => {{
                    // Remove active from all tabs and panes
                    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

                    // Add active to clicked tab and corresponding pane
                    btn.classList.add('active');
                    document.getElementById(btn.dataset.tab).classList.add('active');
                }});
            }});

            // Revoke device access
            async function revokeAccess(ipAddress) {{
                if (!confirm(`Are you sure you want to revoke access for device ${{ipAddress}}?`)) return;

                try {{
                    const response = await fetch(`/admin/revoke/${{ipAddress}}`, {{
                        method: 'POST'
                    }});

                    const result = await response.json();

                    if (result.status === 'success') {{
                        alert('Device access revoked successfully');
                        location.reload();
                    }} else {{
                        alert('Error: ' + result.message);
                    }}
                }} catch (error) {{
                    alert('Failed to revoke access: ' + error.message);
                }}
            }}

            // Auto-refresh TOTP codes every 30 seconds
            setInterval(() => {{
                if (document.getElementById('totp').classList.contains('active')) {{
                    location.reload();
                }}
            }}, 30000);
        </script>
    </body>
    </html>
    """

    return HTMLResponse(html_content.format(
        total_devices=total_devices or 0,
        authorized_devices=authorized_devices or 0,
        gateway_mode=settings.gateway_mode.replace('_', ' ').title(),
        gateway_ip=settings.gateway_ip,
        web_port=settings.web_port,
        debug_mode='Enabled' if settings.debug else 'Disabled',
        auto_recovery='Enabled' if settings.auto_recovery else 'Disabled',
        gateway_interface=settings.gateway_interface,
        current_codes_html=''.join([
            f'''<div class="totp-item">
                <div class="totp-code">{code}</div>
                <div class="totp-duration">{duration_key.replace('_', ' ').title()}</div>
            </div>''' for duration_key, code in current_codes.items()
        ]),
        devices_html=generate_devices_html(devices),
        qr_codes_html=''.join([
            f'''<div class="qr-item">
                <div class="qr-title">{duration_key.replace('_', ' ').title()}: HomeguardGuard</div>
                <div class="qr-code">
                    <img src="data:image/png;base64,{qr_code}" alt="QR Code for {duration_key}">
                </div>
                <div class="qr-subtitle">Scan with your authenticator app</div>
            </div>''' for duration_key, qr_code in qr_codes.items()
        ])
    ))


# =============================================================================
# HEALTH CHECK ENDPOINT
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return JSONResponse({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "gateway_mode": settings.gateway_mode,
        "version": "3.0.0"
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)