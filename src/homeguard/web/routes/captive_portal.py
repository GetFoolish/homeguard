"""Captive portal routes for TOTP authentication."""

import logging
from datetime import datetime
from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path

from ...database.connection import get_session
from ...database.models import Device
from ...network.traffic_monitor import traffic_monitor
from ..utils.client_info import get_client_info, should_enforce_totp, show_transparent_access_page

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize templates
templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/", response_class=HTMLResponse)
async def captive_portal(request: Request, session: AsyncSession = Depends(get_session)):
    """Main captive portal landing page."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]
    client_ip = client_info["ip_address"]
    user_agent = request.headers.get("user-agent", "")

    # Debug current settings
    from ...config.settings import settings
    logger.info(f"🔧 Current settings - gateway_mode: {settings.gateway_mode}, testing_ip: {settings.testing_ip}")

    # Check if TOTP enforcement applies to this device
    enforce_totp = should_enforce_totp(client_ip)
    logger.info(f"📍 Device {client_ip} - TOTP enforcement check: {enforce_totp}")

    if not enforce_totp:
        logger.info(f"📍 Device {client_ip} - TOTP not enforced (mode: {settings.gateway_mode}, testing_ip: {settings.testing_ip})")
        return show_transparent_access_page(client_info)

    logger.info(f"🔐 Device {client_ip} - TOTP enforcement active")

    # Check if device is already authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is already authenticated - show success page
        granted_time = device.access_granted_at or datetime.utcnow()
        expires_time = device.access_expires_at or datetime.utcnow()
        access_duration = device.access_duration or "unknown"

        # Calculate time remaining
        time_left_seconds = 0
        time_left_formatted = "Expired"
        if expires_time and expires_time > datetime.utcnow():
            time_left_seconds = int((expires_time - datetime.utcnow()).total_seconds())
            hours = time_left_seconds // 3600
            minutes = (time_left_seconds % 3600) // 60
            seconds = time_left_seconds % 60
            time_left_formatted = f"{hours}h {minutes}m {seconds}s"

        return templates.TemplateResponse("auth_success.html", {
            "request": request,
            "client_ip": client_ip,
            "mac_address": mac_address,
            "device_type": client_info["device_type"],
            "access_duration": access_duration.replace('_', ' '),
            "granted_time": granted_time.strftime('%Y-%m-%d %H:%M:%S') if granted_time else 'Unknown',
            "expires_time": expires_time.strftime('%Y-%m-%d %H:%M:%S') if expires_time else 'Unknown',
            "time_left_seconds": time_left_seconds,
            "time_left_formatted": time_left_formatted
        })

    # Device needs authentication - show captive portal
    return templates.TemplateResponse("captive_portal.html", {
        "request": request,
        "client_ip": client_ip,
        "device_type": client_info["device_type"],
        "os": client_info["os"],
        "browser": client_info["browser"]
    })


@router.post("/authenticate")
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
            # Success! Show the success page with proper connectivity indicators
            device = await session.get(Device, client_info["mac_address"])
            if device:
                granted_time = device.access_granted_at or datetime.utcnow()
                expires_time = device.access_expires_at or datetime.utcnow()
                access_duration = device.access_duration or "unknown"

                # Calculate time remaining
                time_left_seconds = 0
                time_left_formatted = "Expired"
                if expires_time and expires_time > datetime.utcnow():
                    time_left_seconds = int((expires_time - datetime.utcnow()).total_seconds())
                    hours = time_left_seconds // 3600
                    minutes = (time_left_seconds % 3600) // 60
                    seconds = time_left_seconds % 60
                    time_left_formatted = f"{hours}h {minutes}m {seconds}s"

                return templates.TemplateResponse("auth_success.html", {
                    "request": request,
                    "client_ip": client_info["ip_address"],
                    "mac_address": client_info["mac_address"],
                    "device_type": client_info["device_type"],
                    "access_duration": access_duration.replace('_', ' '),
                    "granted_time": granted_time.strftime('%Y-%m-%d %H:%M:%S') if granted_time else 'Unknown',
                    "expires_time": expires_time.strftime('%Y-%m-%d %H:%M:%S') if expires_time else 'Unknown',
                    "time_left_seconds": time_left_seconds,
                    "time_left_formatted": time_left_formatted
                })
            else:
                # Fallback if device not found in database
                return RedirectResponse(url="/", status_code=302)
        else:
            # Authentication failed - show error page
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>HomeguardGuard - Authentication Failed</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 20px;
                    }}
                    .error-container {{
                        background: white;
                        border-radius: 20px;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        max-width: 450px;
                        width: 100%;
                        padding: 40px 30px;
                        text-align: center;
                    }}
                    .error-icon {{
                        width: 60px;
                        height: 60px;
                        background: #dc3545;
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin: 0 auto 20px;
                    }}
                    .error-icon svg {{
                        width: 24px;
                        height: 24px;
                        fill: white;
                    }}
                    h1 {{
                        color: #dc3545;
                        font-size: 28px;
                        margin-bottom: 15px;
                    }}
                    .message {{
                        background: #f8d7da;
                        color: #721c24;
                        padding: 20px;
                        border-radius: 12px;
                        margin: 20px 0;
                        border: 1px solid #f5c6cb;
                    }}
                    .retry-btn {{
                        background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
                        color: white;
                        border: none;
                        padding: 14px 28px;
                        border-radius: 25px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: transform 0.2s;
                        text-decoration: none;
                        display: inline-block;
                        margin-top: 10px;
                    }}
                    .retry-btn:hover {{
                        transform: translateY(-2px);
                    }}
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-icon">
                        <svg viewBox="0 0 24 24">
                            <path d="M13,13H11V7H13M13,17H11V15H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z"/>
                        </svg>
                    </div>
                    <h1>Authentication Failed</h1>
                    <div class="message">
                        {message}
                    </div>
                    <a href="/" class="retry-btn">Try Again</a>
                </div>
            </body>
            </html>
            """, status_code=401)

    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>HomeguardGuard - System Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: #f8f9fa;
                }}
                .error {{
                    background: white;
                    padding: 40px;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    max-width: 400px;
                    margin: 0 auto;
                }}
                h2 {{ color: #dc3545; margin-bottom: 20px; }}
                a {{
                    color: white;
                    background: #007bff;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 6px;
                    display: inline-block;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="error">
                <h2>⚠️ System Error</h2>
                <p>Please try again later or contact support.</p>
                <a href="/">Back to Login</a>
            </div>
        </body>
        </html>
        """, status_code=500)