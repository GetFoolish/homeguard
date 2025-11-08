"""FastAPI service for Homeguard with all endpoints."""

import logging
import asyncio
import secrets
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from fastapi import FastAPI, Depends, HTTPException, Request, Form, Cookie, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pathlib import Path

# Set timezone to Toronto/EST
TIMEZONE = ZoneInfo("America/Toronto")

from ..database.connection import get_session, db_manager
from ..database.models import Device, AccessLog, TotpAttempt
from ..auth.totp import totp_manager
from ..iptables.manager import iptables_manager
from ..config.settings import settings, save_config_file
from ..network.scanner import device_scanner
from .connectivity import router as connectivity_router

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Homeguard Network Gateway",
    description="TOTP-based network access control system",
    version="4.0.0"
)

# Include connectivity check router for automatic captive portal detection
app.include_router(connectivity_router)

# Setup templates
templates_dir = Path(__file__).parent.parent / "frontend" / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Admin session management
ADMIN_SESSION_SECRET = secrets.token_urlsafe(32)
ADMIN_SESSION_TIMEOUT = 900  # 15 minutes in seconds
active_admin_sessions = {}  # token -> expiry_time

def create_admin_session_token() -> str:
    """Create a signed session token for admin access."""
    token = secrets.token_urlsafe(32)
    expiry = datetime.now(TIMEZONE) + timedelta(seconds=ADMIN_SESSION_TIMEOUT)
    active_admin_sessions[token] = expiry
    return token

def verify_admin_session(admin_session: str = Cookie(default=None)) -> bool:
    """Verify admin session cookie."""
    if not admin_session:
        return False

    # Check if token exists and is not expired
    if admin_session in active_admin_sessions:
        expiry = active_admin_sessions[admin_session]
        if datetime.now(TIMEZONE) < expiry:
            return True
        else:
            # Token expired, remove it
            del active_admin_sessions[admin_session]

    return False

async def require_admin_session(request: Request, admin_session: str = Cookie(default=None)):
    """Dependency to require valid admin session."""
    if not verify_admin_session(admin_session):
        return RedirectResponse(url="/admin/login", status_code=302)
    return admin_session

# TOTP Rate Limiting (5 attempts per hour per IP)
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 3600  # 1 hour

async def check_rate_limit(ip_address: str, session: AsyncSession) -> tuple[bool, int, int]:
    """
    Check if an IP address has exceeded the rate limit for TOTP attempts.
    
    Returns:
        tuple[bool, int, int]: (is_allowed, attempts_used, time_until_reset_seconds)
    """
    # Get all attempts from this IP in the last hour
    one_hour_ago = datetime.now(TIMEZONE) - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
    
    result = await session.execute(
        select(TotpAttempt)
        .where(TotpAttempt.ip_address == ip_address)
        .where(TotpAttempt.attempted_at >= one_hour_ago)
        .order_by(TotpAttempt.attempted_at.asc())
    )
    attempts = result.scalars().all()
    
    attempts_count = len(attempts)
    
    # If we haven't hit the limit yet, allow the attempt
    if attempts_count < RATE_LIMIT_MAX_ATTEMPTS:
        return (True, attempts_count, 0)
    
    # We've hit the limit - calculate time until oldest attempt expires
    oldest_attempt = attempts[0]
    oldest_time = oldest_attempt.attempted_at
    # Handle timezone compatibility (like in Device model)
    if oldest_time.tzinfo is None:
        oldest_time = oldest_time.replace(tzinfo=TIMEZONE)
    
    time_since_oldest = datetime.now(TIMEZONE) - oldest_time
    time_until_reset = RATE_LIMIT_WINDOW_SECONDS - int(time_since_oldest.total_seconds())
    
    return (False, attempts_count, max(0, time_until_reset))

async def record_totp_attempt(ip_address: str, success: bool, session: AsyncSession):
    """Record a TOTP attempt for rate limiting."""
    attempt = TotpAttempt(
        ip_address=ip_address,
        attempted_at=datetime.now(TIMEZONE),
        success=success
    )
    session.add(attempt)
    await session.commit()

# User-agent parsing for device detection
def parse_user_agent(user_agent: str) -> dict:
    """Parse user-agent string to extract device type, OS, and browser."""
    device_type = "Unknown"
    browser = "Unknown"
    os = "Unknown"

    # Detect device type
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
        elif "Windows NT 6.2" in user_agent:
            os = "Windows 8"
        elif "Windows NT 6.1" in user_agent:
            os = "Windows 7"
        else:
            os = "Windows"
    elif "Mac OS X" in user_agent or "macOS" in user_agent:
        os = "macOS"
    elif "Linux" in user_agent and "Android" not in user_agent:
        os = "Linux"
    elif "Android" in user_agent:
        os = "Android"
    elif "iOS" in user_agent or "iPhone OS" in user_agent:
        os = "iOS"

    return {
        "device_type": device_type,
        "os": os,
        "browser": browser
    }

# Background task for access expiration
async def check_expired_devices():
    """Background task that runs every 30 seconds to check for expired devices."""
    while True:
        try:
            await asyncio.sleep(30)
            logger.debug("Checking for expired device access...")

            async with db_manager.get_session() as session:
                # Get all granted devices
                result = await session.execute(
                    select(Device).where(Device.access_status == "granted")
                )
                granted_devices = result.scalars().all()

                for device in granted_devices:
                    # Check if access has expired
                    if not device.is_access_valid:
                        logger.info(f"Access expired for device {device.ip_address}")
                        # Block the device
                        device.block_access()
                        await session.commit()

                        # Remove from iptables
                        if device.ip_address:
                            iptables_manager.block_access_to_ip(device.ip_address)

                        # Log the event
                        log_entry = AccessLog(
                            mac_address=device.mac_address,
                            ip_address=device.ip_address,
                            event_type="access_expired",
                            event_details=f"Access expired after {device.access_duration}"
                        )
                        session.add(log_entry)
                        await session.commit()

        except Exception as e:
            logger.error(f"Error in expired device check: {e}")


# Background task for cleaning up old TOTP attempts
async def cleanup_old_totp_attempts():
    """Background task that runs daily to clean up TOTP attempts older than 72 hours."""
    while True:
        try:
            # Run once per day (86400 seconds)
            await asyncio.sleep(86400)
            logger.info("Cleaning up old TOTP attempts...")

            async with db_manager.get_session() as session:
                # Delete attempts older than 72 hours
                cutoff_time = datetime.now(TIMEZONE) - timedelta(hours=72)
                
                # Get count before deletion for logging
                count_result = await session.execute(
                    select(TotpAttempt).where(TotpAttempt.attempted_at < cutoff_time)
                )
                old_attempts = count_result.scalars().all()
                count = len(old_attempts)
                
                # Delete old attempts
                for attempt in old_attempts:
                    await session.delete(attempt)
                
                await session.commit()
                
                if count > 0:
                    logger.info(f"🗑️  Deleted {count} TOTP attempt(s) older than 72 hours")
                else:
                    logger.debug("No old TOTP attempts to clean up")

        except Exception as e:
            logger.error(f"Error in TOTP attempts cleanup: {e}")


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("Starting Homeguard API service...")
    await db_manager.initialize()

    # Start background tasks
    asyncio.create_task(check_expired_devices())
    asyncio.create_task(cleanup_old_totp_attempts())

    # Set mode based on config
    if settings.system_mode == "transparent":
        iptables_manager.set_transparent_mode()
    elif settings.system_mode == "totp":
        # Get IOT and granted devices from database
        async with db_manager.get_session() as session:
            iot_result = await session.execute(
                select(Device).where(Device.access_status == "iot")
            )
            iot_devices = [d.ip_address for d in iot_result.scalars().all() if d.ip_address]

            granted_result = await session.execute(
                select(Device).where(Device.access_status == "granted")
            )
            granted_devices = [d.ip_address for d in granted_result.scalars().all() if d.ip_address]

        iptables_manager.set_totp_mode(iot_devices=iot_devices, granted_devices=granted_devices)

    logger.info(f"Homeguard started in {settings.system_mode.upper()} mode")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down Homeguard API service...")
    # Set to transparent mode on shutdown
    iptables_manager.set_transparent_mode()
    await db_manager.close()


# =============================================================================
# MODE MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/set_mode_to_transparent")
async def set_mode_to_transparent():
    """Set system to transparent mode."""
    try:
        logger.info("Setting mode to TRANSPARENT")
        success = iptables_manager.set_transparent_mode()

        if success:
            # Update config
            settings.system_mode = "transparent"
            save_config_file({"system_mode": "transparent"})

            return JSONResponse({
                "status": "success",
                "message": "System set to transparent mode",
                "mode": "transparent"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to set transparent mode")

    except Exception as e:
        logger.error(f"Error setting transparent mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/set_mode_to_totp")
async def set_mode_to_totp(session: AsyncSession = Depends(get_session)):
    """Set system to TOTP mode."""
    try:
        logger.info("Setting mode to TOTP")

        # Get IOT and granted devices from database
        iot_result = await session.execute(
            select(Device).where(Device.access_status == "iot")
        )
        iot_devices = [d.ip_address for d in iot_result.scalars().all() if d.ip_address]

        granted_result = await session.execute(
            select(Device).where(Device.access_status == "granted")
        )
        granted_devices = [d.ip_address for d in granted_result.scalars().all() if d.ip_address and d.is_access_valid]

        # Set TOTP mode
        success = iptables_manager.set_totp_mode(iot_devices=iot_devices, granted_devices=granted_devices)

        if success:
            # Update config
            settings.system_mode = "totp"
            save_config_file({"system_mode": "totp"})

            return JSONResponse({
                "status": "success",
                "message": "System set to TOTP mode",
                "mode": "totp",
                "iot_devices": len(iot_devices),
                "granted_devices": len(granted_devices)
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to set TOTP mode")

    except Exception as e:
        logger.error(f"Error setting TOTP mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# TOTP VALIDATION ENDPOINT
# =============================================================================

@app.post("/validate_totp")
async def validate_totp(totp_code: str):
    """Validate a TOTP code."""
    try:
        result = totp_manager.validate_code(totp_code)

        if result:
            duration_key, duration_seconds = result
            return JSONResponse({
                "validated": True,
                "duration_key": duration_key,
                "duration_seconds": duration_seconds
            })
        else:
            return JSONResponse({
                "validated": False
            })

    except Exception as e:
        logger.error(f"Error validating TOTP: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# DEVICE ACCESS MANAGEMENT ENDPOINTS
# =============================================================================

@app.post("/grant_access_to_ip")
async def grant_access_to_ip(
    ip_address: str,
    totp_code: str,
    session: AsyncSession = Depends(get_session)
):
    """Grant access to an IP address after TOTP validation."""
    try:
        # Validate TOTP
        validation_result = totp_manager.validate_code(totp_code)

        if not validation_result:
            return JSONResponse({
                "status": "error",
                "message": "Invalid TOTP code"
            }, status_code=401)

        duration_key, duration_seconds = validation_result

        # Calculate expiry time
        expires_at = totp_manager.get_expiry_time(duration_seconds)

        # Find or create device
        result = await session.execute(select(Device).where(Device.ip_address == ip_address))
        device = result.scalars().first()

        if not device:
            # Create new device
            device = Device(
                mac_address=f"unknown:{ip_address}",
                ip_address=ip_address,
                first_seen=datetime.now(TIMEZONE),
                last_seen=datetime.now(TIMEZONE)
            )
            session.add(device)

        # Grant access
        device.grant_access(duration_key, expires_at)
        device.last_seen = datetime.now(TIMEZONE)
        await session.commit()

        # Add to iptables
        iptables_manager.grant_access_to_ip(ip_address)

        # Log the event
        log_entry = AccessLog(
            mac_address=device.mac_address,
            ip_address=ip_address,
            event_type="access_granted",
            event_details=f"Granted {duration_key} access"
        )
        session.add(log_entry)
        await session.commit()

        logger.info(f"✅ Granted {duration_key} access to {ip_address}")

        return JSONResponse({
            "status": "success",
            "message": f"Access granted for {duration_key}",
            "ip_address": ip_address,
            "duration": duration_key,
            "expires_at": expires_at.isoformat() if expires_at else None
        })

    except Exception as e:
        logger.error(f"Error granting access to {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/block_access_to_ip")
async def block_access_to_ip(
    ip_address: str,
    session: AsyncSession = Depends(get_session)
):
    """Block access from an IP address."""
    try:
        # Find device
        result = await session.execute(select(Device).where(Device.ip_address == ip_address))
        device = result.scalars().first()

        if not device:
            return JSONResponse({
                "status": "error",
                "message": "Device not found"
            }, status_code=404)

        # Block access
        device.block_access()
        await session.commit()

        # Remove from iptables
        iptables_manager.block_access_to_ip(ip_address)

        # Log the event
        log_entry = AccessLog(
            mac_address=device.mac_address,
            ip_address=ip_address,
            event_type="access_blocked",
            event_details="Access manually blocked"
        )
        session.add(log_entry)
        await session.commit()

        logger.info(f"🔒 Blocked access from {ip_address}")

        return JSONResponse({
            "status": "success",
            "message": "Access blocked",
            "ip_address": ip_address
        })

    except Exception as e:
        logger.error(f"Error blocking access to {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/grant_access_to_IOT")
async def grant_access_to_iot(
    ip_address: str,
    session: AsyncSession = Depends(get_session)
):
    """Add device to IOT proxy."""
    try:
        # Find or create device
        result = await session.execute(select(Device).where(Device.ip_address == ip_address))
        device = result.scalars().first()

        if not device:
            # Create new device
            device = Device(
                mac_address=f"iot:{ip_address}",
                ip_address=ip_address,
                first_seen=datetime.now(TIMEZONE),
                last_seen=datetime.now(TIMEZONE)
            )
            session.add(device)

        # Set as IOT device
        device.set_iot()
        device.last_seen = datetime.now(TIMEZONE)
        await session.commit()

        # Add to iptables IOT chain
        iptables_manager.add_iot_device(ip_address)

        # Log the event
        log_entry = AccessLog(
            mac_address=device.mac_address,
            ip_address=ip_address,
            event_type="iot_added",
            event_details="Device added to IOT proxy"
        )
        session.add(log_entry)
        await session.commit()

        logger.info(f"🔌 Added {ip_address} to IOT proxy")

        return JSONResponse({
            "status": "success",
            "message": "Device added to IOT proxy",
            "ip_address": ip_address
        })

    except Exception as e:
        logger.error(f"Error adding IOT device {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/remove_iot_device")
async def remove_iot_device(
    ip_address: str = Form(...),
    session: AsyncSession = Depends(get_session)
):
    """Remove device from IOT proxy."""
    try:
        # Find device
        result = await session.execute(select(Device).where(Device.ip_address == ip_address))
        device = result.scalars().first()

        if not device:
            return JSONResponse({
                "status": "error",
                "message": "Device not found"
            }, status_code=404)

        # Block access (sets status to blocked)
        device.block_access()
        await session.commit()

        # Remove from iptables IOT chain
        iptables_manager.remove_iot_device(ip_address)

        # Log the event
        log_entry = AccessLog(
            mac_address=device.mac_address,
            ip_address=ip_address,
            event_type="iot_removed",
            event_details="Device removed from IOT proxy"
        )
        session.add(log_entry)
        await session.commit()

        logger.info(f"🔌 Removed {ip_address} from IOT proxy")

        return JSONResponse({
            "status": "success",
            "message": "Device removed from IOT proxy",
            "ip_address": ip_address
        })

    except Exception as e:
        logger.error(f"Error removing IOT device {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# DEVICE LISTING AND SCANNING ENDPOINTS
# =============================================================================

@app.get("/scan_network")
async def scan_network(session: AsyncSession = Depends(get_session)):
    """Scan network for active devices and update database."""
    try:
        # Scan network
        scanned_devices = device_scanner.get_all_devices()

        # Update database with scanned devices
        for scanned_dev in scanned_devices:
            # First check if device exists by MAC address (primary key)
            mac_result = await session.execute(
                select(Device).where(Device.mac_address == scanned_dev['mac_address'])
            )
            device_by_mac = mac_result.scalars().first()

            # Also check by IP address
            ip_result = await session.execute(
                select(Device).where(Device.ip_address == scanned_dev['ip_address'])
            )
            device_by_ip = ip_result.scalars().first()

            if device_by_mac:
                # Device exists with this MAC, update it
                device_by_mac.last_seen = datetime.now(TIMEZONE)
                device_by_mac.ip_address = scanned_dev['ip_address']  # Update IP if it changed
                if scanned_dev.get('hostname'):
                    device_by_mac.hostname = scanned_dev['hostname']
            elif device_by_ip:
                # Device exists with this IP but different MAC
                # Only update if the existing MAC looks like a placeholder
                if device_by_ip.mac_address.startswith(('unknown:', 'portal:', 'iot:')):
                    device_by_ip.mac_address = scanned_dev['mac_address']
                device_by_ip.last_seen = datetime.now(TIMEZONE)
                if scanned_dev.get('hostname'):
                    device_by_ip.hostname = scanned_dev['hostname']
            else:
                # Create new device with blocked status (default)
                device = Device(
                    mac_address=scanned_dev['mac_address'],
                    ip_address=scanned_dev['ip_address'],
                    hostname=scanned_dev.get('hostname'),
                    first_seen=datetime.now(TIMEZONE),
                    last_seen=datetime.now(TIMEZONE),
                    access_status="blocked"
                )
                session.add(device)

        await session.commit()

        logger.info(f"Network scan complete: {len(scanned_devices)} devices found")

        return JSONResponse({
            "status": "success",
            "devices_found": len(scanned_devices)
        })

    except Exception as e:
        logger.error(f"Error scanning network: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/devices")
async def list_devices(session: AsyncSession = Depends(get_session)):
    """List all devices with effective access status based on system mode."""
    try:
        result = await session.execute(select(Device).order_by(Device.last_seen.desc()))
        devices = result.scalars().all()

        device_list = []
        for device in devices:
            # Calculate effective access based on system mode and device status
            if settings.system_mode == "transparent":
                # In transparent mode, all devices have internet EXCEPT explicitly blocked ones
                effective_access = device.access_status != "blocked"
            else:  # totp mode
                # In TOTP mode, only granted/iot devices with valid access have internet
                effective_access = (
                    (device.access_status == "granted" or device.access_status == "iot")
                    and device.is_access_valid
                )

            device_list.append({
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "hostname": device.hostname,
                "access_status": device.access_status,
                "effective_access": effective_access,  # Reflects actual internet access
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "access_expires_at": device.access_expires_at.isoformat() if device.access_expires_at else None
            })

        return JSONResponse({"devices": device_list})

    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# FRONTEND
# =============================================================================

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: str = None):
    """Serve the admin login page."""
    return templates.TemplateResponse("admin_login.html", {
        "request": request,
        "error": error
    })


@app.post("/admin/login")
async def admin_login(
    request: Request, 
    totp_code: str = Form(...),
    session: AsyncSession = Depends(get_session)
):
    """Handle admin login with TOTP."""
    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit
    is_allowed, attempts_used, time_until_reset = await check_rate_limit(client_ip, session)
    
    if not is_allowed:
        minutes = time_until_reset // 60
        seconds = time_until_reset % 60
        time_msg = f"{minutes}min {seconds}s" if minutes > 0 else f"{seconds}s"
        
        logger.warning(f"🚫 Admin login rate limit exceeded for IP {client_ip}")
        return RedirectResponse(
            url=f"/admin/login?error=Too+many+attempts.+Wait+{time_msg}",
            status_code=302
        )
    
    # Strip whitespace from TOTP code
    totp_code = totp_code.strip().replace(" ", "")

    # Validate TOTP
    validation_result = totp_manager.validate_code(totp_code)

    if not validation_result:
        # Record failed attempt
        await record_totp_attempt(client_ip, success=False, session=session)
        
        return RedirectResponse(
            url="/admin/login?error=Invalid+authentication+code",
            status_code=302
        )

    duration_key, duration_seconds = validation_result

    # Only accept 15min duration codes for admin access
    if duration_key != "15min":
        # Record failed attempt (wrong duration)
        await record_totp_attempt(client_ip, success=False, session=session)
        
        return RedirectResponse(
            url="/admin/login?error=Admin+access+requires+15min+TOTP+code",
            status_code=302
        )

    # Record successful attempt
    await record_totp_attempt(client_ip, success=True, session=session)

    # Create session token and redirect to admin dashboard
    session_token = create_admin_session_token()
    response = RedirectResponse(url="/admin", status_code=302)
    response.set_cookie(
        key="admin_session",
        value=session_token,
        max_age=ADMIN_SESSION_TIMEOUT,
        httponly=True,
        samesite="lax"
    )

    logger.info(f"✅ Admin login successful from {client_ip}")
    return response


@app.get("/admin/logout")
async def admin_logout(admin_session: str = Cookie(default=None)):
    """Handle admin logout."""
    # Remove session token from active sessions
    if admin_session and admin_session in active_admin_sessions:
        del active_admin_sessions[admin_session]

    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_session")
    logger.info("Admin logged out")
    return response


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root URL - serve captive portal for devices."""
    return RedirectResponse(url="/portal", status_code=302)


@app.get("/admin", response_class=HTMLResponse)
async def dashboard(request: Request, admin_session: str = Cookie(default=None)):
    """Serve the admin dashboard (requires admin auth)."""
    # Check admin session
    if not verify_admin_session(admin_session):
        return RedirectResponse(url="/admin/login", status_code=302)

    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/qr_codes")
async def get_qr_codes():
    """Generate and return QR codes for all TOTP durations."""
    try:
        import qrcode
        import io
        import base64

        qr_codes = {}
        provisioning_uris = totp_manager.get_provisioning_uris(issuer="Homeguard")

        for duration_key, uri in provisioning_uris.items():
            # Create QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(uri)
            qr.make(fit=True)

            # Create image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_codes[duration_key] = base64.b64encode(buffer.getvalue()).decode()

        return JSONResponse({"qr_codes": qr_codes})

    except Exception as e:
        logger.error(f"Error generating QR codes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/portal", response_class=HTMLResponse)
async def captive_portal(request: Request):
    """Serve the captive portal for blocked devices."""
    # Get client info
    client_ip = request.client.host if request.client else "Unknown"
    user_agent = request.headers.get("user-agent", "")

    # Parse user-agent for device detection
    device_info = parse_user_agent(user_agent)

    return templates.TemplateResponse("captive_portal.html", {
        "request": request,
        "client_ip": client_ip,
        "device_type": device_info["device_type"],
        "os": device_info["os"],
        "browser": device_info["browser"],
        "gateway_ip": settings.gateway_ip
    })


@app.post("/portal/authenticate")
async def portal_authenticate(
    request: Request,
    totp_code: str = Form(...),
    session: AsyncSession = Depends(get_session)
):
    """Handle TOTP authentication from captive portal."""
    try:
        # Strip whitespace from TOTP code (form formats with spaces for readability)
        totp_code = totp_code.strip().replace(" ", "")

        # Get client IP
        client_ip = request.client.host if request.client else None

        if not client_ip:
            return templates.TemplateResponse(
                "auth_failure.html",
                {
                    "request": request,
                    "error_message": "Unable to determine your device IP address."
                }
            )

        # Check rate limit BEFORE validating the TOTP
        is_allowed, attempts_used, time_until_reset = await check_rate_limit(client_ip, session)
        
        if not is_allowed:
            # Calculate minutes and seconds for user-friendly message
            minutes = time_until_reset // 60
            seconds = time_until_reset % 60
            time_msg = f"{minutes} minute{'s' if minutes != 1 else ''}" if minutes > 0 else f"{seconds} second{'s' if seconds != 1 else ''}"
            
            logger.warning(f"🚫 Rate limit exceeded for IP {client_ip}: {attempts_used} attempts in last hour")
            return templates.TemplateResponse(
                "auth_failure.html",
                {
                    "request": request,
                    "error_message": f"Too many authentication attempts. You have used {attempts_used} of {RATE_LIMIT_MAX_ATTEMPTS} allowed attempts per hour. Please wait {time_msg} before trying again."
                }
            )

        # Validate TOTP (includes universal passwords)
        validation_result = totp_manager.validate_code(totp_code)
        
        if not validation_result:
            # Record failed attempt
            await record_totp_attempt(client_ip, success=False, session=session)
            
            # Calculate remaining attempts
            remaining_attempts = RATE_LIMIT_MAX_ATTEMPTS - (attempts_used + 1)
            attempts_msg = f"You have {remaining_attempts} attempt{'s' if remaining_attempts != 1 else ''} remaining in the next hour." if remaining_attempts > 0 else ""
            
            return templates.TemplateResponse(
                "auth_failure.html",
                {
                    "request": request,
                    "error_message": f"Invalid authentication code. Please try again. {attempts_msg}"
                }
            )

        # Record successful attempt
        await record_totp_attempt(client_ip, success=True, session=session)

        duration_key, duration_seconds = validation_result
        expires_at = totp_manager.get_expiry_time(duration_seconds)

        # Find or create device
        result = await session.execute(select(Device).where(Device.ip_address == client_ip))
        device = result.scalars().first()

        if not device:
            device = Device(
                mac_address=f"portal:{client_ip}",
                ip_address=client_ip,
                first_seen=datetime.now(TIMEZONE),
                last_seen=datetime.now(TIMEZONE)
            )
            session.add(device)

        # Grant access
        device.grant_access(duration_key, expires_at)
        device.last_seen = datetime.now(TIMEZONE)
        await session.commit()

        # Add to iptables
        iptables_manager.grant_access_to_ip(client_ip)

        # Log the event
        log_entry = AccessLog(
            mac_address=device.mac_address,
            ip_address=client_ip,
            event_type="portal_auth_success",
            event_details=f"Granted {duration_key} access via portal"
        )
        session.add(log_entry)
        await session.commit()

        logger.info(f"✅ Portal: Granted {duration_key} access to {client_ip}")

        # Format duration for display
        duration_display = duration_key.replace('_', ' ').title()
        expires_at_str = expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if expires_at else "Never"

        return templates.TemplateResponse(
            "auth_success.html",
            {
                "request": request,
                "client_ip": client_ip,
                "duration_display": duration_display,
                "expires_at": expires_at_str if expires_at else None
            }
        )

    except Exception as e:
        logger.error(f"Portal authentication error: {e}")
        return templates.TemplateResponse(
            "auth_failure.html",
            {
                "request": request,
                "error_message": "An error occurred during authentication. Please try again."
            }
        )


# =============================================================================
# HEALTH CHECK
# =============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return JSONResponse({
        "status": "healthy",
        "mode": settings.system_mode,
        "execution_mode": settings.execution_mode,
        "version": "4.0.0"
    })
