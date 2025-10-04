"""FastAPI service for Homeguard with all endpoints."""

import logging
import asyncio
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from pathlib import Path

from ..database.connection import get_session, db_manager
from ..database.models import Device, AccessLog
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


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    logger.info("Starting Homeguard API service...")
    await db_manager.initialize()

    # Start background task for expiration checking
    asyncio.create_task(check_expired_devices())

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
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            session.add(device)

        # Grant access
        device.grant_access(duration_key, expires_at)
        device.last_seen = datetime.utcnow()
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
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            session.add(device)

        # Set as IOT device
        device.set_iot()
        device.last_seen = datetime.utcnow()
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
    ip_address: str,
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
            result = await session.execute(
                select(Device).where(Device.ip_address == scanned_dev['ip_address'])
            )
            device = result.scalars().first()

            if device:
                # Update existing device
                device.last_seen = datetime.utcnow()
                if scanned_dev.get('hostname'):
                    device.hostname = scanned_dev['hostname']
                if scanned_dev.get('mac_address'):
                    device.mac_address = scanned_dev['mac_address']
            else:
                # Create new device with blocked status
                device = Device(
                    mac_address=scanned_dev['mac_address'],
                    ip_address=scanned_dev['ip_address'],
                    hostname=scanned_dev.get('hostname'),
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
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
                # In transparent mode, all devices have internet access by default
                effective_access = True
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

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the device management dashboard."""
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

    return templates.TemplateResponse("captive_portal.html", {
        "request": request,
        "client_ip": client_ip,
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
        # Get client IP
        client_ip = request.client.host if request.client else None

        if not client_ip:
            return JSONResponse({
                "success": False,
                "message": "Unable to determine client IP"
            }, status_code=400)

        # Validate TOTP
        validation_result = totp_manager.validate_code(totp_code)

        if not validation_result:
            return JSONResponse({
                "success": False,
                "message": "Invalid TOTP code"
            })

        duration_key, duration_seconds = validation_result
        expires_at = totp_manager.get_expiry_time(duration_seconds)

        # Find or create device
        result = await session.execute(select(Device).where(Device.ip_address == client_ip))
        device = result.scalars().first()

        if not device:
            device = Device(
                mac_address=f"portal:{client_ip}",
                ip_address=client_ip,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            session.add(device)

        # Grant access
        device.grant_access(duration_key, expires_at)
        device.last_seen = datetime.utcnow()
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

        return JSONResponse({
            "success": True,
            "message": f"Access granted for {duration_key}",
            "duration": duration_key,
            "expires_at": expires_at.isoformat() if expires_at else None
        })

    except Exception as e:
        logger.error(f"Portal authentication error: {e}")
        return JSONResponse({
            "success": False,
            "message": "Authentication failed"
        }, status_code=500)


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
