"""Captive portal connectivity check endpoints for automatic portal detection."""

import logging
from fastapi import APIRouter, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database.connection import get_session
from ..database.models import Device
from ..config.settings import settings

router = APIRouter()
logger = logging.getLogger(__name__)


async def check_device_authenticated(request: Request, session: AsyncSession) -> bool:
    """
    Check if the device making the request is authenticated.

    Args:
        request: FastAPI request object
        session: Database session

    Returns:
        bool: True if device is authenticated, False otherwise
    """
    try:
        # Get client IP
        client_ip = request.client.host if request.client else None
        if not client_ip:
            return False

        # Look up device by IP address
        result = await session.execute(
            select(Device).where(Device.ip_address == client_ip)
        )
        device = result.scalars().first()

        # Check if device exists and has valid access
        if device and device.is_access_valid:
            logger.debug(f"Device {client_ip} is authenticated")
            return True

        logger.debug(f"Device {client_ip} is NOT authenticated")
        return False

    except Exception as e:
        logger.error(f"Error checking device authentication: {e}")
        return False


async def check_device_blocked(request: Request, session: AsyncSession) -> bool:
    """
    Check if the device is explicitly blocked (in transparent mode).

    Args:
        request: FastAPI request object
        session: Database session

    Returns:
        bool: True if device is blocked, False otherwise
    """
    try:
        # Get client IP
        client_ip = request.client.host if request.client else None
        if not client_ip:
            return False

        # Look up device by IP address
        result = await session.execute(
            select(Device).where(Device.ip_address == client_ip)
        )
        device = result.scalars().first()

        # Check if device exists and is blocked
        if device and device.access_status == "blocked":
            logger.debug(f"Device {client_ip} is BLOCKED")
            return True

        logger.debug(f"Device {client_ip} is NOT blocked")
        return False

    except Exception as e:
        logger.error(f"Error checking if device is blocked: {e}")
        return False


@router.api_route("/generate_204", methods=["GET", "HEAD"])
async def android_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Android/Chrome connectivity check.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - 204 No Content if device has internet access (transparent mode or authenticated in TOTP mode)
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"📱 Android check: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"📱 Android check: {client_ip} - transparent mode - returning 204")
            return Response(status_code=204)

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"📱 Android check: {client_ip} authenticated - returning 204")
        return Response(status_code=204)
    else:
        logger.info(f"📱 Android check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/connecttest.txt", methods=["GET", "HEAD"])
async def windows_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Windows connectivity check.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - "Microsoft Connect Test" if device has internet access
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"💻 Windows check: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"💻 Windows check: {client_ip} - transparent mode - returning success")
            return Response(content="Microsoft Connect Test", media_type="text/plain")

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"💻 Windows check: {client_ip} authenticated - returning success")
        return Response(content="Microsoft Connect Test", media_type="text/plain")
    else:
        logger.info(f"💻 Windows check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/ncsi.txt", methods=["GET", "HEAD"])
async def windows_ncsi_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Windows Network Connectivity Status Indicator (NCSI) check.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - "Microsoft NCSI" if device has internet access
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"💻 Windows NCSI: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"💻 Windows NCSI: {client_ip} - transparent mode - returning Microsoft NCSI")
            return Response(content="Microsoft NCSI", media_type="text/plain")

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"💻 Windows NCSI: {client_ip} authenticated - returning Microsoft NCSI")
        return Response(content="Microsoft NCSI", media_type="text/plain")
    else:
        logger.info(f"💻 Windows NCSI: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/hotspot-detect.html", methods=["GET", "HEAD"])
async def apple_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Apple iOS/macOS connectivity check.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - Success HTML if device has internet access
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"🍎 Apple check: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"🍎 Apple check: {client_ip} - transparent mode - returning Success")
            return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"🍎 Apple check: {client_ip} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        logger.info(f"🍎 Apple check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/library/test/success.html", methods=["GET", "HEAD"])
async def apple_legacy_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Apple legacy connectivity check endpoint.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - Success HTML if device has internet access
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"🍎 Apple legacy: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"🍎 Apple legacy: {client_ip} - transparent mode - returning Success")
            return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"🍎 Apple legacy: {client_ip} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        logger.info(f"🍎 Apple legacy: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.api_route("/success.txt", methods=["GET", "HEAD"])
async def generic_success_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Generic success endpoint for various OS connectivity checks.
    Supports both GET and HEAD methods (HEAD used for faster connectivity checks).

    Returns:
        - "success" if device has internet access
        - 302 Redirect to captive portal if device is blocked or not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    # In transparent mode, check if device is explicitly blocked
    if settings.system_mode == "transparent":
        if await check_device_blocked(request, session):
            logger.info(f"✅ Generic check: {client_ip} - BLOCKED in transparent mode - redirecting to portal")
            return RedirectResponse(url="/portal", status_code=302)
        else:
            logger.info(f"✅ Generic check: {client_ip} - transparent mode - returning success")
            return Response(content="success", media_type="text/plain")

    # In TOTP mode, check authentication
    if await check_device_authenticated(request, session):
        logger.info(f"✅ Generic check: {client_ip} authenticated - returning success")
        return Response(content="success", media_type="text/plain")
    else:
        logger.info(f"✅ Generic check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/favicon.ico")
async def favicon():
    """Return empty favicon to avoid 404 errors in browser."""
    return Response(status_code=204)
