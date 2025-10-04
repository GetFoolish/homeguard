"""Captive portal connectivity check endpoints for automatic portal detection."""

import logging
from fastapi import APIRouter, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database.connection import get_session
from ..database.models import Device

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


@router.get("/generate_204")
async def android_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Android/Chrome connectivity check.

    Returns:
        - 204 No Content if device is authenticated (internet working)
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    if await check_device_authenticated(request, session):
        logger.info(f"📱 Android check: {client_ip} authenticated - returning 204")
        return Response(status_code=204)
    else:
        logger.info(f"📱 Android check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/connecttest.txt")
async def windows_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Windows connectivity check.

    Returns:
        - "Microsoft Connect Test" if device is authenticated
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    if await check_device_authenticated(request, session):
        logger.info(f"💻 Windows check: {client_ip} authenticated - returning success")
        return Response(content="Microsoft Connect Test", media_type="text/plain")
    else:
        logger.info(f"💻 Windows check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/ncsi.txt")
async def windows_ncsi_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Windows Network Connectivity Status Indicator (NCSI) check.

    Returns:
        - "Microsoft NCSI" if device is authenticated
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    if await check_device_authenticated(request, session):
        logger.info(f"💻 Windows NCSI: {client_ip} authenticated - returning Microsoft NCSI")
        return Response(content="Microsoft NCSI", media_type="text/plain")
    else:
        logger.info(f"💻 Windows NCSI: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/hotspot-detect.html")
async def apple_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Apple iOS/macOS connectivity check.

    Returns:
        - Success HTML if device is authenticated
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    if await check_device_authenticated(request, session):
        logger.info(f"🍎 Apple check: {client_ip} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        logger.info(f"🍎 Apple check: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/library/test/success.html")
async def apple_legacy_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Apple legacy connectivity check endpoint.

    Returns:
        - Success HTML if device is authenticated
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

    if await check_device_authenticated(request, session):
        logger.info(f"🍎 Apple legacy: {client_ip} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        logger.info(f"🍎 Apple legacy: {client_ip} not authenticated - redirecting to portal")
        return RedirectResponse(url="/portal", status_code=302)


@router.get("/success.txt")
async def generic_success_check(request: Request, session: AsyncSession = Depends(get_session)):
    """
    Generic success endpoint for various OS connectivity checks.

    Returns:
        - "success" if device is authenticated
        - 302 Redirect to captive portal if not authenticated
    """
    client_ip = request.client.host if request.client else "unknown"

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
