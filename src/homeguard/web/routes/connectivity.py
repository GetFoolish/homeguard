"""Captive portal connectivity check endpoints for various operating systems."""

import logging
from fastapi import APIRouter, Request, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ...database.connection import get_session
from ...database.models import Device
from ..utils.client_info import get_client_info

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/generate_204")
async def android_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Android/Chrome connectivity check - returns 204 if authenticated, 302 if not."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return 204 No Content (success)
        logger.info(f"📱 Android connectivity check: Device {mac_address} authenticated - returning 204")
        return Response(status_code=204)
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"📱 Android connectivity check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/connecttest.txt")
async def windows_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Windows connectivity check - returns 'Microsoft Connect Test' if authenticated."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return expected content
        logger.info(f"💻 Windows connectivity check: Device {mac_address} authenticated - returning success")
        return Response(content="Microsoft Connect Test", media_type="text/plain")
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"💻 Windows connectivity check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/hotspot-detect.html")
async def apple_connectivity_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Apple iOS/macOS connectivity check - returns Success if authenticated."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return Apple success response
        logger.info(f"🍎 Apple connectivity check: Device {mac_address} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"🍎 Apple connectivity check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/success.txt")
async def generic_success_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Generic success endpoint for various OS connectivity checks."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return success
        logger.info(f"✅ Generic connectivity check: Device {mac_address} authenticated - returning success")
        return Response(content="success", media_type="text/plain")
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"✅ Generic connectivity check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/library/test/success.html")
async def apple_legacy_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Apple legacy connectivity check endpoint."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return Apple success response
        logger.info(f"🍎 Apple legacy connectivity check: Device {mac_address} authenticated - returning Success")
        return HTMLResponse("""<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>""")
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"🍎 Apple legacy connectivity check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/ncsi.txt")
async def windows_ncsi_check(request: Request, session: AsyncSession = Depends(get_session)):
    """Windows Network Connectivity Status Indicator check."""
    client_info = get_client_info(request)
    mac_address = client_info["mac_address"]

    # Check if device is authenticated
    device = await session.get(Device, mac_address)
    if device and device.is_access_valid:
        # Device is authenticated - return expected NCSI response
        logger.info(f"💻 Windows NCSI check: Device {mac_address} authenticated - returning Microsoft NCSI")
        return Response(content="Microsoft NCSI", media_type="text/plain")
    else:
        # Device not authenticated - redirect to captive portal
        logger.info(f"💻 Windows NCSI check: Device {mac_address} not authenticated - redirecting")
        return RedirectResponse(url="/", status_code=302)


@router.get("/favicon.ico")
async def favicon():
    """Return empty favicon to avoid 404 errors."""
    return Response(status_code=204)