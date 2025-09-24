"""Utilities for extracting client information from requests."""

import hashlib
import logging
from fastapi import Request

logger = logging.getLogger(__name__)


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

    # Generate MAC address from client IP (since we can't get real MAC over HTTP)
    # This is a deterministic fake MAC based on IP for tracking purposes
    mac_hash = hashlib.md5(client_ip.encode()).hexdigest()
    fake_mac = f"http:{mac_hash[:2]}:{mac_hash[2:4]}:{mac_hash[4:6]}:{mac_hash[6:8]}:{mac_hash[8:10]}:{mac_hash[10:12]}"

    # Enhanced NAT detection for complex networks
    is_behind_nat = False
    nat_router_ip = None

    # Check if we have forwarded headers (common in NAT environments)
    if forwarded_ip and forwarded_ip != direct_ip:
        is_behind_nat = True
        nat_router_ip = direct_ip  # The router's IP
        logger.info(f"🔍 NAT detected: Client IP {forwarded_ip} via router {direct_ip}")

    # Private IP ranges indicate NAT
    if any(client_ip.startswith(prefix) for prefix in ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]):
        if not is_behind_nat:  # Only log if we haven't already detected NAT
            logger.info(f"🏠 Private IP detected: {client_ip} - likely behind NAT")

    return {
        "ip_address": client_ip,
        "direct_ip": direct_ip,
        "forwarded_ip": forwarded_ip,
        "mac_address": fake_mac,
        "user_agent": user_agent,
        "device_type": device_type,
        "browser": browser,
        "os": os,
        "is_behind_nat": is_behind_nat,
        "nat_router_ip": nat_router_ip,
        "hostname": None  # Will be resolved later if needed
    }


def should_enforce_totp(client_ip: str) -> bool:
    """Determine if TOTP enforcement should apply to this client IP."""
    from ...config.settings import settings

    if settings.gateway_mode == "transparent":
        # Mode 3: Transparent mode - no TOTP enforcement for anyone
        return False
    elif settings.gateway_mode == "totp_testing":
        # Mode 1: TOTP testing - only enforce for specific testing IP
        return client_ip == settings.testing_ip
    elif settings.gateway_mode == "totp_full":
        # Mode 2: TOTP full - enforce for everyone
        return True
    else:
        # Unknown mode - default to no enforcement for safety
        logger.warning(f"Unknown gateway_mode: {settings.gateway_mode} - defaulting to no TOTP enforcement")
        return False


def show_transparent_access_page(client_info: dict) -> str:
    """Return HTML for transparent access (no TOTP required)."""
    from fastapi.responses import HTMLResponse

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>HomeguardGuard - Network Access</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
            .container {{ max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .success {{ color: #28a745; text-align: center; font-size: 28px; margin-bottom: 20px; }}
            .status-badge {{ background: #28a745; color: white; padding: 8px 16px; border-radius: 20px; display: inline-block; margin-bottom: 20px; }}
            .info {{ background: #e8f5e9; color: #2e7d32; padding: 20px; border-radius: 8px; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success">✅ Network Access Active</div>
            <div class="status-badge">Transparent Mode</div>
            <div class="info">
                <h3>Welcome to HomeguardGuard Network</h3>
                <p>Your device has full internet access.</p>
                <p>No authentication required in current mode.</p>
                <p><strong>Device IP:</strong> {client_info['ip_address']}</p>
                <p><strong>Device Type:</strong> {client_info['device_type']} ({client_info['os']} - {client_info['browser']})</p>
            </div>
        </div>
    </body>
    </html>
    """)