"""HTTP Proxy Server with authentication-based traffic filtering."""

import asyncio
import logging
import socket
from urllib.parse import urlparse
from typing import Optional, Tuple
import aiohttp
from aiohttp import web
import json

from ..network.traffic_monitor import traffic_monitor
from ..config.settings import settings

logger = logging.getLogger(__name__)


class HTTPProxyServer:
    """HTTP proxy server with authentication-based filtering."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        """Initialize HTTP proxy server."""
        self.host = host
        self.port = port
        self.app = web.Application()
        self.app.router.add_route("*", "/{path:.*}", self.handle_request)
        
        # Blocked domains (configurable)
        self.blocked_domains = [
            "youtube.com",
            "www.youtube.com", 
            "m.youtube.com",
            "youtu.be",
            "googlevideo.com"
        ]
        
        # Add more blocked domains from settings if available
        if hasattr(settings, 'dns_blocked_domains'):
            self.blocked_domains.extend(settings.dns_blocked_domains)
    
    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming HTTP proxy requests."""
        try:
            # Extract client info
            client_ip = request.remote
            user_agent = request.headers.get("User-Agent", "")
            
            # Generate MAC address for this client (same logic as web interface)
            mac_address = self._generate_mac_from_client(client_ip, user_agent)
            
            # Get target URL
            target_url = str(request.url)
            if not target_url.startswith("http"):
                target_url = f"http://{request.host}{request.path_qs}"
            
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc.lower()
            
            logger.info(f"Proxy request from {client_ip} ({mac_address}): {domain}")
            
            # Check if device is authenticated
            is_authenticated = await self._check_device_authentication(mac_address)
            
            # Check if domain should be blocked for unauthenticated users
            should_block = self._should_block_domain(domain)
            
            if should_block and not is_authenticated:
                logger.info(f"🚫 Blocking {domain} for unauthenticated device {mac_address}")
                return await self._return_captive_portal_redirect(request)
            
            # Forward the request
            logger.info(f"✅ Allowing {domain} for device {mac_address} (authenticated: {is_authenticated})")
            return await self._forward_request(request, target_url)
            
        except Exception as e:
            logger.error(f"Error handling proxy request: {e}")
            return web.Response(
                text=f"Proxy Error: {str(e)}", 
                status=500,
                headers={"Content-Type": "text/plain"}
            )
    
    def _generate_mac_from_client(self, client_ip: str, user_agent: str) -> str:
        """Generate consistent MAC address for client (same as web interface logic)."""
        import hashlib
        mac_seed = f"{client_ip}:{user_agent[:50]}"
        mac_hash = hashlib.md5(mac_seed.encode()).hexdigest()[:12]
        mac_address = ":".join([mac_hash[i:i+2] for i in range(0, 12, 2)])
        return mac_address
    
    async def _check_device_authentication(self, mac_address: str) -> bool:
        """Check if device is authenticated via traffic monitor."""
        try:
            # Use the same authentication check as the main system
            return mac_address in traffic_monitor.authorized_devices
        except Exception as e:
            logger.error(f"Error checking authentication for {mac_address}: {e}")
            return False
    
    def _should_block_domain(self, domain: str) -> bool:
        """Check if domain should be blocked for unauthenticated users."""
        # Remove port if present
        domain = domain.split(':')[0].lower()
        
        # Check against blocked domains
        for blocked_domain in self.blocked_domains:
            if blocked_domain in domain or domain.endswith(blocked_domain):
                return True
        
        return False
    
    async def _return_captive_portal_redirect(self, request: web.Request) -> web.Response:
        """Return captive portal redirect for blocked requests."""
        # Determine the homeguard web interface URL
        # In testing: http://localhost:8080
        # On Pi: http://192.168.x.x:8080 (gateway IP)
        captive_portal_url = f"http://{request.host.split(':')[0]}:8080"
        
        # For CONNECT requests (HTTPS), return error
        if request.method == "CONNECT":
            return web.Response(
                text="HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
                     "<html><body><h1>Access Denied</h1>"
                     f"<p>Please authenticate at <a href='{captive_portal_url}'>{captive_portal_url}</a></p>"
                     "</body></html>",
                status=403,
                headers={"Content-Type": "text/html"}
            )
        
        # For HTTP requests, return redirect page
        redirect_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Access Required</title>
            <meta http-equiv="refresh" content="0;url={captive_portal_url}">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin: 50px; }}
                .container {{ max-width: 500px; margin: 0 auto; }}
                .btn {{ background: #007bff; color: white; padding: 15px 30px; 
                        text-decoration: none; border-radius: 5px; display: inline-block; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 Authentication Required</h1>
                <p>You need to authenticate to access the internet.</p>
                <p>Redirecting to captive portal...</p>
                <a href="{captive_portal_url}" class="btn">Authenticate Now</a>
            </div>
        </body>
        </html>
        """
        
        return web.Response(
            text=redirect_html,
            status=200,
            headers={"Content-Type": "text/html"}
        )
    
    async def _forward_request(self, request: web.Request, target_url: str) -> web.Response:
        """Forward the request to the target server."""
        try:
            # Create aiohttp client session
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Prepare headers (remove hop-by-hop headers)
                headers = dict(request.headers)
                headers.pop('Host', None)
                headers.pop('Connection', None)
                headers.pop('Proxy-Connection', None)
                
                # Forward the request
                async with session.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    data=await request.read() if request.method in ["POST", "PUT", "PATCH"] else None,
                    allow_redirects=False
                ) as response:
                    # Prepare response headers
                    response_headers = dict(response.headers)
                    response_headers.pop('Transfer-Encoding', None)
                    response_headers.pop('Connection', None)
                    
                    # Read response body
                    body = await response.read()
                    
                    return web.Response(
                        body=body,
                        status=response.status,
                        headers=response_headers
                    )
                    
        except Exception as e:
            logger.error(f"Error forwarding request to {target_url}: {e}")
            return web.Response(
                text=f"Gateway Error: Unable to reach {target_url}",
                status=502,
                headers={"Content-Type": "text/plain"}
            )
    
    async def start(self):
        """Start the HTTP proxy server."""
        try:
            logger.info(f"Starting HTTP proxy server on {self.host}:{self.port}")
            logger.info(f"Blocked domains: {', '.join(self.blocked_domains)}")
            
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(runner, self.host, self.port)
            await site.start()
            
            logger.info(f"✅ HTTP proxy server started on http://{self.host}:{self.port}")
            logger.info("Configure your browser to use this as HTTP proxy for testing")
            
        except Exception as e:
            logger.error(f"Failed to start HTTP proxy server: {e}")
            raise
    
    async def stop(self):
        """Stop the HTTP proxy server."""
        logger.info("Stopping HTTP proxy server...")


# Global proxy server instance
proxy_server = HTTPProxyServer()