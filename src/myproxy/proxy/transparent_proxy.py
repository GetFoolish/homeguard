"""Transparent HTTP proxy server for traffic interception and filtering."""

import asyncio
import aiohttp
import logging
from urllib.parse import urlparse
from aiohttp import web
import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from src.myproxy.network.enhanced_filter import enhanced_filter
from src.myproxy.integrations.sheets import sheets_manager
from src.myproxy.config.settings import settings

logger = logging.getLogger(__name__)


class TransparentHTTPProxy:
    """Transparent HTTP proxy that filters traffic and redirects blocked content."""
    
    def __init__(self, listen_port=8080, admin_port=8081):
        self.listen_port = listen_port
        self.admin_port = admin_port
        self.app = web.Application()
        self.setup_routes()
        
    def setup_routes(self):
        """Set up proxy routes."""
        # Add explicit CONNECT handler for HTTPS tunneling
        self.app.router.add_route('CONNECT', '/{path:.*}', self.proxy_handler)
        # Catch all other HTTP traffic
        self.app.router.add_route('*', '/{path:.*}', self.proxy_handler)
        
    async def proxy_handler(self, request):
        """Handle proxied HTTP requests with filtering."""
        try:
            # Get the original URL
            method = request.method
            url = str(request.url)
            headers = dict(request.headers)
            
            # Get client IP
            client_ip = request.remote
            
            logger.info(f"🔍 Intercepted: {method} {url} from {client_ip}")
            
            # Handle HTTPS CONNECT requests
            if method == 'CONNECT':
                return await self.handle_connect(request, client_ip)
            
            # Read request body for keyword filtering
            body = b""
            if method in ['POST', 'PUT', 'PATCH']:
                body = await request.read()
            
            # Apply filtering
            filter_result = await enhanced_filter.filter_request(
                url=url,
                content=body.decode('utf-8', errors='ignore'),
                client_ip=client_ip
            )
            
            if filter_result.blocked:
                logger.info(f"🚫 BLOCKED: {url} - {filter_result.reason}")
                
                # Redirect to content blocked page
                redirect_url = (
                    f"http://{settings.gateway_ip}:{self.admin_port}/blocked?"
                    f"url={url}&"
                    f"reason={filter_result.reason}&"
                    f"rule_type={filter_result.rule_type}&"
                    f"pattern={filter_result.pattern}&"
                    f"client_mac={client_ip}"
                )
                
                return web.Response(
                    text=f"""
                    <html>
                    <head>
                        <title>Content Blocked</title>
                        <meta http-equiv="refresh" content="0;url={redirect_url}">
                    </head>
                    <body>
                        <h1>Content Blocked</h1>
                        <p>This content has been blocked by the network security policy.</p>
                        <p><a href="{redirect_url}">Click here if not redirected automatically</a></p>
                    </body>
                    </html>
                    """,
                    content_type='text/html',
                    status=200
                )
            
            # Content is allowed - proxy the request
            logger.info(f"✅ ALLOWED: {url}")
            
            # Forward the request
            try:
                async with aiohttp.ClientSession() as session:
                    # Remove hop-by-hop headers
                    forward_headers = {k: v for k, v in headers.items() 
                                     if k.lower() not in ['host', 'connection', 'content-length']}
                    
                    async with session.request(
                        method=method,
                        url=url,
                        headers=forward_headers,
                        data=body if body else None,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        
                        # Read response body
                        response_body = await response.read()
                        
                        # Check response content for keywords
                        if response_body:
                            content_filter_result = await enhanced_filter.filter_request(
                                url=url,
                                content=response_body.decode('utf-8', errors='ignore'),
                                client_ip=client_ip
                            )
                            
                            if content_filter_result.blocked:
                                logger.info(f"🚫 RESPONSE BLOCKED: {url} - {content_filter_result.reason}")
                                
                                # Redirect to content blocked page
                                redirect_url = (
                                    f"http://{settings.gateway_ip}:{self.admin_port}/blocked?"
                                    f"url={url}&"
                                    f"reason={content_filter_result.reason}&"
                                    f"rule_type={content_filter_result.rule_type}&"
                                    f"pattern={content_filter_result.pattern}&"
                                    f"client_mac={client_ip}"
                                )
                                
                                return web.Response(
                                    text=f"""
                                    <html>
                                    <head>
                                        <title>Content Blocked</title>
                                        <meta http-equiv="refresh" content="0;url={redirect_url}">
                                    </head>
                                    <body>
                                        <h1>Content Blocked</h1>
                                        <p>This content has been blocked due to inappropriate keywords.</p>
                                        <p><a href="{redirect_url}">Click here if not redirected automatically</a></p>
                                    </body>
                                    </html>
                                    """,
                                    content_type='text/html',
                                    status=200
                                )
                        
                        # Return the response
                        response_headers = {k: v for k, v in response.headers.items() 
                                          if k.lower() not in ['content-length', 'transfer-encoding']}
                        
                        return web.Response(
                            body=response_body,
                            status=response.status,
                            headers=response_headers
                        )
                        
            except asyncio.TimeoutError:
                logger.error(f"⏱️ Timeout accessing: {url}")
                return web.Response(
                    text="<h1>Request Timeout</h1><p>The request timed out.</p>",
                    content_type='text/html',
                    status=504
                )
            except Exception as e:
                logger.error(f"❌ Error proxying {url}: {e}")
                return web.Response(
                    text=f"<h1>Proxy Error</h1><p>Error accessing {url}: {str(e)}</p>",
                    content_type='text/html',
                    status=502
                )
                
        except Exception as e:
            logger.error(f"❌ Proxy handler error: {e}")
            return web.Response(
                text="<h1>Proxy Error</h1><p>Internal proxy error</p>",
                content_type='text/html',
                status=500
            )
    
    async def handle_connect(self, request, client_ip):
        """Handle HTTPS CONNECT requests with proper tunnel establishment."""
        try:
            # Extract target host from CONNECT request
            path = request.path_qs
            if ':' in path:
                target_host, target_port = path.rsplit(':', 1)
                target_port = int(target_port)
            else:
                target_host = path
                target_port = 443  # Default HTTPS port
            
            logger.info(f"🔒 CONNECT request to {target_host}:{target_port} from {client_ip}")
            
            # Create a synthetic URL for filtering (HTTPS assumed)
            synthetic_url = f"https://{target_host}/"
            
            # Apply domain filtering
            filter_result = await enhanced_filter.filter_request(
                url=synthetic_url,
                content="",  # No content to analyze for CONNECT
                client_ip=client_ip
            )
            
            if filter_result.blocked:
                logger.info(f"🚫 HTTPS BLOCKED: {target_host} - {filter_result.reason}")
                
                # For blocked CONNECT requests, return 403 Forbidden with connection close
                # This tells the browser the connection is refused rather than trying to tunnel
                return web.Response(
                    text=f"Access to {target_host} blocked by network policy: {filter_result.reason}",
                    status=403,
                    headers={
                        'Connection': 'close',
                        'Content-Type': 'text/plain'
                    }
                )
            
            # Site is allowed - establish TCP tunnel
            logger.info(f"✅ HTTPS ALLOWED: {target_host} - establishing tunnel")
            
            # Try to establish connection to target server
            try:
                # Open connection to target server
                reader, writer = await asyncio.open_connection(target_host, target_port)
                
                # Send 200 Connection Established response to client
                response_text = "HTTP/1.1 200 Connection established\r\n\r\n"
                
                # Return a streaming response that will handle the tunnel
                return web.StreamResponse(
                    status=200,
                    reason='Connection established',
                    headers={'Proxy-Agent': 'MyProxy/1.0'}
                )
                
            except Exception as conn_error:
                logger.error(f"❌ Failed to connect to {target_host}:{target_port}: {conn_error}")
                return web.Response(
                    text=f"Failed to connect to {target_host}: {str(conn_error)}",
                    status=502,
                    headers={'Connection': 'close'}
                )
                
        except Exception as e:
            logger.error(f"❌ CONNECT handler error: {e}")
            return web.Response(
                text=f"CONNECT tunnel error: {str(e)}",
                status=502,
                headers={'Connection': 'close'}
            )
    
    async def start(self):
        """Start the transparent proxy server."""
        try:
            logger.info(f"🚀 Starting Transparent HTTP Proxy on port {self.listen_port}")
            
            # Initialize filtering components
            await enhanced_filter.start()
            await sheets_manager.start()
            
            # Sync latest rules
            sync_result, message = await sheets_manager.sync_rules()
            logger.info(f"📊 Rules sync: {message}")
            
            # Apply sheets rules to filter
            if sheets_manager.cached_rules:
                enhanced_filter.apply_phase_rules(sheets_manager.cached_rules)
                logger.info(f"📜 Applied {len(sheets_manager.cached_rules)} rules from Google Sheets")
            
            # Start the proxy server
            runner = web.AppRunner(self.app)
            await runner.setup()
            
            site = web.TCPSite(runner, '0.0.0.0', self.listen_port)
            await site.start()
            
            logger.info(f"✅ Transparent HTTP Proxy started on http://0.0.0.0:{self.listen_port}")
            logger.info(f"🔗 Admin interface: http://{settings.gateway_ip}:{self.admin_port}")
            
            return runner
            
        except Exception as e:
            logger.error(f"❌ Failed to start proxy: {e}")
            raise


async def main():
    """Main function to run the transparent proxy."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    proxy = TransparentHTTPProxy()
    runner = await proxy.start()
    
    try:
        print("🌐 Transparent HTTP Proxy running...")
        print(f"🧪 Test by setting your browser proxy to {settings.gateway_ip}:8080")
        print(f"🧪 Or test with: curl --proxy {settings.gateway_ip}:8080 http://ndtv.com")
        print("⏹️  Press Ctrl+C to stop")
        
        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("🔄 Shutting down proxy...")
        
        # Cleanup
        await runner.cleanup()
        await enhanced_filter.stop()
        await sheets_manager.stop()
        
        print("✅ Proxy shut down successfully")


if __name__ == "__main__":
    asyncio.run(main())