"""Main application entry point for MyProxy."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from myproxy.config.settings import settings
from myproxy.network.traffic_monitor import traffic_monitor
from myproxy.web.app import app
from myproxy.proxy.http_proxy import proxy_server
import uvicorn

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('myproxy.log') if not settings.debug else logging.NullHandler()
    ]
)

logger = logging.getLogger(__name__)


async def start_services():
    """Start all MyProxy services."""
    logger.info("Starting MyProxy services...")
    
    shutdown_event = asyncio.Event()
    
    def signal_handler():
        logger.info("Received shutdown signal")
        shutdown_event.set()
    
    # Set up signal handlers
    for sig in [signal.SIGTERM, signal.SIGINT]:
        asyncio.get_event_loop().add_signal_handler(sig, signal_handler)
    
    try:
        # Start the traffic monitor in the background
        monitor_task = asyncio.create_task(traffic_monitor.start())
        logger.info("TrafficMonitor started")
        
        # Start the HTTP proxy server
        proxy_task = asyncio.create_task(proxy_server.start())
        logger.info("HTTP Proxy started")
        
        # Start the web server
        config = uvicorn.Config(
            app=app,
            host=settings.web_host,
            port=settings.web_port,
            log_level=settings.log_level.lower(),
            reload=settings.debug
        )
        server = uvicorn.Server(config)
        
        logger.info(f"Starting web server on {settings.web_host}:{settings.web_port}")
        
        # Start server in background
        server_task = asyncio.create_task(server.serve())
        
        # Wait for shutdown signal
        await shutdown_event.wait()
        
        # Graceful shutdown
        logger.info("Shutting down services...")
        await traffic_monitor.stop()
        await proxy_server.stop()
        server.should_exit = True
        
        # Wait for tasks to complete
        await asyncio.gather(monitor_task, proxy_task, server_task, return_exceptions=True)
        
    except Exception as e:
        logger.error(f"Service startup failed: {e}")
        raise


def main():
    """Main entry point."""
    logger.info("HomeguardGuard Network Gateway starting...")
    logger.info("=" * 50)
    logger.info(f"🔧 Configuration loaded from: /etc/homeguard/config.yaml")
    logger.info(f"🚀 Operational Mode: {settings.gateway_mode.upper()}")

    if settings.gateway_mode == "transparent":
        logger.info("📝 Mode: TRANSPARENT - All traffic allowed through without filtering")
    elif settings.gateway_mode == "totp_testing":
        logger.info(f"📝 Mode: TOTP TESTING - Only blocking {settings.testing_ip}")
    elif settings.gateway_mode == "totp_full":
        logger.info("📝 Mode: TOTP FULL - All devices blocked until TOTP authentication")
    else:
        logger.warning(f"⚠️  Unknown mode: {settings.gateway_mode}")

    logger.info(f"🌐 Gateway: {settings.gateway_ip}:{settings.web_port}")
    logger.info(f"🔧 Debug mode: {settings.debug}")
    logger.info(f"🔄 Auto recovery: {settings.auto_recovery}")
    logger.info("=" * 50)

    try:
        asyncio.run(start_services())
    except KeyboardInterrupt:
        logger.info("HomeguardGuard shutdown complete")
    except Exception as e:
        logger.error(f"HomeguardGuard failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()