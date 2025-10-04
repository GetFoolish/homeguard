"""Main entry point for Homeguard service."""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from homeguard.config.settings import settings
from homeguard.api.service import app
from homeguard.iptables.manager import iptables_manager
import uvicorn

# Configure logging
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format=log_format,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(settings.log_file)
    ]
)

logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command-line arguments and override settings."""
    parser = argparse.ArgumentParser(description="Homeguard Network Gateway")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run in LIVE mode (apply actual iptables changes)"
    )
    parser.add_argument(
        "--mode",
        choices=["transparent", "totp"],
        help="System mode (transparent or totp)"
    )
    args = parser.parse_args()

    # Override settings based on command-line arguments
    if args.live:
        settings.execution_mode = "live"
    if args.mode:
        settings.system_mode = args.mode

    return args


def main():
    """Main entry point."""
    # Parse command-line arguments and override settings
    parse_arguments()

    logger.info("=" * 60)
    logger.info("🛡️  HOMEGUARD NETWORK GATEWAY v4.0.0")
    logger.info("=" * 60)
    logger.info(f"🔧 System Mode: {settings.system_mode.upper()}")
    logger.info(f"🧪 Execution Mode: {settings.execution_mode.upper()}")
    logger.info(f"🌐 Gateway: {settings.gateway_ip}:{settings.web_port}")
    logger.info(f"📊 Database: {settings.database_url}")
    logger.info(f"📝 Log File: {settings.log_file}")

    if settings.execution_mode == "testing":
        logger.warning("⚠️  TESTING MODE: No actual iptables changes will be made!")
        logger.warning("⚠️  All iptables commands will be logged only.")
    else:
        logger.warning("🚨 LIVE MODE: Actual iptables changes will be applied!")
        logger.warning("🚨 This will affect network traffic routing!")

    logger.info("=" * 60)

    try:
        # Start the uvicorn server
        config = uvicorn.Config(
            app=app,
            host=settings.web_host,
            port=settings.web_port,
            log_level=settings.log_level.lower(),
            access_log=True
        )
        server = uvicorn.Server(config)

        logger.info(f"🚀 Starting web server on {settings.web_host}:{settings.web_port}")
        logger.info(f"📱 Dashboard: http://{settings.gateway_ip}:{settings.web_port}/")
        logger.info("=" * 60)

        # Run the server
        server.run()

    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal...")
        # Set to transparent mode on shutdown
        logger.info("🔓 Setting system to transparent mode before shutdown...")
        iptables_manager.set_transparent_mode()
        logger.info("✅ Homeguard shutdown complete")

    except Exception as e:
        logger.error(f"❌ Homeguard failed to start: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
