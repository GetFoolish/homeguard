"""Enhanced traffic filtering with keyword and URL blocking capabilities."""

import re
import logging
import asyncio
import subprocess
from typing import Set, Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    """Result of traffic filtering operation."""
    blocked: bool
    reason: str
    rule_type: str
    pattern: str
    action_taken: str = ""


class ContentInspector:
    """Handles HTTP content inspection for keyword filtering."""
    
    def __init__(self):
        """Initialize content inspector."""
        self.blocked_keywords: Set[str] = set()
        self.blocked_patterns: Dict[str, re.Pattern] = {}
        
    def add_keyword(self, keyword: str):
        """Add a keyword to block list."""
        self.blocked_keywords.add(keyword.lower())
        logger.info(f"Added keyword filter: {keyword}")
    
    def add_pattern(self, pattern_name: str, regex_pattern: str):
        """Add a regex pattern to block list."""
        try:
            compiled_pattern = re.compile(regex_pattern, re.IGNORECASE)
            self.blocked_patterns[pattern_name] = compiled_pattern
            logger.info(f"Added pattern filter: {pattern_name}")
        except re.error as e:
            logger.error(f"Invalid regex pattern {pattern_name}: {e}")
    
    def remove_keyword(self, keyword: str):
        """Remove a keyword from block list."""
        self.blocked_keywords.discard(keyword.lower())
        logger.info(f"Removed keyword filter: {keyword}")
    
    def remove_pattern(self, pattern_name: str):
        """Remove a pattern from block list."""
        if pattern_name in self.blocked_patterns:
            del self.blocked_patterns[pattern_name]
            logger.info(f"Removed pattern filter: {pattern_name}")
    
    def inspect_content(self, content: str, url: str = "") -> FilterResult:
        """
        Inspect content for blocked keywords and patterns.
        
        Args:
            content: Text content to inspect
            url: URL of the content (optional)
            
        Returns:
            FilterResult indicating if content should be blocked
        """
        content_lower = content.lower()
        
        # Check for blocked keywords
        for keyword in self.blocked_keywords:
            if keyword in content_lower:
                return FilterResult(
                    blocked=True,
                    reason=f"Contains blocked keyword: {keyword}",
                    rule_type="keyword",
                    pattern=keyword,
                    action_taken="content_blocked"
                )
        
        # Check for blocked patterns
        for pattern_name, pattern in self.blocked_patterns.items():
            if pattern.search(content):
                return FilterResult(
                    blocked=True,
                    reason=f"Matches blocked pattern: {pattern_name}",
                    rule_type="pattern",
                    pattern=pattern_name,
                    action_taken="content_blocked"
                )
        
        return FilterResult(
            blocked=False,
            reason="Content allowed",
            rule_type="none",
            pattern="",
            action_taken="allowed"
        )
    
    def get_stats(self) -> Dict[str, int]:
        """Get filtering statistics."""
        return {
            "blocked_keywords": len(self.blocked_keywords),
            "blocked_patterns": len(self.blocked_patterns)
        }


class DomainFilter:
    """Handles domain-based filtering."""
    
    def __init__(self):
        """Initialize domain filter."""
        self.blocked_domains: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.domain_patterns: Dict[str, re.Pattern] = {}
        
    def add_domain(self, domain: str):
        """Add a domain to block list."""
        # Handle wildcard domains
        if domain.startswith("*."):
            # Convert wildcard to regex pattern
            pattern_name = f"wildcard_{domain}"
            escaped_domain = re.escape(domain[2:])  # Remove *.
            regex_pattern = f".*\\.{escaped_domain}$|^{escaped_domain}$"
            try:
                self.domain_patterns[pattern_name] = re.compile(regex_pattern, re.IGNORECASE)
                logger.info(f"Added wildcard domain filter: {domain}")
            except re.error as e:
                logger.error(f"Invalid wildcard domain pattern {domain}: {e}")
        else:
            self.blocked_domains.add(domain.lower())
            logger.info(f"Added domain filter: {domain}")
    
    def add_ip(self, ip: str):
        """Add an IP address to block list."""
        self.blocked_ips.add(ip)
        logger.info(f"Added IP filter: {ip}")
    
    def remove_domain(self, domain: str):
        """Remove a domain from block list."""
        if domain.startswith("*."):
            pattern_name = f"wildcard_{domain}"
            if pattern_name in self.domain_patterns:
                del self.domain_patterns[pattern_name]
                logger.info(f"Removed wildcard domain filter: {domain}")
        else:
            self.blocked_domains.discard(domain.lower())
            logger.info(f"Removed domain filter: {domain}")
    
    def remove_ip(self, ip: str):
        """Remove an IP from block list."""
        self.blocked_ips.discard(ip)
        logger.info(f"Removed IP filter: {ip}")
    
    def is_domain_blocked(self, domain: str) -> FilterResult:
        """
        Check if a domain should be blocked.
        
        Args:
            domain: Domain name to check
            
        Returns:
            FilterResult indicating if domain should be blocked
        """
        domain_lower = domain.lower()
        
        # Check exact domain matches
        if domain_lower in self.blocked_domains:
            return FilterResult(
                blocked=True,
                reason=f"Domain blocked: {domain}",
                rule_type="domain",
                pattern=domain,
                action_taken="domain_blocked"
            )
        
        # Check wildcard patterns
        for pattern_name, pattern in self.domain_patterns.items():
            if pattern.match(domain_lower):
                return FilterResult(
                    blocked=True,
                    reason=f"Domain matches blocked pattern: {pattern_name}",
                    rule_type="domain_pattern",
                    pattern=pattern_name,
                    action_taken="domain_blocked"
                )
        
        return FilterResult(
            blocked=False,
            reason="Domain allowed",
            rule_type="none",
            pattern="",
            action_taken="allowed"
        )
    
    def is_ip_blocked(self, ip: str) -> FilterResult:
        """
        Check if an IP should be blocked.
        
        Args:
            ip: IP address to check
            
        Returns:
            FilterResult indicating if IP should be blocked
        """
        if ip in self.blocked_ips:
            return FilterResult(
                blocked=True,
                reason=f"IP blocked: {ip}",
                rule_type="ip",
                pattern=ip,
                action_taken="ip_blocked"
            )
        
        return FilterResult(
            blocked=False,
            reason="IP allowed",
            rule_type="none",
            pattern="",
            action_taken="allowed"
        )
    
    def get_stats(self) -> Dict[str, int]:
        """Get filtering statistics."""
        return {
            "blocked_domains": len(self.blocked_domains),
            "blocked_ips": len(self.blocked_ips),
            "domain_patterns": len(self.domain_patterns)
        }


class URLFilter:
    """Handles URL pattern-based filtering."""
    
    def __init__(self):
        """Initialize URL filter."""
        self.url_patterns: Dict[str, re.Pattern] = {}
        self.blocked_paths: Set[str] = set()
        
    def add_url_pattern(self, pattern_name: str, regex_pattern: str):
        """Add a URL pattern to block list."""
        try:
            compiled_pattern = re.compile(regex_pattern, re.IGNORECASE)
            self.url_patterns[pattern_name] = compiled_pattern
            logger.info(f"Added URL pattern filter: {pattern_name}")
        except re.error as e:
            logger.error(f"Invalid URL pattern {pattern_name}: {e}")
    
    def add_path(self, path: str):
        """Add a URL path to block list."""
        self.blocked_paths.add(path.lower())
        logger.info(f"Added path filter: {path}")
    
    def remove_url_pattern(self, pattern_name: str):
        """Remove a URL pattern from block list."""
        if pattern_name in self.url_patterns:
            del self.url_patterns[pattern_name]
            logger.info(f"Removed URL pattern filter: {pattern_name}")
    
    def remove_path(self, path: str):
        """Remove a path from block list."""
        self.blocked_paths.discard(path.lower())
        logger.info(f"Removed path filter: {path}")
    
    def is_url_blocked(self, url: str) -> FilterResult:
        """
        Check if a URL should be blocked.
        
        Args:
            url: URL to check
            
        Returns:
            FilterResult indicating if URL should be blocked
        """
        try:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            
            # Check blocked paths
            for blocked_path in self.blocked_paths:
                if blocked_path in path_lower:
                    return FilterResult(
                        blocked=True,
                        reason=f"URL path blocked: {blocked_path}",
                        rule_type="path",
                        pattern=blocked_path,
                        action_taken="url_blocked"
                    )
            
            # Check URL patterns
            for pattern_name, pattern in self.url_patterns.items():
                if pattern.search(url):
                    return FilterResult(
                        blocked=True,
                        reason=f"URL matches blocked pattern: {pattern_name}",
                        rule_type="url_pattern",
                        pattern=pattern_name,
                        action_taken="url_blocked"
                    )
            
            return FilterResult(
                blocked=False,
                reason="URL allowed",
                rule_type="none",
                pattern="",
                action_taken="allowed"
            )
            
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return FilterResult(
                blocked=False,
                reason="URL parsing error",
                rule_type="error",
                pattern="",
                action_taken="allowed"
            )
    
    def get_stats(self) -> Dict[str, int]:
        """Get filtering statistics."""
        return {
            "url_patterns": len(self.url_patterns),
            "blocked_paths": len(self.blocked_paths)
        }


class EnhancedTrafficFilter:
    """
    Enhanced traffic filtering system with keyword, URL, and domain blocking.
    Integrates with the phase management system.
    """
    
    def __init__(self):
        """Initialize enhanced traffic filter."""
        self.content_inspector = ContentInspector()
        self.domain_filter = DomainFilter()
        self.url_filter = URLFilter()
        self.is_active = False
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "blocks_by_type": {}
        }
        
    async def start(self):
        """Start the enhanced traffic filter."""
        try:
            logger.info("Starting Enhanced Traffic Filter...")
            
            # Initialize with default blocked content for testing
            await self._load_default_filters()
            
            self.is_active = True
            logger.info("✅ Enhanced Traffic Filter started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start Enhanced Traffic Filter: {e}")
            raise
    
    async def stop(self):
        """Stop the enhanced traffic filter."""
        logger.info("Stopping Enhanced Traffic Filter...")
        self.is_active = False
        logger.info("✅ Enhanced Traffic Filter stopped")
    
    async def _load_default_filters(self):
        """Load default filters for testing."""
        # Add default blocked domains
        self.domain_filter.add_domain("ndtv.com")
        self.domain_filter.add_domain("*.ndtv.com")
        
        # Add default blocked keywords
        self.content_inspector.add_keyword("mickey")
        self.content_inspector.add_keyword("jj")
        self.content_inspector.add_keyword("mickey and jj")
        
        # Add default URL patterns
        self.url_filter.add_url_pattern("ndtv_urls", r".*ndtv\.com.*")
        
        logger.info("Default filters loaded")
    
    def apply_phase_rules(self, phase_rules: List):
        """Apply filtering rules from phase manager."""
        try:
            # Clear existing rules
            self.clear_all_filters()
            
            # Apply rules based on type
            for rule in phase_rules:
                if not rule.enabled or rule.action != "block":
                    continue
                
                if rule.rule_type == "domain":
                    self.domain_filter.add_domain(rule.pattern)
                elif rule.rule_type == "keyword":
                    self.content_inspector.add_keyword(rule.pattern)
                elif rule.rule_type == "url_pattern":
                    self.url_filter.add_url_pattern(f"phase_rule_{rule.pattern}", rule.pattern)
                
            logger.info(f"Applied {len(phase_rules)} phase rules to traffic filter")
            
        except Exception as e:
            logger.error(f"Error applying phase rules: {e}")
    
    def clear_all_filters(self):
        """Clear all filtering rules."""
        self.content_inspector.blocked_keywords.clear()
        self.content_inspector.blocked_patterns.clear()
        self.domain_filter.blocked_domains.clear()
        self.domain_filter.blocked_ips.clear()
        self.domain_filter.domain_patterns.clear()
        self.url_filter.url_patterns.clear()
        self.url_filter.blocked_paths.clear()
        
        logger.info("All filters cleared")
    
    async def filter_request(self, url: str, content: str = "", client_ip: str = "") -> FilterResult:
        """
        Filter a request through all filtering mechanisms.
        
        Args:
            url: Request URL
            content: Request/response content (optional)
            client_ip: Client IP address (optional)
            
        Returns:
            FilterResult indicating if request should be blocked
        """
        self.stats["total_requests"] += 1
        
        try:
            # Extract domain from URL
            domain = urlparse(url).netloc
            
            # 1. Check domain filtering
            domain_result = self.domain_filter.is_domain_blocked(domain)
            if domain_result.blocked:
                await self._log_block(domain_result, url, client_ip)
                return domain_result
            
            # 2. Check URL pattern filtering
            url_result = self.url_filter.is_url_blocked(url)
            if url_result.blocked:
                await self._log_block(url_result, url, client_ip)
                return url_result
            
            # 3. Check content filtering (if content available)
            if content:
                content_result = self.content_inspector.inspect_content(content, url)
                if content_result.blocked:
                    await self._log_block(content_result, url, client_ip)
                    return content_result
            
            # Request allowed
            self.stats["allowed_requests"] += 1
            return FilterResult(
                blocked=False,
                reason="Request allowed",
                rule_type="none",
                pattern="",
                action_taken="allowed"
            )
            
        except Exception as e:
            logger.error(f"Error filtering request {url}: {e}")
            # Default to allow on error
            self.stats["allowed_requests"] += 1
            return FilterResult(
                blocked=False,
                reason=f"Filter error: {str(e)}",
                rule_type="error",
                pattern="",
                action_taken="allowed"
            )
    
    async def _log_block(self, result: FilterResult, url: str, client_ip: str):
        """Log a blocked request."""
        self.stats["blocked_requests"] += 1
        
        # Update block type statistics
        if result.rule_type in self.stats["blocks_by_type"]:
            self.stats["blocks_by_type"][result.rule_type] += 1
        else:
            self.stats["blocks_by_type"][result.rule_type] = 1
        
        logger.info(f"BLOCKED: {result.reason} | URL: {url} | Client: {client_ip}")
        
        # Log to database (optional - can be implemented later)
        try:
            from ..database.connection import db_manager
            from ..database.models import AccessLog
            
            async with db_manager.session_maker() as session:
                log_entry = AccessLog(
                    mac_address=client_ip or "unknown",
                    event_type="content_blocked",
                    event_details=f"{result.reason} | URL: {url}",
                    timestamp=datetime.utcnow()
                )
                session.add(log_entry)
                await session.commit()
                
        except Exception as e:
            logger.debug(f"Failed to log block to database: {e}")
    
    def get_filter_stats(self) -> Dict[str, any]:
        """Get comprehensive filtering statistics."""
        return {
            "filter_status": "active" if self.is_active else "inactive",
            "request_stats": self.stats,
            "content_inspector": self.content_inspector.get_stats(),
            "domain_filter": self.domain_filter.get_stats(),
            "url_filter": self.url_filter.get_stats(),
            "total_rules": (
                len(self.content_inspector.blocked_keywords) +
                len(self.content_inspector.blocked_patterns) +
                len(self.domain_filter.blocked_domains) +
                len(self.domain_filter.blocked_ips) +
                len(self.domain_filter.domain_patterns) +
                len(self.url_filter.url_patterns) +
                len(self.url_filter.blocked_paths)
            )
        }
    
    def reset_stats(self):
        """Reset filtering statistics."""
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "blocks_by_type": {}
        }
        logger.info("Filter statistics reset")
    
    # Public API methods for rule management
    
    def add_blocked_domain(self, domain: str):
        """Add a domain to the block list."""
        self.domain_filter.add_domain(domain)
    
    def remove_blocked_domain(self, domain: str):
        """Remove a domain from the block list."""
        self.domain_filter.remove_domain(domain)
    
    def add_blocked_keyword(self, keyword: str):
        """Add a keyword to the block list."""
        self.content_inspector.add_keyword(keyword)
    
    def remove_blocked_keyword(self, keyword: str):
        """Remove a keyword from the block list."""
        self.content_inspector.remove_keyword(keyword)
    
    def add_url_pattern(self, name: str, pattern: str):
        """Add a URL pattern to the block list."""
        self.url_filter.add_url_pattern(name, pattern)
    
    def remove_url_pattern(self, name: str):
        """Remove a URL pattern from the block list."""
        self.url_filter.remove_url_pattern(name)
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of blocked domains."""
        return list(self.domain_filter.blocked_domains)
    
    def get_blocked_keywords(self) -> List[str]:
        """Get list of blocked keywords."""
        return list(self.content_inspector.blocked_keywords)
    
    def get_url_patterns(self) -> List[str]:
        """Get list of URL patterns."""
        return list(self.url_filter.url_patterns.keys())


# Global enhanced traffic filter instance
enhanced_filter = EnhancedTrafficFilter()