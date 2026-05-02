from __future__ import annotations

import json
import logging
from functools import lru_cache
import socket
import ipaddress
from urllib.parse import urlparse
from pathlib import Path

import httpx
from pydantic import ValidationError

from axg.models import Plugin

logger = logging.getLogger(__name__)

class PluginLoadError(Exception):
    pass


class PluginLoader:
    """
    Loads AXG plugins from local filesystem or remote URIs.
    Supports OIDC-like dynamic policy discovery.
    """
    def __init__(self, plugins_dir: Path | None = None):
        self.plugins_dir = plugins_dir or Path(__file__).resolve().parent.parent / "plugins"

    @lru_cache(maxsize=64)
    def load(self, plugin_id: str) -> Plugin:
        """Loads a plugin by ID (local name) or URI (remote URL)."""
        if plugin_id.startswith(("http://", "https://")):
            return self._load_remote(plugin_id)
        return self._load_local(plugin_id)

    def _load_local(self, plugin_id: str) -> Plugin:
        plugin_path = self.plugins_dir / plugin_id / "rules.json"
        if not plugin_path.exists():
            raise PluginLoadError(f"Local plugin '{plugin_id}' not found at {plugin_path}")

        try:
            with plugin_path.open("r", encoding="utf-8") as plugin_file:
                data = json.load(plugin_file)
            return Plugin.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as exc:
            raise PluginLoadError(f"Local plugin '{plugin_id}' is invalid: {exc}") from exc

    def _load_remote(self, plugin_url: str) -> Plugin:
        """Fetches a plugin from a remote URL with SSRF protection."""
        if not self._is_safe_url(plugin_url):
            raise PluginLoadError(f"Remote plugin URL is unsafe or not HTTPS: {plugin_url}")

        logger.info(f"Fetching remote AXG plugin: {plugin_url}")
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(plugin_url)
                response.raise_for_status()
                data = response.json()
            return Plugin.model_validate(data)
        except httpx.HTTPError as exc:
            raise PluginLoadError(f"Failed to fetch remote plugin from {plugin_url}: {exc}") from exc
        except (json.JSONDecodeError, ValidationError) as exc:
            raise PluginLoadError(f"Remote plugin from {plugin_url} is invalid: {exc}") from exc

    def _is_safe_url(self, url: str) -> bool:
        """Validates that a URL is safe for remote plugin loading (SSRF protection)."""
        try:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                return False
            
            # Resolve hostname to IP to check for private networks
            hostname = parsed.hostname
            if not hostname:
                return False
                
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Block private, loopback and link-local IPs
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False
                
            return True
        except Exception:
            return False
