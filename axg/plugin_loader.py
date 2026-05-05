from __future__ import annotations

import json
import logging
import os
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
            if os.environ.get("ENABLE_REMOTE_PLUGINS", "false").lower() != "true":
                raise PluginLoadError(
                    "Remote plugin loading is disabled for security. "
                    "Set ENABLE_REMOTE_PLUGINS=true to enable."
                )
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
        """Fetches a plugin from a remote URL with strict SSRF protection (DNS Pinning)."""
        parsed = urlparse(plugin_url)
        hostname = parsed.hostname
        if not hostname:
            raise PluginLoadError(f"Invalid remote plugin URL: {plugin_url}")

        if parsed.scheme != "https":
            raise PluginLoadError(f"Remote plugins MUST use HTTPS: {plugin_url}")

        # Resolve and validate IP (DNS Pinning start)
        safe_ip = self._get_safe_ip(hostname)
        if not safe_ip:
            raise PluginLoadError(f"Remote plugin host '{hostname}' is unsafe or resolves to private IP.")

        # Reconstruct URL using IP to prevent rebinding
        port_str = f":{parsed.port}" if parsed.port else ""
        ip_url = parsed._replace(netloc=f"{safe_ip}{port_str}").geturl()

        logger.info(f"Fetching remote AXG plugin: {hostname} ({safe_ip})")
        try:
            # We use headers for Host and extensions for SNI to preserve TLS verification
            with httpx.Client(timeout=10.0, verify=True) as client:
                response = client.get(
                    ip_url,
                    headers={"Host": hostname},
                    extensions={"sni_hostname": hostname}
                )
                response.raise_for_status()
                data = response.json()
            return Plugin.model_validate(data)
        except httpx.HTTPError as exc:
            raise PluginLoadError(f"Failed to fetch remote plugin from {hostname}: {exc}") from exc
        except (json.JSONDecodeError, ValidationError) as exc:
            raise PluginLoadError(f"Remote plugin from {hostname} is invalid: {exc}") from exc

    def _get_safe_ip(self, hostname: str) -> str | None:
        """
        Resolves hostname and returns a safe IP only if ALL resolved addresses are global.
        Enterprise-grade protection against SSRF, CGNAT, and DNS rebinding.
        """
        try:
            # Use getaddrinfo to see ALL potential target addresses
            # We restrict to IPv4 for consistent pinning logic
            addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
            if not addr_info:
                return None
            
            ips = list(set(info[4][0] for info in addr_info))
            
            # CGNAT range (Shared Address Space)
            cgnat_net = ipaddress.ip_network("100.64.0.0/10")
            
            for ip in ips:
                ip_obj = ipaddress.ip_address(ip)
                
                # 1. Must be a global public address
                # is_global covers most, but we add explicit checks for defense-in-depth
                if not ip_obj.is_global or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_link_local or ip_obj.is_unspecified:
                    logger.warning(f"[AXG] Blocked unsafe/non-global IP for {hostname}: {ip}")
                    return None
                
                # 2. Block CGNAT (100.64.0.0/10)
                if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in cgnat_net:
                    logger.warning(f"[AXG] Blocked CGNAT IP for {hostname}: {ip}")
                    return None
            
            # Return the first safe IP for pinning
            return ips[0]
        except Exception as e:
            logger.error(f"[AXG] DNS resolution/validation failed for {hostname}: {e}")
            return None
