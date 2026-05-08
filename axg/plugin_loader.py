from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from axg.models import Plugin


class PluginLoadError(Exception):
    pass


class PluginLoader:
    def __init__(self, plugins_dir: Path | None = None):
        self.plugins_dir = plugins_dir or Path(__file__).resolve().parent.parent / "plugins"

    @lru_cache(maxsize=64)
    def load(self, plugin_id: str) -> Plugin:
        plugin_path = self.plugins_dir / plugin_id / "rules.json"
        if not plugin_path.exists():
            raise PluginLoadError(f"plugin '{plugin_id}' not found")

        try:
            with plugin_path.open("r", encoding="utf-8") as plugin_file:
                data = json.load(plugin_file)
            return Plugin.model_validate(data)
        except json.JSONDecodeError as exc:
            raise PluginLoadError(f"plugin '{plugin_id}' contains invalid JSON") from exc
        except ValidationError as exc:
            raise PluginLoadError(f"plugin '{plugin_id}' failed schema validation") from exc

    def clear_cache(self):
        """Clear the plugin cache, allowing policies to be reloaded."""
        self.load.cache_clear()
