import importlib.util
import os
from pathlib import Path
from typing import List, Type
from sandsight.plugins.base import BasePlugin
from rich.console import Console

console = Console()

class PluginManager:
    """
    Manages discovery and execution of plugins.
    """
    def __init__(self, plugins_dir: str = "sandsight/plugins/user"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: List[BasePlugin] = []
        
        if not self.plugins_dir.exists():
            self.plugins_dir.mkdir(parents=True, exist_ok=True)
            # Create an __init__.py to make it a package
            (self.plugins_dir / "__init__.py").touch()

    def discover_plugins(self):
        """
        Dynamically load plugins from the plugins directory.
        """
        self.plugins = []
        for file in self.plugins_dir.glob("*.py"):
            if file.name == "__init__.py":
                continue
                
            module_name = f"sandsight.plugins.user.{file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if isinstance(item, type) and issubclass(item, BasePlugin) and item is not BasePlugin:
                            self.plugins.append(item())
                            console.print(f"[bold blue][*][/bold blue] Loaded plugin: [yellow]{item().name}[/yellow]")
                except Exception as e:
                    console.print(f"[bold red][!][/bold red] Failed to load plugin {file.name}: {e}")

    def run_static_hooks(self, file_path: str, results: Dict[str, Any]):
        for plugin in self.plugins:
            try:
                plugin.on_static_analysis(file_path, results)
            except Exception as e:
                console.print(f"[bold red][!][/bold red] Plugin {plugin.name} failed during static hook: {e}")

    def run_dynamic_hooks(self, results: Dict[str, Any]):
        for plugin in self.plugins:
            try:
                plugin.on_dynamic_analysis(results)
            except Exception as e:
                console.print(f"[bold red][!][/bold red] Plugin {plugin.name} failed during dynamic hook: {e}")
