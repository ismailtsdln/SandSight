from sandsight.plugins.base import BasePlugin
from typing import Dict, Any

class ExamplePlugin(BasePlugin):
    """
    An example plugin for SandSight that adds a custom flag to the results.
    """
    
    @property
    def name(self) -> str:
        return "ExamplePlugin"

    @property
    def description(self) -> str:
        return "A simple plugin example that adds a 'scanned_by_plugin' flag."

    def on_static_analysis(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Add a custom flag to static analysis results.
        """
        if "plugin_data" not in results:
            results["plugin_data"] = {}
        
        results["plugin_data"]["example_static_flag"] = True
        results["plugin_data"]["target_file"] = file_path

    def on_dynamic_analysis(self, results: Dict[str, Any]) -> None:
        """
        Add a custom flag to dynamic analysis results.
        """
        if "plugin_data" not in results:
            results["plugin_data"] = {}
            
        results["plugin_data"]["example_dynamic_flag"] = True
