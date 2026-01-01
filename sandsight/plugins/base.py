from abc import ABC, abstractmethod
from typing import Dict, Any

class BasePlugin(ABC):
    """
    Base class that all SandSight plugins must inherit from.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of the plugin."""
        pass

    def on_static_analysis(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Hook called after static analysis is completed.
        Plugins can modify the results dictionary in-place.
        """
        pass

    def on_dynamic_analysis(self, results: Dict[str, Any]) -> None:
        """
        Hook called after dynamic analysis is completed.
        Plugins can modify the results dictionary in-place.
        """
        pass
