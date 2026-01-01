from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any

class BaseParser(ABC):
    """
    Base class for all static analysis parsers.
    """
    def __init__(self, file_path: Path):
        self.file_path = file_path
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")

    @abstractmethod
    def analyze(self) -> Dict[str, Any]:
        """
        Perform static analysis and return a dictionary of results.
        """
        pass

    def get_basic_info(self) -> Dict[str, Any]:
        """
        Common file info for all formats.
        """
        import hashlib
        
        with open(self.file_path, "rb") as f:
            data = f.read()
            
        return {
            "hashes": {
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "size": len(data),
            "extension": self.file_path.suffix,
        }
