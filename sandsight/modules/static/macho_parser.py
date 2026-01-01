import lief
from pathlib import Path
from typing import Dict, Any, List
from .base import BaseParser

class MachOParser(BaseParser):
    """
    Parser for macOS Mach-O files using LIEF.
    """
    def __init__(self, file_path: Path):
        super().__init__(file_path)
        try:
            self.binary = lief.parse(str(file_path))
            if not self.binary:
                raise ValueError("Could not parse Mach-O binary.")
        except Exception as e:
            raise ValueError(f"Invalid Mach-O file: {e}")

    def analyze(self) -> Dict[str, Any]:
        results = self.get_basic_info()
        
        results.update({
            "format": "Mach-O",
            "entry_point": hex(self.binary.entrypoint) if hasattr(self.binary, 'entrypoint') else None,
            "architecture": str(self.binary.header.cpu_type),
            "commands": [],
            "sections": [],
            "imports": [],
            "exports": [],
        })

        # Load commands
        for cmd in self.binary.commands:
            results["commands"].append(str(cmd.command))

        # Sections analysis
        for section in self.binary.sections:
            results["sections"].append({
                "name": section.name,
                "offset": hex(section.offset),
                "size": hex(section.size),
                "entropy": section.entropy,
            })

        # Imports
        if hasattr(self.binary, 'imported_functions'):
            for func in self.binary.imported_functions:
                results["imports"].append(func)

        # Exports
        if hasattr(self.binary, 'exported_functions'):
            for func in self.binary.exported_functions:
                results["exports"].append(func)

        return results
