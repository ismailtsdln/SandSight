import pefile
import math
from pathlib import Path
from typing import Dict, Any, List
from .base import BaseParser

class PEParser(BaseParser):
    """
    Parser for Windows PE files.
    """
    def __init__(self, file_path: Path):
        super().__init__(file_path)
        try:
            self.pe = pefile.PE(str(file_path))
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def analyze(self) -> Dict[str, Any]:
        results = self.get_basic_info()
        
        results.update({
            "format": "PE",
            "entry_point": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
            "compilation_timestamp": self.pe.FILE_HEADER.dump_dict().get('TimeDateStamp', {}).get('Value'),
            "sections": [],
            "imports": {},
            "exports": [],
        })

        # Sections analysis
        for section in self.pe.sections:
            section_data = {
                "name": section.Name.decode(errors='replace').strip('\x00'),
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "entropy": self.calculate_entropy(section.get_data()),
            }
            results["sections"].append(section_data)

        # Imports analysis
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                results["imports"][dll_name] = []
                for imp in entry.imports:
                    results["imports"][dll_name].append(
                        imp.name.decode() if imp.name else f"ordinal_{imp.ordinal}"
                    )

        # Exports analysis
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                results["exports"].append(
                    exp.name.decode() if exp.name else f"ordinal_{exp.ordinal}"
                )

        return results
