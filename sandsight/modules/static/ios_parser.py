import zipfile
import plistlib
from pathlib import Path
from typing import Dict, Any, List
from .base import BaseParser

class IPAParser(BaseParser):
    """
    Parser for iOS IPA files (Static Analysis).
    """
    def __init__(self, file_path: Path):
        super().__init__(file_path)
        if not zipfile.is_zipfile(file_path):
            raise ValueError("Invalid IPA file: Not a ZIP archive.")

    def analyze(self) -> Dict[str, Any]:
        results = self.get_basic_info()
        
        results.update({
            "format": "IPA",
            "bundle_identifier": None,
            "bundle_name": None,
            "bundle_version": None,
            "min_os_version": None,
            "permissions": [],
        })

        try:
            with zipfile.ZipFile(self.file_path, "r") as zip_ref:
                # Find the Info.plist file
                plist_path = None
                for name in zip_ref.namelist():
                    if name.startswith("Payload/") and name.endswith(".app/Info.plist"):
                        plist_path = name
                        break
                
                if plist_path:
                    with zip_ref.open(plist_path) as plist_file:
                        plist_data = plistlib.load(plist_file)
                        
                        results["bundle_identifier"] = plist_data.get("CFBundleIdentifier")
                        results["bundle_name"] = plist_data.get("CFBundleName")
                        results["bundle_version"] = plist_data.get("CFBundleShortVersionString")
                        results["min_os_version"] = plist_data.get("MinimumOSVersion")
                        
                        # Extract permissions (Usage Descriptions)
                        for key in plist_data.keys():
                            if key.endswith("UsageDescription"):
                                results["permissions"].append(key)
        except Exception as e:
            results["error"] = f"Failed to parse IPA: {e}"

        return results
