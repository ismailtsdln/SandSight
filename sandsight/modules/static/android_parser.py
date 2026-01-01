from androguard.core.bytecodes.apk import APK
from pathlib import Path
from typing import Dict, Any, List
from .base import BaseParser

class AndroParser(BaseParser):
    """
    Parser for Android APK files using Androguard.
    """
    def __init__(self, file_path: Path):
        super().__init__(file_path)
        try:
            self.apk = APK(str(file_path))
        except Exception as e:
            raise ValueError(f"Invalid APK file: {e}")

    def analyze(self) -> Dict[str, Any]:
        results = self.get_basic_info()
        
        results.update({
            "format": "APK",
            "package_name": self.apk.get_package(),
            "app_name": self.apk.get_app_name(),
            "android_version_code": self.apk.get_androidversion_code(),
            "android_version_name": self.apk.get_androidversion_name(),
            "min_sdk_version": self.apk.get_min_sdk_version(),
            "target_sdk_version": self.apk.get_target_sdk_version(),
            "permissions": self.apk.get_permissions(),
            "activities": self.apk.get_activities(),
            "services": self.apk.get_services(),
            "receivers": self.apk.get_receivers(),
            "providers": self.apk.get_providers(),
            "features": self.apk.get_features(),
            "main_activity": self.apk.get_main_activity(),
        })

        # Check for suspicious permissions
        dangerous_permissions = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ]
        
        results["suspicious_permissions"] = [p for p in results["permissions"] if p in dangerous_permissions]

        return results
