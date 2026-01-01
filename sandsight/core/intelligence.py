import os
import requests
from typing import Dict, Any, Optional
from rich.console import Console

console = Console()

class IntelManager:
    """
    Manages threat intelligence enrichment for analyzed files.
    """
    def __init__(self):
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.bazaar_base_url = "https://mb-api.abuse.ch/api/v1/"

    def lookup_virustotal(self, sha256: str) -> Optional[Dict[str, Any]]:
        """
        Lookup a file hash on VirusTotal.
        """
        if not self.vt_api_key:
            return None
            
        headers = {
            "x-apikey": self.vt_api_key
        }
        
        try:
            url = f"{self.vt_base_url}/files/{sha256}"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("attributes", {})
            elif response.status_code == 404:
                console.print(f"[dim]Hash {sha256} not found on VirusTotal.[/dim]")
                return None
            else:
                console.print(f"[yellow]VirusTotal API returned status {response.status_code}[/yellow]")
                return None
        except Exception as e:
            console.print(f"[red]Error querying VirusTotal: {e}[/red]")
            return None

    def lookup_malwarebazaar(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """
        Lookup a file hash on MalwareBazaar.
        """
        data = {
            "query": "get_info",
            "hash": hash_value
        }
        
        try:
            response = requests.post(self.bazaar_base_url, data=data)
            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    return result.get("data", [{}])[0]
                else:
                    return None
            return None
        except Exception as e:
            console.print(f"[red]Error querying MalwareBazaar: {e}[/red]")
            return None

    def enrich_results(self, hashes: Dict[str, str]) -> Dict[str, Any]:
        """
        Enrich analysis results with threat intelligence.
        """
        sha256 = hashes.get("sha256")
        if not sha256:
            return {}
            
        intelligence = {}
        
        # VirusTotal Lookup
        console.print(f"[bold blue][*][/bold blue] Querying VirusTotal...")
        vt_results = self.lookup_virustotal(sha256)
        if vt_results:
            intelligence["virustotal"] = vt_results
            
        # MalwareBazaar Lookup
        console.print(f"[bold blue][*][/bold blue] Querying MalwareBazaar...")
        bazaar_results = self.lookup_malwarebazaar(sha256)
        if bazaar_results:
            intelligence["malwarebazaar"] = bazaar_results
            
        return intelligence
