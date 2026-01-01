import yara
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console

console = Console()

class MemoryAnalyzer:
    """
    Module for analyzing memory dumps.
    """
    def __init__(self):
        self.rules_path = Path(__file__).parent.parent.parent.parent / "data/yara_rules"
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """
        Compile YARA rules specifically for memory analysis.
        """
        if not self.rules_path.exists():
             console.print(f"[yellow]Warning: Rules directory not found at {self.rules_path}[/yellow]")
             return

        rule_files = {}
        # Load all rules or specifically shellcode ones
        for yar_file in self.rules_path.glob("*.yar*"):
            rule_files[yar_file.stem] = str(yar_file)

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except yara.SyntaxError as e:
                console.print(f"[red]Error compiling Memory YARA rules: {e}[/red]")

    def analyze_dump(self, dump_path: Path) -> Dict[str, Any]:
        """
        Analyze a raw memory dump file.
        """
        if not dump_path.exists():
            return {"error": f"Dump file not found: {dump_path}"}
            
        results = {
            "matches": [],
            "metadata": {
                "size": dump_path.stat().st_size,
                "path": str(dump_path)
            }
        }
        
        if self.rules:
            try:
                # Scan the file
                matches = self.rules.match(str(dump_path))
                for match in matches:
                    results["matches"].append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": match.strings # Be careful with large dumps, maybe limit this
                    })
            except Exception as e:
                results["error"] = str(e)
                
        return results
