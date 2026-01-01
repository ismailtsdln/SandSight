import yara
from pathlib import Path
from typing import Dict, Any, List

class YaraScanner:
    """
    YARA scanner module for SandSight.
    """
    def __init__(self, rules_path: Path = None):
        self.rules_path = rules_path or Path(__file__).parent.parent.parent / "data/yara_rules"
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """
        Compile YARA rules from the rules directory.
        """
        if not self.rules_path.exists():
            self.rules_path.mkdir(parents=True, exist_ok=True)
            # Create a dummy rule if none exist
            dummy_rule = "rule dummy { condition: false }"
            with open(self.rules_path / "dummy.yar", "w") as f:
                f.write(dummy_rule)

        rule_files = {}
        for yar_file in self.rules_path.glob("*.yar*"):
            rule_files[yar_file.stem] = str(yar_file)

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except yara.SyntaxError as e:
                print(f"Error compiling YARA rules: {e}")

    def scan(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Scan a file using compiled rules.
        """
        matches = []
        if self.rules:
            try:
                scanner_matches = self.rules.match(str(file_path))
                for match in scanner_matches:
                    matches.append({
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "namespace": match.namespace,
                    })
            except Exception as e:
                print(f"Error during YARA scan: {e}")
        return matches
