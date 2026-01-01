import json
from pathlib import Path
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader

class Reporter:
    """
    Reporting engine for SandSight.
    """
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(self.templates_dir)))

    def generate_json(self, data: Dict[str, Any], output_path: Path):
        """
        Generate a JSON report.
        """
        with open(output_path, "w") as f:
            json.dump(data, f, indent=4, default=str)

    def generate_html(self, data: Dict[str, Any], output_path: Path):
        """
        Generate an HTML report using Jinja2 templates.
        """
        template = self.env.get_template("report.html")
        html_content = template.render(results=data)
        
        with open(output_path, "w") as f:
            f.write(html_content)

    def generate_report(self, data: Dict[str, Any], output_path: Path, format: str = "json"):
        """
        Generate a report in the specified format.
        """
        output_path = Path(output_path)
        
        if format.lower() == "json":
            if output_path.suffix != ".json":
                output_path = output_path.with_suffix(".json")
            self.generate_json(data, output_path)
        
        elif format.lower() == "html":
            if output_path.suffix != ".html":
                output_path = output_path.with_suffix(".html")
            self.generate_html(data, output_path)
            
        else:
            raise ValueError(f"Unsupported report format: {format}")
            
        return output_path
