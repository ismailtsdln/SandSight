import magic
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from sandsight.modules.static.pe_parser import PEParser
from sandsight.modules.static.macho_parser import MachOParser
from sandsight.modules.static.android_parser import AndroParser
from sandsight.modules.static.ios_parser import IPAParser
from sandsight.modules.static.yara_scanner import YaraScanner
from sandsight.modules.dynamic.sandbox import DockerSandbox
from sandsight.modules.dynamic.memory import MemoryAnalyzer
from sandsight.modules.dynamic.monitor import Monitor
from sandsight.core.plugin_manager import PluginManager
from sandsight.core.intelligence import IntelManager

console = Console()

class SandSightCore:
    def __init__(self):
        self.supported_formats = {
            "application/x-dosexec": "PE",
            "application/x-executable": "ELF",
            "application/x-mach-binary": "Mach-O",
            "application/vnd.android.package-archive": "APK",
            "application/x-ios-app": "IPA", # IPA might be detected as ZIP
            "application/zip": "ZIP/IPA",
        }
        self.yara_scanner = YaraScanner()
        self.memory_analyzer = MemoryAnalyzer()
        self.monitor = Monitor()
        self.plugin_manager = PluginManager()
        self.plugin_manager.discover_plugins()
        self.intel_manager = IntelManager()

    def detect_file_type(self, file_path: Path) -> str:
        """
        Detect the file type using magic numbers.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        mime = magic.Magic(mime=True)
        file_mime = mime.from_file(str(file_path))
        
        # Refine detection for mobile apps if needed
        if file_mime == "application/zip":
            if file_path.suffix.lower() == ".apk":
                return "APK"
            if file_path.suffix.lower() == ".ipa":
                return "IPA"
        
        return self.supported_formats.get(file_mime, "Unknown")

    def run_static_analysis(self, file_path: Path) -> Dict[str, Any]:
        """
        Orchestrate static analysis based on file type.
        """
        file_type = self.detect_file_type(file_path)
        console.print(f"[bold blue][*][/bold blue] Detected file type: [yellow]{file_type}[/yellow]")
        
        results = {
            "file_info": {
                "name": file_path.name,
                "path": str(file_path.absolute()),
                "type": file_type,
                "size": file_path.stat().st_size,
            },
            "static_analysis": {},
            "detections": [],
        }

        # Initialize parsers based on file type
        if file_type == "PE":
            parser = PEParser(file_path)
            results["static_analysis"] = parser.analyze()
        elif file_type == "Mach-O":
            parser = MachOParser(file_path)
            results["static_analysis"] = parser.analyze()
        elif file_type == "APK":
            parser = AndroParser(file_path)
            results["static_analysis"] = parser.analyze()
        elif file_type == "IPA":
            parser = IPAParser(file_path)
            results["static_analysis"] = parser.analyze()
        
        # Run YARA scan for all files
        console.print(f"[bold blue][*][/bold blue] Running YARA scan...")
        results["detections"] = self.yara_scanner.scan(file_path)
        
        # Plugin Hooks: Static Analysis
        console.print(f"[bold blue][*][/bold blue] Running plugin static analysis hooks...")
        self.plugin_manager.run_static_hooks(str(file_path), results)
        
        # Threat Intelligence Enrichment
        if "hashes" in results.get("static_analysis", {}):
            results["intelligence"] = self.intel_manager.enrich_results(results["static_analysis"]["hashes"])
        
        return results

    def run_sandbox(self, file_path: Path, allow_network: bool = False, dump_memory: bool = False) -> Dict[str, Any]:
        """
        Orchestrate sandbox execution.
        """
        console.print(f"[bold blue][*][/bold blue] Initializing Docker Sandbox...")
        sandbox = DockerSandbox(working_dir=file_path.parent)
        
        console.print(f"[bold blue][*][/bold blue] specific image: sandsight-sandbox:latest")
        
        if allow_network:
            console.print(f"[bold yellow][!][/bold yellow] Network access ENABLED for this sample.")
        
        console.print(f"[bold blue][*][/bold blue] Running sample in isolated container...")
        results = sandbox.run_sample(file_path, allow_network=allow_network, dump_memory=dump_memory)
        
        if results.get("error"):
            console.print(f"[bold red][!][/bold red] Sandbox Error: {results['error']}")
        else:
            console.print(f"[bold green][+][/bold green] Execution finished. Duration: {results['duration']:.2f}s")
            
            # Parse behaviors from strace
            if results.get("strace_log"):
                console.print(f"[bold blue][*][/bold blue] Analyzing behavioral patterns...")
                results["behavior"] = self.monitor.parse_strace(results["strace_log"])
            
            # Save PCAP if available
            if results.get("pcap_data"):
                pcap_path = file_path.with_suffix(".pcap")
                with open(pcap_path, "wb") as f:
                    f.write(results["pcap_data"])
                console.print(f"[bold green][+][/bold green] Network capture saved to: [cyan]{pcap_path}[/cyan]")
                results["pcap_file"] = str(pcap_path)

            # Analyze Memory Dump if available
            if results.get("memory_dump"):
                dump_path = file_path.with_suffix(".dmp")
                with open(dump_path, "wb") as f:
                    f.write(results["memory_dump"])
                console.print(f"[bold green][+][/bold green] Memory dump saved to: [cyan]{dump_path}[/cyan]")
                
                console.print(f"[bold blue][*][/bold blue] Performing forensics on captured memory dump...")
                mem_results = self.analyze_memory(dump_path)
                results["memory_forensics"] = mem_results

        # Plugin Hooks: Dynamic Analysis
        console.print(f"[bold blue][*][/bold blue] Running plugin dynamic analysis hooks...")
        self.plugin_manager.run_dynamic_hooks(results)
            
        return {"dynamic_analysis": results}

    def analyze_memory(self, dump_path: Path) -> Dict[str, Any]:
        """
        Analyze a memory dump.
        """
        console.print(f"[bold blue][*][/bold blue] Analyzing memory dump: [cyan]{dump_path}[/cyan]")
        results = self.memory_analyzer.analyze_dump(dump_path)
        
        match_count = len(results.get("matches", []))
        if match_count > 0:
            console.print(f"[bold red][!][/bold red] Found {match_count} suspicious memory artifacts.")
        else:
             console.print(f"[bold green][+][/bold green] No suspicious memory artifacts found.")
             
        return {"memory_analysis": results}
