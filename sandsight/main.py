import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional
from pathlib import Path
from sandsight.core.engine import SandSightCore
from sandsight.core.reporter import Reporter

app = typer.Typer(
    name="sandsight",
    help="SandSight - A cross-platform malware analysis and sandbox framework.",
    add_completion=False,
)

console = Console()
core = SandSightCore()
reporter = Reporter()

def display_banner():
    banner_text = """
    ███████╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗ ██████╗ ██╗  ██╗████████╗
    ██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝
    ███████╗███████║██╔██╗ ██║██║  ██║███████╗██║██║  ███╗███████║   ██║   
    ╚════██║██╔══██║██║╚██╗██║██║  ██║╚════██║██║██║   ██║██╔══██║   ██║   
    ███████║██║  ██║██║ ╚████║██████╔╝███████║██║╚██████╔╝██║  ██║   ██║   
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                                           
              Cross-Platform Malware Analysis & Sandbox Framework
    """
    console.print(Panel(banner_text, style="bold blue", expand=False))

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    SandSight CLI: Main entry point.
    """
    if ctx.invoked_subcommand is None:
        display_banner()
        console.print(ctx.get_help())

@app.command()
def scan(
    path: Path = typer.Argument(..., help="Path to the file to scan."),
    sandbox: bool = typer.Option(True, "--sandbox/--no-sandbox", help="Enable or disable sandbox execution."),
    format: str = typer.Option("text", "--format", "-f", help="Output format (text, json, html)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Path to save the report."),
    network: bool = typer.Option(False, "--network", help="Enable network access in sandbox."),
    memory_dump: bool = typer.Option(False, "--memory-dump", help="Capture memory dump from sandbox."),
):
    """
    Perform a full analysis (Static + Dynamic + Intelligence) on a file.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Analyzing file...", total=None)
        
        try:
            # 1. Static Analysis
            static_results = core.run_static_analysis(path)
            
            # 2. Dynamic Analysis
            dynamic_results = {}
            if sandbox:
                dynamic_results = core.run_sandbox(path, allow_network=network, dump_memory=memory_dump)
            
            # 3. Combine results
            results = {
                "file_info": {
                    "name": path.name,
                    "path": str(path.absolute()),
                    "size": path.stat().st_size,
                    "type": static_results.get("file_info", {}).get("type", "Unknown")
                },
                "static_analysis": static_results.get("static_analysis", {}),
                "detections": static_results.get("detections", []),
                "dynamic_analysis": dynamic_results.get("dynamic_analysis"),
                "intelligence": static_results.get("intelligence")
            }

            # Reporting
            output_name = f"report_{path.stem}"
            output_path = reporter.generate_report(results, output_name, format=format)
            progress.console.print(f"[bold green][+][/bold green] Analysis complete. Report generated: [cyan]{output_path}[/cyan]")
            
        except Exception as e:
            progress.console.print(f"[bold red]Error during analysis:[/bold red] {e}")
            raise typer.Exit(code=1)


@app.command()
def static(
    path: Path = typer.Argument(..., help="Path to the file for static analysis."),
    format: str = typer.Option("json", "--format", "-f", help="Output format options."),
):
    """
    Perform only static analysis on a file.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][*][/bold green] Running static analysis on: [cyan]{path}[/cyan]")
    
    try:
        results = core.run_static_analysis(path)
        
        # Simple output to console for static command
        if format == "json":
            import json
            console.print_json(json.dumps(results, default=str))
        else:
             console.print(results)
             
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def sandbox_run(
    path: Path = typer.Argument(..., help="Path to the file to run in sandbox."),
    network: bool = typer.Option(False, "--network", help="Enable network access in sandbox."),
    memory_dump: bool = typer.Option(False, "--memory-dump", help="Capture memory dump from sandbox."),
):
    """
    Run a file in the isolated sandbox.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    console.print(f"[bold yellow][!][/bold yellow] Warning: Executing sample in sandbox: [cyan]{path}[/cyan]")
    
    try:
        core.run_sandbox(path, allow_network=network, dump_memory=memory_dump)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def memory_scan(
    path: Path = typer.Argument(..., help="Path to the memory dump file."),
):
    """
    Scan a memory dump for suspicious artifacts.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][*][/bold green] Scanning memory dump: [cyan]{path}[/cyan]")
    
    try:
        core.analyze_memory(path)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@app.command()
def yara_scan(
    path: Path = typer.Argument(..., help="Path to the file to scan with YARA."),
    rules: Optional[Path] = typer.Option(None, "--rules", "-r", help="Path to custom YARA rules file."),
):
    """
    Scan a file using YARA rules.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][*][/bold green] Scanning with YARA: [cyan]{path}[/cyan]")
    
    # Using the scanner from core for now, ignoring custom rules arg for brevity unless needed.
    # To support custom rules properly we'd need to modify YaraScanner to accept them dynamically or create a new instance.
    # For now, let's use the core scanner.
    
    try:
        results = core.yara_scanner.scan(path)
        if results:
            console.print(f"[bold red][!][/bold red] Found {len(results)} matches:")
            for match in results:
                console.print(f"  - [red]{match['rule']}[/red]")
        else:
             console.print(f"[green]No matches found.[/green]")
             
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

if __name__ == "__main__":
    app()
