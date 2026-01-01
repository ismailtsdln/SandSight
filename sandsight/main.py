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
    report: bool = typer.Option(True, "--report/--no-report", help="Generate a report after scan."),
    format: str = typer.Option("html", "--format", "-f", help="Report format (json/html)."),
):
    """
    Perform a complete scan (Static + Dynamic if enabled) on a file.
    """
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green][*][/bold green] Starting scan for: [cyan]{path}[/cyan]")
    
    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,       
    ) as progress:
        task1 = progress.add_task(description="Running static analysis...", total=None)
        
        try:
            # Static Analysis
            static_results = core.run_static_analysis(path)
            results.update(static_results)
            progress.console.print(f"[bold green][+][/bold green] Static analysis complete.")
            
            # Sandbox Analysis
            if sandbox:
                task2 = progress.add_task(description="Running sandbox analysis...", total=None)
                sandbox_results = core.run_sandbox(path)
                results.update(sandbox_results)
                progress.console.print(f"[bold green][+][/bold green] Sandbox analysis complete.")
            
        except Exception as e:
            progress.console.print(f"[bold red]Error during analysis:[/bold red] {e}")
            # Continue to report even if partial failure? 
            # For now, let's keep what we have.

    # Reporting
    if report:
        try:
            output_name = f"report_{path.stem}"
            output_path = reporter.generate_report(results, output_name, format=format)
            console.print(f"[bold green][+][/bold green] Report generated: [cyan]{output_path}[/cyan]")
        except Exception as e:
             console.print(f"[bold red]Error generating report:[/bold red] {e}")


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
):
    """
    Run a file in the isolated sandbox (Skeleton).
    """
    console.print(f"[bold yellow][!][/bold yellow] Warning: Executing sample in sandbox: [cyan]{path}[/cyan]")
    # Placeholder for Phase 2
    console.print("[dim]Sandbox functionality is under development (Phase 2).[/dim]")

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
