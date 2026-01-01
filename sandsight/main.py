import typer
from rich.console import Console
from rich.panel import Panel
from typing import Optional
from pathlib import Path

app = typer.Typer(
    name="sandsight",
    help="SandSight - A cross-platform malware analysis and sandbox framework.",
    add_completion=False,
)

console = Console()

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
):
    """
    Perform a complete scan (Static + Dynamic if enabled) on a file.
    """
    console.print(f"[bold green][*][/bold green] Starting scan for: [cyan]{path}[/cyan]")
    # TODO: Implement orchestration logic

@app.command()
def static(
    path: Path = typer.Argument(..., help="Path to the file for static analysis."),
):
    """
    Perform only static analysis on a file.
    """
    console.print(f"[bold green][*][/bold green] Running static analysis on: [cyan]{path}[/cyan]")
    # TODO: Implement static analysis logic

@app.command()
def sandbox_run(
    path: Path = typer.Argument(..., help="Path to the file to run in sandbox."),
):
    """
    Run a file in the isolated sandbox.
    """
    console.print(f"[bold yellow][!][/bold yellow] Warning: Executing sample in sandbox: [cyan]{path}[/cyan]")
    # TODO: Implement sandbox execution logic

@app.command()
def yara_scan(
    path: Path = typer.Argument(..., help="Path to the file to scan with YARA."),
    rules: Optional[Path] = typer.Option(None, "--rules", "-r", help="Path to custom YARA rules file."),
):
    """
    Scan a file using YARA rules.
    """
    console.print(f"[bold green][*][/bold green] Scanning with YARA: [cyan]{path}[/cyan]")
    # TODO: Implement YARA scanning logic

@app.command()
def report(
    path: Path = typer.Argument(..., help="Path to the analysis results."),
    format: str = typer.Option("html", "--format", "-f", help="Output format: json, html, markdown."),
):
    """
    Generate a report from analysis results.
    """
    console.print(f"[bold green][*][/bold green] Generating [cyan]{format}[/cyan] report for: [cyan]{path}[/cyan]")
    # TODO: Implement reporting logic

if __name__ == "__main__":
    app()
