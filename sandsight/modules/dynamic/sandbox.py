from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional
import time
import docker # type: ignore
from rich.console import Console

console = Console()

class BaseSandbox(ABC):
    """
    Abstract base class for sandbox backends.
    """
    def __init__(self, working_dir: Path):
        self.working_dir = working_dir
        if not self.working_dir.exists():
            self.working_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def start(self):
        """Start the sandbox environment."""
        pass

    @abstractmethod
    def stop(self):
        """Stop and cleanup the sandbox environment."""
        pass

    @abstractmethod
    def run_sample(self, file_path: Path, timeout: int = 60) -> Dict[str, Any]:
        """Run the sample in the sandbox."""
        pass

class DockerSandbox(BaseSandbox):
    """
    Docker-based sandbox implementation.
    """
    def __init__(self, working_dir: Path, image_name: str = "sandsight-sandbox:latest"):
        super().__init__(working_dir)
        self.image_name = image_name
        self.client = docker.from_env()
        self.container = None

    def start(self):
        # Docker containers are usually started on demand in run_sample, 
        # but we could spin up a warm container here.
        # For now, we'll keep it simple.
        pass

    def stop(self):
        if self.container:
            try:
                self.container.stop()
                self.container.remove()
                console.print("[dim]Container stopped and removed.[/dim]")
            except Exception as e:
                console.print(f"[red]Error stopping container: {e}[/red]")

    def run_sample(self, file_path: Path, timeout: int = 60) -> Dict[str, Any]:
        results = {
            "execution_logs": "",
            "exit_code": None,
            "duration": 0,
            "error": None
        }
        
        try:
            # Check if image exists, pull if not (mock logic mostly for now, assumes local image or public)
            try:
                self.client.images.get(self.image_name)
            except docker.errors.ImageNotFound:
                 console.print(f"[yellow]Image {self.image_name} not found, attempting pull...[/yellow]")
                 # self.client.images.pull(self.image_name) # Commented out to avoid random pulling
                 results["error"] = f"Image {self.image_name} not found. Please build it first."
                 return results

            start_time = time.time()
            
            # Run container with strace
            # We mount the file as read-only to /sample
            cmd = f"/bin/sh -c 'chmod +x /sample/{file_path.name} && strace -f -e trace=file,network,process -o /tmp/strace.log /sample/{file_path.name}'"
            
            self.container = self.client.containers.run(
                self.image_name,
                command=cmd,
                volumes={str(file_path.parent.absolute()): {'bind': '/sample', 'mode': 'ro'}},
                detach=True,
                network_disabled=True, 
                mem_limit='512m',
                cap_add=['SYS_PTRACE'], # Required for strace
                security_opt=['seccomp:unconfined'], # Often required for strace
            )
            
            # Wait for finish or timeout
            try:
                result = self.container.wait(timeout=timeout)
                results["exit_code"] = result.get('StatusCode')
            except Exception as e: # Timeout
                self.container.kill()
                results["error"] = "Execution timed out"
            
            results["duration"] = time.time() - start_time
            
            # Capture logs
            logs = self.container.logs(stdout=True, stderr=True)
            results["execution_logs"] = logs.decode('utf-8', errors='replace')
            
            # Capture strace output
            try:
                # This is a bit hacky: copying file from container. 
                # Ideally use a shared volume or `get_archive`.
                bits, stat = self.container.get_archive('/tmp/strace.log')
                import tarfile
                import io
                
                file_obj = io.BytesIO()
                for chunk in bits:
                    file_obj.write(chunk)
                file_obj.seek(0)
                
                with tarfile.open(fileobj=file_obj) as tar:
                    member = tar.getmember("strace.log")
                    f = tar.extractfile(member)
                    results["strace_log"] = f.read().decode('utf-8', errors='replace')
            except Exception as e:
                results["strace_error"] = str(e)
                
        except Exception as e:
            results["error"] = str(e)
        finally:
            self.stop()
            
        return results
